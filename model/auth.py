import logging
from datetime import timedelta, datetime
from typing import Dict, Any, Tuple

import falcon
from falcon_auth import FalconAuthMiddleware, JWTAuthBackend
from ldap3.core.exceptions import LDAPCommunicationError, LDAPInvalidCredentialsResult

from model.anti_spam import AntiSpam
from model.db import DatabaseFactory, FalconLdapError
from model.mailer import Mailer
from model.view import View


class JwtAuthApi:
    auth = {
        'auth_disabled': True
    }

    def __init__(self, auth: 'Auth'):
        self.authenticator = auth

    def on_post(self, req: falcon.Request, resp: falcon.Response):
        content = req.media

        resp.media = self.authenticator.login(content['username'], content['password'])
        resp.status = falcon.HTTP_200

    def register(self, app: falcon.API):
        app.add_route('/jwt-auth', self)


class JwtRefreshApi:
    def __init__(self, auth: 'Auth'):
        self.authenticator = auth

    def on_post(self, req: falcon.Request, resp: falcon.Response):
        user = req.context.get('user')
        if user is None:
            raise falcon.HTTPForbidden()

        userdata, token = self.authenticator.create_token(user)

        resp.status = falcon.HTTP_200
        resp.media = {
            'token': token,
            'user': userdata.to_dict()
        }
        logging.info("Refreshed", userdata)

    def register(self, app: falcon.API):
        app.add_route('/jwt-refresh', self)


class AuthUserApi:
    """Gets the currently authenticated user"""
    def on_get(self, req: falcon.Request, resp: falcon.Response):
        user = req.context.get('user')
        if user is None:
            raise falcon.HTTPForbidden()

        resp.status = falcon.HTTP_200
        resp.media = user

    def register(self, app: falcon.API):
        app.add_route('/auth', self)


class RegisterUserApi:
    """Register a new user."""

    auth = {
        'auth_disabled': True
    }

    def __init__(self, anti_spam: AntiSpam, view: View):
        self.anti_spam = anti_spam
        self.view = view

    def on_post(self, req: falcon.Request, resp: falcon.Response):
        """Create a new user."""
        user = req.media

        self.anti_spam.verify_answer(user, 'antiSpamToken', 'antiSpamAnswer')

        self.view.create_register(user)

        logging.info("Registered with comment", user['signupComment'])

        resp.status = falcon.HTTP_200

    def register(self, app: falcon.API):
        app.add_route('/register', self)


class RegisterConfigApi:
    auth = {
        'auth_disabled': True
    }

    def __init__(self, view: View):
        self.config = view.public_config

    def on_get(self, req: falcon.Request, resp: falcon.Response):
        resp.media = self.config
        resp.status = falcon.HTTP_200

    def register(self, app: falcon.API):
        app.add_route('/register-config', self)


class MailLoginApi:
    auth = {
        'auth_disabled': True
    }

    def __init__(self, auth: 'Auth', mailer: Mailer):
        self.authenticator = auth
        self.mailer = mailer

    def on_post(self, req: falcon.Request, resp: falcon.Response):
        search_email = req.media['email']
        user_id = self.authenticator.view.resolve_primary_key_by_mail(search_email)
        token_data, user_data = self.authenticator.auto_login(user_id)

        valid_duration = timedelta(seconds=self.authenticator.auto_login_expiration)
        valid_until = datetime.now() + valid_duration

        self.mailer.send_mail(user_data.get('language', 'en'), 'auto_login', user_data['mail'], {
            'display_name': user_data['displayName'],
            'mail': user_data['mail'],
            'login_link': f"auth/token-login?token={token_data['token']}",
            'valid_duration': valid_duration,
            'valid_until': valid_until,
        })

        resp.status = falcon.HTTP_200

    def register(self, app: falcon.API):
        app.add_route('/mail-login', self)


class Auth:
    def __init__(self, all_views: Dict[str, View], db_factory: DatabaseFactory, config: dict):
        self.secret_key = config['secretKey']
        self.header_prefix = config['headerPrefix']
        self.expiration = config['expiration']
        self.auto_login_expiration = config['autoLoginExpiration']
        self.view = all_views[config['view']]
        self.db_factory = db_factory

        self.anti_spam = AntiSpam(config['antiSpam'])

        self.auth_backend = JWTAuthBackend(
            self.user_loader,
            secret_key=self.secret_key,
            auth_header_prefix=self.header_prefix,
            expiration_delta=self.expiration
        )

        self.auto_auth_backend = JWTAuthBackend(
            self.user_loader,
            secret_key=self.secret_key,
            auth_header_prefix=self.header_prefix,
            expiration_delta=self.auto_login_expiration
        )

        self.auth_middleware = FalconAuthMiddleware(
            self.auth_backend,
            exempt_routes=['/jwt-auth'],
            exempt_methods=['HEAD', 'OPTIONS']
        )

    def user_loader(self, jwt_payload):
        primary_key = jwt_payload['user']['primaryKey']
        assert isinstance(primary_key, str)
        auth_entry = self.view.get_auth_entry(primary_key)
        if 'timestamp' in auth_entry:
            if auth_entry['timestamp'] != jwt_payload['user']['timestamp']:
                raise falcon.HTTPUnauthorized()
        return auth_entry

    def auto_login(self, primary_key: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        auth_entry = self.view.get_auth_entry(primary_key)

        return {'token': self.auto_auth_backend.get_auth_token(auth_entry)}, auth_entry

    def relogin(self, primary_key: str) -> Dict[str, Any]:
        auth_entry = self.view.get_auth_entry(primary_key)

        return self.create_token(auth_entry)

    def create_token(self, auth_entry: Dict[str, Any]):
        return {'token': self.auth_backend.get_auth_token(auth_entry)}

    def login(self, primary_key: str, password: str) -> Dict[str, Any]:
        try:
            if primary_key is None:
                raise ValueError("primary_key must not be None")
            if password is None:
                raise ValueError("password must not be None")
            self.db_factory.connect(user=self.view.get_dn(primary_key), password=password)
        except LDAPInvalidCredentialsResult:
            raise falcon.HTTPUnauthorized()
        except LDAPCommunicationError as e:
            raise FalconLdapError(e)

        return self.relogin(primary_key)

    def register(self, app: falcon.API, mailer: Mailer):
        JwtAuthApi(self).register(app)
        JwtRefreshApi(self).register(app)
        AuthUserApi().register(app)
        RegisterUserApi(self.anti_spam, self.view).register(app)
        self.anti_spam.register(app)
        RegisterConfigApi(self.view).register(app)
        MailLoginApi(self, mailer).register(app)
