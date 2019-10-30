import logging
from typing import Dict

import falcon
from falcon_auth import FalconAuthMiddleware, JWTAuthBackend
from ldap3.core.exceptions import LDAPCommunicationError, LDAPInvalidCredentialsResult

from model.anti_spam import AntiSpam
from model.db import DatabaseFactory, FalconLdapError
from model.view import View


class JwtAuthApi:
    auth = {
        'auth_disabled': True
    }

    def __init__(self, auth: 'Auth'):
        self.authenticator = auth

    def on_post(self, req: falcon.Request, resp: falcon.Response):
        content = req.media

        userdata, token = self.authenticator.login(content['username'], content['password'])

        resp.status = falcon.HTTP_200
        resp.media = {
            'token': token,
            'user': userdata
        }
        logging.info("Authenticated", userdata)

    def register(self, app: falcon.API):
        app.add_route('/jwt-auth', self)


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


class SelfUserApi:
    """Modify self user."""

    def __init__(self, view: View):
        self.view = view

    def on_get(self, req: falcon.Request, resp: falcon.Response):
        user = req.context.get('user')
        if user is None:
            raise falcon.HTTPForbidden()

        resp.media = self.view.get_self_entry(user)
        resp.status = falcon.HTTP_200

    def on_patch(self, req: falcon.Request, resp: falcon.Response):
        """Modify self user."""
        user = req.context.get('user')
        if user is None:
            raise falcon.HTTPForbidden()

        self.view.update_self(user, req.media)
        resp.status = falcon.HTTP_200

    def register(self, app: falcon.API):
        app.add_route('/user', self)


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


class Auth:
    def __init__(self, all_views: Dict[str, View], db_factory: DatabaseFactory, config: dict):
        self.secret_key = config['secretKey']
        self.header_prefix = config['headerPrefix']
        self.expiration = config['expiration']
        self.view = all_views[config['view']]
        self.db_factory = db_factory

        self.anti_spam = AntiSpam(config['antiSpam'])

        self.auth_backend = JWTAuthBackend(
            self.user_loader,
            secret_key=self.secret_key,
            auth_header_prefix=self.header_prefix,
            expiration_delta=self.expiration
        )

        self.auth_middleware = FalconAuthMiddleware(
            self.auth_backend,
            exempt_routes=['/jwt-auth'],
            exempt_methods=['HEAD', 'OPTIONS']
        )

    def user_loader(self, jwt_payload):
        primary_key = jwt_payload['user']['uid']
        assert isinstance(primary_key, str)
        auth_entry = self.view.get_auth_entry(primary_key)
        if 'timestamp' in auth_entry:
            if auth_entry['timestamp'] != jwt_payload['user']['timestamp']:
                raise falcon.HTTPUnauthorized()
        return auth_entry

    def login(self, primary_key: str, password: str):
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

        auth_entry = self.view.get_auth_entry(primary_key)

        jwt_payload = {'uid': primary_key}
        if 'timestamp' in auth_entry:
            jwt_payload['timestamp'] = auth_entry['timestamp']
        return auth_entry, self.auth_backend.get_auth_token(jwt_payload)

    def register(self, app: falcon.API):
        JwtAuthApi(self).register(app)
        AuthUserApi().register(app)
        RegisterUserApi(self.anti_spam, self.view).register(app)
        SelfUserApi(self.view).register(app)
        self.anti_spam.register(app)
        RegisterConfigApi(self.view).register(app)
