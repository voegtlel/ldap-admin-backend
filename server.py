#!/usr/bin/env python
import logging
import os

import falcon
from falcon_cors import CORS

from config import config
from model.auth import Auth
from model.db import DatabaseFactory
from model.mailer import Mailer
from model.view_api import ViewsApi

cors = CORS(
    allow_origins_list=config['allowOrigins'],
    allow_headers_list=['Content-Type', 'Authorization'],
    allow_methods_list=['GET', 'POST', 'PUT', 'PATCH', 'DELETE']
)


class RequireJSON:
    def process_request(self, req: falcon.Request, resp: falcon.Response):
        if not req.client_accepts_json:
            raise falcon.HTTPNotAcceptable(
                'This API only supports responses encoded as JSON.',
                href='http://docs.examples.com/api/json')

        if req.method in ('POST', 'PUT', 'PATCH'):
            if not req.content_type or 'application/json' not in req.content_type:
                raise falcon.HTTPUnsupportedMediaType(
                    'This API only supports requests encoded as JSON.',
                    href='http://docs.examples.com/api/json')


class MaxBody:
    def __init__(self, max_size=1*1024*1025):
        self._max_size = max_size

    def process_request(self, req: falcon.Request, resp: falcon.Response):
        length = req.content_length
        if length is not None and length > self._max_size:
            msg = ('The size of the request is too large. The body must not '
                   'exceed ' + str(self._max_size) + ' bytes in length.')
            raise falcon.HTTPPayloadTooLarge('Request body is too large', msg)


logging.basicConfig(level=logging.INFO)


if os.environ.get('TEST_USER_DATABASE') == "1":
    from db_mock import MockDatabaseFactory

    db_factory = MockDatabaseFactory(config['ldap'])

    auth_view = config['views'][config['auth']['view']]
    view_prefix = auth_view['dn'] + "," + config['ldap']['prefix']
    db_factory.connection.add(view_prefix, ['top', 'organizationalUnit'], {'ou': ['groups']})
else:
    db_factory = DatabaseFactory(config['ldap'])
views = ViewsApi(db_factory, config['views'])
auth = Auth(views.views, db_factory, config['auth'])

app = falcon.API(
    middleware=[cors.middleware, auth.auth_middleware, RequireJSON(), MaxBody()],
)
mailer = Mailer(config['mail'])

views.register(app, auth.relogin)
auth.register(app, mailer)


if os.environ.get('TEST_USER_DATABASE') == "1":
    users_view = views.views['users']
    groups_view = views.views['groups']

    user = {
        permission: True
        for permission in config['views'][config['auth']['view']]['permissions']
    }
    user[config['views'][config['auth']['view']]['primaryKey']] = 'unknown'

    groups_view.create_detail(user, {
        'group': {
            'cn': 'admin'
        }
    })
    groups_view.create_detail(user, {
        'group': {
            'cn': 'superuser'
        }
    })
    groups_view.create_detail(user, {
        'group': {
            'cn': 'new'
        }
    })

    users_view.create_detail(
        user=user,
        assignments={
            'user': {
                'uid': 'test',
                'givenName': 'Test',
                'sn': 'Tester',
                'mail': 'tester@localhost.localdomain',
                'mobile': '0123 456789',
                'isAdmin': True,
                'isSuperuser': True,
                'isNew': False,
            },
            'password': {
                '_enabled': True,
                'userPassword': 'blabla',
            },
            'memberOfGroups': {'add': ['admin', 'superuser']},
        }
    )

    users_view.create_detail(
        user=user,
        assignments={
            'user': {
                'uid': 'test2',
                'givenName': 'Test',
                'sn': 'Tester-Two',
                'mail': 'tester2@localhost.localdomain',
                'mobile': '0123 456789',
                'isAdmin': False,
                'isSuperuser': False,
                'isNew': False,
            },
            'password': {
                '_enabled': True,
                'userPassword': 'blabla',
            },
            'memberOfGroups': {'add': []},
        }
    )
