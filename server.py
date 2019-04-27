#!/usr/bin/env python
import falcon
from falcon_cors import CORS

from config import config
from model.auth import Auth
from model.db import DatabaseFactory
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
            if 'application/json' not in req.content_type:
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


db_factory = DatabaseFactory(config['ldap'])
views = ViewsApi(db_factory, config['views'])
auth = Auth(views.views, db_factory, config['auth'])

app = falcon.API(
    middleware=[cors.middleware, auth.auth_middleware, RequireJSON(), MaxBody()],
)

views.register(app)
auth.register(app)

