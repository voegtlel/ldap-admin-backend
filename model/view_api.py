from collections import OrderedDict
from typing import Dict, Callable, Any

import falcon

from model.db import DatabaseFactory
from model.view import View

TokenGeneratorFn = Callable[[str], Dict[str, Any]]


class ViewListApi:
    def __init__(self, view: View):
        self.view = view

    def on_get(self, req: falcon.Request, resp: falcon.Response):
        """List view"""
        user = req.context.get('user')
        if user is None:
            raise falcon.HTTPForbidden()

        resp.media = self.view.get_list(user)
        resp.status = falcon.HTTP_200

    def on_post(self, req: falcon.Request, resp: falcon.Response):
        """Create a new user. Requires admin permissions."""
        user = req.context.get('user')
        if user is None:
            raise falcon.HTTPForbidden()

        self.view.create_detail(user, req.media)
        resp.status = falcon.HTTP_200

    def register(self, app: falcon.API):
        app.add_route('/' + self.view.key, self)


class ViewDetailApi:
    def __init__(self, view: View, token_generator: TokenGeneratorFn):
        self.view = view
        self.token_generator = token_generator

    def on_get(self, req: falcon.Request, resp: falcon.Response, primary_key: str):
        """Get detail view."""
        user = req.context.get('user')
        if user is None:
            raise falcon.HTTPForbidden()

        resp.media = self.view.get_detail_entry(user, primary_key)
        resp.status = falcon.HTTP_200

    def on_patch(self, req: falcon.Request, resp: falcon.Response, primary_key: str):
        """Write attributes."""
        user = req.context.get('user')
        if user is None:
            raise falcon.HTTPForbidden()

        self.view.update_details(user, primary_key, req.media)
        if primary_key == user['primaryKey']:
            resp.media = self.token_generator(user['primaryKey'])
        resp.status = falcon.HTTP_200

    def on_delete(self, req: falcon.Request, resp: falcon.Response, primary_key: str):
        """Delete entity."""
        user = req.context.get('user')
        if user is None:
            raise falcon.HTTPForbidden()

        self.view.delete(user, primary_key)
        resp.status = falcon.HTTP_200

    def register(self, app: falcon.API):
        app.add_route('/' + self.view.key + '/{primary_key}', self)


class ViewDetailSelfApi:
    """Modify self view."""

    def __init__(self, view: View, token_generator: TokenGeneratorFn):
        self.view = view
        self.token_generator = token_generator

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
        resp.media = self.token_generator(user['primaryKey'])
        resp.status = falcon.HTTP_200

    def register(self, app: falcon.API):
        app.add_route('/' + self.view.key + '/self', self)


class UserConfigApi:
    def __init__(self, views: Dict[str, View]):
        self.views = views

    def on_get(self, req: falcon.Request, resp: falcon.Response):
        user = req.context.get('user')
        if user is None:
            raise falcon.HTTPForbidden()

        resp.media = [view.user_config(user) for view in self.views.values()]
        resp.status = falcon.HTTP_200

    def register(self, app: falcon.API):
        app.add_route('/config', self)


class ViewsApi:
    def __init__(self, db: DatabaseFactory, config: dict):
        self.views = OrderedDict((key, View(db, key, view_cfg)) for key, view_cfg in config.items())
        for view in self.views.values():
            view.init(self.views)

    def register(self, app: falcon.API, token_generator: TokenGeneratorFn):
        for key, view in self.views.items():
            ViewListApi(view).register(app)
            ViewDetailApi(view, token_generator).register(app)
            if view.has_self:
                ViewDetailSelfApi(view, token_generator).register(app)
        UserConfigApi(self.views).register(app)
