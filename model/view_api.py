from collections import OrderedDict
from typing import Dict

import falcon

from model.db import DatabaseFactory
from model.view import View


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
        app.add_route('/' + self.view.key + '/', self)


class ViewDetailApi:
    def __init__(self, view: View):
        self.view = view

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
        resp.status = falcon.HTTP_200

    def on_delete(self, req: falcon.Request, resp: falcon.Response, primary_key: str):
        """Delete entity."""
        user = req.context.get('user')
        if user is None:
            raise falcon.HTTPForbidden()

        self.view.delete(user, primary_key)
        resp.status = falcon.HTTP_200

    def register(self, app: falcon.API):
        app.add_route('/' + self.view.key + '/{primary_key}/', self)


class UserConfigApi:
    def __init__(self, views: Dict[str, View]):
        self.user_config = [view.user_config for view in views.values()]

    def on_get(self, req: falcon.Request, resp: falcon.Response):
        user = req.context.get('user')
        if user is None:
            raise falcon.HTTPForbidden()

        resp.media = self.user_config
        resp.status = falcon.HTTP_200

    def register(self, app: falcon.API):
        app.add_route('/config/', self)


class ViewsApi:
    def __init__(self, db: DatabaseFactory, config: dict):
        self.views = OrderedDict((key, View(db, key, view_cfg)) for key, view_cfg in config.items())
        for view in self.views.values():
            view.init(self.views)

    def register(self, app: falcon.API):
        for key, view in self.views.items():
            ViewListApi(view).register(app)
            ViewDetailApi(view).register(app)
        UserConfigApi(self.views).register(app)
