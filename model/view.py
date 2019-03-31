from collections import OrderedDict
from typing import Dict, List, Set, Any, Optional, Union

from model.db import Database, Scope, LdapModlist, LdapAddlist
from model.view_details import ViewDetails
from model.view_list import ViewList

import falcon


class View:
    def __init__(self, db: Database, key: str, config: dict, **overrides):
        config.update(overrides)
        self._key = key
        self._db = db
        self._dn = config['dn'] + ',' + db.prefix
        self._title = config['title']
        self._primary_key = config['primaryKey']
        self._permissions = config['permissions']
        self._classes = [cls.encode() for cls in config['classes']]
        self._list_view = ViewList(config['list'])
        self._detail_view = ViewDetails(config['details'])
        self._self_view: Optional[ViewDetails] = (
            ViewDetails(config['self'])
            if 'self' in config else None
        )
        self._register_view: Optional[ViewDetails] = (
            ViewDetails(config['register'])
            if 'register' in config else None
        )
        self._auth_view: Optional[ViewList] = (
            ViewList(config['auth'])
            if 'auth' in config else None
        )

        self._class_filter = "(&" + "".join("(objectClass={})".format(cls) for cls in config['classes']) + ")"
        self._dn_prefix = self._primary_key + "="
        self._dn_suffix = "," + self._dn

        self._user_config = OrderedDict([
            ('key', self._key),
            ('primaryKey', self._primary_key),
            ('permissions', self._permissions),
            ('title', self._title),
            ('description', config.get('description', '')),
            ('iconClasses', config.get('iconClasses', '')),
        ])
        if self._list_view is not None:
            self._user_config['list'] = self._list_view.config
        if self._detail_view is not None:
            self._user_config['details'] = self._detail_view.config
        if self._self_view is not None:
            self._user_config['self'] = self._self_view.config
        if self._auth_view is not None:
            self._user_config['auth'] = self._auth_view.config

        if self._register_view is not None:
            self._public_config = OrderedDict([
                ('key', self._key),
                ('primaryKey', self._primary_key),
                ('title', self._title),
                ('iconClasses', config.get('iconClasses', '')),
                ('description', config.get('description', '')),
                ('register', self._register_view.config),
            ])
        else:
            self._public_config = None

    @property
    def user_config(self) -> dict:
        return self._user_config

    @property
    def public_config(self) -> Optional[dict]:
        return self._public_config

    @property
    def key(self):
        return self._key

    def _check_permissions(self, user: Dict[str, Any], primary_key: Optional[str] = None):
        if 'self' in self._permissions:
            if primary_key == user[self._primary_key]:
                return
        for permission in self._permissions:
            if user[permission]:
                return
        raise falcon.HTTPForbidden(description="Insufficient permissions")

    def init(self, all_views: Dict[str, 'View']):
        self._list_view.init(all_views)
        self._detail_view.init(all_views)
        if self._self_view is not None:
            self._self_view.init(all_views)
        if self._auth_view is not None:
            self._auth_view.init(all_views)
        if self._register_view is not None:
            self._register_view.init(all_views)

    def _create(self, view: ViewDetails, assignments: Dict[str, Dict[str, Any]]):
        primary_key: str = None
        for value in assignments.values():
            if self._primary_key in value:
                primary_key = value[self._primary_key]
        if not primary_key:
            raise falcon.HTTPBadRequest(description="Missing primary key in assignments")
        addlist: LdapAddlist = [('objectClass', self._classes)]
        dn = self.get_dn(primary_key)
        view.create((dn, dict()), addlist, assignments)
        self._db.create(dn, addlist)
        view.set_post((dn, dict()), assignments, True)

    def _list(self, view: ViewList):
        fetches: Set[str] = set()
        view.get_fetch(fetches)
        result = self._db.search(self._dn, Scope.ONELEVEL, self._class_filter, attrlist=list(fetches))
        return view.get(result)

    def _get_entry(self, view: Union[ViewList, ViewDetails], primary_key: str) -> Dict[str, Any]:
        fetches: Set[str] = set()
        view.get_fetch(fetches)
        result = self._db.get(self.get_dn(primary_key), attrlist=list(fetches))
        if isinstance(view, ViewList):
            return view.get([result])[0]
        elif isinstance(view, ViewDetails):
            return view.get(result)
        raise ValueError("Invalid value for view: {}".format(view))

    def _update(self, view: ViewDetails, primary_key: str, assignments: Dict[str, Dict[str, Any]]):
        dn = self.get_dn(primary_key)
        fetches: Set[str] = set()
        view.set_fetch(fetches, assignments)
        fetched = self._db.get(dn, list(fetches))
        modlist: LdapModlist = []
        view.set(fetched, modlist, assignments)
        self._db.update(dn, modlist)
        view.set_post(fetched, assignments, False)

    def create_register(self, assignments: Dict[str, Dict[str, Any]]):
        self._create(self._register_view, assignments)

    def create_detail(self, user: Dict[str, Any], assignments: Dict[str, Dict[str, Any]]):
        self._check_permissions(user)
        self._create(self._detail_view, assignments)

    def get_list(self, user: Dict[str, Any]) -> List[Dict[str, Any]]:
        self._check_permissions(user)
        return self._list(self._list_view)

    def get_list_entry(self, user: Dict[str, Any], primary_key: str) -> Dict[str, Any]:
        self._check_permissions(user, primary_key)
        return self._get_entry(self._list_view, primary_key)

    def get_self_entry(self, user: Dict[str, Any]) -> Dict[str, Any]:
        return self._get_entry(self._list_view, user['primaryKey'])

    def get_detail_entry(self, user: Dict[str, Any], primary_key: str) -> Dict[str, List[str]]:
        self._check_permissions(user, primary_key)
        return self._get_entry(self._detail_view, primary_key)

    def get_auth_entry(self, primary_key: str) -> Dict[str, Any]:
        return self._get_entry(self._auth_view, primary_key)

    def update_self(self, user: Dict[str, Any], assignments: Dict[str, Dict[str, Any]]):
        self._update(self._self_view, user['primaryKey'], assignments)

    def update_details(self, user: Dict[str, Any], primary_key: str, assignments: Dict[str, Dict[str, Any]]):
        self._check_permissions(user, primary_key)
        self._update(self._detail_view, primary_key, assignments)

    def delete(self, user: Dict[str, Any], primary_key: str):
        self._check_permissions(user)
        self._db.delete(self.get_dn(primary_key))

    def save_foreign_field(self, primary_key: str, modlist: LdapModlist):
        self._db.update(self.get_dn(primary_key), modlist)

    def get_dn(self, primary_key: str) -> str:
        return self._primary_key + "=" + self._db.escape_dn(primary_key) + "," + self._dn

    def try_get_dn(self, primary_key: str) -> Optional[str]:
        return self._primary_key + "=" + self._db.escape_dn(primary_key) + "," + self._dn

    def get_dns(self, primary_keys: List[str]) -> List[str]:
        return [self.get_dn(pk) for pk in primary_keys]

    def try_get_dns(self, primary_keys: List[str]) -> List[str]:
        dns = [self.try_get_dn(pk) for pk in primary_keys]
        return [dn for dn in dns if dn is not None]

    def get_primary_key(self, dn: str) -> str:
        if not dn.startswith(self._dn_prefix) or not dn.endswith(self._dn_suffix):
            raise falcon.HTTPBadRequest(
                description="Invalid dn {}, expected {}pk{}".format(dn, self._dn_prefix, self._dn_suffix)
            )
        pk = dn[len(self._dn_prefix):-len(self._dn_suffix)]
        if '=' in pk:
            raise falcon.HTTPBadRequest(
                description="Invalid dn {}, expected {}pk{}".format(dn, self._dn_prefix, self._dn_suffix)
            )
        return pk

    def try_get_primary_key(self, dn: str) -> Optional[str]:
        if not dn.startswith(self._dn_prefix) or not dn.endswith(self._dn_suffix):
            return None
        pk = dn[len(self._dn_prefix):-len(self._dn_suffix)]
        if '=' in pk:
            return None
        return pk

    def get_primary_keys(self, dns: List[str]) -> List[str]:
        pks = [self.get_primary_key(dn) for dn in dns]
        return [pk for pk in pks if pk is not None]

    def try_get_primary_keys(self, dns: List[str]) -> List[str]:
        pks = [self.try_get_primary_key(dn) for dn in dns]
        return [pk for pk in pks if pk is not None]
