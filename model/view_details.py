from abc import ABC, abstractmethod
from collections import OrderedDict
from typing import List, Set, Dict, Any, Union, cast

import falcon

from model.http_helper import HTTPBadRequestField
from model.view_field import ViewField, view_field_types
from model.db import LdapModlist, LdapAddlist, LdapMods, LdapFetch

import model.view


class ViewGroup(ABC):
    def __init__(self, key: str, config: dict, **overrides):
        config.update(**overrides)
        self.key = key
        self.type = config['type']
        self.title = config['title']

        self.config = OrderedDict([
            ('key', self.key),
            ('type', self.type),
            ('title', self.title),
        ])

    def init(self, all_views: Dict[str, 'model.view.View']):
        """
        Initialize this view.

        Args:
            all_views: Mapping of all views, such that other views can be references.
        """
        pass

    @abstractmethod
    def get_fetch(self, fetches: Set[str]):
        """
        Called to select which fields to fetch for getting the value of this field.

        Args:
            fetches: List of fetched attributes to be fetched.
        """
        ...

    @abstractmethod
    def get(self, fetches: LdapFetch) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
        """
        Called to get the json value of the field.

        Args:
            fetches: The fetched attributes.

        Returns:
            The fetched values
        """
        ...

    @abstractmethod
    def set_fetch(self, fetches: Set[str], assignments: Dict[str, Any]):
        """
        Called to select which fields to fetch for settings the value of this view.

        Args:
            fetches: List of fetched attributes.
            assignments: The requested assignments.
        """
        ...

    def set(self, fetches: LdapFetch, modlist: LdapModlist, assignments: Dict[str, Any]):
        """
        Set the value of the field by updating the modlist.

        Args:
            fetches: All fetches.
            modlist: The modlist.
            assignments: The requested assignments.
        """
        pass

    def create(self, fetches: LdapFetch, addlist: LdapAddlist, assignments: Dict[str, Any]):
        """
        Set the value of the field by updating the addlist.

        Args:
            fetches: All fetches.
            addlist: The addlist.
            assignments: The requested assignments.
        """
        pass

    def set_post(self, fetches: LdapFetch, assignments: Dict[str, Any], is_new: bool):
        """
        Sets external values if needed.

        Args:
            fetches: All fetches.
            assignments: The requested assignments.
            is_new: If true, a new object is about to be created
        """
        pass


class ViewGroupFields(ViewGroup):
    def __init__(self, key: str, config: dict, **overrides):
        super().__init__(key, config, **overrides)
        self.fields: List[ViewField] = [
            view_field_types[cfg['type']](key, cfg)
            for key, cfg in config['fields'].items()
        ]

        self.config.update(OrderedDict([
            ('fields', [field.config for field in self.fields]),
        ]))

    def init(self, all_views: Dict[str, 'model.view.View']):
        all_fields = {
            field.key: field
            for field in self.fields
        }
        for field in self.fields:
            field.init(all_views, all_fields)

    def get_fetch(self, fetches: Set[str]):
        for field in self.fields:
            try:
                field.get_fetch(fetches)
            except falcon.HTTPBadRequest as e:
                raise HTTPBadRequestField(e.title, e.description, field.key)

    def get(self, fetches: LdapFetch) -> Dict[str, Any]:
        res: Dict[str, Any] = OrderedDict()
        for field in self.fields:
            try:
                field.get(fetches, res)
            except falcon.HTTPBadRequest as e:
                raise HTTPBadRequestField(e.title, e.description, field.key)
        return res

    def set_fetch(self, fetches: Set[str], assignments: Dict[str, Any]):
        for field in self.fields:
            try:
                field.set_fetch(fetches, assignments)
            except falcon.HTTPBadRequest as e:
                raise HTTPBadRequestField(e.title, e.description, field.key)

    def set(self, fetches: LdapFetch, modlist: LdapModlist, assignments: Dict[str, Any]):
        for field in self.fields:
            try:
                field.set(fetches, modlist, assignments)
            except falcon.HTTPBadRequest as e:
                raise HTTPBadRequestField(e.title, e.description, field.key)

    def set_post(self, fetches: LdapFetch, assignments: Dict[str, Any], is_new: bool):
        for field in self.fields:
            try:
                field.set_post(fetches, assignments, is_new)
            except falcon.HTTPBadRequest as e:
                raise HTTPBadRequestField(e.title, e.description, field.key)

    def create(self, fetches: LdapFetch, modlist: LdapAddlist, assignments: Dict[str, Any]):
        for field in self.fields:
            try:
                field.create(fetches, modlist, assignments)
            except falcon.HTTPBadRequest as e:
                raise HTTPBadRequestField(e.title, e.description, field.key)


class ViewGroupMemberOf(ViewGroup):
    def __init__(self, key: str, config: dict, **overrides):
        super().__init__(key, config, **overrides)
        self.foreign_view_name: str = config['foreignView']
        self.foreign_view: 'model.view.View' = cast('model.view.View', None)
        self.field: str = config.get('field', 'memberOf')
        self.foreign_field: str = config.get('foreignField', 'member')
        self.writable: bool = config.get('writable', True)

        self.config.update(OrderedDict([
            ('field', self.field),
            ('foreignView', self.foreign_view_name),
            ('foreignField', self.foreign_field),
            ('writable', self.writable),
        ]))

    def init(self, all_views: Dict[str, 'model.view.View']):
        self.foreign_view = all_views[self.foreign_view_name]

    def get_fetch(self, fetches: Set[str]):
        fetches.add(self.field)

    def get(self, fetches: LdapFetch) -> List[Dict[str, Any]]:
        if self.field not in fetches.values:
            return []
        primary_keys = self.foreign_view.try_get_primary_keys([val for val in fetches.values[self.field]])
        return [self.foreign_view.get_list_entry_permitted(pk) for pk in primary_keys]

    def set_fetch(self, fetches: Set[str], assignments: Dict[str, Any]):
        if len(assignments.get('add', [])) > 0 or len(assignments.get('delete', [])) > 0:
            fetches.add(self.field)

    def set_post(self, fetches: LdapFetch, assignments: Dict[str, Any], is_new: bool):
        for add_ref in assignments.get('add', []):
            if not self.writable:
                raise falcon.HTTPBadRequest(description="Cannot write {}".format(self.key))
            if self.field not in fetches.values:
                fetches.values[self.field] = []
            foreign_dn = self.foreign_view.get_dn(add_ref)
            if foreign_dn not in fetches.values[self.field]:
                self.foreign_view.save_foreign_field(add_ref, {
                    self.foreign_field: [(LdapMods.ADD, [fetches.dn])]
                })
                fetches.values[self.field].append(foreign_dn)
        if self.field in fetches.values:
            for del_ref in assignments.get('delete', []):
                if not self.writable:
                    raise falcon.HTTPBadRequest(description="Cannot write {}".format(self.key))
                foreign_dn = self.foreign_view.get_dn(del_ref)
                if foreign_dn in fetches.values[self.field]:
                    self.foreign_view.save_foreign_field(del_ref, {
                        self.foreign_field: [(LdapMods.DELETE, [fetches.dn])]
                    })
                    fetches.values[self.field].remove(foreign_dn)


class ViewGroupMember(ViewGroup):
    def __init__(self, key: str, config: dict, **overrides):
        super().__init__(key, config, **overrides)
        self.foreign_view_name = config['foreignView']
        self.foreign_view: 'model.view.View' = cast('model.view.View', None)
        self.field: str = config.get('field', 'member')
        self.foreign_field: str = config.get('foreignField', 'memberOf')
        self.writable: bool = config.get('writable', True)

        self.config.update(OrderedDict([
            ('field', self.field),
            ('foreignView', self.foreign_view_name),
            ('foreignField', self.foreign_field),
            ('writable', self.writable),
        ]))

    def init(self, all_views: Dict[str, 'model.view.View']):
        self.foreign_view = all_views[self.foreign_view_name]

    def get_fetch(self, fetches: Set[str]):
        fetches.add(self.field)

    def get(self, fetches: LdapFetch) -> List[Dict[str, Any]]:
        if self.field not in fetches.values:
            return []
        primary_keys = self.foreign_view.try_get_primary_keys([val for val in fetches.values[self.field]])
        return [self.foreign_view.get_list_entry_permitted(pk) for pk in primary_keys]

    def set_fetch(self, fetches: Set[str], assignments: Dict[str, Any]):
        if len(assignments.get('add', [])) > 0 or len(assignments.get('delete', [])) > 0:
            fetches.add(self.field)

    def set(self, fetches: LdapFetch, modlist: LdapModlist, assignments: Dict[str, Any]):
        add_dns = [add_dn for add_dn in self.foreign_view.get_dns(assignments.get('add', []))]
        if add_dns:
            if not self.writable:
                raise falcon.HTTPBadRequest(description="Cannot write {}".format(self.key))
            if self.field not in modlist:
                modlist[self.field] = []
            add_dns = [add_dn for add_dn in add_dns if add_dn not in modlist[self.field]]
            modlist[self.field].append((LdapMods.ADD, add_dns))
            if self.field in fetches.values:
                fetches.values[self.field].extend(add_dns)
            else:
                fetches.values[self.field] = add_dns
        delete_dns = [delete_dn for delete_dn in self.foreign_view.get_dns(assignments.get('delete', []))]
        if delete_dns:
            if not self.writable:
                raise falcon.HTTPBadRequest(description="Cannot write {}".format(self.key))
            if self.field in fetches.values:
                if self.field not in modlist:
                    modlist[self.field] = []
                delete_dns = [delete_dn for delete_dn in delete_dns if delete_dn in fetches.values[self.field]]
                modlist[self.field].append((LdapMods.DELETE, delete_dns))
                for dn in delete_dns:
                    fetches.values[self.field].remove(dn)

    def create(self, fetches: LdapFetch, addlist: LdapAddlist, assignments: Dict[str, Any]):
        add_dns = [add_dn for add_dn in self.foreign_view.get_dns(assignments.get('add', []))]
        if assignments.get('delete', []):
            raise falcon.HTTPBadRequest(description="Cannot remove on creation")
        if len(add_dns) == 0:
            return
        if not self.writable:
            raise falcon.HTTPBadRequest(description="Cannot create {}".format(self.key))
        if self.field not in addlist:
            addlist[self.field] = add_dns
        else:
            addlist[self.field].extend(add_dns)
        if self.field in fetches.values:
            fetches.values[self.field].extend(add_dns)
        else:
            fetches.values[self.field] = add_dns


view_detail_types = {
    'fields': ViewGroupFields,
    'memberOf': ViewGroupMemberOf,
    'member': ViewGroupMember,
}


class ViewDetails:
    def __init__(self, config: dict):
        self.views: List[ViewGroup] = [
            view_detail_types[cfg['type']](key, cfg)
            for key, cfg in config.items()
        ]

        self.config = [view.config for view in self.views]

    def init(self, all_views: Dict[str, 'model.view.View']):
        for view in self.views:
            view.init(all_views)

    def get_fetch(self, fetches: Set[str]):
        for view in self.views:
            try:
                view.get_fetch(fetches)
            except HTTPBadRequestField as e:
                e.field = {view.key: e.field}
                raise
            except falcon.HTTPBadRequest as e:
                raise HTTPBadRequestField(e.title, e.description, view.key)

    def get(self, fetches: LdapFetch) -> Dict[str, Union[Dict[str, Any], List[str]]]:
        results: Dict[str, Union[Dict[str, Any], List[str]]] = dict()
        for view in self.views:
            try:
                results[view.key] = view.get(fetches)
            except HTTPBadRequestField as e:
                e.field = {view.key: e.field}
                raise
            except falcon.HTTPBadRequest as e:
                raise HTTPBadRequestField(e.title, e.description, view.key)
        return results

    def set_fetch(self, fetches: Set[str], assignments: Dict[str, Any]):
        for view in self.views:
            view_assignments = assignments.get(view.key)
            if view_assignments is not None:
                try:
                    view.set_fetch(fetches, view_assignments)
                except HTTPBadRequestField as e:
                    e.field = {view.key: e.field}
                    raise
                except falcon.HTTPBadRequest as e:
                    raise HTTPBadRequestField(e.title, e.description, view.key)

    def set(
            self, fetches: LdapFetch, modlist: LdapModlist,
            assignments: Dict[str, Dict[str, Any]]
    ):
        for view in self.views:
            view_assignments = assignments.get(view.key)
            if view_assignments is not None:
                try:
                    view.set(fetches, modlist, view_assignments)
                except HTTPBadRequestField as e:
                    e.field = {view.key: e.field}
                    raise
                except falcon.HTTPBadRequest as e:
                    raise HTTPBadRequestField(e.title, e.description, view.key)

    def create(
            self, fetches: LdapFetch, addlist: LdapAddlist,
            assignments: Dict[str, Dict[str, Any]]
    ):
        for view in self.views:
            view_assignments = assignments.get(view.key)
            if view_assignments is not None:
                try:
                    view.create(fetches, addlist, view_assignments)
                except HTTPBadRequestField as e:
                    e.field = {view.key: e.field}
                    raise
                except falcon.HTTPBadRequest as e:
                    raise HTTPBadRequestField(e.title, e.description, view.key)

    def set_post(
            self, fetches: LdapFetch, assignments: Dict[str, Dict[str, Any]], is_new: bool
    ):
        for view in self.views:
            view_assignments = assignments.get(view.key)
            if view_assignments is not None:
                try:
                    view.set_post(fetches, view_assignments, is_new)
                except HTTPBadRequestField as e:
                    e.field = {view.key: e.field}
                    raise
                except falcon.HTTPBadRequest as e:
                    raise HTTPBadRequestField(e.title, e.description, view.key)
