from abc import ABC, abstractmethod
from collections import OrderedDict
from typing import List, Set, Dict, Any, Union, cast

from model.view_field import ViewField, view_field_types
from model.db import LdapModlist, Mod, LdapSearchEntity, LdapAddlist

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
    def get(self, fetches: LdapSearchEntity) -> Union[Dict[str, Any], List[str]]:
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

    def set(self, fetches: LdapSearchEntity, modlist: LdapModlist, assignments: Dict[str, Any]):
        """
        Set the value of the field by updating the modlist.

        Args:
            fetches: All fetches.
            modlist: The modlist.
            assignments: The requested assignments.
        """
        pass

    def create(self, fetches: LdapSearchEntity, addlist: LdapAddlist, assignments: Dict[str, Any]):
        """
        Set the value of the field by updating the addlist.

        Args:
            fetches: All fetches.
            addlist: The addlist.
            assignments: The requested assignments.
        """
        pass

    def set_post(self, fetches: LdapSearchEntity, assignments: Dict[str, Any], is_new: bool):
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
            field.get_fetch(fetches)

    def get(self, fetches: LdapSearchEntity) -> Dict[str, Any]:
        res: Dict[str, Any] = OrderedDict()
        for field in self.fields:
            field.get(fetches, res)
        return res

    def set_fetch(self, fetches: Set[str], assignments: Dict[str, Any]):
        for field in self.fields:
            field.set_fetch(fetches, assignments)

    def set(self, fetches: LdapSearchEntity, modlist: LdapModlist, assignments: Dict[str, Any]):
        for field in self.fields:
            field.set(fetches, modlist, assignments)

    def set_post(self, fetches: LdapSearchEntity, assignments: Dict[str, Any], is_new: bool):
        for field in self.fields:
            field.set_post(fetches, assignments, is_new)

    def create(self, fetches: LdapSearchEntity, modlist: LdapAddlist, assignments: Dict[str, Any]):
        for field in self.fields:
            field.create(fetches, modlist, assignments)


class ViewGroupMemberOf(ViewGroup):
    def __init__(self, key: str, config: dict, **overrides):
        super().__init__(key, config, **overrides)
        self.foreign_view_name: str = config['foreignView']
        self.foreign_view: 'model.view.View' = cast('model.view.View', None)
        self.field: str = config.get('field', 'memberOf')
        self.foreign_field: str = config.get('foreignField', 'member')

        self.config.update(OrderedDict([
            ('field', self.field),
            ('foreignView', self.foreign_view_name),
            ('foreignField', self.foreign_field),
        ]))

    def init(self, all_views: Dict[str, 'model.view.View']):
        self.foreign_view = all_views[self.foreign_view_name]

    def get_fetch(self, fetches: Set[str]):
        fetches.add(self.field)

    def get(self, fetches: LdapSearchEntity) -> List[str]:
        dn, fetch = fetches
        if self.field not in fetch:
            return []
        return self.foreign_view.try_get_primary_keys([val.decode() for val in fetch[self.field]])

    def set_fetch(self, fetches: Set[str], assignments: Dict[str, Any]):
        pass

    def set_post(self, fetches: LdapSearchEntity, assignments: Dict[str, Any], is_new: bool):
        dn, fetch = fetches

        for add_ref in assignments.get('add', []):
            self.foreign_view.save_foreign_field(add_ref, [
                (Mod.ADD, self.foreign_field, [dn.encode()])
            ])
        for add_ref in assignments.get('delete', []):
            self.foreign_view.save_foreign_field(add_ref, [
                (Mod.DELETE, self.foreign_field, [dn.encode()])
            ])


class ViewGroupMember(ViewGroup):
    def __init__(self, key: str, config: dict, **overrides):
        super().__init__(key, config, **overrides)
        self.foreign_view_name = config['foreignView']
        self.foreign_view: 'model.view.View' = cast('model.view.View', None)
        self.field: str = config.get('field', 'member')
        self.foreign_field: str = config.get('foreignField', 'memberOf')

        self.config.update(OrderedDict([
            ('field', self.field),
            ('foreignView', self.foreign_view_name),
            ('foreignField', self.foreign_field),
        ]))

    def init(self, all_views: Dict[str, 'model.view.View']):
        self.foreign_view = all_views[self.foreign_view_name]

    def get_fetch(self, fetches: Set[str]):
        fetches.add(self.field)

    def get(self, fetches: LdapSearchEntity) -> List[str]:
        dn, fetch = fetches
        if self.field not in fetch:
            return []
        return self.foreign_view.try_get_primary_keys([val.decode() for val in fetch[self.field]])

    def set_fetch(self, fetches: Set[str], assignments: Dict[str, Any]):
        pass

    def set(self, fetches: LdapSearchEntity, modlist: LdapModlist, assignments: Dict[str, Any]):
        add_dns = [add_dn.encode() for add_dn in self.foreign_view.get_dns(assignments.get('add', []))]
        if add_dns:
            modlist.append((Mod.ADD, self.field, add_dns))
        delete_dns = [delete_dn.encode() for delete_dn in self.foreign_view.get_dns(assignments.get('delete', []))]
        if delete_dns:
            modlist.append((Mod.DELETE, self.field, delete_dns))

    def create(self, fetches: LdapSearchEntity, addlist: LdapAddlist, assignments: Dict[str, Any]):
        add_dns = [add_dn.encode() for add_dn in self.foreign_view.get_dns(assignments.get('add', []))]
        if assignments.get('delete', []):
            raise ValueError("Cannot remove on creation")
        if len(add_dns) == 0:
            return
        add_entry = None
        for entry in addlist:
            if entry[0] == self.field:
                add_entry = entry
        if add_entry is None:
            addlist.append((self.field, add_dns))
        else:
            add_entry[1].extend(add_dns)


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
            view.get_fetch(fetches)

    def get(self, fetches: LdapSearchEntity) -> Dict[str, Union[Dict[str, Any], List[str]]]:
        results: Dict[str, Union[Dict[str, Any], List[str]]] = dict()
        for view in self.views:
            results[view.key] = view.get(fetches)
        return results

    def set_fetch(self, fetches: Set[str], assignments: Dict[str, Any]):
        for view in self.views:
            view_assignments = assignments.get(view.key)
            if view_assignments is not None:
                view.set_fetch(fetches, view_assignments)

    def set(
            self, fetches: LdapSearchEntity, modlist: LdapModlist,
            assignments: Dict[str, Dict[str, Any]]
    ):
        for view in self.views:
            view_assignments = assignments.get(view.key)
            if view_assignments is not None:
                view.set(fetches, modlist, view_assignments)

    def create(
            self, fetches: LdapSearchEntity, addlist: LdapAddlist,
            assignments: Dict[str, Dict[str, Any]]
    ):
        for view in self.views:
            view_assignments = assignments.get(view.key)
            if view_assignments is not None:
                view.create(fetches, addlist, view_assignments)

    def set_post(
            self, fetches: LdapSearchEntity, assignments: Dict[str, Dict[str, Any]], is_new: bool
    ):
        for view in self.views:
            view_assignments = assignments.get(view.key)
            if view_assignments is not None:
                view.set_post(fetches, view_assignments, is_new)
