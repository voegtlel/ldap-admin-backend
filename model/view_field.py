import string
from abc import ABC, abstractmethod
from collections import OrderedDict
from datetime import datetime
from typing import Dict, Set, List, Any, Optional, Pattern, Callable, Iterable, cast

import dateutil.parser
import falcon
import passlib.hash
import passlib.pwd
import pwnedpasswords
import regex

import model
from model.db import LdapModlist, LdapMods, LdapAddlist, LdapFetch


class ViewField(ABC):
    def __init__(self, key: str, config: dict, **overrides):
        self.key = key
        config.update(overrides)
        self.title = config['title']
        self.type = config['type']
        self.required = config.get('required', False)
        self.creatable = config.get('creatable', True)
        self.readable = config.get('readable', True)
        self.writable = config.get('writable', True)
        self.hidden = config.get('hidden', False)

        self.config = OrderedDict([
            ('key', self.key),
            ('type', self.type),
            ('title', self.title),
            ('required', self.required),
            ('creatable', self.creatable),
            ('readable', self.readable),
            ('writable', self.writable),
            ('hidden', self.hidden),
        ])
    
    def _is_enabled(self, values: Dict[str, Any]):
        """
        Gets if this view is enabled depending on the values.
        
        Args:
            values: The values to check
        
        Returns:
            True, if the field is enabled
        """
        return self.key == '_enabled' or values.get('_enabled', True)

    def init(self, all_views: Dict[str, 'model.view.View'], all_fields: Dict[str, 'ViewField']):
        """
        Initializes this field.

        Args:
            all_views: All defined views.
            all_fields: Reference to all fields within the view.
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
    def get(self, fetches: LdapFetch, results: Dict[str, Any]):
        """
        Called to get the json value of the field.

        Args:
            fetches: The fetched attributes.
            results: The results to write to.
        """
        ...

    @abstractmethod
    def set_fetch(self, fetches: Set[str], assignments: Dict[str, Any]):
        """
        Called to select which fields to fetch for settings the value of this field.

        Args:
            fetches: List of fetched attributes.
            assignments: The requested assignments.
        """
        ...

    def set(self, fetches: LdapFetch, modlist: LdapModlist,
            assignments: Dict[str, Any]):
        """
        Set the value of the field by updating the modlist.

        Args:
            fetches: All fetches.
            modlist: The modlist.
            assignments: The requested assignments.
        """
        pass

    def create(self, fetches: LdapFetch, addlist: LdapAddlist,
               assignments: Dict[str, Any]):
        """
        Create the value of the field by updating the addlist.

        Args:
            fetches: All fetches.
            addlist: The addlist.
            assignments: The requested assignments.
        """
        pass

    def set_post(self, fetches: LdapFetch, assignments: Dict[str, Any], is_new: bool):
        """
        Set external values.

        Args:
            fetches: All fetches.
            assignments: The requested assignments.
            is_new: If true, a new object is about to be created
        """
        pass


class ViewFieldText(ViewField):
    def __init__(self, key: str, config: dict, **overrides):
        super().__init__(key, config, **overrides)
        if key == '_enabled':
            raise ValueError("Cannot use text as _enabled")

        self.field: str = config.get('field', self.key)
        self.format: Pattern = regex.compile(config.get('format', ''), regex.UNICODE)
        self.format_message: str = config.get('formatMessage', config.get('format', ''))

        self.enum = config.get('enum')
        self.enum_values = [value['value'] for value in self.enum] if self.enum is not None else None

        self.config.update(OrderedDict([
            ('field', self.field),
            ('format', config.get('formatJs', config.get('format', ''))),
            ('formatMessage', self.format_message),
            ('enum', [
                OrderedDict([('title', value['title']), ('value', value['value'])])
                for value in self.enum
            ] if self.enum is not None else None),
        ]))

    def get_fetch(self, fetches: Set[str]):
        if not self.readable:
            return
        fetches.add(self.field)

    def get(self, fetches: LdapFetch, results: Dict[str, Any]):
        if not self.readable or not self._is_enabled(results):
            return
        if self.field in fetches.values and len(fetches.values[self.field]) > 0:
            results[self.key] = fetches.values[self.field][0]

    def set_fetch(self, fetches: Set[str], assignments: Dict[str, Any]):
        if self.key not in assignments or not self._is_enabled(assignments):
            return
        if self.required and not assignments[self.key]:
            raise falcon.HTTPBadRequest(description="{} is required".format(self.key))
        if not self.writable:
            raise falcon.HTTPBadRequest(description="Cannot write {}".format(self.key))
        fetches.add(self.field)

    def set(self, fetches: LdapFetch, modlist: LdapModlist, assignments: Dict[str, Any]):
        if self.key not in assignments or not self._is_enabled(assignments):
            return
        if not self.writable:
            raise falcon.HTTPBadRequest(description="Cannot write {}".format(self.key))

        value = assignments[self.key]
        if value:
            if not self.format.fullmatch(value):
                raise falcon.HTTPBadRequest(description="Invalid value {} for {}, expecting {}".format(
                    assignments[self.key], self.key, self.format_message
                ))
            if self.enum_values is not None and value not in self.enum_values:
                raise falcon.HTTPBadRequest(
                    description="Value for {} must be one of: {}".format(self.key, ", ".join(self.enum_values))
                )

        if not value:
            if self.required:
                raise falcon.HTTPBadRequest(description="{} is required".format(self.key))
            if self.field in fetches.values:
                modlist[self.field] = [(LdapMods.DELETE, [])]
        elif self.field in fetches.values:
            fetch_val = fetches.values[self.field]
            if len(fetch_val) != 1 or fetch_val[0] != value:
                modlist[self.field] = [(LdapMods.REPLACE, [value])]
        else:
            modlist[self.field] = [(LdapMods.ADD, [value])]
        fetches.values[self.field] = [value]

    def create(self, fetches: LdapFetch, addlist: LdapAddlist, assignments: Dict[str, Any]):
        if self.key not in assignments:
            if self.required and self._is_enabled(assignments):
                raise falcon.HTTPBadRequest(description="{} is required".format(self.key))
            return
        if not self.creatable:
            raise falcon.HTTPBadRequest(description="Cannot create {}".format(self.key))

        value = assignments[self.key]
        if value:
            if not self.format.fullmatch(value):
                raise falcon.HTTPBadRequest(description="Invalid value {} for {}, expecting {}".format(
                    assignments[self.key], self.key, self.format_message
                ))
            if self.enum_values is not None and value not in self.enum_values:
                raise falcon.HTTPBadRequest(
                    description="Value for {} must be one of: {}".format(self.key, ", ".join(self.enum_values))
                )
        if self.field in fetches.values:
            raise falcon.HTTPBadRequest(description="Cannot modify value")
        if not value and self.required:
            raise falcon.HTTPBadRequest(description="{} is required".format(self.key))
        if value and self.enum_values is not None and value not in self.enum_values:
            raise falcon.HTTPBadRequest(
                description="Value for {} must be one of: {}".format(self.key, ", ".join(self.enum_values))
            )
        addlist[self.field] = [value]
        fetches.values[self.field] = [value]


class ViewFieldDateTime(ViewField):
    format = regex.compile(
        r'^(-?(?:[1-9][0-9]*)?[0-9]{4})-(1[0-2]|0[1-9])-(3[01]|0[1-9]|[12][0-9])'
        r'T(2[0-3]|[01][0-9]):([0-5][0-9]):([0-5][0-9])(\.[0-9]+)?'
        r'(Z|[+-](?:2[0-3]|[01][0-9]):[0-5][0-9])?$'
    )

    formatMessage = "ISO 8601"

    def __init__(self, key: str, config: dict, **overrides):
        super().__init__(key, config, **overrides)
        if key == '_enabled':
            raise ValueError("Cannot use datetime as _enabled")

        self.field: str = config.get('field', self.key)

        self.config.update(OrderedDict([
            ('field', self.field),
            ('format', self.format.pattern),
            ('formatMessage', self.formatMessage),
        ]))

    def get_fetch(self, fetches: Set[str]):
        if not self.readable:
            return
        fetches.add(self.field)

    def get(self, fetches: LdapFetch, results: Dict[str, Any]):
        if not self.readable or not self._is_enabled(results):
            return
        if self.field in fetches.values and len(fetches.values[self.field]) > 0:
            results[self.key] = cast(datetime, fetches.values[self.field][0]).isoformat()

    def set_fetch(self, fetches: Set[str], assignments: Dict[str, Any]):
        if self.key not in assignments or not self._is_enabled(assignments):
            return
        if self.required and not assignments[self.key]:
            raise falcon.HTTPBadRequest(description="{} is required".format(self.key))
        if not self.writable:
            raise falcon.HTTPBadRequest(description="Cannot write {}".format(self.key))
        fetches.add(self.field)

    def set(self, fetches: LdapFetch, modlist: LdapModlist, assignments: Dict[str, Any]):
        if self.key not in assignments or not self._is_enabled(assignments):
            return
        if not self.writable:
            raise falcon.HTTPBadRequest(description="Cannot write {}".format(self.key))

        value = assignments[self.key]
        if value and not self.format.fullmatch(value):
            raise falcon.HTTPBadRequest(description="Invalid value {} for {}, expecting ISO 8601".format(
                assignments[self.key], self.key,
            ))
        if not value:
            if self.required:
                raise falcon.HTTPBadRequest(description="{} is required".format(self.key))
            if self.field in fetches.values:
                modlist[self.field] = [(LdapMods.DELETE, [])]
        elif self.field in fetches.values:
            fetch_val = fetches.values[self.field]
            if len(fetch_val) != 1 or fetch_val[0] != value:
                modlist[self.field] = [(LdapMods.REPLACE, [dateutil.parser.isoparse(value)])]
        else:
            modlist[self.field] = [(LdapMods.ADD, [dateutil.parser.isoparse(value)])]
        fetches.values[self.field] = [value]

    def create(self, fetches: LdapFetch, addlist: LdapAddlist, assignments: Dict[str, Any]):
        if self.key not in assignments:
            if self.required and self._is_enabled(assignments):
                raise falcon.HTTPBadRequest(description="{} is required".format(self.key))
            return
        if not self.creatable:
            raise falcon.HTTPBadRequest(description="Cannot create {}".format(self.key))

        value = assignments[self.key]
        if value and not self.format.fullmatch(value):
            raise falcon.HTTPBadRequest(description="Invalid value {} for {}, expecting {}".format(
                assignments[self.key], self.key, self.format
            ))
        if self.field in fetches.values:
            raise falcon.HTTPBadRequest(description="Cannot modify value")
        if not value and self.required:
            raise falcon.HTTPBadRequest(description="{} is required".format(self.key))
        addlist[self.field] = [dateutil.parser.isoparse(value)]
        fetches.values[self.field] = [dateutil.parser.isoparse(value)]


class ViewFieldPassword(ViewField):
    def __init__(self, key: str, config: dict, **overrides):
        super().__init__(key, config, **overrides)
        if key == '_enabled':
            raise ValueError("Cannot use password as _enabled")

        self.field: str = config.get('field', self.key)
        self.auto_generate: bool = config.get('autoGenerate', False)
        self.hashing: Optional[Callable[[str], str]] = getattr(passlib.hash, 'ldap_' + config['hashing']).hash
        self.pwned_password_check: bool = config.get('pwnedPasswordCheck', False)

        self.config.update(OrderedDict([
            ('field', self.field),
            ('autoGenerate', self.auto_generate),
            ('hashing', config['hashing'])
        ]))

    def get_fetch(self, fetches: Set[str]):
        if not self.readable:
            return
        fetches.add(self.field)

    def get(self, fetches: LdapFetch, results: Dict[str, Any]):
        if not self.readable or not self._is_enabled(results):
            return
        if self.field in fetches.values and len(fetches.values[self.field]) > 0:
            passwd = fetches.values[self.field][0]
            if isinstance(passwd, bytes):
                passwd = passwd.decode()
            results[self.key] = passwd

    def set_fetch(self, fetches: Set[str], assignments: Dict[str, Any]):
        if self.key not in assignments or not self._is_enabled(assignments):
            return
        if self.required and not assignments[self.key]:
            raise falcon.HTTPBadRequest(description="{} is required".format(self.key))
        if not self.writable:
            raise falcon.HTTPBadRequest(description="Cannot write {}".format(self.key))
        fetches.add(self.field)

    def set(self, fetches: LdapFetch, modlist: LdapModlist, assignments: Dict[str, Any]):
        if self.key not in assignments or not self._is_enabled(assignments):
            return
        if not self.writable:
            raise falcon.HTTPBadRequest(description="Cannot write {}".format(self.key))
        if self.auto_generate and not assignments[self.key]:
            str_value = passlib.pwd.genword('secure')
        else:
            str_value = assignments[self.key]

        if self.pwned_password_check:
            if pwnedpasswords.check(str_value, plain_text=True):
                raise falcon.HTTPBadRequest(description="Password is in list of leaked passwords, not accepted")

        value = self.hashing(str_value)
        if not value:
            if self.required and self._is_enabled(assignments):
                raise falcon.HTTPBadRequest(description="{} is required".format(self.key))
            if self.field in fetches.values:
                modlist[self.field] = [(LdapMods.DELETE, [])]
        elif self.field in fetches.values:
            fetch_val = fetches.values[self.field]
            if len(fetch_val) != 1 or fetch_val[0] != value:
                modlist[self.field] = [(LdapMods.REPLACE, [value])]
        else:
            modlist[self.field] = [(LdapMods.ADD, [value])]
        fetches.values[self.field] = [value]

    def create(self, fetches: LdapFetch, addlist: LdapAddlist, assignments: Dict[str, Any]):
        if self.key not in assignments:
            if self.required and self._is_enabled(assignments):
                raise falcon.HTTPBadRequest(description="{} is required".format(self.key))
            return
        if not self.creatable:
            raise falcon.HTTPBadRequest(description="Cannot create {}".format(self.key))
        if self.auto_generate and not assignments[self.key]:
            str_value = passlib.pwd.genword('secure')
        else:
            str_value = assignments[self.key]

        if self.pwned_password_check:
            if pwnedpasswords.check(str_value, plain_text=True):
                raise falcon.HTTPBadRequest(description="Password is in list of leaked passwords, not accepted")

        value = self.hashing(str_value)
        if self.field in fetches.values:
            raise falcon.HTTPBadRequest("Cannot modify value")
        if not value and self.required:
            raise falcon.HTTPBadRequest(description="{} is required".format(self.key))
        addlist[self.field] = [value]
        fetches.values[self.field] = [value]


class FieldNameExtractorFormatter(string.Formatter):
    def __init__(self):
        super().__init__()
        self.fields: Set[str] = set()

    def get_value(self, key, args, kwargs):
        self.fields.add(key)
        return ""

    def format_field(self, value, format_spec):
        return value

    def convert_field(self, value, conversion):
        return value


class ViewFieldGenerate(ViewField):
    def __init__(self, key: str, config: dict, **overrides):
        super().__init__(key, config, **overrides)
        if key == '_enabled':
            raise ValueError("Cannot use generator as _enabled")

        self.field: str = config.get('field', self.key)
        self.format: str = config.get('format')
        name_extractor = FieldNameExtractorFormatter()
        name_extractor.format(self.format)
        self.input_field_names: Iterable[str] = name_extractor.fields
        self.input_fields: List[ViewField] = []

        self.config.update(OrderedDict([
            ('field', self.field),
            ('format', config.get('formatJs', config.get('format', '')))
        ]))

    def init(self, all_views: Dict[str, 'model.view.View'], all_fields: Dict[str, 'ViewField']):
        self.input_fields = [
            all_fields[key] for key in self.input_field_names
        ]

    def get_fetch(self, fetches: Set[str]):
        if not self.readable:
            return
        fetches.add(self.field)

    def get(self, fetches: LdapFetch, results: Dict[str, Any]):
        if not self.readable or not self._is_enabled(results):
            return
        if self.field in fetches.values and len(fetches.values[self.field]) > 0:
            results[self.key] = fetches.values[self.field][0]

    def set_fetch(self, fetches: Set[str], assignments: Dict[str, Any]):
        if self.key in assignments:
            raise falcon.HTTPBadRequest(description="Cannot assign value to generated field {}".format(self.key))
        if not self.writable or not self._is_enabled(assignments):
            return
        if any(field in assignments for field in self.input_field_names):
            for input_field in self.input_fields:
                input_field.get_fetch(fetches)
            fetches.add(self.field)

    def set(self, fetches: LdapFetch, modlist: LdapModlist, assignments: Dict[str, Any]):
        if self.key in assignments:
            raise falcon.HTTPBadRequest(description="Cannot assign value to generated field {}".format(self.key))
        if not self.writable or not self._is_enabled(assignments):
            return
        if not any(field in assignments for field in self.input_field_names):
            return

        format_args: Dict[str, Any] = dict()
        for input_field in self.input_fields:
            if input_field.key in assignments:
                format_args[input_field.key] = assignments[input_field.key]
            else:
                input_field.get(fetches, format_args)
        value = self.format.format(**format_args)
        if not value:
            if self.field in fetches.values:
                modlist[self.field] = [(LdapMods.DELETE, [])]
        elif self.field in fetches.values:
            fetch_val = fetches.values[self.field]
            if len(fetch_val) != 1 or fetch_val[0] != value:
                modlist[self.field] = [(LdapMods.REPLACE, [value])]
        else:
            modlist[self.field] = [(LdapMods.ADD, [value])]
        fetches.values[self.field] = [value]

    def create(self, fetches: LdapFetch, addlist: LdapAddlist, assignments: Dict[str, Any]):
        if self.key in assignments:
            raise falcon.HTTPBadRequest(description="Cannot assign value to generated field {}".format(self.key))
        if not self.creatable or not self._is_enabled(assignments):
            return
        
        format_args: Dict[str, Any] = dict()
        for input_field in self.input_fields:
            if input_field.key in assignments:
                format_args[input_field.key] = assignments[input_field.key]
            else:
                input_field.get(fetches, format_args)
        value = self.format.format(**format_args)
        if self.field in fetches.values:
            raise falcon.HTTPBadRequest("Cannot modify value")
        if not value and self.required:
            raise falcon.HTTPBadRequest(description="{} is required".format(self.key))
        addlist[self.field] = [value]
        fetches.values[self.field] = [value]


class ViewFieldIsMemberOf(ViewField):
    def __init__(self, key: str, config: dict, **overrides):
        super().__init__(key, config, **overrides)
        self.member_of_name: str = config['memberOf']
        self.member_of_dn: bytes = cast(bytes, None)
        self.field: str = config.get('field', 'memberOf')
        self.foreign_view_name: str = config['foreignView']
        self.foreign_view: 'model.view.View' = cast('model.view.View', None)
        self.foreign_field: str = config.get('foreignField', 'member')

        self.config.update(OrderedDict([
            ('field', self.field),
            ('memberOf', self.member_of_name),
            ('foreignView', self.foreign_view_name),
            ('foreignField', self.foreign_field),
        ]))

    def init(self, all_views: Dict[str, 'model.view.View'], all_fields: Dict[str, 'ViewField']):
        self.foreign_view = all_views[self.foreign_view_name]
        self.member_of_dn = self.foreign_view.get_dn(self.member_of_name)

    def get_fetch(self, fetches: Set[str]):
        if not self.readable:
            return
        fetches.add(self.field)

    def get(self, fetches: LdapFetch, results: Dict[str, Any]):
        if not self.readable or not self._is_enabled(results):
            return
        
        results[self.key] = self.member_of_dn in fetches.values.get(self.field, ())

    def set_fetch(self, fetches: Set[str], assignments: Dict[str, Any]):
        if self.key not in assignments or not self._is_enabled(assignments):
            if self.key == '_enabled':
                fetches.add(self.field)
            return
        if self.required and not assignments[self.key]:
            raise falcon.HTTPBadRequest(description="{} is required".format(self.key))
        if not self.writable:
            raise falcon.HTTPBadRequest(description="Cannot write {}".format(self.key))
        fetches.add(self.field)

    def set_post(self, fetches: LdapFetch, assignments: Dict[str, Any], is_new: bool):
        if self.key not in assignments:
            if is_new and self.required and self._is_enabled(assignments):
                raise falcon.HTTPBadRequest(description="{} is required".format(self.key))
            if self.key == '_enabled':
                assignments[self.key] = self.member_of_dn in fetches.values.get(self.field, ())
            return
        if not (is_new and self.creatable) and not self.writable:
            raise falcon.HTTPBadRequest(description="Cannot write {}".format(self.key))

        if self.field not in fetches.values:
            fetches.values[self.field] = []
        is_member = self.member_of_dn in fetches.values[self.field]
        if is_member == assignments[self.key]:
            return

        if assignments[self.key]:
            self.foreign_view.save_foreign_field(self.member_of_name, {
                self.foreign_field: [(LdapMods.ADD, [fetches.dn])]
            })
            fetches.values[self.field].append(self.member_of_dn)
        else:
            self.foreign_view.save_foreign_field(self.member_of_name, {
                self.foreign_field: [(LdapMods.DELETE, [fetches.dn])]
            })
            if self.field not in fetches.values:
                fetches.values[self.field] = []
            fetches.values[self.field].remove(self.member_of_dn)


class ViewFieldInitial(ViewField):
    def __init__(self, key: str, config: dict, **overrides):
        super().__init__(key, config, **overrides)
        self.value = config['value']
        assert self.creatable
        self.target = view_field_types[config['target']['type']](config['target']['key'], config['target'])

        self.config.update(OrderedDict([
            ('value', self.value),
            ('target', self.target.config),
        ]))

    def init(self, all_views: Dict[str, 'model.view.View'], all_fields: Dict[str, 'ViewField']):
        self.target.init(all_views, all_fields)

    def get_fetch(self, fetches: Set[str]):
        pass

    def get(self, fetches: LdapFetch, results: Dict[str, Any]):
        pass

    def set_fetch(self, fetches: Set[str], assignments: Dict[str, Any]):
        pass

    def set(self, fetches: LdapFetch, modlist: LdapModlist, assignments: Dict[str, Any]):
        pass

    def create(self, fetches: LdapFetch, addlist: LdapAddlist, assignments: Dict[str, Any]):
        if assignments[self.key]:
            raise falcon.HTTPBadRequest("Cannot assign {}".format(self.key))
        if not self._is_enabled(assignments):
            return
        assignments[self.target.key] = self.value
        self.target.create(fetches, addlist, assignments)

    def set_post(self, fetches: LdapFetch, assignments: Dict[str, Any], is_new: bool):
        if not is_new:
            pass
        if assignments[self.key]:
            raise falcon.HTTPBadRequest("Cannot assign {}".format(self.key))
        if not self._is_enabled(assignments):
            return
        assignments[self.target.key] = self.value
        self.target.set_post(fetches, assignments, is_new)


class ViewFieldObjectClass(ViewField):
    def __init__(self, key: str, config: dict, **overrides):
        super().__init__(key, config, **overrides)
        self.object_class: str = config['objectClass']
        self.field: str = config.get('field', 'objectClass')

        self.config.update(OrderedDict([
            ('field', self.field),
            ('objectClass', self.object_class),
        ]))

    def get_fetch(self, fetches: Set[str]):
        if not self.readable:
            return
        fetches.add(self.field)

    def get(self, fetches: LdapFetch, results: Dict[str, Any]):
        if not self.readable or not self._is_enabled(results):
            return

        results[self.key] = self.object_class in fetches.values.get(self.field, ())

    def set_fetch(self, fetches: Set[str], assignments: Dict[str, Any]):
        if self.key not in assignments or not self._is_enabled(assignments):
            if self.key == '_enabled':
                fetches.add(self.field)
            return
        if self.required and not assignments[self.key]:
            raise falcon.HTTPBadRequest(description="{} is required".format(self.key))
        if not self.writable:
            raise falcon.HTTPBadRequest(description="Cannot write {}".format(self.key))
        fetches.add(self.field)

    def set(self, fetches: LdapFetch, modlist: LdapModlist, assignments: Dict[str, Any]):
        if self.key not in assignments or not self._is_enabled(assignments):
            if self.key == '_enabled':
                assignments[self.key] = self.object_class in fetches.values.get(self.field, ())
            return
        if not self.writable:
            raise falcon.HTTPBadRequest(description="Cannot write {}".format(self.key))

        field_value = fetches.values.get(self.field)
        value = assignments[self.key]
        if not value:
            if field_value is not None and self.object_class in field_value:
                modlist[self.field] = [(LdapMods.DELETE, [self.object_class])]
                field_value.remove(self.object_class)
        elif field_value is None or self.object_class not in field_value:
            modlist[self.field] = [(LdapMods.ADD, [self.object_class])]
            if field_value is None:
                fetches.values[self.field] = [self.object_class]
            else:
                fetches.values[self.field].append(self.object_class)

    def create(self, fetches: LdapFetch, addlist: LdapAddlist, assignments: Dict[str, Any]):
        if self.key not in assignments:
            if self.required and self._is_enabled(assignments):
                raise falcon.HTTPBadRequest(description="{} is required".format(self.key))
            if self.key == '_enabled':
                assignments[self.key] = False
            return
        if not self.creatable:
            raise falcon.HTTPBadRequest(description="Cannot create {}".format(self.key))

        if assignments[self.key]:
            new_value = addlist[self.field]
            if self.field in addlist:
                if isinstance(new_value, list):
                    new_value.append(self.object_class)
                else:
                    addlist[self.field] = [new_value, self.object_class]
            else:
                addlist[self.field] = [self.object_class]
            if self.field in fetches.values:
                fetches.values[self.field].append(self.object_class)
            else:
                fetches.values[self.field] = [self.object_class]


view_field_types = {
    'text': ViewFieldText,
    'datetime': ViewFieldDateTime,
    'generate': ViewFieldGenerate,
    'isMemberOf': ViewFieldIsMemberOf,
    'password': ViewFieldPassword,
    'initial': ViewFieldInitial,
    'objectClass': ViewFieldObjectClass,
}
