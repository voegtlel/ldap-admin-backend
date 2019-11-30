import re
from datetime import datetime
from typing import Dict, List, Sequence, Union

import ldap3
import passlib.hash
from ldap3.core.exceptions import LDAPInvalidCredentialsResult, LDAPNoSuchObjectResult

from model.db import LdapModlist, LdapMods

ValueType = Union[str, int, bytes, datetime]


class MockResult:
    def __init__(self, entry_dn: str, attributes: Dict[str, List[ValueType]]):
        self.entry_dn = entry_dn
        self.entry_attributes_as_dict = attributes


class MockConnection:
    def __init__(self, user: str, data: Dict[str, Dict[str, List[ValueType]]], mod_timestamp: datetime = None):
        self.user = user
        self.data = data

        self.mod_timestamp = mod_timestamp

        self.entries: List[MockResult] = []

        self._filter_re = re.compile(r'\(&(\(objectClass=([^)]+)\))+\)')
        self._email_filter_re = re.compile(r'\(&(\(objectClass=([^)]+)\))+(\(mail=(?P<mail>[^)]+)\))\)')

    def _add_member(self, owner_dn: str, member_dn: str):
        member = self.data.get(owner_dn)
        if 'memberOf' in member:
            member['memberOf'].append(member_dn)
        else:
            member['memberOf'] = [member_dn]

    def _remove_member(self, owner_dn: str, member_dn: str):
        member = self.data.get(owner_dn)
        if 'memberOf' in member:
            member['memberOf'].remove(member_dn)

    def _copy_keys(self, obj: Dict[str, List[ValueType]], keys: Sequence[str] = None) -> Dict[str, List[ValueType]]:
        if keys is None:
            return {
                key: list(value)
                for key, value in obj.items()
            }
        else:
            return {
                key: list(obj[key]) if key in obj else []
                for key in keys
            }

    def add(self, dn, object_class: Union[str, List[str]] = None, attributes: Dict[str, Union[List[ValueType], ValueType]] = None):
        # ldap3.Connection.add()
        assert dn not in self.data
        obj = {
            key: list(attribute)
            if isinstance(attribute, list) else
            [attribute]
            for key, attribute in {'objectClass': object_class, **attributes}.items()
        }
        if 'member' in obj:
            for member_dn in obj['member']:
                self._add_member(member_dn, dn)
        if self.mod_timestamp is None:
            obj['modifyTimestamp'] = [datetime.now()]
        else:
            obj['modifyTimestamp'] = [self.mod_timestamp]
        self.data[dn] = obj

    def search(
            self, search_base: str, search_filter: str, search_scope=ldap3.SUBTREE, attributes: Sequence[str] = None
    ):
        # ldap3.Connection.search()
        self.entries = []
        mail_filter = self._email_filter_re.fullmatch(search_filter)
        if search_filter == '(objectClass=*)' or self._filter_re.fullmatch(search_filter) or mail_filter:
            if search_scope == ldap3.BASE:
                if search_base not in self.data:
                    raise LDAPNoSuchObjectResult(f'Object {search_base} not in data')
                self.entries.append(MockResult(search_base, self._copy_keys(self.data[search_base], attributes)))
            elif search_scope == ldap3.LEVEL:
                if mail_filter:
                    mail = mail_filter.group('mail')
                else:
                    mail = None
                for key, data in self.data.items():
                    if key.endswith("," + search_base) and mail is None or mail in data.get('mail', ()):
                        self.entries.append(MockResult(key, self._copy_keys(data, attributes)))
            else:
                raise NotImplemented()
        else:
            raise NotImplemented()

    def modify(self, dn: str, changes: LdapModlist):
        # ldap3.Connection.modify()
        entry = self.data[dn]
        for key, item_changes in changes.items():
            data = entry.get(key)
            for (change, value) in item_changes:
                if change == LdapMods.ADD:
                    if data is None:
                        data = list(value)
                        entry[key] = data
                    else:
                        data.extend(value)
                    if key == 'member':
                        for member_dn in value:
                            self._add_member(member_dn, dn)
                elif change == LdapMods.DELETE:
                    if data is not None:
                        if not value:
                            if key == 'member':
                                for member_dn in entry[key]:
                                    self._remove_member(member_dn, dn)
                            del entry[key]
                        else:
                            if key == 'member':
                                for member_dn in value:
                                    self._remove_member(member_dn, dn)
                            for val in value:
                                entry[key].remove(val)
                            if len(entry[key]) == 0:
                                del entry[key]
                elif change == LdapMods.REPLACE:
                    if key == 'member':
                        for member_dn in entry[key]:
                            self._remove_member(member_dn, dn)
                    data = list(value)
                    entry[key] = data
                    if key == 'member':
                        for member_dn in value:
                            self._add_member(member_dn, dn)
                elif change == LdapMods.INCREMENT:
                    if data is None:
                        data = [0]
                        entry[key] = data
                    else:
                        data[0] += 1
        if self.mod_timestamp is None:
            entry['modifyTimestamp'] = [datetime.now()]
        else:
            entry['modifyTimestamp'] = [self.mod_timestamp]

    def delete(self, dn: str):
        # ldap3.Connection.delete()
        if 'member' in self.data[dn]:
            for member_dn in self.data[dn]['member']:
                self._remove_member(member_dn, dn)
        del self.data[dn]


class MockDatabaseFactory:
    def __init__(self, config: dict, mod_timestamp: datetime = None):
        self.data: Dict[str, Dict[str, List[ValueType]]] = {}

        self.prefix: str = config['prefix']
        self._timeout: int = int(config['timeout'])

        self._connection = MockConnection(
            user=config['bindDn'],
            data=self.data,
            mod_timestamp=mod_timestamp,
        )

    def connect(self, user: str, password: str) -> MockConnection:
        user_data = self.data.get(user)
        if user_data is None:
            raise LDAPInvalidCredentialsResult()
        user_passwords = user_data.get('userPassword')
        if user_passwords is None:
            raise LDAPInvalidCredentialsResult()
        if not any(passlib.hash.ldap_salted_sha1.verify(password, user_password) for user_password in user_passwords):
            raise LDAPInvalidCredentialsResult()
        return MockConnection(
            user=user,
            data=self.data,
        )

    @property
    def connection(self) -> MockConnection:
        return self._connection
