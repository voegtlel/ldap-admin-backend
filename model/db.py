from types import GeneratorType
from typing import List, Tuple, NewType, Dict, Union, Set

import falcon
import ldap3
from ldap3.core.exceptions import LDAPExceptionError

LdapValue = Union[int, float, bytes, bytearray, str]

LdapValueList = Union[LdapValue, List[LdapValue], Tuple[LdapValue], Set[LdapValue], GeneratorType]

LdapMod = NewType("LdapMod", str)


class LdapMods:
    ADD = LdapMod(ldap3.MODIFY_ADD)
    DELETE = LdapMod(ldap3.MODIFY_DELETE)
    REPLACE = LdapMod(ldap3.MODIFY_REPLACE)
    INCREMENT = LdapMod(ldap3.MODIFY_INCREMENT)


LdapModlist = NewType('LdapModlist', Dict[str, List[Tuple[LdapMod, LdapValueList]]])
LdapAddlist = NewType('LdapAddlist', Dict[str, LdapValueList])


class LdapFetch:
    def __init__(self, dn: str, values: Dict[str, List[str]]):
        self.dn = dn
        self.values = values

    @staticmethod
    def from_entry(entry: ldap3.Entry) -> 'LdapFetch':
        return LdapFetch(entry.entry_dn, entry.entry_attributes_as_dict)

    @staticmethod
    def from_entries(entries: List[ldap3.Entry]) -> List['LdapFetch']:
        return [LdapFetch.from_entry(entry) for entry in entries]


class FalconLdapError(falcon.HTTPBadRequest):
    def __init__(self, original_error: LDAPExceptionError):
        super().__init__(
            description="{} ({})".format(str(original_error), type(original_error).__name__)
        )
        self.original_error = original_error


class DatabaseFactory:
    def __init__(self, config: dict, **overrides):
        config.update(overrides)

        self._server = ldap3.Server(config['serverUri'])
        self.prefix: str = config['prefix']
        self._timeout: str = config['timeout']

        self._connection = self.connect(config['bindDn'], config['bindPassword'])

    def connect(self, user: str, password: str) -> ldap3.Connection:
        return ldap3.Connection(
            server=self._server,
            user=user,
            password=password,
            auto_bind=True,
            receive_timeout=self._timeout,
            raise_exceptions=True,
            client_strategy=ldap3.SYNC,
        )

    @property
    def connection(self) -> ldap3.Connection:
        return self._connection
