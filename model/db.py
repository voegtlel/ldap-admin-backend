import falcon
import ldap
from enum import Enum
from typing import Dict, List, Tuple, Optional


LdapSearchEntity = Tuple[str, Dict[str, List[bytes]]]


class Mod(Enum):
    ADD = ldap.MOD_ADD
    DELETE = ldap.MOD_DELETE
    REPLACE = ldap.MOD_REPLACE


LdapModlist = List[Tuple[Mod, str, Optional[List[bytes]]]]

LdapAddlist = List[Tuple[str, Optional[List[bytes]]]]


class Scope(Enum):
    BASE = ldap.SCOPE_BASE
    ONELEVEL = ldap.SCOPE_ONELEVEL
    SUBORDINATE = ldap.SCOPE_SUBORDINATE
    SUBTREE = ldap.SCOPE_SUBTREE


class LdapError(falcon.HTTPBadRequest):
    def __init__(self, original_error: ldap.LDAPError):
        super(LdapError, self).__init__(
            description="{} ({})".format(str(original_error), type(original_error).__name__)
        )
        self.original_error = original_error


class Database:
    def __init__(self, config: dict, **overrides):
        config.update(overrides)

        self._uri: str = config['serverUri']
        self._ldap = ldap.initialize(self._uri)
        self._ldap.timeout = config['timeout']

        self._prefix: str = config['prefix']

        self._ldap.bind_s(config['bindDn'], config['bindPassword'])

    def _get_modlist(self, modlist: LdapModlist) -> List[Tuple[int, str, Optional[List[bytes]]]]:
        return [(a.value, b, c) for a, b, c in modlist]

    def create(self, dn: str, addlist: LdapAddlist):
        """
        Create a new entity
        Args:
            dn: DN of the new entity
            addlist: The addlist
        """
        try:
            self._ldap.add_s(dn, addlist)
        except ldap.LDAPError as e:
            raise LdapError(e)

    def search(
            self, base: str, scope: Scope, filterstr: str = None, attrlist: List[str] = None
    ) -> List[LdapSearchEntity]:
        """
        Search for entities.

        Args:
            base: The base dn to search at
            scope: The scope of the search
            filterstr: The filter string.
            attrlist: A list of attributes to select

        Returns:
            The found entities
        """
        try:
            return self._ldap.search_s(base, scope.value, filterstr, attrlist)
        except ldap.LDAPError as e:
            raise LdapError(e)

    def get(
            self, dn: str, attrlist: List[str] = None
    ) -> LdapSearchEntity:
        """
        Search for exactly one entity, which must exist.

        Args:
            dn: The entity to retrieve
            attrlist: A list of attributes to select

        Returns:
            The requested entity
        """
        result = self.search(dn, Scope.BASE, None, attrlist)
        if len(result) == 0:
            raise falcon.HTTPNotFound(description="No entity for {}".format(dn))
        if len(result) > 1:
            raise falcon.HTTPBadRequest(description="Got more than one entity for {}".format(dn))
        return result[0]

    def update(self, dn: str, modlist: LdapModlist):
        """
        Update the dn entity with modlist.
        Args:
            dn: The entity
            modlist: The modlist
        """
        try:
            self._ldap.modify_s(dn, self._get_modlist(modlist))
        except ldap.LDAPError as e:
            raise LdapError(e)

    def delete(self, dn: str):
        """
        Delete by dn.
        Args:
            dn: The dn to delete
        """
        try:
            self._ldap.delete_s(dn)
        except ldap.LDAPError as e:
            raise LdapError(e)

    def escape_dn(self, s: str) -> str:
        """
        Escapes the given string usable for a dn name.

        Args:
            s: The dn string to escape

        Returns:
            The escaped string
        """
        return ldap.dn.escape_dn_chars(s)

    def verify_password(self, dn: str, password: str) -> bool:
        """
        Verifies that the given password is correct for the given dn entity.
        Args:
            dn: The entity to check the password for.
            password: The password to check.

        Returns:
            True if verified successfully. False if authentication failed.
        """
        if not password:
            return False
        bind_ldap = ldap.initialize(self._uri)
        try:
            bind_ldap.bind_s(dn, password)
        except ldap.INVALID_CREDENTIALS:
            return False
        finally:
            bind_ldap.unbind_s()
        return True

    @property
    def prefix(self) -> str:
        return self._prefix
