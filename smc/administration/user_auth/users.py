#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.
"""
.. versionadded:: 0.6.2
    Requires SMC >= 6.4.3

The Users module provides an interface to user specific related elements such
as External LDAP domains, Internal domains and external/internal users and
external/internal groups.

Example of browsing all available external ldap user domains::

    >>> from smc.administration.user_auth.users import ExternalLdapUserDomain
    >>> for domain in ExternalLdapUserDomain.objects.all():
    ...   domain
    ...
    ExternalLdapUserDomain(name=ud)

If you know the name of the domain or want to load it directly, do so like other elements::

    >>> ldap = ExternalLdapUserDomain('ud')
    >>> ldap.ldap_server
    [ActiveDirectoryServer(name=dc)]

Find all groups in a specified LDAP domain::

    >>> ldap
    ExternalLdapUserDomain(name=ud)
    >>> ldap.browse()
    [ExternalLdapUserGroup(name=Computers), ExternalLdapUserGroup(name=Domain Controllers),
     ExternalLdapUserGroup(name=ForeignSecurityPrincipals),
     ExternalLdapUserGroup(name=Managed Service Accounts),
     ExternalLdapUserGroup(name=Program Data), ExternalLdapUserGroup(name=System),
     ExternalLdapUserGroup(name=Users),
     ExternalLdapUserGroup(name=resource users)]

Find all users in specific LDAP user group::

    >>> for group in ldap.browse():
    ...   if group.name == 'Users':
    ...     group.browse()
    ...
    [ExternalLdapUser(name=Administrator),
     ExternalLdapUserGroup(name=Allowed RODC Password Replication Group),
     ExternalLdapUserGroup(name=Cert Publishers), ExternalLdapUserGroup(name=Cisco ISE Wireless),
     ExternalLdapUserGroup(name=Cloneable Domain Controllers),
     ExternalLdapUserGroup(name=DHCP Administrators),
     ExternalLdapUserGroup(name=DHCP Users)
     ...

.. note:: Depending on your LDAP directory structure,
    groups may yield other groups as in the example above


Internal domains, groups and users are configured statically within the SMC. By default, the SMC
comes with an single `InternalDomain` domain configured.

.. note:: The SMC only supports a single Internal User Domain

Example of fetching an internal domain, browsing it's contents and iterating over the
users and groups to delete a user named 'testuser'::

    >>> from smc.administration.user_auth.users import InternalUserDomain
    >>> domain = InternalUserDomain('InternalDomain')
    >>> domain.browse()
    [InternalUserGroup(name=Mobile VPN users), InternalUserGroup(name=testgroup),
     InternalUser(name=testuser)]
    >>> for user in domain.browse():
    ...   if user.name == 'testuser':
    ...     user.delete()
    ...
    >>> domain.browse()
    [InternalUserGroup(name=Mobile VPN users), InternalUserGroup(name=testgroup)]

"""
from smc.base.model import Element, ElementCreator, UserElement, ElementList, ElementRef
from smc.base.structs import BaseIterable
from smc.base.util import element_resolver, datetime_to_ms


class ExternalLdapUserEntriesCollection(BaseIterable):
    """
    An external ldap user group collection provides top level search capabilities
    to iterate or get external ldap user group from a given external ldap user domain.

    All external ldap user groups can be fetched from the external ldap user domain::

        >>> external_domain_obj = ExternalLdapUserDomain("Test Forcepoint Domain")
        >>> for user in external_domain_obj.external_ldap_user_entries.all():
        ...   print(user)
        ...
        ExternalLdapUser(name=External Test User1)
        ExternalLdapUser(name=External Test User2)
        ExternalLdapUser(name=External Test User3)
        ExternalLdapUser(name=External Test User4)
        ExternalLdapUserGroup(name=All Servers)
        ExternalLdapUserGroup(name=All Members)
        ExternalLdapUserGroup(name=All Users)

    Or search for specific user:

        >>> external_domain_obj.external_ldap_user_entries.get(name="All Member")
        ExternalLdapUserGroup(name=All Members)
    """

    def __init__(self, external_ldap_user_group):

        self.external_ldap_user_group = external_ldap_user_group
        item = self.list_all()
        super(ExternalLdapUserEntriesCollection, self).__init__(item)

    def list_all(self):
        """
        Browse all External Ldap User Group.
        """
        all_entries = []
        for user_or_group in self.external_ldap_user_group.browse():
            self._browse_all(user_or_group, all_entries)
        return all_entries

    def _browse_all(self, user_entry: UserElement, all_entries):
        """
        Browse all External Ldap User element and return collectively.
        :rtype: list(ExternalLdapUserGroup, ExternalLdapUser)
        """
        all_entries.append(user_entry)
        if isinstance(user_entry, ExternalLdapUserGroup):
            for child in user_entry.browse():
                self._browse_all(child, all_entries)


class Browseable(object):
    """
    Domain users represents common methods used by Internal and LDAP
    domains to fetch user accounts.
    """

    def browse(self):
        """
        Browse the elements nested below this Domain or Group.
        Results could be internal users or groups.

        :return: list of Element by type
        :rtype: list
        """
        return [Element.from_meta(**element) for element in self.make_request(resource="browse")]


class InternalUserDomain(Browseable, Element):
    """
    This represents the default internal user Domain. There is one internal
    user domain per SMC. This domain can be used to create users and groups
    that would allow authentication when not using external authentication
    through ExternalLdapUserDomain's.
    """

    typeof = "internal_user_domain"
    user_dn = "dc=stonegate,domain=InternalDomain"


class ExternalLdapUserDomain(Browseable, Element):
    """
    External User Domain represents an external LDAP service configured to
    retrieve identity information. Identities are synchronized into SMC and
    then can be used as source objects within a policy.

    :ivar list(ActiveDirectoryServer) ldap_server: LDAP server/s used by this
        external domain
    :ivar AuthenticationMethod auth_method: default authentication method for
        this domain. Can also be set as attribute.
    """

    typeof = "external_ldap_user_domain"
    ldap_server = ElementList("ldap_server")
    auth_method = ElementRef("auth_method")

    @classmethod
    def create(cls, name, ldap_server, isdefault=False, auth_method=None, comment=None):
        """
        Create an External LDAP user domain. These are used as containers for
        retrieving user and groups from the configured LDAP server/s. If you
        have multiple authentication methods supported for your LDAP server,
        or have none configured, you can set the `auth_method` to
        a supported AuthenticationMethod.

        :param str name: name of external LDAP domain
        :param list(str,ActiveDirectoryServer) ldap_server: list of existing
            authentication servers in href or element format
        :param bool isdefault: set this to 'Default LDAP domain'
        :param str,AuthenticationMethod auth_method: authentication method to
            use. Usually set when multiple are defined in LDAP service or
            none are defined.
        :param str comment: optional comment
        :raises CreateElementFailed: failed to create
        :rtype: ExternalLdapUserDomain
        """
        return ElementCreator(
            cls,
            json={
                "name": name,
                "ldap_server": element_resolver(ldap_server),
                "auth_method": element_resolver(auth_method),
                "isdefault": isdefault,
                "comment": comment,
            },
        )

    @property
    def external_ldap_user_entries(self):
        """
        Retrieving list of an external LDAP group or user.
        :rtype: ExternalLdapUserEntriesCollection.
        """
        return ExternalLdapUserEntriesCollection(self)


class ExternalLdapUserGroup(Browseable, UserElement):
    """
    This represents an external LDAP Group defined on an external LDAP server.
    Retrieving an external LDAP group can be done by specifying the full DN
    of the group::

    ExternalLdapUserGroup.get('cn=Users,dc=du,dc=local,domain=du')

    :ivar str name: name of ldap user
    :ivar str unique_id: the fully qualified DN for the group
    """

    typeof = "external_ldap_user_group"


class ExternalLdapUser(UserElement):
    """
    This represents an external LDAP User defined on an external LDAP server.

    :ivar str name: name of ldap user
    :ivar str unique_id: the fully qualified DN for the user
    """

    typeof = "external_ldap_user"


class InternalUser(UserElement):
    """
    This represents an internal user defined within the SMC only
    You can retrieve an internal user by referencing it by either
    name::

        user = InternalUser('myuser')

    Creating users can be done and optionally can provide activation,
    expiration, group and a comment::

        InternalUser.create(name='myuser', user_group=[InternalUserGroup('foogroup')],
            expiration_date=datetime(2018, 10, 01), comment=None)

    :ivar str name: name of user
    :ivar str unique_id: the fully qualified DN for the user
    """

    typeof = "internal_user"

    @classmethod
    def create(
            cls, name, user_group=None, activation_date=None, expiration_date=None,
            authentication_method=[], password=None, pre_shared_key=None, comment=None,
    ):
        """
        Create an internal user.
        Add a user example::

            InternalUser.create(name='goog', comment='my comment')

        :param str name: name of user that is displayed in SMC
        :param list(str,InternalUserGroup) user_group: internal user groups
            which to add this user to.
        :param datetime activation_date: activation date as datetime object.
            Activation date only supports year and month/day
        :param datetime expiration_date: expiration date as datetime object.
            Expiration date only supports year and month/day
        :param list(authentication_method) authentication_method: list of authentication method.
        :param str password: The password in case of password authentication method.
        :param str pre_shared_key: The Pre-Shared key in case of pre shared key authentication
        method.
        :param str comment: optional comment
        :raises ElementNotFound: thrown if group specified does not exist
        :rtype: InternalUser
        """
        json = {
            "name": name,
            "unique_id": "cn={},{}".format(name, InternalUserDomain.user_dn),
            "comment": comment,
            "subject_alt_names": f"CN={name}"
        }

        limits = {"activation_date": activation_date, "expiration_date": expiration_date}
        for attr, value in limits.items():
            json[attr] = datetime_to_ms(value) if value else None

        if user_group:
            json.update(user_group=element_resolver(user_group))
        if authentication_method:
            json.update(authentication_method=element_resolver(authentication_method))
            if password:
                json.update(password=password)
            if pre_shared_key:
                json.update(pre_shared_key=pre_shared_key)
        return ElementCreator(cls, json)

    @property
    def user_group(self):
        """
        InternalUserGroup associated with internal user.
        :rtype: list
        """
        return [Element.from_href(group) for group in self.data.get("user_group")]

    @property
    def authentication_method(self):
        """
        List of authentication method for specific internal user.
        :rtype: list
        """
        return [Element.from_href(method) for method in self.data.get("authentication_method")]


class InternalUserGroup(Browseable, UserElement):
    """
    This represents an internal user group defined within the SMC only
    You can retrieve an internal user by referencing it by either
    name::

        InternalUserGroup('Mobile VPN users')

    Creating groups, you can optionally add members during creation::

        InternalUserGroup.create('groupa', member=[InternalUser('google4')])

    :ivar str name: name of user
    :ivar str unique_id: the fully qualified DN for the user
    """

    typeof = "internal_user_group"

    @classmethod
    def create(cls, name, member=None, comment=None):
        """
        Create an internal user group. An internal group will always be attached
        to the default (and only) InternalUserDomain within the SMC.

        Example of creating an internal user group::

            InternalUserGroup.create(name='foogroup2', comment='mycomment')

        :param str name: Name of group
        :param list(InternalUser) member: list of internal users to add to
            this group
        :param str comment: optional comment
        :raises CreateElementFailed: failed to create user group
        :rtype: InternalUserGroup
        """
        json = {
            "name": name,
            "unique_id": "cn={},{}".format(name, InternalUserDomain.user_dn),
            "comment": comment,
        }
        if member:
            json.update(member=element_resolver(member))

        return ElementCreator(cls, json)

    @property
    def members(self):
        """
        Members of the InternalUserGroup. Members will be a list elements of
        type InternalUser or InternalGroup.

        :rtype: list
        """
        return [Element.from_href(member) for member in self.data.get("member")]
