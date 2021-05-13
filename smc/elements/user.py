"""
User module to hold accounts related to users (admin or local) in the SMC

You can create an Admin User, enable superuser, enable/disable the account,
assign local access to engines, and change the account password for SMC or
engine access.

It is possible to fully provision an Admin User with specific permissions and
roles and initial password.

Create the admin::

    admin = AdminUser.create(name='auditor', superuser=False)

.. note:: If the Admin User should have unrestricted access, set ``superuser=True`` and
    skip the below sections related to adding permissions and roles.

Permissions relate to elements that the user will have access to (Policies, Engines or
AccessControlLists) and the domain where the privileges apply (default is 'Shared Domain').

Create a permission using the default domain of Shared, granting access to a specific
engine and firewall policy::

    permission = Permission.create(
        elements=[Engine('vm'), FirewallPolicy('VM Policy')],
        role=Role('Viewer'))

Create a second permission granting access to all firewalls in the domain 'mydomain'::

    domain_perm = Permission.create(
        elements=[AccessControlList('ALL Firewalls')],
        role=Role('Owner'),
        domain=AdminDomain('mydomain'))

Add the permissions to the Admin User::

    admin.add_permission([permission, domain_perm])

Set an initial password for the Admin User::

    admin.change_password('Newpassword1')

.. note:: Roles are used to define what granular controls will be available to the assigned
    user, such as read/read write/all. AccessControlLists encapsulate elements into a single
    container for re-use.

.. seealso:: :class:`smc.administration.role.Role` and
    :class:`smc.administration.access_rights.AccessControlList` for more information.

"""
from smc.base.model import Element, ElementCreator
from smc.api.exceptions import ModificationFailed
from smc.administration.access_rights import Permission


class UserMixin(object):
    """
    User Mixin class providing common operations for Admin Users and
    API Clients.
    """

    def enable_disable(self):
        """
        Toggle enable and disable of administrator account.
        Change is committed immediately.

        :raises UpdateElementFailed: failed with reason
        :return: None
        """
        self.update(href=self.get_relation("enable_disable"), etag=None)

    def change_password(self, password):
        """
        Change user password. Change is committed immediately.

        :param str password: new password
        :return: None
        """
        self.make_request(
            ModificationFailed,
            method="update",
            resource="change_password",
            params={"password": password},
        )

    def generate_password(self):
        """
        Generate a random password for this user.

        :return: random password
        :rtype: str
        """
        pwd = self.make_request(method="update", resource="generate_password")
        if "value" in pwd:
            return pwd["value"][0]

    def add_permission(self, permission):
        """
        Add a permission to this Admin User. A role defines permissions that
        can be enabled or disabled. Elements define the target for permission
        operations and can be either Access Control Lists, Engines or Policy
        elements. Domain specifies where the access is granted. The Shared
        Domain is default unless specific domain provided. Change is committed
        at end of method call.

        :param permission: permission/s to add to admin user
        :type permission: list(Permission)
        :raises UpdateElementFailed: failed updating admin user
        :return: None
        """
        if "permissions" not in self.data:
            self.data["superuser"] = False
            self.data["permissions"] = {"permission": []}

        for p in permission:
            self.data["permissions"]["permission"].append(p.data)
        self.update()

    @property
    def permissions(self):
        """
        Return each permission role mapping for this Admin User. A permission
        role will have 3 fields:

        * Domain
        * Role (Viewer, Operator, etc)
        * Elements (Engines, Policies, or ACLs)

        :return: permissions as list
        :rtype: list(Permission)
        """
        if "permissions" in self.data:
            _permissions = self.data["permissions"]["permission"]
            return [Permission(**perm) for perm in _permissions]
        return []


class AdminUser(UserMixin, Element):
    """Represents an Adminitrator account on the SMC
    Use the constructor to create the user.

    Create an Admin::

        >>> AdminUser.create(name='admin', superuser=True)
        AdminUser(name=admin)

    If modifications are required after you can access the admin and
    make changes::

        admin = AdminUser('admin')
        admin.change_password('mynewpassword1')
        admin.enable_disable()

    Attributes available:

    :ivar bool allow_sudo: is this account allowed to sudo on an engine.
    :ivar bool local_admin: is the admin a local admin
    :ivar bool superuser: is this account a superuser for SMC
    """

    typeof = "admin_user"

    @classmethod
    def create(
        cls,
        name,
        local_admin=False,
        allow_sudo=False,
        superuser=False,
        enabled=True,
        engine_target=None,
        can_use_api=True,
        console_superuser=False,
        allowed_to_login_in_shared=True,
        comment=None,
    ):
        """
        Create an admin user account.

        .. versionadded:: 0.6.2
            Added can_use_api, console_superuser, and allowed_to_login_in_shared.
            Requires SMC >= SMC 6.4

        :param str name: name of account
        :param bool local_admin: is a local admin only
        :param bool allow_sudo: allow sudo on engines
        :param bool can_use_api: can log in to SMC API
        :param bool console_superuser: can this user sudo via SSH/console
        :param bool allowed_to_login_in_shared: can this user log in to the
            shared domain
        :param bool superuser: is a super administrator
        :param bool enabled: is account enabled
        :param list engine_target: engine to allow remote access to
        :raises CreateElementFailed: failure creating element with reason
        :return: instance with meta
        :rtype: AdminUser
        """
        engines = [] if engine_target is None else engine_target

        json = {
            "name": name,
            "enabled": enabled,
            "allow_sudo": allow_sudo,
            "console_superuser": console_superuser,
            "allowed_to_login_in_shared": allowed_to_login_in_shared,
            "engine_target": engines,
            "local_admin": local_admin,
            "superuser": superuser,
            "can_use_api": can_use_api,
            "comment": comment,
        }

        return ElementCreator(cls, json)

    @property
    def enabled(self):
        """
        Read only enabled status

        :rtype: bool
        """
        return self.data.get("enabled")

    def change_engine_password(self, password):
        """Change Engine password for engines on allowed
        list.

        :param str password: password for engine level
        :raises ModificationFailed: failed setting password on engine
        :return: None
        """
        self.make_request(
            ModificationFailed,
            method="update",
            resource="change_engine_password",
            params={"password": password},
        )


class ApiClient(UserMixin, Element):
    """
    Represents an API Client
    """

    typeof = "api_client"

    @classmethod
    def create(cls, name, enabled=True, superuser=True):
        """
        Create a new API Client. Once client is created,
        you can create a new password by::

            >>> client = ApiClient.create('myclient')
            >>> print(client)
            ApiClient(name=myclient)
            >>> client.change_password('mynewpassword')

        :param str name: name of client
        :param bool enabled: enable client
        :param bool superuser: is superuser account
        :raises CreateElementFailed: failure creating element with reason
        :return: instance with meta
        :rtype: ApiClient
        """
        json = {"enabled": enabled, "name": name, "superuser": superuser}

        return ElementCreator(cls, json)
