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
from smc.base.structs import NestedDict
from smc.base.util import element_resolver
from smc.administration.user_auth import servers


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
        auth_method=None,
        comment=None,
        permissions=None,
        ldap_user_href=None,
        ldap_group_href=None,
        tls_field=None,
        tls_value=None,
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
        :param auth_method: authentication method
        :param bool enabled: is account enabled
        :param list engine_target: engine to allow remote access to
        :param comment: object comment
        :param permissions object in case SMC admin is not superuser
        :param ldap_user_href External user href to link as SMC admin
        :param ldap_group_href External user href to link as SMC admin
        :param tls_field: TLS field name for client identity
        :param tls_value: TLS value corresponding the field for client identity
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
            "permissions": {"permission": []},
            "ldap_user": ldap_user_href,
            "ldap_group": ldap_group_href,
        }

        if tls_field:
            json["client_identity"] = {"tls_field": tls_field, "tls_value": tls_value}

        if permissions:
            for p in permissions:
                json["permissions"]["permission"].append(p.data)

        if auth_method:
            auth_method_ref = servers.AuthenticationMethod(auth_method).href
            json.update(auth_method=auth_method_ref)

        return ElementCreator(cls, json)

    @property
    def enabled(self):
        """
        Read only enabled status

        :rtype: bool
        """
        return self.data.get("enabled")

    def unlock_account(self, unlock_reason: str):
        """
        Unlock the SMC Administrator User account.
        By default, the audit message for this operation will be:
        "Unlocked account from SMC API" but can be overriden by 'unlock_reason' parameter

        :raises ResourceNotFound is the operation is not supported by your SMC version.
        """
        self.make_request(
            method="update",
            resource="unlock_account",
            params={"unlock_reason": unlock_reason},
        )

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

    @property
    def password_meta_data(self):
        """
        Provides creation_date and expiration_date of the password for AdminUser,ApiClient and
        WebPortalAdminUser.
        :return: PasswordMetaData : PasswordMetaData contains creation_date and expiration_date.
        """
        pwd_meta_data = self.make_request(resource="pwd_meta_data")
        return PasswordMetaData(pwd_meta_data)


class ApiClient(UserMixin, Element):
    """
    Represents an API Client
    """

    typeof = "api_client"

    @classmethod
    def create(
        cls,
        name,
        enabled=True,
        superuser=True,
        allowed_to_login_in_shared=True,
        permissions=None,
    ):
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
        :param bool allowed_to_login_in_shared: can this user log in to the
            shared domain
        :param permissions object in case SMC admin is not superuser
        :raises CreateElementFailed: failure creating element with reason
        :return: instance with meta
        :rtype: ApiClient
        """
        json = {
            "enabled": enabled,
            "name": name,
            "superuser": superuser,
            "allowed_to_login_in_shared": allowed_to_login_in_shared,
            "permissions": {"permission": []},
        }

        if permissions:
            for p in permissions:
                json["permissions"]["permission"].append(p.data)

        return ElementCreator(cls, json)


class PasswordMetaData(NestedDict):
    """
    Represents the password meta-data for AdminUser, ApiClient and WebPortalAdminUser. it provides
    creation_date and expiration_date of the password for AdminUser,ApiClient and WebPortalAdminUser
    """

    typeof = "pwd_meta_data"

    def __init__(self, value):
        super(PasswordMetaData, self).__init__(data=value)


class WebPortalAdminUser(UserMixin, Element):
    """
    This represents a Web Portal User.It is an element that defines the details of a single person
     that is allowed to log on to the Web Portal,
     the Browser-based service that allows users to view logs, Policy Snapshots, and reports

    Create a Web Portal Admin User::

        >>> WebPortalAdminUser.create(name='admin')

    If modifications are required after you can access the admin and
    make changes::

        admin = WebPortalAdminUser('admin')
        admin.change_password('mynewpassword1')
        admin.enable_disable()
    """

    typeof = "web_portal_user"

    @classmethod
    def create(
        cls,
        name,
        enabled=True,
        granted_engine=None,
        console_superuser=False,
        log_service_enabled=True,
        policy_service_enabled=True,
        report_service_enabled=True,
        show_inspection_policy=True,
        show_main_policy=True,
        show_only_ip_addresses=True,
        show_sub_policy=True,
        show_template_policy=False,
        show_upload_comment=True,
        show_upload_history=True,
        granted_template_policy=None,
        granted_sub_policy=None,
        granted_report_design=None,
        filter_tag=None,
        comment=None,
    ):
        """
        Create a web portal admin user account.

        .. versionadded:: 0.6.2
            Added can_use_api, console_superuser, and allowed_to_login_in_shared.
            Requires SMC >= SMC 6.4

        :param str name: name of account
        :param bool enabled: is account enabled
        :param list granted_engine: The list of Granted Engines
        :param bool console_superuser: can this user sudo via SSH/console.
        :param bool log_service_enabled: check if the log service enabled?
        :param bool policy_service_enabled: check if the policy service enabled.
        :param bool report_service_enabled: Is the report service enabled?
        :param bool show_inspection_policy: Should we display the inspection policy?
        :param bool show_main_policy: Should we display the main policy?
        :param bool show_only_ip_addresses: Should we display only the IP Addresses of elements?
        :param bool show_sub_policy: Should we display the sub policy?
        :param bool show_template_policy: Should we display the template policy?
        :param bool show_upload_comment: Should we display the upload comment?
        :param bool show_upload_history: Should we display the upload history?
        :param list granted_template_policy: The list of Granted Template Policies.
            null value means ANY.
        :param list granted_sub_policy: The list of Granted Sub Policies.
            null value means ANY
        :param list granted_report_design: The list of Granted Report Designs.
            null value means ANY.
        :param list filter_tag: The list of Filter expression tags for the log browsing.
            null value means ANY.
        :param str comment: comment,
        :raises CreateElementFailed: failure creating element with reason
        :return: instance with meta
        :rtype: WebPortalAdminUser
        """
        engines = [] if granted_engine is None else element_resolver(granted_engine)
        policy = (
            [] if granted_template_policy is None else element_resolver(granted_template_policy)
        )
        sub_policy = [] if granted_sub_policy is None else element_resolver(granted_sub_policy)
        report_design = (
            [] if granted_report_design is None else element_resolver(granted_report_design)
        )
        tag = [] if filter_tag is None else element_resolver(filter_tag)
        json = {
            "name": name,
            "enabled": enabled,
            "console_superuser": console_superuser,
            "log_service_enabled": log_service_enabled,
            "policy_service_enabled": policy_service_enabled,
            "report_service_enabled": report_service_enabled,
            "show_inspection_policy": show_inspection_policy,
            "show_main_policy": show_main_policy,
            "show_only_ip_addresses": show_only_ip_addresses,
            "show_sub_policy": show_sub_policy,
            "show_template_policy": show_template_policy,
            "show_upload_comment": show_upload_comment,
            "show_upload_history": show_upload_history,
            "granted_engine": engines,
            "granted_template_policy": policy,
            "granted_sub_policy": sub_policy,
            "granted_report_design": report_design,
            "filter_tag": tag,
            "comment": comment,
        }
        return ElementCreator(cls, json)

    @property
    def enabled(self):
        return self.data.get("enabled")

    def unlock_account(self, unlock_reason: str):
        """
        Unlock the web portal admin user account.
        By default, the audit message for this operation will be:
        "Unlocked account from SMC API" but can be overriden by 'unlock_reason' parameter

        :raises ResourceNotFound is the operation is not supported by your SMC version.
        """
        self.make_request(
            method="update",
            resource="unlock_account",
            params={"unlock_reason": unlock_reason},
        )

    @property
    def granted_engine(self):
        return self.data.get("granted_engine")

    @property
    def console_superuser(self):
        return self.data.get("console_superuser")

    @property
    def log_service_enabled(self):
        return self.data.get("log_service_enabled")

    @property
    def policy_service_enabled(self):
        return self.data.get("policy_service_enabled")

    @property
    def report_service_enabled(self):
        return self.data.get("report_service_enabled")

    @property
    def show_inspection_policy(self):
        return self.data.data("show_inspection_policy")

    @property
    def show_main_policy(self):
        return self.data.get("show_main_policy")

    @property
    def show_only_ip_addresses(self):
        return self.data.get("show_only_ip_addresses")

    @property
    def show_sub_policy(self):
        return self.data.get("show_sub_policy")

    @property
    def show_template_policy(self):
        return self.data.get("show_template_policy")

    @property
    def show_upload_comment(self):
        return self.data.get("show_upload_comment")

    @property
    def show_upload_history(self):
        return self.data.get("show_upload_history")

    @property
    def granted_template_policy(self):
        return self.data.get("granted_template_policy")

    @property
    def granted_sub_policy(self):
        return self.data.get("granted_sub_policy")

    @property
    def granted_report_design(self):
        return self.data.get("granted_report_design")

    @property
    def filter_tag(self):
        return self.data.get("filter_tag")
