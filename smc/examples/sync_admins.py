#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
Example script to show how to synchronize, from an LDAP domain, SMC administrators.
'sync_admins_config.json' configuration json file represents the mapping between
LDAP group and SMC permissions.
"""
import argparse
import logging
import sys
import json

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.compat import is_api_version_less_than  # noqa
from smc.administration.user_auth.users import (ExternalLdapUser,
                                                ExternalLdapUserDomain,
                                                ExternalLdapUserGroup)  # noqa
from smc.administration.access_rights import Permission, AccessControlList  # noqa
from smc.administration.user_auth.servers import AuthenticationMethod  # noqa
from smc.administration.role import Role  # noqa
from smc.administration.system import AdminDomain  # noqa
from smc.elements.user import AdminUser  # noqa
from smc.administration.user_auth.servers import ActiveDirectoryServer  # noqa


def search(element_type, element_name, exact_match=True):
    """ Search for an element """
    return list(element_type.objects.filter(
        name=element_name,
        exact_match=exact_match))


def main():
    return_code = 0
    try:
        arguments = parse_command_line_arguments()

        logging.getLogger()
        logging.basicConfig(
            level=arguments.log_level.upper(),
            format='%(asctime)s - %(name)s - [%(levelname)s] : %(message)s',
            stream=sys.stdout)

        session.login(url=arguments.api_url, api_key=arguments.api_key,
                      login=arguments.smc_user,
                      pwd=arguments.smc_pwd, api_version=arguments.api_version)

        logging.info("Open to parse the configuration json file...")
        with open(arguments.config_path, "r") as config_file:
            config = json.load(config_file)
        logging.info(f"{arguments.config_path} json file has been loaded.")

        permissions_per_ad_group = {}

        for key, value in config["permissions_per_ad_group"].items():
            if value is None:
                permissions_per_ad_group[key] = None
            else:
                permissions_per_ad_group[key] = [Permission.create(
                    elements=[AccessControlList(value['elements'])],
                    role=Role(value['role']),
                    domain=AdminDomain(value['domain']))]

        external_user_domain = ExternalLdapUserDomain(config["ldap_domain"])
        if not is_api_version_less_than("7.1"):
            # just to sure to retrieve all external LDAP domain updates
            external_user_domain.invalidate_cache()

        ldap_admin_user_names = []
        fail_if_no_permissions = bool(config["fail_if_no_permission"])

        # retrieve the external ldap user entries from ldap domain
        sync_AD_entity(permissions_per_ad_group, fail_if_no_permissions, external_user_domain.browse(), ldap_admin_user_names)

        # Retrieve all admin users
        for admin_user in AdminUser.objects.all():
            # admin user linked to an LDAP user
            if ("ldap_user" in admin_user.data
                    # admin user which is enabled
                    and admin_user.enabled
                    # admin user which is not anymore linked to an AD entity
                    and admin_user.name not in ldap_admin_user_names):
                if bool(config["disabled_if_obsolete"]):
                    admin_user.enable_disable()
                    logging.warning(
                        f"Admin User {admin_user.name} is now disabled since not linked to an AD entity.")
                else:
                    admin_user.delete()
                    logging.warning(
                        f"Admin User {admin_user.name} has been deleted since not linked to an AD entity.")

    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        session.logout()

    logging.info(f"Script completed")
    return return_code


def sync_AD_entity(permissions_per_ad_group, fail_if_no_permissions, external_ldap_entries,
                   ldap_admin_user_names, parent_AD_entity=None):
    """
    Synchronizes the specified list of external ldap entries with the local SMC
    Administrators:
    - if the external ldap user is not present as local SMC administrator, we create it
    with associated permissions (specified from the config file)
    - if the external ldap user is present already as local SMC administrator, we check if
    permissions are aligned
    """
    for external_ldap_entry in external_ldap_entries:
        if isinstance(external_ldap_entry, ExternalLdapUserGroup):
            logging.info(f"Parsing external group: {external_ldap_entry.name}")

            if (external_ldap_entry.name == "Users" or
                    external_ldap_entry.name in permissions_per_ad_group.keys()):
                sync_AD_entity(permissions_per_ad_group, fail_if_no_permissions,
                               external_ldap_entry.browse(),
                               ldap_admin_user_names, external_ldap_entry)
        elif isinstance(external_ldap_entry, ExternalLdapUser):
            logging.info(f"Parsing external user: {external_ldap_entry.name}")

            if parent_AD_entity.name in permissions_per_ad_group.keys():
                logging.info(f"External User with groups giving access to "
                             f"SMC: {external_ldap_entry}, {parent_AD_entity}")
                ldap_admin_user_names.append(external_ldap_entry.name)

                existing_admin_users = search(AdminUser, external_ldap_entry.name)
                associated_permissions = permissions_per_ad_group[parent_AD_entity.name]

                if bool(existing_admin_users):
                    existing_admin_user = existing_admin_users[0]
                    if not existing_admin_user.enabled:
                        existing_admin_user.enable_disable()
                        logging.warning(
                            f"{external_ldap_entry.name} AdminUser were disabled: we enabled it.")

                    if associated_permissions is None:
                        associated_permissions = []

                    if not existing_admin_user.permissions == associated_permissions:
                        logging.warning(
                            f"User: {external_ldap_entry.name} has incorrect "
                            f"permission, updating accordingly")

                        logging.info(f'{existing_admin_user.permissions} != {associated_permissions}')

                        if len(associated_permissions) == 0:
                            if fail_if_no_permissions:
                                raise BaseException(f"Fail to update the existing administrator "
                                                    f"{existing_admin_user.name}: no associated permission!")
                            else:
                                existing_admin_user.update(superuser=True)
                        else:
                            existing_admin_user.update(superuser=True)
                            existing_admin_user.add_permission(associated_permissions)
                else:
                    if associated_permissions:
                        AdminUser.create(
                            name=external_ldap_entry.name,
                            ldap_user_href=external_ldap_entry.href,
                            can_use_api=False,
                            auth_method="LDAP Authentication",
                            permissions=associated_permissions,
                        )
                    else:
                        AdminUser.create(
                            name=external_ldap_entry.name,
                            ldap_user_href=external_ldap_entry.href,
                            can_use_api=False,
                            superuser=True,
                            auth_method="LDAP Authentication",
                        )

                    logging.info(
                        f"AD user {external_ldap_entry.name} from AD group "
                        f"{parent_AD_entity.name} has been created.")
            else:
                logging.debug(f"Not interesting External User: "
                              f"{external_ldap_entry}, {parent_AD_entity}")


def parse_command_line_arguments():
    """ Parse command line arguments. """
    parser = argparse.ArgumentParser(
        description='Example script to show how to sync LDAP entities '
                    'and local SMC Administrators.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        add_help=False)
    parser.add_argument(
        '-h', '--help',
        action='store_true',
        help='show this help message and exit')

    parser.add_argument(
        '--api-url',
        type=str,
        default="http://127.0.0.1:8082",
        help='SMC API url like https://192.168.1.1:8082')
    parser.add_argument(
        '--api-version',
        type=str,
        help='The API version to use for run the script'
    )
    parser.add_argument(
        '--smc-user',
        type=str,
        help='SMC API user')
    parser.add_argument(
        '--smc-pwd',
        type=str,
        help='SMC API password')
    parser.add_argument(
        '--api-key',
        type=str,
        help='SMC API api key (Default: None)')
    parser.add_argument(
        '--config-path',
        type=str,
        help='Path for the config json file.')
    parser.add_argument(
        '--log_level',
        type=str,
        default='INFO',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        help='Set the logging level')

    arguments = parser.parse_args()

    if arguments.help:
        parser.print_help()
        sys.exit(1)
    if arguments.api_url is None:
        parser.print_help()
        sys.exit(1)

    return arguments


if __name__ == '__main__':
    sys.exit(main())
