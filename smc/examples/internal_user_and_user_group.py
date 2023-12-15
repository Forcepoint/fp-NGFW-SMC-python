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
Example of creating and accessing internal user and internal user group.
"""
import argparse
import logging
import sys

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.administration.user_auth.servers import AuthenticationMethod  # noqa
from smc.administration.user_auth.users import InternalUserGroup, InternalUser  # noqa
from smc.base.util import element_resolver  # noqa

INTERNAL_USER_GROUP_CREATE_ERROR = "Failed to create internal user group."
FAILED_TO_CREATE_USER = "Failed to create internal user."
UPDATE_ERROR = "Failed to update internal user."
UPDATE_AUTH_METHOD_ERROR = "Failed to update method to internal user."
group_name = "test_internal_user_group"
user_name1 = "test_internal_user1"
user_name2 = "test_internal_user2"
user_password = "test_internal_user1"
pre_shared_key = "XYXPQRABCD"
method1 = AuthenticationMethod(name="User password")
method2 = AuthenticationMethod(name="Pre-Shared Key Method")

logging.getLogger()
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - '
                                                '%(name)s - [%(levelname)s] : %(message)s')


def check_if_user_present(user_name):
    """
    check if the user is present or not.
    """
    is_user_created = InternalUser.objects.filter(name=user_name)
    assert is_user_created, FAILED_TO_CREATE_USER


def delete_if_user_present(user_name):
    """
    check and delete if the user is present.
    """
    if InternalUser.objects.filter(name=user_name, exact_match=True):
        InternalUser(user_name).delete()


def create_user_group_and_verify():
    """
    If an internal user group is present, delete it, then add it again and validate that it was
    created.
    """
    if InternalUserGroup.objects.filter(name=group_name, exact_match=True):
        InternalUserGroup(group_name).delete()
    internal_user_group = InternalUserGroup.create(group_name)
    is_group_created = InternalUserGroup.objects.filter(name=group_name)
    assert is_group_created, INTERNAL_USER_GROUP_CREATE_ERROR
    logging.info(f"successfully created an internal user group : {group_name}")
    return internal_user_group


def main():
    return_code = 0
    try:
        arguments = parse_command_line_arguments()
        session.login(url=arguments.api_url, api_key=arguments.api_key,
                      login=arguments.smc_user,
                      pwd=arguments.smc_pwd, api_version=arguments.api_version)
        logging.info("session OK")
        # get list of all internal user group
        all_internal_user_group = list(InternalUserGroup.objects.all())
        logging.info(f"Accessing the list of internal user groups: {len(all_internal_user_group)}")
        internal_user_group_object = create_user_group_and_verify()
        delete_if_user_present(user_name1)
        authentication_methods = [method1.href]
        internal_user_object1 = InternalUser.create(user_name1, password=user_password,
                                                    authentication_method=authentication_methods,
                                                    comment="testing of internal user")
        check_if_user_present(user_name1)
        logging.info(f"internal user successfully created: {user_name1}")
        internal_user_object1.update(password=user_password,
                                     user_group=element_resolver([internal_user_group_object]))
        assert [group for group in internal_user_object1.user_group if
                group.name == internal_user_group_object.name], UPDATE_ERROR
        logging.info("Member of internal user group added to internal user")
        authentication_methods = [method.href for method in
                                  list(AuthenticationMethod.objects.all()) if
                                  method.name in [method1.name, method2.name]]

        internal_user_object1.update(pre_shared_key="XYXPQRABCD",
                                     authentication_method=authentication_methods,
                                     password=user_password)
        logging.info("Added two authentication method to internal user")
        assert [method for method in internal_user_object1.authentication_method if
                method.name == method2.name], UPDATE_AUTH_METHOD_ERROR
        delete_if_user_present(user_name2)
        internal_user_object2 = InternalUser.create(user_name2, pre_shared_key=pre_shared_key,
                                                    authentication_method=[method2.href],
                                                    comment="testing of internal user")
        check_if_user_present(user_name2)
    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        InternalUserGroup(group_name).delete()
        logging.info(f"Internal user group {group_name} successfully deleted")
        InternalUser(user_name1).delete()
        logging.info(f"Internal user {user_name1} successfully deleted")
        InternalUser(user_name2).delete()
        logging.info(f"Internal user {user_name2} successfully deleted.")
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example of creating and accessing internal user and internal user group.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        add_help=False)
    parser.add_argument(
        '-h', '--help',
        action='store_true',
        help='show this help message and exit')

    parser.add_argument(
        '--api-url',
        type=str,
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
        type=str, default=None,
        help='SMC API api key (Default: None)')

    arguments = parser.parse_args()

    if arguments.help:
        parser.print_help()
        sys.exit(1)
    if arguments.api_url is None:
        parser.print_help()
        sys.exit(1)

    return arguments


if __name__ == "__main__":
    sys.exit(main())
