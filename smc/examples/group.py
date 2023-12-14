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
Example of how to create a group
"""

import argparse
import logging
import sys

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.elements.group import Group  # noqa
from smc.elements.servers import NTPServer  # noqa

FIRST_UPDATE_CREATE_COMMENT = "my first update or created group"
FIRST_UPDATE_CREATE_MEMBERS_COMMENT = "my first update or created group with members"
PREVIOUSLY_CREATED_COMMENT = "myGroup2 previously created, comment updated"
FIRST_CREATE_COMMENT = "my first create group with members"
REMOVED_MEMBERS = "myGroup3 removed members"
WRONG_COMMENT = "Wrong comment in assert!"
WRONG_MEMBERS = "Wrong members in assert!"

logging.getLogger()
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - '
                                                '%(name)s - [%(levelname)s] : %(message)s')


def main():
    return_code = 0
    try:
        arguments = parse_command_line_arguments()
        session.login(url=arguments.api_url, api_key=arguments.api_key,
                      login=arguments.smc_user,
                      pwd=arguments.smc_pwd, api_version=arguments.api_version)
        logging.info("session OK")

        # Create NTP server to add to the group
        new_ntp_server = NTPServer().create(name="myNTPServer",
                                            comment="NTP Server created by the SMC API",
                                            address="192.168.1.200",
                                            ntp_auth_key_type="none"
                                            )

        # Create Group then add members
        grp = Group.update_or_create(name="myGroup", comment=FIRST_UPDATE_CREATE_COMMENT)
        assert grp.members == [], WRONG_MEMBERS
        grp.update_members([new_ntp_server])

        grp = Group("myGroup")
        logging.info(f"comment=>{grp.comment}")
        assert grp.comment == FIRST_UPDATE_CREATE_COMMENT, WRONG_COMMENT
        assert grp.members == [new_ntp_server.href], WRONG_MEMBERS

        # Create Group with members
        Group.update_or_create(name="myGroup2",
                               comment=FIRST_UPDATE_CREATE_MEMBERS_COMMENT,
                               members=[new_ntp_server])

        grp = Group("myGroup2")
        logging.info(f"members=>{grp.members}")
        assert grp.comment == FIRST_UPDATE_CREATE_MEMBERS_COMMENT, WRONG_COMMENT
        assert grp.members == [new_ntp_server.href], WRONG_MEMBERS

        # Update existing myGroup2
        Group.update_or_create(name="myGroup2",
                               comment=PREVIOUSLY_CREATED_COMMENT,
                               members=[new_ntp_server])

        grp = Group("myGroup2")
        logging.info(f"updated comment=>{grp.comment}, members={grp.members}")
        assert grp.comment == PREVIOUSLY_CREATED_COMMENT, WRONG_COMMENT
        assert grp.members == [new_ntp_server.href], WRONG_MEMBERS

        # Create Group using create method
        Group.create(name="myGroup3",
                     comment=FIRST_CREATE_COMMENT,
                     members=[new_ntp_server])

        grp = Group("myGroup3")
        logging.info(f"comment={grp.comment}, members=>{grp.members}")
        assert grp.comment == FIRST_CREATE_COMMENT, WRONG_COMMENT
        assert grp.members == [new_ntp_server.href], WRONG_MEMBERS

        # Update myGroup3 remove members
        Group.update_or_create(name="myGroup3",
                               comment=REMOVED_MEMBERS,
                               remove_members=True,
                               members=[new_ntp_server])
        grp = Group("myGroup3")
        logging.info(f"comment={grp.comment}, members=>{grp.members}")
        assert grp.comment == REMOVED_MEMBERS, WRONG_COMMENT
        assert grp.members == [], WRONG_MEMBERS
    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        Group("myGroup").delete()
        Group("myGroup2").delete()
        Group("myGroup3").delete()
        NTPServer("myNTPServer").delete()
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to create a group',
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


if __name__ == '__main__':
    sys.exit(main())
