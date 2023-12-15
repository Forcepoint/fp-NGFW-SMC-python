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
Example script to show how to use Connection Type
"""
import argparse
import logging
import sys

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.elements.netlink import LinkType  # noqa
from smc.vpn.elements import ConnectionType  # noqa

connection_type_name = "test_connection_type"
message = "Testing of connection link."
mode = 'active'

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

        link_type = list(LinkType.objects.all())[0]
        logging.info("Accessing first link type element.")
        # create connection type
        connection_type = ConnectionType.create(name=connection_type_name, mode=mode,
                                                connectivity_group=1, link_type_ref=link_type,
                                                comment=message)
        assert connection_type.mode() == mode, ("Failed to create connection type with mode "
                                                "attribute.")
        assert connection_type.link_type_ref() == link_type.href, ("Failed to create "
                                                                   "connection type with "
                                                                   "link_type_ref attribute")
        logging.info(f"Connection Type {connection_type.name} created successfully.")
        connection_type.update(link_type_ref=None)
        assert connection_type.link_type_ref() is None, "Failed to update connection type."
    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        ConnectionType(connection_type_name).delete()
        logging.info("Deleted Connection Type Successfully.")
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to use Connection Type',
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
