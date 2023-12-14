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
Example script to show how to use Switch interfaces
-create switch interface/port group for an engine
-display switch interface
-delete switch interface

Needs Demo mode
"""

# Python Base Import
import argparse
import logging
import sys

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.core.engines import Layer3Firewall  # noqa

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

        single_fw = Layer3Firewall("Plano")
        (single_fw.switch_physical_interface.add_switch_interface
         (1, "110", "My new switch interface"))

        # retrieve interface id
        switch_interface_id = single_fw.switch_physical_interface.all()[0].interface_id

        single_fw.switch_physical_interface \
                 .add_port_group_interface(switch_interface_id, 1, [1],
                                           interfaces=[{'nodes': [{'address': '12.12.12.12',
                                                                   'network_value': '12.12.12.0/24',
                                                                   'nodeid': 1}]}])
        single_fw.switch_physical_interface \
                 .add_port_group_interface(switch_interface_id, 2, [2, 3, 4, 5])

        logging.info(f"{switch_interface_id}:"
                     f"{single_fw.switch_physical_interface.get(switch_interface_id)}")

        for interface in single_fw.switch_physical_interface:
            logging.info(f"{interface}: {interface.port_group_interface}")

        interface = single_fw.switch_physical_interface.get(switch_interface_id)
        for sub_intf in interface.all_interfaces:
            intf_id = sub_intf.data.interface_id
            logging.info(f"{intf_id}: {sub_intf}")

    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        single_fw.switch_physical_interface.get(switch_interface_id).delete()
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to use Switch interfaces',
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
