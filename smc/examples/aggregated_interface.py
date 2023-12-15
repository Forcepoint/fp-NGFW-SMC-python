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
Example of creating an aggregated interface
"""
import argparse
import logging
import sys

sys.path.append('../../')   # smc-python
from smc.core.engines import Layer3Firewall  # noqa
from smc import session  # noqa

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

        engine = Layer3Firewall.create(
            name="myEngine",
            mgmt_ip="172.18.1.1",
            mgmt_network="172.18.1.0/24",
            mgmt_interface=0,
        )
        engine.physical_interface.add_layer3_interface(interface_id=1,
                                                       address="172.18.2.10",
                                                       network_value="172.18.2.0/24",
                                                       comment="My aggregate interface",
                                                       aggregate_mode="ha",
                                                       second_interface_id=2)

        # retrieve interface id
        for interface in engine.physical_interface.all():
            logging.info(f"Interfaced created:{interface.interface_id}:{interface}")

        interface_keys = ['id', 'contact_addresse_ip']
        engine = Layer3Firewall("myEngine")
        # Contact Address information
        interface_inventory = []
        list_itf = []
        for ca in engine.contact_addresses:
            list_itf.append(ca.interface_id)
        uniq_list_itf = list(set(list_itf))
        for itf_id in uniq_list_itf:
            contact = engine.interface.get(itf_id).contact_addresses
            ip = contact[0].interface_ip
            interface_values = [itf_id, ip]
            interface_inventory.append(dict(zip(interface_keys, interface_values)))

        logging.info(f"interface_inventory={interface_inventory}")
    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1

    finally:
        engine = Layer3Firewall("myEngine")
        engine.delete()
        session.logout()
        return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example of creating an aggregated interface',
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
