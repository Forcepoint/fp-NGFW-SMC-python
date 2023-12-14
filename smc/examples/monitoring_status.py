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
Example script to show monitoring status usage.
"""

# Python Base Import
import argparse
import logging
import sys

# Python SMC Import
sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.administration.monitoring_status import MonitoringStatus  # noqa
from smc.compat import min_smc_version, is_smc_version_less_than  # noqa
from smc.core.engines import Layer3Firewall, Layer3VirtualEngine  # noqa
from smc.elements.servers import ManagementServer  # noqa
from smc.vpn.policy import PolicyVPN  # noqa

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
        # get status for Firewall
        fw = Layer3Firewall("Plano")
        status = MonitoringStatus.get_status(href=fw.href)
        logging.info(f"Firewall status monitoring={status}")
        logging.info(f"History is {status.history}")
        # get SDWAN status in result
        for sub_status in status.result:
            sub_status = MonitoringStatus.get_status(href=sub_status.get("href"))
            logging.info(f"sub status monitoring={sub_status}")

        # get Nodes status
        for node in fw.nodes:
            status = MonitoringStatus.get_status(href=node.href)
            logging.info(f"Node status monitoring={status}")

        # get status for Mgt Server
        mgt = ManagementServer.objects.first()
        status = MonitoringStatus.get_status(href=mgt.href)
        logging.info(f"status monitoring={status}")

        # get status for virtual firewall and nodes
        virtual = Layer3VirtualEngine.objects.first()
        status = MonitoringStatus.get_status(href=virtual.href)
        logging.info(f"status monitoring={status}")
        for node in virtual.nodes:
            status = MonitoringStatus.get_status(href=node.href)
            logging.info(f"Node status monitoring={status}")
            # master_node field exists since SMC 6.10 (all api versions)
            if min_smc_version("6.10"):
                logging.info(f"Master Node={status.master_node}")
        vpn = PolicyVPN("Corporate VPN")
        vpn = PolicyVPN("Corporate SD-WAN")
        status = MonitoringStatus.get_status(href=vpn.href)
        logging.info(f"vpn status monitoring={status}")

        # get tunnel status in result
        for sub_status in status.result:
            sub_status = MonitoringStatus.get_status(href=sub_status.get("href"))
            logging.info(f"tunnel status monitoring={sub_status}")

    except BaseException as e:
        logging.error(f"Error:{e}")
        exit(-1)
    finally:
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show monitoring status usage',
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
