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
Example script to show how to use Cloud L3 Firewall.
"""
import argparse
import logging
import sys
sys.path.append('../../')  # smc-python
from smc.core.engine import Engine  # noqa
from smc.core.engines import CloudSGSingleFW  # noqa
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

        # Cloud engine creation
        logging.info("Create cloud fw: Cloud Single firewall 1...")
        CloudSGSingleFW.create_dynamic(interface_id=0, name="Cloud Single firewall 1")

        # Should not use regular create method but create_dynamic instead
        # Since cloud firewall should use dynamic interface
        try:
            CloudSGSingleFW.create(name="test cloud name", mgmt_ip="1.1.1.1",
                                   mgmt_network="1.1.1.0/24")
        except Exception as e:
            logging.info(f"regular create method not supported : {e}")
            logging.info("The example can continue..")

        # Retrieve the Engine
        logging.info("Get cloud fw...")
        engine = Engine("Cloud Single firewall 1")
        logging.info(list(engine.nodes))

        logging.info("============================================================================="
                     "=========")
        logging.info(f"Firewall name: {engine}")
        logging.info(f"Firewall REF: {engine.href}")
        for node in engine.nodes:
            logging.info(f"Firewall nodes: {node}")
            logging.info(f"Firewall nodes: {node.href}")
        logging.info("============================================================================="
                     "=========")

        # Check node status
        logging.info("Get node status...")
        for node in engine.nodes:
            logging.info(f"Firewall node {node.name} status: {node.status()}")

    except Exception as e:
        logging.error(f"Exception:{e}")
        return_code = 1

    finally:
        engine = CloudSGSingleFW("Cloud Single firewall 1")
        engine.delete()
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to use Cloud L3 Firewall.',
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
