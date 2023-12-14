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
Example of creating and accessing internal gateway certificate.
"""
import argparse
import logging
import sys
import time
sys.path.append('../../')  # smc-python
from smc.core.engines import Layer3Firewall  # noqa
from smc import session  # noqa

RETRY_ONLINE = 30
FW_NAME = 'myFW'
NOT_EXPIRE_DATE_ERR = "Expire date is not available"

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
        engine = Layer3Firewall.create(name=FW_NAME,
                                       mgmt_ip="192.168.10.1",
                                       mgmt_network="192.168.10.0/24")
        logging.info("initial contact and license..")
        for node in engine.nodes:
            node.initial_contact()
            node.bind_license()
        # wait time for engine to be online
        online = False
        retry = 0
        while not online and retry < RETRY_ONLINE:
            status = engine.nodes[0].status().monitoring_state
            online = status == "READY"
            time.sleep(5)
            retry += 1
        engine.internal_gateway.generate_certificate(
            engine.internal_gateway.name)
        temp_list = engine.vpn.gateway_certificate
        assert temp_list[0].expiration is not None, NOT_EXPIRE_DATE_ERR
    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        engine = Layer3Firewall(FW_NAME)
        engine.delete()
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example of creating and accessing internal gateway certificate.',
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
