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
Example script to show how to use Internal Gateways from L3 Firewalls.
"""
import argparse
import logging
import sys

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.core.engines import Layer3Firewall  # noqa
from smc.vpn.elements import ConnectionType  # noqa

NOT_CREATED_MSG = "Fail to create internal gateway"
ERROR_IN_GET_ALL_GATEWAY = "Not received list of all internal gateways."
ERROR_IN_GETEWAY_DEL = "Error in delete internal gateway"
GATEWAY_UPDATE_ERROR = "Failed to update an internal gateway"
UPDATE_CONN_TYPE_ERROR = "Failed to update connection type in internal endpoint"
RETRY_ONLINE = 30
FW_NAME = 'myFW'
TEST_GATEWAY = 'test_gateway'

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
        engine.create_internal_gateway(TEST_GATEWAY)
        list_of_vpn_object = engine.all_vpns
        assert len(list_of_vpn_object) >= 2, ERROR_IN_GET_ALL_GATEWAY
        is_vpn_gateway_created = False
        for vpn in list_of_vpn_object:
            if vpn.name == TEST_GATEWAY:
                # update connection type in internal endpoint
                standby_con_type = ConnectionType("Standby")
                for endpoint in engine.vpn.internal_endpoint:
                    endpoint.update(connection_type_ref=standby_con_type.href)
                    assert endpoint.data.get(
                        "connection_type_ref") == standby_con_type.href, UPDATE_CONN_TYPE_ERROR
                    logging.info("Updated connection type to standby successfully.")
                is_vpn_gateway_created = True
                vpn.vpn_client.update(
                    firewall=True, antivirus=True)
                assert vpn.vpn_client.firewall and vpn.vpn_client.antivirus, GATEWAY_UPDATE_ERROR
                vpn.remove()
                assert len(vpn.engine.all_vpns) == 1, ERROR_IN_GETEWAY_DEL
                break
        assert is_vpn_gateway_created, NOT_CREATED_MSG
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
        description='Example script to show how to use Internal Gateways from L3 Firewalls',
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
