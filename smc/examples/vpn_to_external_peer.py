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
VPN Configuration

Create a VPN external gateway to be used in a Policy Based VPN configuration.
An External Gateway is a non-SMC managed peer defining the remote IP connectivity
information as well as the remote network site information.
Sites are defined to identify the remote networks protected behind the VPN peer
network.

"""
import argparse
import logging
import sys
sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.elements.network import Network  # noqa
from smc.core.engines import Engine, Layer3Firewall  # noqa
from smc.vpn.elements import ExternalGateway  # noqa
from smc.vpn.policy import PolicyVPN  # noqa

logging.getLogger()
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - '
                                                '%(name)s - [%(levelname)s] : %(message)s')


def create_single_fw():
    """
    Create single layer 3 firewall for this example
    """
    Layer3Firewall.create(name="testfw", mgmt_ip="192.168.10.1", mgmt_network="192.168.10.0/24")


def main():
    return_code = 0
    try:
        arguments = parse_command_line_arguments()
        session.login(url=arguments.api_url, api_key=arguments.api_key,
                      login=arguments.smc_user,
                      pwd=arguments.smc_pwd, api_version=arguments.api_version)

        create_single_fw()

        """
        An external gateway defines a non-SMC managed gateway device that acts as a
        remote VPN peer.
        First create the external gateway element
        """
        external_gateway = ExternalGateway.create("mygw")

        """
        An external endpoint is defined within the external gateway and specifies the
        IP address settings and other VPN specific settings for this endpoint
        After creating, add to the external gateway
        """
        external_gateway.external_endpoint.create(name="myendpoint", address="2.2.2.2")

        """
        Lastly, 'sites' need to be configured that identify the network/s on the
        other end of the VPN. You can either use pre-existing network elements, or create
        new ones as in the example below.
        Then add this site to the external gateway
        """
        network = Network.create("remote-network", "1.1.1.0/24").href

        external_gateway.vpn_site.create("remote-site", [network])

        """
        Retrieve the internal gateway for SMC managed engine by loading the
        engine configuration. The internal gateway reference is located as
        engine.internal_gateway.href
        """
        engine = Engine("testfw").load()

        """
        Create the VPN Policy
        """
        vpn = PolicyVPN.create(name="myVPN", nat=True)
        logging.info(vpn.name, vpn.vpn_profile)

        vpn.open()
        vpn.add_central_gateway(engine.internal_gateway.href)
        vpn.add_satellite_gateway(external_gateway.href)
        vpn.save()
        vpn.close()
    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to create a VPN external gateway to be used in a '
                    'Policy Based VPN configuration.',
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
