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
Example script to show how to use Vpn Site.
"""
import argparse
import logging
import sys

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.core.engines import Layer3Firewall  # noqa
from smc.vpn.elements import ConnectionType  # noqa
from smc.core.engine import Engine  # noqa
from smc.vpn.policy import PolicyVPN  # noqa

ERROR_CREATE_VPN_SITE = "Fail to add vpn site."
ERROR_UPDATE_VPN_SITE = "Fail to update vpn site."
ENGINE_NAME = "Plano"
ENABLED = "enabled"
VPN_REFERENCE = "vpn_references"
SITE_MODE = "site_mode"
VPN_SITE_NAME = "test_vpn_site"
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

        policy_vpn = PolicyVPN('Corporate SD-WAN')
        policy_vpn.open()
        engine = Engine(ENGINE_NAME)
        policy_vpn.add_central_gateway(Engine(ENGINE_NAME))

        policy_vpn.save()
        policy_vpn.close()
        engine.vpn.add_site(name=VPN_SITE_NAME, site_elements=[engine.href])
        site = engine.vpn.sites.get_contains(VPN_SITE_NAME)
        assert site.data[VPN_REFERENCE][0][ENABLED] and \
               site.data[VPN_REFERENCE][0][SITE_MODE] == 'Normal', ERROR_CREATE_VPN_SITE
        site.data[VPN_REFERENCE][0][ENABLED] = False
        site.data[VPN_REFERENCE][0][SITE_MODE] = 'Hub'
        site.update()
        engine = Engine(ENGINE_NAME)
        site = engine.vpn.sites.get_contains(VPN_SITE_NAME)
        assert not site.data[VPN_REFERENCE][0][ENABLED] and \
               site.data[VPN_REFERENCE][0][SITE_MODE] == 'Hub', ERROR_UPDATE_VPN_SITE
    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to use Vpn Site',
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
