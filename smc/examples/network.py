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
Example script to show how to use Host and Router element.
"""
import argparse
import logging
import sys

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.elements.common import ThirdPartyMonitoring  # noqa
from smc.elements.network import Host, Router  # noqa
from smc.elements.other import Location  # noqa
from smc.elements.servers import LogServer  # noqa
from smc.elements.ssm import LoggingProfile, ProbingProfile  # noqa

HOST_NOT_CREATED_MSG = "Fail to create Host"
HOST_UPDATE_ERROR = "Failed to update Host"
HOST_NAME = 'test_host'
IPV6_ADDRESS = "2001:db8:3333:4444:5555:6666:7777:7777"
HOST_COMMENT = "This is testing of Host element."
ADDRESS1 = "192.168.1.1"
ADDRESS2 = "192.168.1.2"
ROUTER_NOT_CREATED_MSG = "Fail to create Router"
ROUTER_UPDATE_ERROR = "Failed to update Router"
ROUTER_NAME = 'test_router'
ROUTER_COMMENT = "This is testing of Router element."

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
        log_server = list(LogServer.objects.all())[0]
        location = list(Location.objects.all())[0]
        logging_profile = list(LoggingProfile.objects.all())[0]
        probing_profile = list(ProbingProfile.objects.all())[0]
        router = list(Router.objects.all())[0]
        third_party_monitoring = ThirdPartyMonitoring.create(encoding="UTF-8",
                                                             logging_profile_ref=logging_profile,
                                                             monitoring_log_server_ref=log_server,
                                                             netflow=True,
                                                             probing_profile_ref=probing_profile,
                                                             snmp_trap=True,
                                                             time_zone="Europe/Paris")
        # create Host
        host = Host.create(name=HOST_NAME, address=ADDRESS1, secondary=[ADDRESS2],
                           ipv6_address=IPV6_ADDRESS, third_party_monitoring=third_party_monitoring,
                           comment=HOST_COMMENT)

        assert host.address == ADDRESS1 and ADDRESS2 in host.secondary and \
               host.third_party_monitoring.monitoring_log_server_ref.href == log_server.href \
               and host.third_party_monitoring.snmp_trap, HOST_NOT_CREATED_MSG
        logging.info("Host created successfully.")
        monitoring = host.third_party_monitoring
        monitoring["snmp_trap"] = False
        host.update(ipv6_address=IPV6_ADDRESS, third_party_monitoring=monitoring)
        host = Host(HOST_NAME)
        assert host.ipv6_address == IPV6_ADDRESS and \
               not host.third_party_monitoring.snmp_trap, HOST_UPDATE_ERROR
        logging.info("Host updated successfully.")

        # create Router
        router = Router.create(ROUTER_NAME, address=ADDRESS1, secondary=[ADDRESS2],
                               ipv6_address=IPV6_ADDRESS,
                               third_party_monitoring=third_party_monitoring,
                               comment=ROUTER_COMMENT)

        assert router.address == ADDRESS1 and ADDRESS2 in router.secondary and \
               router.third_party_monitoring.monitoring_log_server_ref.href == log_server.href \
               and router.third_party_monitoring.snmp_trap, ROUTER_NOT_CREATED_MSG
        logging.info("Router created successfully.")
        monitoring = router.third_party_monitoring
        monitoring["snmp_trap"] = False
        router.update(ipv6_address=IPV6_ADDRESS, third_party_monitoring=monitoring)
        router = Router(ROUTER_NAME)
        assert router.ipv6_address == IPV6_ADDRESS and \
               not router.third_party_monitoring.snmp_trap, ROUTER_UPDATE_ERROR
        logging.info("Router updated successfully.")
    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        Host(HOST_NAME).delete()
        logging.info("Host deleted successfully.")
        Router(ROUTER_NAME).delete()
        logging.info("Router deleted successfully.")
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to use Host and Router element',
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
