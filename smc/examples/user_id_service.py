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
Example script to show how to use UserIDService.
"""
import argparse
import logging
import sys

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.administration.certificates.tls import TLSProfile  # noqa
from smc.elements.common import ThirdPartyMonitoring  # noqa
from smc.elements.profiles import UserIDService  # noqa
from smc.elements.servers import LogServer  # noqa
from smc.elements.ssm import LoggingProfile, ProbingProfile  # noqa

CREATE_FAILED = "Failed to create UserIDService"
UPDATE_FAILED = "Failed to update UserIDService"
ADDRESS = "127.0.0.1"
IPV6_ADDRESS = "2001:2db8:85a3:1111:2222:8a2e:1370:7334"
PORT = 5000
NAME = 'user_id_service_test'
MSG = "testing of user id service"
EXPIRE = 500
TIMEOUT = 20

logging.getLogger()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - '
                                               '%(name)s - [%(levelname)s] : %(message)s')


def main():
    return_code = 0
    try:
        arguments = parse_command_line_arguments()
        session.login(url=arguments.api_url, api_key=arguments.api_key,
                      login=arguments.smc_user,
                      pwd=arguments.smc_pwd, api_version=arguments.api_version)
        logging.info("session OK")
        tls = list(TLSProfile.objects.all())[0]
        log_server = list(LogServer.objects.all())[0]
        logging_profile = list(LoggingProfile.objects.all())[0]
        probing_profile = list(ProbingProfile.objects.all())[0]
        third_party_monitoring = ThirdPartyMonitoring.create(encoding="UTF-8",
                                                             logging_profile_ref=logging_profile,
                                                             monitoring_log_server_ref=log_server,
                                                             netflow=True,
                                                             probing_profile_ref=probing_profile,
                                                             snmp_trap=True,
                                                             time_zone="Europe/Paris")
        user_id_service = UserIDService.create(NAME,
                                               address="127.0.0.1",
                                               ipv6_address=IPV6_ADDRESS,
                                               monitored_user_domains=None,
                                               tls_field="DNSName",
                                               tls_value="10",
                                               tls_profile=tls,
                                               port=PORT,
                                               address_list=None,
                                               third_party_monitoring=third_party_monitoring,
                                               comment=MSG)
        assert user_id_service.address == ADDRESS and user_id_service.port == PORT and \
               user_id_service.tls_profile.href == tls.href and \
               user_id_service.third_party_monitoring.netflow and \
               user_id_service.third_party_monitoring.snmp_trap and \
               user_id_service.third_party_monitoring.monitoring_log_server_ref.href == \
               log_server.href, CREATE_FAILED
        logging.info("UserIDService successfully created.")
        user_id_service.update(cache_expiration=EXPIRE, connect_timeout=TIMEOUT)
        user_id_service = UserIDService(NAME)
        assert user_id_service.cache_expiration == EXPIRE and user_id_service.connect_timeout == \
               TIMEOUT, UPDATE_FAILED
        logging.info("UserIDService successfully updated.")
    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        UserIDService(NAME).delete()
        logging.info("Deleted UserIDService successfully.")
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to use UserIDService',
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
