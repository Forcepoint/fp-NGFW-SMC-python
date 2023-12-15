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
Example script to show how to use Protocol Agent
-create service using protocol agent and proxy service
-update proxy service
-check and delete
"""

# Python Base Import
import argparse
import logging
import sys

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.elements.protocols import ProtocolAgent  # noqa
from smc.elements.servers import ProxyServer  # noqa
from smc.elements.service import TCPService  # noqa

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

        pa = ProtocolAgent("SMTP")
        service = TCPService().create("myTCPService",
                                      min_dst_port=45,
                                      max_dst_port=50,
                                      protocol_agent=pa)
        proxy_service_value = service.protocol_agent_values.get('redir_cis')
        logging.info(proxy_service_value)

        # Get first proxy server
        logging.info("Get first proxy server..")
        proxy_server = list(ProxyServer.objects.all())[0]

        logging.info(f"Add proxy server {proxy_server.name} to protocol agent values")
        updated = service.protocol_agent_values.update(name='redir_cis', proxy_server=proxy_server)
        proxy_service_value = service.protocol_agent_values.get('redir_cis')
        logging.info(proxy_service_value)

        service.update()

        # Retrieve service and check proxy server is set
        logging.info("Get myTCPService..")
        service1 = TCPService("myTCPService")
        proxy_service_value = service1.protocol_agent_values.get('redir_cis')
        logging.info("******************")
        logging.info(proxy_service_value)
        logging.info(proxy_service_value.proxy_server)
        logging.info(proxy_server.name)
        logging.info((proxy_server))
        assert proxy_service_value.proxy_server.name == proxy_server.name
    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        logging.info("delete elements..")
        service = TCPService("myTCPService")
        service.delete()
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to use Protocol Agent',
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
