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
Example script to show how to use Servers
-get logserver
-create Netflow collector
-add Netflow collectors to log server
-remove a Netflow collector from log server
"""

# Python Base Import
import argparse
import logging
import sys
import time
import requests

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.administration.certificates.tls import TLSServerCredential, TLSCryptographySuite, \
    TLSProfile  # noqa
from smc.elements.network import Host  # noqa
from smc.elements.other import FilterExpression  # noqa
from smc.elements.servers import LogServer, DataContext, NetflowCollector, ManagementServer  # noqa

logging.getLogger()
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - '
                                                '%(name)s - [%(levelname)s] : %(message)s')


def check_if_smc_api_is_running(smc_url, cert=False):
    api_url = f"{smc_url}/api"
    _check_if_web_app_is_running(api_url, "version", cert, max_wait_time=180)


def _check_if_web_app_is_running(url, pattern, cert=False, max_wait_time=120):
    logging.debug(f"URL is ==> {url}")
    api_session = requests.Session()
    timeout = time.time() + max_wait_time
    while True:
        try:
            response = api_session.get(url, verify=cert)
            if response.text.__contains__(pattern):
                logging.info("Web app is up and running")
                break
        except Exception as exc:
            # Web APP SMC API not yet ready
            logging.debug(exc)
            time.sleep(2)

        if time.time() > timeout:
            logging.error("Timeout while waiting for web app to be up and running.")
            raise TimeoutError
        time.sleep(1)


def update_mgt_server(secure=False):
    for mgt_server in ManagementServer.objects.all():
        for webapp in mgt_server.web_app:
            logging.info(f"web_app={webapp}")
            if webapp["web_app_identifier"] == "smc_api":
                logging.info(f"set SSL mode with SSl session ID enabled={secure} ..")
                webapp["ssl_session_id"] = True if secure else False
                webapp["server_credentials_ref"] = list(TLSServerCredential.objects.all())[0].href\
                    if secure else None
                webapp["tls_cipher_suites"] = list(TLSCryptographySuite.objects.all())[0].href\
                    if secure else None
                # Save and restart mgt server
                mgt_server.update(json=mgt_server.data)


def main():
    return_code = 0
    arguments = parse_command_line_arguments()
    try:
        session.login(url=arguments.api_url, api_key=arguments.api_key,
                      login=arguments.smc_user,
                      pwd=arguments.smc_pwd, api_version=arguments.api_version)
        logging.info("session OK")

        update_mgt_server(secure=True)
        session.logout()

        # wait for webapp to restart
        SMC_URL = arguments.api_url.replace("http", "https")
        check_if_smc_api_is_running(SMC_URL)

        session.login(url=SMC_URL, api_key=arguments.api_key,
                      login=arguments.smc_user,
                      pwd=arguments.smc_pwd, api_version=arguments.api_version)
        logging.info("Login Ok")

        for log_server in LogServer.objects.all():
            logging.info(f"LS={log_server}")
        log_server = LogServer.get("Log Server")

        # Wait for session timeout
        logging.info("Wait for user session timeout..")
        logging.info("So we can force a Login refresh")
        time.sleep(120)

        # Create Netflow Collectors
        data_context = DataContext.get("All Log Data")
        filter_expression = FilterExpression.get("OMAPI Connections")
        host1 = Host.get("DNS 1")
        tls_profile = list(TLSProfile.objects.all())[0]
        tls_identity = {
            "tls_field": "IPAddress",
            "tls_value": "10.10.1.1"
        }
        netflow_collector1 = NetflowCollector(
            data_context=data_context,
            filter=filter_expression,
            host=host1,
            netflow_collector_port=255,
            netflow_collector_service="tcp_with_tls",
            netflow_collector_version="netflow_v9",
            tls_profile=tls_profile.href,
            tlsIdentity=tls_identity
        )
        host2 = Host.get("DNS 2")
        netflow_collector2 = NetflowCollector(
            data_context=data_context,
            host=host2,
            netflow_collector_port=255,
            netflow_collector_service="udp",
            netflow_collector_version="netflow_v9",
        )
        list_netflow_collector = list()
        list_netflow_collector.append(netflow_collector1)
        list_netflow_collector.append(netflow_collector2)

        # Add Netflow Collectors to log server
        logging.info(f"Add netflow collector list:{list_netflow_collector}...")
        log_server.add_netflow_collector(list_netflow_collector)

        for netflow_collector in log_server.netflow_collector:
            logging.info(f"NF ={netflow_collector}")

        logging.info("Remove netflow collector:{netflow_collector2}")
        # Remove Netflow Collector from log server
        log_server.remove_netflow_collector(netflow_collector2)

        for netflow_collector in log_server.netflow_collector:
            logging.info(f"NF ={netflow_collector}")

        logging.info(f"Remove netflow collector:{netflow_collector1}")
        # Remove Netflow Collector from log server
        log_server.remove_netflow_collector(netflow_collector1)
    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        logging.info("Finally: Cleaning...")
        # reconnect to new session in case login refresh was not done automatically
        # SMC return 404 instead of 401 case
        session.logout()
        session.login(url=arguments.api_url, api_key=arguments.api_key,
                      login=arguments.smc_user,
                      pwd=arguments.smc_pwd, api_version=arguments.api_version)
        logging.info("Login Ok")
        logging.info("Set server to http protocol..")
        update_mgt_server(secure=False)
        logging.info("Wait 20s for api to restart..")
        # Have to wait some times to be sure all threads run to the web app are terminated
        time.sleep(20)
        SMC_URL = arguments.api_url.replace("https", "http")
        check_if_smc_api_is_running(SMC_URL)
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to use Servers',
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
