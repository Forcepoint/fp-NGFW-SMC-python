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
Example script to show how to subscribe to routing monitoring notifications using websocket library
or smc_monitoring extension
"""


# Python Base Import
import json
import ssl
import argparse
import logging
import sys


from websocket import create_connection

sys.path.append('../../../')  # smc-python
sys.path.append('../../../smc-monitoring')  # smc-python-monitoring
from smc import session  # noqa
from smc_monitoring.monitors.routes import RoutingQuery  # noqa
ENGINE_NAME = "Plano"

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
        logging.info("Retrieve all entries in routing table using websocket library")

        ws = create_connection(
            f"{arguments.ws_url}/{str(arguments.api_version)}/monitoring/session/socket",
            cookie=session.session_id,
            socket=session.sock,
            sslopt={"cert_reqs": ssl.CERT_NONE}
        )

        query = {
            "query": {"definition": "ROUTING", "target": ENGINE_NAME},
            "fetch": {},
            "format": {"type": "texts"},
        }
        try:
            ws.send(json.dumps(query))
            result = ws.recv()
            logging.info(f"Received '{result}'")
            fetch_id = json.loads(result)['fetch']
            result = ws.recv()
            logging.info(f"Received '{result}'")
        finally:
            ses_mon_abort_query = {"abort": fetch_id}
            ws.send(json.dumps(ses_mon_abort_query))
            ws.close()

        logging.info(" ")
        logging.info("Retrieve all entries in routing table using smc_monitoring fetch_batch")
        query = RoutingQuery(target=ENGINE_NAME)
        for record in query.fetch_batch(query_timeout=10):
            logging.info(record)

        logging.info("Retrieve all entries in routing table using smc_monitoring fetch_as_element")
        query = RoutingQuery(target=ENGINE_NAME)

        # retrieve All RoutingView initial elements (first_fetch True)
        # Use max_recv to stop fetching elements after 2mn query or 20s inactivity
        for element in query.fetch_as_element(max_recv=0, query_timeout=120, inactivity_timeout=20):
            logging.info(element)

    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to routing monitoring notifications using '
                    'websocket library or smc_monitoring extension',
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
        '--ws-url',
        type=str,
        help='SMC WS url like https://192.168.1.1:8082')
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
