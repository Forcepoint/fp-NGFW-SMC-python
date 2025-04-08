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
Example script to show how to subscribe to NEIGHBORS notifications using websocket library
or smc_monitoring extension
"""

import argparse
# Python Base Import
import json
import logging
import ssl
import sys

from websocket import create_connection

sys.path.append('../../../')  # smc-python
sys.path.append('../../../smc-monitoring')  # smc-python-monitoring
from smc import session  # noqa
from smc_monitoring.monitors.neighbors import NeighborQuery  # noqa
from smc_monitoring.models.values import FieldValue, StringValue  # noqa
from smc_monitoring.models.constants import LogField  # noqa

ENGINENAME = "Plano"

logging.getLogger()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - '
                                               '%(name)s - [%(levelname)s] : %(message)s')


def main():
    return_code = 0
    try:
        arguments = parse_command_line_arguments()
        session.login(url=arguments.api_url, api_key=arguments.api_key,
                      login=arguments.smc_user,
                      pwd=arguments.smc_pwd, api_version=arguments.api_version,
                      verify=False)
        logging.info("session OK")
        logging.info("Retrieve Neighbors using websocket library")

        ws = create_connection(
            f"{arguments.ws_url}/{str(arguments.api_version)}/monitoring/session/socket",
            cookie=session.session_id,
            subprotocols={"access_token", session._token} if session._token else None,
            sslopt={"cert_reqs": ssl.CERT_NONE}
        )

        query = {
            "query": {"definition": "NEIGHBORS", "target": ENGINENAME},
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

        logging.info("")
        logging.info("Retrieve IPv6 Neighbors Data using smc_monitoring")
        query = NeighborQuery(ENGINENAME)
        query.add_in_filter(FieldValue(LogField.NEIGHBORPROTOCOL), [StringValue("IPv6")])
        for record in query.fetch_batch():
            logging.info(record)

        logging.info("Retrieve all Neighbor elements using smc_monitoring")
        query = NeighborQuery(ENGINENAME)
        for element in query.fetch_as_element(max_recv=1):
            logging.info(f"{element.first_fetch} {element.node_id} {element.neighbor_state} "
                         f"{element.neighbor_interface} {element.neighbor_protocol} "
                         f"{element.neighbor_l3_data}->{element.neighbor_l2_data}")
    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to subscribe to NEIGHBORS notifications '
                    'using websocket library or smc_monitoring extension',
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
        help='SMC WS url like https://192.168.1.1:8085')
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
