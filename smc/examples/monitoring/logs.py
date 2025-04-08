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
Example script to show how to subscribe to LOGS notifications using websocket library
or smc_monitoring extension and to use filters
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
from smc_monitoring.monitors.logs import LogQuery  # noqa
from smc.administration.filter import Filter  # noqa
from smc_monitoring.models.values import (FieldValue,
                                          NumberValue, TranslatedValue, ServiceValue,
                                          IPValue)  # noqa
from smc_monitoring.models.filters import InFilter, QueryFilter  # noqa
from smc_monitoring.models.constants import LogField  # noqa
from smc_monitoring.wsocket import (FetchAborted, BUFFER_ERROR)  # noqa

FILTER_FAILED = "filter failed!"
LIST_OF_FILTER_TYPES = ['Inspection', 'Packet Filtering']
EXISTING_FILTER_FAILED = "Fail to get log with existing filter."
INVALID_FILTER = "Fail to get logs, invalid filter."

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
        logging.info("Retrieve logs using websocket library")

        ws = create_connection(
            f"{arguments.ws_url}/{str(arguments.api_version)}/monitoring/log/socket",
            cookie=session.session_id,
            sslopt={"cert_reqs": ssl.CERT_NONE},
            subprotocols={"access_token", session._token} if session._token else None,
            verify=False)

        # show how to use operator "or" with  source port = 22, 25
        #                                 or type translated source port = 7000
        #                                 or type translated dst ip = 74.125.127.191
        #                                 or type translated protocol = "TCP"
        query = {
            'query': {'start_ms': 0, 'end_ms': 0, 'type': 'stored',
                      "filter": {"type": "or",
                                 "values": [
                                     {"type": "in", "left": {"type": "field", "id": LogField.DPORT},
                                      "right": [{"type": "number", "value": 22},
                                                {"type": "number", "value": 25}]},
                                     {"type": "translated", "value": "$Sport == 7000"},
                                     {"type": "translated",
                                      "value": "$Dst == ipv4( 74.125.127.191 )"},
                                     {"type": "translated", "value": "$Protocol == \"TCP\""}]
                                 }},
            'fetch': {'quantity': 1, 'backwards': True},
            'format': {'type': 'texts', 'field_format': 'pretty', 'resolving': {'senders': True}}
        }

        try:
            logging.info("Get filtered logs using native Websocket..")
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

        # test NumberValue
        logging.info(" ")
        logging.info("Get filtered dst port or service logs using LogQuery add_or_filter "
                     "and InFilter..")
        query = LogQuery(fetch_size=10)
        #        query = LogQuery(max_recv=0)
        query.add_or_filter([
            InFilter(FieldValue(LogField.DPORT), [NumberValue(80)]),
            InFilter(FieldValue(LogField.SERVICE), [ServiceValue('TCP/80')])])

        a = list(query.fetch_raw())
        for log in a:
            for entry in log:
                logging.info(entry)
                dst_port = entry.get("Dst Port")
                assert (dst_port == '80'), FILTER_FAILED

        # test NumberValue
        logging.info(" ")
        logging.info("Get filtered dst port logs using LogQuery add_in_filter..")
        query = LogQuery(fetch_size=10)
        query.add_in_filter(FieldValue(LogField.DPORT), [NumberValue(22, 25)])

        a = list(query.fetch_raw())
        for log in a:
            for entry in log:
                logging.info(entry)
                dst_port = entry.get("Dst Port")
                assert (dst_port == '22' or dst_port == '25'), FILTER_FAILED

        # test TranslatedFilter
        logging.info("")
        logging.info("Get filtered src port logs using LogQuery translated_filter..")
        query = LogQuery(fetch_size=10)
        translated_filter = query.add_translated_filter()
        translated_filter.update_filter("$Sport == 7000 OR $Sport == 7001")

        a = list(query.fetch_raw())
        for log in a:
            for entry in log:
                logging.info(entry)
                src_port = entry.get("Src Port")
                assert (src_port == '7000' or src_port == '7001'), FILTER_FAILED

        #   test TranslatedFilter with defined functions example
        logging.info(" ")
        logging.info("Get filtered logs using LogQuery translated_filter special functions..")
        query = LogQuery(fetch_size=10)
        translated_filter = query.add_translated_filter()
        # use special filter functions
        translated_filter.within_ipv4_network('$Dst', ['192.168.4.0/24'])
        #    translated_filter.within_ipv4_range('$Src', ['1.1.1.1-192.168.1.254'])
        #    translated_filter.exact_ipv4_match('$Src', ['172.18.1.152', '192.168.4.84'])

        a = list(query.fetch_raw())
        for log in a:
            logging.info(log)

        # test TranslatedValue
        logging.info(" ")
        logging.info("Get filtered dst port logs using LogQuery QueryFilter update_filter "
                     "TranslatedValue..")
        query = LogQuery(fetch_size=10)
        query_filter = QueryFilter("translated")
        query_filter.update_filter(TranslatedValue("$Dport == 22 OR $Dport == 25").value)
        query.update_filter(query_filter)

        a = list(query.fetch_raw())
        for log in a:
            for entry in log:
                logging.info(entry)
                dst_port = entry.get("Dst Port")
                assert (dst_port == '22' or dst_port == '25'), FILTER_FAILED

        # test existing filter
        query = LogQuery(fetch_size=10)
        query.add_existing_filter(Filter("Inspection and Packet Filter Facility"))
        logs = list(query.fetch_raw())
        if logs:
            for log in logs[0]:
                assert log['Facility'] in LIST_OF_FILTER_TYPES, EXISTING_FILTER_FAILED
            logging.info("Get filtered logs using LogQuery with existing filter.")

        # check query filter limit
        is_fetch_aborted = False
        try:
            list_all_ip = tuple([f'10.1.1.{i}' for i in range(1, 204)])
            query = LogQuery(fetch_size=10)
            query.add_and_filter([
                InFilter(FieldValue(LogField.DST), [IPValue(*list_all_ip)]),
                InFilter(FieldValue(LogField.SERVICE), [ServiceValue('TCP/80')])])
            list(query.fetch_raw())
        except FetchAborted as ex:
            if BUFFER_ERROR.decode("utf-8") in str(ex):
                is_fetch_aborted = True
        assert is_fetch_aborted, INVALID_FILTER
    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to subscribe to LOGS notifications using websocket '
                    'library or smc_monitoring extension and to use filters',
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
