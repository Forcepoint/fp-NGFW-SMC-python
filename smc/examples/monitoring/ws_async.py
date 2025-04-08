#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Example script to show how to subscribe to LOGS, ALERT or SESSION monitoring notifications
using callback methods and how to use formatters
"""
import argparse
import logging
import sys
# Python Base Import
import time

sys.path.append('../../../')  # smc-python
sys.path.append('../../../smc-monitoring')  # smc-python-monitoring
from smc import session  # noqa
from smc_monitoring.monitors.alerts import ActiveAlertQuery, Alert  # noqa
from smc_monitoring.monitors.logs import LogQuery  # noqa
from smc_monitoring.monitors.neighbors import NeighborQuery, Neighbor  # noqa
from smc_monitoring.monitors.routes import RoutingQuery, RoutingView  # noqa
from smc_monitoring.wsocket import SMCSocketAsyncProtocol  # noqa
from smc_monitoring.models.formatters import RawDictFormat, ElementFormat, TableFormat  # noqa
from smc_monitoring.models.values import (FieldValue, NumberValue, ServiceValue,
                                          ConstantValue)  # noqa
from smc_monitoring.models.filters import InFilter  # noqa
from smc_monitoring.models.constants import LogField, Alerts  # noqa

from smc.core.engine import Engine  # noqa

FILTER_FAILED = "filter failed!"
ENGINENAME = "Plano"
FORMAT = "%(asctime)s - %(levelname)s - %(message)s"

# counters to validate messages received
nb_alert_raw = 0
nb_alert_element = 0
nb_log_table = 0
nb_log_table_serial = 0
nb_routing_element = 0
nb_routing_table = 0
nb_neighbor_element = 0

logging.getLogger()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - '
                                               '%(name)s - [%(levelname)s] : %(message)s')


# CALLBACK function definition
def callback_log_table_fct_serial(wso, data):
    global nb_log_table_serial
    nb_log_table_serial += 1
    logging.info(f"Serial WS Logs table received :{nb_log_table_serial}")


def callback_alert_element_fct(wso, element):
    global nb_alert_element
    nb_alert_element += 1
    logging.info(f"Alert received:{nb_alert_element}")
    logging.info(element)


def callback_log_table_fct(wso, data):
    global nb_log_table
    nb_log_table += 1
    logging.info(f"Logs table received :{nb_log_table}")


def callback_routing_element_fct(wso, element):
    global nb_routing_element
    nb_routing_element += 1
    logging.info(f"Routing received ElementFormat:{nb_routing_element}")
    logging.info(element)


def callback_routing_table_fct(wso, message):
    global nb_routing_table
    nb_routing_table += 1
    logging.info(f"Routing received TableFormat {nb_routing_table}:")
    logging.info(message)


def callback_neighbor_element_fct(wso, element):
    global nb_neighbor_element
    nb_neighbor_element += 1
    logging.info(f"Neighbor received:{nb_neighbor_element}")
    logging.info(element)


def main():
    return_code = 0
    try:
        arguments = parse_command_line_arguments()
        session.login(url=arguments.api_url, api_key=arguments.api_key,
                      login=arguments.smc_user,
                      pwd=arguments.smc_pwd, api_version=arguments.api_version)
        logging.info("session OK")

        # SERIAL RUN 2 WS ( use background=True but force close after 10s )

        logging.info("=== SERIAL A - Retrieve logs using AsyncProtocol ===")

        logQuery = LogQuery()
        logQuery.add_or_filter([
            InFilter(FieldValue(LogField.DPORT), [NumberValue(80)]),
            InFilter(FieldValue(LogField.SERVICE), [ServiceValue('TCP/80')])])
        logQuery.request["fetch"].update(quantity=400)
        ws1 = SMCSocketAsyncProtocol(query=logQuery,
                                     on_message_fct=callback_log_table_fct_serial,
                                     formatter=TableFormat)

        ws1.run(background=True)
        time.sleep(10)
        ws1.close()

        # CONTINUE IN PARALLEL 5 WS ( use background=True )

        logging.info("=== 1 -  Retrieve alerts using Async Protocol ===")

        query = ActiveAlertQuery()
        query.add_in_filter(
            FieldValue(LogField.ALERTSEVERITY), [ConstantValue(Alerts.CRITICAL)])

        async_ws1 = SMCSocketAsyncProtocol(query=query,
                                           on_message_fct=callback_alert_element_fct,
                                           formatter=ElementFormat,
                                           element_name=Alert)
        # this call is blocking if background=False
        async_ws1.run(background=True)

        logging.info("main thread running..")

        logging.info("=== 2 - Retrieve logs using AsyncProtocol ===")

        logging.info("Get filtered dst port or service logs using LogQuery add_or_filter and "
                     "InFilter..")
        async_ws2 = SMCSocketAsyncProtocol(query=logQuery,
                                           on_message_fct=callback_log_table_fct,
                                           formatter=TableFormat)

        async_ws2.run(background=True)

        logging.info("main thread running..")

        logging.info("=== 3 - Retrieve all entries in routing table using AsyncProtocol and  "
                     "ElementFormat")

        engine = Engine(ENGINENAME)
        logging.info(f"engine={engine}")

        query = RoutingQuery(target=ENGINENAME)
        async_ws3 = SMCSocketAsyncProtocol(query=query,
                                           on_message_fct=callback_routing_element_fct,
                                           formatter=ElementFormat,
                                           element_name=RoutingView)
        async_ws3.run(background=True)
        # sleep 10
        time.sleep(10)
        logging.info("main thread running..")

        logging.info("=== 4 - Retrieve all entries in routing table using AsyncProtocol and "
                     "TableFormat")

        query = RoutingQuery(target=ENGINENAME)
        async_ws4 = SMCSocketAsyncProtocol(query=query,
                                           on_message_fct=callback_routing_table_fct,
                                           formatter=TableFormat)
        async_ws4.run(background=True)

        logging.info("main thread running..")

        logging.info("=== 5 - Retrieve all Neighbor elements using AsyncProtocol ===")

        query = NeighborQuery(ENGINENAME)
        async_ws5 = SMCSocketAsyncProtocol(query=query,
                                           on_message_fct=callback_neighbor_element_fct,
                                           formatter=ElementFormat,
                                           element_name=Neighbor)
        # this call is blocking if background=False
        async_ws5.run(background=True)

        logging.info("main thread running..")

        # Sleep to let all data coming from WS before ending
        time.sleep(20)

    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        logging.info(f"serial log table={nb_log_table_serial}")
        logging.info(f"alert element={nb_alert_element}")
        logging.info(f"log table={nb_log_table}")
        logging.info(f"routing element={nb_routing_element}")
        logging.info(f"routing table={nb_routing_table}")
        logging.info(f"neighbor element={nb_neighbor_element}")
        # close all the web socket connections
        async_ws1.close()
        async_ws2.close()
        async_ws3.close()
        async_ws4.close()
        async_ws5.close()

        assert nb_log_table_serial > 0 \
               and nb_alert_element > 0 \
               and nb_log_table > 0 \
               and nb_routing_element > 0 \
               and nb_routing_table > 0 \
               and nb_neighbor_element > 0, "Some WS data not received"

        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to subscribe to LOGS, ALERT or SESSION monitoring '
                    'notifications using callback methods and how to use formatters',
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
