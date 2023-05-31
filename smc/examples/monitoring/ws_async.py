"""
Example script to show how to subscribe to LOGS, ALERT or SESSION monitoring notifications
using callback methods and how to use formatters
"""
import logging
# Python Base Import
import time

from smc import session
from smc_monitoring.monitors.alerts import ActiveAlertQuery, Alert
from smc_monitoring.monitors.logs import LogQuery
from smc_monitoring.monitors.neighbors import NeighborQuery, Neighbor
from smc_monitoring.monitors.routes import RoutingQuery, RoutingView
from smc_monitoring.wsocket import SMCSocketAsyncProtocol
from smc_monitoring.models.formatters import RawDictFormat, ElementFormat, TableFormat
from smc_monitoring.models.values import FieldValue, NumberValue, ServiceValue, ConstantValue
from smc_monitoring.models.filters import InFilter
from smc_monitoring.models.constants import LogField, Alerts

from smc.core.engine import Engine
from smc_info import SMC_URL, API_KEY, API_VERSION

FILTER_FAILED = "filter failed!"
ENGINENAME = "Plano"
FORMAT = "%(asctime)s - %(levelname)s - %(message)s"


# CALLBACK function definition
def callback_log_table_fct_serial(wso, data):
    global nb_log_table_serial
    nb_log_table_serial += 1
    print("Serial WS Logs table received :{}".format(nb_log_table_serial))


def callback_alert_element_fct(wso, element):
    global nb_alert_element
    nb_alert_element += 1
    print("Alert received:{}".format(nb_alert_element))
    print(element)


def callback_log_table_fct(wso, data):
    global nb_log_table
    nb_log_table += 1
    print("Logs table received :{}".format(nb_log_table))


def callback_routing_element_fct(wso, element):
    global nb_routing_element
    nb_routing_element += 1
    print("Routing received ElementFormat:{}".format(nb_routing_element))
    print(element)


def callback_routing_table_fct(wso, message):
    global nb_routing_table
    nb_routing_table += 1
    print("Routing received TableFormat {}:".format(nb_routing_table))
    print(message)


def callback_neighbor_element_fct(wso, element):
    global nb_neighbor_element
    nb_neighbor_element += 1
    print("Neighbor received:{}".format(nb_neighbor_element))
    print(element)


if __name__ == '__main__':
    logging.getLogger()
    logging.basicConfig(level=logging.DEBUG, format=FORMAT, datefmt="%H:%M:%S")

    session.login(url=SMC_URL,
                  api_key=API_KEY,
                  verify=False,
                  timeout=120,
                  api_version=API_VERSION,
                  pool_maxsize=1)
    print("session OK")

try:

    # counters to validate messages received
    nb_alert_raw = 0
    nb_alert_element = 0
    nb_log_table = 0
    nb_log_table_serial = 0
    nb_routing_element = 0
    nb_routing_table = 0
    nb_neighbor_element = 0

    # SERIAL RUN 2 WS ( use background=True but force close after 10s )

    print("=== SERIAL A - Retrieve logs using AsyncProtocol ===")

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

    print("=== 1 -  Retrieve alerts using Async Protocol ===")

    query = ActiveAlertQuery()
    query.add_in_filter(
        FieldValue(LogField.ALERTSEVERITY), [ConstantValue(Alerts.CRITICAL)])

    async_ws1 = SMCSocketAsyncProtocol(query=query,
                                       on_message_fct=callback_alert_element_fct,
                                       formatter=ElementFormat,
                                       element_name=Alert)
    # this call is blocking if background=False
    async_ws1.run(background=True)

    print("main thread running..")

    print("=== 2 - Retrieve logs using AsyncProtocol ===")

    print("Get filtered dst port or service logs using LogQuery add_or_filter and InFilter..")
    async_ws2 = SMCSocketAsyncProtocol(query=logQuery,
                                       on_message_fct=callback_log_table_fct,
                                       formatter=TableFormat)

    async_ws2.run(background=True)

    print("main thread running..")

    print("=== 3 - Retrieve all entries in routing table using AsyncProtocol and  ElementFormat")

    engine = Engine(ENGINENAME)
    print("engine={}".format(engine))

    query = RoutingQuery(target=ENGINENAME)
    async_ws3 = SMCSocketAsyncProtocol(query=query,
                                       on_message_fct=callback_routing_element_fct,
                                       formatter=ElementFormat,
                                       element_name=RoutingView)
    async_ws3.run(background=True)
    # sleep 10
    time.sleep(10)
    print("main thread running..")

    print("=== 4 - Retrieve all entries in routing table using AsyncProtocol and TableFormat")

    query = RoutingQuery(target=ENGINENAME)
    async_ws4 = SMCSocketAsyncProtocol(query=query,
                                       on_message_fct=callback_routing_table_fct,
                                       formatter=TableFormat)
    async_ws4.run(background=True)

    print("main thread running..")

    print("=== 5 - Retrieve all Neighbor elements using AsyncProtocol ===")

    query = NeighborQuery(ENGINENAME)
    async_ws5 = SMCSocketAsyncProtocol(query=query,
                                       on_message_fct=callback_neighbor_element_fct,
                                       formatter=ElementFormat,
                                       element_name=Neighbor)
    # this call is blocking if background=False
    async_ws5.run(background=True)

    print("main thread running..")

    # Sleep to let all data coming from WS before ending
    time.sleep(20)

except BaseException as e:
    print(e)
    exit(-1)
finally:
    print("serial log table={}".format(nb_log_table_serial))
    print("alert element={}".format(nb_alert_element))
    print("log table={}".format(nb_log_table))
    print("routing element={}".format(nb_routing_element))
    print("routing table={}".format(nb_routing_table))
    print("neighbor element={}".format(nb_neighbor_element))
    # close all the web socket connections
    async_ws1.close()
    async_ws2.close()
    async_ws3.close()
    async_ws4.close()
    async_ws5.close()

    assert nb_log_table_serial > 0 \
           and nb_alert_element > 0 \
           and nb_log_table > 0\
           and nb_routing_element > 0\
           and nb_routing_table > 0\
           and nb_neighbor_element > 0, "Some WS data not received"

    session.logout()
