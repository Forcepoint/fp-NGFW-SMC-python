"""
Example script to show how to use Servers
-get logserver
-create Netflow collector
-add Netflow collectors to log server
-remove a Netflow collector from log server
"""

# Python Base Import
import sys
from smc import session
from smc.api.common import SMCRequest
from smc.base.model import Element
from smc.elements.network import Host, Expression
from smc.elements.other import FilterExpression
from smc.elements.servers import LogServer, DataContext, NetflowCollector
from smc.policy.rule_elements import MatchExpression

if __name__ == "__main__":
    URLSMC = "http://localhost:8082"
    APIKEYSMC = "HuphG4Uwg4dN6TyvorTR0001"
    try:
        session.login(url=URLSMC, api_key=APIKEYSMC, verify=False, timeout=120, api_version="6.10")
    except BaseException as exception_retournee:
        sys.exit(-1)

    print("session OK")

try:
    for log_server in LogServer.objects.all():
        print("LS={}".format(log_server))
    log_server = LogServer.get("Log Server")

    # Create Netflow Collectors
    data_context = DataContext.get("All Log Data")
    filter_expression = FilterExpression.get("OMAPI Connections")
    host1 = Host.get("DNS 1")
    netflow_collector1 = NetflowCollector(
        data_context=data_context,
        filter=filter_expression,
        host=host1,
        netflow_collector_port=255,
        netflow_collector_service="tcp_with_tls",
        netflow_collector_version="netflow_v9",
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
    log_server.add_netflow_collector(list_netflow_collector)

    for netflow_collector in log_server.netflow_collector:
        print("NF ={}".format(netflow_collector))

    print("Remove netflow collector:{}".format(netflow_collector2))
    # Remove Netflow Collectors from log server
    log_server.remove_netflow_collector(netflow_collector2)

    for netflow_collector in log_server.netflow_collector:
        print("NF ={}".format(netflow_collector))

except Exception as e:
    print(e)
finally:
    session.logout()
