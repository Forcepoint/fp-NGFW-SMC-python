"""
Example script to show how to subscribe to NEIGHBORS notifications using websocket library
or smc_monitoring extension
"""


# Python Base Import
import json
from websocket import create_connection

from smc import session
from smc_monitoring.monitors.neighbors import NeighborQuery
from smc_monitoring.models.values import FieldValue, StringValue
from smc_monitoring.models.constants import LogField
from smc_info import *

ENGINENAME = "Plano"

if __name__ == '__main__':
    session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120, api_version=API_VERSION)
    print("session OK")

try:
    print("Retrieve Neighbors using websocket library")

    ws = create_connection(
        "{}/{}/monitoring/session/socket".format(WS_URL, str(API_VERSION)),
        cookie=session.session_id
    )

    query = {
        "query": {"definition": "NEIGHBORS", "target": ENGINENAME},
        "fetch": {},
        "format": {"type": "texts"},
    }

    try:
        ws.send(json.dumps(query))
        result = ws.recv()
        print("Received '{}'".format(result))
        fetch_id = json.loads(result)['fetch']
        result = ws.recv()
        print("Received '{}'".format(result))
    finally:
        ses_mon_abort_query = {"abort": fetch_id}
        ws.send(json.dumps(ses_mon_abort_query))
        ws.close()

    print("")
    print("Retrieve IPv6 Neighbors Data using smc_monitoring")
    query = NeighborQuery(ENGINENAME)
    query.add_in_filter(FieldValue(LogField.NEIGHBORPROTOCOL), [StringValue("IPv6")])
    for record in query.fetch_batch():
        print(record)

    print("Retrieve all Neighbor elements using smc_monitoring")
    query = NeighborQuery(ENGINENAME)
    for element in query.fetch_as_element(max_recv=1):
        print("{} {} {} {} {} {}->{}".format(element.first_fetch,
                                             element.node_id,
                                             element.neighbor_state,
                                             element.neighbor_interface,
                                             element.neighbor_protocol,
                                             element.neighbor_l3_data,
                                             element.neighbor_l2_data))
except BaseException as e:
    print(e)
    exit(-1)
finally:
    session.logout()
