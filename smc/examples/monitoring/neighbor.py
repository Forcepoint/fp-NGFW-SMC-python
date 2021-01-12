"""
Example script to subscribe to NEIGHBORS notifications using websocket library or smc_monitoring extension

"""


# Python Base Import
import sys, json
from websocket import create_connection

from smc import session
from smc_monitoring.monitors.neighbors import NeighborQuery
from smc_monitoring.models.values import FieldValue, StringValue
from smc_monitoring.models.constants import LogField

if __name__ == '__main__':
    URLSMC='localhost:8082'
    APIKEYSMC='HuphG4Uwg4dN6TyvorTR0001'
    ENGINENAME = 'Plano'

    try:
        session.login(url="http://"+URLSMC, api_key=APIKEYSMC, verify=False, timeout=120)
    except BaseException as exception_retournee:
        sys.exit(-1)

print("session OK")


print("Retrieve Neighbors using websocket library")

ws = create_connection("ws://"+URLSMC+"/6.9/monitoring/session/socket", cookie=session.session_id)
query = {"query": {"definition": "NEIGHBORS", "target": ENGINENAME}, "fetch": {}, "format": {"type": "texts"}}
ws.send(json.dumps(query))
result = ws.recv()
print("Received '%s'" % result)
result = ws.recv()
print("Received '%s'" % result)
ws.close()

print("")
print("Retrieve IPv6 Neighbors Data using smc_monitoring")
query = NeighborQuery(ENGINENAME)
query.add_in_filter(FieldValue(LogField.NEIGHBORPROTOCOL), [StringValue("IPv6")])
for record in query.fetch_batch():
    print(record)

print("Retrieve all Neighbor elements using smc_monitoring")
query = NeighborQuery(ENGINENAME)
for element in query.fetch_as_element():
    print(element.node_id + " " + element.neighbor_state + " " + element.neighbor_interface + " " + element.neighbor_protocol + " " + element.neighbor_l3_data + "->" + element.neighbor_l2_data)

session.logout()
