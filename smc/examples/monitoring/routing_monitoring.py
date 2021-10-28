"""
Example script to show how to subscribe to routing monitoring notifications using websocket library
or smc_monitoring extension
"""


# Python Base Import
import json
from websocket import create_connection

from smc import session
from smc_monitoring.monitors.routes import RoutingQuery
from smc_info import *
ENGINE_NAME = "Plano"

if __name__ == '__main__':
    session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120, api_version=API_VERSION)
    print("session OK")


try:
    print("Retrieve all entries in routing table using websocket library")

    ws = create_connection(
        "{}/{}/monitoring/session/socket".format(WS_URL, str(API_VERSION)),
        cookie=session.session_id
    )

    query = {
        "query": {"definition": "ROUTING", "target": ENGINE_NAME},
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
    print("Retrieve all entries in routing table using smc_monitoring fetch_batch")
    query = RoutingQuery(target=ENGINE_NAME)
    for record in query.fetch_batch(query_timeout=10):
        print(record)

    print("Retrieve all entries in routing table using smc_monitoring fetch_as_element")
    query = RoutingQuery(target=ENGINE_NAME)
    # retrieve RoutingView elements
    # Use max_recv to stop fetching elements after 1 block received
    for element in query.fetch_as_element(max_recv=1):
        print(element)

except BaseException as e:
    print(e)
    exit(-1)
finally:
    session.logout()
