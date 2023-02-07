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
import smc.examples


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

    # retrieve All RoutingView initial elements (first_fetch True)
    # Use max_recv to stop fetching elements after 2mn query or 20s inactivity
    for element in query.fetch_as_element(max_recv=0, query_timeout=120, inactivity_timeout=20):
        print(element)

except BaseException as e:
    print(e)
    exit(-1)
finally:
    session.logout()
