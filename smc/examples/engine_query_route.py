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
Allows querying a route for the specific supported engine {cluster_type} with key
{element_key} Options:
A. Using Query Parameters:
    source: the IP Address A.B.C.D corresponding to the source query ip address.
    destination: the IP Address A.B.C.D corresponding to the destination query ip address.
B. Using payload to be able to specify source network element uri
    and/or destination network element uri.
"""
from smc import session
from smc.core.engine import Engine
from smc.elements.network import Host
from smc_info import API_VERSION, SMC_URL, API_KEY

ROUTE_ERROR = "Error to get list of route"
engine_name = 'Plano'
if __name__ == "__main__":
    session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120, api_version=API_VERSION)
    try:
        engine = Engine(engine_name)
        # Find route for source to destination using ip address
        list_of_route = engine.query_route(source_ip='0.0.0.0', destination_ip='0.0.0.0')
        assert list_of_route, ROUTE_ERROR
        # Find the route using query route with ref
        list_of_routing = list(Host.objects.all())
        if list_of_routing:
            host1 = list_of_routing[0]
            host2 = list_of_routing[1]
            list_of_route = engine.query_route(source_ref=host1.href, destination_ref=host2.href)
            assert list_of_route, ROUTE_ERROR
            list_of_route = engine.query_route(source_ip='0.0.0.0', destination_ref=host2.href)
            list_of_route = engine.query_route(source_ref=host1.href, destination_ip='0.0.0.0')
    except Exception as ex:
        print("Exception is {}".format(ex))
    finally:
        session.logout()
