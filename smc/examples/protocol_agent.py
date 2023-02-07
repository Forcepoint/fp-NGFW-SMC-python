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
Example script to show how to use Protocol Agent
-create service using protocol agent and proxy service
-update proxy service
-check and delete
"""

# Python Base Import
import smc.examples

from smc import session
from smc.elements.protocols import ProtocolAgent
from smc.elements.servers import ProxyServer
from smc.elements.service import TCPService
from smc_info import *

if __name__ == '__main__':

    session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120, api_version=API_VERSION)
    print("session OK")

try:
    pa = ProtocolAgent("SMTP")
    service = TCPService().create("myTCPService",
                                  min_dst_port=45,
                                  max_dst_port=50,
                                  protocol_agent=pa)
    proxy_service_value = service.protocol_agent_values.get('redir_cis')
    print(proxy_service_value)

    # Get first proxy server
    print("Get first proxy server..")
    proxy_server = list(ProxyServer.objects.all())[0]

    print("Add proxy server {} to protocol agent values".format(proxy_server.name))
    updated = service.protocol_agent_values.update(name='redir_cis',
                                                   proxy_server=proxy_server)
    proxy_service_value = service.protocol_agent_values.get('redir_cis')
    print(proxy_service_value)

    service.update()

    # Retrieve service and check proxy server is set
    print("Get myTCPService..")
    service1 = TCPService("myTCPService")
    proxy_service_value = service1.protocol_agent_values.get('redir_cis')
    print(proxy_service_value)
    assert proxy_service_value.proxy_server.name == proxy_server.name

except Exception as e:
    print(e)
    exit(-1)
finally:
    print("delete elements..")
    service = TCPService("myTCPService")
    service.delete()
    session.logout()
