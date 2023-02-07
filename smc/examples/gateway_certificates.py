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
Example of creating and accessing internal gateway certificate.
"""
import time
from smc.core.engines import Layer3Firewall
from smc import session
from smc_info import API_VERSION, SMC_URL, API_KEY

RETRY_ONLINE = 30
FW_NAME = 'myFW'
NOT_EXPIRE_DATE_ERR = "Expire date is not available"
if __name__ == "__main__":
    try:
        session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120,
                      api_version=API_VERSION)
        print("session OK")
        engine = Layer3Firewall.create(name=FW_NAME,
                                       mgmt_ip="192.168.10.1",
                                       mgmt_network="192.168.10.0/24")
        print("initial contact and license..")
        for node in engine.nodes:
            node.initial_contact()
            node.bind_license()
        # wait time for engine to be online
        online = False
        retry = 0
        while not online and retry < RETRY_ONLINE:
            status = engine.nodes[0].status().monitoring_state
            online = status == "READY"
            time.sleep(5)
            retry += 1
        engine.internal_gateway.generate_certificate(
            engine.internal_gateway.name)
        temp_list = engine.vpn.gateway_certificate
        assert temp_list[0].expiration is not None, NOT_EXPIRE_DATE_ERR
    except BaseException as e:
        print("Exception:{}".format(e))
        exit(-1)
    finally:
        engine = Layer3Firewall(FW_NAME)
        engine.delete()
