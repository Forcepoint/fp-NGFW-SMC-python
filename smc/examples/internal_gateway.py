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
Example script to show how to use Internal Gateways from L3 Firewalls.
"""

from smc import session
from smc.core.engines import Layer3Firewall
from smc.vpn.elements import ConnectionType
from smc_info import SMC_URL, API_KEY, API_VERSION

NOT_CREATED_MSG = "Fail to create internal gateway"
ERROR_IN_GET_ALL_GATEWAY = "Not received list of all internal gateways."
ERROR_IN_GETEWAY_DEL = "Error in delete internal gateway"
GATEWAY_UPDATE_ERROR = "Failed to update an internal gateway"
UPDATE_CONN_TYPE_ERROR = "Failed to update connection type in internal endpoint"
RETRY_ONLINE = 30
FW_NAME = 'myFW'
TEST_GATEWAY = 'test_gateway'
if __name__ == "__main__":
    try:
        session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120,
                      api_version=API_VERSION)
        print("session OK")
        engine = Layer3Firewall.create(name=FW_NAME,
                                       mgmt_ip="192.168.10.1",
                                       mgmt_network="192.168.10.0/24")
        engine.create_internal_gateway(TEST_GATEWAY)
        list_of_vpn_object = engine.all_vpns
        assert len(list_of_vpn_object) >= 2, ERROR_IN_GET_ALL_GATEWAY
        is_vpn_gateway_created = False
        for vpn in list_of_vpn_object:
            if vpn.name == TEST_GATEWAY:
                # update connection type in internal endpoint
                standby_con_type = ConnectionType("Standby")
                for endpoint in engine.vpn.internal_endpoint:
                    endpoint.update(connection_type_ref=standby_con_type.href)
                    assert endpoint.data.get(
                        "connection_type_ref") == standby_con_type.href, UPDATE_CONN_TYPE_ERROR
                    print("Updated connection type to standby successfully.")
                is_vpn_gateway_created = True
                vpn.vpn_client.update(
                    firewall=True, antivirus=True)
                assert vpn.vpn_client.firewall and vpn.vpn_client.antivirus, GATEWAY_UPDATE_ERROR
                vpn.remove()
                assert len(vpn.engine.all_vpns) == 1, ERROR_IN_GETEWAY_DEL
                break
        assert is_vpn_gateway_created, NOT_CREATED_MSG
    except BaseException as e:
        print("Exception:{}".format(e))
        exit(-1)
    finally:
        engine = Layer3Firewall(FW_NAME)
        engine.delete()
