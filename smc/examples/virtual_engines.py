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
Example of creating a Master Engine and 8 virtual engines. Each virtual engine is mapped to 2
Master Engine interfaces and a unique VLAN.
This example is based on SMC 6.5.x
"""
import smc.examples

from smc.core.engines import MasterEngine, Layer3VirtualEngine
from smc.core.sub_interfaces import SingleNodeInterface
from smc.elements.network import Router, Network
from smc import session
from smc_info import *
NAME = "master"
DELETE_VLAN_ERROR = "Failed to delete all vlan interfaces of master engine."
UPDATE_INTERFACE_ERROR = "Failed to update physical interface of master engine."
VLAN_CREATE_ERROR = "Failed to create vlan interface in virtual engine."
ADD_IP_ADDRESS_ERROR = "Failed to add new ip address to vlan interface."
if __name__ == "__main__":
    session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120, api_version=API_VERSION)
    print("session OK")

try:
    master_engine = MasterEngine.create(
        name=NAME,
        master_type="firewall",
        mgmt_ip="172.18.1.1",
        mgmt_network="172.18.1.0/24",
        mgmt_interface=0,
    )

    # Create top level interface on master engine with a zone name
    master_engine.physical_interface.add(interface_id=1, zone_ref="Northbound")
    master_engine.physical_interface.add(interface_id=2, zone_ref="Southbound")

    # First create the Virtual Resources (Customer 1 - 8)
    for vr in range(1, 9):
        master_engine.virtual_resource.create(name="Customer {}".format(vr), vfw_id=vr)

    # Add the VLANs to the interfaces and attach the Virtual Resources
    for vr in range(1, 9):
        master_engine.physical_interface.add_layer3_vlan_interface(
            interface_id=1,
            vlan_id=vr,
            virtual_mapping=1,
            virtual_resource_name="Customer {}".format(vr),
        )
        master_engine.physical_interface.add_layer3_vlan_interface(
            interface_id=2,
            vlan_id=vr,
            virtual_mapping=2,
            virtual_resource_name="Customer {}".format(vr),
        )

    # Router object used for default route
    router = Router.update_or_create(
        name="southbound", address="10.1.2.254", comment="virtual engine gateway"
    )

    print("Master Engine created:{}".format(master_engine))
    # Now create the Virtual Firewalls for each customer and set interface information
    # VirtualEngine interface numbering starts at interface 1!
    for vr in range(1, 9):
        virtual_engine = Layer3VirtualEngine.create(
            name="Customer {}".format(vr),
            master_engine="master",
            virtual_resource="Customer {}".format(vr),
            outgoing_intf=1,
            interfaces=[
                {
                    "interface_id": 1,
                    "address": "10.1.1.1",
                    "network_value": "10.1.1.0/24",
                    "zone_ref": "",
                },
                {
                    "interface_id": 2,
                    "address": "10.1.2.1",
                    "network_value": "10.1.2.0/24",
                    "zone_ref": "",
                },
            ],
        )
        # Add default route
        interface_1 = virtual_engine.routing.get(2)
        interface_1.add_static_route(gateway=Router("southbound"),
                                     destination=[Network("Any network")])
        print("Virtual Engine created:{}".format(virtual_engine))
    # Remove all vlan interfaces of master engine
    for interface in master_engine.interface:
        for vlan_interface in interface.vlan_interface:
            vlan_interface.delete()

    master_engine = MasterEngine(NAME)
    for interface in master_engine.interface:
        assert not interface.vlan_interface, DELETE_VLAN_ERROR

    print("Removed all vlan interfaces of master engine successfully")

    # update master engine's interface to allow configure vlan interface on virtual engine.
    interface = master_engine.physical_interface.get(1)
    interface.update(virtual_resource_settings=[
        {"virtual_resource_name": "Customer {}".format(1), "virtual_mapping": 1}],
        virtual_engine_vlan_ok=True)
    interface = master_engine.physical_interface.get(2)
    interface.update(virtual_resource_settings=[
        {"virtual_resource_name": "Customer {}".format(1), "virtual_mapping": 2}],
        virtual_engine_vlan_ok=True)
    master_engine = MasterEngine(NAME)
    for ifc in master_engine.physical_interface:
        # ignoring unwanted interface
        if ifc.interface_id == '0':
            continue
        assert ifc.data.get("virtual_engine_vlan_ok") and \
               ifc.data.get("virtual_resource_settings")[0][
                   "virtual_resource_name"] == "Customer 1", UPDATE_INTERFACE_ERROR

    # add vlan interface on virtual engine.
    for vr in range(1, 9):
        virtual_engine = Layer3VirtualEngine(name="Customer {}".format(vr))
        virtual_engine.virtual_physical_interface.add_layer3_vlan_interface(
            interface_id=1,
            vlan_id=vr,
            virtual_mapping=1,
            virtual_resource_name="Customer {}".format(vr),
            address="10.1.3.1",
            network_value="10.1.3.0/24",
        )
        virtual_engine.virtual_physical_interface.add_layer3_vlan_interface(
            interface_id=2,
            vlan_id=vr,
            virtual_mapping=2,
            virtual_resource_name="Customer {}".format(vr),
        )
    print("Added vlan interface on virtual engine successfully.")
    # add another ip address on vlan interface
    for vr in range(1, 9):
        virtual_engine = Layer3VirtualEngine(name="Customer {}".format(vr))
        for interface in virtual_engine.interface:
            for vlan_interface in interface.vlan_interface:
                sni = SingleNodeInterface.create(vlan_interface.interface_id, address="1.1." + str(
                    interface.interface_id) + ".1", network_value="1.1." + str(
                    interface.interface_id) + ".0/24")
                vlan_interface.add_ip_address(sni=sni)
    for vr in range(1, 9):
        virtual_engine = Layer3VirtualEngine(name="Customer {}".format(vr))
        for interface in virtual_engine.interface:
            # make sure vlan interface in exist
            assert len(interface.vlan_interface), VLAN_CREATE_ERROR
            for vlan_interface in interface.vlan_interface:
                # make sure new ip address added in vlan interface.
                assert len(vlan_interface.addresses) == 2, ADD_IP_ADDRESS_ERROR
    print("Added additional ip address to vlan interface successfully.")
except Exception as ex:
    print("Exception : {}".format(ex))

finally:
    for vr in range(1, 9):
        name = "Customer {}".format(vr)
        Layer3VirtualEngine(name).delete()

    MasterEngine("master").delete()
