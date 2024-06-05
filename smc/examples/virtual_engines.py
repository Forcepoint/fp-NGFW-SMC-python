#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
import argparse
import logging
import sys

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.core.engines import MasterEngine, Layer3VirtualEngine  # noqa
from smc.core.sub_interfaces import SingleNodeInterface  # noqa
from smc.elements.network import Router, Network, Zone  # noqa

NAME = "master"
DELETE_VLAN_ERROR = "Failed to delete all vlan interfaces of master engine."
UPDATE_INTERFACE_ERROR = "Failed to update physical interface of master engine."
VLAN_CREATE_ERROR = "Failed to create vlan interface in virtual engine."
ADD_IP_ADDRESS_ERROR = "Failed to add new ip address to vlan interface."

logging.getLogger()
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - '
                                                '%(name)s - [%(levelname)s] : %(message)s')


def main():
    return_code = 0
    try:
        arguments = parse_command_line_arguments()
        session.login(url=arguments.api_url, api_key=arguments.api_key,
                      login=arguments.smc_user,
                      pwd=arguments.smc_pwd, api_version=arguments.api_version)
        logging.info("session OK")

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
        for vr in range(1, 11):
            master_engine.virtual_resource.create(name=f"Customer {vr}", vfw_id=vr)

        # Add the VLANs to the interfaces and attach the Virtual Resources
        for vr in range(1, 9):
            master_engine.physical_interface.add_layer3_vlan_interface(
                interface_id=1,
                vlan_id=vr,
                virtual_mapping=1,
                virtual_resource_name=f"Customer {vr}",
            )
            master_engine.physical_interface.add_layer3_vlan_interface(
                interface_id=2,
                vlan_id=vr,
                virtual_mapping=2,
                virtual_resource_name=f"Customer {vr}",
            )

        # Router object used for default route
        router = Router.update_or_create(
            name="southbound", address="10.1.2.254", comment="virtual engine gateway"
        )

        # Add New Shared Virtual Interface
        zone_ref = Zone.objects.first()
        # Add two virtual resource mapping
        virtual_resource_settings = [{"qos_limit": -1,
                                      "virtual_mapping": "3",
                                      "virtual_resource_name": "Customer 9"},
                                     {"qos_limit": -1,
                                      "virtual_mapping": "3",
                                      "virtual_resource_name": "Customer 10"}]
        master_engine.physical_interface. \
            add_layer3_shared_virtual_interface(vlan_id=1,
                                                interface_id=3,
                                                mac_address_prefix="00:00:00:5e:13",
                                                virtual_resource_settings=virtual_resource_settings,
                                                zone_ref=zone_ref)
        logging.info(f"Master Engine created:{master_engine}")

        # Now create the Virtual Firewalls for each customer and set interface information
        # VirtualEngine interface numbering starts at interface 1!
        for vr in range(1, 9):
            virtual_engine = Layer3VirtualEngine.create(
                name=f"Customer {vr}",
                master_engine="master",
                virtual_resource=f"Customer {vr}",
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
            logging.info(f"Virtual Engine created:{virtual_engine}")
        # Remove all vlan interfaces of master engine
        for interface in master_engine.interface:
            for vlan_interface in interface.vlan_interface:
                vlan_interface.delete()

        master_engine = MasterEngine(NAME)
        for interface in master_engine.interface:
            assert not interface.vlan_interface, DELETE_VLAN_ERROR

        logging.info("Removed all vlan interfaces of master engine successfully")

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
            if ifc.interface_id == '0' or ifc.interface_id == '3':
                continue
            assert ifc.data.get("virtual_engine_vlan_ok") and \
                   ifc.data.get("virtual_resource_settings")[0][
                       "virtual_resource_name"] == "Customer 1", UPDATE_INTERFACE_ERROR

        # add vlan interface on virtual engine.
        for vr in range(1, 9):
            virtual_engine = Layer3VirtualEngine(name=f"Customer {vr}")
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
                virtual_resource_name=f"Customer {vr}",
            )
        logging.info("Added vlan interface on virtual engine successfully.")
        # add another ip address on vlan interface
        for vr in range(1, 9):
            virtual_engine = Layer3VirtualEngine(name=f"Customer {vr}")
            for interface in virtual_engine.interface:
                for vlan_interface in interface.vlan_interface:
                    sni = SingleNodeInterface.create(vlan_interface.interface_id,
                                                     address="1.1." + str(interface.interface_id) +
                                                             ".1",
                                                     network_value="1.1."
                                                                   + str(interface.interface_id)
                                                                   + ".0/24")
                    vlan_interface.add_ip_address(sni=sni)
        for vr in range(1, 9):
            virtual_engine = Layer3VirtualEngine(name=f"Customer {vr}")
            for interface in virtual_engine.interface:
                # make sure vlan interface in exist
                assert len(interface.vlan_interface), VLAN_CREATE_ERROR
                for vlan_interface in interface.vlan_interface:
                    # make sure new ip address added in vlan interface.
                    assert len(vlan_interface.addresses) == 2, ADD_IP_ADDRESS_ERROR
        logging.info("Added additional ip address to vlan interface successfully.")
    except BaseException as ex:
        logging.error(f"Exception : {ex}")
        return_code = 1
    finally:
        for vr in range(1, 9):
            name = f"Customer {vr}"
            Layer3VirtualEngine(name).delete()

        MasterEngine("master").delete()
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to create a Master Engine and 8 virtual engines',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        add_help=False)
    parser.add_argument(
        '-h', '--help',
        action='store_true',
        help='show this help message and exit')

    parser.add_argument(
        '--api-url',
        type=str,
        help='SMC API url like https://192.168.1.1:8082')
    parser.add_argument(
        '--api-version',
        type=str,
        help='The API version to use for run the script'
    )
    parser.add_argument(
        '--smc-user',
        type=str,
        help='SMC API user')
    parser.add_argument(
        '--smc-pwd',
        type=str,
        help='SMC API password')
    parser.add_argument(
        '--api-key',
        type=str, default=None,
        help='SMC API api key (Default: None)')

    arguments = parser.parse_args()

    if arguments.help:
        parser.print_help()
        sys.exit(1)
    if arguments.api_url is None:
        parser.print_help()
        sys.exit(1)

    return arguments


if __name__ == '__main__':
    sys.exit(main())
