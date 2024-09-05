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
Example of how to create a 3 node cluster in SMC
Before any operations can be done on the SMC, you must first call login, and remember to call logout
after complete::
    smc.api.web.session.login('http://172.18.1.150:8082', 'EiGpKD4QxlLJ25dbBEp20001')
This is a Layer 3 Firewall cluster with the following configuration::
    :param name: Name of cluster engine
    :param cluster_virtual: IP address of CVI
    :param cluster_mask: Netmask of CVI
    :param cluster_nic: Which physical nic id to use
    :param macaddress: Packet Dispatch clustering requires a MAC address
    :param nodes: Node addresses to add to cluster. Each address/netmask combination
                  is added as a singular node
    :param dns: Optional DNS settings for engine
    :param zone_ref: Optional zone to assign to physical interface
    :param default_nat: enable default NAT for outbound
    :param enable_gti: enable GTI on engine
    :param enable_antivirus: enable AV on engine
See :class:`smc.elements.engines.FirewallCluster` for more details.
Once the Cluster has been created, initial contact is done to retrieve
the initial configuration required
to fully bootstrap each engine. A filename is specified to which to save the engine.cfg,
but it can also be printed out by retrieving result.content (SMCResult).
SMC-python is configured to leverage the python logging module. To obtain logger messages,
uncomment the following line below and set the logging level
(recommend ERROR unless troubleshooting)::
    logging.basicConfig(level=logging.ERROR)
"""
import argparse
import logging
import sys

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.administration.access_rights import AdminRoleContainer  # noqa
from smc.administration.role import Role  # noqa
from smc.administration.system import AdminDomain  # noqa
from smc.api.exceptions import UpdateElementFailed  # noqa
from smc.core.engine import LBFilter  # noqa
from smc.core.engines import FirewallCluster  # noqa
from smc.core.general import NTPSettings  # noqa
from smc.core.route import Routing  # noqa
from smc.core.sub_interfaces import ClusterVirtualInterface, NodeInterface  # noqa
from smc.elements.helpers import zone_helper  # noqa
import ipaddress  # noqa
from smc.routing.bgp import AutonomousSystem, BGPPeering, ExternalBGPPeer  # noqa
from smc.core.engines import MasterEngineCluster  # noqa

from smc.elements.servers import NTPServer  # noqa
from smc.elements.user import AdminUser  # noqa

CREATE_TUNNEL_INTERFACE_ERROR = "Failed to created tunnel interface."
TWO_CVI_CREATE_ERROR = "Failed to create engine with two CVIs in same interface."
FAILED_TO_ADD_IP = "Failed to add ip address to tunnel interface"
TUNNEL_IP_ADDRESS = "9.9.9.9"
TUNNEL_NETWORK_VALUE = "9.9.9.0/32"
TUNNEL_INTERFACE_ID = "1010"
IPV6_NETWORK_VALUE1 = "2001:db8:3333:4444:5555:6666:7777:0000/128"
IPV6_NETWORK_VALUE2 = "2001:db8:3333:4444::/64"
IPV6_ADDRESS = '2001:db8:3333:4444:5555:6666:8888:8888'
ADD_BGP_PEERING_ERROR = "Fail to add bgp peering with ipv6 address."
IPV6_NETWORK_ADDRESS = "2001:db8:3333:4444:5555:6666:7777:0"

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
        # Update existing netlink probe configuration
        engine = FirewallCluster("Paris")
        # get routing for interface number 1
        routing_node = engine.routing.get(1)
        for static_netlink in routing_node.netlinks:
            interface, network, netlink = static_netlink
            logging.info(f"netlink={netlink}")
            logging.info(f"network={network}")
            any_network_href = netlink.data.routing_node[0].get("link")[0].get("href")
            any_network = Routing(href=any_network_href, parent=netlink)
            logging.info(f"network any level={any_network}")
            # update probe test to ping
            any_network.probe_test = "ping"
            any_network.probe_ecmp = 1
            any_network.probe_interval = 500
            any_network.probe_ipaddress = "172.31.3.1"
            any_network.probe_metric = 0
            any_network.probe_retry_count = 2
            any_network.update()

        # Create NTP server
        new_ntp_server = NTPServer().create(name="myNTPServer",
                                            comment="NTP Server created by the SMC API",
                                            address="192.168.1.200",
                                            ntp_auth_key_type="none"
                                            )

        # create Layer3 FW using NTPSettings object
        ntp = NTPSettings.create(ntp_enable=True,
                                 ntp_servers=[new_ntp_server])

        # Add multiple cvi in single interface in cluster engine creation.
        interfaces = [
            {'interface_id': 0,
             'macaddress': '02:02:02:02:02:02',
             'interfaces': [{'cluster_virtual': '2.2.2.1',
                             'network_value': '2.2.2.0/24',
                             'nodes': [{'address': '2.2.2.2', 'network_value': '2.2.2.0/24',
                                        'nodeid': 1, 'primary_mgt': False,
                                        'primary_heartbeat': False, 'outgoing': False, },
                                       {'address': '2.2.2.3', 'network_value': '2.2.2.0/24',
                                        'nodeid': 2, 'primary_mgt': False,
                                        'primary_heartbeat': False, 'outgoing': False, },
                                       {'address': '2.2.2.4', 'network_value': '2.2.2.0/24',
                                        'nodeid': 3, 'primary_mgt': False,
                                        'primary_heartbeat': False, 'outgoing': False, }
                                       ]
                             }]
             }]

        # Create the Firewall Cluster
        engine = FirewallCluster.create(
            name="mycluster",
            cluster_virtual="1.1.1.1",
            cluster_mask="1.1.1.0/24",
            network_value="1.1.1.0/24",
            interface_id=0,
            cluster_nic=0,
            macaddress="02:02:02:02:02:02",
            nodes=[
                {"address": "1.1.1.2", "network_value": "1.1.1.0/24", "nodeid": 1},
                {"address": "1.1.1.3", "network_value": "1.1.1.0/24", "nodeid": 2},
                {"address": "1.1.1.4", "network_value": "1.1.1.0/24", "nodeid": 3},
            ],
            ntp_settings=ntp,
            timezone="Europe/Paris",
            domain_server_address=["1.1.1.1"],
            zone_ref=zone_helper("Internal"),
            enable_antivirus=True,
            enable_gti=True,
            default_nat=True,
            extra_opts={"is_cert_auto_renewal": True},
            interfaces=interfaces
        )
        assert len(engine.interface.get(0).cluster_virtual_interface) == 2, TWO_CVI_CREATE_ERROR
        engine.lbfilter_useports = True
        lbfilter = LBFilter.create(nodeid=0, action="replace", ip_descriptor="1.1.1.1/32",
                                   replace_ip="2.2.2.2", use_ports=True)
        lbfilter.use_ipsec = True
        engine.lbfilters = [lbfilter]
        engine.update()

        # refresh engine to check update is ok
        engine = FirewallCluster("mycluster")

        filters = engine.lbfilters
        for lbfilter in filters:
            assert lbfilter.action == "replace", "Failed to update lbfilter"
            assert lbfilter.use_ipsec is True, "Failed to update lbfilter"
            # Update the existing filter
            lbfilter.ignore_other = True

        # save the engine with filter updated
        engine.lbfilters = filters
        engine.update()

        # refresh engine from DB to check update is ok
        engine = FirewallCluster("mycluster")

        # verify ignore_other is True
        for lbfilter in engine.lbfilters:
            assert lbfilter.ignore_other is True, "Failed to update lbfilter"

        # Add BGP Peering with ipv6 address.
        list_of_nodes_ipv6 = [{'address': '2001:db8:3333:4444:5555:6666:8888:8881',
                               'network_value': IPV6_NETWORK_VALUE2,
                               'nodeid': 1},
                              {'address': '2001:db8:3333:4444:5555:6666:8888:8882',
                               'network_value': IPV6_NETWORK_VALUE2,
                               'nodeid': 2},
                              {'address': '2001:db8:3333:4444:5555:6666:8888:8883',
                               'network_value': IPV6_NETWORK_VALUE2,
                               'nodeid': 3}
                              ]
        list_of_node_interfaces_ipv6 = []
        interface = engine.interface.get(0)
        for _node in list_of_nodes_ipv6:
            ndi = NodeInterface.create(interface_id=interface.interface_id, **_node)
            list_of_node_interfaces_ipv6.append(ndi)
        ipv6_cvi = ClusterVirtualInterface.create(
            interface.interface_id,
            IPV6_ADDRESS,
            IPV6_NETWORK_VALUE2,
        )
        interface.add_ip_address(cvi=ipv6_cvi, nodes=list_of_node_interfaces_ipv6)
        ExternalBGPPeer.create(
            name="test_external_bgp_peering",
            neighbor_as=AutonomousSystem('Plano AS'),
            neighbor_ip="2001:db8:3333:4444:5555:6666:8888:8884",
        )
        logging.info("Successfully created bgp peering with ipv6 address.")

        interface = engine.routing.get(0)
        interface.add_bgp_peering(
            BGPPeering('BGP Peering'),
            ExternalBGPPeer('test_external_bgp_peering'), IPV6_NETWORK_VALUE2)

        is_true = False
        for routing in engine.routing.get(0):
            if routing.ip == IPV6_NETWORK_VALUE2:
                routing = routing.data['routing_node'][0]
                if routing['ip'] == IPV6_ADDRESS and \
                        routing['related_element_type'] == 'bgp_peering':
                    is_true = True
        assert is_true, ADD_BGP_PEERING_ERROR
        logging.info("Successfully added BGP Peering with ipv6 address.")

        engine.physical_interface.add_layer3_cluster_interface(
            interface_id=1,
            cluster_virtual="5.5.5.1",
            network_value="5.5.5.0/24",
            macaddress="02:03:03:03:03:03",
            nodes=[
                {"address": "5.5.5.2", "network_value": "5.5.5.0/24", "nodeid": 1},
                {"address": "5.5.5.3", "network_value": "5.5.5.0/24", "nodeid": 2},
                {"address": "5.5.5.4", "network_value": "5.5.5.0/24", "nodeid": 3},
            ],
            zone_ref=zone_helper("Heartbeat"),
        )

        engine.physical_interface.add_layer3_cluster_interface(
            interface_id=2,
            cluster_virtual="10.10.10.1",
            network_value="10.10.10.0/24",
            macaddress="02:04:04:04:04:04",
            nodes=[
                {"address": "10.10.10.2", "network_value": "10.10.10.0/24", "nodeid": 1},
                {"address": "10.10.10.3", "network_value": "10.10.10.0/24", "nodeid": 2},
                {"address": "10.10.10.4", "network_value": "10.10.10.0/24", "nodeid": 3},
            ],
            zone_ref=zone_helper("External"),
        )

        engine.add_route("10.10.10.254", "0.0.0.0/0")
        engine.add_route("5.5.5.100", "192.168.3.0/24")

        # add tunnel interface
        nodes = [{'address': '7.7.7.1',
                  'network_value': '7.7.7.0/24',
                  'nodeid': 1},
                 {'address': '7.7.7.2',
                  'network_value': '7.7.7.0/24',
                  'nodeid': 2},
                 {'address': '7.7.7.3',
                  'network_value': '7.7.7.0/24',
                  'nodeid': 3}
                 ]
        engine.tunnel_interface.add_cluster_virtual_interface(interface_id=TUNNEL_INTERFACE_ID,
                                                              cluster_virtual='7.7.7.4',
                                                              nodes=nodes,
                                                              network_value='7.7.7.0/24',
                                                              zone_ref=None,
                                                              comment=None)
        # flag to check tunnel interface and ip address in tunnel interface is created.
        is_tunnel_interface = False
        added_ipv4_address = False
        added_ipv6_address = False
        for interface in engine.tunnel_interface:
            if interface.interface_id == TUNNEL_INTERFACE_ID:
                cvi = ClusterVirtualInterface.create(
                    interface.interface_id,
                    TUNNEL_IP_ADDRESS,
                    TUNNEL_NETWORK_VALUE,
                )
                list_of_nodes = [{'address': '9.9.9.1',
                                  'network_value': TUNNEL_NETWORK_VALUE,
                                  'nodeid': 1},
                                 {'address': '9.9.9.2',
                                  'network_value': TUNNEL_NETWORK_VALUE,
                                  'nodeid': 2},
                                 {'address': '9.9.9.3',
                                  'network_value': TUNNEL_NETWORK_VALUE,
                                  'nodeid': 3}
                                 ]
                list_of_node_interfaces = []
                for _node in list_of_nodes:
                    ndi = NodeInterface.create(interface_id=interface.interface_id, **_node)
                    list_of_node_interfaces.append(ndi)
                # add ip address to tunnel interface
                interface.add_ip_address(cvi=cvi, nodes=list_of_node_interfaces)

                ipv6_cvi = ClusterVirtualInterface.create(
                    interface.interface_id,
                    IPV6_NETWORK_ADDRESS,
                    IPV6_NETWORK_VALUE1
                )

                list_of_nodes_ipv6 = [{'address': '2001:db8:3333:4444:5555:6666:7777:8886',
                                       'network_value': IPV6_NETWORK_VALUE1,
                                       'nodeid': 1},
                                      {'address': '2001:db8:3333:4444:5555:6666:7777:8887',
                                       'network_value': IPV6_NETWORK_VALUE1,
                                       'nodeid': 2},
                                      {'address': '2001:db8:3333:4444:5555:6666:7777:8888',
                                       'network_value': IPV6_NETWORK_VALUE1,
                                       'nodeid': 3}
                                      ]
                list_of_node_interfaces_ipv6 = []
                for _node in list_of_nodes_ipv6:
                    ndi = NodeInterface.create(interface_id=interface.interface_id, **_node)
                    list_of_node_interfaces_ipv6.append(ndi)
                # add ip address to tunnel interface
                interface.add_ip_address(cvi=ipv6_cvi, nodes=list_of_node_interfaces_ipv6)
                break
        for interface in engine.tunnel_interface.all():
            if interface.interface_id == TUNNEL_INTERFACE_ID:
                is_tunnel_interface = True
                for intf in interface.sub_interfaces():
                    if intf.address == TUNNEL_IP_ADDRESS:
                        added_ipv4_address = True
                    elif intf.address == IPV6_NETWORK_ADDRESS:
                        added_ipv6_address = True
                list_of_ip_address = [ip[0] for ip in interface.addresses]
                for _ndi in interface.ndi_interfaces:
                    assert _ndi.address in list_of_ip_address, "Error in ndi ip address creation."
                break
        assert is_tunnel_interface, CREATE_TUNNEL_INTERFACE_ERROR
        logging.info("Created tunnel interface successfully.")
        assert added_ipv4_address, FAILED_TO_ADD_IP
        assert added_ipv6_address, FAILED_TO_ADD_IP
        logging.info("Successfully added ip(cvi and ndi) address to tunnel interface.")

        # Create initial configuration for each node
        for node in engine.nodes:
            result = node.initial_contact(enable_ssh=True, filename=node.name + ".cfg")
            if result:
                logging.info(f"Successfully wrote initial configuration for node: {node.name}, "
                             f"to file: {node.name}" + ".cfg")
        assert engine.is_cert_auto_renewal, "Failed to pass attribute using extra_opts"

        # check engine permission
        permissions_object = engine.permissions
        existing_role_cnt = 0
        if permissions_object.role_containers:
            existing_role_cnt = len(permissions_object.role_containers[0].roles)
        admin_user = list(AdminUser.objects.all())[0]
        admin_domain = list(AdminDomain.objects.all())[0]
        viewer_role = Role("Viewer")
        log_viewer_role = Role("Logs Viewer")
        role_container = [
            AdminRoleContainer.create(roles=[viewer_role, log_viewer_role],
                                      granted_domain=admin_domain,
                                      admin=admin_user)]
        permissions_object.update(role_containers=role_container)
        try:
            engine.permissions = permissions_object
            updated_roles_cnt = len(engine.permissions.role_containers[0].roles)
            assert updated_roles_cnt > existing_role_cnt, "Failed to update engine permissions."
            logging.info("Successfully updated engine permissions.")
        except UpdateElementFailed as ex:
            logging.error("This is expected exception as update engine permission is not "
                          "supported in 7.0.")

        # Create a master engine
        cnodes = [{'nodeid': 1, 'reverse_connection': True, 'network_value': '192.168.0.0/17',
                   'address': '192.168.1.1'},
                  {'nodeid': 2, 'reverse_connection': True, 'network_value': '192.168.0.0/17',
                   'address': '192.168.1.2'}]
        cluster_virtual = "192.168.127.254"
        macaddress = "0A:A0:C0:A8:7F:FE"
        mgmt_ip = "192.168.0.0/17"
        cidr = ipaddress.IPv4Network(mgmt_ip)
        name = "myMaster"

        cluster = MasterEngineCluster.get_or_create(
            name=name,
            nodes=cnodes,
            mgmt_interface=0,
            macaddress=macaddress,
            master_type='firewall',
            mgmt_ip=cluster_virtual,
            mgmt_netmask=str(cidr.prefixlen),
        )

        logging.info(cluster)
    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        FirewallCluster("mycluster").delete()
        ExternalBGPPeer('test_external_bgp_peering').delete()
        MasterEngineCluster("myMaster").delete()
        NTPServer("myNTPServer").delete()
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to create a 3 node cluster in SMC',
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
