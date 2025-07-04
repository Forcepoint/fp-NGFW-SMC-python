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

from smc.core.interfaces import (
    ClusterPhysicalInterface,
    TunnelInterface,
    Layer3PhysicalInterface,
    Layer2PhysicalInterface,
    SwitchPhysicalInterface, SwitchInterface,
)
from smc.core.sub_interfaces import LoopbackInterface
from smc.core.engine import Engine, HAForSingleEngine
from smc.api.exceptions import CreateEngineFailed, CreateElementFailed, ElementNotFound
from smc.base.model import ElementCreator
from smc.compat import min_smc_version


class Layer3Firewall(Engine):
    """
    .. versionchanged:: 0.7.0
        extra_opts can be passed to the top level engine dict to customize
        input

    Represents a Layer 3 Firewall configuration.
    A layer 3 single engine is a standalone engine instance (not a cluster). You can
    use the `create` constructor and add interfaces after the engine exists,
    or use `create_bulk` to fully create the engine and interfaces in a single
    operation.

    You can also pass arbitrary kwargs passed in to the engine dict by providing
    the `extra_opts` value as a dict. Therefore it can support any custom
    configurations as long as the format is valid.
    For example, enabling file reputation on a SMC >= 6.6::

        extra_opts= {'file_reputation_settings':{'file_reputation_context': 'gti_cloud_only'}}

    """

    typeof = "single_fw"

    @classmethod
    def create_bulk(
        cls,
        name,
        interfaces=None,
        primary_mgt=None,
        backup_mgt=None,
        auth_request=None,
        log_server_ref=None,
        domain_server_address=None,
        nodes=1,
        nodes_definition=None,
        node_type="firewall_node",
        location_ref=None,
        default_nat='automatic',
        enable_antivirus=False,
        enable_gti=False,
        sidewinder_proxy_enabled=False,
        known_host_lists=[],
        enable_ospf=False,
        ospf_profile=None,
        comment=None,
        snmp=None,
        ntp_settings=None,
        timezone=None,
        extra_opts=None,
        engine_type=None,
        lldp_profile=None,
        link_usage_profile=None,
        quic_enabled=True,
        discard_quic_if_cant_inspect=True,
        ssm_advanced_setting=None,
        scan_detection=None,
        static_multicast_route=None,
        pim_settings=None,
        web_authentication=None,
        nat64_settings=None,
        **kw
    ):
        """
        Create a Layer 3 Firewall providing all of the interface configuration.
        This method provides a way to fully create the engine and all interfaces
        at once versus using :py:meth:`~create` and creating each individual
        interface after the engine exists.

        Example interfaces format::

            interfaces=[
                {'interface_id': 1},
                {'interface_id': 2,
                 'interfaces':[{'nodes': [{'address': '2.2.2.2', 'network_value': '2.2.2.0/24'}]}],
                 'zone_ref': 'myzone'},
                {'interface_id': 3,
                 'interfaces': [{'nodes': [{'address': '3.3.3.3', 'network_value': '3.3.3.0/24'}],
                                 'vlan_id': 3,
                                 'zone_ref': 'myzone'},
                                 {'nodes': [{'address': '4.4.4.4', 'network_value': '4.4.4.0/24'}],
                                  'vlan_id': 4}]},
                {'interface_id': 4,
                 'interfaces': [{'vlan_id': 4,
                                 'zone_ref': 'myzone'}]},
                {'interface_id': 5,
                 'interfaces': [{'vlan_id': 5}]},
                {'interface_id': 1000,
                 'interfaces': [{'nodes': [{'address': '10.10.10.1',
                                 'network_value': '10.10.10.0/24'}]}],
                                 'type': 'tunnel_interface'}]

        Sample of creating a simple two interface firewall::

            firewall_def = {
                'name': 'firewall',
                'domain_server_address': ['192.168.122.1'],
                'primary_mgt': 0,
                'interfaces': [
                    {'interface_id': 0,
                     'interfaces': [{'nodes': [{'address': '192.168.122.100',
                                    'network_value': '192.168.122.0/24', 'auth_request': False}]}
                                    ]
                     },
                    {'interface_id': 1,
                     'interfaces': [{'nodes': [{'address': '10.0.0.254',
                                   'network_value': '10.0.0.0/24', 'auth_request': True}]}
                                    ]
                     }
                ]
            }
            fw = Layer3Firewall.create_bulk(**firewall_def)

        .. note:: You can set primary_mgt, backup_mgt, outgoing, and auth_request within the
           interface definition itself to specify interface options. If provided in the constructor,
           this will be passed to the interface creation factory. You should use one or the other
           method, not both.

        See :class:`smc.core.interfaces.Layer3PhysicalInterface` for more advanced examples
        """
        physical_interfaces = []
        for interface in interfaces:
            if "interface_id" not in interface:
                raise CreateEngineFailed(
                    "Interface definitions must contain the interface_id "
                    "field. Failed to create engine: %s" % name
                )
            if interface.get("type", None) == "tunnel_interface":
                tunnel_interface = TunnelInterface(**interface)
                physical_interfaces.append({"tunnel_interface": tunnel_interface})
            elif interface.get("type", None) == "switch_physical_interface":
                physical_interfaces.append(
                    {
                        "switch_physical_interface": SwitchPhysicalInterface(
                            primary_mgt=primary_mgt,
                            backup_mgt=backup_mgt,
                            auth_request=auth_request,
                            **interface
                        )
                    }
                )
            elif interface.get("type", None) == "switch_interface":
                physical_interfaces.append(
                    {
                        "switch_interface": SwitchInterface(
                            primary_mgt=primary_mgt,
                            backup_mgt=backup_mgt,
                            auth_request=auth_request,
                            **interface
                        )
                    }
                )
            else:
                interface.update(interface="single_node_interface")
                interface = Layer3PhysicalInterface(
                    primary_mgt=primary_mgt,
                    backup_mgt=backup_mgt,
                    auth_request=auth_request,
                    **interface
                )
                physical_interfaces.append({"physical_interface": interface})

        if snmp:
            snmp_agent = dict(
                snmp_agent_ref=snmp.get("snmp_agent", ""),
                snmp_location=snmp.get("snmp_location", ""),
            )

            snmp_agent.update(snmp_interface=add_snmp(interfaces, snmp.get("snmp_interface", [])))

        # convert ntp_settings from extra_opts to parameter for _create function
        if extra_opts is not None and "ntp_settings" in extra_opts:
            ntp_settings = extra_opts['ntp_settings']
            del extra_opts['ntp_settings']

        # convert timezone from extra_opts to parameter for _create function
        if extra_opts is not None and "timezone" in extra_opts:
            timezone = extra_opts['timezone']
            del extra_opts['timezone']

        # convert lldp_profile from extra_opts to parameter for _create function
        if extra_opts is not None and "lldp_profile_ref" in extra_opts:
            lldp_profile = extra_opts['lldp_profile_ref']
            del extra_opts['lldp_profile_ref']

        # convert link_usage profile from extra_opts to parameter for _create function
        if extra_opts is not None and "link_usage_profile_ref" in extra_opts:
            link_usage_profile = extra_opts['link_usage_profile']
            del extra_opts['link_usage_profile_ref']

        # convert known_host_list from extra_opts to parameter for _create function
        if extra_opts is not None and "known_host_lists_ref" in extra_opts:
            known_host_lists = extra_opts["known_host_lists_ref"]
            del extra_opts["known_host_lists_ref"]

        try:
            engine = super(Layer3Firewall, cls)._create(
                name=name,
                node_type=node_type,
                physical_interfaces=physical_interfaces,
                loopback_ndi=kw.pop("loopback_ndi", []),
                domain_server_address=domain_server_address,
                log_server_ref=log_server_ref,
                nodes=nodes,
                nodes_definition=nodes_definition,
                enable_gti=enable_gti,
                enable_antivirus=enable_antivirus,
                sidewinder_proxy_enabled=sidewinder_proxy_enabled,
                known_host_lists=known_host_lists,
                default_nat=default_nat,
                location_ref=location_ref,
                enable_ospf=enable_ospf,
                ospf_profile=ospf_profile,
                link_usage_profile=link_usage_profile,
                snmp_agent=snmp_agent if snmp else None,
                ntp_settings=ntp_settings,
                timezone=timezone,
                lldp_profile=lldp_profile,
                comment=comment,
                discard_quic_if_cant_inspect=discard_quic_if_cant_inspect,
                ssm_advanced_setting=ssm_advanced_setting,
                scan_detection=scan_detection,
                static_multicast_route=static_multicast_route,
                pim_settings=pim_settings,
                web_authentication=web_authentication,
                nat64_settings=nat64_settings,
                **extra_opts if extra_opts else {}
            )

            if min_smc_version("7.0"):
                if quic_enabled:
                    quic = {"quic_enabled": "true"}
                else:
                    quic = {"quic_enabled": "false"}
                engine.update(quic)

            return ElementCreator(engine_type if engine_type else cls, json=engine)

        except (ElementNotFound, CreateElementFailed) as e:
            raise CreateEngineFailed(e)

    @classmethod
    def create(
        cls,
        name,
        mgmt_ip,
        mgmt_network,
        mgmt_interface=0,
        log_server_ref=None,
        default_nat='automatic',
        reverse_connection=False,
        domain_server_address=None,
        zone_ref=None,
        enable_antivirus=False,
        enable_gti=False,
        location_ref=None,
        enable_ospf=False,
        sidewinder_proxy_enabled=False,
        known_host_lists=[],
        ospf_profile=None,
        snmp=None,
        ntp_settings=None,
        timezone=None,
        comment=None,
        extra_opts=None,
        engine_type=None,
        node_type="firewall_node",
        lldp_profile=None,
        link_usage_profile=None,
        quic_enabled=True,
        discard_quic_if_cant_inspect=True,
        node_definition=None,
        ssm_advanced_setting=None,
        scan_detection=None,
        static_multicast_route=None,
        web_authentication=None,
        **kw
    ):
        """
        Create a single layer 3 firewall with management interface and DNS.
        Provide the `interfaces` keyword argument if adding multiple additional interfaces.
        Interfaces can be one of any valid interface for a layer 3 firewall. Unless the
        interface type is specified, physical_interface is assumed.

        If providing the `interfaces` keyword during creation, the valid interface
        types are:

            - physical_interface (default if not specified)
            - tunnel_interface
            - switch_physical_interface

        If providing all engine interfaces in a single operation, see :py:meth:`~create_bulk`
        for additional examples.

        :param str name: name of firewall engine
        :param str mgmt_ip: ip address of management interface
        :param str mgmt_network: management network in cidr format
        :param str log_server_ref: (optional) href to log_server instance for engine
        :param int mgmt_interface: (optional) interface for management from SMC to engine
        :param list domain_server_address: (optional) DNS server addresses
        :param str zone_ref: zone name, str href or zone name for management interface
            (created if not found)
        :param bool reverse_connection: should the NGFW be the mgmt initiator (used when behind NAT)
        :param default_nat: (optional) Whether to enable default NAT for outbound.
          Accepted values are:
           'true': use Default NAT Address for Traffic from Internal Networks |
           'false': don't use Default NAT Address for Traffic from Internal Networks |
           'automatic': use Default NAT Address for Traffic from Internal Networks if the firewall has a default route
        :param bool enable_antivirus: (optional) Enable antivirus (required DNS)
        :param bool enable_gti: (optional) Enable GTI
        :param bool sidewinder_proxy_enabled: Enable Sidewinder proxy functionality
        :param list known_host_lists: hrefs of ssh known host list objects (comma separated)
        :param str location_ref: location href or not for engine if needed to contact SMC
            behind NAT (created if not found)
        :param bool enable_ospf: whether to turn OSPF on within engine
        :param str ospf_profile: optional OSPF profile to use on engine, by ref
        :param NTPSettings ntp_settings: NTP settings
        :param LLDPProfile lldp_profile: LLDP Profile represents a set of attributes used for
        configuring LLDP
        :param LinkUsageProfile link_usage_profile
        :param dict extra_opts: extra options as a dict to be passed to the top level engine
        :param kw: optional keyword arguments specifying additional interfaces
        :param bool quic_enabled: (optional) include QUIC ports for web traffic
        :param bool discard_quic_if_cant_inspect: (optional) discard or allow QUIC
        :param node_definition information for the node itself
         if inspection is not possible
        :param list(SidewinderProxyAdvancedSettings) ssm_advanced_setting: Sidewinder proxy advanced
            settings.
        :param dict,ScanDetection scan_detection: This represents the definition of Scan Detection
            on a NGFW.
        :param list(dict),list(StaticMulticastRoute) static_multicast_route: Represents Firewall
            multicast routing entry for Static/IGMP Proxy multicast routing modes.
        :param WebAuthentication/dict web_authentication: This represents the Browser-Based User
            Authentication settings for a NGFW.
        :raises CreateEngineFailed: Failure to create with reason
        :return: :py:class:`smc.core.engine.Engine`
        """
        interfaces = kw.pop("interfaces", [])
        # Add the primary interface to the interface list
        interface = {
            "interface_id": mgmt_interface,
            "interface": "single_node_interface",
            "zone_ref": zone_ref,
            "interfaces": [
                {
                    "nodes": [
                        {
                            "address": mgmt_ip,
                            "network_value": mgmt_network,
                            "nodeid": 1,
                            "reverse_connection": reverse_connection,
                        }
                    ]
                }
            ],
        }
        interfaces.append(interface)

        nodes_definition = []
        if node_definition:
            nodes_definition.append(node_definition)

        return Layer3Firewall.create_bulk(
            name=name,
            node_type=node_type,
            interfaces=interfaces,
            primary_mgt=mgmt_interface,
            domain_server_address=domain_server_address,
            log_server_ref=log_server_ref,
            enable_gti=enable_gti,
            nodes=1,
            nodes_definition=nodes_definition,
            enable_antivirus=enable_antivirus,
            sidewinder_proxy_enabled=sidewinder_proxy_enabled,
            known_host_lists=known_host_lists,
            default_nat=default_nat,
            location_ref=location_ref,
            enable_ospf=enable_ospf,
            ospf_profile=ospf_profile,
            snmp=snmp,
            ntp_settings=ntp_settings,
            comment=comment,
            timezone=timezone,
            engine_type=engine_type,
            extra_opts=extra_opts,
            lldp_profile=lldp_profile,
            link_usage_profile=link_usage_profile,
            quic_enabled=quic_enabled,
            discard_quic_if_cant_inspect=discard_quic_if_cant_inspect,
            ssm_advanced_setting=ssm_advanced_setting,
            scan_detection=scan_detection,
            static_multicast_route=static_multicast_route,
            web_authentication=web_authentication
        )

    @classmethod
    def create_dynamic(
        cls,
        name,
        interface_id,
        dynamic_index=1,
        reverse_connection=True,
        automatic_default_route=True,
        domain_server_address=None,
        loopback_ndi="127.0.0.1",
        location_ref=None,
        log_server_ref=None,
        zone_ref=None,
        enable_gti=False,
        enable_antivirus=False,
        sidewinder_proxy_enabled=False,
        known_host_lists=[],
        default_nat='automatic',
        comment=None,
        extra_opts=None,
        engine_type=None,
        node_type="firewall_node",
        lldp_profile=None,
        link_usage_profile=None,
        quic_enabled=True,
        discard_quic_if_cant_inspect=True,
        node_definition=None,
        ssm_advanced_setting=None,
        web_authentication=None,
        **kw
    ):
        """
        Create a single layer 3 firewall with only a single DHCP interface. Useful
        when creating virtualized engine's such as in Microsoft Azure.

        :param str name: name of engine
        :param str,int interface_id: interface ID used for dynamic interface and management
        :param bool reverse_connection: specifies the dynamic interface should initiate connections
            to management (default: True)
        :param bool automatic_default_route: allow SMC to create a dynamic netlink for the default
            route (default: True)
        :param list domain_server_address: list of IP addresses for engine DNS
        :param str loopback_ndi: IP address for a loopback NDI. When creating a dynamic engine, the
            `auth_request` must be set to a different interface, so loopback is created
        :param str location_ref: location by name for the engine
        :param str log_server_ref: log server reference, will use the default or first retrieved if
            not specified
        :param LLDPProfile lldp_profile: LLDP Profile represents a set of attributes used for
        configuring LLDP
        :param dict extra_opts: extra options as a dict to be passed to the top level engine
        :param bool quic_enabled: (optional) include QUIC ports for web traffic
        :param bool discard_quic_if_cant_inspect: (optional) discard or allow QUIC
        :param node_definition information for the node itself
         if inspection is not possible
        :param WebAuthentication/dict web_authentication: This represents the Browser-Based User
            Authentication settings for a NGFW.
        :raises CreateElementFailed: failed to create engine
        :return: :py:class:`smc.core.engine.Engine`
        """
        interfaces = kw.pop("interfaces", [])
        # Add the primary interface to the interface list
        interface = {
            "interface_id": interface_id,
            "interface": "single_node_interface",
            "zone_ref": zone_ref,
            "interfaces": [
                {
                    "nodes": [
                        {
                            "dynamic": True,
                            "dynamic_index": dynamic_index,
                            "nodeid": 1,
                            "reverse_connection": reverse_connection,
                            "automatic_default_route": automatic_default_route,
                        }
                    ]
                }
            ],
        }
        interfaces.append(interface)

        loopback = LoopbackInterface.create(
            address=loopback_ndi, nodeid=1, auth_request=True, rank=1
        )

        nodes_definition = []
        if node_definition:
            nodes_definition.append(node_definition)

        return Layer3Firewall.create_bulk(
            name=name,
            node_type=node_type,
            nodes_definition=nodes_definition,
            primary_mgt=interface_id,
            interfaces=interfaces,
            loopback_ndi=[loopback.data],
            domain_server_address=domain_server_address,
            log_server_ref=log_server_ref,
            enable_gti=enable_gti,
            nodes=1,
            enable_antivirus=enable_antivirus,
            sidewinder_proxy_enabled=sidewinder_proxy_enabled,
            known_host_lists=known_host_lists,
            default_nat=default_nat,
            location_ref=location_ref,
            comment=comment,
            engine_type=engine_type,
            extra_opts=extra_opts,
            lldp_profile=lldp_profile,
            link_usage_profile=link_usage_profile,
            quic_enabled=quic_enabled,
            discard_quic_if_cant_inspect=discard_quic_if_cant_inspect,
            ssm_advanced_setting=ssm_advanced_setting,
            web_authentication=web_authentication
        )

    @property
    def quic_enabled(self):
        """
        include QUIC ports for web traffic

        :rtype: bool
        """
        return self.data.get("quic_enabled")

    @quic_enabled.setter
    def quic_enabled(self, value):
        if min_smc_version("7.0"):
            self.data["quic_enabled"] = value

    @property
    def ha_settings(self):
        """
        HA settings for the engine

        :rtype: HAForSingleEngine or None
        """
        if min_smc_version("7.2"):
            return HAForSingleEngine(self.data)


class CloudSGSingleFW(Layer3Firewall):
    """
    Creates a Cloud Firewall with a default dynamic interface
    To instantiate and create, call 'create_dynamic' classmethod as follows::

        engine = CloudSGSingleFW.create_dynamic(interface_id=0,
                                                name='Cloud Single firewall 1')

    """

    typeof = "cloud_single_fw"

    @classmethod
    def create_dynamic(
        cls,
        name,
        interface_id,
        dynamic_index=1,
        reverse_connection=True,
        automatic_default_route=True,
        domain_server_address=None,
        loopback_ndi="127.0.0.1",
        location_ref=None,
        log_server_ref=None,
        zone_ref=None,
        enable_gti=False,
        enable_antivirus=False,
        sidewinder_proxy_enabled=False,
        known_host_lists=[],
        default_nat='automatic',
        comment=None,
        extra_opts=None,
        **kw
    ):
        return Layer3Firewall.create_dynamic(
            name,
            interface_id,
            dynamic_index,
            reverse_connection,
            automatic_default_route,
            domain_server_address,
            loopback_ndi,
            location_ref,
            log_server_ref,
            zone_ref,
            enable_gti,
            enable_antivirus,
            sidewinder_proxy_enabled,
            known_host_lists,
            default_nat,
            comment,
            extra_opts,
            cls,
            "cloud_fw_node",
            **kw
        )

    @classmethod
    def create(
        cls,
        name,
        mgmt_ip,
        mgmt_network,
        mgmt_interface=0,
        log_server_ref=None,
        default_nat='automatic',
        reverse_connection=False,
        domain_server_address=None,
        zone_ref=None,
        enable_antivirus=False,
        enable_gti=False,
        location_ref=None,
        enable_ospf=False,
        sidewinder_proxy_enabled=False,
        known_host_lists=[],
        ospf_profile=None,
        snmp=None,
        comment=None,
        extra_opts=None,
        engine_type=None,
        node_type="firewall_node",
        **kw
    ):
        raise Exception(
            "create method not supported by " + str(cls) + " use create_dynamic instead !"
        )


class Layer2Firewall(Engine):
    """
    Creates a Layer 2 Firewall with a default inline interface pair
    To instantiate and create, call 'create' classmethod as follows::

        engine = Layer2Firewall.create(name='myinline',
                                       mgmt_ip='1.1.1.1',
                                       mgmt_network='1.1.1.0/24')
    """

    typeof = "single_layer2"

    @classmethod
    def create(
        cls,
        name,
        mgmt_ip,
        mgmt_network,
        mgmt_interface=0,
        inline_interface="1-2",
        logical_interface="default_eth",
        log_server_ref=None,
        domain_server_address=None,
        zone_ref=None,
        enable_antivirus=False,
        enable_gti=False,
        comment=None,
        extra_opts=None,
        lldp_profile=None,
        discard_quic_if_cant_inspect=True,
        node_definition=None,
        scan_detection=None,
        **kw
    ):
        """
        Create a single layer 2 firewall with management interface and inline pair

        :param str name: name of firewall engine
        :param str mgmt_ip: ip address of management interface
        :param str mgmt_network: management network in cidr format
        :param int mgmt_interface: (optional) interface for management from SMC to engine
        :param str inline_interface: interfaces to use for first inline pair
        :param str logical_interface: name, str href or LogicalInterface (created if it
            doesn't exist)
        :param str log_server_ref: (optional) href to log_server instance
        :param list domain_server_address: (optional) DNS server addresses
        :param str zone_ref: zone name, str href or Zone for management interface
            (created if not found)
        :param bool enable_antivirus: (optional) Enable antivirus (required DNS)
                :param bool enable_gti: (optional) Enable GTI
        :param LLDPProfile lldp_profile: LLDP Profile represents a set of attributes used for
        configuring LLDP
        :param bool discard_quic_if_cant_inspect: (optional) discard or allow QUIC
         if inspection is not possible
        :param node_definition information for the node itself
        :param dict extra_opts: extra options as a dict to be passed to the top level engine
        :param dict,ScanDetection scan_detection: This represents the definition of Scan Detection
            on a NGFW.
        :raises CreateEngineFailed: Failure to create with reason
        :return: :py:class:`smc.core.engine.Engine`
        """
        interfaces = []
        interface_id, second_interface_id = inline_interface.split("-")
        l2 = {
            "interface_id": interface_id,
            "interface": "inline_interface",
            "second_interface_id": second_interface_id,
            "logical_interface_ref": logical_interface,
        }

        interfaces.append({"physical_interface": Layer2PhysicalInterface(**l2)})

        layer3 = {
            "interface_id": mgmt_interface,
            "zone_ref": zone_ref,
            "interfaces": [
                {"nodes": [{"address": mgmt_ip,
                            "network_value": mgmt_network,
                            "nodeid": 1}]}
            ],
        }

        interfaces.append(
            {"physical_interface": Layer3PhysicalInterface(primary_mgt=mgmt_interface, **layer3)}
        )

        nodes_definition = []
        if node_definition:
            nodes_definition.append(node_definition)

        engine = super(Layer2Firewall, cls)._create(
            name=name,
            node_type="fwlayer2_node",
            nodes_definition=nodes_definition,
            physical_interfaces=interfaces,
            domain_server_address=domain_server_address,
            log_server_ref=log_server_ref,
            enable_gti=enable_gti,
            nodes=1,
            enable_antivirus=enable_antivirus,
            comment=comment,
            lldp_profile=lldp_profile,
            discard_quic_if_cant_inspect=discard_quic_if_cant_inspect,
            scan_detection=scan_detection,
            **extra_opts if extra_opts else {},
        )

        try:
            return ElementCreator(cls, json=engine)

        except CreateElementFailed as e:
            raise CreateEngineFailed(e)


class Layer2Cluster(Layer2Firewall):
    typeof = "layer2_cluster"


class VirtualLayer2(Layer2Firewall):
    typeof = "virtual_firewall_layer2"


class IPS(Engine):
    """
    Creates an IPS engine with a default inline interface pair
    """

    typeof = "single_ips"

    @classmethod
    def create(
        cls,
        name,
        mgmt_ip,
        mgmt_network,
        mgmt_interface=0,
        inline_interface="1-2",
        logical_interface="default_eth",
        log_server_ref=None,
        domain_server_address=None,
        zone_ref=None,
        enable_antivirus=False,
        enable_gti=False,
        comment=None,
        extra_opts=None,
        lldp_profile=None,
        discard_quic_if_cant_inspect=True,
        node_definition=None,
        scan_detection=None,
        **kw
    ):
        """
        Create a single IPS engine with management interface and inline pair

        :param str name: name of ips engine
        :param str mgmt_ip: ip address of management interface
        :param str mgmt_network: management network in cidr format
        :param int mgmt_interface: (optional) interface for management from SMC to engine
        :param str inline_interface: interfaces to use for first inline pair
        :param str logical_interface: name, str href or LogicalInterface (created if it
            doesn't exist)
        :param str log_server_ref: (optional) href to log_server instance
        :param list domain_server_address: (optional) DNS server addresses
        :param str zone_ref: zone name, str href or Zone for management interface
            (created if not found)
        :param bool enable_antivirus: (optional) Enable antivirus (required DNS)
                :param bool enable_gti: (optional) Enable GTI
        :param LLDPProfile lldp_profile: LLDP Profile represents a set of attributes used for
        configuring LLDP
        :param bool discard_quic_if_cant_inspect: (optional) discard or allow QUIC
         if inspection is not possible
        :param dict extra_opts: extra options as a dict to be passed to the top level engine
        :param node_definition information for the node itself
        :param dict,ScanDetection scan_detection: This represents the definition of Scan Detection
            on a NGFW.
        :raises CreateEngineFailed: Failure to create with reason
        :return: :py:class:`smc.core.engine.Engine`
        """
        interfaces = []
        interface_id, second_interface_id = inline_interface.split("-")
        l2 = {
            "interface_id": interface_id,
            "interface": "inline_interface",
            "second_interface_id": second_interface_id,
            "logical_interface_ref": logical_interface,
        }

        interfaces.append({"physical_interface": Layer2PhysicalInterface(**l2)})

        layer3 = {
            "interface_id": mgmt_interface,
            "zone_ref": zone_ref,
            "interfaces": [
                {"nodes": [{"address": mgmt_ip,
                            "network_value": mgmt_network,
                            "nodeid": 1}]}
            ],
        }

        interfaces.append(
            {"physical_interface": Layer3PhysicalInterface(primary_mgt=mgmt_interface, **layer3)}
        )

        nodes_definition = []
        if node_definition:
            nodes_definition.append(node_definition)

        engine = super(IPS, cls)._create(
            name=name,
            node_type="ips_node",
            nodes_definition=nodes_definition,
            physical_interfaces=interfaces,
            domain_server_address=domain_server_address,
            log_server_ref=log_server_ref,
            enable_gti=enable_gti,
            nodes=1,
            enable_antivirus=enable_antivirus,
            comment=comment,
            lldp_profile=lldp_profile,
            discard_quic_if_cant_inspect=discard_quic_if_cant_inspect,
            scan_detection=scan_detection,
            **extra_opts if extra_opts else {},
        )

        try:
            return ElementCreator(cls, json=engine)

        except CreateElementFailed as e:
            raise CreateEngineFailed(e)


class VirtualIPS(IPS):
    typeof = "virtual_ips"

    @classmethod
    def create(
        cls,
        name,
        inline_interface="1-2",
        logical_interface="default_eth",
        log_server_ref=None,
        domain_server_address=None,
        zone_ref=None,
        enable_antivirus=False,
        enable_gti=False,
        comment=None,
        extra_opts=None,
        lldp_profile=None,
        discard_quic_if_cant_inspect=True,
        node_definition=None,
        scan_detection=None,
        **kw
    ):
        """
        Create a single IPS engine with management interface and inline pair

        :param str name: name of ips engine
        :param str inline_interface: interfaces to use for first inline pair
        :param str logical_interface: name, str href or LogicalInterface (created if it
            doesn't exist)
        :param str log_server_ref: (optional) href to log_server instance
        :param list domain_server_address: (optional) DNS server addresses
        :param str zone_ref: zone name, str href or Zone for management interface
            (created if not found)
        :param bool enable_antivirus: (optional) Enable antivirus (required DNS)
                :param bool enable_gti: (optional) Enable GTI
        :param LLDPProfile lldp_profile: LLDP Profile represents a set of attributes used for
        configuring LLDP
        :param bool discard_quic_if_cant_inspect: (optional) discard or allow QUIC
         if inspection is not possible
        :param dict extra_opts: extra options as a dict to be passed to the top level engine
        :param node_definition information for the node itself
        :param dict,ScanDetection scan_detection: This represents the definition of Scan Detection
            on a NGFW.
        :raises CreateEngineFailed: Failure to create with reason
        :return: :py:class:`smc.core.engine.Engine`
        """
        interfaces = []
        interface_id, second_interface_id = inline_interface.split("-")
        l2 = {
            "interface_id": interface_id,
            "interface": "inline_interface",
            "second_interface_id": second_interface_id,
            "logical_interface_ref": logical_interface,
        }

        interfaces.append({"physical_interface": Layer2PhysicalInterface(**l2)})

        nodes_definition = []
        if node_definition:
            nodes_definition.append(node_definition)

        engine = super(VirtualIPS, cls)._create(
            name=name,
            node_type="virtual_ips_node",
            nodes_definition=nodes_definition,
            physical_interfaces=interfaces,
            domain_server_address=domain_server_address,
            log_server_ref=log_server_ref,
            enable_gti=enable_gti,
            nodes=1,
            enable_antivirus=enable_antivirus,
            comment=comment,
            lldp_profile=lldp_profile,
            discard_quic_if_cant_inspect=discard_quic_if_cant_inspect,
            scan_detection=scan_detection,
            **extra_opts if extra_opts else {},
        )

        try:
            return ElementCreator(cls, json=engine)

        except CreateElementFailed as e:
            raise CreateEngineFailed(e)


class Layer3VirtualEngine(Engine):
    """
    Create a layer3 virtual engine and map to specified Master Engine
    Each layer 3 virtual firewall will use the same virtual resource that
    should be pre-created.

    To instantiate and create, call 'create' as follows::

        engine = Layer3VirtualEngine.create(
                                name='myips',
                                master_engine='mymaster_engine',
                                virtual_engine='ve-3',
                                interfaces=[{'interface_id': 0,
                                             'address': '5.5.5.5',
                                             'network_value': '5.5.5.5/30',
                                             'zone_ref': ''}]
    """

    typeof = "virtual_fw"

    @classmethod
    def create(
        cls,
        name,
        master_engine,
        virtual_resource,
        interfaces,
        default_nat='automatic',
        outgoing_intf=0,
        domain_server_address=None,
        enable_ospf=False,
        ospf_profile=None,
        comment=None,
        extra_opts=None,
        quic_enabled=True,
        discard_quic_if_cant_inspect=True,
        ssm_advanced_setting=None,
        scan_detection=None,
        static_multicast_route=None,
        pim_settings=None,
        web_authentication=None,
        nat64_settings=None,
        **kw
    ):
        """
        Create a Layer3Virtual engine for a Master Engine. Provide interfaces
        as a list of dict items specifying the interface details in format::

            {'interface_id': 1, 'address': '1.1.1.1', 'network_value': '1.1.1.0/24',
             'zone_ref': zone_by_name,href, 'comment': 'my interface comment'}

        :param str name: Name of this layer 3 virtual engine
        :param str master_engine: Name of existing master engine
        :param str virtual_resource: name of pre-created virtual resource
        :param list interfaces: dict of interface details
        :param default_nat: (optional) Whether to enable default NAT for outbound.
          Accepted values are:
           'true': use Default NAT Address for Traffic from Internal Networks |
           'false': don't use Default NAT Address for Traffic from Internal Networks |
           'automatic': use Default NAT Address for Traffic from Internal Networks if the firewall has a default route
        :param int outgoing_intf: outgoing interface for VE. Specifies interface number
        :param list interfaces: interfaces mappings passed in
        :param bool enable_ospf: whether to turn OSPF on within engine
        :param str ospf_profile: optional OSPF profile to use on engine, by ref
        :param bool quic_enabled: (optional) include QUIC ports for web traffic
        :param bool discard_quic_if_cant_inspect: (optional) discard or allow QUIC
         if inspection is not possible
        :param dict extra_opts: extra options as a dict to be passed to the top level engine
        :param list(SidewinderProxyAdvancedSettings) ssm_advanced_setting: Sidewinder proxy advanced
            settings.
        :param dict,ScanDetection scan_detection: This represents the definition of Scan Detection
            on a NGFW.
        :param list(dict),list(StaticMulticastRoute) static_multicast_route: Represents Firewall
            multicast routing entry for Static/IGMP Proxy multicast routing modes.
        :param PIM/dict pim_settings: This represents the PIM Multicast routing settings.
        :param WebAuthentication/dict web_authentication: This represents the Browser-Based User
            Authentication settings for a NGFW.
        :param Nat64Settings/dict nat64_settings: This represents the NAT64 settings for a NGFW.
        :raises CreateEngineFailed: Failure to create with reason
        :raises LoadEngineFailed: master engine not found
        :return: :py:class:`smc.core.engine.Engine`
        """
        virt_resource_href = None  # need virtual resource reference
        master_engine = Engine(master_engine)

        for virt_resource in master_engine.virtual_resource.all():
            if virt_resource.name == virtual_resource:
                virt_resource_href = virt_resource.href
                break
        if not virt_resource_href:
            raise CreateEngineFailed(
                "Cannot find associated virtual resource for "
                "VE named: {}. You must first create a virtual resource for the "
                "master engine before you can associate a virtual engine. Cannot "
                "add VE".format(name)
            )

        virtual_interfaces = []
        for interface in interfaces:
            nodes = {
                "address": interface.get("address"),
                "network_value": interface.get("network_value"),
            }

            layer3 = {
                "interface_id": interface.get("interface_id"),
                "interface": "single_node_interface",
                "comment": interface.get("comment", None),
                "zone_ref": interface.get("zone_ref"),
            }

            if interface.get("interface_id") == outgoing_intf:
                nodes.update(outgoing=True, auth_request=True)

            layer3["interfaces"] = [{"nodes": [nodes]}]

            virtual_interfaces.append(
                {"virtual_physical_interface": Layer3PhysicalInterface(**layer3).data.data}
            )

            engine = super(Layer3VirtualEngine, cls)._create(
                name=name,
                node_type="virtual_fw_node",
                physical_interfaces=virtual_interfaces,
                domain_server_address=domain_server_address,
                log_server_ref=None,  # Isn't used in VE
                nodes=1,
                default_nat=default_nat,
                enable_ospf=enable_ospf,
                ospf_profile=ospf_profile,
                comment=comment,
                discard_quic_if_cant_inspect=discard_quic_if_cant_inspect,
                ssm_advanced_setting=ssm_advanced_setting,
                scan_detection=scan_detection,
                static_multicast_route=static_multicast_route,
                pim_settings=pim_settings,
                web_authentication=web_authentication,
                nat64_settings=nat64_settings,
                **extra_opts if extra_opts else {}
            )

            engine.update(virtual_resource=virt_resource_href)
            # Master Engine provides this service
            engine.pop("log_server_ref", None)

        if min_smc_version("7.0"):
            if quic_enabled:
                quic = {"quic_enabled": "true"}
            else:
                quic = {"quic_enabled": "false"}
            engine.update(quic)

        try:
            return ElementCreator(cls, json=engine)

        except CreateElementFailed as e:
            raise CreateEngineFailed(e)

    @property
    def quic_enabled(self):
        """
        include QUIC ports for web traffic

        :rtype: bool
        """
        return self.data.get("quic_enabled")

    @quic_enabled.setter
    def quic_enabled(self, value):
        if min_smc_version("7.0"):
            self.data["quic_enabled"] = value


class FirewallCluster(Engine):
    """
    Firewall Cluster
    Creates a layer 3 firewall cluster engine with CVI and NDI's. Once engine is
    created, you can later add additional interfaces using the `engine.physical_interface`
    reference.

    .. seealso::  :func:`smc.core.physical_interface.add_layer3_cluster_interface`
    """

    typeof = "fw_cluster"

    @classmethod
    def create_bulk(
        cls,
        name,
        interfaces=None,
        nodes=2,
        nodes_definition=[],
        cluster_mode="balancing",
        primary_mgt=None,
        backup_mgt=None,
        primary_heartbeat=None,
        log_server_ref=None,
        domain_server_address=None,
        location_ref=None,
        default_nat='automatic',
        enable_antivirus=False,
        enable_gti=False,
        comment=None,
        snmp=None,
        ntp_settings=None,
        timezone=None,
        extra_opts=None,
        lldp_profile=None,
        link_usage_profile=None,
        quic_enabled=True,
        discard_quic_if_cant_inspect=True,
        ssm_advanced_setting=None,
        scan_detection=None,
        static_multicast_route=None,
        pim_settings=None,
        web_authentication=None,
        nat64_settings=None,
        **kw
    ):
        """
        Create bulk is called by the `create` constructor when creating a cluster engine.
        This allows for multiple interfaces to be defined and passed in during element
        creation.

        :param dict snmp: SNMP dict should have keys `snmp_agent` str defining name of SNMPAgent,
            `snmp_interface` which is a list of interface IDs, and optionally `snmp_location` which
            is a string with the SNMP location name.
        :param list(dict),list(StaticMulticastRoute) static_multicast_route: Represents Firewall
            multicast routing entry for Static/IGMP Proxy multicast routing modes.
        :param PIM/dict pim_settings: This represents the PIM Multicast routing settings.
        """
        primary_heartbeat = primary_mgt if not primary_heartbeat else primary_heartbeat

        physical_interfaces = []
        for interface in interfaces:
            if "interface_id" not in interface:
                raise CreateEngineFailed(
                    "Interface definitions must contain the interface_id "
                    "field. Failed to create engine: %s" % name
                )
            if interface.get("type", None) == "tunnel_interface":
                tunnel_interface = TunnelInterface(**interface)
                physical_interfaces.append({"tunnel_interface": tunnel_interface})
            else:
                cluster_interface = ClusterPhysicalInterface(
                    primary_mgt=primary_mgt,
                    backup_mgt=backup_mgt,
                    primary_heartbeat=primary_heartbeat,
                    **interface
                )
                physical_interfaces.append({"physical_interface": cluster_interface})

        if snmp:
            snmp_agent = dict(
                snmp_agent_ref=snmp.get("snmp_agent", ""),
                snmp_location=snmp.get("snmp_location", ""),
            )

            snmp_agent.update(snmp_interface=add_snmp(interfaces, snmp.get("snmp_interface", [])))

        # convert ntp_settings from extra_opts to parameter for _create function
        if extra_opts is not None and "ntp_settings" in extra_opts:
            ntp_settings = extra_opts['ntp_settings']
            del extra_opts['ntp_settings']

        # convert timezone from extra_opts to parameter for _create function
        if extra_opts is not None and "timezone" in extra_opts:
            timezone = extra_opts['timezone']
            del extra_opts['timezone']

        # convert lldp_profile_ref from extra_opts to parameter for _create function
        if extra_opts is not None and "lldp_profile_ref" in extra_opts:
            lldp_profile = extra_opts['lldp_profile_res']
            del extra_opts['lldp_profile_ref']

        # convert link_usage_profile_ref from extra_opts to parameter for _create function
        if extra_opts is not None and "link_usage_profile_ref" in extra_opts:
            lldp_profile = extra_opts['link_usage_profile_ref']
            del extra_opts['link_usage_profile_ref']

        try:
            engine = super(FirewallCluster, cls)._create(
                name=name,
                node_type="firewall_node",
                physical_interfaces=physical_interfaces,
                domain_server_address=domain_server_address,
                log_server_ref=log_server_ref,
                location_ref=location_ref,
                enable_gti=enable_gti,
                nodes=nodes,
                nodes_definition=nodes_definition,
                enable_antivirus=enable_antivirus,
                default_nat=default_nat,
                snmp_agent=snmp_agent if snmp else None,
                ntp_settings=ntp_settings,
                comment=comment,
                timezone=timezone,
                lldp_profile=lldp_profile,
                link_usage_profile=link_usage_profile,
                discard_quic_if_cant_inspect=discard_quic_if_cant_inspect,
                ssm_advanced_setting=ssm_advanced_setting,
                scan_detection=scan_detection,
                static_multicast_route=static_multicast_route,
                pim_settings=pim_settings,
                web_authentication=web_authentication,
                nat64_settings=nat64_settings,
                ** extra_opts if extra_opts else {},
            )
            engine.update(cluster_mode=cluster_mode)

            if min_smc_version("7.0"):
                if quic_enabled:
                    quic = {"quic_enabled": "true"}
                else:
                    quic = {"quic_enabled": "false"}
                engine.update(quic)

            return ElementCreator(cls, json=engine)

        except (ElementNotFound, CreateElementFailed) as e:
            raise CreateEngineFailed(e)

    @classmethod
    def create(
        cls,
        name,
        cluster_virtual,
        network_value,
        macaddress,
        interface_id,
        nodes,
        nodes_definition=[],
        vlan_id=None,
        cluster_mode="balancing",
        backup_mgt=None,
        primary_heartbeat=None,
        log_server_ref=None,
        domain_server_address=None,
        location_ref=None,
        zone_ref=None,
        default_nat='automatic',
        enable_antivirus=False,
        enable_gti=False,
        comment=None,
        snmp=None,
        ntp_settings=None,
        timezone=None,
        extra_opts=None,
        lldp_profile=None,
        link_usage_profile=None,
        quic_enabled=True,
        discard_quic_if_cant_inspect=True,
        ssm_advanced_setting=None,
        static_multicast_route=None,
        pim_settings=None,
        web_authentication=None,
        **kw
    ):
        """
        Create a layer 3 firewall cluster with management interface and any number
        of nodes. If providing keyword arguments to create additional interfaces,
        use the same constructor arguments and pass an `interfaces` keyword argument.
        The constructor defined interface will be assigned as the primary
        management interface by default. Otherwise the engine will be created with a
        single interface and interfaces can be added after.

        .. versionchanged:: 0.6.1
            Chgnged `cluster_nic` to `interface_id`, and `cluster_mask` to `network_value`

        :param str name: name of firewall engine
        :param str cluster_virtual: ip of cluster CVI
        :param str network_value: ip netmask of cluster CVI
        :param str macaddress: macaddress for packet dispatch clustering
        :param str interface_id: nic id to use for primary interface
        :param list nodes: address/network_value/nodeid combination for cluster nodes
        :param list nodes_definition : list of node info (name, comment..)
        :param str vlan_id: optional VLAN id for the management interface, i.e. '15'.
        :param str cluster_mode: 'balancing' or 'standby' mode (default: balancing)
        :param str,int primary_heartbeat: optionally set the primary_heartbeat. This is
            automatically set to the management interface but can be overridden to use
            another interface if defining additional interfaces using `interfaces`.
        :param str,int backup_mgt: optionally set the backup management interface. This
            is unset unless you define additional interfaces using `interfaces`.
        :param str log_server_ref: (optional) href to log_server instance
        :param list domain_server_address: (optional) DNS server addresses
        :param str location_ref: location href or not for engine if needed to contact SMC
            behind NAT (created if not found)
        :param str zone_ref: zone name, str href or Zone for management interface
            (created if not found)
        :param bool enable_antivirus: (optional) Enable antivirus (required DNS)
        :param bool enable_gti: (optional) Enable GTI
        :param list interfaces: optional keyword to supply additional interfaces
        :param dict snmp: SNMP dict should have keys `snmp_agent` str defining name of SNMPAgent,
            `snmp_interface` which is a list of interface IDs, and optionally `snmp_location` which
            is a string with the SNMP location name.
        :param LLDPProfile lldp_profile: LLDP Profile represents a set of attributes used for
        configuring LLDP
        :param LinkUsageProfile link_usage_profile: Link usage profile
        :param bool quic_enabled: (optional) include QUIC ports for web traffic
        :param bool discard_quic_if_cant_inspect: (optional) discard or allow QUIC
         if inspection is not possible
        :param list(SidewinderProxyAdvancedSettings) ssm_advanced_setting: Sidewinder proxy advanced
            settings.
        :param list(dict),list(StaticMulticastRoute) static_multicast_route: Represents Firewall
            multicast routing entry for Static/IGMP Proxy multicast routing modes.
        :param PIM/dict pim_settings: This represents the PIM Multicast routing settings.
        :param WebAuthentication/dict web_authentication: This represents the Browser-Based User
            Authentication settings for a NGFW.
        :param dict extra_opts: extra options as a dict to be passed to the top level engine
        :raises CreateEngineFailed: Failure to create with reason
        :return: :py:class:`smc.core.engine.Engine`

        Example nodes parameter input::

            [{'address':'5.5.5.2', 'network_value':'5.5.5.0/24', 'nodeid':1},
             {'address':'5.5.5.3', 'network_value':'5.5.5.0/24', 'nodeid':2},
             {'address':'5.5.5.4', 'network_value':'5.5.5.0/24', 'nodeid':3}]

        You can also create additional CVI+NDI, or NDI only interfaces by providing
        the keyword argument interfaces using the same keyword values from the
        constructor::

            interfaces=[
               {'interface_id': 1,
                'macaddress': '02:02:02:02:02:03',
                'interfaces': [{'cluster_virtual': '2.2.2.1',
                                'network_value': '2.2.2.0/24',
                                'nodes':[{'address': '2.2.2.2', 'network_value': '2.2.2.0/24',
                                          'nodeid': 1},
                                         {'address': '2.2.2.3', 'network_value': '2.2.2.0/24',
                                          'nodeid': 2}]
                              }]
                },
               {'interface_id': 2,
                'interfaces': [{'nodes':[{'address': '3.3.3.2', 'network_value': '3.3.3.0/24',
                                          'nodeid': 1},
                                         {'address': '3.3.3.3', 'network_value': '3.3.3.0/24',
                                          'nodeid': 2}]
                              }]
                }]

        You can add additional CVI's+NDI in primary interface being created with parameter passed
        in create method.

        The primary CVI of the primary interface will be created from (cluster_virtual,
        network_value,nodes) parameter passed to constructor.
        For example, if interface_id '0' is the primary interface, then additional CVI's can be added by
        providing the keyword argument interfaces using the same keyword values from the
        constructor::

            interfaces=[
               {'interface_id': 0,
                'macaddress': '02:02:02:02:02:01',
                'interfaces': [{'cluster_virtual': '2.2.2.1',
                                'network_value': '2.2.2.0/24',
                                'nodes':[{'address': '2.2.2.2', 'network_value': '2.2.2.0/24',
                                          'nodeid': 1},
                                         {'address': '2.2.2.3', 'network_value': '2.2.2.0/24',
                                          'nodeid': 2}]
                              }]
                },]

        Then additional CVI(2.2.2.1)+NDI's(2.2.2.2, 2.2.2.3) will be added to primary
            interface 0.

        It is also possible to define VLAN interfaces by providing the `vlan_id` keyword.
        Example VLAN with NDI only interfaces. If nesting the zone_ref within the interfaces
        list, the zone will be applied to the VLAN versus the top level interface::

            interfaces=[
               {'interface_id': 2,
                'interfaces': [{'nodes':[{'address': '3.3.3.2', 'network_value': '3.3.3.0/24',
                                          'nodeid': 1},
                                         {'address': '3.3.3.3', 'network_value': '3.3.3.0/24',
                                          'nodeid': 2}],
                                'vlan_id': 22,
                                'zone_ref': 'private-network'
                              },
                              {'nodes': [{'address': '4.4.4.1', 'network_value': '4.4.4.0/24',
                                          'nodeid': 1},
                                         {'address': '4.4.4.2', 'network_value': '4.4.4.0/24',
                                          'nodeid': 2}],
                               'vlan_id': 23,
                               'zone_ref': 'other_vlan'
                            }]
            }]

        Tunnel interfaces can also be created. As all interfaces defined are assumed to be
        a physical interface type, you must specify the `type` parameter to indicate the
        interface is a tunnel interface. Tunnel interfaces do not have a macaddress or VLANs.
        They be configured with NDI interfaces by omitting the `cluster_virtual` and
        `network_value` top level attributes::

            interfaces=[
                {'interface_id': 1000,
                 'interfaces': [{'cluster_virtual': '100.100.100.1',
                                 'network_value': '100.100.100.0/24',
                                 'nodes':[{'address': '100.100.100.2', 'network_value':
                                           '100.100.100.0/24', 'nodeid': 1},
                                          {'address': '100.100.100.3', 'network_value':
                                           '100.100.100.0/24', 'nodeid': 2}]
                               }],
                 'zone_ref': 'AWStunnel',
                 'type': 'tunnel_interface'
                }]

        If setting primary_heartbeat or backup_mgt to a specific interface (the primary
        interface configured in the constructor will have these roles by default), you
        must define the interfaces in the `interfaces` keyword argument list.

        .. note:: If creating additional interfaces, you must at minimum provide the
            `interface_id` and `nodes` to create an NDI only interface.

        """
        interfaces = kw.pop("interfaces", [])
        # Add the primary interface to the interface list
        interface = {
            "cluster_virtual": cluster_virtual,
            "network_value": network_value,
            "nodes": nodes,
        }
        if vlan_id:
            interface.update(vlan_id=vlan_id)

        # merging node of same interface
        is_ifc_append = False
        for intfc in interfaces:
            if "interface_id" in intfc and intfc['interface_id'] == interface_id:
                intfc.update({'macaddress': macaddress, 'zone_ref': zone_ref})
                for ifc in intfc['interfaces']:
                    # By default, primary CVI will be used for identity for authentication requests.
                    ifc['auth_request'] = False
                intfc['interfaces'].append(interface)
                is_ifc_append = True
                break

        if not is_ifc_append:
            interfaces.append(
                dict(
                    interface_id=interface_id,
                    macaddress=macaddress,
                    zone_ref=zone_ref,
                    interfaces=[interface],
                )
            )

        primary_mgt = interface_id if not vlan_id else "{}.{}".format(interface_id, vlan_id)

        return FirewallCluster.create_bulk(
            name,
            interfaces=interfaces,
            nodes=len(nodes),
            nodes_definition=nodes_definition,
            cluster_mode=cluster_mode,
            primary_mgt=primary_mgt,
            backup_mgt=backup_mgt,
            primary_heartbeat=primary_heartbeat,
            log_server_ref=log_server_ref,
            domain_server_address=domain_server_address,
            location_ref=location_ref,
            default_nat=default_nat,
            enable_antivirus=enable_antivirus,
            enable_gti=enable_gti,
            comment=comment,
            snmp=snmp,
            ntp_settings=ntp_settings,
            timezone=timezone,
            extra_opts=extra_opts,
            lldp_profile=lldp_profile,
            link_usage_profile=link_usage_profile,
            quic_enabled=quic_enabled,
            discard_quic_if_cant_inspect=discard_quic_if_cant_inspect,
            ssm_advanced_setting=ssm_advanced_setting,
            static_multicast_route=static_multicast_route,
            pim_settings=pim_settings,
            web_authentication=web_authentication
        )

    @property
    def quic_enabled(self):
        """
        include QUIC ports for web traffic

        :rtype: bool
        """
        return self.data.get("quic_enabled")

    @quic_enabled.setter
    def quic_enabled(self, value):
        if min_smc_version("7.0"):
            self.data["quic_enabled"] = value


class MasterEngine(Engine):
    """
    Creates a master engine in a firewall role. Layer3VirtualEngine should be used
    to add each individual instance to the Master Engine.
    """

    typeof = "master_engine"

    @classmethod
    def create(
        cls,
        name,
        master_type,
        mgmt_ip,
        mgmt_network,
        mgmt_interface=0,
        log_server_ref=None,
        zone_ref=None,
        domain_server_address=None,
        enable_gti=False,
        enable_antivirus=False,
        comment=None,
        extra_opts=None,
        lldp_profile=None,
        cluster_mode="standby",
        reverse_connection=False,
        node_definition=None,
        ssm_advanced_setting=None,
        scan_detection=None,
        **kw
    ):
        """
        Create a Master Engine with management interface

        :param str name: name of master engine engine
        :param str master_type: firewall|
        :param str mgmt_ip: ip address for management interface
        :param str mgmt_network: full netmask for management
        :param str mgmt_interface: interface to use for mgmt (default: 0)
        :param str log_server_ref: (optional) href to log_server instance
        :param list domain_server_address: (optional) DNS server addresses
        :param bool enable_antivirus: (optional) Enable antivirus (required DNS)
        :param bool enable_gti: (optional) Enable GTI
        :param dict extra_opts: extra options as a dict to be passed to the top level engine
        :param LLDPProfile lldp_profile: LLDP Profile represents a set of attributes used for
        configuring LLDP
        :param str cluster_mode: Defines whether the clustered engines are all online balancing the
            traffic or whether one node is online at a time and the other engines are used as backup
        :param boolean reverse_connection: Reverse connection.
        :param node_definition information for the node itself
        :param list(SidewinderProxyAdvancedSettings) ssm_advanced_setting: Sidewinder proxy advanced
            settings.
        :raises CreateEngineFailed: Failure to create with reason
        :return: :py:class:`smc.core.engine.Engine`
        """
        interface = {
            "interface_id": mgmt_interface,
            "interfaces": [{"nodes": [{"address": mgmt_ip,
                                       "network_value": mgmt_network,
                                       "reverse_connection": reverse_connection}]}],
            "zone_ref": zone_ref,
            "comment": comment,
        }

        interface = Layer3PhysicalInterface(
            primary_mgt=mgmt_interface, primary_heartbeat=mgmt_interface, **interface
        )

        nodes_definition = []
        if node_definition:
            nodes_definition.append(node_definition)

        engine = super(MasterEngine, cls)._create(
            name=name,
            node_type="master_node",
            physical_interfaces=[{"physical_interface": interface}],
            domain_server_address=domain_server_address,
            log_server_ref=log_server_ref,
            enable_gti=enable_gti,
            nodes=1,
            nodes_definition=nodes_definition,
            enable_antivirus=enable_antivirus,
            comment=comment,
            lldp_profile=lldp_profile,
            ssm_advanced_setting=ssm_advanced_setting,
            scan_detection=scan_detection,
            **extra_opts if extra_opts else {}
        )

        engine.update(master_type=master_type, cluster_mode=cluster_mode)

        try:
            return ElementCreator(cls, json=engine)

        except CreateElementFailed as e:
            raise CreateEngineFailed(e)


class MasterEngineCluster(Engine):
    """
    Master Engine Cluster
    Clusters are currently supported in an active/standby configuration
    only.
    """

    typeof = "master_engine"

    @classmethod
    def create(
        cls,
        name,
        master_type,
        macaddress,
        nodes,
        nodes_definition=None,
        mgmt_interface=0,
        log_server_ref=None,
        domain_server_address=None,
        enable_gti=False,
        enable_antivirus=False,
        comment=None,
        extra_opts=None,
        lldp_profile=None,
        cluster_mode="standby",
        reverse_connection=False,
        ssm_advanced_setting=None,
        scan_detection=None,
        **kw
    ):
        """
        Create Master Engine Cluster

        :param str name: name of master engine engine
        :param str master_type: firewall|
        :param str mgmt_ip: ip address for management interface
        :param str mgmt_netmask: full netmask for management
        :param str mgmt_interface: interface to use for mgmt (default: 0)
        :param list nodes: address/network_value/nodeid combination for cluster nodes
        :param str log_server_ref: (optional) href to log_server instance
        :param list domain_server_address: (optional) DNS server addresses
        :param bool enable_antivirus: (optional) Enable antivirus (required DNS)
        :param bool enable_gti: (optional) Enable GTI
        :param dict extra_opts: extra options as a dict to be passed to the top level engine
        :param LLDPProfile lldp_profile: LLDP Profile represents a set of attributes used for
        configuring LLDP
        :param str cluster_mode: Defines whether the clustered engines are all online balancing the
            traffic or whether one node is online at a time and the other engines are used as backup
        :param boolean reverse_connection: Reverse connection.
        :param list nodes_definition : list of node info (name, comment..)
        :param list(SidewinderProxyAdvancedSettings) ssm_advanced_setting: Sidewinder proxy advanced
            settings.
        :param dict,ScanDetection scan_detection: This represents the definition of Scan Detection
            on a NGFW.
        :raises CreateEngineFailed: Failure to create with reason
        :return: :py:class:`smc.core.engine.Engine`

        Example nodes parameter input::

            [{'address':'5.5.5.2',
              'network_value':'5.5.5.0/24',
              'nodeid':1},
             {'address':'5.5.5.3',
              'network_value':'5.5.5.0/24',
              'nodeid':2},
             {'address':'5.5.5.4',
              'network_value':'5.5.5.0/24',
              'nodeid':3}]
        """
        primary_mgt = primary_heartbeat = mgmt_interface

        interface = {
            "interface_id": mgmt_interface,
            "interfaces": [{"nodes": nodes, "reverse_connection": reverse_connection}],
            "macaddress": macaddress,
        }

        interface = Layer3PhysicalInterface(
            primary_mgt=primary_mgt, primary_heartbeat=primary_heartbeat, **interface
        )

        engine = super(MasterEngineCluster, cls)._create(
            name=name,
            node_type="master_node",
            physical_interfaces=[{"physical_interface": interface}],
            domain_server_address=domain_server_address,
            log_server_ref=log_server_ref,
            enable_gti=enable_gti,
            nodes=len(nodes),
            nodes_definition=nodes_definition,
            enable_antivirus=enable_antivirus,
            comment=comment,
            lldp_profile=lldp_profile,
            ssm_advanced_setting=ssm_advanced_setting,
            scan_detection=scan_detection,
            **extra_opts if extra_opts else {}
        )

        engine.update(master_type=master_type, cluster_mode=cluster_mode)

        try:
            return ElementCreator(cls, json=engine)

        except CreateElementFailed as e:
            raise CreateEngineFailed(e)


def add_snmp(data, interfaces):
    """
    Format data for adding SNMP to an engine.

    :param list data: list of interfaces as provided by kw
    :param list interfaces: interfaces to enable SNMP by id
    """
    snmp_interface = []
    if interfaces:  # Not providing interfaces will enable SNMP on all NDIs
        interfaces = map(str, interfaces)
        for interface in data:
            interface_id = str(interface.get("interface_id"))
            for if_def in interface.get("interfaces", []):
                _interface_id = None
                if "vlan_id" in if_def:
                    _interface_id = "{}.{}".format(interface_id, if_def["vlan_id"])
                else:
                    _interface_id = interface_id
                if _interface_id in interfaces and "type" not in interface:
                    for node in if_def.get("nodes", []):
                        snmp_interface.append(
                            {"address": node.get("address"), "nicid": _interface_id}
                        )
    return snmp_interface
