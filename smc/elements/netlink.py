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
NetLink elements are used to represent alternative routes that lead to the
same destination IP addresses.

NetLinks usually represent Internet connections, but can be used for other
communications links as well.

You can use a single Router if a single route is enough for routing traffic
to a network through an interface or an aggregated link. If you want to create
separate routes for traffic to a network through two or more interfaces, you
must use NetLinks.

To use traffic handlers, you must first create the netlink type required, then
add this to the engine routing node.

Creating a static netlink element::

    StaticNetlink.create(
        name='netlink',
        gateway=Router('routerfoo'),
        network=[Network('mynetwork')],
        domain_server_address=['8.8.8.8', '8.8.4.4'],
        probe_address=['1.1.1.254'],
        comment='foobar')

Add the netlink to the desired routing interface::

    engine = Engine('vm')
    rnode = engine.routing.get(0) #interface 0
    rnode.add_traffic_handler(
        netlink=StaticNetlink('mynetlink'),
        netlink_gw=[Router('myrtr')])

.. seealso:: :class:`smc.core.route.Routing.add_traffic_handler`

Creating Multilink's require that you first have StaticNetlink or DynamicNetlink
elements. Once you have this created, you can create a multilink in a two step
process.

First create the multilink members specifying the created netlinks. A multilink
member encapsulates the creation process and collects the required information for
each netlink such as ip_range to use for source NAT (static netlink only) and
the network role::

    member = MultilinkMember.create(
        StaticNetlink('netlink1'), ip_range='1.1.1.1-1.1.1.2', netlink_role='active')

    member1 = MultilinkMember.create(
        StaticNetlink('netlink2'), ip_range='2.1.1.1-2.1.1.2', netlink_role='standby')

Then create the multilink specifying the multilink members::

        Multilink.create(name='internet', multilink_members=[member, member1])

.. seealso:: :class:`~Multilink`
"""
from smc.base.model import Element, ElementCreator, ElementCache, ElementRef, ElementList
from smc.base.structs import NestedDict
from smc.vpn.elements import ConnectionType
from smc.base.util import element_resolver
from smc.core.general import RankedDNSAddress
from smc.compat import is_api_version_less_than_or_equal


class StaticNetlink(Element):
    """
    A Static Netlink is applied to an interface to provide an alternate
    route to a destination. It is typically used when you have fixed IP
    interfaces versus using DHCP (use a Dynamic NetLink).

    :ivar Router,Engine gateway: gateway for this netlink. Should be
        the 'next hop' element associated with the netlink
    :ivar list(Network) network: list of networks associated with this
        netlink
    :ivar int input_speed: input speed in Kbps, used for ratio-based
            load-balancing
    :ivar int output_speed: output speed in Kbps,  used for ratio-based
        load-balancing
    :ivar list probe_address: list of IP addresses to use as probing
        addresses to validate connectivity
    :ivar int standby_mode_period: Specifies the probe period when
        standby mode is used (in seconds)
    :ivar int standby_mode_timeout: probe timeout in seconds
    :ivar int active_mode_period: Specifies the probe period when active
        mode is used (in seconds)
    :ivar int active_mode_timeout: probe timeout in seconds
    """

    typeof = "netlink"
    gateway = ElementRef("gateway_ref")
    network = ElementList(("6.5", "ref"), ("6.6", "network_ref"))

    @classmethod
    def create(
        cls,
        name,
        gateway,
        network,
        connection_type=None,
        input_speed=None,
        output_speed=None,
        domain_server_address=None,
        provider_name=None,
        probe_address=None,
        standby_mode_period=3600,
        standby_mode_timeout=30,
        active_mode_period=5,
        active_mode_timeout=1,
        ipv4_outbound=None,
        ipv6_outbound=None,
        comment=None
    ):
        """
        Create a new StaticNetlink to be used as a traffic handler.

        :param str name: name of netlink Element
        :param gateway_ref: gateway to map this netlink to. This can be an element
            or str href.
        :type gateway_ref: Router,Engine
        :param connection_type: default QoS connection type. By default, we put Active.
        :type connection_type: ConnectionType,str
        :param list ref: network/s associated with this netlink.
        :type ref: list(str,Element)
        :param connection_type: the mandatory connection type from v6.5
        :param int input_speed: input speed in Kbps, used for ratio-based
            load-balancing
        :param int output_speed: output speed in Kbps,  used for ratio-based
            load-balancing
        :param list domain_server_address: dns addresses for netlink. Engine
            DNS can override this field
        :type dns_addresses: list(str,Element)
        :param str provider_name: optional name to identify provider for this
            netlink
        :param list probe_address: list of IP addresses to use as probing
            addresses to validate connectivity
        :type probe_ip_address: list(str)
        :param int standby_mode_period: Specifies the probe period when
            standby mode is used (in seconds)
        :param int standby_mode_timeout: probe timeout in seconds
        :param int active_mode_period: Specifies the probe period when active
            mode is used (in seconds)
        :param int active_mode_timeout: probe timeout in seconds
        :param str ipv4_outbound: The IP address that will be used to NAT the IPv4 outbound traffic.
            By default, it uses the CVI address defined in the routing view.
        :param str ipv6_outbound: The IP address that will be used to NAT the IPv6 outbound traffic.
            By default, it uses the CVI address defined in the routing view.
        :param str comment: Optional comment.
        :raises ElementNotFound: if using type Element parameters that are
            not found.
        :raises CreateElementFailed: failure to create netlink with reason
        :rtype: StaticNetlink

        .. note:: To monitor the status of the network links, you must define
                  at least one probe IP address.
        """
        json = {
            "name": name,
            "gateway_ref": element_resolver(gateway),
            "input_speed": input_speed,
            "output_speed": output_speed,
            "probe_address": probe_address,
            "nsp_name": provider_name,
            "comment": comment,
            "standby_mode_period": standby_mode_period,
            "standby_mode_timeout": standby_mode_timeout,
            "active_mode_period": active_mode_period,
            "active_mode_timeout": active_mode_timeout,
            "ipv4_outbound": ipv4_outbound,
            "ipv6_outbound": ipv6_outbound
        }

        if is_api_version_less_than_or_equal("6.5"):
            json.update(ref=element_resolver(network))
        else:
            json.update(network_ref=element_resolver(network))

        # connection_type_ref available since
        # SMC6.8 api>=6.8
        if not is_api_version_less_than_or_equal("6.7"):
            if not connection_type:
                # by default, Active is used
                json.update(connection_type_ref=element_resolver(ConnectionType("Active")))
            else:
                json.update(connection_type_ref=element_resolver(connection_type))

        if domain_server_address:
            r = RankedDNSAddress([])
            r.add(domain_server_address)
            json.update(domain_server_address=r.entries)

        return ElementCreator(cls, json)

    @classmethod
    def update_or_create(cls, with_status=False, **kwargs):
        """
        Update or create static netlink. DNS entry differences are not
        resolved, instead any entries provided will be the final state
        for this netlink. If the intent is to add/remove DNS entries
        you can use the :meth:`~domain_server_address` method to add
        or remove.

        :raises CreateElementFailed: failed creating element
        :return: element instance by type or 3-tuple if with_status set
        """
        dns_address = kwargs.pop("domain_server_address", [])
        element, updated, created = super(StaticNetlink, cls).update_or_create(
            with_status=True, defer_update=True, **kwargs
        )
        if not created:
            if dns_address:
                new_entries = RankedDNSAddress([])
                new_entries.add(dns_address)
                element.data.update(domain_server_address=new_entries.entries)
                updated = True
        if updated:
            element.update()
        if with_status:
            return element, updated, created
        return element

    @property
    def domain_server_address(self):
        """
        Configured DNS servers for this netlink

        :return: list of DNS servers; if elements are specifed, they will
            be returned as type Element
        :rtype: RankedDNSAddress
        """
        return RankedDNSAddress(self.data.get("domain_server_address"))

    @property
    def networks(self):
        return self.network


class DynamicNetlink(Element):
    """
    A Dynamic Netlink is automatically created when an interface is using
    DHCP to obtain it's network address. It is also possible to manually
    create a dynamic netlink.

    :ivar int input_speed: input speed in Kbps, used for ratio-based
            load-balancing
    :ivar int output_speed: output speed in Kbps,  used for ratio-based
        load-balancing
    :ivar list probe_address: list of IP addresses to use as probing
        addresses to validate connectivity
    :ivar int standby_mode_period: Specifies the probe period when
        standby mode is used (in seconds)
    :ivar int standby_mode_timeout: probe timeout in seconds
    :ivar int active_mode_period: Specifies the probe period when active
        mode is used (in seconds)
    :ivar int active_mode_timeout: probe timeout in seconds
    :ivar bool learn_dns_automatically: whether to obtain the DNS server
        address from the DHCP lease
    """

    typeof = "dynamic_netlink"

    @classmethod
    def create(
        cls,
        name,
        connection_type=None,
        input_speed=None,
        learn_dns_automatically=True,
        output_speed=None,
        provider_name=None,
        probe_address=None,
        standby_mode_period=3600,
        standby_mode_timeout=30,
        active_mode_period=5,
        active_mode_timeout=1,
        comment=None,
    ):
        """
        Create a Dynamic Netlink.

        :param str name: name of netlink Element
        :param connection_type: default QoS connection type. By default, we put Active.
        :param int input_speed: input speed in Kbps, used for ratio-based
            load-balancing
        :param int output_speed: output speed in Kbps,  used for ratio-based
            load-balancing
        :param bool learn_dns_automatically: whether to obtain DNS automatically
            from the DHCP interface
        :param str provider_name: optional name to identify provider for this
            netlink
        :param list probe_address: list of IP addresses to use as probing
            addresses to validate connectivity
        :type probe_ip_address: list(str)
        :param int standby_mode_period: Specifies the probe period when
            standby mode is used (in seconds)
        :param int standby_mode_timeout: probe timeout in seconds
        :param int active_mode_period: Specifies the probe period when active
            mode is used (in seconds)
        :param int active_mode_timeout: probe timeout in seconds
        :raises CreateElementFailed: failure to create netlink with reason
        :rtype: DynamicNetlink

        .. note:: To monitor the status of the network links, you must define
                  at least one probe IP address.
        """
        json = {
            "name": name,
            "input_speed": input_speed,
            "output_speed": output_speed,
            "probe_address": probe_address,
            "nsp_name": provider_name,
            "comment": comment,
            "standby_mode_period": standby_mode_period,
            "standby_mode_timeout": standby_mode_timeout,
            "active_mode_period": active_mode_period,
            "active_mode_timeout": active_mode_timeout,
            "learn_dns_server_automatically": learn_dns_automatically,
        }
        # connection_type_ref available since
        # SMC6.8 api>=6.8
        if not is_api_version_less_than_or_equal("6.7"):
            if not connection_type:
                # by default, Active is used
                json.update(connection_type_ref=element_resolver(ConnectionType("Active")))
            else:
                json.update(connection_type_ref=element_resolver(connection_type))

        return ElementCreator(cls, json)


class Multilink(Element):
    """
    You can use Multi-Link to distribute outbound traffic between multiple
    network connections and to provide High Availability and load balancing
    for outbound traffic.

    Creating a multilink requires several steps:

    * Create the static netlink/s
    * Create the multilink using the netlinks
    * Add the multilink to an outbound NAT rule

    Create the static netlink::

        StaticNetlink.create(
            name='isp1',
            gateway=Router('nexthop'),     # 10.10.0.1
            network=[Network('comcast')],  # 10.10.0.0/16
            probe_address=['10.10.0.1'])

    Create the multilink members based on the pre-created netlinks. A multilink
    member specifies the ip range to use for source NAT, the role (active/standby)
    and obtains the defined network from the StaticNetlink::

        member = MultilinkMember.create(
            StaticNetlink('netlink1'), ip_range='1.1.1.1-1.1.1.2', netlink_role='active')

        member1 = MultilinkMember.create(
            StaticNetlink('netlink2'), ip_range='2.1.1.1-2.1.1.2', netlink_role='standby')

    Create the multilink using the multilink members::

        Multilink.create(name='internet', multilink_members=[member, member1])

    Lastly, add a NAT rule with dynamic source nat using the multilink::

        policy = FirewallPolicy('outbound')
        policy.fw_ipv4_nat_rules.create(
            name='mynat',
            sources=[Network('mynetwork')],
            destinations='any',
            services='any',
            dynamic_src_nat=Multilink('internet'))

    .. note:: Multi-Link is supported on Single Firewalls, Firewall Clusters,
        and Virtual Firewalls
    """

    typeof = "outbound_multilink"

    @classmethod
    def create(
        cls, name, multilink_members, multilink_method="rtt", retries=2, timeout=3600, comment=None
    ):
        """
        Create a new multilink configuration. Multilink requires at least
        one netlink for operation, although 2 or more are recommeneded.

        :param str name: name of multilink
        :param list multilink_members: the output of calling
            :func:`.multilink_member` to retrieve the proper formatting for
            this sub element.
        :param str multilink_method: 'rtt' or 'ratio'. If ratio is used, each
            netlink must have a probe IP address configured and also have
            input and output speed configured (default: 'rtt')
        :param int retries: number of keep alive retries before a destination
            link is considered unavailable (default: 2)
        :param int timeout: timeout between retries (default: 3600 seconds)
        :param str comment: comment for multilink (optional)
        :raises CreateElementFailed: failure to create multilink
        :rtype: Multilink
        """
        json = {
            "name": name,
            "comment": comment,
            "retries": retries,
            "timeout": timeout,
            "multilink_member": multilink_members,
            "multilink_method": multilink_method,
        }

        return ElementCreator(cls, json)

    @classmethod
    def create_with_netlinks(cls, name, netlinks, **kwargs):
        """
        Create a multilink with a list of StaticNetlinks. To properly create
        the multilink using this method, pass a list of netlinks with the
        following dict structure::

            netlinks = [{'netlink': StaticNetlink,
                         'ip_range': 1.1.1.1-1.1.1.2,
                         'netlink_role': 'active'}]

        The `netlink_role` can be either `active` or `standby`. The remaining
        settings are resolved from the StaticNetlink. The IP range value must
        be an IP range within the StaticNetlink's specified network.
        Use kwargs to pass any additional arguments that are supported by the
        `create` constructor.
        A full example of creating a multilink using predefined netlinks::

            multilink = Multilink.create_with_netlinks(
                name='mynewnetlink',
                netlinks=[{'netlink': StaticNetlink('netlink1'),
                           'ip_range': '1.1.1.2-1.1.1.3',
                           'netlink_role': 'active'},
                          {'netlink': StaticNetlink('netlink2'),
                           'ip_range': '2.1.1.2-2.1.1.3',
                           'netlink_role': 'standby'}])

        :param StaticNetlink,DynamicNetlink netlink: StaticNetlink element
        :param str ip_range: ip range for source NAT on this netlink
        :param str netlink_role: the role for this netlink, `active` or
            `standby`
        :raises CreateElementFailed: failure to create multilink
        :rtype: Multilink
        """
        multilink_members = []
        for member in netlinks:
            m = {
                "ip_range": member.get("ip_range", "0.0.0.0"),
                "netlink_role": member.get("netlink_role", "active"),
            }
            netlink = member.get("netlink")
            m.update(netlink_ref=netlink.href)
            if netlink.typeof == "netlink":
                if is_api_version_less_than_or_equal("6.5"):
                    m.update(network_ref=netlink.data.get("ref")[0])
                else:
                    m.update(network_ref=netlink.data.get("network_ref")[0])
            multilink_members.append(m)

        return cls.create(name, multilink_members, **kwargs)

    @classmethod
    def update_or_create(cls, with_status=False, **kwargs):
        element, updated, created = super(Multilink, cls).update_or_create(
            with_status=True, defer_update=True, **kwargs
        )
        if not created:
            multilink_members = kwargs.pop("multilink_members", [])
            if multilink_members:
                if set(multilink_members) ^ set(element.members):
                    element.data["multilink_member"] = multilink_members
                    updated = True
        if updated:
            element.update()
        if with_status:
            return element, updated, created
        return element

    @property
    def members(self):
        """
        Multilink members associated with this multilink. This provides a
        a reference to the existing netlinks and their member settings.

        :rtype: MultilinkMember
        """
        return [MultilinkMember(mm) for mm in self.multilink_member]


class MultilinkMember(object):
    """
    A multilink member represents an netlink member used on a multilink
    configuration. Multilink uses netlinks to specify settings specific
    to a connection, network, whether it should be active or standby and
    optionally QoS.
    Use this class to create mutlilink members that are required for
    creating a Multilink element.

    :ivar Network network: network element reference specifying netlink subnet
    :ivar StaticNetlink,DynamicNetlink netlink: netlink element reference
    """

    network = ElementRef("network_ref")
    netlink = ElementRef("netlink_ref")

    def __init__(self, kwargs):
        self.data = ElementCache(kwargs)

    def __eq__(self, other):
        return all(
            [
                self.ip_range == other.ip_range,
                self.netlink_role == other.netlink_role,
                self.data.get("network_ref") == other.data.get("network_ref"),
                self.data.get("netlink_ref") == other.data.get("netlink_ref"),
            ]
        )

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash(
            (
                self.ip_range,
                self.netlink_role,
                self.data.get("network_ref"),
                self.data.get("netlink_ref"),
            )
        )

    @property
    def ip_range(self):
        """
        Specifies the IP address range for dynamic source address
        translation (NAT) for the internal source IP addresses on the
        NetLink. Can also be set.

        :rtype: str
        """
        return self.data.get("ip_range")

    @ip_range.setter
    def ip_range(self, value):
        if "-" in value:
            self.data.update(ip_range=value)

    @property
    def netlink_role(self):
        """
        Shows whether the Netlink is active or standby.
        Active - traffic is routed through the NetLink according to the
        method you specify in the Outbound Multi-Link element properties.
        Standby - traffic is only routed through the netlink if all primary
        (active) netlinks are unavailable.

        :rtype: str
        """
        return self.data.get("netlink_role")

    @netlink_role.setter
    def netlink_role(self, value):
        if value in ("standby", "active"):
            self.data.update(netlink_role=value)

    @classmethod
    def create(cls, netlink, ip_range=None, netlink_role="active"):
        """
        Create a multilink member. Multilink members are added to an
        Outbound Multilink configuration and define the ip range, static
        netlink to use, and the role. This element can be passed to the
        Multilink constructor to simplify creation of the outbound multilink.

        :param StaticNetlink,DynamicNetlink netlink: static netlink element to
            use as member
        :param str ip_range: the IP range for source NAT for this member. The
            IP range should be part of the defined network range used by this
            netlink. Not required for dynamic netlink
        :param str netlink_role: role of this netlink, 'active' or 'standby'
        :raises ElementNotFound: Specified netlink could not be found
        :rtype: MultilinkMember
        """
        member_def = dict(
            netlink_ref=netlink.href,
            netlink_role=netlink_role,
            ip_range=ip_range if netlink.typeof == "netlink" else "0.0.0.0",
        )
        if netlink.typeof == "netlink":  # static netlink vs dynamic netlink
            member_def.update(network_ref=netlink.network[0].href)

        return cls(member_def)

    def __repr__(self):
        return "MultilinkMember(netlink={},netlink_role={},ip_range={})".format(
            self.netlink, self.netlink_role, self.ip_range
        )


class LinkType(Element):
    """
    This represents the Link Type.
    """
    typeof = "link_type"

    @classmethod
    def create(cls, name, comment=None):
        """
        Create a new Link Type.

        :param str name: name of link type
        :param str comment: comment for link type
        :raises CreateElementFailed: failed to create link type
        :rtype: LinkType
        """
        json = {"name": name, "comment": comment}
        return ElementCreator(cls, json)


class IpNetLinkWeight(NestedDict):
    """
    Clients make their incoming connections to the address of the Server Pool. The Firewall then
    decides which server is going to handle the connection and translates (in a NAT operation) the
    public address to the private IP address of that server. The external address or addresses of
    the Server Pool are defined as properties of the Server Pool element.
    """

    def __init__(self, data):
        super(IpNetLinkWeight, self).__init__(data=data)

    @classmethod
    def create(cls, arp_generate=True, ipaddress=None, netlink=None, network=None,
               status=True):
        """
        :param bool arp_generate: Automatically generate a proxy ARP for the NATed address in the
            selected Network. Otherwise, must be defined in  the ARP entry manually in the Firewall
            element properties.Not Required, Default is true.
        :param str ipaddress: Defines the external NATed destination IP Address for the Server Pool:
            A valid IPv4 or IPv6 address. This is the address client machines contact when accessing
            the service that the server(s) in the Server Pool offer. Required
        :param StaticNetlink netlink: NetLink to use. To configure load sharing for the servers
            but no traffic balancing between NetLinks, select Not Specified (netlink/0). Required
        :param Network network: Network element that is used for the Server Pool’s external
            NATed address. Required
        :param bool status: Weight of this Net Link in the pool. Set the weight to false to disable
            the net link. Not Required, Default is true.
        :rtype: IpNetLinkWeight
        """

        json = {
            "arp_generate": arp_generate,
            "ipaddress": ipaddress,
            "netlink_ref": element_resolver(netlink),
            "weight": 1 if status else 0
        }
        if not network:
            json.update(network_ref=netlink.data.get("network_ref")[0])
        else:
            json.update(network_ref=element_resolver(network))
        return cls(json)

    @property
    def arp_generate(self):
        """
        Automatically generate a proxy ARP for the NATed address in the selected Network.
        :rtype: bool
        """
        return self.data.get("arp_generate")

    @property
    def ipaddress(self):
        """
        External NATed destination IP Address for the Server Pool
        :rtype: str
        """
        return self.data.get("ipaddress")

    @property
    def netlink_ref(self):
        """
        NetLink to use.
        :rtype: StaticNetlink
        """
        return Element.from_href(self.data.get("netlink_ref"))

    @property
    def weight(self):
        """
        Weight of this Net Link in the pool.
        :rtype: int
        """
        return self.data.get("weight")

    @property
    def network_ref(self):
        """
        Network element that is used for the Server Pool’s external NATed address
        :rtype: list(Network)
        """
        return [Element.from_href(network) for network in self.data.get("network_ref")]


class ServerPoolMember(NestedDict):
    """
    Host element for the internal IP address of each member of the Server Pool. The Firewall uses
    these addresses to select which server handles which traffic that arrives to the Server Pool’s
    external address. The Server Pool can have any number of members. You can also create a
    one-server Server Pool to enable DDNS updates for a single server when ISP links go down if the
    server does not need the other Server Pool features.
    """

    @classmethod
    def create(cls, member_rank=None, member=None):
        """
        :param int member_rank: Order of the network element in the list: -1 means no order.
            Not Required
        :param NetworkElement member: Existing Server element (for servers that have some special
            role in the SMC configuration) or Host element (for other servers). Required
        :rtype: ServerPoolMember
        """
        json = {
            "member_rank": member_rank,
            "member": element_resolver(member)
        }
        return cls(json)


class ServerPool(Element):
    """
    This represents a Server Pool. A Network Element representing a group of Servers. Used for
    inbound traffic management. Clients make their incoming connections to the address of the Server
    Pool. The Firewall then decides which server is going to handle the connection and translates
    (in a NAT operation) the public address to the private IP address of that server. The external
    address or addresses of the Server Pool are defined as properties of the Server Pool element.
    """
    typeof = "server_pool"

    @classmethod
    def create(cls, name=None, ip_netlink_weight=None, members_list=None, monitoring_frequency=10,
               monitoring_mode="ping", monitoring_port=0, server_allocation="host",
               monitoring_request=None, monitoring_response=None, monitoring_url=None,
               monitoring_host=None, dns_server=None, domain_name=None, comment=None):
        """

        :param str name: The name of server pool.
        :param list(IpNetLinkWeight) ip_netlink_weight: Clients make their incoming connections
            to the address of the Server Pool.
        :param list(ServerPoolMember) members_list: List of Members.
        :param int monitoring_frequency: How often the availability will checked (seconds). Integer
            between 0 and 65535 seconds. Required
        :param str monitoring_mode: Monitoring Method for monitoring the availability of the servers
            in the Server Pool. Required
            The available monitoring mode given below:
            1. ping: Uses ICMP echo request (ping) messages to monitor the availability of the
                servers.
            2. agent: Uses the Server Pool Monitoring Agent feature. Before enabling this method,
                make sure you have installed and configured the Monitoring Agents on all the servers
                See Installing Monitoring Agents. For instructions on how to configure this feature,
                see Enabling Monitoring Agents.
            3. tcp: Checks that a specific TCP service is available.
            4. http: Checks that the HTTP service is available.
        :param int monitoring_port: Define the port number (0 to 65535). Not Required
        :param str server_allocation: Select the granularity for the server selection (defines how
            likely it is that traffic is redirected to a particular server). Usually it is best to
            choose the least granular option that still produces an acceptable distribution of
            traffic.
            The options are (from least granular to most granular):
                1. order: Allocate traffic by order of priority, when a member is not available the
                    next one in the list is chosen.
                2. network: directs traffic coming from the same C-class network to the same server.
                    This is a good choice when connections come from many different networks.
                3. host: directs traffic coming from the same IP address to the same server. This is
                    a good choice when a large portion of connections come from different hosts in
                    the same C-class network.
                4. connection: makes a new traffic management decision for each new connection. This
                    choice may be necessary if a large portion of connections uses just one IP
                    address.
                5. notdefined: has the same effect as the Source Network option.
        :param str monitoring_request: String of text that to be sent. Not Required
        :param str monitoring_response: String of text that expected to receive.
            In HTTP mode: the text can be returned from the HTTP protocol headers or the actual
            content of the web page.
        :param str monitoring_url: Define the path to the web page.
        :param str monitoring_host: Define the host name of the web server.
        :param DNSServer dns_server: DNSServer
            Firewalls support the Dynamic DNS protocol and can send DDNS updates to a specified DNS
            server. If a network connection specified by a NetLink element fails, the dynamic DNS
            updates notify the DNS, which then removes the corresponding IP address from its records
        :param str domain_name: Fully Qualified Domain Name.
        :param str comment: Optional comment.
        :rtype: ServerPool
        """

        json = {
            "name": name,
            "ip_netlink_weight": [ip_netlink.data for ip_netlink in ip_netlink_weight],
            "members_list": [member.data for member in members_list],
            "monitoring_frequency": monitoring_frequency,
            "monitoring_mode": monitoring_mode,
            "monitoring_port": monitoring_port,
            "server_allocation": server_allocation,
            "comment": comment,
        }
        if monitoring_request or monitoring_response or monitoring_url or monitoring_host:
            json.update(monitoring_request=monitoring_request,
                        monitoring_response=monitoring_response, monitoring_url=monitoring_url,
                        monitoring_host=monitoring_host)
        if dns_server:
            json.update(dns_server=element_resolver(dns_server), domain_name=domain_name)

        return ElementCreator(cls, json)

    @property
    def ip_netlink_weight(self):
        """
        The address of the Server Pool
        :rtype: list(IpNetLinkWeight)
        """
        return [IpNetLinkWeight(netlink) for netlink in self.data.get("ip_netlink_weight")]
