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
Module providing service configuration and creation.

Some services may be generic services while others might provide more
in depth functionality using protocol agents. A protocol agent provides
layer 7 configuration capabilities specific to the protocol it defines.
If a given service inherits the ProtocolAgentMixin, this service type is
eligible to have a protocol agent attached.

.. seealso:: :py:mod:`smc.elements.protocols`

"""
from smc.base.model import Element, ElementCreator
from smc.base.structs import NestedDict
from smc.elements.protocols import ProtocolAgentMixin
from smc.base.util import element_resolver


class TCPService(ProtocolAgentMixin, Element):
    """
    Represents a TCP based service in SMC
    TCP Service can use a range of ports or single port. If using
    single port, set only min_dst_port. If using range, set both
    min_dst_port and max_dst_port.

    Create a TCP Service for port 5000::

        >>> TCPService.create('tcpservice', 5000, comment='my service')
        TCPService(name=tcpservice)

    Available attributes:

    :ivar int min_dst_port: starting destination port for this service. If the
        service is a single port service, use only this field
    :ivar int max_dst_port: used in conjunction with min_dst_port for creating a
        port range service.
    """

    typeof = "tcp_service"

    @classmethod
    def create(
        cls,
        name,
        min_dst_port,
        max_dst_port=None,
        min_src_port=None,
        max_src_port=None,
        protocol_agent=None,
        comment=None,
    ):
        """
        Create the TCP service

        :param str name: name of tcp service
        :param int min_dst_port: minimum destination port value
        :param int max_dst_port: maximum destination port value
        :param int min_src_port: minimum source port value
        :param int max_src_port: maximum source port value
        :param str,ProtocolAgent protocol_agent: optional protocol agent for
            this service
        :param str comment: optional comment for service
        :raises CreateElementFailed: failure creating element with reason
        :return: instance with meta
        :rtype: TCPService
        """
        max_dst_port = max_dst_port if max_dst_port is not None else ""
        json = {
            "name": name,
            "min_dst_port": min_dst_port,
            "max_dst_port": max_dst_port,
            "min_src_port": min_src_port,
            "max_src_port": max_src_port,
            "protocol_agent_ref": element_resolver(protocol_agent) or None,
            "comment": comment,
        }

        return ElementCreator(cls, json)


class UDPService(ProtocolAgentMixin, Element):
    """
    UDP Services can use a range of ports or single port. If using
    single port, set only min_dst_port. If using range, set both
    min_dst_port and max_dst_port.

    Create a UDP Service for port range 5000-5005::

        >>> UDPService.create('udpservice', 5000, 5005)
        UDPService(name=udpservice)

    Available attributes:

    :ivar int min_dst_port: starting destination port for this service. If the
        service is a single port service, use only this field
    :ivar int max_dst_port: used in conjunction with min_dst_port for creating a
        port range service
    """

    typeof = "udp_service"

    @classmethod
    def create(
        cls,
        name,
        min_dst_port,
        max_dst_port=None,
        min_src_port=None,
        max_src_port=None,
        protocol_agent=None,
        comment=None,
    ):
        """
        Create the UDP Service

        :param str name: name of udp service
        :param int min_dst_port: minimum destination port value
        :param int max_dst_port: maximum destination port value
        :param int min_src_port: minimum source port value
        :param int max_src_port: maximum source port value
        :param str,ProtocolAgent protocol_agent: optional protocol agent for
            this service
        :param str comment: optional comment
        :raises CreateElementFailed: failure creating element with reason
        :return: instance with meta
        :rtype: UDPService
        """
        max_dst_port = max_dst_port if max_dst_port is not None else ""
        json = {
            "name": name,
            "min_dst_port": min_dst_port,
            "max_dst_port": max_dst_port,
            "min_src_port": min_src_port,
            "max_src_port": max_src_port,
            "protocol_agent_ref": element_resolver(protocol_agent) or None,
            "comment": comment,
        }

        return ElementCreator(cls, json)


class IPService(ProtocolAgentMixin, Element):
    """
    Represents an IP-Proto service in SMC
    IP Service is represented by a protocol number. This will display
    in the SMC under Services -> IP-Proto. It may also show up in
    Services -> With Protocol if the protocol is tied to a Protocol Agent.

    Create an IP Service for protocol 93 (AX.25)::

        >>> IPService.create('ipservice', 93)
        IPService(name=ipservice)

    Available attributes:

    :ivar str protocol_number: IP protocol number for this service
    """

    typeof = "ip_service"

    @classmethod
    def create(cls, name, protocol_number, protocol_agent=None, comment=None):
        """
        Create the IP Service

        :param str name: name of ip-service
        :param int protocol_number: ip proto number for this service
        :param str,ProtocolAgent protocol_agent: optional protocol agent for
            this service
        :param str comment: optional comment
        :raises CreateElementFailed: failure creating element with reason
        :return: instance with meta
        :rtype: IPService
        """
        json = {
            "name": name,
            "protocol_number": protocol_number,
            "protocol_agent_ref": element_resolver(protocol_agent) or None,
            "comment": comment,
        }

        return ElementCreator(cls, json)

    @property
    def protocol_number(self):
        """
        Protocol number for this IP Service

        :rtype: int
        """
        return int(self.data.get("protocol_number"))


class EthernetService(Element):
    """
    Represents an ethernet based service in SMC
    Ethernet service only supports adding Ethernet II frame type.

    The value1 field should be the ethernet2 ethertype hex code
    which will be converted to decimal format.

    Create an ethernet rule representing the presence of an IEEE
    802.1Q tag::

        >>> EthernetService.create(name='8021q frame', value1='0x8100')
        EthernetService(name=8021q frame)

    .. note:: Ethernet Services are only available as of SMC version 6.1.2

    """

    typeof = "ethernet_service"

    @classmethod
    def create(cls, name, frame_type="eth2", value1=None, value2=None, protocol_agent_ref=None,
               comment=None):
        """
        Create an ethernet service

        :param str name: name of service
        :param str frame_type: ethernet frame type, eth2
        :param str value1: hex code representing ethertype field
        :param str value2: Following the frame_type value: For llc: the DSAP (destination service
            access point) address that the traffic uses. For snap: the type that the traffic uses.
        :param ProtocolAgent protocol_agent_ref: The possible Protocol linked to this service.
        :param str comment: optional comment
        :raises CreateElementFailed: failure creating element with reason
        :return: instance with meta
        :rtype: EthernetService
        """
        json = {
            "frame_type": frame_type,
            "name": name,
            "value1": int(value1, 16),
            "value2": int(value2, 16),
            "protocol_agent_ref": element_resolver(protocol_agent_ref),
            "comment": comment,
        }

        return ElementCreator(cls, json)

    @property
    def value1(self):
        if "value1" in self.data:
            return hex(int(self.data.get("value1")))

    @value1.setter
    def value1(self, value):
        if "value1" in self.data:
            self.data["value1"] = int(value, 16)

    @property
    def value2(self):
        if "value2" in self.data:
            return hex(int(self.data.get("value2")))

    @value2.setter
    def value2(self, value):
        if "value2" in self.data:
            self.data["value2"] = int(value, 16)

    @property
    def protocol_agent_ref(self):
        """
        The possible Protocol linked to this service.
        :rtype: ProtocolAgent
        """
        return Element.from_href(self.data.get("protocol_agent_ref"))


class RPCService(Element):
    """
    Represents an RPC service element
    """

    typeof = "rpc_service"

    @classmethod
    def create(cls, name, program_number=None, transport=None, rpc_version=None, comment=None):
        """
        This represents a SUN-RPC service.
        :param str name: name of rpc service.
        :param str program_number: The programe number. Not Required.
        :param str transport: The transport type:
                        tcp: Allows the RPC message when transported over TCP.
                        udp: Allows the RPC message when transported over UDP.
                        both: Allows the RPC message when transported over TCP and UDP.
        :param str rpc_version: The remote program version number. If you do not enter
            a program version, the element matches traffic of any version.
        :param str comment: optional comment.
        :rtype RPCService.
        """
        json = {"name": name, "program_number": program_number, "transport": transport,
                "rpc_version": rpc_version, "comment": comment}

        return ElementCreator(cls, json)

    @property
    def rpc_version(self):
        """
        The remote program version number
        :rtype str
        """
        return self.data.get("rpc_version")

    @property
    def transport(self):
        """
        The transport type.
        :rtype str
        """
        return self.data.get("transport")

    @property
    def program_number(self):
        """
        The programe number.
        :rtype str
        """
        return self.data.get("program_number")


class ICMPServiceMixin:
    """
    Represents ICMPService and ICMPIPv6Service common operation.
    """

    @property
    def icmp_type(self):
        """
        The ICMP type number.
        :rtype int
        """
        return self.data.get("icmp_type")

    @property
    def icmp_code(self):
        """
        The ICMP code number.
        :rtype int
        """
        return self.data.get("icmp_code")


class ICMPService(Element, ICMPServiceMixin):
    """
    Represents an ICMP Service in SMC
    Use the RFC icmp type and code fields to set values. ICMP
    type is required, icmp code is optional but will make the service
    more specific if type codes exist.

    Create an ICMP service using type 3, code 7 (Dest. Unreachable)::

        >>> ICMPService.create(name='api-icmp', icmp_type=3, icmp_code=7)
        ICMPService(name=api-icmp)

    Available attributes:

    :ivar int icmp_type: icmp type field
    :ivar int icmp_code: icmp type code
    """

    typeof = "icmp_service"

    @classmethod
    def create(cls, name, icmp_type, icmp_code=None, comment=None):
        """
        Create the ICMP service element

        :param str name: name of service
        :param int icmp_type: icmp type field
        :param int icmp_code: icmp type code
        :param str comment: optional comment.
        :raises CreateElementFailed: failure creating element with reason
        :return: instance with meta
        :rtype: ICMPService
        """
        icmp_code = icmp_code if icmp_code else ""
        json = {"name": name, "icmp_type": icmp_type, "icmp_code": icmp_code, "comment": comment}

        return ElementCreator(cls, json)


class ICMPIPv6Service(Element, ICMPServiceMixin):
    """
    Represents an ICMPv6 Service type in SMC
    Set the icmp type field at minimum. At time of writing the
    icmp code fields were all 0.

    Create an ICMPv6 service for Neighbor Advertisement Message::

        >>> ICMPIPv6Service.create('api-Neighbor Advertisement Message', icmp_type=4, icmp_code=8)
        ICMPIPv6Service(name=api-Neighbor Advertisement Message)

    Available attributes:

    :ivar int icmp_type: ipv6 icmp type field
    :ivar int icmp_code: icmpv6 type code
    """

    typeof = "icmp_ipv6_service"

    @classmethod
    def create(cls, name, icmp_type, icmp_code=None, comment=None):
        """
        Create the ICMPIPv6 service element

        :param str name: name of service
        :param int icmp_type: ipv6 icmp type field
        :param int icmp_code: icmp type code
        :param str comment: optional comment.
        :raises CreateElementFailed: failure creating element with reason
        :return: instance with meta
        :rtype: ICMPIPv6Service
        """
        json = {"name": name, "icmp_type": icmp_type, "icmp_code": icmp_code, "comment": comment}

        return ElementCreator(cls, json)


class ApplicationSituation(Element):
    """
    Application Situations are network applications used as rule service
    parameters in policies. Applications examples are 'facebook chat',
    'facebook plugins', etc. These transcend the layer 7 protocol being
    used (most commonly port 80 and 443) and instead provide visibility
    into the application itself.
    """

    typeof = "application_situation"


class URLCategory(Element):
    """
    Represents a URL Category for policy. URL Categories are read only.
    To make whitelist or blacklists, use :class:`smc.elements.network.IPList`.
    """

    typeof = "url_category"


class IntegratedUisIgnoreValue(NestedDict):
    """
    This represents an entry in the Integrated User ID service's ignore list.
    """

    @classmethod
    def create(cls, iuis_ignore_user=None, iuis_ignore_ip=None, ne_ref=None):
        """
        :param str iuis_ignore_user: The ignore username.  Omit for 'Any'.
        :param str iuis_ignore_ip: The ignore ip address, subnet or range.  Omit for 'Any'.
            Not allowed with ne_ref.
        :param AddressRange/Host/Network ne_ref: The ignore network element which should be Host,
            Range or Network type. Omit for 'Any'. Not allowed with iuis_ignore_ip.
        :rtype: instance of IntegratedUisIgnoreValue.
        """

        json = {"iuis_ignore_user": iuis_ignore_user}
        if iuis_ignore_ip:
            json.update(iuis_ignore_ip=iuis_ignore_ip)
        if ne_ref:
            json.update(ne_ref=element_resolver(ne_ref))

        return cls(json)


class IntegratedUserIdService(Element):
    """
    This represents an Integrated User Identification Service.
    """
    typeof = "integrated_uis"

    @classmethod
    def create(cls, name, iuis_domain=None, iuis_ignore=None, iuis_initial_query_time=None,
               iuis_polling_interval=None, comment=None):
        """
        Create the IntegratedUserIdService service.

        :param str name: name of service
        :param ExternalLdapUserDomain iuis_domain: The active directory domain object.
        :param list(IntegratedUisIgnoreValue) iuis_ignore: The list of ignore entries.
        :param int iuis_initial_query_time: The initial query time in seconds.
        :param int iuis_polling_interval: The polling interval in seconds.
        :param str comment: Optional comment.
        :raises CreateElementFailed: failure creating element with reason
        :return: instance with meta
        :rtype: IntegratedUserIdService
        """
        iuis_ignore = iuis_ignore if iuis_ignore else []
        json = {"name": name, "iuis_domain": element_resolver(iuis_domain),
                "iuis_ignore": [ignore.data for ignore in iuis_ignore],
                "iuis_initial_query_time": iuis_initial_query_time,
                "iuis_polling_interval": iuis_polling_interval,
                "comment": comment}

        return ElementCreator(cls, json)

    @property
    def iuis_initial_query_time(self):
        """
        The initial query time in seconds.
        :rtype: int
        """
        return self.data.get("iuis_initial_query_time")

    @property
    def iuis_polling_interval(self):
        """
        The polling interval in seconds.
        :rtype: int
        """
        return self.data.get("iuis_polling_interval")

    @property
    def iuis_ignore(self):
        """
        The list of ignore entries.
        :rtype: list(IntegratedUisIgnoreValue)
        """
        return [IntegratedUisIgnoreValue(value) for value in self.data.get("iuis_ignore")]

    @property
    def iuis_domain(self):
        """
        The active directory domain object.
        :rtype: ExternalLdapUserDomain
        """
        return Element.from_href(self.data.get("iuis_domain"))
