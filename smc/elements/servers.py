"""
Module that represents server based configurations
"""
from smc.base.model import SubElement, ElementCreator, Element, ElementRef
from smc.base.structs import NestedDict
from smc.elements.helpers import location_helper
from smc.elements.other import ContactAddress, Location
from smc.api.exceptions import CreateElementFailed
from smc.base.util import element_resolver
from smc.administration.certificates import tls


class MultiContactAddress(SubElement):
    """
    A MultiContactAddress is a location and contact address pair which
    can have multiple addresses. Server elements such as Management
    and Log Server can have configured locations with mutliple addresses
    per location.

    Use this server reference to create, add or remove contact addresses
    from servers::

        mgt_server = ManagementServer.objects.first()
        mgt_server.contact_addresses.update_or_create(
            location='mylocation', addresses=['1.1.1.1', '1.1.1.2'])

    Or remove by location::

        mgt_server.contact_addresses.delete('mylocation')

    """

    @property
    def _cas(self):
        return self.data.get("multi_contact_addresses", []) or self.data.get(
            "contact_addresses", []
        )

    def __iter__(self):
        for address in self._cas:
            yield ContactAddress(**address)

    def __contains__(self, location_href):
        for location in self._cas:
            if location.get("location_ref") == location_href:
                return True
        return False

    def get(self, location_name):
        """
        Get a contact address by location name

        :param str location_name: name of location
        :return: return contact address element or None
        :rtype: ContactAddress
        """
        location_ref = location_helper(location_name, search_only=True)
        if location_ref:
            for location in self:
                if location.location_ref == location_ref:
                    return location

    def delete(self, location_name):
        """
        Remove a given location by location name. This operation is
        performed only if the given location is valid, and if so,
        `update` is called automatically.

        :param str location: location name or location ref
        :raises UpdateElementFailed: failed to update element with reason
        :rtype: bool
        """
        updated = False
        location_ref = location_helper(location_name, search_only=True)
        if location_ref in self:
            self._cas[:] = [loc for loc in self if loc.location_ref != location_ref]
            self.update()
            updated = True
        return updated

    def update_or_create(
        self, location, contact_addresses, with_status=False, overwrite_existing=False, **kw
    ):
        """
        Update or create a contact address and location pair. If the
        location does not exist it will be automatically created. If the
        server already has a location assigned with the same name, the
        contact address specified will be added if it doesn't already
        exist (Management and Log Server can have multiple address for a
        single location).

        :param list(str) contact_addresses: list of contact addresses for
            the specified location
        :param str location: location to place the contact address in
        :param bool overwrite_existing: if you want to replace existing
            location to address mappings set this to True. Otherwise if
            the location exists, only new addresses are appended
        :param bool with_status: if set to True, a 3-tuple is returned with
            (Element, modified, created), where the second and third tuple
            items are booleans indicating the status
        :raises UpdateElementFailed: failed to update element with reason
        :rtype: MultiContactAddress
        """
        updated, created = False, False
        location_ref = location_helper(location)
        if location_ref in self:
            for loc in self:
                if loc.location_ref == location_ref:
                    if overwrite_existing:
                        loc["addresses"][:] = contact_addresses
                        updated = True
                    else:
                        for ca in contact_addresses:
                            if ca not in loc.addresses:
                                loc["addresses"].append(ca)
                                updated = True
        else:
            self.data.setdefault("multi_contact_addresses", []).append(
                dict(addresses=contact_addresses, location_ref=location_ref)
            )
            created = True

        if updated or created:
            self.update()
        if with_status:
            return self, updated, created
        return self


class ContactAddressMixin(object):
    """
    Mixin class to provide an interface to contact addresses on the
    management and log server.
    Contact addresses on servers can contain multiple IP's for a single
    location.
    """

    @property
    def contact_addresses(self):
        """
        Provides a reference to contact addresses used by this server.

        Obtain a reference to manipulate or iterate existing contact
        addresses::

            >>> from smc.elements.servers import ManagementServer
            >>> mgt_server = ManagementServer.objects.first()
            >>> for contact_address in mgt_server.contact_addresses:
            ...   contact_address
            ...
            ContactAddress(location=Default,addresses=[u'1.1.1.1'])
            ContactAddress(location=foolocation,addresses=[u'12.12.12.12'])

        :rtype: MultiContactAddress
        """
        return MultiContactAddress(
            href=self.get_relation("contact_addresses"), type=self.typeof, name=self.name
        )

    def add_contact_address(self, contact_address, location):
        """
        Add a contact address to the Log Server::

            server = LogServer('LogServer 172.18.1.25')
            server.add_contact_address('44.44.44.4', 'ARmoteLocation')

        :param str contact_address: IP address used as contact address
        :param str location: Name of location to use, will be created if
               it doesn't exist
        :raises ModificationFailed: failed adding contact address
        :return: None
        """
        return self.contact_addresses.update_or_create(location, [contact_address])

    def remove_contact_address(self, location):
        """
        Remove contact address by name of location. You can obtain all contact
        addresses by calling :func:`contact_addresses`.

        :param str location: str name of location, will be created if it
            doesn't exist
        :raises ModificationFailed: failed removing contact address
        :return: None
        """
        return self.contact_addresses.delete(location)


class ManagementServer(ContactAddressMixin, Element):
    """
    Management Server configuration. Most configuration settings are better set
    through the SMC, such as HA, however this object can be used to do simple
    tasks such as add a contact addresses to the Management Server when a security
    engine needs to communicate over NAT.

    It's easiest to get the management server reference through a collection::

        >>> ManagementServer.objects.first()
        ManagementServer(name=Management Server)

    :ivar name: name of management server
    :ivar address: address of Management Server

    """

    typeof = "mgt_server"


class DataContext(Element):
    """
    This represents the Data Context.
    """

    typeof = "data_context"

    @property
    def info_data_tag(self):
        return self.data.get("info_data_tag")


class NetflowCollector(NestedDict):
    """
    Represents a Netflow collector.
    This is a sub part of Log Server entity.
    Log Servers can be configured to forward log data to external hosts. You can define which type
    of log data you want to forward and in which format. You can also use Filters to specify in
    detail which log data is forwarded.
    """

    def __init__(
        self,
        data_context,
        host,
        netflow_collector_port,
        netflow_collector_service,
        netflow_collector_version,
        filter=None,
    ):
        dc = dict(
            data_context=element_resolver(data_context),
            filter=element_resolver(filter),
            host=element_resolver(host),
            netflow_collector_port=netflow_collector_port,
            netflow_collector_service=netflow_collector_service,
            netflow_collector_version=netflow_collector_version,
        )
        super(NetflowCollector, self).__init__(data=dc)

    def __str__(self):
        str = ""
        str += "data_context = {}; ".format(self.data_context)
        str += "filter = {}; ".format(self.filter)
        str += "host = {}; ".format(self.host)
        str += "netflow_collector_port = {}; ".format(self.netflow_collector_port)
        str += "netflow_collector_service = {}; ".format(self.netflow_collector_service)
        str += "netflow_collector_version = {}; ".format(self.netflow_collector_version)
        return str

    @property
    def data_context(self):
        """
        The type of log data that is forwarded.
        :rtype: DataContext
        """
        return (
            Element.from_href(self.get("data_context"))
            if self.get("data_context") is not None
            else None
        )

    @property
    def filter(self):
        """
        An optional local filter that defines which log data is forwarded. The
        local filter is only applied to the log data that matches the Log
        Forwarding rule.
        :rtype: FilterExpression
        """
        return Element.from_href(self.get("filter")) if self.get("filter") is not None else None

    @property
    def host(self):
        """
        The Host element that represents the target host to which the log
        data is forwarded.
        :rtype: Host
        """
        return Element.from_href(self.get("host")) if self.get("host") is not None else None

    @property
    def netflow_collector_port(self):
        """
        The Port that is used for log forwarding. The default port used by
        IPFIX/NetFlow data collectors is 2055.<br/>
        <b>Note!</b> If you have to define an Access rule that allows traffic to the
        target host, make sure that the Port you select is also used as the
        Port in the Access rule.
        :rtype: int
        """
        return self.data["netflow_collector_port"]

    @property
    def netflow_collector_service(self):
        """
        The network protocol for forwarding the log data (udp/tcp/tcp_with_tls).<br/>
        <b>Note!</b> If you have to define an Access rule that allows traffic to the
        target host, make sure that the Service you specify is also used as
        the Service in the Access rule.
        :rtype: str
        """
        return self.data["netflow_collector_service"]

    @property
    def netflow_collector_version(self):
        """
        The format for forwarding the log data:
        <ul>
        <li><i>cef</i>: Logs are forwarded in CEF format.</li>
        <li><i>csv</i>: Logs are forwarded in CSV format.</li>
        <li><i>leef</i>: Logs are forwarded in LEEF format.</li>
        <li><i>netflow_v11</i>: Logs are forwarded in NetFlow format.
                                The supported version is NetFlow v16.</li>
        <li><i>ipfix</i>: Logs are forwarded in IPFIX (NetFlow v16) format.</li>
        <li><i>xml</i>: Logs are forwarded in XML format.</li>
        <li><i>esm</i>: Logs are forwarded in McAfee ESM format.</li>
        </ul>
        <b> Only csv, xml and esm are supported for Audit Forwarding from Mgt Server</b>
        :rtype: str
        """
        return self.data["netflow_collector_version"]


class DataContext(Element):
    """
    This represents the Data Context.
    """
    typeof = "data_context"

    @property
    def info_data_tag(self):
        return self.data.get("info_data_tag")


class NetflowCollector(NestedDict):
    """
    Represents a Netflow collector.
    This is a sub part of Log Server entity.
    Log Servers can be configured to forward log data to external hosts. You can define which type
    of log data you want to forward and in which format. You can also use Filters to specify in
    detail which log data is forwarded.
    """

    def __init__(self, data_context, host, netflow_collector_port,
                 netflow_collector_service, netflow_collector_version, filter=None):
        dc = dict(data_context=element_resolver(data_context),
                  filter=element_resolver(filter),
                  host=element_resolver(host),
                  netflow_collector_port=netflow_collector_port,
                  netflow_collector_service=netflow_collector_service,
                  netflow_collector_version=netflow_collector_version
                  )
        super(NetflowCollector, self).__init__(data=dc)

    def __str__(self):
        str = ""
        str += "data_context = {}; ".format(self.data_context)
        str += "filter = {}; ".format(self.filter)
        str += "host = {}; ".format(self.host)
        str += "netflow_collector_port = {}; ".format(self.netflow_collector_port)
        str += "netflow_collector_service = {}; ".format(self.netflow_collector_service)
        str += "netflow_collector_version = {}; ".format(self.netflow_collector_version)
        return str

    @property
    def data_context(self):
        """
        The type of log data that is forwarded.
        :rtype: DataContext
        """
        element_href = None
        if self.get('data_context'):
            element_href = Element.from_href(self.get('data_context'))
        return element_href

    @property
    def filter(self):
        """
        An optional local filter that defines which log data is forwarded. The
        local filter is only applied to the log data that matches the Log
        Forwarding rule.
        :rtype: FilterExpression
        """
        return Element.from_href(self.get('filter')) if self.get('filter') is not None else None

    @property
    def host(self):
        """
        The Host element that represents the target host to which the log
        data is forwarded.
        :rtype: Host
        """
        return Element.from_href(self.get('host')) if self.get('host') is not None else None

    @property
    def netflow_collector_port(self):
        """
        The Port that is used for log forwarding. The default port used by
        IPFIX/NetFlow data collectors is 2055.<br/>
        <b>Note!</b> If you have to define an Access rule that allows traffic to the
        target host, make sure that the Port you select is also used as the
        Port in the Access rule.
        :rtype: int
        """
        return self.data['netflow_collector_port']

    @property
    def netflow_collector_service(self):
        """
        The network protocol for forwarding the log data (udp/tcp/tcp_with_tls).<br/>
        <b>Note!</b> If you have to define an Access rule that allows traffic to the
        target host, make sure that the Service you specify is also used as
        the Service in the Access rule.
        :rtype: str
        """
        return self.data['netflow_collector_service']

    @property
    def netflow_collector_version(self):
        """
        The format for forwarding the log data:
        <ul>
        <li><i>cef</i>: Logs are forwarded in CEF format.</li>
        <li><i>csv</i>: Logs are forwarded in CSV format.</li>
        <li><i>leef</i>: Logs are forwarded in LEEF format.</li>
        <li><i>netflow_v11</i>: Logs are forwarded in NetFlow format.
        The supported version is NetFlow v16.</li>
        <li><i>ipfix</i>: Logs are forwarded in IPFIX (NetFlow v16) format.</li>
        <li><i>xml</i>: Logs are forwarded in XML format.</li>
        <li><i>esm</i>: Logs are forwarded in McAfee ESM format.</li>
        </ul>
        <b> Only csv, xml and esm are supported for Audit Forwarding from Mgt Server</b>
        :rtype: str
        """
        return self.data['netflow_collector_version']


class LogServer(ContactAddressMixin, Element):
    """
    Log Server elements are used to receive log data from the security engines
    Most settings on Log Server generally do not need to be changed, however it
    may be useful to set a contact address location and IP mapping if the Log Server
    needs to be reachable from an engine across NAT

     It's easiest to get the management server reference through a collection::

        >>> LogServer.objects.first()
        LogServer(name=LogServer 172.18.1.150)
    """

    typeof = "log_server"

    @property
    def netflow_collector(self):
        """
        A collection of NetflowCollector

        :rtype: list(NetflowCollector)DomainController
        """
        return [NetflowCollector(**nc) for nc in self.data.get("netflow_collector", [])]

    def add_netflow_collector(self, netflow_collectors):
        """
        Add netflow collector/s to this log server.

        :param netflow_collectors: netflow_collector/s to add to log server
        :type netflow_collectors: list(netflow_collectors)
        :raises UpdateElementFailed: failed updating log server
        :return: None
        """
        if "netflow_collector" not in self.data:
            self.data["netflow_collector"] = {"netflow_collector": []}

        for p in netflow_collectors:
            self.data["netflow_collector"].append(p.data)
        self.update()

    def remove_netflow_collector(self, netflow_collector):
        """
        Remove a netflow collector from this log server.

        :param NetflowCollector netflow_collector: element to remove
        :return: remove element if it exists and return bool
        :rtype: bool
        """
        _netflow_collector = []
        changed = False
        for nf in self.netflow_collector:
            if nf != netflow_collector:
                _netflow_collector.append(nf.data)
            else:
                changed = True

        if changed:
            self.data["netflow_collector"] = _netflow_collector
            self.update()

        return changed


class HttpProxy(Element):
    """
    An HTTP Proxy based element. Used in various areas of the configuration
    such as engine properties to define proxies for File Reputation, etc.

    """

    typeof = "http_proxy"

    @classmethod
    def create(
        cls,
        name,
        address,
        proxy_port=8080,
        username=None,
        password=None,
        secondary=None,
        comment=None,
    ):
        """
        Create a new HTTP Proxy service. Proxy must define at least
        one primary address but can optionally also define a list
        of secondary addresses.

        :param str name: Name of the proxy element
        :param str address: Primary address for proxy
        :param int proxy_port: proxy port (default: 8080)
        :param str username: optional username for authentication (default: None)
        :param str password: password for username if defined (default: None)
        :param str comment: optional comment
        :param list secondary: secondary list of proxy server addresses
        :raises CreateElementFailed: Failed to create the proxy element
        :rtype: HttpProxy
        """
        json = {
            "name": name,
            "address": address,
            "comment": comment,
            "http_proxy_port": proxy_port,
            "http_proxy_username": username if username else "",
            "http_proxy_password": password if password else "",
            "secondary": secondary if secondary else [],
        }

        return ElementCreator(cls, json)


class DNSServer(Element):
    """
    There are some cases in which you must define an External DNS Server
    element.

    * For dynamic DNS (DDNS) updates with a Multi-Link configuration.
    * If you want to use a DNS server for resolving malware signature mirrors.
    * If you want to use a DNS server for resolving domain names and URL filtering
      categorization services on Firewalls, IPS engines, and Layer 2 Firewalls.

    You can also optionally use External DNS Server elements to specify the DNS servers
    to which the firewall forwards DNS requests when you configure DNS relay.

    :ivar int time_to_live: how long a DNS entry can be cached
    :ivar int update_interval: how often DNS entries can be updated
    """

    typeof = "dns_server"

    @classmethod
    def create(
        cls, name, address, time_to_live=20, update_interval=10, secondary=None, comment=None
    ):
        """
        Create a DNS Server element.

        :param str name: Name of DNS Server
        :param str address: IP address for DNS Server element
        :param int time_to_live: Defines how long a DNS entry can be cached
            before querying the DNS server again (default: 20)
        :param int update_interval: Defines how often the DNS entries can be
            updated to the DNS server if the link status changes constantly
            (default: 10)
        :param list secondary: a secondary set of IP address for this element
        :raises CreateElementFailed: Failed to create with reason
        :rtype: DNSServer
        """
        json = {
            "name": name,
            "address": address,
            "comment": comment,
            "time_to_live": time_to_live,
            "update_interval": update_interval,
            "secondary": secondary if secondary else [],
        }

        return ElementCreator(cls, json)


class DHCPServer(Element):
    """
    A DHCP Server based element. Used in various areas to define External DHCP Server.
    """

    typeof = "dhcp_server"
    location = ElementRef("location_ref")

    @classmethod
    def create(cls, name, address, ipv6_address=None, location=None, comment=None):
        """
        Create a DHCP Server element.

        :param str name: Name of DHCP Server
        :param str address: IP address for DHCP Server element
        :param str ipv6_address: IPv6 addres fir DHCP Server
        :param str location: Specifies the location for the server if there is a NAT
            device between the server and other SMC components.
        :param str comment: Comment for DHCP Server element
        :raises CreateElementFailed: Failed to create with reason
        :rtype: DHCPServer
        """
        json = {"name": name, "address": address, "ipv6_address": ipv6_address, "comment": comment}

        if location:
            json.update(location_ref=element_resolver(location))

        return ElementCreator(cls, json)


class ProxyServer(ContactAddressMixin, Element):
    """
    A ProxyServer element is used in the firewall policy to provide the ability to
    send HTTP, HTTPS, FTP or SMTP traffic to a next hop proxy.
    There are two types of next hop proxies, 'Generic' and 'Forcepoint AP Web".

    Example of creating a configuration for a Forcepoint AP-Web proxy redirect::

        server = ProxyServer.update_or_create(name='myproxy',
            address='1.1.1.1', proxy_service='forcepoint_ap-web_cloud',
            fp_proxy_key='mypassword', fp_proxy_key_id=3, fp_proxy_user_id=1234,
            inspected_service=[{'service_type': 'HTTP', 'port': '80'}])

    Create a Generic Proxy forward service::

        server = ProxyServer.update_or_create(name='generic', address='1.1.1.1,1.1.1.2',
            inspected_service=[{'service_type': 'HTTP', 'port': 80},
                               {'service_type': 'HTTPS', 'port': 8080}])

    Inspected services take a list of keys `service_type` and `port`. Service type key values
    are 'HTTP', 'HTTPS', 'FTP' and 'SMTP'. Port value is the port for the respective protocol.

    :param str http_proxy: type of proxy configuration, either generic or forcepoint_ap-web_cloud
    """

    typeof = "proxy_server"
    location = ElementRef("location_ref")

    @classmethod
    def create(
        cls,
        name,
        address,
        inspected_service,
        secondary=None,
        balancing_mode="ha",
        proxy_service="generic",
        location=None,
        comment=None,
        add_x_forwarded_for=False,
        trust_host_header=False,
        **kw
    ):
        """
        Create a Proxy Server element

        :param str name: name of proxy server element
        :param str address: address of element. Can be a single FQDN or comma separated
            list of IP addresses
        :param list secondary: list of secondary IP addresses
        :param str balancing_mode: how to balance traffic, valid options are
            ha (first available server), src, dst, srcdst (default: ha)
        :param str proxy_service: which proxy service to use for next hop, options
            are generic or forcepoint_ap-web_cloud
        :param str,Element location: location for this proxy server
        :param bool add_x_forwarded_for: add X-Forwarded-For header when using the
            Generic Proxy forwarding method (default: False)
        :param bool trust_host_header: trust the host header when using the Generic
            Proxy forwarding method (default: False)
        :param dict inspected_service: inspection services dict. Valid keys are
            service_type and port. Service type valid values are HTTP, HTTPS, FTP or SMTP
            and are case sensitive
        :param str comment: optional comment
        :param kw: keyword arguments are used to collect settings when the proxy_service
            value is forcepoint_ap-web_cloud. Valid keys are `fp_proxy_key`,
            `fp_proxy_key_id`, `fp_proxy_user_id`. The fp_proxy_key is the password value.
            All other values are of type int
        """
        json = {
            "name": name,
            "comment": comment,
            "secondary": secondary or [],
            "http_proxy": proxy_service,
            "balancing_mode": balancing_mode,
            "inspected_service": inspected_service,
            "trust_host_header": trust_host_header,
            "add_x_forwarded_for": add_x_forwarded_for,
            "location_ref": element_resolver(location),
        }
        addresses = address.split(",")
        json.update(address=addresses.pop(0))
        json.update(ip_address=addresses if "ip_address" not in kw else kw["ip_address"])

        if proxy_service == "forcepoint_ap-web_cloud":
            for key in ("fp_proxy_key", "fp_proxy_key_id", "fp_proxy_user_id"):
                if key not in kw:
                    raise CreateElementFailed(
                        "Missing required fp key when adding a "
                        "proxy server to forward to forcepoint. Missing key: %s" % key
                    )
                json[key] = kw.get(key)

        return ElementCreator(cls, json)

    @property
    def proxy_service(self):
        """
        The proxy service for this proxy server configuration

        :rtype: str
        """
        return self.data.get("http_proxy")

    @classmethod
    def update_or_create(cls, with_status=False, **kwargs):
        element, updated, created = super(ProxyServer, cls).update_or_create(
            defer_update=True, **kwargs
        )

        if not created:
            if (
                "proxy_service" in element.data
                and element.http_proxy != element.data["proxy_service"]
            ):
                element.data["http_proxy"] = element.data.pop("proxy_service")
                updated = True
            if "address" in kwargs:
                if "," in element.data.get("address"):
                    addresses = element.data.pop("address").split(",")
                    element.data["address"] = addresses.pop(0)
                    # Remainder is ip_address attribute
                    if set(addresses) ^ set(element.data.get("ip_address", [])):
                        element.data["ip_address"] = addresses
                    updated = True

            inspected_service = kwargs.pop("inspected_service", None)
            if inspected_service is not None:
                service_keys = set([k.get("service_type") for k in inspected_service])
                element_keys = set(
                    [k.get("service_type") for k in element.data.get("inspected_service", [])]
                )
                if service_keys ^ element_keys:
                    element.data["inspected_service"] = inspected_service
                    updated = True
            if updated:
                element.update()

        if with_status:
            return element, updated, created
        return element

    @property
    def inspected_services(self):
        """
        The specified services for inspection. An inspected service is a
        reference to a protocol that can be forwarded for inspection, such
        as HTTP, HTTPS, FTP and SMTP.

        :rtype: list(InspectedService)
        """
        return [
            InspectedService(**service)
            for service in self.make_request(resource="inspected_services")
        ]


class InspectedService(SubElement):
    """
    This represents the service defined for inspection for a
    ProxyServer element.

    :ivar str service_type: the service type for inspection
    :ivar int port: the port for this service
    """

    pass


class ElasticsearchCluster(ContactAddressMixin, Element):
    """
    An ElasticsearchCluster server type element.
    """

    typeof = "elasticsearch_cluster"
    location = ElementRef("location_ref")

    @classmethod
    def create(
        cls,
        name,
        addresses,
        port=9200,
        es_retention_period=30,
        es_shard_number=0,
        es_replica_number=0,
        enable_cluster_sniffer=False,
        location=None,
        comment=None,
        tls_profile=None,
        use_internal_credentials=True,
        tls_credentials=None,
    ):
        """
        Create a Elasticsearch Cluster Server element.

        :param str name: Name of Elasticsearch Cluster
        :param list,str addresses: str comma-separated list or list
         of one or more FQDNs or IP addresses
        :param int port: Default port is 9200
        :param int es_retention_period: How much time logs will be kept
        30days default
        :param int es_shard_number: Auto by default, number of shards
        :param int es_replica_number : number of ES replicas
        :param bool enable_cluster_sniffer : Enable cluster sniffer (False
        default)
        :param str location: Specifies the location for the server if there
        is a NAT device between the server and other SMC components.
        :param str comment: Comment for Elasticsearch cluster Server element
        :param str tls_profile: tls profile name to use
        :param bool use_internal_credentials: use internal credentials
        :param str tls_credentials: tls credentials name to use

        :raises CreateElementFailed: Failed to create with reason
        :rtype: ElasticsearchCluster
        """
        json = {
            "name": name,
            "port": port,
            "es_retention_period": es_retention_period,
            "es_shard_number": es_shard_number,
            "es_replica_number": es_replica_number,
            "es_enable_cluster_sniffer": enable_cluster_sniffer,
            "comment": comment,
        }

        if isinstance(addresses, str):
            addresses_lst = addresses.split(",")
        else:
            addresses_lst = addresses
        json.update(addresses=addresses_lst)
        if location:
            location_href = Location(location).href
            json.update(location_ref=location_href)
        if tls_profile:
            tls_profile_ref = tls.TLSProfile(tls_profile).href
            json.update(tls_profile=tls_profile_ref)
        if tls_credentials:
            tls_credentials_ref = tls.TLSServerCredential(tls_credentials).href
            json.update(
                es_tls_settings={
                    "use_internal_credentials": use_internal_credentials,
                    "tls_credentials": tls_credentials_ref,
                }
            )
        else:
            json.update(es_tls_settings={"use_internal_credentials": use_internal_credentials})

        return ElementCreator(cls, json)


#     @classmethod
#     def create(cls, service_type, port, comment=None):
#         """
#         Create a service type defintion for a proxy server protocol.
#
#         :param str service_type: service type to use, HTTP, HTTPS, FTP or
#             SMTP
#         :param str,int port: port for this service
#         :param str comment: optional comment
#         """
#         json = {'service_type': service_type.upper(),
#             'port': port, 'comment': comment}
#         data = ElementCache(data=json)
#         return type(cls.__name__, (cls,), {'data': data})()

class NTPServer(Element):
    """
    This represents an NTP server: A Network Element that represents an NTP instance of server.
    """

    typeof = "ntp"

    @property
    def address(self):
        """
        The NTP address (Required)
        """
        return self.data.get("ntp_host_name")

    @property
    def ntp_host_name(self):
        """
        The NTP Host Name (Not Required)
        """
        return self.data.get("ntp_host_name")

    @property
    def ntp_auth_key_type(self):
        """
        The NTP Authentication Key Type (Required)
        Possible values are:
        - none
        - md5
        - sha1
        - sha256
        """
        return self.data.get("ntp_auth_key_type")

    @property
    def ntp_auth_key_id(self):
        """
        The NTP Authentication Key ID (Not Required)
        value between 1 - 65534
        """
        return self.data.get("ntp_auth_key_id")

    @property
    def ntp_auth_key(self):
        """
        The NTP Authentication Key (Not Required)
        """
        return self.data.get("ntp_auth_key")

    @classmethod
    def create(
            cls,
            name,
            address,
            ntp_host_name=None,
            ntp_auth_key_type="none",
            ntp_auth_key_id=None,
            ntp_auth_key=None,
            comment=None
    ):
        """
        Create NTP server

        :param str name: name for the Element
        :param str ntp_host_name: NTP server name to use
        :param str ntp_auth_key_type:The NTP Authentication Key Type (Required)
        possible values are (none, md5, sha1, sha256)
        :param str ntp_auth_key_id:The NTP Authentication Key ID (Not Required)
        value between 1 - 65534
        :param str ntp_auth_key:The NTP Authentication Key (Not Required)
        :param str address: The NTP address (Required)
        :param str comment: comment for the element

        :raises CreateElementFailed: Failed to create with reason
        :rtype: NTPServer
        """
        ntp_server_json = {
            "address": address,
            "comment": comment,
            "name": name,
            "ntp_host_name": ntp_host_name,
            "ntp_auth_key_type": ntp_auth_key_type,
            "ntp_auth_key_id": ntp_auth_key_id,
            "ntp_auth_key": ntp_auth_key,
        }
        return ElementCreator(cls, ntp_server_json)
