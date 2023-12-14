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
Module representing network elements used within the SMC
"""
import copy

from smc.base.model import Element, ElementCreator
from smc.api.exceptions import (
    MissingRequiredInput,
    CreateElementFailed,
    ElementNotFound,
    FetchElementFailed,
)
from smc.base.structs import NestedDict
from smc.base.util import element_resolver
from smc.compat import is_api_version_less_than, is_smc_version_less_than_or_equal
from smc.api.common import fetch_entry_point
from smc.elements.common import IPv6Node


class Host(Element, IPv6Node):
    """
    Class representing a Host object used in access rules

    Create a host element with ipv4::

        Host.create(name='myhost', address='1.1.1.1',
                    secondary=['1.1.1.2'],
                    comment='some comment for my host')

    Create a host element with ipv6 and secondary ipv4 address::

        Host.create(name='mixedhost',
                    ipv6_address='2001:cdba::3257:9652',
                    secondary=['1.1.1.1'])

    Available attributes:

    :ivar str address: IPv4 address for this element
    :ivar str ipv6_address: IPv6 address for this host element
    :ivar list secondary: secondary IP addresses for this host
    :ivar ThirdPartyMonitoring third_party_monitoring: The optional Third Party Monitoring
            configuration.
    :ivar DeviceToolsProfile tools_profile_ref: Allows you to add commands to the element’s
            right-click menu. Not Required.
    """

    typeof = "host"

    @classmethod
    def create(cls, name, address=None, ipv6_address=None, secondary=None,
               third_party_monitoring=None, tools_profile_ref=None, comment=None):
        """
        Create the host element

        :param str name: Name of element
        :param str address: ipv4 address of host object (optional if ipv6)
        :param str ipv6_address: ipv6 address (optional if ipv4)
        :param list secondary: secondary ip addresses (optional)
        :param ThirdPartyMonitoring third_party_monitoring: The optional Third Party Monitoring
            configuration.
        :param DeviceToolsProfile tools_profile_ref: Allows you to add commands to the element’s
            right-click menu. Not Required.
        :param str comment: comment (optional)
        :raises CreateElementFailed: element creation failed with reason
        :return: instance with meta
        :rtype: Host

        .. note:: Either ipv4 or ipv6 address is required
        """
        address = address if address else None
        ipv6_address = ipv6_address if ipv6_address else None
        secondaries = [] if secondary is None else secondary
        json = {
            "name": name,
            "address": address,
            "ipv6_address": ipv6_address,
            "secondary": secondaries,
            "tools_profile_ref": element_resolver(tools_profile_ref),
            "comment": comment,
        }
        if third_party_monitoring:
            json.update(third_party_monitoring=third_party_monitoring.data)

        return ElementCreator(cls, json)


class AddressRange(Element):
    """
    Class representing a IpRange object used in access rules

    Create an address range element::

        IpRange.create('myrange', '1.1.1.1-1.1.1.5')

    Available attributes:

    :ivar str ip_range: IP range for element. In format:
        '10.10.10.1-10.10.10.10'
    """

    typeof = "address_range"

    @classmethod
    def create(cls, name, ip_range, comment=None):
        """
        Create an AddressRange element

        :param str name: Name of element
        :param str iprange: iprange of element
        :param str comment: comment (optional)
        :raises CreateElementFailed: element creation failed with reason
        :return: instance with meta
        :rtype: AddressRange
        """
        json = {"name": name, "ip_range": ip_range, "comment": comment}

        return ElementCreator(cls, json)

    @classmethod
    def any(cls):
        return Element.from_href(fetch_entry_point("address_range")+'/0')


class Router(Element, IPv6Node):
    """
    Class representing a Router object used in access rules

    Create a router element with ipv4 address::

        Router.create('myrouter', '1.2.3.4', comment='my router comment')

    Create a router element with ipv6 address::

        Router.create(name='mixedhost',
                      ipv6_address='2001:cdba::3257:9652')

    Available attributes:

    :ivar str address: IPv4 address for this router
    :ivar str ipv6_address: IPv6 address for this router
    :ivar list secondary: list of additional IP's for this router
    :ivar ThirdPartyMonitoring third_party_monitoring: The optional Third Party Monitoring
        configuration.
    :ivar DeviceToolsProfile tools_profile_ref: Allows you to add commands to the element’s
        right-click menu. Not Required.
    """

    typeof = "router"

    @classmethod
    def create(cls, name, address=None, ipv6_address=None, secondary=None,
               third_party_monitoring=None, tools_profile_ref=None, comment=None):
        """
        Create the router element

        :param str name: Name of element
        :param str address: ip address of host object (optional if ipv6)
        :param str ipv6_address: ipv6 address (optional if ipv4)
        :param list secondary: secondary ip address (optional)
        :param ThirdPartyMonitoring third_party_monitoring: The optional Third Party Monitoring
            configuration.
        :param DeviceToolsProfile tools_profile_ref: Allows you to add commands to the element’s
            right-click menu. Not Required.
        :param str comment: comment (optional)
        :raises CreateElementFailed: element creation failed with reason
        :return: instance with meta
        :rtype: Router

        .. note:: either ipv4 or ipv6 address is required
        """
        address = address if address else None
        ipv6_address = ipv6_address if ipv6_address else None
        secondary = [] if secondary is None else secondary
        json = {
            "name": name,
            "address": address,
            "ipv6_address": ipv6_address,
            "secondary": secondary,
            "tools_profile_ref": element_resolver(tools_profile_ref),
            "comment": comment,
        }

        if third_party_monitoring:
            json.update(third_party_monitoring=third_party_monitoring.data)

        return ElementCreator(cls, json)


class Network(Element):
    """
    Class representing a Network object used in access rules
    Network format should be CIDR based. It is recommended that when
    creating the network element, you use a naming convention that
    includes the network cidr in the name, such as 'network-1.1.1.0/24'.
    This will simplify searches later and workaround the restriction
    that searches with '/' and '-' only match on the name field and
    not an actual attribute value.

    Create an ipv4 network element::

        Network.create('mynetwork', '2.2.2.0/24')

    Create an ipv6 network element::

        Network.create(name='mixednetwork', ipv6_network='fc00::/7')

    Available attributes:

    :ivar str ipv4_network: IPv4 network, in format: 10.10.10.0/24
    :ivar str ipv6_network: IPv6 network
    """

    typeof = "network"

    @classmethod
    def create(cls, name, ipv4_network=None, ipv6_network=None, broadcast=True, location_ref=None,
               comment=None):
        """
        Create the network element

        :param str name: Name of element
        :param str ipv4_network: network cidr (optional if ipv6)
        :param str ipv6_network: network cidr (optional if ipv4)
        :param bool broadcast: Includes the broadcast address and the network address in the
            definition. This option is only used in the Source and Destination cells in rules. In
            other uses, the broadcast and network addresses are always included in the definition
            regardless of this option.
        :param Location location_ref: Location of the network.
        :param str comment: comment (optional)
        :raises CreateElementFailed: element creation failed with reason
        :return: instance with meta
        :rtype: Network

        .. note:: Either an ipv4_network or ipv6_network must be specified
        """
        ipv4_network = ipv4_network if ipv4_network else None
        ipv6_network = ipv6_network if ipv6_network else None
        json = {
            "name": name,
            "ipv4_network": ipv4_network,
            "ipv6_network": ipv6_network,
            "broadcast": broadcast,
            "location_ref": element_resolver(location_ref),
            "comment": comment,
        }

        return ElementCreator(cls, json)


class DomainName(Element):
    """
    Represents a domain name used as FQDN in policy
    Use this object to reference a DNS resolvable FQDN or
    partial domain name to be used in policy.

     Create a domain based network element::

        DomainName.create('mydomain.net')
    """

    typeof = "domain_name"

    @classmethod
    def create(cls, name, domain_name_entry=None, comment=None):
        """
        Create domain name element

        :param str name: name of domain, i.e. example.net, www.example.net
        :param list(str) domain_name_entry: The additional domain names.
        :param str comment: Optional comment.
        :raises CreateElementFailed: element creation failed with reason
        :return: instance with meta
        :rtype: DomainName
        """
        json = {"name": name, "comment": comment}
        if not is_smc_version_less_than_or_equal("6.10"):
            json.update(domain_name_entry=domain_name_entry)
        return ElementCreator(cls, json)

    @property
    def domain_name_entry(self):
        """
        The additional domain names.
        :rtype: list(str)
        """
        return self.data.get("domain_name_entry")


class Expression(Element):
    """
    Expressions are used to build boolean like objects used in policy. For example,
    if you wanted to create an expression that negates a specific set of network
    elements to use in a "NOT" rule, an expression would be the element type.

    For example, adding a rule that negates (network A or network B)::

        sub_expression = Expression.build_sub_expression(
                            name='mytestexporession',
                            ne_ref=['http://172.18.1.150:8082/6.0/elements/host/3999',
                                    'http://172.18.1.150:8082/6.0/elements/host/4325'],
                            operator='union')

        Expression.create(name='apiexpression',
                          ne_ref=[],
                          sub_expression=sub_expression)

    .. note:: The sub-expression creates the json for the expression
              (network A or network B) and is then used as an parameter to create.
    """

    typeof = "expression"

    @staticmethod
    def build_sub_expression(name, ne_ref=None, operator="union"):
        """
        Static method to build and return the proper json for a sub-expression.
        A sub-expression would be the grouping of network elements used as a
        target match. For example, (network A or network B) would be considered
        a sub-expression. This can be used to compound sub-expressions before
        calling create.

        :param str name: name of sub-expression
        :param list ne_ref: network elements references
        :param str operator: exclusion (negation), union, intersection (default: union)
        :return: JSON of subexpression. Use in :func:`~create` constructor
        """
        ne_ref = [] if ne_ref is None else ne_ref
        json = {"name": name, "ne_ref": ne_ref, "operator": operator}
        return json

    @classmethod
    def create(cls, name, ne_ref=None, operator="exclusion", sub_expression=None, comment=None):
        """
        Create the expression

        :param str name: name of expression
        :param list ne_ref: network element references for expression
        :param str operator: 'exclusion' (negation), 'union', 'intersection'
               (default: exclusion)
        :param dict sub_expression: sub expression used
        :param str comment: optional comment
        :raises CreateElementFailed: element creation failed with reason
        :return: instance with meta
        :rtype: Expression
        """
        sub_expression = [] if sub_expression is None else [sub_expression]
        json = {
            "name": name,
            "operator": operator,
            "ne_ref": ne_ref,
            "sub_expression": sub_expression,
            "comment": comment,
        }

        return ElementCreator(cls, json)


class ApplicationPort(NestedDict):
    """
    This represents the definition of port for an Application element.
    """
    def __init__(
            self,
            port_from,
            port_to,
            protocol_ref,
            tls,
            mode="regular",
            min_version=None,
            max_version=None
    ):
        dc = dict(
            port_from=port_from,
            port_to=port_to,
            protocol_ref=protocol_ref,
            tls=tls
        )

        if not is_api_version_less_than("7.0"):
            dc.update(mode=mode)
            dc.update(max_version=max_version)
            dc.update(min_version=min_version)

        super(ApplicationPort, self).__init__(data=dc)
        # hack to fix "from" and "to" reserved python keyword
        self.data["from"] = self.data.pop("port_from")
        self.data["to"] = self.data.pop("port_to")

    def __str__(self):
        result = ""
        result += "port_from = {}; ".format(self.port_from)
        result += "port_to = {}; ".format(self.port_to)
        result += "protocol_ref = {}; ".format(self.protocol_ref)
        result += "tls = {}; ".format(self.tls)
        result += "mode = {}; ".format(self.mode)
        result += "min_version = {}; ".format(self.min_version)
        result += "max_version = {}; ".format(self.max_version)
        return result

    @property
    def port_from(self):
        """
        The inspected min port.
        It is applicable for protocols that use ports: TCP, UDP and SCTP.
        :rtype: int
        """
        return self.get("from")

    @property
    def port_to(self):
        """
        The inspected max port.
        It is applicable for protocols that use ports: TCP, UDP and SCTP.
        :rtype: int
        """
        return self.get("to")

    @property
    def protocol_ref(self):
        """
        The application protocol for this port setting.
        :rtype: str
        """
        return self.get("protocol_ref")

    @property
    def tls(self):
        """
        The Application port TLS setting:
        ***no***: it is forbidden to identify the traffic with the TLS match.
        ***possible***: it is possible that the traffic is identified with the TLS match.
        ***mandatory***: it is mandatory that the traffic is identified with the TLS match.
        ***free***: it is free that the traffic is identified with the TLS match.
        :rtype: str
        """
        return self.get("tls")

    @property
    def mode(self):
        """
        The Application port mode:
        ***regular***: normal mode
        ***quic***: applies only for NGFW engines where QUIC ports are included for web traffic
        :rtype: str
        .. note:: This method requires SMC version >= 7.0
        """
        return self.get("mode")

    @property
    def min_version(self):
        """
        Minimum version of engine that supports the port.
        If not defined, the port applies to the same versions as the parent element
        (eg. network application)
        """
        return self.get("min_version")

    @property
    def max_version(self):
        """
        Maximum version of engine that supports the port.
        If not defined, the port applies to the same versions as the parent element
        (eg. network application)
        """
        return self.get("max_version")


class URLListApplication(Element):
    """
    URL List Application represents a list of URL's (typically by domain)
    that allow for easy grouping for performing whitelist and blacklisting

    Creating a URL List::

        URLListApplication.create(
            name='whitelist',
            url_entry=['www.google.com', 'www.cnn.com'])

    .. note:: URLListApplication requires SMC API version >= 6.1

    Available attributes:

    :ivar list url_entry: URL entries as strings
    """

    typeof = "url_list_application"

    @classmethod
    def create(cls,
               name,
               url_entry,
               application_ports=None,
               comment=None):
        """
        Create the custom URL list

        :param str name: name of url list
        :param list url_entry: list of url's
        :param list application_ports: list of ApplicationPort
        :param str comment: optional comment
        :raises CreateElementFailed: element creation failed with reason
        :return: instance with meta
        :rtype: URLListApplication
        """
        json = {"name": name, "url_entry": url_entry, "comment": comment}

        if application_ports:
            json.update({"application_port": []})
            for p in application_ports:
                json["application_port"].append(p.data)

        return ElementCreator(cls, json)

    @property
    def application_port(self):
        """
        A collection of ApplicationPort

        :rtype: list(ApplicationPort)
        """
        # fix "from" and "to" python reserved keywords
        to_return = []
        data_clone = copy.deepcopy(self.data.data)
        for ap in data_clone.get("application_port", []):
            if "from" in ap:
                ap["port_from"] = ap.pop("from")
            if "to" in ap:
                ap["port_to"] = ap.pop("to")
            to_return.append(ApplicationPort(**ap))
        return to_return

    @application_port.setter
    def application_port(self, application_port_list):
        """
        set application port list

        :param application_port_list: url list to add
        :type application_port_list: list(ApplicationPort)
        """
        self.data["application_port"] = {}
        for app in application_port_list:
            self.data["application_port"].append(app.data)

    def add_application_port(self, application_ports):
        """
        Add application_ports to this url list application.

        :param application_ports: application ports to add
        :type application_ports: list(ApplicationPort)
        :raises UpdateElementFailed: failed updating the url list application
        :return: None
        """
        if "application_port" not in self.data:
            self.data["application_port"] = []

        for p in application_ports:
            self.data["application_port"].append(p.data)
        self.update()

    @property
    def url_entry(self):
        """
        URL list
        :rtype: list(str)
        """
        return self.data.get("url_entry")

    @url_entry.setter
    def url_entry(self, list_url):
        """
        set URL list
        :param list_url: url list to add
        :type list_url: list(str)
        """
        self.data["url_entry"] = list_url


class IPListGroup(Element):
    """
    .. note:: IPListGroup requires SMC API version >= 6.1
    """

    pass


class IPList(Element):
    """
    IPList represent a custom list of IP addresses, networks or
    ip ranges (IPv4 or IPv6). These are used in source/destination
    fields of a rule for policy enforcement.

    .. note:: IPList requires SMC API version >= 6.1

    Create an empty IPList::

        IPList.create(name='mylist')

    Create an IPList with initial content::

        IPList.create(name='mylist', iplist=['1.1.1.1','1.1.1.2', '1.2.3.4'])

    Example of downloading the IPList in text format::

        >>> iplist = list(IPList.objects.filter('mylist'))
        >>> print(iplist)
        [IPList(name=mylist)]
        >>> iplist[0].download(filename='iplist.txt', as_type='txt')

    Example of uploading an IPList as a zip file::

        >>> iplist = list(IPList.objects.filter('mylist'))
        >>> print(iplist)
        [IPList(name=mylist)]
        iplist[0].upload(filename='/path/to/iplist.zip')

    Upload an IPList using json format::

        >>> iplist = IPList('mylist')
        >>> iplist.upload(json={'ip': ['4.4.4.4']}, as_type='json')

    """

    typeof = "ip_list"

    def download(self, filename=None, as_type="zip"):
        """
        Download the IPList. List format can be either zip, text or
        json. For large lists, it is recommended to use zip encoding.
        Filename is required for zip downloads.

        :param str filename: Name of file to save to (required for zip)
        :param str as_type: type of format to download in: txt,json,zip (default: zip)
        :raises IOError: problem writing to destination filename
        :return: None
        """
        headers = None
        if as_type in ["zip", "txt", "json"]:
            if as_type == "zip":
                if filename is None:
                    raise MissingRequiredInput(
                        "Filename must be specified when " "downloading IPList as a zip file."
                    )
                filename = "{}".format(filename)
            elif as_type == "txt":
                headers = {"accept": "text/plain"}
            elif as_type == "json":
                headers = {"accept": "application/json"}

            result = self.make_request(
                FetchElementFailed,
                raw_result=True,
                resource="ip_address_list",
                filename=filename,
                headers=headers,
            )

            return result.json if as_type == "json" else result.content

    def upload(self, filename=None, json=None, as_type="zip"):
        """
        Upload an IPList to the SMC. The contents of the upload
        are not incremental to what is in the existing IPList.
        So if the intent is to add new entries, you should first retrieve
        the existing and append to the content, then upload.
        The only upload type that can be done without loading a file as
        the source is as_type='json'.

        :param str filename: required for zip/txt uploads
        :param str json: required for json uploads
        :param str as_type: type of format to upload in: txt|json|zip (default)
        :raises IOError: filename specified cannot be loaded
        :raises CreateElementFailed: element creation failed with reason
        :return: None
        """
        headers = {"content-type": "multipart/form-data"}
        params = None
        files = None
        if filename:
            files = {"ip_addresses": open(filename, "rb")}
        if as_type == "json":
            headers = {"accept": "application/json", "content-type": "application/json"}
        elif as_type == "txt":
            params = {"format": "txt"}

        self.make_request(
            CreateElementFailed,
            method="create",
            resource="ip_address_list",
            headers=headers,
            files=files,
            json=json,
            params=params,
        )

    @classmethod
    def update_or_create(cls, append_lists=True, with_status=False, **kwargs):
        """
        Update or create an IPList.

        :param bool append_lists: append to existing IP List
        :param dict kwargs: provide at minimum the name attribute
            and optionally match the create constructor values
        :raises FetchElementFailed: Reason for retrieval failure
        """
        was_created, was_modified = False, False
        element = None
        try:
            element = cls.get(kwargs.get("name"))
            if append_lists:
                iplist = element.iplist
                diff = [i for i in kwargs.get("iplist", []) if i not in iplist]
                if diff:
                    iplist.extend(diff)
                else:
                    iplist = []
            else:
                iplist = kwargs.get("iplist", [])

            if iplist:
                element.upload(json={"ip": iplist}, as_type="json")
                was_modified = True

        except ElementNotFound:
            element = cls.create(kwargs.get("name"), iplist=kwargs.get("iplist", []))
            was_created = True

        if with_status:
            return element, was_modified, was_created
        return element

    @property
    def iplist(self):
        """
        Return a list representation of this IPList. This is not
        a recommended function if the list is extremely large.
        In that case use the download function in zip format.

        :raises FetchElementFailed: Reason for retrieval failure
        :rtype: list
        """
        return self.download(as_type="json").get("ip", [])

    @classmethod
    def create(cls, name, iplist=None, comment=None):
        """
        Create an IP List. It is also possible to add entries by supplying
        a list of IPs/networks, although this is optional. You can also
        use upload/download to add to the iplist.

        :param str name: name of ip list
        :param list iplist: list of ipaddress
        :param str comment: optional comment
        :raises CreateElementFailed: element creation failed with reason
        :return: instance with meta
        :rtype: IPList
        """
        json = {"name": name, "comment": comment}
        result = ElementCreator(cls, json)
        if result and iplist is not None:
            element = IPList(name)

            element.make_request(
                CreateElementFailed,
                method="create",
                resource="ip_address_list",
                json={"ip": iplist},
            )

        return result


class Zone(Element):
    """
    Class representing a zone used on physical interfaces and
    used in access control policy rules, typically in source and
    destination fields. Zones can be applied on multiple interfaces
    which would allow logical grouping in policy.

    Create a zone::

        Zone.create('myzone')
    """

    typeof = "interface_zone"

    @classmethod
    def create(cls, name, comment=None):
        """
        Create the zone element

        :param str zone: name of zone
        :param str comment: optional comment
        :raises CreateElementFailed: element creation failed with reason
        :return: instance with meta
        :rtype: Zone
        """
        json = {"name": name, "comment": comment}

        return ElementCreator(cls, json)


class Country(Element):
    """
    Country elements cannot be created, only viewed

    .. note:: Country requires SMC API version >= 6.1
    """

    typeof = "country"


class IPCountryGroup(Element):
    """
    IP Country Group

    .. note:: IP Country Group requires SMC API version >= 6.1
    """

    typeof = "ip_country_group"


class Alias(Element):
    """
    Aliases are adaptive objects that represent a single
    element having different values based on the engine
    applied on. There are many default aliases in SMC
    and new ones can also be created.

    Finding aliases can be achieved by using collections
    or loading directly if you know the alias name:
    ::

        >>> from smc.elements.network import Alias
        >>> list(Alias.objects.all())
        [Alias(name=$$ Interface ID 46.net), Alias(name=$$ Interface ID 45.net), etc]

    Resolve an alias to a specific engine::

        >>> alias = Alias('$$ Interface ID 0.ip')
        >>> alias.resolve('myfirewall')
        [u'10.10.0.1']

    Create an alias and assign values specific to an engine::

        >>> alias = Alias.update_or_create(
            name='fooalias', engine=Layer3Firewall('vm'), translation_values=[Host('foo')])
        >>> alias
        Alias(name=fooalias)

    """

    typeof = "alias"

    @classmethod
    def create(cls, name, comment=None, default_values=None, alias_values=None):
        """
        Create an alias.

        :param str name: name of alias
        :param str comment: comment for this alias
        :param list(Element) default_values: the default translated values
        :param dict alias_values: the dedicated translated values for specified engines
               {Engine1: [Element1, Element2], Engine2: [Element3]}
        :raises CreateElementFailed: create failed with reason
        :rtype: Alias
        """
        alias_json_content = {"name": name,
                              "comment": comment}
        if default_values:
            d_values = cls.__convert_default_values(default_values=default_values)
            alias_json_content["default_alias_value"] = d_values
        if alias_values:
            a_values = cls.__convert_alias_values(alias_values=alias_values)
            alias_json_content["alias_value"] = a_values

        return ElementCreator(cls,
                              json=alias_json_content)

    @classmethod
    def __convert_default_values(cls, default_values=None):
        parsed_default_values = None
        if default_values:
            parsed_default_values = element_resolver(default_values) if default_values else []

        return parsed_default_values

    @classmethod
    def __convert_alias_values(cls, alias_values=None):
        parsed_alias_values = None
        if alias_values:
            parsed_alias_values = []
            for engine, translated_values in alias_values.items():
                resolved_tvs = element_resolver(translated_values) if translated_values else []
                parsed_alias_values.append({'cluster_ref': engine.href,
                                            'translated_element': resolved_tvs})

        return parsed_alias_values

    @classmethod
    def update_or_create(cls,
                         name,
                         engine=None,
                         translation_values=None,
                         with_status=False,
                         default_values=None,
                         alias_values=None):
        """
        Update or create an Alias and it's mappings.

        :param str name: name of alias
        :param Engine engine: engine to modify alias translation values
        :param list(str,Element) translation_values: translation values
            as elements. Can be None if you want to unset any existing values
        :param bool with_status: if set to True, a 3-tuple is returned with
            (Element, modified, created), where the second and third tuple
            items are booleans indicating the status
        :param list(Element) default_values: the default translated values
        :param dict alias_values: the dedicated translated values for specified engines
               {Engine1: [Element1, Element2], Engine2: [Element3]}
        :raises ElementNotFound: specified engine or translation values are not
            found in the SMC
        :raises UpdateElementFailed: update failed with reason
        :raises CreateElementFailed: create failed with reason
        :rtype: Element
        """
        updated, created = False, False
        alias = cls.get(name, raise_exc=False)
        if not alias:
            alias = cls.create(name, default_values=default_values, alias_values=alias_values)
            created = True
        elif default_values or alias_values:
            d_values = cls.__convert_default_values(default_values=default_values)
            a_values = cls.__convert_alias_values(alias_values=alias_values)
            alias.update(default_alias_value=d_values,
                         alias_value=a_values)
            updated = True

        if engine:
            elements = element_resolver(translation_values) if translation_values else []

            if not created:  # possible update
                # Does alias already exist with a value
                alias_value = [
                    _alias
                    for _alias in engine.data.get("alias_value", [])
                    if _alias.get("alias_ref") == alias.href
                ]

                if alias_value:
                    if not elements:
                        alias_value[0].update(translated_element=None)
                        updated = True
                    else:
                        t_values = alias_value[0].get("translated_element")
                        if set(t_values) ^ set(elements):
                            t_values[:] = elements
                            updated = True

            if elements and (created or not updated):
                engine.data.setdefault("alias_value", []).append(
                    {"alias_ref": alias.href, "translated_element": elements}
                )
                updated = True

            if updated:
                engine.update()

        if with_status:
            return alias, updated, created
        return alias

    @classmethod
    def _from_engine(cls, data, alias_list):
        """
        Return an alias for the engine. The data is dict provided
        when calling engine.alias_resolving(). The alias list is
        the list of aliases pre-fetched from Alias.objects.all().
        This will return an Alias element by taking the alias_ref
        and finding the name in the alias list.

        :rtype: Alias
        """
        for alias in alias_list:
            href = data.get("alias_ref")
            if alias.href == href:
                _alias = Alias(alias.name, href=href)
                _alias.typeof = alias._meta.type
                return _alias

    def resolve(self, engine):
        """
        Resolve this Alias to a specific value. Specify the
        engine by name to find it's value.

        ::

            alias = Alias('$$ Interface ID 0.ip')
            alias.resolve('smcpython-fw')

        :param str engine: name of engine to resolve value
        :raises ElementNotFound: if alias not found on engine
        :return: alias resolving values
        :rtype: list
        """
        return self.make_request(
                ElementNotFound, href=self.get_relation("resolve"), params={"for": engine}
            ).get("resolved_value")

    def full_resolve(self, engine):
        """
        Fully resolve this Alias to a specific value (both translated_element and resolved_value).
        Specify the engine by name to find it's value.

        ::

            alias = Alias('$$ Interface ID 0.ip')
            alias.full_resolve('smcpython-fw')

        :param str engine: name of engine to resolve value
        :raises ElementNotFound: if alias not found on engine
        :return: alias resolving values:
        {"resolved_value": [resolved type:str..],
         "translated_element": [translated type:Element..]}
        :rtype: {resolved_value:list str, translated_element: list Element}
        """
        result = self.make_request(ElementNotFound, href=self.get_relation("resolve"),
                                   params={"for": engine})

        return {"resolved_value": result.get('resolved_value'),
                # list of Element
                "translated_element": list(
                    # filter NONE
                    filter(lambda resolved_element: resolved_element.name != 'NONE',
                           # resolve Element from href
                           map(lambda element: Element.from_href(element),
                               # consider 'translated_element' if there is
                               result.get("translated_element", []))))}
