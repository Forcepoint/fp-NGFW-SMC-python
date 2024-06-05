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
Other element types that treated more like generics, or that can be applied in
different areas within the SMC. They will not independently be created as standalone
objects and will be more generic container classes that define the required json when
used by API functions or methods.
For example, blocklist can be applied to an engine directly or system wide. This class
will define the format when calling blocklist functions.
"""
from smc.base.decorators import cached_property
from smc.base.model import Element, ElementCreator, ElementList
from smc.base.structs import NestedDict
from smc.base.util import element_resolver
from smc.api.exceptions import ModificationFailed


class Category(Element):
    """
    A Category is used by an element to group and categorize elements by
    some criteria. Once a category is created, it can be assigned to the
    element and used as a search filter when managing large
    numbers of elements. A category can be added to a category tag (or tags)
    to provide a higher level container/group for searching.
    ::

        >>> from smc.elements.other import Category
        >>> Category.create(name='footag', comment='test tag')
        Category(name=footag)

    :ivar list(CategoryTag) categories: category tags for this category
    """

    typeof = "category_tag"
    categories = ElementList("category_parent_ref")

    @classmethod
    def create(cls, name, comment=None):
        """
        Add a category element

        :param name: name of location
        :return: instance with meta
        :rtype: Category
        """
        json = {"name": name, "comment": comment}

        return ElementCreator(cls, json)

    def search_elements(self):
        """
        Find all elements assigned to this category tag. You can also find
        category tags assigned directly to an element also::

            >>> host = Host('kali')
            >>> host.categories
            [Category(name=myelements), Category(name=foocategory)]

        :return: :py:class:`smc.base.model.Element`
        :rtype: list
        """
        return [
            Element.from_meta(**tag)
            for tag in self.make_request(resource="search_elements_from_category_tag")
        ]

    def add_element(self, element):
        """
        Element can be href or type :py:class:`smc.base.model.Element`
        ::

            >>> from smc.elements.other import Category
            >>> category = Category('foo')
            >>> category.add_element(Host('kali'))

        :param str,Element element: element to add to tag
        :raises: ModificationFailed: failed adding element
        :return: None
        """
        element = element_resolver(element)

        self.make_request(
            ModificationFailed,
            method="create",
            resource="category_add_element",
            json={"value": element},
        )

    def remove_element(self, element):
        """
        Remove an element from this category tag. Find elements assigned
        by :func:`~search_elements`. Element can be str href or type
        :py:class:`smc.base.model.Element`.
        ::

            >>> from smc.elements.other import Category
            >>> from smc.elements.network import Host
            >>> category.remove_element(Host('kali'))

        :param str, Element element: element to remove
        :raises ModificationFailed: cannot remove element
        :return: None
        """
        element = element_resolver(element)

        self.make_request(
            ModificationFailed,
            method="create",
            resource="category_remove_element",
            json={"value": element},
        )

    def add_category_tag(self, tags, append_lists=True):
        """
        Add this category to a category tag (group). This provides drop down
        filters in the SMC by category tag.

        :param list tags: category tag by name
        :param bool append_lists: append to existing tags or overwrite
            default: append)
        :type tags: list(str)
        :return: None
        """
        tags = element_resolver(tags)
        self.update(category_parent_ref=tags, append_lists=append_lists)

    def add_category(self, tags):
        pass


class CategoryTag(Element):
    """
    A Category Tag is a grouping of categories within SMC. Category Tags
    are used as filters (typically in the SMC) to change the view based
    on the tag.

    :ivar list(Category,CategoryTag) child_categories: child categories
    :ivar list(Category,CategoryTag) parent_categories: parent categories
    """

    typeof = "category_group_tag"
    child_categories = ElementList("category_child_ref")
    parent_categories = ElementList("parent_categories")

    @classmethod
    def create(cls, name, comment=None):
        """
        Create a CategoryTag. A category tag represents a group of categories
        or a group of category tags (nested groups). These are used to provide
        filtering views within the SMC and organize elements by user defined
        criteria.

        :param str name: name of category tag
        :param str comment: optional comment
        :raises CreateElementFailed: problem creating tag
        :return: instance with meta
        :rtype: CategoryTag
        """
        json = {"name": name, "comment": comment}
        return ElementCreator(cls, json)

    def remove_category(self, categories):
        """
        Remove a category from this Category Tag (group).

        :param list categories: categories to remove
        :type categories: list(str,Element)
        :return: None
        """
        categories = element_resolver(categories)
        diff = [
            category for category in self.data["category_child_ref"] if category not in categories
        ]
        self.update(category_child_ref=diff)


class SituationTag(Category):
    """
    A situation tag is used to categorize situations based on some sort
    of user defined criteria such as Botnet, Attacks, etc. These can help
    with categorization of specific threat event types.
    """

    typeof = "situation_tag"


class FilterExpression(Element):
    """
    A filter expression defines either a system element filter or a
    user defined filter based on an expression. For example, a system
    level filter is 'Match All'. For classes that allow filters as
    input, a filter expression can be used.
    """

    typeof = "filter_expression"


class QueryDataFilter(Element):
    """
    A Query Data Filter is an Internal filter container.
    Created on the fly when adding filtering context in some components
    """

    typeof = "query_data_filter"


class Location(Element):
    """
    Locations are used by elements to identify when they are behind a NAT
    connection. For example, if you have an engine that connects to the SMC
    across the internet using a public address, a location will be the tag
    applied to the Management Server (with contact address) and on the engine
    to identify how to connect. In this case, the location will map to a contact
    address using a public IP.

    .. note:: Locations require SMC API version >= 6.1
    """

    typeof = "location"

    @classmethod
    def create(cls, name, comment=None):
        """
        Create a location element

        :param name: name of location
        :raises CreateElementFailed: failed creating element with reason
        :return: instance with meta
        :rtype: Location
        """
        json = {"name": name, "comment": comment}

        return ElementCreator(cls, json)

    @property
    def used_on(self):
        """
        Return all NAT'd elements using this location.

        .. note::
            Available only in SMC version 6.2

        :return: elements used by this location
        :rtype: list
        """
        return [
            Element.from_meta(**element)
            for element in self.make_request(resource="search_nated_elements_from_location")
        ]


class Geolocation(Element):
    """
    Geolocation objects are mutable as of SMC version 6.6

    .. versionadded:: 0.7.0
    """

    typeof = "geolocation"

    @classmethod
    def create(cls, name, latitude, longitude, country_code="US", **kw):
        json = {
            "name": name,
            "latitude": latitude,
            "longitude": longitude,
            "country_code": country_code,
        }
        json.update(kw)
        return ElementCreator(cls, json)


class LogicalInterface(Element):
    """
    Logical interface is used on either inline or capture interfaces. If an
    engine has both inline and capture interfaces (L2 Firewall or IPS role),
    then you must use a unique Logical Interface on the interface type.

    Create a logical interface::

        LogicalInterface.create('mylogical_interface')
    """

    typeof = "logical_interface"

    @classmethod
    def create(cls, name, comment=None):
        """
        Create the logical interface

        :param str name: name of logical interface
        :param str comment: optional comment
        :raises CreateElementFailed: failed creating element with reason
        :return: instance with meta
        :rtype: LogicalInterface
        """
        json = {"name": name, "comment": comment}

        return ElementCreator(cls, json)


class MacAddress(Element):
    """
    Mac Address network element that can be used in L2 and IPS
    policy source and destination fields.

    Creating a MacAddress::

        >>> MacAddress.create(name='mymac', mac_address='22:22:22:22:22:22')
        MacAddress(name=mymac)
    """

    typeof = "mac_address"

    @classmethod
    def create(cls, name, mac_address, comment=None):
        """
        Create the Mac Address

        :param str name: name of mac address
        :param str mac_address: mac address notation
        :param str comment: optional comment
        :raises CreateElementFailed: failed creating element with reason
        :return: instance with meta
        :rtype: MacAddress
        """
        json = {"name": name, "address": mac_address, "comment": comment}

        return ElementCreator(cls, json)


class ContactAddress(NestedDict):
    """
    A contact address is used by elements to provide an alternative
    IP or FQDN mapping based on a location
    """

    @property
    def addresses(self):
        """
        List of addresses set as contact address

        :rtype: list
        """
        return self.data.get("addresses") or self.data.get("address")

    @property
    def location_ref(self):
        return self.data["location_ref"]

    @property
    def name(self):
        """
        Location name for this contact address

        :rtype: str
        """
        return self.location.name

    @cached_property
    def location(self):
        """
        Location name for contact address

        :rtype: str
        """
        return Element.from_href(self.location_ref)

    def __repr__(self):
        return "{}(location={},addresses={})".format(
            self.__class__.__name__, self.name, self.addresses
        )


class Blocklist(object):
    """
    Blocklist provides a simple container to add multiple block_list
    entries. Pass an instance of this to :class:`smc.core.engine.block_list_bulk`
    to upload to the engine.

    .. note:: This method requires SMC version >= 7.0
    """

    def __init__(self):
        self.entries = {}

    def add_entry(
        self,
        src,
        dst,
        duration=3600,
        src_port1=None,
        src_port2=None,
        src_proto="predefined_tcp",
        dst_port1=None,
        dst_port2=None,
        dst_proto="predefined_tcp",
    ):
        """
        Create a blocklist entry.

        A blocklist can be added directly from the engine node, or from
        the system context. If submitting from the system context, it becomes
        a global blocklist. This will return the properly formatted json
        to submit.

        :param src: source address, with cidr, i.e. 10.10.10.10/32 or 'any'
        :param dst: destination address with cidr, i.e. 1.1.1.1/32 or 'any'
        :param int duration: length of time to blocklist

        Both the system and engine context blocklist allow kw to be passed
        to provide additional functionality such as adding source and destination
        ports or port ranges and specifying the protocol. The following parameters
        define the ``kw`` that can be passed.

        The following example shows creating an engine context blocklist
        using additional kw::

            engine.block_list('1.1.1.1/32', '2.2.2.2/32', duration=3600,
                src_port1=1000, src_port2=1500, src_proto='predefined_udp',
                dst_port1=3, dst_port2=3000, dst_proto='predefined_udp')

        :param int src_port1: start source port to limit blocklist
        :param int src_port2: end source port to limit blocklist
        :param str src_proto: source protocol. Either 'predefined_tcp'
            or 'predefined_udp'. (default: 'predefined_tcp')
        :param int dst_port1: start dst port to limit blocklist
        :param int dst_port2: end dst port to limit blocklist
        :param str dst_proto: dst protocol. Either 'predefined_tcp'
            or 'predefined_udp'. (default: 'predefined_tcp')

        .. note:: if blocking a range of ports, use both src_port1 and
            src_port2, otherwise providing only src_port1 is adequate. The
            same applies to dst_port1 / dst_port2. In addition, if you provide
            src_portX but not dst_portX (or vice versa), the undefined port
            side definition will default to all ports.
        """
        self.entries.setdefault("entries", []).append(
            prepare_block_list(
                src, dst, duration, src_port1, src_port2, src_proto, dst_port1, dst_port2, dst_proto
            )
        )


class Blacklist(object):
    """
    Blacklist provides a simple container to add multiple blacklist
    entries. Pass an instance of this to :class:`smc.core.engine.blacklist_bulk`
    to upload to the engine.

    .. note:: This method requires SMC version < 7.0
    since this version, "blacklist" is renamed "block_list"
    """

    def __init__(self):
        self.entries = {}

    def add_entry(
            self,
            src,
            dst,
            duration=3600,
            src_port1=None,
            src_port2=None,
            src_proto="predefined_tcp",
            dst_port1=None,
            dst_port2=None,
            dst_proto="predefined_tcp",
    ):
        """
        Create a blacklist entry.

        A blacklist can be added directly from the engine node, or from
        the system context. If submitting from the system context, it becomes
        a global blacklist. This will return the properly formatted json
        to submit.

        :param src: source address, with cidr, i.e. 10.10.10.10/32 or 'any'
        :param dst: destination address with cidr, i.e. 1.1.1.1/32 or 'any'
        :param int duration: length of time to blacklist

        Both the system and engine context blacklist allow kw to be passed
        to provide additional functionality such as adding source and destination
        ports or port ranges and specifying the protocol. The following parameters
        define the ``kw`` that can be passed.

        The following example shows creating an engine context blacklist
        using additional kw::

            engine.blacklist('1.1.1.1/32', '2.2.2.2/32', duration=3600,
                src_port1=1000, src_port2=1500, src_proto='predefined_udp',
                dst_port1=3, dst_port2=3000, dst_proto='predefined_udp')

        :param int src_port1: start source port to limit blacklist
        :param int src_port2: end source port to limit blacklist
        :param str src_proto: source protocol. Either 'predefined_tcp'
            or 'predefined_udp'. (default: 'predefined_tcp')
        :param int dst_port1: start dst port to limit blacklist
        :param int dst_port2: end dst port to limit blacklist
        :param str dst_proto: dst protocol. Either 'predefined_tcp'
            or 'predefined_udp'. (default: 'predefined_tcp')

        .. note:: if blocking a range of ports, use both src_port1 and
            src_port2, otherwise providing only src_port1 is adequate. The
            same applies to dst_port1 / dst_port2. In addition, if you provide
            src_portX but not dst_portX (or vice versa), the undefined port
            side definition will default to all ports.
        """
        self.entries.setdefault("entries", []).append(
            prepare_blacklist(
                src, dst, duration, src_port1, src_port2, src_proto, dst_port1, dst_port2, dst_proto
            )
        )


class HTTPSInspectionExceptions(Element):
    """
    The HTTPS Inspection Exceptions element is a list of domains that are
    excluded from decryption and inspection. HTTPS Inspection Exceptions are
    used in a custom HTTPS service to define a list of domains for which HTTPS
    traffic is not decrypted. The custom HTTPS service must be used in a rule,
    and only traffic that matches the rule is excluded from decryption and
    inspection.

    .. note:: As of SMC 6.4.3, this is a read-only element
    """

    typeof = "tls_inspection_policy"


class RuleValidityTime(Element):
    """
    This represents a Rule Validity Time object used in access rules
    """

    typeof = "rule_validity_time"

    @classmethod
    def create(cls, name, rule_time_active='always', rule_time_zone='utc', rule_time_start=None,
               rule_time_end=None, rule_time_repeat_start=None, rule_time_repeat_end=None,
               week_day=None, month_day=None,
               yearly_day_start=None, yearly_day_end=None,
               yearly_month_start=None, yearly_month_end=None):
        """
        Create a Validity Time element::

            RuleValidityTime.create(name='ValidityTime', rule_time_active='always',
                        rule_time_start='2019-12-24 08:52:15',
                        rule_time_end='2020-12-24 08:52:15')

        Available attributes:
        :param str name: name for this element
        :param str rule_time_active: periodicity for validity time element active.
            Value should be one of those:
            'always', 'time_of_day', 'day_of_week', 'day_of_month', 'date_of_year'
        :param str rule_time_zone: Time zone for this element
            Value should be one of those: 'utc', 'engine_time'
        :param str rule_time_start: time for rule enabling
            Following format should be used: 'YYYY-MM-DD HH:MM:SS', ie '2019-12-24 08:52:15'
        :param str rule_time_end: time for rule disabling
            Following format should be used: 'YYYY-MM-DD HH:MM:SS', ie '2019-12-24 08:52:15'
        :param str rule_time_repeat_start: time to enable rule in repetition
            Following format should be used: 'HH:MM', ie '08:15'
        :param str rule_time_repeat_end: time to disable rule in repetition
            Following format should be used: 'HH:MM', ie '08:15'
        :param str week_day: day of the week to repeat rule enabling
            Value should be one of those: 'mo', 'tu', 'we', 'th', 'fr', sa', 'su'
        :param str month_day: day of the month to repeat rule enabling
            Value is a number comprised between '1' and '31'
        :param str yearly_day_start: day of the year to start rule enabling
            Value is a number comprised between '1' and '366'
        :param str yearly_day_end: day of the year to end rule enabling
            Value is a number comprised between '1' and '366'
        :param str yearly_month_start: month of the year to start rule enabling
            Value is a number comprised between '1' and '12'
        :param str yearly_month_end: month of the year to end rule enabling
            Value is a number comprised between '1' and '12'
        """

        json = {
            "name": name, "rule_time_active": rule_time_active,
            "rule_time_zone": rule_time_zone, "rule_time_start": rule_time_start,
            "rule_time_end": rule_time_end, "rule_time_repeat_start": rule_time_repeat_start,
            "rule_time_repeat_end": rule_time_repeat_end, "week_day": week_day,
            "month_day": month_day, "yearly_day_start": yearly_day_start,
            "yearly_day_end": yearly_day_end, "yearly_month_start": yearly_month_start,
            "yearly_month_end": yearly_month_end
        }

        return ElementCreator(cls, json)


class UpdateServerProfile(Element):
    """
    This represents Update Server Profile (aka Update Service)
    """
    typeof = "update_service"

    @classmethod
    def create(cls, name, retry=0, timeout=0, urls=None, tls_profile_ref=None, comment=None):
        """
        Create a UpdateServerProfile. A Update Server Profile represents a update service.
        These are used to provide server providing the updates within the SMC.

        :param str name: name of category tag.
        :param int retry: number of retries.
        :param int timeout: connection timeout.
        :param list urls: list of URL, at least one is mandatory.
        :param str tls_profile_ref: TLS profile used to connect to the server(s).
        :param str comment: optional comment.
        :raises CreateElementFailed: problem creating tag.
        :return: instance with meta.
        :rtype: CategoryTag.
        """

        json = {"name": name, "retry": retry, "timeout": timeout,
                "tls_profile_ref": element_resolver(tls_profile_ref), "comment": comment}
        if urls:
            ordered_url = []
            for rank, url in enumerate(urls):
                ordered_url.append({
                    "rank": rank,
                    "url": url
                })
            json.update(ordered_url=ordered_url)
        return ElementCreator(cls, json)

    @property
    def retry(self):
        """
        number of retries
        """
        return self.data.get("retry")

    @property
    def timeout(self):
        """
        It is connection timeout
        """
        return self.data.get("timeout")

    @property
    def ordered_url(self):
        """
        The list of url used by update service.
        :rtype List(url)
        """
        return self.data.get("ordered_url")

    @property
    def tls_profile(self):
        """
        TLS profile used to connect to the server(s).
        :rtype TLSProfile
        """
        return Element.from_href(self.data.get("tls_profile_ref"))


def prepare_blacklist(
    src,
    dst,
    duration=3600,
    src_port1=None,
    src_port2=None,
    src_proto="predefined_tcp",
    dst_port1=None,
    dst_port2=None,
    dst_proto="predefined_tcp",
):
    """
    Create a blacklist entry.

    A blacklist can be added directly from the engine node, or from
    the system context. If submitting from the system context, it becomes
    a global blacklist. This will return the properly formatted json
    to submit.

    :param src: source address, with cidr, i.e. 10.10.10.10/32 or 'any'
    :param dst: destination address with cidr, i.e. 1.1.1.1/32 or 'any'
    :param int duration: length of time to blacklist

    Both the system and engine context blacklist allow kw to be passed
    to provide additional functionality such as adding source and destination
    ports or port ranges and specifying the protocol. The following parameters
    define the ``kw`` that can be passed.

    The following example shows creating an engine context blacklist
    using additional kw::

        engine.blacklist('1.1.1.1/32', '2.2.2.2/32', duration=3600,
            src_port1=1000, src_port2=1500, src_proto='predefined_udp',
            dst_port1=3, dst_port2=3000, dst_proto='predefined_udp')

    :param int src_port1: start source port to limit blacklist
    :param int src_port2: end source port to limit blacklist
    :param str src_proto: source protocol. Either 'predefined_tcp'
        or 'predefined_udp'. (default: 'predefined_tcp')
    :param int dst_port1: start dst port to limit blacklist
    :param int dst_port2: end dst port to limit blacklist
    :param str dst_proto: dst protocol. Either 'predefined_tcp'
        or 'predefined_udp'. (default: 'predefined_tcp')

    .. note:: if blocking a range of ports, use both src_port1 and
        src_port2, otherwise providing only src_port1 is adequate. The
        same applies to dst_port1 / dst_port2. In addition, if you provide
        src_portX but not dst_portX (or vice versa), the undefined port
        side definition will default to all ports.

        .. note:: This method requires SMC version < 7.0
    """

    json = {}

    directions = {src: "end_point1", dst: "end_point2"}

    for direction, key in directions.items():
        json[key] = (
            {"address_mode": "any"}
            if "any" in direction.lower()
            else {"address_mode": "address", "ip_network": direction}
        )

    if src_port1:
        json.setdefault("end_point1").update(
            port1=src_port1, port2=src_port2 or src_port1, port_mode=src_proto
        )

    if dst_port1:
        json.setdefault("end_point2").update(
            port1=dst_port1, port2=dst_port2 or dst_port1, port_mode=dst_proto
        )

    json.update(duration=duration)

    return json


def prepare_block_list(
        src,
        dst,
        duration=3600,
        src_port1=None,
        src_port2=None,
        src_proto="predefined_tcp",
        dst_port1=None,
        dst_port2=None,
        dst_proto="predefined_tcp",
):
    """
    Create a block_list entry.

    A blocklist can be added directly from the engine node, or from
    the system context. If submitting from the system context, it becomes
    a global blocklist. This will return the properly formatted json
    to submit.

    :param src: source address, with cidr, i.e. 10.10.10.10/32 or 'any'
    :param dst: destination address with cidr, i.e. 1.1.1.1/32 or 'any'
    :param int duration: length of time to blocklist

    Both the system and engine context blocklist allow kw to be passed
    to provide additional functionality such as adding source and destination
    ports or port ranges and specifying the protocol. The following parameters
    define the ``kw`` that can be passed.

    The following example shows creating an engine context blocklist
    using additional kw::

        engine.block_list('1.1.1.1/32', '2.2.2.2/32', duration=3600,
            src_port1=1000, src_port2=1500, src_proto='predefined_udp',
            dst_port1=3, dst_port2=3000, dst_proto='predefined_udp')

    :param int src_port1: start source port to limit blocklist
    :param int src_port2: end source port to limit blocklist
    :param str src_proto: source protocol. Either 'predefined_tcp'
        or 'predefined_udp'. (default: 'predefined_tcp')
    :param int dst_port1: start dst port to limit blocklist
    :param int dst_port2: end dst port to limit blocklist
    :param str dst_proto: dst protocol. Either 'predefined_tcp'
        or 'predefined_udp'. (default: 'predefined_tcp')

    .. note:: if blocking a range of ports, use both src_port1 and
        src_port2, otherwise providing only src_port1 is adequate. The
        same applies to dst_port1 / dst_port2. In addition, if you provide
        src_portX but not dst_portX (or vice versa), the undefined port
        side definition will default to all ports.

    .. note:: This method requires SMC version >= 7.0
    """
    return prepare_blacklist(src=src,
                             dst=dst,
                             duration=duration,
                             src_port1=src_port1,
                             src_port2=src_port2,
                             src_proto=src_proto,
                             dst_port1=dst_port1,
                             dst_port2=dst_port2,
                             dst_proto=dst_proto
                             )
