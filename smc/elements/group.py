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
Groups that are used for element types, such as TCPServiceGroup,
Group (generic), etc. All group types inherit from GroupMixin which
allow for modifications of existing groups and their members.
"""
from __future__ import annotations

from typing import Any, Callable, Optional, Union, Iterator, cast

from smc.api.exceptions import ElementNotFound
from smc.base.model import Element, ElementCreator
from smc.base.util import element_resolver
from smc.compat import min_smc_version


class GroupMixin(object):
    """
    Methods associated with handling modification of Group
    objects for existing elements
    """

    #: provided by the concrete element class (ElementBase)
    data: Any
    update: Callable[..., Any]

    @classmethod
    def update_or_create(
        cls,
        append_lists: bool = True,
        with_status: bool = False,
        remove_members: bool = False,
        **kwargs: Any,
    ) -> Any:
        """
        Update or create group entries. If the group exists, the members
        will be updated. Set append_lists=True to add new members to
        the list, or False to reset the list to the provided members. If
        setting remove_members, this will override append_lists if set.
        ``members`` is optional: without it (or with an empty list) the
        members are left untouched and only the other attributes are
        updated. See :meth:`update_members`.

        :param bool append_lists: add to existing members, if any
        :param bool remove_members: remove specified members instead of appending
            or overwriting
        :param dict kwargs: keyword arguments to satisfy the `create`
            constructor if the group needs to be created.
        :raises CreateElementFailed: could not create element with reason
        :return: element instance by type
        :rtype: Element
        """
        was_created, was_modified = False, False
        try:
            element = cast(Any, cls).get(kwargs.get("name"))
            was_modified = element.update_members(append_lists=append_lists,
                                                  remove_members=remove_members,
                                                  **kwargs)
        except ElementNotFound:
            element = cast(Any, cls).create(**kwargs)
            was_created = True

        if with_status:
            return element, was_modified, was_created
        return element

    def update_members(
        self,
        members: Any = None,
        append_lists: bool = False,
        remove_members: bool = False,
        **kwargs: Any,
    ) -> bool:
        """
        Update group members with member list. Set append_lists=True
        to append to existing members, or append_lists=False to overwrite.

        The method is idempotent: the SMC is only updated, and True only
        returned, when something really changes. Members are compared as
        an unordered set of hrefs, so the order of ``members`` is irrelevant.

        - overwrite (default): replace the members with ``members``
        - ``append_lists=True``: only the members not already in the group
          are added
        - ``remove_members=True``: only the members present in the group are
          removed (takes precedence over ``append_lists``)

        If ``members`` is None or empty, the members are left untouched and
        only the other attributes given in ``kwargs`` (comment, ...) that
        differ from the current ones are updated. An empty list does **not**
        clear the group, use :meth:`empty_members` for that.

        :param list members: new members for group by href or Element
        :type members: list[str, Element]
        :param bool append_lists: whether to append
        :param bool remove_members: remove members from the group
        :param kwargs: other attributes to update (e.g. comment)
        :return: True if the group was modified on the SMC, False otherwise
        :rtype: bool
        """
        requested = {element_resolver(member) for member in members or []}
        current = set(self.members)

        # Group membership is unordered and a member can only occur once.
        if not requested:
            target, members_changed = requested, False
        elif remove_members:
            target, append_lists = current - requested, False
            members_changed = target != current
        elif append_lists:
            target = requested - current
            members_changed = bool(target)
        else:
            target = requested
            members_changed = target != current

        if members_changed:
            self.update(element=list(target), append_lists=append_lists, **kwargs)
            return True

        # Membership untouched or already satisfied: only send the other
        # attributes that differ
        changed = {
            key: value for key, value in kwargs.items()
            if (self.data.get(key) or None) != (value or None)
        }
        if changed:
            self.update(**changed)
            return True
        return False

    def obtain_members(self) -> list[Any]:
        """
        Obtain all group members from this group

        :return: group members as elements
        :rtype: list(Element)
        """
        return [Element.from_href(member) for member in self.data.get("element", [])]

    def empty_members(self) -> None:
        """
        Empty members from group

        :return: None
        """
        self.update(element=[])

    @property
    def members(self) -> list[Any]:
        """
        Return members in raw href format. If you want to obtain a
        resolved list of elements as instance of Element, call
        `~obtain_members`.

        :rtype: list
        """
        return self.data.get("element", [])


class Group(GroupMixin, Element):  # type: ignore[misc]  # update_or_create intentionally differs from Element
    """
    Class representing a Group object used in access rules
    Groups can hold other network element types as well as
    other groups.

    Create a group element::

        Group.create('mygroup') #no members

    Group with members::

        Group.create('mygroup', [Host('kali'), Network('mynetwork')])

    Available attributes:

    :ivar list element: list of elements by href. Call `~obtain_members` to
        retrieve the resolved list of elements.
    """

    typeof = "group"

    @classmethod
    def create(
        cls,
        name: str,
        members: Optional[Any] = None,
        comment: Optional[str] = None,
        is_monitored: bool = False,
    ) -> "Group":
        """
        Create the group

        :param str name: Name of element
        :param list members: group members by element names
        :type members: str,Element
        :param str comment: optional comment
        :param bool is_monitored: optional option
            Enable or not monitoring of the group. Default: False
        :raises CreateElementFailed: element creation failed with reason
        :return: instance with meta
        :rtype: Group
        """
        elements = [] if members is None else element_resolver(members)
        json = {"name": name, "element": elements, "comment": comment, "is_monitored": is_monitored}

        return ElementCreator(cls, json)


class ConnectionSynchronizationGroup(Element):
    """
    Class representing a Connection Synchronization Group object used in single engine for
    high availability.
    The elements cannot be added directly in the group.
    They are added by selecting the group in engine.

    Create a group element::

        ConnectionSynchronizationGroup.create('mygroup') #no members

    Available attributes:

    :ivar list element: list of elements by href. Call `~obtain_members` to
        retrieve the resolved list of elements.
    """

    typeof = "connection_sync_group"

    @classmethod
    def create(  # type: ignore[return]  # implicit None on old SMC
        cls,
        name: str,
        comment: Optional[str] = None,
        is_monitored: bool = False,
    ) -> Optional["ConnectionSynchronizationGroup"]:
        """
        Create the group

        :param str name: Name of element
        :param str comment: optional comment
        :param bool is_monitored: optional option
            Enable or not monitoring of the group. Default: False
        :raises CreateElementFailed: element creation failed with reason
        :return: instance with meta
        :rtype: ConnectionSynchronizationGroup
        """
        if min_smc_version("7.2"):
            json = {"name": name, "comment": comment, "is_monitored": is_monitored}

            return ElementCreator(cls, json)

    def obtain_members(self) -> list[Any]:
        """
        Obtain all group members from this group

        :return: group members as elements
        :rtype: list(Element)
        """
        return [Element.from_href(member) for member in self.data.get("element", [])]

    @property
    def members(self) -> list[Any]:
        """
        Return members in raw href format. If you want to obtain a
        resolved list of elements as instance of Element, call
        `~obtain_members`.

        :rtype: list
        """
        return self.data.get("element", [])


class ServiceGroup(GroupMixin, Element):  # type: ignore[misc]  # update_or_create intentionally differs from Element
    """
    Represents a service group in SMC. Used for grouping
    objects by service. Services can be "mixed" TCP/UDP/ICMP/
    IPService, Protocol or other Service Groups.
    Element is an href to the location of the resource.

    Create a TCP and UDP Service and add to ServiceGroup::

        tcp1 = TCPService.create('api-tcp1', 5000)
        udp1 = UDPService.create('api-udp1', 5001)
        ServiceGroup.create('servicegroup', element=[tcp1, udp1])

    Available attributes:

    :ivar list element: list of elements by href. Call `~obtain_members` to
        retrieved the resolved list of elements.
    """

    typeof = "service_group"

    @classmethod
    def create(
        cls,
        name: str,
        members: Optional[Any] = None,
        comment: Optional[str] = None,
    ) -> "ServiceGroup":
        """
        Create the TCP/UDP Service group element

        :param str name: name of service group
        :param list members: elements to add by href or Element
        :type members: list(str,Element)
        :raises CreateElementFailed: element creation failed with reason
        :return: instance with meta
        :rtype: ServiceGroup
        """
        elements = [] if members is None else element_resolver(members)
        json = {"name": name, "element": elements, "comment": comment}

        return ElementCreator(cls, json)


class TCPServiceGroup(GroupMixin, Element):  # type: ignore[misc]  # update_or_create intentionally differs from Element
    """
    Represents a TCP Service group

    Create TCP Services and add to TCPServiceGroup::

        tcp1 = TCPService.create('api-tcp1', 5000)
        tcp2 = TCPService.create('api-tcp2', 5001)
        ServiceGroup.create('servicegroup', element=[tcp1, tcp2])

    Available attributes:

    :ivar list element: list of elements by href. Call `~obtain_members` to
        retrieved the resolved list of elements.
    """

    typeof = "tcp_service_group"

    @classmethod
    def create(
        cls,
        name: str,
        members: Optional[Any] = None,
        comment: Optional[str] = None,
    ) -> "TCPServiceGroup":
        """
        Create the TCP Service group

        :param str name: name of tcp service group
        :param list element: tcp services by element or href
        :type element: list(str,Element)
        :raises CreateElementFailed: element creation failed with reason
        :return: instance with meta
        :rtype: TCPServiceGroup
        """
        element = [] if members is None else element_resolver(members)
        json = {"name": name, "element": element, "comment": comment}

        return ElementCreator(cls, json)


class UDPServiceGroup(GroupMixin, Element):  # type: ignore[misc]  # update_or_create intentionally differs from Element
    """
    UDP Service Group
    Used for storing UDP Services or UDP Service Groups.

    Create two UDP Services and add to UDP service group::

        udp1 = UDPService.create('udp-svc1', 5000)
        udp2 = UDPService.create('udp-svc2', 5001)
        UDPServiceGroup.create('udpsvcgroup', element=[udp1, udp2])

    Available attributes:

    :ivar list element: list of elements by href. Call `~obtain_members` to
        retrieved the resolved list of elements.
    """

    typeof = "udp_service_group"

    @classmethod
    def create(
        cls,
        name: str,
        members: Optional[Any] = None,
        comment: Optional[str] = None,
    ) -> "UDPServiceGroup":
        """
        Create the UDP Service group

        :param str name: name of service group
        :param list element: UDP services or service group by reference
        :type members: list(str,Element)
        :raises CreateElementFailed: element creation failed with reason
        :return: instance with meta
        :rtype: UDPServiceGroup
        """
        element = [] if members is None else element_resolver(members)
        json = {"name": name, "element": element, "comment": comment}

        return ElementCreator(cls, json)


class IPServiceGroup(GroupMixin, Element):  # type: ignore[misc]  # update_or_create intentionally differs from Element
    """
    IP Service Group
    Used for storing IP Services or IP Service Groups

    Available attributes:

    :ivar list element: list of elements by href. Call `~obtain_members` to
        retrieved the resolved list of elements.
    """

    typeof = "ip_service_group"

    @classmethod
    def create(
        cls,
        name: str,
        members: Optional[Any] = None,
        comment: Optional[str] = None,
    ) -> "IPServiceGroup":
        """
        Create the IP Service group element

        :param str name: name of service group
        :param list element: IP services or IP service groups by href
        :type members: list(str,Element)
        :raises CreateElementFailed: element creation failed with reason
        :return: instance with meta
        :rtype: IPServiceGroup
        """
        elements = [] if members is None else element_resolver(members)
        json = {"name": name, "element": elements, "comment": comment}

        return ElementCreator(cls, json)


class ICMPServiceGroup(GroupMixin, Element):  # type: ignore[misc]  # update_or_create intentionally differs from Element
    """
    IP Service Group
    Used for storing IP Services or IP Service Groups

    Available attributes:

    :ivar list element: list of elements by href. Call `~obtain_members` to
        retrieved the resolved list of elements.
    """

    typeof = "icmp_service_group"

    @classmethod
    def create(
        cls,
        name: str,
        members: Optional[Any] = None,
        comment: Optional[str] = None,
    ) -> "ICMPServiceGroup":
        """
        Create the IP Service group element

        :param str name: name of service group
        :param list element: IP services or IP service groups by href
        :type members: list(str,Element)
        :raises CreateElementFailed: element creation failed with reason
        :return: instance with meta
        :rtype: ICMPServiceGroup
        """
        elements = [] if members is None else element_resolver(members)
        json = {"name": name, "element": elements, "comment": comment}

        return ElementCreator(cls, json)


class URLCategoryGroup(Element):
    typeof = "url_category_group"


class EthernetServiceGroup(GroupMixin, Element):  # type: ignore[misc]  # update_or_create intentionally differs from Element
    """
    This represents an Ethernet Service Group, it groups a list of Ethernet Services.

    Create EthernetService and add to EthernetServiceGroup::

        es1 = EthernetService.create('EthernetService1', frame_type="eth2",
                                                  protocol_agent_ref=protocol, value1='1',
                                                  value2='2', comment=COMMENT)
        es2 = EthernetService.create('EthernetService2', frame_type="eth2",
                                                  protocol_agent_ref=protocol, value1='1',
                                                  value2='2', comment=COMMENT)
        EthernetServiceGroup.create('ethernetservicegroup', element=[es1, es2])
    """

    typeof = "ethernet_service_group"

    @classmethod
    def create(
        cls,
        name: str,
        members: Optional[Any] = None,
        comment: Optional[str] = None,
    ) -> "EthernetServiceGroup":
        """
        Create the Ethernet Service Group

        :param str name: name of ethernet service group.
        :param list(EthernetService) members: The elements that are included in the
            EthernetServiceGroup.
        :param str comment: Optional comment.
        :raises CreateElementFailed: element creation failed with reason.
        :return: instance with meta
        :rtype: EthernetServiceGroup
        """
        element = [] if members is None else element_resolver(members)
        json = {"name": name, "element": element, "comment": comment}
        return ElementCreator(cls, json)


class RpcServiceGroup(GroupMixin, Element):  # type: ignore[misc]  # update_or_create intentionally differs from Element
    """
    This represents a SUN-RPC Service Group, it groups a list of SUN-RPC Services.
    """
    typeof = "rpc_service_group"

    @classmethod
    def create(
        cls,
        name: str,
        members: Optional[Any] = None,
        comment: Optional[str] = None,
    ) -> "RpcServiceGroup":
        """
        Create the SUN-RPC Service Group element.

        :param str name: name of rpc service group
        :param list members: The elements that are included in the Service Group.
        :type members: list(str,Element)
        :param str comment: optional comment.
        :raises CreateElementFailed: element creation failed with reason
        :return: instance with meta
        :rtype: RpcServiceGroup
        """
        elements = [] if members is None else element_resolver(members)
        json = {"name": name, "element": elements, "comment": comment}

        return ElementCreator(cls, json)
