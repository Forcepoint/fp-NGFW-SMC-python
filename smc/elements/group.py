"""
Groups that are used for element types, such as TCPServiceGroup,
Group (generic), etc. All group types inherit from GroupMixin which
allow for modifications of existing groups and their members.
"""
from smc.base.model import Element, ElementCreator
from smc.api.exceptions import ElementNotFound
from smc.base.util import element_resolver


class GroupMixin(object):
    """
    Methods associated with handling modification of Group
    objects for existing elements
    """

    @classmethod
    def update_or_create(cls, append_lists=True, with_status=False, remove_members=False, **kwargs):
        """
        Update or create group entries. If the group exists, the members
        will be updated. Set append_lists=True to add new members to
        the list, or False to reset the list to the provided members. If
        setting remove_members, this will override append_lists if set.

        :param bool append_lists: add to existing members, if any
        :param bool remove_members: remove specified members instead of appending
            or overwriting
        :paran dict kwargs: keyword arguments to satisfy the `create`
            constructor if the group needs to be created.
        :raises CreateElementFailed: could not create element with reason
        :return: element instance by type
        :rtype: Element
        """
        was_created, was_modified = False, False
        element = None
        try:
            element = cls.get(kwargs.get("name"))
            was_modified = element.update_members(
                kwargs.get("members", []), append_lists=append_lists, remove_members=remove_members
            )
        except ElementNotFound:
            element = cls.create(kwargs.get("name"), members=kwargs.get("members", []))
            was_created = True

        if with_status:
            return element, was_modified, was_created
        return element

    def update_members(self, members, append_lists=False, remove_members=False):
        """
        Update group members with member list. Set append=True
        to append to existing members, or append=False to overwrite.

        :param list members: new members for group by href or Element
        :type members: list[str, Element]
        :param bool append_lists: whether to append
        :param bool remove_members: remove members from the group
        :return: bool was modified or not
        """
        if members:
            elements = [element_resolver(element) for element in members]
            if remove_members:
                element = [e for e in self.members if e not in elements]
                if set(element) == set(self.members):
                    remove_members = element = False
                append_lists = False
            elif append_lists:
                element = [e for e in elements if e not in self.members]
            else:
                element = list(set(elements))

            if element or remove_members:
                self.update(element=element, append_lists=append_lists)
                return True

        return False

    def obtain_members(self):
        """
        Obtain all group members from this group

        :return: group members as elements
        :rtype: list(Element)
        """
        return [Element.from_href(member) for member in self.data.get("element", [])]

    def empty_members(self):
        """
        Empty members from group

        :return: None
        """
        self.update(element=[])

    @property
    def members(self):
        """
        Return members in raw href format. If you want to obtain a
        resolved list of elements as instance of Element, call
        `~obtain_members`.

        :rtype: list
        """
        return self.data.get("element", [])


class Group(GroupMixin, Element):
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
        retrieved the resolved list of elements.
    """

    typeof = "group"

    @classmethod
    def create(cls, name, members=None, comment=None, is_monitored=False):
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


class ServiceGroup(GroupMixin, Element):
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
    def create(cls, name, members=None, comment=None):
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


class TCPServiceGroup(GroupMixin, Element):
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
    def create(cls, name, members=None, comment=None):
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


class UDPServiceGroup(GroupMixin, Element):
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
    def create(cls, name, members=None, comment=None):
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


class IPServiceGroup(GroupMixin, Element):
    """
    IP Service Group
    Used for storing IP Services or IP Service Groups

    Available attributes:

    :ivar list element: list of elements by href. Call `~obtain_members` to
        retrieved the resolved list of elements.
    """

    typeof = "ip_service_group"

    @classmethod
    def create(cls, name, members=None, comment=None):
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


class ICMPServiceGroup(GroupMixin, Element):
    """
    IP Service Group
    Used for storing IP Services or IP Service Groups

    Available attributes:

    :ivar list element: list of elements by href. Call `~obtain_members` to
        retrieved the resolved list of elements.
    """

    typeof = "icmp_service_group"

    @classmethod
    def create(cls, name, members=None, comment=None):
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
