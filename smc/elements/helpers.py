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
Helper functions to retrieve various elements that may be required by specific
constructors.
"""
from __future__ import annotations

from typing import Any, Optional, Union, Iterator

from smc.elements.network import Zone
from smc.policy.qos import QoSPolicy
from smc.administration.system import AdminDomain
from smc.elements.other import LogicalInterface, Location
from smc.api.exceptions import ElementNotFound
from smc.base.collection import Search


def location_helper(name: Any, search_only: bool = False) -> Optional[str]:
    """
    Location finder by name. If location doesn't exist, create it
    and return the href

    :param str,Element name: location to resolve. If the location is
        by name, it will be retrieved or created, if href, returned
        and if Location, href returned. If None, settings an elements
        location to None will set it to the Default location.
    :param bool search_only: only search for the location, if not found
        do not create
    :return str href: href of location if search_only is not False
    :rtype: str or None
    """
    try:
        return name.href
    except AttributeError:
        if name and name.startswith("http"):
            return name
    except ElementNotFound:
        return Location.create(name=name.name).href if not search_only else None

    # Get all locations; tmp to support earlier 6.x versions.
    if name is not None:
        locations = [
            location for location in Search.objects.entry_point("location") if location.name == name
        ]
        if not locations:
            return Location.create(name=name).href if not search_only else None
        return locations[0].href


def zone_helper(zone: Any) -> Optional[str]:
    """
    Zone finder by name. If zone doesn't exist, create it and
    return the href

    :param str zone: name of zone (if href, will be returned as is)
    :return str href: href of zone
    """
    if zone is None:
        return None
    elif isinstance(zone, Zone):
        return zone.href
    elif zone.startswith("http"):
        return zone
    return Zone.get_or_create(name=zone).href


def qos_policy_helper(qos_policy: Any) -> Optional[str]:
    """
    QoS Policy finder by name. If QoS Policy doesn't exist, create it and
    return the href

    :param str qos_policy: name of QoS Policy (if href, will be returned as is)
    :return str href: href of QoS Policy
    """
    if qos_policy is None:
        return None
    elif isinstance(qos_policy, QoSPolicy):
        return qos_policy.href
    elif qos_policy.startswith("http"):
        return qos_policy
    return QoSPolicy.get_or_create(name=qos_policy).href


def logical_intf_helper(interface: Any) -> Optional[str]:
    """
    Logical Interface finder by name. Create if it doesn't exist.
    This is useful when adding logical interfaces to for inline
    or capture interfaces.

    :param interface: logical interface name
    :return str href: href of logical interface
    """
    if interface is None:
        return LogicalInterface.get_or_create(name="default_eth").href
    elif isinstance(interface, LogicalInterface):
        return interface.href
    elif interface.startswith("http"):
        return interface
    return LogicalInterface.get_or_create(name=interface).href


def domain_helper(name: Any) -> Optional[str]:
    """
    Find a domain based on name

    :return: href of domain
    :rtype: str
    """
    try:
        return AdminDomain(name).href
    except ElementNotFound:
        pass
