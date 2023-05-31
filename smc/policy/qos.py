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
QoS Policy that would be applied to a rule set or physical / tunnel interface.
QoS can also be applied at the VLAN level of an interface.
"""
from smc.base.model import Element, ElementCreator


class QoSPolicy(Element):
    """
    This represents a QoS Policy.
    A set of rules for Bandwidth Management and Traffic Prioritization for traffic that
    has a particular QoS Class, or rules for assigning QoS Classes based on a DSCP Match
    found in the traffic.
    """

    typeof = "qos_policy"


class LinkSelection(object):
    def __init__(self, bandwidth=0, jitter=0, latency=0, packet_loss=0, stability=0):
        self.bandwidth = bandwidth
        self.jitter = jitter
        self.latency = latency
        self.packet_loss = packet_loss
        self.stability = stability
        link_selection_json = {}
        link_selection_json.update(jitter=jitter)
        link_selection_json.update(latency=latency)
        link_selection_json.update(bandwidth=bandwidth)
        link_selection_json.update(packet_loss=packet_loss)
        link_selection_json.update(stability=stability)
        self.link_selection = link_selection_json

    def jitter(self):
        return self.jitter

    def latency(self):
        return self.latency

    def bandwidth(self):
        return self.bandwidth

    def packet_loss(self):
        return self.packet_loss

    def stability(self):
        return self.stability


class QoSClass(Element):
    """
    This represents a QoS Class.
    It is an element that works as a link between a rule in a QoS Policy and one or
    more Firewall Actions.
    The traffic allowed in the access rule is assigned the QoS Class defined for the rule, and the
    QoS class is used as the matching criteria for applying QoS Policy rules.
    """

    typeof = "qos_class"

    @classmethod
    def create(cls, name, comment=None, lsv_override=None, link_selection=None):
        """
        Create the QoS Class.

        :param str name: name of QoS Class
        :param str comment: optional comment
        :param bool lsv_override: optional can be True or False
        :param object link_selection : optional value to override link selection value
        :raises CreateElementFailed: failed creating element with reason
        :return: instance with meta
        :rtype: QoSClass
        """
        json = {"name": name, "comment": comment}
        link_selection = link_selection
        if lsv_override:
            json.update(lsv_override=lsv_override)
        if link_selection:
            json.update(link_selection=link_selection.link_selection)
        return ElementCreator(cls, json)

    @property
    def link_selection(self):
        """
        link_selection
        """
        return self.data.get("link_selection")
