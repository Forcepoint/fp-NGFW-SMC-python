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
    def create(cls, name, comment=None):
        """
        Create the QoS Class.

        :param str name: name of QoS Class
        :param str comment: optional comment
        :raises CreateElementFailed: failed creating element with reason
        :return: instance with meta
        :rtype: QoSClass
        """
        json = {"name": name, "comment": comment}

        return ElementCreator(cls, json)
