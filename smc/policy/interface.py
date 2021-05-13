"""
.. versionadded:: 0.5.6
    Requires engine version >=6.3, SMC >=6.3

Interface Policies are applied at the engine level when layer 3 single
engines or cluster layer 3 engines have layer 2 interfaces. The configuration
is identical to creating Layer 2 Rules for layer 2 or IPS engines.

"""
from smc.base.collection import rule_collection
from smc.policy.policy import Policy
from smc.policy.rule import IPv4Layer2Rule, EthernetRule
from smc.api.exceptions import (
    ElementNotFound,
    LoadPolicyFailed,
    CreateElementFailed,
    CreatePolicyFailed,
)
from smc.base.model import ElementCreator


class InterfaceRule(object):
    """
    Layer 2 Interface Rules are the same as Layer 2 Engine/IPS rules.
    """

    @property
    def layer2_ipv4_access_rules(self):
        """
        Layer2 IPv4 access rule

        :rtype: rule_collection(IPv4Layer2Rule)
        """
        return rule_collection(self.get_relation("l2_interface_ipv4_access_rules"), IPv4Layer2Rule)

    @property
    def layer2_ipv6_access_rules(self):
        """
        Layer 2 IPv6 access rule

        """
        # l2_interface_ipv6_access_rules
        # return create_collection(self.layer2_ipv6_access_rules)
        pass

    @property
    def layer2_ethernet_rules(self):
        """
        Layer 2 Ethernet access rule

        :rtype: rule_collection(EthernetRule)
        """
        return rule_collection(self.get_relation("l2_interface_ethernet_rules"), EthernetRule)


class InterfacePolicy(InterfaceRule, Policy):
    """
    Layer 2 Interface Policy represents a set of rules applied to layer 2
    interfaces installed on a single or cluster layer 3 engine. Set the interface
    policy on the engine properties.
    Interface policies do not have inspection policies and instead inherit
    from the engines primary policy.

    Instance Resources:

    :ivar layer2_ipv4_access_rules: :py:class:`~Layer2Rule.layer2_ipv4_access_rules`
    :ivar layer2_ipv6_access_rules: :py:class:`~Layer2Rule.layer2_ipv6_access_rules`
    :ivar layer2_ethernet_rules: :py:class:`~Layer2Rule.layer2_ethernet_rules`
    """

    typeof = "l2_interface_policy"

    @classmethod
    def create(cls, name, template):
        """
        Create a new Layer 2 Interface Policy.

        :param str name: name of policy
        :param str template: name of the NGFW Engine template to base policy on
        :raises LoadPolicyFailed: cannot find policy by name
        :raises CreatePolicyFailed: cannot create policy with reason
        :return: Layer2InterfacePolicy
        """
        try:
            fw_template = InterfaceTemplatePolicy(template).href
        except ElementNotFound:
            raise LoadPolicyFailed(
                "Cannot find specified layer2 firewall template: {}".format(template)
            )

        json = {"name": name, "template": fw_template}
        try:
            return ElementCreator(cls, json)
        except CreateElementFailed as err:
            raise CreatePolicyFailed(err)

    def inspection_policy(self):
        pass


class InterfaceTemplatePolicy(InterfaceRule, Policy):
    """
    Interface Template Policy. Required when creating a new
    Interface Policy. Useful for containing global rules or
    best practice configurations which will be inherited by
    the assigned policy.
    ::

        print(list(InterfaceTemplatePolicy.objects.all())

    """

    typeof = "l2_interface_template_policy"

    def inspection_policy(self):
        pass

    def upload(self):
        pass  # Not supported on the template
