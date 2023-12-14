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

Interface Policies are applied at the engine level when layer 3 single
engines or cluster layer 3 engines have layer 2 interfaces. The configuration
is identical to creating Layer 2 Rules for layer 2 or IPS engines.

"""
from smc.base.collection import rule_collection
from smc.policy.policy import Policy
from smc.policy.rule import IPv4Layer2Rule, IPv6Layer2Rule, EthernetRule
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
        return rule_collection(self.get_relation("l2_interface_ipv6_access_rules"), IPv6Layer2Rule)
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


class InterfaceTemplatePolicy(InterfacePolicy):
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


class InterfaceSubPolicy(Policy):
    """
    A Interface Sub Policy is a rule section within a Interface policy
    that provides a container to create rules that are referenced from
    a 'jump' rule. Typically rules in a sub policy are similar in some
    fashion such as applying to a specific service. Sub Policies can also
    be delegated from an administrative perspective.

    Interface Sub Policies only provide access to creating IPv4 rules.

        p = InterfaceSubPolicy('MySubPolicy')
        p.layer2_ethernet_rules.create(
            name='newule',
            sources='any',
            destinations='any',
            services=[TCPService('SSH')],
            action='discard')
    """

    typeof = "sub_l2_interface_policy"

    @classmethod
    def create(cls, name):
        """
        Create a sub policy. Only name is required. Other settings are
        inherited from the parent firewall policy (template, policy, etc).

        :param str name: name of sub policy
        :raises CreateElementFailed: failed to create policy
        :rtype: InterfaceSubPolicy
        """
        return ElementCreator(cls, json={"name": name})

    @property
    def layer2_ipv4_access_rules(self):
        """
        IPv4 rule entry point

        :rtype: rule_collection(EthernetRule)
        """
        return rule_collection(self.get_relation("l2_interface_ipv4_access_rules"), EthernetRule)
