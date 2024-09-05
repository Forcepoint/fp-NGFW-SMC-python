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
IPS Engine policy

Module that represents resources related to creating and managing IPS engine
policies.

To get an existing policy::

    >>> policy = IPSPolicy('Default IPS Policy')
    >>> print(policy.template)
    IPSTemplatePolicy(name=High-Security IPS Template)

Or through collections::

    >>> from smc.policy.ips import IPSPolicy
    >>> list(IPSPolicy.objects.all())
    [IPSPolicy(name=Default IPS Policy), IPSPolicy(name=High-Security Inspection IPS Policy)]

To create a new policy, use::

    policy = IPSPolicy.create(name='my_ips_policy',
                              template='High Security Inspection Template')
    policy.ips_ipv4_access_rules.create(name='ipsrule1',
                                        sources='any',
                                        action='continue')

    for rule in policy.ips_ipv4_access_rules.all():
        print(rule)

Example rule deletion::

    policy = IPSPolicy('Amazon Cloud')
    for rule in policy.ips_ipv4_access_rules.all():
        if rule.name == 'ipsrule1':
            rule.delete()
"""
from smc.policy.policy import Policy
from smc.policy.rule import IPv4Layer2Rule, IPv6Layer2Rule, EthernetRule, IPSRule
from smc.base.model import ElementCreator
from smc.api.exceptions import (
    ElementNotFound,
    LoadPolicyFailed,
    CreatePolicyFailed,
    CreateElementFailed,
)
from smc.base.collection import rule_collection


class IPSPolicyRule(object):
    """
    Encapsulates all references to IPS rule related entry
    points. This is referenced by multiple classes such as
    IPSPolicy and IPSPolicyTemplate.
    """

    @property
    def ips_ipv4_access_rules(self):
        """
        IPS ipv4 access rules

        :rtype: rule_collection(IPv4Layer2Rule)
        """
        return rule_collection(self.get_relation("ips_ipv4_access_rules"), IPv4Layer2Rule)

    @property
    def ips_ipv6_access_rules(self):
        """"""
        return rule_collection(self.get_relation("ips_ipv6_access_rules"), IPv6Layer2Rule)

    @property
    def ips_ethernet_rules(self):
        """
        IPS Ethernet access rule

        :rtype: rule_collection(EthernetRule)
        """
        return rule_collection(self.get_relation("ips_ethernet_rules"), EthernetRule)


class IPSPolicy(IPSPolicyRule, Policy):
    """
    IPS Policy represents a set of rules installed on an IPS / IDS
    engine. IPS mode supports both inline and SPAN interface types and
    ethernet based rules. Layer 2 and IPS engines do not current features that
    require routed interfaces.

    :ivar template: which policy template is used

    Instance Resources:

    :ivar ips_ipv4_access_rules: :py:class:`~IPSRule.ips_ipv4_access_rules`
    :ivar ips_ipv6_access_rules: :py:class:`~IPSRule.ips_ipv6_access_rules`
    :ivar ips_ethernet_rules: :py:class:`~IPSRule.ips_ethernet_rules`
    """

    typeof = "ips_policy"

    @classmethod
    def create(cls, name, template="High-Security IPS Template"):
        """
        Create an IPS Policy

        :param str name: Name of policy
        :param str template: name of template
        :raises CreatePolicyFailed: policy failed to create
        :return: IPSPolicy
        """
        try:
            if cls.typeof == "ips_template_policy" and template is None:
                fw_template = None
            elif cls.typeof == "ips_policy" and template is None:
                # it is not relevant to create a normal ips policy without inherited insert point
                raise LoadPolicyFailed("An IPS Template is required.")
            else:
                fw_template = IPSTemplatePolicy(template).href
        except ElementNotFound:
            raise LoadPolicyFailed("Cannot find specified firewall template: {}".format(template))
        json = {"name": name, "template": fw_template}
        try:
            return ElementCreator(cls, json)
        except CreateElementFailed as err:
            raise CreatePolicyFailed(err)


class IPSSubPolicy(Policy):
    """
    A IPS Sub Policy is a rule section within an IPS policy
    that provides a container to create rules that are referenced from
    a 'jump' rule. Typically rules in a sub policy are similar in some
    fashion such as applying to a specific service. Sub Policies can also
    be delegated from an administrative perspective.

        p = IPSSubPolicy('MyIPSSubPolicy')
        p.fw_ipv4_access_rules.create(
            name='newule',
            sources='any',
            destinations='any',
            services=[TCPService('SSH')],
            action='discard')
    """

    typeof = "sub_ipv4_ips_policy"

    @classmethod
    def create(cls, name):
        """
        Create a sub policy. Only name is required. Other settings are
        inherited from the parent IPS policy (template, inspection
        policy, etc).

        :param str name: name of sub policy
        :raises CreateElementFailed: failed to create policy
        :rtype: IPSSubPolicy
        """
        return ElementCreator(cls, json={"name": name})

    @property
    def ips_ipv4_access_rules(self):
        """
        IPv4 rule entry point

        :rtype: rule_collection(IPSRule)
        """
        return rule_collection(self.get_relation("ips_ipv4_access_rules"), IPSRule)


class IPSTemplatePolicy(IPSPolicy):
    """
    All IPS Policies will reference an IPS policy template.

    Most templates will be pre-configured best practice configurations
    and rarely need to be modified. However, you may want to view the
    details of rules configured in a template or possibly insert additional
    rules.

    For example, view rules in an ips policy template after loading the
    ips policy::

        policy = IPSPolicy('InlineIPS')
        for rule in policy.template.ips_ipv4_access_rules.all():
            print(rule)
    """

    typeof = "ips_template_policy"

    def upload(self):
        pass
