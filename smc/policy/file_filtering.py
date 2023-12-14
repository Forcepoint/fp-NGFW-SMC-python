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
from smc.api.exceptions import CreateRuleFailed, MissingRequiredInput, ElementNotFound
from smc.base.util import element_resolver
from smc.policy.policy import Policy
from smc.base.model import SubElement, ElementCreator
from smc.base.collection import rule_collection
from smc.policy.rule import RuleCommon, Rule
from smc.policy.rule_elements import LogOptions, SituationMatchPart, FileFilteringRuleAction


class FileFilteringRule(RuleCommon, Rule, SubElement):
    """
    Represents a file filtering rule.
    """

    typeof = "file_filtering_rule"
    _actions = (
        "allow",
        "discard",
        "allow_after"
    )

    def create(
            self,
            name,
            sources=None,
            destinations=None,
            action="allow",
            log_options=None,
            connection_tracking=None,
            is_disabled=False,
            situations=None,
            add_pos=None,
            after=None,
            before=None,
            comment=None,
            validate=True,
            **kw
    ):
        """
        Create a file filtering rule.

        .. versionchanged:: 0.7.0
            Action field now requires a list of actions as strings when using API
            version >= 6.6
        Example::
            Api version <=6.5 action is a string
            rule_file = p.file_filtering_rules.create( name="newrule",
                                                      sources=[Network("London Internal Network")],
                                                      destinations=[Network("net-172.31.14.0/24")],
                                                      action="apply_vpn",
                                                      vpn_policy=vpn)
            Api version >=6.6 action is a list
            vpn_actions = Action()
            vpn_actions.action = ['allow', 'apply_vpn']
            p.file_filtering_rules.create(name='new_rule',
                                          sources=[Network("London Internal Network")],
                                          destinations=[Network("net-172.31.14.0/24")],
                                          action=vpn_actions,
                                          vpn_policy=vpn)
        :param str name: name of rule
        :param sources: source/s for rule
        :type sources: Source, list[str, Element]
        :param destinations: destination/s for rule
        :type destinations: Destination, list[str, Element]
        :param action: allow,discard,continue,refuse,jump,apply_vpn,enforce_vpn,forward_vpn
            ,block_list,terminate,forward,next_hop,forced_next_hop (default: allow)
        :type action: Action,str,list[str]
        :param LogOptions log_options: LogOptions object
        :param ConnectionTracking connection_tracking: custom connection tracking settings
        :param bool is_disabled: whether to disable rule or not
        :param situations: A set of matching criteria that defines the file types the rule matches.
            If nothing is specified, that means None and the Rule will be ignored.
        :type situations: Situations,str,dict
        :param int add_pos: position to insert the rule, starting with position 1. If
            the position value is greater than the number of rules, the rule is inserted at
            the bottom. If add_pos is not provided, rule is inserted in position 1. Mutually
            exclusive with ``after`` and ``before`` params.
        :param str after: Rule tag to add this rule after. Mutually exclusive with ``add_pos``
            and ``before`` params.
        :param str before: Rule tag to add this rule before. Mutually exclusive with ``add_pos``
            and ``after`` params.
        :param str comment: optional comment for this rule
        :param bool validate: validate the inspection policy during rule creation. Default: True
        :raises MissingRequiredInput: when options are specified the need additional
            setting, i.e. use_vpn action requires a vpn policy be specified.
        :raises CreateRuleFailed: rule creation failure
        :return: the created FileFilteringRule
        :rtype: FileFilteringRule
        """
        rule_values = self.update_targets(sources, destinations, situations=situations)

        rule_action = self._get_action(action)
        log_options = LogOptions() if not log_options else log_options

        if connection_tracking is not None:
            rule_action.connection_tracking_options.update(**connection_tracking)

        rule_values.update(
            name=name,
            comment=comment,
            action=rule_action.data,
            options=log_options.data,
            is_disabled=is_disabled,
            **kw
        )

        params = {"validate": False} if not validate else {}
        href = self.href
        if add_pos is not None:
            href = self.add_at_position(add_pos)
        elif before or after:
            params.update(**self.add_before_after(before, after))

        return ElementCreator(
            self.__class__, exception=CreateRuleFailed, href=href, params=params, json=rule_values
        )

    @property
    def situations(self):
        """
        Situations for this rule

        :rtype: Situations
        """
        return SituationMatchPart(self)

    def get_action(self):
        """
        Return action instance.
        rtype: FileFilteringRuleAction
        """
        return FileFilteringRuleAction()


class FileFilteringPolicy(Policy):
    """
    The File Filtering Policy references a specific file based policy for
    doing additional inspection based on file types. Use the policy
    parameters to specify how certain files are treated by either threat
    intelligence feeds,sandbox or by local AV scanning. You can also use
    this policy to disable threat prevention based on specific files.
    """

    typeof = "file_filtering_policy"

    @classmethod
    def create(cls, name, comment=None):
        """
        Create the custom File Filtering Policy
        :param str name: name of File Filtering Policy
        :param str comment: optional comment
        :raises CreateElementFailed: failed creating element with reason
        :return: instance with meta of File Filtering Policy.
        :rtype: FileFilteringPolicy
        """
        json = {"name": name, "comment": comment}
        return ElementCreator(cls, json)

    @property
    def file_filtering_rules(self):
        """
        File filtering rules for this policy.

        :rtype: rule_collection(FileFilteringRule)
        """
        return rule_collection(self.get_relation("file_filtering_rules"), FileFilteringRule)
