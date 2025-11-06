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
Alert element types that can be used as a matching criteria in the rules of an Alert Policy.
"""
from smc.api.exceptions import AlertChainError, UnsupportedAlertChannel, AlertPolicyError
from smc.base.model import Element, ElementCreator, SubElement
from smc.base.util import element_resolver
from smc.compat import is_api_version_more_than_or_equal, is_smc_version_more_than_or_equal
from smc.api.exceptions import CreateRuleFailed
from smc.base.collection import rule_collection


class AlertElement(Element):
    """
    Base alert element.
    """


class CustomAlert(AlertElement):
    """
    This represents a custom Alert.
    It gives the name and description to an Alert Event. The Alert element can be used
    as a matching criteria in the rules of an Alert Policy.

    Create an alert::

        CustomAlert.create('myalert')
    """

    typeof = "alert"

    @classmethod
    def create(cls, name, comment=None):
        """
        Create the custom alert

        :param str name: name of custom alert
        :param str comment: optional comment
        :raises CreateElementFailed: failed creating element with reason
        :return: instance with meta
        :rtype: CustomAlert
        """
        json = {"name": name, "comment": comment}

        return ElementCreator(cls, json)


class FwAlert(AlertElement):
    """
    This represents a predefined Firewall Alert.
    It gives the name and description to an Alert Event. The Alert element can be used
    as a matching criteria in the rules of an Alert Policy.
    """

    typeof = "fw_alert"


class IdsAlert(AlertElement):
    """
    This represents a predefined IDS Alert.
    It gives the name and description to an Alert Event. The Alert element can be used
    as a matching criteria in the rules of an Alert Policy.
    """

    typeof = "ids_alert"


class AlertChain(Element):
    """
    This represents an Alert Chain.
    """
    typeof = "alert_chain"

    @classmethod
    def create(cls, name, final_action=None, alert_chain_ref=None, comment=None):
        """
        Create the custom alert
        :param str name: name of alert chain
        :param str comment: optional comment
        :param str final_action: optional final_action
            possible values:
                1)none: stop policy processing without acknowledging.
                2)acknowledge: stop policy processing and acknowledge.
                3)redirect: redirect to another alert chain.
                4)return: return to the next policy rule.
        :param obj alert_chain_ref: The redirect alert chain. object of AlertChain.
        :raises CreateElementFailed: failed creating element with reason
        :return: instance with meta of alert chain
        :rtype: AlertChain
        """
        json = {"name": name, "final_action": final_action, "comment": comment}
        if final_action == 'redirect':
            json.update(alert_chain_ref=alert_chain_ref)

        return ElementCreator(cls, json)

    @property
    def final_action(self):
        return self.data.get("final_action", None)

    @property
    def open(self):
        self.make_request(href=self.get_relation("open"), method="create")

    @property
    def save(self):
        self.make_request(href=self.get_relation("save"), method="create")

    @property
    def alert_chain_rules(self):
        return [AlertChainRule(**rule) for rule in self.make_request(resource="alert_chain_rules")]

    def add_rule_section(self, name, add_pos=None,
                         after=None, before=None, background_color=None):
        return AlertChainRule.create_rule_section(self, self.get_relation("alert_chain_rules"),
                                                          name, add_pos, after,
                                                          before, background_color)

    def add_alert_chain_rule(self, name, alert_channel=None, destination=None, delay=0,
                             admin_name=[], amount=None, notify_first_block=0, period=0,
                             comment=None, add_pos=None, after=None, before=None, validate=False):
        return AlertChainRule.create(self, name, alert_channel, destination, delay, admin_name,
                                             amount, notify_first_block, period, comment, add_pos,
                                             after, before, validate)


class AlertRuleCommon(object):
    """
    Functionality common to all alert rules
    """

    @property
    def background_color(self):
        """
        Background color in hexadecimal format (#RRGGBB).
        Applicable for rule section and insert point.
        """
        return self.data.get("background_color", None)

    def is_locked(self):
        """
        Locked flag for this rule.
        """
        return self.data.get("locked", None)

    def lock(self, reason_for=None):
        """
        .. Requires SMC version >= 6.10.10 or >= 7.0.2 or >= 7.1.0

        Locks this rule with an optional reason.

        :raises ResourceNotFound: If not running on supported SMC version
        """
        if reason_for:
            return self.make_request(method="update",
                                     resource="lock",
                                     params={"reason_for": reason_for})
        else:
            return self.make_request(method="update", resource="lock")

    def unlock(self):
        """
        .. Requires SMC version >= 6.10.10 or >= 7.0.2 or >= 7.1.0

        Unlocks this rule.

        :raises ResourceNotFound: If not running on supported SMC version
        """
        return self.make_request(method="update", resource="unlock")


class AlertChainRule(AlertRuleCommon, SubElement):
    """
    This represents a Alert Chain Rule for Alert Chain Policy.
    """
    typeof = "alert_chain_rule"

    @staticmethod
    def create_rule_section(self, rules_href, name, add_pos=None,
                            after=None, before=None, background_color=None):
        """
        Create an alert rule section in an Alert Chain or Alert Policy.
        To specify a specific numbering position for the rule section, use the `add_pos` field.
        If no position or before/after is specified, the rule section will be placed
        at the top which will encapsulate all rules below.
        Create a rule section for the relavant policy::

            policy = AlertPolicy('mypolicy')
            policy.alert_rules.create_rule_section(name='attop')

        :param str name: create a rule section by name
        :param int add_pos: position to insert the rule, starting with position 1.
            If the position value is greater than the number of rules, the rule is
            inserted at the bottom. If add_pos is not provided, rule is inserted in
            position 1. Mutually exclusive with ``after`` and ``before`` params.
        :param str after: Rule tag to add this rule after. Mutually exclusive with
            ``add_pos`` and ``before`` params.
        :param str before: Rule tag to add this rule before. Mutually exclusive with
            ``add_pos`` and ``after`` params.
        :param str background_color: the background color of the rule section.
            in hexadecimal format (#RRGGBB)
        :raises MissingRequiredInput: when options are specified the need additional
            setting, i.e. use_vpn action requires a vpn policy be specified.
        :raises CreateRuleFailed: rule creation failure
        :return: the created ipv4 rule
        :rtype: IPv4Rule
        """
        params = {}
        href = AlertChainRule.set_up_positions(self, params, rules_href, add_pos, after, before)

        json = {"comment": name, "alert_channel": None}
        if (is_api_version_more_than_or_equal("7.1") and
                is_smc_version_more_than_or_equal("7.1.7") and
                background_color):
            json.update(background_color=background_color)

        return ElementCreator(
            self.__class__,
            exception=CreateRuleFailed,
            href=href,
            params=params,
            json=json,
        )

    @staticmethod
    def create(self, name, alert_channel=None, destination=None, delay=0, admin_name=[],
               amount=None, notify_first_block=0, period=0, comment=None, add_pos=None,
               after=None, before=None, validate=False):
        """
        :param object self: object of AlertChain.
        :param str name: name of alert chain rule.
        :param str alert_channel: The alert channel, default is Delay channel.Valid values are below
            smtp: SMTP channel.
            sms: SMS channel.
            snmp: SNMP channel.
            custom_script: Custom script channel.
            delay: Delay channel.
            user_notification: User notification channel.
        :param str destination: destination address
        :param int delay: The delay before the next notification, in minutes.
        :param list admin_name: List of admin users. Used in the case of User notification channel.
        :param int amount: The maximum number of notifications to be sent before activating
        moderation.
        :param int notify_first_block: Indicates whether we shall notify the first blocked
        notification upon moderation activation.
        :param int period: The period during which notifications are tracked before activating
        moderation. period need to be mentioned in minutes.
        :param str comment: descript of element.
        :param int add_pos: position to insert the rule, starting with position 1. If
            the position value is greater than the number of rules, the rule is inserted at
            the bottom. If add_pos is not provided, rule is inserted in position 1. Mutually
            exclusive with ``after`` and ``before`` params.
        :param str after: Rule tag to add this rule after. Mutually exclusive with ``add_pos``
            and ``before`` params.
        :param str before: Rule tag to add this rule before. Mutually exclusive with ``add_pos``
            and ``after`` params.
        :param bool validate: validate the rule creation. Default: False
        :raises CreateElementFailed: failed creating element with reason
        :return: instance with meta of alert chain rule
        :rtype: AlertChainRule
        """
        if alert_channel not in ['smtp', 'sms', 'snmp', 'custom_script', 'user_notification',
                                 'delay'] and alert_channel:
            raise UnsupportedAlertChannel(
                "Failed to create an alert chain rule due to an unsupported alert channel {}".
                format(alert_channel))
        json = {
            "name": name,
            "alert_channel": alert_channel,
            "delay": delay,
            "period": period,
            "notify_first_block": notify_first_block,
            "admin_name": admin_name,
            "comment": comment
        }
        if amount:
            json.update(amount=amount)
        if destination:
            json.update(destination=destination)

        params = {"validate": False} if not validate else {}
        href = AlertChainRule.set_up_positions(self, params,
                                               self.get_relation("alert_chain_rules"),
                                               add_pos, after, before)

        return ElementCreator(
            AlertChainRule,
            exception=AlertChainError,
            href=href,
            params=params,
            json=json,
        )

    @staticmethod
    def set_up_positions(self, params, href, add_pos, after, before):
        if add_pos is not None and is_smc_version_more_than_or_equal("7.1.9"):
            if add_pos <= 0:
                add_pos = 1
            rules = self.make_request(href=href)
            if rules:
                if len(rules) >= add_pos:  # Position somewhere in the list
                    for position, entry in enumerate(rules):
                        if position + 1 == add_pos:
                            href = self.__class__(**entry).get_relation("add_before")
                            break
                else:  # Put at the end
                    last_rule = rules.pop()
                    href = self.__class__(**last_rule).get_relation("add_after")
        elif after:
            params.update(after=after)
        elif before:
            params.update(before=before)
        return href


class AlertPolicy(Element):
    """
    This represents an Alert Policy.
    """
    typeof = "alert_policy"

    @classmethod
    def create(cls, name, comment=None):
        """
        Create the custom alert
        :param str name: name of alert policy
        :param str comment: optional comment
        :raises CreateElementFailed: failed creating element with reason
        :return: instance with meta of alert policy
        :rtype: AlertPolicy
        """
        json = {"name": name, "comment": comment}
        return ElementCreator(cls, json)

    @property
    def alert_rules(self):
        return [AlertRule(**rule) for rule in self.make_request(resource="alert_rules")]

    def add_rule_section(self, name, add_pos=None,
                         after=None, before=None, background_color=None):
        return AlertRule.create_rule_section(self, self.get_relation("alert_rules"), name,
                                               add_pos, after, before, background_color)

    def add_alert_rule(self, name, alert_chain_ref=None, match_sender_ref=[],
                       alert_and_situation_ref=[], min_severity=1, max_severity=10,
                       rule_validity_times=[], comment=None, add_pos=None,
                       after=None, before=None, validate=False):
        """
        creation of the element of type alert_rule.
        :param object self: object of AlertPolicy.
        :param str name: name of alert rule.
        :param str(AlertChain) alert_chain_ref: The Alert Chain.
        :param str match_sender_ref: The senders. If empty, it is considered as ANY.
        :param list alert_and_situation_ref: The alerts and situations. If empty, it is considered
            as ANY.
        :param int min_severity: The minimum value for the severity (value between 1 and 10)
        :param int max_severity: The maximum value for the severity (value between 1 and 10)
        :param list rule_validity_times: The rule's validity to a specific time period. During the
            specified time period, the rule matches. Outside the specified time period, the rule
            does not match and the matching continues to the next rule.
        :param str comment: descript of element.
        :param int add_pos: position to insert the rule, starting with position 1. If
            the position value is greater than the number of rules, the rule is inserted at
            the bottom. If add_pos is not provided, rule is inserted in position 1. Mutually
            exclusive with ``after`` and ``before`` params.
        :param str after: Rule tag to add this rule after. Mutually exclusive with ``add_pos``
            and ``before`` params.
        :param str before: Rule tag to add this rule before. Mutually exclusive with ``add_pos``
            and ``after`` params.
        :param bool validate: validate the rule creation. Default: False
        :raises CreateElementFailed: failed creating element with reason
        :return: instance with meta of alert rule
        :rtype: AlertRule
        """
        return AlertRule.create(self, name, alert_chain_ref, match_sender_ref,
                                  alert_and_situation_ref,
                                  min_severity, max_severity, rule_validity_times, comment,
                                  add_pos, after, before, validate)


class AlertRule(AlertRuleCommon, SubElement):
    """
    This represents Alert Rule for Alert Policy.
    """
    typeof = "alert_rule"

    @staticmethod
    def create_rule_section(self, rules_href, name, add_pos=None,
                            after=None, before=None, background_color=None):
        """
        Create an alert rule section in an Alert Chain or Alert Policy.
        To specify a specific numbering position for the rule section, use the `add_pos` field.
        If no position or before/after is specified, the rule section will be placed
        at the top which will encapsulate all rules below.
        Create a rule section for the relavant policy::

            policy = AlertPolicy('mypolicy')
            policy.alert_rules.create_rule_section(name='attop')

        :param str name: create a rule section by name
        :param int add_pos: position to insert the rule, starting with position 1.
            If the position value is greater than the number of rules, the rule is
            inserted at the bottom. If add_pos is not provided, rule is inserted in
            position 1. Mutually exclusive with ``after`` and ``before`` params.
        :param str after: Rule tag to add this rule after. Mutually exclusive with
            ``add_pos`` and ``before`` params.
        :param str before: Rule tag to add this rule before. Mutually exclusive with
            ``add_pos`` and ``after`` params.
        :param str background_color: the background color of the rule section.
            in hexadecimal format (#RRGGBB)
        :raises MissingRequiredInput: when options are specified the need additional
            setting, i.e. use_vpn action requires a vpn policy be specified.
        :raises CreateRuleFailed: rule creation failure
        :return: the created ipv4 rule
        :rtype: IPv4Rule
        """
        params = {}
        href = AlertChainRule.set_up_positions(self, params, rules_href, add_pos, after, before)

        json = {"comment": name}
        if (is_api_version_more_than_or_equal("7.1") and
                is_smc_version_more_than_or_equal("7.1.7") and
                background_color):
            json.update(background_color=background_color)

        return ElementCreator(
            self.__class__,
            exception=CreateRuleFailed,
            href=href,
            params=params,
            json=json,
        )

    @staticmethod
    def create(self, name, alert_chain_ref=None, match_sender_ref=[], alert_and_situation_ref=[],
               min_severity=1, max_severity=10, rule_validity_times=[], comment=None, add_pos=None,
               after=None, before=None, validate=False):
        """
        creation of the element of type alert_rule.
        :param object self: object of AlertPolicy.
        :param str name: name of alert rule.
        :param str(AlertChain) alert_chain_ref: The Alert Chain.
        :param list match_sender_ref: The senders. If empty, it is considered as ANY.
        :param list alert_and_situation_ref: The alerts and situations. If empty, it is considered
            as ANY.
        :param int min_severity: The minimum value for the severity (value between 1 and 10):Matches
            the rule to only Situations with the specified Severity value(s). For example, if your
            rule is general and matches a wide range of Situations, you may want to create two
            similar rules: one for less severe Situations and one for more Severe situations. Useful
            in rules that contain Tags in the Situation cell.
        :param int max_severity: The maximum value for the severity (value between 1 and 10):Matches
            the rule to only Situations with the specified Severity value(s). For example if your
            rule is general and matches a wide range of Situations, you may want to create two
            similar rules: one for less severe Situations and one for more Severe situations. Useful
            in rules that contain Tags in the Situation cell.
        :param list rule_validity_times: The rule's validity to a specific time period. During the
            specified time period, the rule matches. Outside the specified time period, the rule
            does not match and the matching continues to the next rule.
        :param str comment: descript of element.
        :param int add_pos: position to insert the rule, starting with position 1. If
            the position value is greater than the number of rules, the rule is inserted at
            the bottom. If add_pos is not provided, rule is inserted in position 1. Mutually
            exclusive with ``after`` and ``before`` params.
        :param str after: Rule tag to add this rule after. Mutually exclusive with ``add_pos``
            and ``before`` params.
        :param str before: Rule tag to add this rule before. Mutually exclusive with ``add_pos``
            and ``after`` params.
        :param bool validate: validate the rule creation. Default: False
        :raises CreateElementFailed: failed creating element with reason
        :return: instance with meta of alert rule
        :rtype: AlertRule
        """
        json = {
            "name": name,
            "match_sender_ref": element_resolver(match_sender_ref),
            "alert_and_situation_ref": element_resolver(alert_and_situation_ref),
            "rule_validity_times": element_resolver(rule_validity_times),
            "min_severity": min_severity,
            "max_severity": max_severity,
            "comment": comment
        }
        if alert_chain_ref:
            json.update(alert_chain_ref=element_resolver(alert_chain_ref))

        params = {"validate": False} if not validate else {}
        href = AlertRule.set_up_positions(self, params,
                                          self.get_relation("alert_rules"),
                                          add_pos, after, before)

        return ElementCreator(
            AlertRule,
            exception=AlertPolicyError,
            href=href,
            params=params,
            json=json,
        )

    @staticmethod
    def set_up_positions(self, params, href, add_pos, after, before):
        if add_pos is not None and is_smc_version_more_than_or_equal("7.1.9"):
            if add_pos <= 0:
                add_pos = 1
            rules = self.make_request(href=href)
            if rules:
                if len(rules) >= add_pos:  # Position somewhere in the list
                    for position, entry in enumerate(rules):
                        if position + 1 == add_pos:
                            href = self.__class__(**entry).get_relation("add_before")
                            break
                else:  # Put at the end
                    last_rule = rules.pop()
                    href = self.__class__(**last_rule).get_relation("add_after")
        elif after:
            params.update(after=after)
        elif before:
            params.update(before=before)
        return href
