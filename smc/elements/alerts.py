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

    def add_alert_chain_rule(self, name, alert_channel=None, destination=None, delay=0,
                             admin_name=[], amount=None, notify_first_block=0, period=0,
                             comment=None):
        AlertChainRule.create(self, name, alert_channel, destination, delay, admin_name,
                              amount, notify_first_block, period, comment)


class AlertChainRule(SubElement):
    """
    This represents a Alert Chain Rule for Alert Chain Policy.
    """
    typeof = "alert_chain_rule"

    @staticmethod
    def create(self, name, alert_channel=None, destination=None, delay=0, admin_name=[],
               amount=None, notify_first_block=0, period=0, comment=None):
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
        return ElementCreator(
            AlertChainRule,
            exception=AlertChainError,
            href=self.get_relation("alert_chain_rules"),
            json=json,
        )


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

    def add_alert_rule(self, name, alert_chain_ref=None, match_sender_ref=[],
                       alert_and_situation_ref=[], min_severity=1, max_severity=10,
                       rule_validity_times=[], comment=None):
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
        :raises CreateElementFailed: failed creating element with reason
        :return: instance with meta of alert rule
        :rtype: AlertRule
        """
        return AlertRule.create(self, name, alert_chain_ref, match_sender_ref,
                                alert_and_situation_ref,
                                min_severity, max_severity, rule_validity_times, comment)


class AlertRule(SubElement):
    """
    This represents Alert Rule for Alert Policy.
    """
    typeof = "alert_rule"

    @staticmethod
    def create(self, name, alert_chain_ref=None, match_sender_ref=[], alert_and_situation_ref=[],
               min_severity=1, max_severity=10, rule_validity_times=[], comment=None):
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
        :raises CreateElementFailed: failed creating element with reason
        :return: instance with meta of alert rule
        :rtype: AlertRule
        """
        params = {}
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
        return ElementCreator(
            AlertRule,
            exception=AlertPolicyError,
            href=self.get_relation("alert_rules"),
            params=params,
            json=json,
        )
