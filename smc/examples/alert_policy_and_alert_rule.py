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
Example script to show how to use Alert Policy
-create/update/delete alert policy
-create/update/delete alert rule
"""

import sys
from smc import session
from smc.elements.alerts import AlertChain, AlertPolicy
from smc.elements.other import RuleValidityTime
from smc_info import SMC_URL, API_KEY, API_VERSION

comment_msg = "add {} for testing purpose."
alert_policy = 'alert_policy_test'
rule_name = "alert_rule_test"
CREATE_POLICY_ERROR = "Failed to create alert policy."
CREATE_RULE_ERROR = "Failed to create alert rule."
DELETE_ERROR = "Failed to delete alert rule."


def main():
    try:
        session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120,
                      api_version=API_VERSION)

        # delete if alert policy present
        print("delete if alert policy present")
        if AlertPolicy.objects.filter(alert_policy, exact_match=True):
            if AlertPolicy(alert_policy).is_locked():
                AlertPolicy(alert_policy).unlock()
                print("Alert policy is locked, unlocked it")

            AlertPolicy(alert_policy).delete()
            print("Deleted alert policy as it was already exist")

        # create alert policy
        alert_policy_obj = AlertPolicy.create(alert_policy,
                                              comment=comment_msg.format(alert_policy))
        assert AlertPolicy.objects.filter(alert_policy,
                                          exact_match=True), CREATE_POLICY_ERROR
        print("Alert policy is created successfully with name: {}.".format(alert_policy))
        alert_policy_obj.update(comment="Updating alert policy comment")
        print("Successfully updated alert policy comment.")
        # add alert rule
        rule_validity_time = RuleValidityTime('Rule Validity Time 2')
        alert_chain = AlertChain("Default")
        alert_policy_obj.add_alert_rule(rule_name, rule_validity_times=[rule_validity_time],
                                        alert_chain_ref=alert_chain,
                                        comment=comment_msg.format(rule_name))
        assert [alert_rule for alert_rule in alert_policy_obj.alert_rules if
                alert_rule.name == rule_name], CREATE_RULE_ERROR
        print("Added alert rule successfully.")
        alert_rule = alert_policy_obj.alert_rules[0]
        alert_rule_name = alert_rule.name
        alert_rule.delete()
        assert not [alert_rule for alert_rule in alert_policy_obj.alert_rules if
                    alert_rule.name == alert_rule_name], DELETE_ERROR
        print("Alert rule deleted successfully")
    except BaseException as e:
        print("Exception in checking alert policy : {}".format(str(e)))
        exit(-1)
    finally:
        # delete alert policy
        AlertPolicy(alert_policy).delete()
        print("Alert Policy Deleted successfully")
        session.logout()


if __name__ == '__main__':
    sys.exit(main())
