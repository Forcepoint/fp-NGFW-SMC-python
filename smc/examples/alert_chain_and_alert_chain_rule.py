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
Example script to show how to use Alert Chain
-create/update/delete alert chain
-create/update/delete alert chain rule
"""

import sys
from smc import session
from smc.api.exceptions import UnsupportedAlertChannel
from smc.elements.alerts import AlertChain
from smc_info import SMC_URL, API_KEY, API_VERSION

period = 60
update_period = 120
notify_first_block = 1
amount = 111
comment_msg = "add {} rule for testing purpose"
channel1 = "sms"
channel2 = "smtp"
channel3 = "snmp"
channel4 = "custom_script"
channel5 = "delay"
alert_chain_name = 'alert_chain_test'
rule_name_template = "alert_chain_rule_{}"
FAILED_TO_GET_ATTRIBUTE = "Failed to get period attribute of alert chain rule"
FAILED_TO_UPDATE = "Failed to update attribute of alert chain rule"


def main():
    try:
        session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120,
                      api_version=API_VERSION)
        # delete if alert chain present
        print("delete if alert chain present")
        if AlertChain.objects.filter(alert_chain_name, exact_match=True):
            if AlertChain(alert_chain_name).is_locked():
                AlertChain(alert_chain_name).unlock()
                print("Alert chain is locked, unlocked it")

            AlertChain(alert_chain_name).delete()
            print("Deleted alert chain as it was already exist")
        existing_alert_chain = list(AlertChain.objects.all())[0]

        # create alert chain
        alert_chain_obj = AlertChain.create(alert_chain_name)
        print("Alert chain is created successfully with name: {}".format(alert_chain_name))
        alert_chain_obj.update(final_action='redirect', alert_chain_ref=existing_alert_chain.href)
        expected_exception = False
        # add alert chain rule
        alert_chain_obj.add_alert_chain_rule(rule_name_template.format(channel1),
                                             alert_channel=channel1,
                                             comment=comment_msg.format(channel1),
                                             notify_first_block=notify_first_block, period=period,
                                             amount=amount)
        print("Added alert chain rule : {} to alert chain : {}".format(
            rule_name_template.format(channel1), alert_chain_name))
        alert_chain_obj.add_alert_chain_rule(rule_name_template.format(channel2),
                                             alert_channel=channel2,
                                             comment=comment_msg.format(channel2),
                                             notify_first_block=notify_first_block, period=period,
                                             amount=amount)
        print("Added alert chain rule : {} to alert chain: {}".format(
            rule_name_template.format(channel2), alert_chain_name))
        alert_chain_obj.add_alert_chain_rule(rule_name_template.format(channel3),
                                             alert_channel=channel3,
                                             comment=comment_msg.format(channel3),
                                             notify_first_block=notify_first_block,
                                             period=period,
                                             amount=amount)
        print("Added alert chain rule : {} to alert chain: {}".format(
            rule_name_template.format(channel3), alert_chain_name))
        alert_chain_obj.add_alert_chain_rule(rule_name_template.format(channel4),
                                             alert_channel=channel4,
                                             comment=comment_msg.format(channel4))
        print("Added alert chain rule : {} to alert chain: {}".format(
            rule_name_template.format(channel4), alert_chain_name))
        alert_chain_obj.add_alert_chain_rule(rule_name_template.format(channel5),
                                             comment=comment_msg.format(channel5))
        print("Added alert chain rule : {} to alert chain: {}".format(
            rule_name_template.format(channel5), alert_chain_name))
        # adding rule with incorrect alert channel, it should raise an exception.
        try:
            alert_chain_obj.add_alert_chain_rule("alert_chain_rule",
                                                 alert_channel="incorrect_alert_channel")
        except UnsupportedAlertChannel:
            expected_exception = True
        assert expected_exception, "Unexpected response of adding rule"
        test_alert_chain_rule = list(
            filter(lambda rule: rule.name == rule_name_template.format(channel2),
                   alert_chain_obj.alert_chain_rules))[0]
        assert test_alert_chain_rule.period == period, FAILED_TO_GET_ATTRIBUTE
        print("Alert chain rule with existing value is correct")
        test_alert_chain_rule.update(period=update_period)
        assert test_alert_chain_rule.period == update_period, FAILED_TO_UPDATE
        print("Alert chain rule with update value is correct")
        test_alert_chain_rule.delete()
    except BaseException as e:
        print("Exception in checking alert chain : {}".format(str(e)))
        exit(-1)
    finally:
        # delete alert chain
        AlertChain(alert_chain_name).delete()
        print("Alert Chain Deleted successfully")
        session.logout()


if __name__ == '__main__':
    sys.exit(main())
