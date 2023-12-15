#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
import argparse
import logging
import sys

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.api.exceptions import UnsupportedAlertChannel  # noqa
from smc.elements.alerts import AlertChain  # noqa


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

logging.getLogger()
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - '
                                                '%(name)s - [%(levelname)s] : %(message)s')


def main():
    return_code = 0
    try:
        arguments = parse_command_line_arguments()
        session.login(url=arguments.api_url, api_key=arguments.api_key,
                      login=arguments.smc_user,
                      pwd=arguments.smc_pwd, api_version=arguments.api_version)

        # delete if alert chain present
        logging.info("delete if alert chain present")
        if AlertChain.objects.filter(alert_chain_name, exact_match=True):
            if AlertChain(alert_chain_name).is_locked():
                AlertChain(alert_chain_name).unlock()
                logging.info("Alert chain is locked, unlocked it")

            AlertChain(alert_chain_name).delete()
            logging.info("Deleted alert chain as it was already exist")
        existing_alert_chain = list(AlertChain.objects.all())[0]

        # create alert chain
        alert_chain_obj = AlertChain.create(alert_chain_name)
        logging.info(f"Alert chain is created successfully with name: {alert_chain_name}")
        alert_chain_obj.update(final_action='redirect', alert_chain_ref=existing_alert_chain.href)
        expected_exception = False
        # add alert chain rule
        alert_chain_obj.add_alert_chain_rule(rule_name_template.format(channel1),
                                             alert_channel=channel1,
                                             comment=comment_msg.format(channel1),
                                             notify_first_block=notify_first_block, period=period,
                                             amount=amount)
        logging.info(
            f"Added alert chain rule : {rule_name_template.format(channel1)} "
            f"to alert chain : {alert_chain_name}")
        alert_chain_obj.add_alert_chain_rule(rule_name_template.format(channel2),
                                             alert_channel=channel2,
                                             comment=comment_msg.format(channel2),
                                             notify_first_block=notify_first_block, period=period,
                                             amount=amount)
        logging.info(
            f"Added alert chain rule : {rule_name_template.format(channel2)} "
            f"to alert chain : {alert_chain_name}")
        alert_chain_obj.add_alert_chain_rule(rule_name_template.format(channel3),
                                             alert_channel=channel3,
                                             comment=comment_msg.format(channel3),
                                             notify_first_block=notify_first_block,
                                             period=period,
                                             amount=amount)
        logging.info(
            f"Added alert chain rule : {rule_name_template.format(channel3)} "
            f"to alert chain : {alert_chain_name}")
        alert_chain_obj.add_alert_chain_rule(rule_name_template.format(channel4),
                                             alert_channel=channel4,
                                             comment=comment_msg.format(channel4))
        logging.info(
            f"Added alert chain rule : {rule_name_template.format(channel4)} "
            f"to alert chain : {alert_chain_name}")
        alert_chain_obj.add_alert_chain_rule(rule_name_template.format(channel5),
                                             comment=comment_msg.format(channel5))
        logging.info(
            f"Added alert chain rule : {rule_name_template.format(channel5)} "
            f"to alert chain : {alert_chain_name}")
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
        logging.info("Alert chain rule with existing value is correct")
        test_alert_chain_rule.update(period=update_period)
        assert test_alert_chain_rule.period == update_period, FAILED_TO_UPDATE
        logging.info("Alert chain rule with update value is correct")
        test_alert_chain_rule.delete()
    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        # delete alert chain
        AlertChain(alert_chain_name).delete()
        logging.info("Alert Chain Deleted successfully")
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to use Alert Chain',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        add_help=False)
    parser.add_argument(
        '-h', '--help',
        action='store_true',
        help='show this help message and exit')

    parser.add_argument(
        '--api-url',
        type=str,
        help='SMC API url like https://192.168.1.1:8082')
    parser.add_argument(
        '--api-version',
        type=str,
        help='The API version to use for run the script'
    )
    parser.add_argument(
        '--smc-user',
        type=str,
        help='SMC API user')
    parser.add_argument(
        '--smc-pwd',
        type=str,
        help='SMC API password')
    parser.add_argument(
        '--api-key',
        type=str, default=None,
        help='SMC API api key (Default: None)')

    arguments = parser.parse_args()

    if arguments.help:
        parser.print_help()
        sys.exit(1)
    if arguments.api_url is None:
        parser.print_help()
        sys.exit(1)

    return arguments


if __name__ == '__main__':
    sys.exit(main())
