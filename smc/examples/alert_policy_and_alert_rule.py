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
Example script to show how to use Alert Policy
-create/update/delete alert policy
-create/update/delete alert rule
"""
import argparse
import logging
import sys

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.elements.alerts import AlertChain, AlertPolicy  # noqa
from smc.elements.other import RuleValidityTime  # noqa
from smc.compat import is_api_version_more_than_or_equal, is_smc_version_equal  # noqa

comment_msg = "add {} for testing purpose."
alert_policy = 'alert_policy_test'
rule_name = "alert_rule_test"
CREATE_POLICY_ERROR = "Failed to create alert policy."
CREATE_RULE_ERROR = "Failed to create alert rule."
DELETE_ERROR = "Failed to delete alert rule."

logging.getLogger()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - '
                                               '%(name)s - [%(levelname)s] : %(message)s')


def main():
    return_code = 0
    try:
        arguments = parse_command_line_arguments()
        session.login(url=arguments.api_url, api_key=arguments.api_key,
                      login=arguments.smc_user,
                      pwd=arguments.smc_pwd, api_version=arguments.api_version)

        # delete if alert policy present
        logging.info("delete if alert policy present")
        if AlertPolicy.objects.filter(alert_policy, exact_match=True):
            if AlertPolicy(alert_policy).is_locked():
                AlertPolicy(alert_policy).unlock()
                logging.info("Alert policy is locked, unlocked it")

            AlertPolicy(alert_policy).delete()
            logging.info("Deleted alert policy as it was already exist")

        # create alert policy
        alert_policy_obj = AlertPolicy.create(alert_policy,
                                              comment=comment_msg.format(alert_policy))
        assert AlertPolicy.objects.filter(alert_policy,
                                          exact_match=True), CREATE_POLICY_ERROR
        logging.info(f"Alert policy is created successfully with name: {alert_policy}.")
        alert_policy_obj.update(comment="Updating alert policy comment")
        logging.info("Successfully updated alert policy comment.")
        higher_than_6_10 = is_api_version_more_than_or_equal('7.1')
        is_smc_7_3_0 = is_smc_version_equal("7.3.0")
        first_section = None
        add_before_add_section_allowed = higher_than_6_10 and not is_smc_7_3_0
        if add_before_add_section_allowed:
            first_section = alert_policy_obj.add_rule_section("first_section")
        # add alert rule
        rule_validity_time = RuleValidityTime('Rule Validity Time 2')
        alert_chain = AlertChain("Default")
        first_rule = alert_policy_obj.add_alert_rule(rule_name,
                                                     rule_validity_times=[rule_validity_time],
                                                     alert_chain_ref=alert_chain,
                                                     comment=comment_msg.format(rule_name),
                                                     after=first_section.tag
                                                     if add_before_add_section_allowed else None)
        second_rule = alert_policy_obj.add_alert_rule(rule_name,
                                                      rule_validity_times=[rule_validity_time],
                                                      alert_chain_ref=alert_chain,
                                                      comment=comment_msg.format(rule_name),
                                                      before=first_rule.tag
                                                      if add_before_add_section_allowed else None)
        third_rule = alert_policy_obj.add_alert_rule(rule_name,
                                                     rule_validity_times=[rule_validity_time],
                                                     alert_chain_ref=alert_chain,
                                                     comment=comment_msg.format(rule_name),
                                                     add_pos=1
                                                     if add_before_add_section_allowed else None)
        assert [alert_rule for alert_rule in alert_policy_obj.alert_rules if
                alert_rule.name == rule_name], CREATE_RULE_ERROR
        logging.info("Added alert rule successfully.")
    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        # delete alert policy
        AlertPolicy(alert_policy).delete()
        logging.info("Alert Policy Deleted successfully")
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to use Alert Policy',
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
