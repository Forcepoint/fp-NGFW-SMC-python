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
Example of using policy rule counters to perform potential cleanup based
on whether rules have hit counts associating them with activity. This also
shows a variety of options that can be used to do finer tune searches and
disable, update or print rule configurations.
"""

import argparse
import logging
import sys

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.policy.layer3 import FirewallPolicy  # noqa
from smc.core.engine import Engine  # noqa

ENGINE = "Helsinki"
POLICY = "HQ Policy"

logging.getLogger()
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - '
                                                '%(name)s - [%(levelname)s] : %(message)s')


def get_firewall_policy(name=None):
    """
    Get a firewall policy by it's name. If name is not provided, return
    a list of all firewall policies

    :param str name: name of policy; If None, return all policies
    :raises ElementNotFound: raised if policy was specified and it
        didn't exist
    :rtype: list(FirewallPolicy) or FirewallPolicy
    """
    if name:
        return FirewallPolicy.get(name)
    return [fp for fp in FirewallPolicy.objects.all()]


def main():
    return_code = 0
    try:
        arguments = parse_command_line_arguments()
        session.login(url=arguments.api_url, api_key=arguments.api_key,
                      login=arguments.smc_user,
                      pwd=arguments.smc_pwd, api_version=arguments.api_version)
        logging.info("session OK")

        """
        Obtain the policy based on it's type. This example uses a FirewallPolicy
        type but all policy types are supported, i.e: IPSPolicy or Layer2Policy; as
        well as templates, i.e: IPSTemplatePolicy, FirewallTemplatePolicy, Layer2TemplatePolicy
        .. note:: NAT rules and IPv6 rules are included in the output and do not need
            to be handled separately.
        """

        policy = FirewallPolicy.get(POLICY)
        # policy = get_firewall_policy('Standard*') # <-- Wildcard will only
        # return first match

        """
        Rule counters on a given policy can be obtained for all engines using
        the specified policy. This is equivalent to running the rule counters in the
        SMC without a "Target" specified.
        :rtype: list(smc.policy.policy.RuleCounter)
        """
        logging.info("Rule counters by policy only\n------------------------")
        for counter in policy.rule_counters(engine=None):
            logging.info(counter)

        """
        Get rule counters by specific engine
        :param Engine engine: the engine specified as element
        :rtype: list(smc.policy.policy.RuleCounter)
        """
        logging.info("Rule counters by engine\n------------------------")
        for counter in policy.rule_counters(engine=Engine(ENGINE)):
            logging.info(counter)

        """
        Durations can be used to specify how far back to retrieve the rule
        counters.
        :param str duration_type: duration for obtaining rule counters. Valid
            options are: one_day, one_week, one_month, six_months, one_year,
            custom, since_last_upload; If custom is provided, set the `duration`
            attribute as well
        :rtype: list(smc.policy.policy.RuleCounter)
        """
        logging.info("Rule counters for last month\n------------------------")
        for counter in policy.rule_counters(duration_type="one_month"):
            logging.info(counter)

        """
        Rule counters using custom duration, in seconds from current time
        :rtype: list(smc.policy.policy.RuleCounter)
        """
        logging.info("Rule counters for last 3600 seconds\n------------------------")
        for counter in policy.rule_counters(duration_type="custom", duration=3600):
            logging.info(counter)

        """
        Rule counters for last week on specific engine
        :rtype: list(smc.policy.policy.RuleCounter)
        """
        for counter in policy.rule_counters(engine=Engine(ENGINE), duration_type="one_week"):
            logging.info(counter)

        """
        Rule counters are namedtuples that have the following attributes, allowing you to
        retrieve the given rule from the RuleCounter object
        """
        for counter in policy.rule_counters(engine=Engine(ENGINE), duration_type="one_week"):
            logging.info(counter, counter.rule)

        """
        Obtain the rule reference for each counter and access the History
        of the rule
        """
        for counter in policy.rule_counters(engine=Engine(ENGINE), duration_type="one_week"):
            rule = counter.rule  # smc.policy.rule.Rule
            history = rule.history  # smc.core.resource.History
            logging.info(f"Rule: {rule} -> Last modified: {history.last_modified}")

        """
        Disable all rules that have not been hit 6 months.
        For this example, simply print the rule object and the parent policy it's associated with
        """
        for counter in policy.rule_counters(engine=Engine(ENGINE), duration_type="six_months"):
            if counter.hits == 0:
                logging.info(f"Disable: {counter.rule} from policy: {counter.rule.parent_policy}")
                # counter.rule.update(is_disabled=True, comment='Disabled due to 90
                # days of no usage') # <-- Disable the rule

        """
        View rule details for rules that have not been hit in 6 months.
        Output would be::
            Rule object: IPv4Rule(name=Rule @2100159.25)
            Rule type: fw_ipv4_access_rule
            Name: Rule @2100159.25
            Rank: 61.0
            Sources: [Network(name=network-172.18.1.0/24)]
            Destinations: [Network(name=network-192.168.6.0/25)]
            Services: Any
            Action: enforce_vpn
            Log Options:
                log_payload_additionnal = False # SMC Version below 6.11
                log_level = undefined
                log_closing_mode = True
                log_payload_record = False
                log_payload_excerpt = False
                log_accounting_info_mode = False
                log_severity = -1
            Comment: None
        """
        for counter in policy.rule_counters(engine=Engine(ENGINE), duration_type="six_months"):
            if counter.hits == 0:
                rule = counter.rule
                logging.info(
                    f"Rule object: {rule}\nRule type: {rule.typeof}\nName: {rule.name}\n"
                    f"Rank: {rule.rank}\n"
                )
                for values in ("sources", "destinations", "services"):
                    value = getattr(rule, values)
                    cased_value = values.title()
                    if value.is_any:
                        logging.info(f"{cased_value}: Any")
                    elif value.is_none:
                        logging.info(f"{cased_value}: None")
                    else:
                        logging.info(f"{cased_value}: {value.all()}")
                # NAT rules can be returned here and do not have an action field
                if rule.action:
                    logging.info(f"Action: {rule.action.action}")

                log_options = rule.options
                logging.info("Log Options: ")
                for option, value in log_options.data.items():
                    logging.info(f"\t{option} = {value}")
                logging.info(f"Comment: {rule.comment}")
                logging.info("--------------------------------------")
    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to use policy rule counters to perform potential '
                    'cleanup based on whether rules have hit counts associating them '
                    'with activity.',
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
