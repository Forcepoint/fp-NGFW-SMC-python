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
Example script for template policy
-create FirewallTemplatePolicy
-add a rule
-add a section
-add an insert point
-add an automatic rules insert point
"""

# Python Base Import
import argparse
import logging
import sys

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.policy.layer3 import FirewallTemplatePolicy  # noqa
from smc.elements.service import TCPService  # noqa

WRONG_RULE = "Wrong rule in assert!"

logging.getLogger()
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - '
                                                '%(name)s - [%(levelname)s] : %(message)s')


def search_rule_by_name(policy, name):
    for rule in policy.search_rule(name):
        if rule.name == name:
            return rule

    return None


def main():
    return_code = 0
    try:
        arguments = parse_command_line_arguments()
        session.login(url=arguments.api_url, api_key=arguments.api_key,
                      login=arguments.smc_user,
                      pwd=arguments.smc_pwd, api_version=arguments.api_version)
        logging.info("session OK")

        # Create a Template Policy
        myPolicy = FirewallTemplatePolicy().create("myTemplatePolicy1",
                                                   template=None)

        # add rule to a Template Policy
        myPolicy = FirewallTemplatePolicy("myTemplatePolicy1")
        rule1 = myPolicy.fw_ipv4_access_rules.create(
            name="newrule",
            sources="any",
            destinations="any",
            services=[TCPService("SSH")],
            action="discard",
        )

        # add section after
        section = myPolicy.fw_ipv4_access_rules.create_rule_section(name="my section",
                                                                    after=rule1.tag)

        # add insert point after
        myPolicy.fw_ipv4_access_rules.create_insert_point(name="my insert point",
                                                          insert_point_type="normal",
                                                          after=section.tag)

        # add automatic rules insert point at first
        myPolicy.fw_ipv4_access_rules.create_insert_point(name="Automatic Rules insert point",
                                                          insert_point_type="automatic",
                                                          add_pos=1)

        logging.info("All rules:")
        for rule in myPolicy.fw_ipv4_access_rules:
            logging.info(rule)

        # check automatic rules insert point is rule 1
        automatic_ip = myPolicy.fw_ipv4_access_rules.get(0)
        assert hasattr(automatic_ip, "type") and automatic_ip.type == "automatic", WRONG_RULE

        # check section is rule 3
        section = myPolicy.fw_ipv4_access_rules.get(2)
        assert section.is_rule_section is True, WRONG_RULE

        # check insert point is rule 4
        insert_point = myPolicy.fw_ipv4_access_rules.get(3)
        assert hasattr(insert_point, "type") and insert_point.type == "normal", WRONG_RULE

        # search for the rule
        rule1 = search_rule_by_name(myPolicy, "newrule")
        logging.info(f"Search 'newrule': {rule1} src={rule1.sources} "
                     f"dst={rule1.destinations} action={rule1.action.action}")

        logging.info("All FW template policies:")
        logging.info(list(FirewallTemplatePolicy.objects.all()))
    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        FirewallTemplatePolicy("myTemplatePolicy1").delete()
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to use Template Policies',
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


if __name__ == "__main__":
    sys.exit(main())
