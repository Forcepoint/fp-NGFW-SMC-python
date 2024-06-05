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
Example script to show how to use SourceVpn
-create Policy
-create SourceVpn sub element
-create rule with SourceVon option
-display rule content
"""

# Python Base Import
import argparse
import logging
import sys

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.base.util import element_resolver  # noqa
from smc.elements.alerts import CustomAlert  # noqa
from smc.elements.service import TCPService  # noqa
from smc.policy.layer3 import FirewallPolicy  # noqa
from smc.policy.rule_elements import SourceVpn, Action  # noqa
from smc.vpn.policy import PolicyVPN  # noqa
from smc.elements.profiles import UserResponse  # noqa


custom_fw_policy = "myPolicy1"
custom_alert_name = "My Alert"

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
        logging.info("session OK")

        # Create a Policy
        p = FirewallPolicy()
        p.create(custom_fw_policy)

        # get Vpn list
        vpns = PolicyVPN.objects.all()
        list_vpn = []
        for vpn in vpns:
            logging.info(vpn)
            list_vpn.append(vpn.href)

        sourceVpn = SourceVpn()
        sourceVpn.match_type = "normal"
        sourceVpn.match_vpns = list_vpn

        # add rule to a Policy
        p = FirewallPolicy(custom_fw_policy)
        rule1 = p.fw_ipv4_access_rules.create(
            name="newrule1",
            sources="any",
            destinations="any",
            services=[TCPService("SSH")],
            action="discard",
            match_vpn_options=sourceVpn,
        )
        options = {'log_accounting_info_mode': True,
                   'log_closing_mode': False,
                   'log_level': 'stored',
                   'log_payload_excerpt': False,
                   'log_payload_record': False,
                   'url_category_logging': 'enforced',
                   'endpoint_executable_logging': 'enforced',
                   'log_severity': -1}
        rule1.update(options=options)

        # add rule without match_vpn_options to a Policy
        rule2 = p.fw_ipv4_access_rules.create(
            name="newrule2",
            sources="any",
            destinations="any",
            services=[TCPService("SSH")],
            action="discard",
        )
        my_alert = CustomAlert.create(custom_alert_name)
        options = {'log_accounting_info_mode': True,
                   'log_level': 'alert',
                   'log_alert': element_resolver(my_alert),
                   'log_severity': 1,
                   'application_logging': 'enforced'}
        rule2.update(options=options)

        # Display SourceVpn for rules
        for rule in p.fw_ipv4_access_rules.all():
            logging.info(f"Rule:{rule.name} SourceVpn:{rule.match_vpn_options} "
                         f"Options:{rule.options}")
            if rule.name == 'newrule1':
                assert rule.options.log_accounting_info_mode and \
                       rule.options.url_category_logging == 'enforced' and \
                       rule.options.endpoint_executable_logging == 'enforced',\
                       "Log accounting info mode is not True as it should be."
            else:
                assert rule.options.log_level == 'alert' and \
                       rule.options.log_alert == my_alert, \
                       f"Rule2 should be with alert log_level and {custom_alert_name} as alert."
        # Add user response in action
        user_response = UserResponse.objects.first()
        actions = Action()
        actions.user_response = user_response
        actions.deep_inspection = True
        actions.file_filtering = False
        actions.network_application_latency_monitoring = False
        actions.action = "discard"
        p.fw_ipv4_access_rules.create(name='test_user_response',
                                      sources='any',
                                      destinations='any', services='any',
                                      action=actions)
        for rule in p.fw_ipv4_access_rules.all():
            if rule.name == 'test_user_response':
                assert rule.action.user_response.href == user_response.href, "Fail to set user " \
                                                                             "response. "
    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1

    finally:
        # Delete elements
        FirewallPolicy(custom_fw_policy).delete()
        CustomAlert(custom_alert_name).delete()

        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to use policy rule with source vpn',
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
