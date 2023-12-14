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
Create a policy with nat rules
"""
import argparse
import logging
import sys
import json

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.elements.service import TCPService  # noqa
from smc.policy.layer3 import FirewallPolicy  # noqa
from smc.elements.network import Host, Alias  # noqa

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

        policy = FirewallPolicy.get("mynatpolicy1", raise_exc=False)
        if policy:
            policy.delete()

        kali_host = Host.get_or_create(name="kali", address="1.1.1.1")
        host3 = Host.get_or_create(name="host-3.3.3.3", address="3.3.3.3")
        dest = Host.get_or_create(name="dest", address="3.3.3.3")
        dest_nat = Host.get_or_create(name="dest_nat", address="3.3.3.4")

        policy = FirewallPolicy.create(name="mynatpolicy1", template="Firewall Inspection Template")

        new_rule = policy.fw_ipv4_nat_rules.create(name="update_automatic_proxy",
                                                   services=[TCPService("FTP")],
                                                   sources=[Host("kali")],
                                                   destinations=[Host("dest")],
                                                   comment='IPSec Automatic Rule',
                                                   dynamic_src_nat=None,
                                                   static_dst_nat=Host("dest_nat"),
                                                   validate=False)
        # need to provide all dst nat attributes
        new_rule.update(static_dst_nat=Host("dest_nat"),
                        destinations=[Host("dest")],
                        static_dst_nat_automatic_proxy=True,
                        validate=False)

        # still possible to update by injecting json
        options = {'static_dst_nat': {'automatic_proxy': False}}
        # append_lists=True will merge automatic_proxy attribute with existing static_dst_nat
        new_rule.update(options=options, append_lists=True)

        # Example of creating a dynamic source NAT for host 'kali':
        rule1 = policy.fw_ipv4_nat_rules.create(
            name="mynatrule-srcdyn",
            sources=[Host("kali")],
            destinations="any",
            services="any",
            dynamic_src_nat="1.1.1.1",
            dynamic_src_nat_ports=(1024, 65535),
        )

        rule1.update(dynamic_src_nat="1.1.1.2",
                     dynamic_src_nat_ports=(2048, 65535),
                     )

        options = {'dynamic_src_nat': {'automatic_proxy': True,
                                       'translation_values': [
                                           {'ip_descriptor': '1.1.1.3',
                                            'max_port': 65535,
                                            'min_port': 1024}]
                                       },
                   'log_accounting_info_mode': False,
                   'log_closing_mode': True,
                   'log_level': 'undefined',
                   'log_payload_excerpt': False,
                   'log_payload_record': False,
                   'log_severity': -1}

        # Need to stay compatible with json injection
        rule1.update(services=[TCPService("FTP")], options=options)

        # Example of creating a static source NAT for host 'kali':
        policy.fw_ipv4_nat_rules.create(
            name="mynatrule-srcstat",
            sources=[kali_host],
            destinations="any",
            services="any",
            static_src_nat="1.1.1.1",
        )

        # Example of creating a destination NAT rule for destination host
        # '3.3.3.3' with destination translation address of '1.1.1.1':
        policy.fw_ipv4_nat_rules.create(
            name="mynatrule-desthost",
            sources="any",
            destinations=[host3],
            services="any",
            static_dst_nat="1.1.1.1",
        )

        # Destination NAT with destination port translation:
        policy.fw_ipv4_nat_rules.create(
            name="mynatrule-destport",
            sources="any",
            destinations=[Alias("$$ Interface ID 0.ip")],
            services="any",
            static_dst_nat="1.1.1.1",
            static_dst_nat_ports=(2222, 22),
        )

        nat_rules = policy.fw_ipv4_nat_rules
        logging.info(nat_rules)  # smc.base.collection.IPv4NATRule
        for r in nat_rules.all():
            logging.info("==================================")
            logging.info(r)  # IPv4NATRule
            logging.info(r.name)  # IPv4NATRule
            logging.info(r.destinations)
            logging.info(r.sources)
            logging.info(r.services)
            logging.info(json.dumps(r.data["options"].get("dynamic_src_nat")))
            logging.info(json.dumps(r.data["options"].get("static_src_nat")))
            logging.info(json.dumps(r.data["options"].get("static_dst_nat")))

            dynamic_src_nat = r.dynamic_src_nat  # mbr of NATRule
            logging.info(r.dynamic_src_nat)  # smc.policy.rule_nat.DynamicSourceNAT
            logging.info(r.dynamic_src_nat.translated_value)
            logging.info(r.static_src_nat)  # smc.policy.rule_nat.StaticSourceNAT
            logging.info(r.static_dst_nat)  # smc.policy.rule_nat.StaticDestNAT
    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to create a policy with nat rules',
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
