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
Example script
-create SubPolicy and IPv6SubPolicy
-update a rule
-create IPSPolicy and ips_ipv4_access_rules
-return all FirewallSubPolicy and FirewallIPv6SubPolicy.

"""

# Python Base Import
import argparse
import logging
import sys

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.compat import is_api_version_less_than_or_equal, is_api_version_less_than  # noqa
from smc.core.engines import Layer3Firewall  # noqa
from smc.elements.network import Host, Network  # noqa
from smc.policy.ips import IPSPolicy, IPSSubPolicy  # noqa
from smc.policy.layer3 import FirewallSubPolicy, FirewallIPv6SubPolicy  # noqa
from smc.elements.service import TCPService  # noqa
from smc.policy.rule_elements import Action, Source  # noqa
from smc.vpn.elements import ExternalGateway  # noqa
from smc.vpn.policy import PolicyVPN  # noqa


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

        # Create a Sub Policy
        p = FirewallSubPolicy().create("mySubPolicy1")

        # add rule to a Sub Policy
        p = FirewallSubPolicy("mySubPolicy1")
        rule1 = p.fw_ipv4_access_rules.create(
            name="newrule",
            sources="any",
            destinations="any",
            services=[TCPService("SSH")],
            action="discard",
        )

        logging.info("Create Engine:myFW..")
        engine = Layer3Firewall.create(name="myFw",
                                       mgmt_ip="192.168.10.1",
                                       mgmt_network="192.168.10.0/24")

        if not is_api_version_less_than("7.0"):
            logging.info("Create block_list rule:")
            # add apply block list action rule with restricted allowed block lister
            block_list_action = Action()
            block_list_action.action = ["block_list"]
            block_list_action.valid_block_lister = [engine.href]
            rule_block_list = p.fw_ipv4_access_rules.create(
                    name="block_list_rule",
                    sources="any",
                    destinations="any",
                    services=[TCPService("SSH")],
                    action=block_list_action,
                )

        # check backward compatibility for blacklist renaming
        logging.info("Create blacklist rule:")
        blacklist_action = Action()
        blacklist_action.action = ["blacklist"]
        blacklist_action.valid_blacklister = [engine.href]
        rule_block_list = p.fw_ipv4_access_rules.create(
            name="blacklist_rule",
            sources="any",
            destinations="any",
            services=[TCPService("FTP")],
            action=blacklist_action,
        )

        # Create external gateway used by PolicyVpn, its end-point and site
        external_gateway = ExternalGateway.create("remoteside")
        external_gateway.external_endpoint.create(name="remoteendpoint", address="2.2.2.2")
        network = Network.create(name='remotenet', ipv4_network='172.18.10.0/24', broadcast=True)
        external_gateway.vpn_site.create("remote-site", [network.href])

        fw = Layer3Firewall("Plano")
        vpn = PolicyVPN.create("myVpn")
        vpn.open()
        vpn.add_central_gateway(fw.internal_gateway.internal_gateway.href)
        vpn.add_satellite_gateway(external_gateway.href)
        vpn.save()
        vpn.close()

        # action is a string.. still compatible with 6.5
        rule_vpn = p.fw_ipv4_access_rules.create(
            name="newrule_vpn",
            sources=[Network("London Internal Network")],
            destinations=[Network("net-172.31.14.0/24")],
            services="any",
            action="apply_vpn",
            vpn_policy=vpn)

        # Since API 6.6 action is a list
        vpn_actions = Action()
        vpn_actions.action = ['allow', 'apply_vpn']
        p.fw_ipv4_access_rules.create(name='',
                                      sources=[Network("London Internal Network")],
                                      destinations=[Network("net-172.31.14.0/24")],
                                      services='any', action=vpn_actions, vpn_policy=vpn)

        # create rule using Source, Destination, Service and Action object
        rule_action = Action()
        rule_action.action = ["discard"]
        rule_action.deep_inspection = True
        rule_action.scan_detection = "on"
        rule_source = Source()
        rule_source.set_any()
        rule_a = p.fw_ipv4_access_rules.create(
            name="newrule_a",
            sources=rule_source,
            destinations="any",
            services=[TCPService("SSH")],
            action=rule_action,
        )

        # Create hosts
        host1 = Host.create("myHost1", "192.168.1.1")
        host2 = Host.create("myHost2", "192.168.1.2")
        host3 = Host.create("myHost3", "192.168.1.3")

        #  update rule using Source, Destination, Service and Action object
        rule_action.action = ["allow"]
        rule_source.unset_any()
        rule_source.add_many([host1, host2])
        rule_a.update(sources=rule_source,
                      destinations="any",
                      services=[TCPService("FTP")],
                      action=rule_action)
        logging.info(f"After update {rule_a} action={rule_a.action.action}")
        if is_api_version_less_than_or_equal("6.5"):
            assert search_rule_by_name(p, "newrule_a").action.action == "allow", WRONG_RULE
        else:
            assert search_rule_by_name(p, "newrule_a").action.action == ["allow"], WRONG_RULE

        # update the rule
        # can mix element and element.href
        # like for create, to be compatible with 6.5, we can set action as a String
        # it will be converted to a list of String for api > 6.5
        rule1.update(sources=[host1, host2.href],
                     destinations=[host3],
                     services=[TCPService("FTP")],
                     action="allow")
        logging.info(f"After update {rule1} src={rule1.sources} dst={rule1.destinations}")
        assert search_rule_by_name(p, "newrule").destinations.dst[0] == host3, WRONG_RULE

        # Need to keep backward compatibility and let user inject json code or Elements or href
        # action can also be a list since Api 6.6
        rule1.update(sources={"src": [host1.href]},
                     destinations=[host3],
                     services=[TCPService("FTP").href],
                     action=["allow"])
        logging.info(f"After update {rule1} src={rule1.sources} dst={rule1.destinations} "
                     f"action={rule1.action.action}")
        assert search_rule_by_name(p, "newrule").sources.src[0] == host1, WRONG_RULE

        # action can also be json injection both str and list are accepted
        rule1.update(sources={"src": [host1.href]},
                     destinations=[host3],
                     services=[TCPService("FTP").href],
                     action={"action": "deny"})
        logging.info(f"After update {rule1} src={rule1.sources} dst={rule1.destinations} "
                     f"action={rule1.action.action}")

        if is_api_version_less_than_or_equal("6.5"):
            assert search_rule_by_name(p, "newrule").action.action == "deny", WRONG_RULE
        else:
            assert search_rule_by_name(p, "newrule").action.action == ["deny"], WRONG_RULE

        # action can also be json injection both str and list are accepted
        rule1.update(sources={"src": [host1.href]},
                     destinations=[host3],
                     services=[TCPService("FTP").href],
                     action={"action": ["deny"]})
        logging.info(f"After update {rule1} src={rule1.sources} dst={rule1.destinations} "
                     f"action={rule1.action.action}")

        if is_api_version_less_than_or_equal("6.5"):
            assert search_rule_by_name(p, "newrule").action.action == "deny", WRONG_RULE
        else:
            assert search_rule_by_name(p, "newrule").action.action == ["deny"], WRONG_RULE

        # search for the rule
        rule1 = search_rule_by_name(p, "newrule")

        # update the rule
        rule1.sources.set_any()
        rule1.destinations.add(host2)
        # Save rule1 in DB
        rule1.save()

        rule1 = search_rule_by_name(p, "newrule")
        logging.info(f"Search 'newrule': {rule1} src={rule1.sources} dst={rule1.destinations} "
                     f"action={rule1.action.action}")

        assert rule1.sources.is_any, WRONG_RULE
        assert rule1.destinations.dst == [host2, host3], WRONG_RULE
        if is_api_version_less_than_or_equal("6.5"):
            assert rule1.action.action == "deny", WRONG_RULE
        else:
            assert rule1.action.action == ["deny"], WRONG_RULE

        # Create a second Sub Policy
        p2 = FirewallSubPolicy().create("mySubPolicy2")

        # add rule to a Sub Policy
        p2 = FirewallSubPolicy("mySubPolicy2")
        rule2 = p2.fw_ipv4_access_rules.create(
            name="rule2",
            sources="any",
            destinations="any",
            services="any",
            action="allow",
        )

        # add jump rule
        rule1 = p.fw_ipv4_access_rules.create(
            name="jump_rule",
            sources="any",
            destinations="any",
            services=[TCPService("SSH")],
            action="jump",
            sub_policy=p2.href
        )

        # retrieve rules for sub policy
        jump_rule = p.search_rule("jump_rule")
        if jump_rule[0].action.action[0] == "jump":
            for r in jump_rule[0].action.sub_policy.fw_ipv4_access_rules.all():
                logging.info(f"sub rule:{r}")

        # Test IPS policy and Sub Policy
        ips_policy = IPSPolicy.create("myIPSPolicy1")
        ips_sub_policy = IPSSubPolicy.create("myIPSSubPolicy1")

        # create rule for IPS Sub Policy
        rule2 = ips_sub_policy.ips_ipv4_access_rules.create(
            name="rule2",
            sources="any",
            destinations="any",
            services="any",
            action="allow"
        )

        # create jump rule for IPS Policy
        rule1 = ips_policy.ips_ipv4_access_rules.create(
            name="ips_jump_rule",
            sources="any",
            destinations="any",
            services=[TCPService("SSH")],
            action="jump",
            sub_policy=ips_sub_policy.href
        )

        # retrieve rules for ips sub policy
        jump_rule = ips_policy.search_rule("ips_jump_rule")
        if jump_rule[0].action.action[0] == "jump":
            for r in jump_rule[0].action.sub_policy.ips_ipv4_access_rules.all():
                logging.info(f"sub ips rule:{r}")

        logging.info("All FW sub-policies:")
        logging.info(list(FirewallSubPolicy.objects.all()))

        logging.info("All IPS sub-policies:")
        logging.info(list(IPSSubPolicy.objects.all()))

        # IPv6 SUB Policy
        logging.info("Add myIPv6SubPolicy1:")
        # Create a IPv6 Sub Policy
        p = FirewallIPv6SubPolicy()
        p.create("myIPv6SubPolicy1")

        # add rule to a IPv6 Sub Policy
        p = FirewallIPv6SubPolicy("myIPv6SubPolicy1")
        p.fw_ipv6_access_rules.create(
            name="new_rule",
            sources="any",
            destinations="any",
            services=[TCPService("SSH")],
            action="discard",
        )

        logging.info(list(FirewallIPv6SubPolicy.objects.all()))

    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        FirewallSubPolicy("mySubPolicy1").delete()
        Layer3Firewall("myFw").delete()
        PolicyVPN("myVpn").delete()
        ExternalGateway("remoteside").delete()
        Network("remotenet").delete()
        FirewallSubPolicy("mySubPolicy2").delete()
        Host("myHost1").delete()
        Host("myHost2").delete()
        Host("myHost3").delete()
        IPSPolicy("myIPSPolicy1").delete()
        IPSSubPolicy("myIPSSubPolicy1").delete()
        FirewallIPv6SubPolicy("myIPv6SubPolicy1").delete()
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to use Sub-policies',
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
