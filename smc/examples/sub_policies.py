"""
Example script
-create SubPolicy and IPv6SubPolicy
-update a rule
-create IPSPolicy and ips_ipv4_access_rules
-return all FirewallSubPolicy and FirewallIPv6SubPolicy.

"""

# Python Base Import
from smc import session
from smc.elements.network import Host
from smc.policy.ips import IPSPolicy, IPSSubPolicy
from smc.policy.layer3 import FirewallSubPolicy, FirewallIPv6SubPolicy
from smc.elements.service import TCPService
from smc_info import *

if __name__ == "__main__":

    session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120, api_version=API_VERSION)

    print("session OK")
    try:

        # Create hosts
        host1 = Host.create("myHost1", "192.168.1.1")
        host2 = Host.create("myHost2", "192.168.1.2")
        host3 = Host.create("myHost3", "192.168.1.3")

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

        # update the rule
        # can mix element and element.href
        # like for create, to be compatible with 6.5, we can set action as a String
        # it will be converted to a list of String for api > 6.5
        rule1.update(sources=[host1, host2.href],
                     destinations=[host3],
                     services=[TCPService("FTP")],
                     action="allow")
        print("After update {} src={} dst={}".format(rule1, rule1.sources, rule1.destinations))

        # Need to keep backward compatibility and let user inject json code or Elements or href
        # action can also be a list since Api 6.6
        rule1.update(sources={"src": [host1.href]},
                     destinations=[host3],
                     services=[TCPService("FTP").href],
                     action=["allow"])
        print("After update {} src={} dst={} action={}".format(rule1,
                                                               rule1.sources,
                                                               rule1.destinations,
                                                               rule1.action.action))

        # action can also be json injection both str and list are accepted
        rule1.update(sources={"src": [host1.href]},
                     destinations=[host3],
                     services=[TCPService("FTP").href],
                     action={"action": "deny"})
        print("After update {} src={} dst={} action={}".format(rule1,
                                                               rule1.sources,
                                                               rule1.destinations,
                                                               rule1.action.action))
        # action can also be json injection both str and list are accepted
        rule1.update(sources={"src": [host1.href]},
                     destinations=[host3],
                     services=[TCPService("FTP").href],
                     action={"action": ["deny"]})
        print("After update {} src={} dst={} action={}".format(rule1,
                                                               rule1.sources,
                                                               rule1.destinations,
                                                               rule1.action.action))

        # search for the rule
        rule1 = p.search_rule("newrule")
        print("Search 'newrule': {} src={} dst={} action={}".format(rule1[0],
                                                                    rule1[0].sources,
                                                                    rule1[0].destinations,
                                                                    rule1[0].action.action))
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
                print("sub rule:{}".format(r))

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
                print("sub ips rule:{}".format(r))

        print("All FW sub-policies:")
        print(list(FirewallSubPolicy.objects.all()))

        print("All IPS sub-policies:")
        print(list(IPSSubPolicy.objects.all()))

        # IPv6 SUB Policy
        print("Add myIPv6SubPolicy1:")
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

        print(list(FirewallIPv6SubPolicy.objects.all()))

    except BaseException as e:
        print("ex={}".format(e))
        exit(-1)
    finally:
        FirewallSubPolicy("mySubPolicy1").delete()
        FirewallSubPolicy("mySubPolicy2").delete()
        Host("myHost1").delete()
        Host("myHost2").delete()
        Host("myHost3").delete()
        IPSPolicy("myIPSPolicy1").delete()
        IPSSubPolicy("myIPSSubPolicy1").delete()
        FirewallIPv6SubPolicy("myIPv6SubPolicy1").delete()
        session.logout()
