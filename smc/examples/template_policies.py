"""
Example script for template policy
-create FirewallTemplatePolicy
-add a rule
-add a section
-add an insert point
-add an automatic rules insert point
"""

# Python Base Import
import smc.examples

from smc import session
from smc.policy.layer3 import FirewallTemplatePolicy
from smc.elements.service import TCPService
from smc_info import SMC_URL, API_KEY, API_VERSION

WRONG_RULE = "Wrong rule in assert!"


def search_rule_by_name(policy, name):
    for rule in policy.search_rule(name):
        if rule.name == name:
            return rule

    return None


if __name__ == "__main__":

    session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120, api_version=API_VERSION)

    print("session OK")
    try:

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

        print("All rules:")
        for rule in myPolicy.fw_ipv4_access_rules:
            print(rule)

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
        print("Search 'newrule': {} src={} dst={} action={}".format(rule1,
                                                                    rule1.sources,
                                                                    rule1.destinations,
                                                                    rule1.action.action))

        print("All FW template policies:")
        print(list(FirewallTemplatePolicy.objects.all()))

    except BaseException as e:
        print("ex={}".format(e))
        exit(-1)
    finally:
        FirewallTemplatePolicy("myTemplatePolicy1").delete()
        session.logout()
