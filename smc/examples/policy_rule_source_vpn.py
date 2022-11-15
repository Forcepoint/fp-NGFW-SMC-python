"""
Example script to show how to use SourceVpn
-create Policy
-create SourceVpn sub element
-create rule with SourceVon option
-display rule content
"""

# Python Base Import
import smc.examples

from smc import session
from smc.base.util import element_resolver
from smc.elements.alerts import CustomAlert
from smc.elements.service import TCPService
from smc.policy.layer3 import FirewallPolicy
from smc.policy.rule_elements import SourceVpn
from smc.vpn.policy import PolicyVPN
from smc_info import *


custom_fw_policy = "myPolicy1"
custom_alert_name = "My Alert"

if __name__ == "__main__":

    session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120, api_version=API_VERSION)

    print("session OK")

try:
    # Create a Policy
    p = FirewallPolicy()
    p.create(custom_fw_policy)

    # get Vpn list
    vpns = PolicyVPN.objects.all()
    list_vpn = []
    for vpn in vpns:
        print(vpn)
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
        print("Rule:{} SourceVpn:{} Options:{}".format(rule.name,
                                                       rule.match_vpn_options,
                                                       rule.options))
        if rule.name == 'newrule1':
            assert rule.options.log_accounting_info_mode and \
                   rule.options.url_category_logging == 'enforced' and \
                   rule.options.endpoint_executable_logging == 'enforced',\
                   "Log accounting info mode is not True as it should be."
        else:
            assert rule.options.log_level == 'alert' and \
                   rule.options.log_alert == my_alert, \
                   "Rule2 should be with alert log_level and {} as alert.".format(custom_alert_name)
finally:
    # Delete elements
    FirewallPolicy(custom_fw_policy).delete()
    CustomAlert(custom_alert_name).delete()

    session.logout()
