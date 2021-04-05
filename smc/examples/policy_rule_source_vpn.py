"""
Example script to show how to use SourceVpn
-create Policy
-create SourceVpn sub element
-create rule with SourceVon option
-display rule content
"""

# Python Base Import
import sys
from smc import session
from smc.elements.service import TCPService
from smc.policy.layer3 import FirewallPolicy
from smc.policy.rule_elements import SourceVpn
from smc.vpn.policy import PolicyVPN

if __name__ == '__main__':
    URLSMC='http://localhost:8082'
    APIKEYSMC='HuphG4Uwg4dN6TyvorTR0001'
    try:
        session.login(url=URLSMC, api_key=APIKEYSMC, verify=False, timeout=120, api_version='6.10')
    except BaseException as exception_retournee:
        sys.exit(-1)

    print("session OK")

try:
    # Create a Policy
    p = FirewallPolicy()
    p.create("myPolicy1")

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
    p = FirewallPolicy('myPolicy1')
    p.fw_ipv4_access_rules.create(
     name='newule',
     sources='any',
     destinations='any',
     services=[TCPService('SSH')],
     action='discard',
     match_vpn_options=sourceVpn)

    # add rule without match_vpn_options to a Policy
    p.fw_ipv4_access_rules.create(
     name='newule',
     sources='any',
     destinations='any',
     services=[TCPService('SSH')],
     action='discard')

    # Display SourceVpn for rules
    for rule in p.fw_ipv4_access_rules.all():
        print("Rule:{} SourceVpn:{}".format(rule.name, rule.match_vpn_options))

finally:
    # Delete policy
    p = FirewallPolicy('myPolicy1')
    p.delete()
    session.logout()
