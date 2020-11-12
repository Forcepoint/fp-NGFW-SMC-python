"""
Example script
-create SubPolicy and IPv6SubPolicy
-return all FirewallSubPolicy and FirewallIPv6SubPolicy.

"""

# Python Base Import
import sys
from smc import session
from smc.policy.layer3 import FirewallSubPolicy, FirewallIPv6SubPolicy
from smc.elements.service import TCPService

if __name__ == '__main__':
    URLSMC='http://localhost:8082'
    APIKEYSMC='HuphG4Uwg4dN6TyvorTR0001'
    try:
        session.login(url=URLSMC, api_key=APIKEYSMC, verify=False, timeout=120)
    except BaseException as exception_retournee:
        sys.exit(-1)

    print("session OK")

# Create a Sub Policy
p = FirewallSubPolicy()
p.create("mySubPolicy1")

# add rule to a Sub Policy
p = FirewallSubPolicy('mySubPolicy1')
p.fw_ipv4_access_rules.create(
    name='newule',
    sources='any',
    destinations='any',
    services=[TCPService('SSH')],
    action='discard')

print(list(FirewallSubPolicy.objects.all()))

# Create a IPv6 Sub Policy
p = FirewallIPv6SubPolicy()
p.create("myIPv6SubPolicy1")

# add rule to a IPv6 Sub Policy
p = FirewallIPv6SubPolicy('myIPv6SubPolicy1')
p.fw_ipv6_access_rules.create(
    name='newule',
    sources='any',
    destinations='any',
    services=[TCPService('SSH')],
    action='discard')

print(list(FirewallIPv6SubPolicy.objects.all()))
