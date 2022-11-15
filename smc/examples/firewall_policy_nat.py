"""
Create a policy with nat rules
"""
import smc.examples

from smc import session
from smc.elements.service import TCPService
from smc.policy.layer3 import FirewallPolicy
from smc.elements.network import Host, Alias
from smc_info import *

import json
import logging

logging.getLogger()
logging.basicConfig(level=logging.INFO)

if __name__ == "__main__":

    session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120, api_version=API_VERSION)

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
    print(nat_rules)  # smc.base.collection.IPv4NATRule
    for r in nat_rules.all():
        print("==================================")
        print(r)  # IPv4NATRule
        print(r.name)  # IPv4NATRule
        print(r.destinations)
        print(r.sources)
        print(r.services)
        print(json.dumps(r.data["options"].get("dynamic_src_nat")))
        print(json.dumps(r.data["options"].get("static_src_nat")))
        print(json.dumps(r.data["options"].get("static_dst_nat")))

        dynamic_src_nat = r.dynamic_src_nat  # mbr of NATRule
        print(r.dynamic_src_nat)  # smc.policy.rule_nat.DynamicSourceNAT
        print(r.dynamic_src_nat.translated_value)
        print(r.static_src_nat)  # smc.policy.rule_nat.StaticSourceNAT
        print(r.static_dst_nat)  # smc.policy.rule_nat.StaticDestNAT

    session.logout()
