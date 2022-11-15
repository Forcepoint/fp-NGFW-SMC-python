"""
Example of creating an aggregated interface
"""

import smc.examples

from smc.core.engines import Layer3Firewall
from smc import session
from smc_info import *

if __name__ == "__main__":
    session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120, api_version=API_VERSION)
    print("session OK")

try:
    engine = Layer3Firewall.create(
        name="myEngine",
        mgmt_ip="172.18.1.1",
        mgmt_network="172.18.1.0/24",
        mgmt_interface=0,
    )
    engine.physical_interface.add_layer3_interface(interface_id=1,
                                                   address="172.18.2.10",
                                                   network_value="172.18.2.0/24",
                                                   comment="My aggregate interface",
                                                   aggregate_mode="ha",
                                                   second_interface_id=2)

    # retrieve interface id
    for interface in engine.physical_interface.all():
        print("Interfaced created:{}:{}".format(interface.interface_id, interface))

    interface_keys = ['id', 'contact_addresse_ip']
    engine = Layer3Firewall("myEngine")
    # Contact Address information
    interface_inventory = []
    list_itf = []
    for ca in engine.contact_addresses:
        list_itf.append(ca.interface_id)
    uniq_list_itf = list(set(list_itf))
    for itf_id in uniq_list_itf:
        contact = engine.interface.get(itf_id).contact_addresses
        ip = contact[0].interface_ip
        interface_values = [itf_id, ip]
        interface_inventory.append(dict(zip(interface_keys, interface_values)))

    print("interface_inventory={}".format(interface_inventory))
except BaseException as e:
    print("Exception:{}".format(e))
    exit(-1)

finally:
    engine = Layer3Firewall("myEngine")
    engine.delete()
