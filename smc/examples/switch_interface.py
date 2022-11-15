"""
Example script to show how to use Switch interfaces
-create switch interface/port group for an engine
-display switch interface
-delete switch interface

Needs Demo mode
"""

# Python Base Import
import smc.examples

from smc import session
from smc.core.engines import Layer3Firewall
from smc_info import *


if __name__ == "__main__":
    session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120, api_version=API_VERSION)
    print("session OK")

try:
    single_fw = Layer3Firewall("Plano")
    single_fw.switch_physical_interface.add_switch_interface(1, "110", "My new switch interface")

    # retrieve interface id
    switch_interface_id = single_fw.switch_physical_interface.all()[0].interface_id

    single_fw.switch_physical_interface \
             .add_port_group_interface(switch_interface_id, 1, [1],
                                       interfaces=[{'nodes': [{'address': '12.12.12.12',
                                                               'network_value': '12.12.12.0/24',
                                                               'nodeid': 1}]}])
    single_fw.switch_physical_interface \
             .add_port_group_interface(switch_interface_id, 2, [2, 3, 4, 5])

    print("{}:{}".format(switch_interface_id,
                         single_fw.switch_physical_interface.get(switch_interface_id)))

    for interface in single_fw.switch_physical_interface:
        print("{}: {}".format(interface, interface.port_group_interface))

    interface = single_fw.switch_physical_interface.get(switch_interface_id)
    for sub_intf in interface.all_interfaces:
        intf_id = sub_intf.data.interface_id
        print("{}: {}".format(intf_id, sub_intf))

except Exception as e:
    print(e)
    exit(-1)
finally:
    single_fw.switch_physical_interface.get(switch_interface_id).delete()
    session.logout()
