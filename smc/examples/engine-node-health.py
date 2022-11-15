"""
Example script to show how to use Engine Node health
-get virtual engine or Layer3 firewall
-get health data for each node
-retrieve master engine from virtual engine health
"""

# Python Base Import
import smc.examples

from smc import session
from smc.core.engines import Layer3VirtualEngine, Layer3Firewall
from smc.core.waiters import NodeStatusWaiter
from smc_info import *


if __name__ == "__main__":
    session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120, api_version=API_VERSION)
    print("session OK")

try:

    virtual_engine = Layer3VirtualEngine("Dubai Virtual 1")
    print("Check nodes status for {}...".format(virtual_engine))

    for node in virtual_engine.nodes:

        # Wait for node to be Online
        waiter = NodeStatusWaiter(node, "Online", max_wait=3)
        while not waiter.done():
            status = waiter.result(5)
            print("Status after 5 sec wait: {}".format(status))
        print("Node:{} is {}".format(node, status))

        assert status is not None, "Node {} can't be contacted".format(node)

        for stats in node.hardware_status.filesystem:
            print("hardware status.filesystem={}".format(stats))
        for stats in node.hardware_status.logging_subsystem:
            print("hardware status.logging_subsystem={}".format(stats))
        for stats in node.hardware_status.sandbox_subsystem:
            print("hardware status.sandbox_subsystem={}".format(stats))
        for stats in node.interface_status:
            print("interface status={}".format(stats))
        print("health=>Master Node={}".format(node.health.master_node))
        print("health=>Node status={}".format(node.health.engine_node_status))
        print("health=>dyn up={}".format(node.health.dyn_up))
        # print all attributes
        print("health=>{}".format(node.health))

    single_fw = Layer3Firewall("Plano")
    print("Check nodes status for {}...".format(single_fw))

    for node in single_fw.nodes:

        # Wait for node to be Online
        waiter = NodeStatusWaiter(node, 'Online', max_wait=3)
        while not waiter.done():
            status = waiter.result(5)
            print("Status after 5 sec wait: {}".format(status))
        print("Node:{} is {}".format(node, status))

        assert status is not None, "Node {} can't be contacted".format(node)

        # should be None
        print("health=>Master Node={}".format(node.health.master_node))
        print("health=>Node status={}".format(node.health.engine_node_status))
        print("health=>dyn up={}".format(node.health.dyn_up))
        # print all attributes
        print("health=>{}".format(node.health))

except Exception as e:
    print(e)
    exit(-1)
finally:
    session.logout()
