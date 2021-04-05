"""
Example script to show how to use Engine Node health
-get virtual engine or Layer3 firewall
-get health data for each node
-retrieve master engine from virtual engine health
"""

# Python Base Import
import sys
from smc import session
from smc.core.engines import Layer3VirtualEngine, Layer3Firewall

if __name__ == '__main__':
    URLSMC='http://localhost:8082'
    APIKEYSMC='HuphG4Uwg4dN6TyvorTR0001'
    try:
        session.login(url=URLSMC, api_key=APIKEYSMC, verify=False, timeout=120, api_version='6.10')
    except BaseException as exception_retournee:
        sys.exit(-1)

    print("session OK")

try:
    virtual_engine = Layer3VirtualEngine("Dubai Virtual 1")
    for node in virtual_engine.nodes:
        for stats in node.interface_status:
            print("interface status={}".format(stats))
        print("health=>Master Node={}".format(node.health.master_node))
        print("health=>Node status={}".format(node.health.engine_node_status))
        print("health=>dyn up={}".format(node.health.dyn_up))
        # print all attributes
        print("health=>{}".format(node.health))

    single_fw = Layer3Firewall("Plano")
    for node in single_fw.nodes:
        # should be None
        print("health=>Master Node={}".format(node.health.master_node))
        print("health=>Node status={}".format(node.health.engine_node_status))
        print("health=>dyn up={}".format(node.health.dyn_up))
        # print all attributes
        print("health=>{}".format(node.health))

except Exception as e:
        print(e)
finally:
    session.logout()
