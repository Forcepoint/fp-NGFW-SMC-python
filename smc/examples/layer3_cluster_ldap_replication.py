"""
Example script to show how to use ldap replication enable/disable function
log server must be running

- create cluster
- do initial contact and wait for nodes READY
- enable ldap replication
"""
import time
import smc.examples


from smc import session
from smc.core.engines import FirewallCluster
from smc.elements.helpers import zone_helper

URLSMC = "localhost:8082"

session.login(url="http://" + URLSMC, api_version="6.10", api_key="HuphG4Uwg4dN6TyvorTR0001")

try:
    # Create the Firewall Cluster
    print("create mycluster")
    cluster = FirewallCluster.create(
        name="mycluster",
        cluster_virtual="1.1.1.1",
        cluster_mask="1.1.1.0/24",
        cluster_nic=0,
        macaddress="02:02:02:02:02:02",
        nodes=[
            {"address": "1.1.1.2", "network_value": "1.1.1.0/24", "nodeid": 1},
            {"address": "1.1.1.3", "network_value": "1.1.1.0/24", "nodeid": 2},
            {"address": "1.1.1.4", "network_value": "1.1.1.0/24", "nodeid": 3},
        ],
        domain_server_address=["1.1.1.1"],
        zone_ref=zone_helper("Internal"),
        enable_antivirus=True,
        enable_gti=True,
        default_nat=True,
        interface_id=1,
        network_value="1.1.1.0/24",
    )

    # do initial contact
    print("do initial contact")
    for node in cluster.nodes:
        node.initial_contact()

    # wait for node status online
    print("Wait for nodes to be READY")
    for node in cluster.nodes:
        status = node.status().monitoring_state
        while status != "READY":
            time.sleep(5)
            status = node.status().monitoring_state
            print("node {} status {}".format(node.name, status))

    # enable LDAP replication
    print("enable ldap replication")
    cluster.ldap_replication(True)

    # check LDAP replication is enabled ( not implemented yet in api )..
    # so have to wait sometime for LDAP replication to be effective
    time.sleep(2)

    print("enable ldap replication twice")
    # enable LDAP replication twice expect an already enabled exception
    cluster.ldap_replication(True)

except Exception as e:
    print(e)

finally:
    print("delete cluster mycluster")
    cluster = FirewallCluster("mycluster")
    cluster.delete()
    session.logout()
