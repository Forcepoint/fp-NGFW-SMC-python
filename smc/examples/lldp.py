"""
Example of how to create and use Link Layer Discovery Protocol
"""
import smc.examples

from smc import session
from smc.core.engines import Layer3Firewall, FirewallCluster
from smc.core.lldp import LLDPProfile
from smc.elements.helpers import zone_helper
from smc_info import SMC_URL, API_KEY, API_VERSION

WRONG_PROFILE = "Wrong LLDP Profile in assert!"
WRONG_MODE = "Wrong LLDP Mode in assert!"

if __name__ == "__main__":
    session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120, api_version=API_VERSION)
    print("session OK")

try:
    # Create LLDP Profile
    new_lldp_profile = LLDPProfile().create(name="myLLDPProfile",
                                            comment="LLDP Profile created by the SMC API",
                                            transmit_delay=10,
                                            hold_time_multiplier=4,
                                            system_name=True,
                                            system_description=True,
                                            system_capabilities=True,
                                            management_address=True
                                            )

    lldp_profile1 = LLDPProfile().create(name="myLLDPProfile1",
                                         comment="LLDP Profile 1",
                                         transmit_delay=10,
                                         hold_time_multiplier=4,
                                         system_name=True,
                                         system_description=True,
                                         system_capabilities=True,
                                         management_address=True
                                         )

    # update lldp profile
    lldp_profile = LLDPProfile.update_or_create(name="myLLDPProfile",
                                                system_name=False,
                                                comment="profile updated")

    # Assign LLDP Profile to firewall
    Layer3Firewall.create(name="myFw",
                          mgmt_ip="192.168.10.1",
                          mgmt_network="192.168.10.0/24",
                          lldp_profile=lldp_profile
                          )

    fw = Layer3Firewall("myFw")
    assert fw.lldp_profile == lldp_profile, WRONG_PROFILE

    # Change LLDP Profile
    fw.update(lldp_profile_ref=lldp_profile1.href)
    assert fw.lldp_profile == lldp_profile1, WRONG_PROFILE

    # add physical interface with LLDP mode enabled
    fw.physical_interface.add_layer3_interface(interface_id=1,
                                               address="10.10.10.1",
                                               network_value="10.10.10.0/24",
                                               zone_ref=zone_helper("External"),
                                               lldp_mode="send_and_receive"
                                               )

    assert Layer3Firewall("myFw").physical_interface.get(1)\
                                                    .lldp_mode == "send_and_receive", WRONG_MODE

    # use add method create 2nd interface (only the interface layer)
    fw.physical_interface.add(interface_id=2,
                              zone_ref=zone_helper("External"),
                              lldp_mode="send_and_receive"
                              )

    assert Layer3Firewall("myFw").physical_interface.get(2) \
                                                    .lldp_mode == "send_and_receive", WRONG_MODE

    # update the lldp mode for the interface
    Layer3Firewall("myFw").physical_interface.get(2).update(lldp_mode="disabled")

    assert Layer3Firewall("myFw").physical_interface.get(2) \
                                                    .lldp_mode == "disabled", WRONG_MODE

    # FW Cluster cases
    # Create the Firewall Cluster
    engine = FirewallCluster.create(
        name="mycluster",
        cluster_virtual="1.1.1.1",
        cluster_mask="1.1.1.0/24",
        network_value="1.1.1.0/24",
        interface_id=0,
        cluster_nic=0,
        macaddress="02:02:02:02:02:02",
        nodes=[
            {"address": "1.1.1.2", "network_value": "1.1.1.0/24", "nodeid": 1},
            {"address": "1.1.1.3", "network_value": "1.1.1.0/24", "nodeid": 2},
            {"address": "1.1.1.4", "network_value": "1.1.1.0/24", "nodeid": 3},
        ],
        timezone="Europe/Paris",
        domain_server_address=["1.1.1.1"],
        zone_ref=zone_helper("Internal"),
        enable_antivirus=True,
        enable_gti=True,
        default_nat=True,
        lldp_profile=lldp_profile
    )

    assert FirewallCluster("mycluster").lldp_profile == lldp_profile, WRONG_PROFILE

    engine.physical_interface.add_layer3_cluster_interface(
        interface_id=1,
        cluster_virtual="5.5.5.1",
        network_value="5.5.5.0/24",
        macaddress="02:03:03:03:03:03",
        nodes=[
            {"address": "5.5.5.2", "network_value": "5.5.5.0/24", "nodeid": 1},
            {"address": "5.5.5.3", "network_value": "5.5.5.0/24", "nodeid": 2},
            {"address": "5.5.5.4", "network_value": "5.5.5.0/24", "nodeid": 3},
        ],
        zone_ref=zone_helper("Heartbeat"),
        lldp_mode="send_only"
    )

    assert FirewallCluster("mycluster").physical_interface.get(1) \
                                                          .lldp_mode == "send_only", WRONG_MODE

except BaseException as e:
    print("ex={}".format(e))
    exit(-1)
finally:
    Layer3Firewall("myFw").delete()
    FirewallCluster("mycluster").delete()
    LLDPProfile("myLLDPProfile").delete()
    LLDPProfile("myLLDPProfile1").delete()
    session.logout()
