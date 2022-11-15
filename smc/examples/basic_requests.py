"""
Example to show how to use SMCRequest to create, update and delete data in SMC
this is low level interface and can be used for elements not yet supported
"""
import smc.examples

from smc import session
from smc.api.common import SMCRequest
from smc.base.util import merge_dicts
from smc.core.engines import Layer3Firewall
from smc_info import *


if __name__ == "__main__":
    session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120, api_version=API_VERSION)
    print("session OK")

try:

    # Create NTP server
    ntp_server_json = {
        "address": "192.168.1.200",
        "comment": "NTP Server created by the SMC API",
        "name": "NTP Server",
        "ntp_auth_key_type": "none"
    }
    new_ntp_server = SMCRequest(href=session.entry_points.get("ntp"), json=ntp_server_json).create()
    ntp_server = SMCRequest(href=new_ntp_server.href).read()

    # create Layer3 FW with NTPServer and timezone
    Layer3Firewall.create(name="myFw",
                          mgmt_ip="192.168.10.1",
                          mgmt_network="192.168.10.0/24",
                          extra_opts={"ntp_settings": {"ntp_enable": True,
                                                       "ntp_server_ref": [new_ntp_server.href]},
                                      "timezone": "Europe/Paris"}
                          )

    # Update NTP server settings and timezone for the Firewall
    # Disable NTP Server
    engine = Layer3Firewall("myFw")
    merge_dicts(engine.data, {"ntp_settings": {"ntp_enable": False, "ntp_server_ref": []}})
    # Remove timezone
    engine.data.pop("timezone", None)
    engine.update(json=engine.data,
                  etag=engine.etag)

    # Create LLDP Profile
    lldp_profile_json = {
            "name": "NewLLDPProfile",
            "hold_time_multiplier": 4,
            "transmit_delay": 30,
            "chassis_id": True,
            "management_address": True,
            "port_description": True,
            "port_id": True,
            "system_capabilities": True,
            "system_description": True,
            "system_name": True,
            "time_to_live": True
        }
    new_lldp_profile = SMCRequest(href=session.entry_points.get("lldp_profile"),
                                  json=lldp_profile_json).create()

    # create Layer3 FW with LLDPProfile
    lldp_profile = SMCRequest(href=new_lldp_profile.href).read()
    Layer3Firewall.create(name="myFw_lldp",
                          mgmt_ip="192.168.10.1",
                          mgmt_network="192.168.10.0/24",
                          extra_opts={"lldp_profile_ref": new_lldp_profile.href}
                          )

    # add physical interface
    fw = Layer3Firewall("myFw_lldp")
    fw.physical_interface.add_layer3_interface(interface_id=1,
                                               address="10.10.10.1",
                                               network_value="10.10.10.0/24")
    # Update LLDP profile
    interface = fw.physical_interface.get(1)
    merge_dicts(interface.data, {"lldp_mode": "send_and_receive"})
    interface.update(json=interface.data,
                     etag=interface.etag)

except BaseException as e:
    print("ex={}".format(e))
    exit(-1)
finally:
    # Delete NTP server and Firewall
    Layer3Firewall("myFw").delete()
    request = SMCRequest(href=new_ntp_server.href, headers={"if-match": ntp_server.etag})
    request.delete()

    # Delete LLDP Profile and Firewall
    Layer3Firewall("myFw_lldp").delete()
    request = SMCRequest(href=new_lldp_profile.href, headers={"if-match": lldp_profile.etag})
    request.delete()
    session.logout()
