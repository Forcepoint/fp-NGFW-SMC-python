"""
Example to show how to use SMCRequest to create, update and delete data in SMC
this is low level interface and can be used for elements not yet supported
"""

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

    # create Layer3 FW
    ntp_server = SMCRequest(href=new_ntp_server.href).read()
    Layer3Firewall.create(name="myFw",
                          mgmt_ip="192.168.10.1",
                          mgmt_network="192.168.10.0/24",
                          extra_opts={"ntp_settings": {"ntp_enable": True,
                                                       "ntp_server_ref": [new_ntp_server.href]}}
                          )

    # Update NTP server settings for the Firewall
    engine = Layer3Firewall("myFw")
    merge_dicts(engine.data, {"ntp_settings": {"ntp_enable": False, "ntp_server_ref": []}})
    engine.update(json=engine.data,
                  etag=engine.etag)

except BaseException as e:
    print("ex={}".format(e))
    exit(-1)
finally:
    # Delete NTP server and Firewall
    Layer3Firewall("myFw").delete()
    request = SMCRequest(href=new_ntp_server.href, headers={"if-match": ntp_server.etag})
    request.delete()
    session.logout()
