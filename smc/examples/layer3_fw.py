"""
Example of how to create a layer3 Firewall in SMC
"""

from smc import session
from smc.base.util import merge_dicts
from smc.core.engines import Layer3Firewall
from smc.core.general import NTPSettings
from smc.elements.servers import NTPServer
from smc_info import *


if __name__ == "__main__":
    session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120, api_version=API_VERSION)
    print("session OK")

try:

    # Create NTP server
    new_ntp_server = NTPServer().create(name="myNTPServer",
                                        comment="NTP Server created by the SMC API",
                                        address="192.168.1.200",
                                        ntp_auth_key_type="none"
                                        )

    # create Layer3 FW using NTPSettings object
    ntp = NTPSettings.create(ntp_enable=True,
                             ntp_servers=[new_ntp_server])

    Layer3Firewall.create(name="myFw",
                          mgmt_ip="192.168.10.1",
                          mgmt_network="192.168.10.0/24",
                          ntp_settings=ntp
                          )

    # Update NTP server settings for the Firewall
    engine = Layer3Firewall("myFw")
    ntp = NTPSettings.create(ntp_enable=False,
                             ntp_servers=[])
    merge_dicts(engine.data, ntp.data)
    engine.update(json=engine.data)

except BaseException as e:
    print("ex={}".format(e))
    exit(-1)
finally:
    # Delete NTP server and Firewall
    Layer3Firewall("myFw").delete()
    NTPServer("myNTPServer").delete()
    session.logout()
