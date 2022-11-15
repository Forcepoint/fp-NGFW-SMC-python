"""
Example to show how to use create and delete SSM element objects in the SMC
"""
import smc.examples

from smc import session
from smc.core.engines import Layer3Firewall
from smc.elements.ssm import *
from smc_info import SMC_URL, API_KEY, API_VERSION

if __name__ == "__main__":
    session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120, api_version=API_VERSION)
    print("session OK")

try:

    # Create SSH Profile with multiple algorithms
    profile = SSHProfile.create(name="testSSHProfile",
                                cipher="aes256-ctr,aes128-ctr,aes192-ctr,"
                                       "aes128-gcm@openssh.com,aes192-cbc",
                                kex="diffie-hellman-group-exchange-sha1,"
                                    "diffie-hellman-group14-sha1",
                                mac="hmac-sha2-256,hmac-sha2-512,hmac-sha1-etm@openssh.com",
                                comment="This is an example of creating an SSH Profile.")

    # Create SSH Known Host with IPv4 and IPv6 with ssh-ed25519 host key
    known_host = SSHKnownHosts.create(name="testKnownHost",
                                      host_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIhOmoNeLtMHh"
                                      "r2DlE2uXAqfiJi66TM9DTjvgGEy3ojv",
                                      sshkey_type="ssh-ed25519",
                                      ipaddress="1.2.3.4",
                                      ipv6_address="2607:a600:124:0203::4",
                                      port=22000,
                                      comment="This is an example of creating an SSH Known Host.")

    # Create SSH Known Host List and add SSH Known Host to it
    known_host_list = SSHKnownHostsLists.create(name="testKnownHostList",
                                                known_host=[known_host.href],
                                                comment="This is an example of creating an SSH "
                                                        "Known Host List.")

    # Create empty SSH Known Host List
    empty_known_host_list = SSHKnownHostsLists.create(name="emptyKnownHostList")

    # create Layer3 FW with SSM enabled with Known Host Lists
    Layer3Firewall.create(name="testFw",
                          mgmt_ip="192.168.10.1",
                          mgmt_network="192.168.10.0/24",
                          sidewinder_proxy_enabled=True,
                          known_host_lists=[known_host_list.href, empty_known_host_list.href])

except BaseException as e:
    print("ex={}".format(e))
    exit(-1)
finally:
    # Delete SSH Profile and firewall
    SSHProfile("testSSHProfile").delete()
    Layer3Firewall("testFw").delete()

    # Delete Known Host Lists and Known Host
    SSHKnownHostsLists("testKnownHostList").delete()
    SSHKnownHostsLists("emptyKnownHostList").delete()
    SSHKnownHosts("testKnownHost").delete()

    session.logout()
