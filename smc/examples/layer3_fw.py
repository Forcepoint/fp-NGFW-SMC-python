#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.
"""
Example of how to create a layer3 Firewall in SMC
"""
import smc.examples

from smc import session
from smc.base.util import merge_dicts
from smc.administration.certificates.tls import ClientProtectionCA
from smc.core.engines import Layer3Firewall
from smc.core.general import NTPSettings
from smc.elements.profiles import DNSRelayProfile
from smc.elements.servers import NTPServer, DNSServer
from smc_info import SMC_URL, API_KEY, API_VERSION

engine_name = "myFw"
MESSAGE_FOR_DNS_DELAY = "Failed to check the allow_listening_interfaces_to_dns_relay_port."
MESSAGE_FOR_DNS_RESOLVER = "Failed to check the allow_connections_to_dns_resolvers."

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

    Layer3Firewall.create(name=engine_name,
                          mgmt_ip="192.168.10.1",
                          mgmt_network="192.168.10.0/24",
                          ntp_settings=ntp,
                          extra_opts={"is_cert_auto_renewal": True}
                          )

    # Update NTP server settings for the Firewall
    engine = Layer3Firewall(engine_name)
    engine.physical_interface.add_layer3_interface(interface_id=1,
                                                   address="10.10.10.1",
                                                   network_value="10.10.10.0/24")
    server = DNSServer.create(name="mydnsserver", address="10.0.0.1")
    engine.dns.add(['8.8.8.8', server])
    engine.update()

    profile = DNSRelayProfile("dnsrules")
    profile.hostname_mapping.add([("hostname1,hostname2", "1.1.1.1")])
    engine.dns_relay.enable(interface_id=1, dns_relay_profile=profile)

    ntp = NTPSettings.create(ntp_enable=False,
                             ntp_servers=[])
    merge_dicts(engine.data, ntp.data)
    engine.update(json=engine.data)

    tls = ClientProtectionCA.create_self_signed(name='client.test.local',
                                                common_name='CN=client.test.local')
    engine.client_inspection.enable(tls)
    engine.update()

    assert engine.client_inspection.status, \
        "{} L3 fw should have client protection settings".format(engine_name)

    engine.sandbox.enable(license_key="licenceKey",
                          license_token="licenseToken")
    engine.update()
    assert engine.sandbox.status, \
        "{} L3 fw should have sandbox settings".format(engine_name)

    engine.sandbox.disable()
    engine.update()
    assert not engine.sandbox.status, \
        "{} L3 fw should have sandbox disabled".format(engine_name)
    assert engine.is_cert_auto_renewal, "Failed to pass attribute using extra_opts"

    assert engine.automatic_rules_settings.allow_auth_traffic, "Failed to get allow_auth_traffic."
    engine.automatic_rules_settings.update_automatic_rules_settings(allow_auth_traffic=False)
    assert engine.automatic_rules_settings.allow_listening_interfaces_to_dns_relay_port, \
        MESSAGE_FOR_DNS_DELAY
    assert engine.automatic_rules_settings.allow_connections_to_dns_resolvers, \
        MESSAGE_FOR_DNS_RESOLVER
    engine.automatic_rules_settings.update_automatic_rules_settings(
        allow_listening_interfaces_to_dns_relay_port=False)
    engine.automatic_rules_settings.update_automatic_rules_settings(
        allow_connections_to_dns_resolvers=False)
    engine.update()

    assert not engine.automatic_rules_settings.allow_auth_traffic, "Failed to update " \
                                                                   "allow_auth_traffic"
    assert not engine.automatic_rules_settings.allow_listening_interfaces_to_dns_relay_port, \
        MESSAGE_FOR_DNS_DELAY
    assert not engine.automatic_rules_settings.allow_connections_to_dns_resolvers, \
        MESSAGE_FOR_DNS_RESOLVER

except BaseException as e:
    print("ex={}".format(e))
    exit(-1)
finally:
    # Delete NTP server and Firewall
    Layer3Firewall("myFw").delete()
    NTPServer("myNTPServer").delete()
    ClientProtectionCA("client.test.local").delete()
    DNSServer("mydnsserver").delete()
    DNSRelayProfile("dnsrules").delete()
    session.logout()
