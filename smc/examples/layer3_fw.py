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
PROTOCOL1 = 'tcp_syn_seen'
PROTOCOL2 = 'tcp_time_wait'
MESSAGE_FOR_DNS_DELAY = "Failed to check the allow_listening_interfaces_to_dns_relay_port."
MESSAGE_FOR_DNS_RESOLVER = "Failed to check the allow_connections_to_dns_resolvers."
TIME_OUT_SETTING_MSG1 = "Protocol settings are already present for {} and {}."
ERROR_CREATE_LOG_SETTING = "Failed to create engine with local log storage settings."
ERROR_UPDATE_LOG_SETTING = "Failed to update local log storage settings."
ERROR_CREATE_LOG_MODERATION = "Failed to create engine with log moderation settings."
ERROR_UPDATE_LOG_MODERATION = "Failed to update log moderation settings."
LOG_SETTING1 = 50
LOG_SETTING2 = 60
RATE = 100
BURST = 1000
LOG_EVENT1 = '1'
LOG_EVENT2 = '2'

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
    interfaces_json = [{'interfaces': [{'nodes': [{'address': '11.11.11.1',
                                                   'network_value': '11.11.11.1/32',
                                                   'nodeid': 1}]}],
                       'interface_id': '1000', 'type': 'tunnel_interface'},
                       {'interfaces': [], 'interface_id': 'SWP_0',
                        'appliance_switch_module': '110 appliance (8 fixed ports)',
                        'type': 'switch_interface',
                        'port_group_interface': [{'interface_id': 'SWP_0.4',
                                                 'switch_interface_port': [{
                                                     'switch_interface_port_comment': 'port 2',
                                                     'physical_switch_port_number': 2},
                                                     {'switch_interface_port_comment': '',
                                                      'physical_switch_port_number': 4},
                                                     {'switch_interface_port_comment': '',
                                                      'physical_switch_port_number': 5},
                                                     {'switch_interface_port_comment': '',
                                                      'physical_switch_port_number': 6}]}]
                        }]
    Layer3Firewall.create(name=engine_name,
                          mgmt_ip="192.168.10.1",
                          mgmt_network="192.168.10.0/24",
                          ntp_settings=ntp,
                          interfaces=interfaces_json,
                          extra_opts={"is_cert_auto_renewal": True, "local_log_storage": {
                              "lls_guaranteed_free_percent": LOG_SETTING1,
                              "lls_guaranteed_free_size_in_mb": LOG_SETTING1,
                              "lls_max_time": LOG_SETTING1,
                              "local_log_storage_activated": True
                          },
                                      "log_spooling_policy": "discard",  # enable log_moderation

                                      "log_moderation": [  # adding  log moderation setting
                                          {
                                              "burst": BURST,
                                              "log_event": LOG_EVENT1,
                                              "rate": RATE
                                          }]
                                      }
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

    # checking connection timeout setting
    print("Checking the idle timeout setting")
    conn_timeout_obj = engine.connection_timeout
    assert not conn_timeout_obj._contains(PROTOCOL1) and not conn_timeout_obj._contains(
        PROTOCOL2), TIME_OUT_SETTING_MSG1.format(PROTOCOL1, PROTOCOL2)
    conn_timeout_obj.add(PROTOCOL1)
    conn_timeout_obj.add(PROTOCOL2)
    engine.update()
    conn_timeout_obj = engine.connection_timeout
    print("IdleTimeout settings after update is {}".format(conn_timeout_obj.data))
    assert conn_timeout_obj._contains(PROTOCOL1) and conn_timeout_obj._contains(
        PROTOCOL2), "Failed to update the protocol setting."
    print("The new protocol has been successfully added to idle timeout.")

    # checking local log storage
    print("Checking local log storage settings : ")
    engine = Layer3Firewall(engine_name)
    local_log_obj = engine.local_log_storage
    assert local_log_obj.local_log_storage_activated and local_log_obj.lls_max_time == \
           LOG_SETTING1 and local_log_obj.lls_guaranteed_free_size_in_mb == LOG_SETTING1 and \
           local_log_obj.lls_guaranteed_free_percent == LOG_SETTING1, ERROR_CREATE_LOG_SETTING
    print("Successfully created the engine with local log storage settings.")
    local_log_obj.update(lls_max_time=LOG_SETTING2, lls_guaranteed_free_size_in_mb=LOG_SETTING2,
                         lls_guaranteed_free_percent=LOG_SETTING2)
    engine.update()
    engine = Layer3Firewall(engine_name)
    local_log_obj = engine.local_log_storage
    assert local_log_obj.local_log_storage_activated and local_log_obj.lls_max_time == \
           LOG_SETTING2 and local_log_obj.lls_guaranteed_free_size_in_mb == LOG_SETTING2 and \
           local_log_obj.lls_guaranteed_free_percent == LOG_SETTING2, ERROR_UPDATE_LOG_SETTING
    print("Successfully updated engine with the local log storage settings.")

    # checking log moderation
    engine = Layer3Firewall(engine_name)
    log_moderation_obj = engine.log_moderation
    assert log_moderation_obj.contains(log_event=LOG_EVENT1) and \
           log_moderation_obj.get(LOG_EVENT1)["rate"] == RATE and \
           log_moderation_obj.get(LOG_EVENT1)["burst"] == BURST, ERROR_CREATE_LOG_MODERATION
    print("Successfully created the engine with the log moderation settings.")
    log_moderation_obj.add(rate=RATE, log_event=LOG_EVENT2, burst=BURST)
    engine.update()
    engine = Layer3Firewall(engine_name)
    log_moderation_obj = engine.log_moderation
    assert log_moderation_obj.contains(log_event=LOG_EVENT2) and \
           log_moderation_obj.get(LOG_EVENT2)["rate"] == RATE and \
           log_moderation_obj.get(LOG_EVENT2)["burst"] == BURST, ERROR_UPDATE_LOG_MODERATION
    print("Successfully updated the engine with log moderation settings.")
    print("Checking the log moderation setting in the interface: ")
    interface = engine.interface.get(1)
    log_moderation_obj = interface.log_moderation
    log_moderation_obj.add(rate=RATE, log_event=LOG_EVENT2, burst=BURST)
    interface.update(override_engine_settings=True, override_log_moderation_settings=True)
    # Reload engine setting from DB
    engine = Layer3Firewall(engine_name)
    interface = engine.interface.get(1)
    log_moderation_obj = interface.log_moderation
    assert log_moderation_obj.contains(log_event=LOG_EVENT1) and \
           log_moderation_obj.get(LOG_EVENT1)["rate"] == RATE and \
           log_moderation_obj.get(LOG_EVENT1)["burst"] == BURST, ERROR_UPDATE_LOG_MODERATION
    print("Successfully updated the interface with log moderation settings.")
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
