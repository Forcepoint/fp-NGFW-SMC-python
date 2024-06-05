#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
import argparse
import logging
import sys
import time

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.base.util import merge_dicts  # noqa
from smc.administration.certificates.tls import ClientProtectionCA, TLSProfile  # noqa
from smc.core.engines import Layer3Firewall  # noqa
from smc.core.general import NTPSettings  # noqa
from smc.elements.profiles import DNSRelayProfile, WebAuthHtmlPage  # noqa
from smc.elements.servers import NTPServer, DNSServer  # noqa
from smc.core.engine import SidewinderProxyAdvancedSettings, ScanDetectionSetting, \
    StaticMulticastRoute, WebAuthentication  # noqa
from smc.elements.alerts import IdsAlert  # noqa

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
SIDEWINDER_SETTING_UPDATE_ERROR = "Failed to update Sidewinder proxy advanced settings."
SIDEWINDER_SETTING_CREATE_ERROR = "Failed to create Sidewinder proxy advanced settings."
LOG_SETTING1 = 50
LOG_SETTING2 = 60
RATE = 100
BURST = 1000
LOG_EVENT1 = '1'
LOG_EVENT2 = '2'

# scan detection
SCAN_DETECTION_CREATE_ERROR = "Fail to create engine with scan detection setting"
SCAN_DETECTION_UPDATE_ERROR = "Fail to update engine with scan detection setting."
TIME_UNIT = "minute"
EVENT_COUNTS = 230
TIME_WINDOW = 2

# static_multicast_route
ERROR_CREATE_STATIC_MULTICAST_ROUTE = "Fail to create engine with static multicast route setting."
ERROR_UPDATE_STATIC_MULTICAST_ROUTE = "Fail to update engine with static multicast route setting."

# Web Authentication
ERROR_CREATE_WEB_AUTH_CONFIG = "Fail to create engine with web authentication setting."
ERROR_UPDATE_WEB_AUTH_CONFIG = "Fail to update engine with web authentication setting."
WEB_AUTH_PAGE = "Default User Authentication Pages"
TIMEOUT1 = 3600
TIMEOUT2 = 3000

logging.getLogger()
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - '
                                                '%(name)s - [%(levelname)s] : %(message)s')


def main():
    return_code = 0
    try:
        arguments = parse_command_line_arguments()
        session.login(url=arguments.api_url, api_key=arguments.api_key,
                      login=arguments.smc_user,
                      pwd=arguments.smc_pwd, api_version=arguments.api_version)
        logging.info("session OK")

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
        sidewinder_setting = [
            SidewinderProxyAdvancedSettings.create(attribute="httpkey", sidewinder_type="HTTP",
                                                   value="value1")]
        # scan detection setting
        alert = IdsAlert.objects.first()
        scan_detection = ScanDetectionSetting.create(
            scan_detection_icmp_events=EVENT_COUNTS,
            scan_detection_icmp_timewindow=TIME_WINDOW,
            scan_detection_icmp_unit=TIME_UNIT,
            scan_detection_tcp_events=EVENT_COUNTS,
            scan_detection_tcp_timewindow=TIME_WINDOW,
            scan_detection_tcp_unit=TIME_UNIT,
            scan_detection_type="default off",
            scan_detection_udp_events=EVENT_COUNTS,
            scan_detection_udp_timewindow=TIME_WINDOW,
            scan_detection_udp_unit=TIME_UNIT
        )

        # static_multicast_route
        static_multicast_route = StaticMulticastRoute.create(dest_interface=[
            "1000"
        ],
            dest_ip="224.1.1.1",
            source_interface="1000",
            source_ip="192.168.1.1"
        )

        # Web Authentication
        web_authentication_page = WebAuthHtmlPage(WEB_AUTH_PAGE)
        tls_profile = TLSProfile.objects.first()
        web_authentication = WebAuthentication.create(all_interfaces=True,
                                                      authentication_idle_timeout=TIMEOUT1,
                                                      authentication_timeout=TIMEOUT1,
                                                      enforce_https=False,
                                                      keep_alive_rate=30,
                                                      page_ref=web_authentication_page,
                                                      use_cert_bba=False)

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
                                          },
                              ssm_advanced_setting=sidewinder_setting,
                              sidewinder_proxy_enabled=True,
                              scan_detection=scan_detection,
                              static_multicast_route=[static_multicast_route],
                              web_authentication=web_authentication
                              )
        # SidewinderProxyAdvancedSettings
        engine = Layer3Firewall(engine_name)
        setting = engine.ssm_advanced_setting[0]
        assert setting.attribute == "httpkey" and setting.type == "HTTP" and \
               setting.value == "value1", SIDEWINDER_SETTING_CREATE_ERROR

        scan_detection = engine.scan_detection
        assert scan_detection.log_level == "stored" and \
               scan_detection.scan_detection_icmp_events == EVENT_COUNTS and \
               scan_detection.scan_detection_icmp_timewindow == TIME_WINDOW and \
               scan_detection.scan_detection_icmp_unit == TIME_UNIT and \
               scan_detection.scan_detection_tcp_events == EVENT_COUNTS and \
               scan_detection.scan_detection_tcp_timewindow == TIME_WINDOW and \
               scan_detection.scan_detection_tcp_unit == TIME_UNIT and \
               scan_detection.scan_detection_type == "default off" and \
               scan_detection.scan_detection_udp_events == EVENT_COUNTS and \
               scan_detection.scan_detection_udp_timewindow == TIME_WINDOW and \
               scan_detection.scan_detection_udp_unit == TIME_UNIT, SCAN_DETECTION_CREATE_ERROR

        scan_detection.update(scan_detection_icmp_events=200, scan_detection_icmp_timewindow=3,
                              scan_detection_icmp_unit="second", log_level="alert",
                              alert_ref=alert.href, severity=TIME_WINDOW)
        engine.update(scan_detection=scan_detection.data)

        engine = Layer3Firewall(engine_name)
        scan_detection = engine.scan_detection
        assert scan_detection.log_level == "alert" and scan_detection.alert_ref == alert.href and \
               scan_detection.scan_detection_icmp_events == 200 and \
               scan_detection.severity == TIME_WINDOW and \
               scan_detection.scan_detection_icmp_timewindow == 3 and \
               scan_detection.scan_detection_icmp_unit == "second", SCAN_DETECTION_UPDATE_ERROR

        logging.info("Successfully created the engine with sidewinder proxy advanced settings.")
        temp = [
            SidewinderProxyAdvancedSettings.create(attribute="sharedkey", sidewinder_type="SHARED",
                                                   value="value2"),
            SidewinderProxyAdvancedSettings.create(attribute="tcpkey", sidewinder_type="TCP",
                                                   value="value3"),
            SidewinderProxyAdvancedSettings.create(attribute="udpkey", sidewinder_type="UDP",
                                                   value="value4"),
            SidewinderProxyAdvancedSettings.create(attribute="sshkey", sidewinder_type="SSH",
                                                   value="value4")]
        engine.update(ssm_advanced_setting=[setting.data for setting in temp])
        engine = Layer3Firewall(engine_name)
        invalid_ssm_setting_type_detected = False
        for setting in engine.ssm_advanced_setting:
            if setting.type not in setting.types:
                invalid_ssm_setting_type_detected = True
                break
        assert not invalid_ssm_setting_type_detected, SIDEWINDER_SETTING_UPDATE_ERROR
        logging.info("Successfully updated the engine with sidewinder proxy advanced settings.")

        # static multicast route
        static_multicast_route = engine.static_multicast_route[0]
        assert "1000" in static_multicast_route.dest_interface and \
               static_multicast_route.dest_ip == "224.1.1.1" and \
               static_multicast_route.source_interface == "1000" and \
               static_multicast_route.source_ip == \
               "192.168.1.1", ERROR_CREATE_STATIC_MULTICAST_ROUTE
        static_multicast_route.update(source_ip="192.168.1.2", dest_ip="224.1.1.2")
        engine.update(static_multicast_route=[static_multicast_route.data])
        engine = Layer3Firewall(engine_name)
        static_multicast_route = engine.static_multicast_route[0]
        assert static_multicast_route.dest_ip == "224.1.1.2" and \
               static_multicast_route.source_ip == \
               "192.168.1.2", ERROR_UPDATE_STATIC_MULTICAST_ROUTE
        # Web Authentication
        web_config = engine.web_authentication
        assert web_config.all_interfaces and \
               web_config.authentication_idle_timeout == TIMEOUT1 and \
               web_config.authentication_timeout == TIMEOUT1 and not web_config.enforce_https and \
               web_config.page_ref == web_authentication_page.href and \
               not web_config.session_handling, ERROR_CREATE_WEB_AUTH_CONFIG
        web_authentication.update(tls_profile=tls_profile.href,
                                  http_port=80,
                                  authentication_idle_timeout=TIMEOUT2,
                                  authentication_timeout=TIMEOUT2,
                                  session_handling=False,
                                  )
        engine.generate_and_sign_user_authentication_certificate()
        engine.update(web_authentication=web_authentication.data)
        engine = Layer3Firewall(engine_name)
        web_config = engine.web_authentication
        assert web_config.authentication_idle_timeout == TIMEOUT2 and \
               web_config.authentication_timeout == TIMEOUT2 and web_config.http_port == 80 and \
               not web_config.session_handling and \
               web_config.tls_profile == tls_profile.href, ERROR_UPDATE_WEB_AUTH_CONFIG

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
            f"{engine_name} L3 fw should have client protection settings"

        engine.sandbox.enable(license_key="licenceKey",
                              license_token="licenseToken")
        engine.update()
        assert engine.sandbox.status, \
            f"{engine_name} L3 fw should have sandbox settings"

        engine.sandbox.disable()
        engine.update()
        assert not engine.sandbox.status, \
            f"{engine_name} L3 fw should have sandbox disabled"
        assert engine.is_cert_auto_renewal, "Failed to pass attribute using extra_opts"

        assert engine.automatic_rules_settings.allow_auth_traffic, \
            "Failed to get allow_auth_traffic."
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
        logging.info("Checking the idle timeout setting")
        conn_timeout_obj = engine.connection_timeout
        assert not conn_timeout_obj._contains(PROTOCOL1) and not conn_timeout_obj._contains(
            PROTOCOL2), TIME_OUT_SETTING_MSG1.format(PROTOCOL1, PROTOCOL2)
        conn_timeout_obj.add(PROTOCOL1)
        conn_timeout_obj.add(PROTOCOL2)
        engine.update()
        conn_timeout_obj = engine.connection_timeout
        logging.info(f"IdleTimeout settings after update is {conn_timeout_obj.data}")
        assert conn_timeout_obj._contains(PROTOCOL1) and conn_timeout_obj._contains(
            PROTOCOL2), "Failed to update the protocol setting."
        logging.info("The new protocol has been successfully added to idle timeout.")

        # checking local log storage
        logging.info("Checking local log storage settings : ")
        engine = Layer3Firewall(engine_name)
        local_log_obj = engine.local_log_storage
        assert local_log_obj.local_log_storage_activated and local_log_obj.lls_max_time == \
               LOG_SETTING1 and local_log_obj.lls_guaranteed_free_size_in_mb == LOG_SETTING1 and \
               local_log_obj.lls_guaranteed_free_percent == LOG_SETTING1, ERROR_CREATE_LOG_SETTING
        logging.info("Successfully created the engine with local log storage settings.")
        local_log_obj.update(lls_max_time=LOG_SETTING2, lls_guaranteed_free_size_in_mb=LOG_SETTING2,
                             lls_guaranteed_free_percent=LOG_SETTING2)
        engine.update()
        engine = Layer3Firewall(engine_name)
        local_log_obj = engine.local_log_storage
        assert local_log_obj.local_log_storage_activated and local_log_obj.lls_max_time == \
               LOG_SETTING2 and local_log_obj.lls_guaranteed_free_size_in_mb == LOG_SETTING2 and \
               local_log_obj.lls_guaranteed_free_percent == LOG_SETTING2, ERROR_UPDATE_LOG_SETTING
        logging.info("Successfully updated engine with the local log storage settings.")

        # checking log moderation
        engine = Layer3Firewall(engine_name)
        log_moderation_obj = engine.log_moderation
        assert log_moderation_obj.contains(log_event=LOG_EVENT1) and \
               log_moderation_obj.get(LOG_EVENT1)["rate"] == RATE and \
               log_moderation_obj.get(LOG_EVENT1)["burst"] == BURST, ERROR_CREATE_LOG_MODERATION
        logging.info("Successfully created the engine with the log moderation settings.")
        log_moderation_obj.add(rate=RATE, log_event=LOG_EVENT2, burst=BURST)
        engine.update()
        engine = Layer3Firewall(engine_name)
        log_moderation_obj = engine.log_moderation
        assert log_moderation_obj.contains(log_event=LOG_EVENT2) and \
               log_moderation_obj.get(LOG_EVENT2)["rate"] == RATE and \
               log_moderation_obj.get(LOG_EVENT2)["burst"] == BURST, ERROR_UPDATE_LOG_MODERATION
        logging.info("Successfully updated the engine with log moderation settings.")
        logging.info("Checking the log moderation setting in the interface: ")
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
        logging.info("Successfully updated the interface with log moderation settings.")
    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        # Delete NTP server and Firewall
        Layer3Firewall("myFw").delete()
        NTPServer("myNTPServer").delete()
        ClientProtectionCA("client.test.local").delete()
        DNSServer("mydnsserver").delete()
        DNSRelayProfile("dnsrules").delete()
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to create a layer3 Firewall in SMC',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        add_help=False)
    parser.add_argument(
        '-h', '--help',
        action='store_true',
        help='show this help message and exit')

    parser.add_argument(
        '--api-url',
        type=str,
        help='SMC API url like https://192.168.1.1:8082')
    parser.add_argument(
        '--api-version',
        type=str,
        help='The API version to use for run the script'
    )
    parser.add_argument(
        '--smc-user',
        type=str,
        help='SMC API user')
    parser.add_argument(
        '--smc-pwd',
        type=str,
        help='SMC API password')
    parser.add_argument(
        '--api-key',
        type=str, default=None,
        help='SMC API api key (Default: None)')

    arguments = parser.parse_args()

    if arguments.help:
        parser.print_help()
        sys.exit(1)
    if arguments.api_url is None:
        parser.print_help()
        sys.exit(1)

    return arguments


if __name__ == '__main__':
    sys.exit(main())
