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
Example script to show how to use different type of servers -
TacacsServer, RadiusServer, IcapServer, SmtpServer, ProxyServer, ActiveDirectoryServer, LDAPServer,
ManagementServer, EpoServer, NtpServer, HttpProxy and LogServer.
"""

# Python SMC Import
import argparse
import logging
import sys

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.administration.certificates.tls import TLSProfile, TLSServerCredential, \
    TLSCryptographySuite  # noqa
from smc.administration.user_auth.servers import AuthenticationMethod, DomainController, \
    ActiveDirectoryServer, LDAPServer  # noqa
from smc.elements.common import ThirdPartyMonitoring  # noqa
from smc.elements.network import Host  # noqa
from smc.compat import is_smc_version_less_than_or_equal  # noqa
from smc.elements.other import Location  # noqa
from smc.elements.servers import TacacsServer, LogServer, RadiusServer, IcapServer, SmtpServer, \
    ProxyServer, ManagementServer, WebApp, NetflowCollector, DataContext, \
    EpoServer, NTPServer, HttpProxy  # noqa
from smc.elements.ssm import LoggingProfile, ProbingProfile  # noqa

EMAIL_ADDRESS = "test@forcepoint.com"
PRIMARY_ADDRESS1 = "192.168.1.10"
SECONDARY_ADDRESS1 = "192.168.1.11"
PRIMARY_ADDRESS2 = "192.168.2.10"
SECONDARY_ADDRESS2 = "192.168.2.11"
IPV6_ADDRESS = "2001:2db8:85a3:1111:2222:8a2e:1370:7334"
TACACS_SERVER_NAME1 = "tacacs server test1"
TACACS_SERVER_NAME2 = "tacacs server test2"
AUTH_METHOD_NAME = "Tacacs Auth Test"
UPDATE_TACACS_ERROR = "Failed to update TacacsServer."
CREATE_TACACS_ERROR = "Failed to create TacacsServer."

RADIUS_SERVER_NAME1 = "radius server test1"
RADIUS_SERVER_NAME2 = "radius server test2"
AUTH_METHOD_NAME1 = "Tacacs Auth Test"
AUTH_METHOD_NAME2 = "Radius Auth Test"
SHARE_SECRET = "afsdfsdjbjbfsdfsf=="

UPDATE_RADIUS_ERROR = "Failed to update RadiusServer."
CREATE_RADIUS_ERROR = "Failed to create RadiusServer."

ICAP_SERVER_NAME = "test_icap_server"
UPDATE_ICAP_SERVER_ERROR = "Failed to update RadiusServer."
CREATE_ICAP_SERVER_ERROR = "Failed to create RadiusServer."

# SmtpServer
SMTP_SERVER_NAME = "test_smtp_server"
CREATE_SMTP_SERVER_ERROR = "Failed to create SmtpServer."
UPDATE_SMTP_SERVER_ERROR = "Failed to update SmtpServer."

# ProxyServer
PROXY_SERVER_NAME = "test_proxy_server"
PROXY_SERVICE1 = "redirect"
PROXY_SERVICE2 = "forcepoint_ap-web_cloud"
PROXY_SERVICE3 = "generic"

PROXY_SERVER_CREATE_ERROR = "Failed to create ProxyServer."
PROXY_SERVER_UPDATE_ERROR = "Failed to update ProxyServer."

# ActiveDirectoryServer
ACTIVE_DIRECTORY_SERVER = "test_active_directory_server"
MOBILE_NUMBER = "8888888888"

ACTIVE_DIRECTORY_SERVER_CREATE_ERROR = "Failed to create ActiveDirectoryServer."
ACTIVE_DIRECTORY_SERVER_UPDATE_ERROR = "Failed to update ActiveDirectoryServer."

# LDAPServer
LDAP_SERVER = "test_ldap_server"
LDAP_SERVER_CREATE_ERROR = "Failed to create LDAPServer."
LDAP_SERVER_UPDATE_ERROR = "Failed to update LDAPServer."

# ManagementServer
MGT_SERVER_NAME = "test_mgt_server"
MGT_SERVER_CREATE_ERROR = "Failed to create ManagementServer."
MGT_SERVER_UPDATE_ERROR = "Failed to update ManagementServer."

# EpoServer
EPO_SERVER_NAME = "test_epo_server"
EPO_SERVER_CREATE_ERROR = "Failed to create EpoServer."
EPO_SERVER_UPDATE_ERROR = "Failed to update EpoServer."
PRIMARY_ADDRESS3 = "192.168.1.12"
SECONDARY_ADDRESS3 = "192.168.1.13"

# NtpServer
NTP_SERVER_NAME = "test_ntp_server"
NTP_SERVER_COMMENT = "NTP Server created by the SMC API"
NTP_SERVER_CREATE_ERROR = "Failed to create NtpServer."
NTP_SERVER_UPDATE_ERROR = "Failed to update NtpServer."

# HttpProxy
HTTP_PROXY_NAME = "test_http_proxy"
HTTP_PROXY_COMMENT = "HttpProxy created by the SMC API"
HTTP_PROXY_CREATE_ERROR = "Failed to create HttpProxy."
HTTP_PROXY_UPDATE_ERROR = "Failed to update HttpProxy."
PRIMARY_ADDRESS4 = "192.168.1.14"
SECONDARY_ADDRESS4 = "192.168.1.15"

# LogServer
LOG_SERVER_NAME = "test_log_server"
LOG_SERVER_COMMENT = "This is testing of element LogServer."
LOG_SERVER_CREATE_ERROR = "Failed to create LogServer."
LOG_SERVER_UPDATE_ERROR = "Failed to update LogServer."

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
        log_server = list(LogServer.objects.all())[0]
        location = list(Location.objects.all())[0]
        logging_profile = list(LoggingProfile.objects.all())[0]
        probing_profile = list(ProbingProfile.objects.all())[0]
        third_party_monitoring = ThirdPartyMonitoring.create(encoding="UTF-8",
                                                             logging_profile_ref=logging_profile,
                                                             monitoring_log_server_ref=log_server,
                                                             netflow=True,
                                                             probing_profile_ref=probing_profile,
                                                             snmp_trap=True,
                                                             time_zone="Europe/Paris")
        # create Tacacs Server without Authentication Method
        tacacs_server1 = TacacsServer.create(TACACS_SERVER_NAME1, address=PRIMARY_ADDRESS1,
                                             secondary=[SECONDARY_ADDRESS1], clear_text=False,
                                             shared_secret=SHARE_SECRET,
                                             third_party_monitoring=third_party_monitoring)
        assert not tacacs_server1.clear_text and tacacs_server1.address == PRIMARY_ADDRESS1 and \
               tacacs_server1.secondary and \
               tacacs_server1.third_party_monitoring.monitoring_log_server_ref.href == \
               log_server.href, CREATE_TACACS_ERROR
        logging.info("TacacsServer created successfully.")
        tacacs_server1.update(location_ref=location.href, clear_text=True)
        tacacs_server1 = TacacsServer(TACACS_SERVER_NAME1)
        assert tacacs_server1.location_ref.href == location.href and tacacs_server1.clear_text, \
            UPDATE_TACACS_ERROR

        # create Tacacs Server with Authentication Method because we need atleast one Tacacs server
        # before creating AuthenticationMethod
        auth_method = AuthenticationMethod.create_tacacs_or_radius(
            authentication_server=[tacacs_server1],
            name=AUTH_METHOD_NAME, comment="This is testing of Auth Method.")
        tacacs_server2 = TacacsServer.create(TACACS_SERVER_NAME2, address=PRIMARY_ADDRESS2,
                                             secondary=[SECONDARY_ADDRESS2], clear_text=False,
                                             shared_secret=SHARE_SECRET,
                                             provided_method=[auth_method],
                                             third_party_monitoring=third_party_monitoring)
        assert not tacacs_server2.clear_text and tacacs_server2.address == PRIMARY_ADDRESS2 and \
               tacacs_server2.secondary and \
               tacacs_server2.third_party_monitoring.monitoring_log_server_ref.href == \
               log_server.href, CREATE_TACACS_ERROR
        logging.info("TacacsServer created successfully.")
        tacacs_server2.update(location_ref=location.href, clear_text=True)
        tacacs_server2 = TacacsServer(TACACS_SERVER_NAME2)
        assert tacacs_server2.location_ref.href == location.href and tacacs_server2.clear_text, \
            UPDATE_TACACS_ERROR
        logging.info("TacacsServer updated successfully.")

        # Example of Radius Server.
        # create Radius Server without Authentication Method
        radius_server1 = RadiusServer.create(RADIUS_SERVER_NAME1, address=PRIMARY_ADDRESS1,
                                             secondary=[SECONDARY_ADDRESS1],
                                             shared_secret=SHARE_SECRET,
                                             third_party_monitoring=third_party_monitoring)
        assert radius_server1.address == PRIMARY_ADDRESS1 and SECONDARY_ADDRESS1 in \
               radius_server1.secondary and \
               radius_server1.third_party_monitoring.monitoring_log_server_ref.href == \
               log_server.href, CREATE_RADIUS_ERROR
        logging.info("RadiusServer created successfully.")
        radius_server1.update(location_ref=location.href)
        radius_server1 = RadiusServer(RADIUS_SERVER_NAME1)
        assert radius_server1.location_ref.href == location.href, UPDATE_RADIUS_ERROR

        # create Radius Server with Authentication Method because we need atleast one Radius server
        # before creating AuthenticationMethod
        auth_method2 = AuthenticationMethod.create_tacacs_or_radius(
            authentication_server=[radius_server1], name=AUTH_METHOD_NAME2, type='radius',
            comment="This is testing of Auth Method.")
        radius_server2 = RadiusServer.create(RADIUS_SERVER_NAME2, address=PRIMARY_ADDRESS2,
                                             secondary=[SECONDARY_ADDRESS2],
                                             shared_secret=SHARE_SECRET,
                                             provided_method=[auth_method2],
                                             third_party_monitoring=third_party_monitoring)
        assert radius_server2.address == PRIMARY_ADDRESS2 and SECONDARY_ADDRESS2 in radius_server2.\
            secondary and radius_server2.third_party_monitoring.monitoring_log_server_ref.href == \
               log_server.href, CREATE_RADIUS_ERROR
        logging.info("Radius created successfully.")
        radius_server2.update(location_ref=location.href)
        radius_server2 = RadiusServer(RADIUS_SERVER_NAME2)
        assert radius_server2.location_ref.href == location.href, UPDATE_RADIUS_ERROR
        logging.info("RadiusServer updated successfully.")

        # IcapServer
        tl_profile = list(TLSProfile.objects.all())[0]
        icap_server = IcapServer.create(
            ICAP_SERVER_NAME,
            address=PRIMARY_ADDRESS1,
            icap_include_xhdrs=True,
            icap_path="test_path",
            icap_port=1344,
            icap_secure=True,
            icap_xhdr_clientip="X-192-168-3-11",
            icap_xhdr_serverip="X-192-168-3-12",
            icap_xhdr_username="X-test-username",
            tls_profile_ref=tl_profile,
            location_ref=location,
            secondary=[SECONDARY_ADDRESS1],
            third_party_monitoring=third_party_monitoring,
            comment="This is testing of IcapServer."
        )
        assert icap_server.icap_path == "test_path" and icap_server.icap_port == 1344 and \
               icap_server.address == PRIMARY_ADDRESS1, CREATE_ICAP_SERVER_ERROR
        logging.info("IcapServer created successfully.")

        icap_server.update(icap_secure=False, icap_include_xhdrs=False, icap_port=11344)
        icap_server = IcapServer(ICAP_SERVER_NAME)
        assert icap_server.icap_port == 11344 and not (icap_server.icap_secure and
                                                       icap_server.icap_include_xhdrs), \
            UPDATE_ICAP_SERVER_ERROR
        logging.info("IcapServer updated successfully.")

        # SmtpServer
        smtp_server = SmtpServer.create(
            SMTP_SERVER_NAME,
            address=PRIMARY_ADDRESS1,
            email_sender_address="test@forcepoint.com",
            email_sender_name="forcepoint",
            location_ref=location,
            secondary=[SECONDARY_ADDRESS1],
            third_party_monitoring=third_party_monitoring,
            comment="This is to test SMTP Server"
        )
        monitoring = smtp_server.third_party_monitoring
        assert smtp_server.address == PRIMARY_ADDRESS1 and SECONDARY_ADDRESS1 in smtp_server \
            .secondary and monitoring.monitoring_log_server_ref.href == log_server.href and \
               monitoring.netflow and monitoring.snmp_trap and smtp_server.email_sender_address == \
               "test@forcepoint.com", CREATE_SMTP_SERVER_ERROR
        smtp_server.update(email_sender_address="change@forcepoint.com",
                           email_sender_name="changed_name")
        smtp_server = SmtpServer(SMTP_SERVER_NAME)
        assert smtp_server.email_sender_name == "changed_name" and smtp_server. \
            email_sender_address == "change@forcepoint.com", UPDATE_SMTP_SERVER_ERROR

        # ProxyServer
        inspected_service = [
            {
                "name": "FTP",
                "port": 21,
                "service_type": "FTP"
            },
            {
                "name": "HTTP",
                "port": 8081,
                "service_type": "HTTP"
            },
            {
                "name": "HTTPS",
                "port": 8082,
                "service_type": "HTTPS"
            },
            {
                "name": "SMTP",
                "port": 25,
                "service_type": "SMTP"
            },
            {
                "name": "Default",
                "port": 8083,
                "service_type": "Default"
            }
        ]

        # create proxy server with proxy service redirect
        proxy_server = ProxyServer.create(
            PROXY_SERVER_NAME,
            address=PRIMARY_ADDRESS1,
            ip_address=[SECONDARY_ADDRESS1, SECONDARY_ADDRESS2],
            inspected_service=inspected_service,
            proxy_service=PROXY_SERVICE1,
            location_ref=location,
            secondary=[SECONDARY_ADDRESS1],
            third_party_monitoring=third_party_monitoring,
            comment="This is to test Proxy Server"
        )
        proxy_server = ProxyServer(PROXY_SERVER_NAME)
        is_http = is_https = is_ftp = is_smtp = is_default = False
        for service in proxy_server.inspected_services:
            if service.service_type == "HTTP" and service.port == 8081:
                is_http = True
            elif service.service_type == "HTTPS" and service.port == 8082:
                is_https = True
            elif service.service_type == "SMTP" and service.port == 25:
                is_smtp = True
            elif service.service_type == "FTP" and service.port == 21:
                is_ftp = True
            elif service.service_type == "Default" and service.port == 8083:
                is_default = True
        assert proxy_server.address == PRIMARY_ADDRESS1 and SECONDARY_ADDRESS1 in \
               proxy_server.ip_address and proxy_server.proxy_service == PROXY_SERVICE1 and \
               proxy_server.third_party_monitoring.snmp_trap and \
               proxy_server.third_party_monitoring.netflow and is_ftp and is_default and is_smtp \
               and is_http and is_https, PROXY_SERVER_CREATE_ERROR
        logging.info(
            f"ProxyServer successfully created with service {PROXY_SERVICE1} Configuration.")

        # update with proxy service forcepoint_ap-web_cloud
        proxy_server.update(http_proxy=PROXY_SERVICE2, fp_proxy_key_id=3,
                            fp_proxy_user_id='2', fp_proxy_key=SHARE_SECRET)
        proxy_server = ProxyServer(PROXY_SERVER_NAME)
        assert proxy_server.proxy_service == PROXY_SERVICE2 and proxy_server.fp_proxy_key_id == 3 \
               and proxy_server.fp_proxy_user_id == '2', PROXY_SERVER_UPDATE_ERROR
        logging.info(
            f"ProxyServer successfully update with service {PROXY_SERVICE2} Configuration.")

        # update with proxy service generic
        proxy_server.update(http_proxy=PROXY_SERVICE3, add_x_forwarded_for=True,
                            trust_host_header=True)
        proxy_server = ProxyServer(PROXY_SERVER_NAME)
        assert proxy_server.proxy_service == PROXY_SERVICE3 and proxy_server.add_x_forwarded_for \
               and proxy_server.trust_host_header, PROXY_SERVER_UPDATE_ERROR
        logging.info(
            f"ProxyServer successfully update with service {PROXY_SERVICE3} Configuration.")

        # Active Directory Server
        domain_controller = DomainController("test_user", SECONDARY_ADDRESS1, SHARE_SECRET,
                                             expiration_time=28800, server_type="dc")
        authentication_method = AuthenticationMethod("LDAP Authentication")
        active_directory_server = ActiveDirectoryServer.create(
            ACTIVE_DIRECTORY_SERVER,
            address=PRIMARY_ADDRESS1,
            auth_ipaddress=PRIMARY_ADDRESS2,
            auth_port=1812,
            base_dn='dc=domain,dc=net',
            bind_password=SHARE_SECRET,
            bind_user_id="cn=admin,cn=users,dc=domain,dc=net",
            client_cert_based_user_search="dc",
            display_name_attr_name="displayName",
            domain_controller=[
                domain_controller],
            email=EMAIL_ADDRESS,
            frame_ip_attr_name=SECONDARY_ADDRESS2,
            group_member_attr="member",
            group_object_class=[
                "sggroup",
                "country",
                "group",
                "groupOfNames",
                "organization",
                "organizationalUnit"
            ],
            internet_auth_service_enabled=True,
            job_title_attr_name="title",
            office_location_attr_name="physicalDeliveryOfficeName",
            photo_attr_name="photo",
            port=389,
            protocol="ldap",
            secondary=[
                SECONDARY_ADDRESS1
            ],
            shared_secret=SHARE_SECRET,
            supported_method=[
                authentication_method
            ],
            timeout=10,
            user_id_attr="sAMAccountName",
            user_object_class=[
                "inetOrgPerson",
                "organizationalPerson",
                "person",
                "sguser"
            ],
            user_principal_name="userPrincipalName",
            comment="This is testing of Active Directory Server"
        )
        active_directory_server = ActiveDirectoryServer(ACTIVE_DIRECTORY_SERVER)
        assert active_directory_server.address == PRIMARY_ADDRESS1 and active_directory_server. \
            auth_ipaddress == PRIMARY_ADDRESS2 and active_directory_server.auth_port == 1812 and \
               active_directory_server.base_dn == 'dc=domain,dc=net' and \
               active_directory_server.internet_auth_service_enabled and \
               active_directory_server.user_id_attr == "sAMAccountName" and \
               active_directory_server.user_principal_name \
               == "userPrincipalName", ACTIVE_DIRECTORY_SERVER_CREATE_ERROR
        logging.info("ActiveDirectoryServer created successfully.")
        active_directory_server.update(mobile_attr_name=MOBILE_NUMBER, timeout=20,
                                       user_principal_name="changeduserPrincipalName",
                                       location_ref=location.href,
                                       third_party_monitoring=third_party_monitoring.data)
        active_directory_server = ActiveDirectoryServer(ACTIVE_DIRECTORY_SERVER)
        assert active_directory_server.mobile_attr_name == MOBILE_NUMBER and \
               active_directory_server.third_party_monitoring.snmp_trap and \
               active_directory_server.user_principal_name == "changeduserPrincipalName" and \
               active_directory_server.location_ref.href \
               == location.href, ACTIVE_DIRECTORY_SERVER_UPDATE_ERROR
        logging.info("ActiveDirectoryServer updated successfully.")

        # Ldap Server
        ldap_server = LDAPServer.create(
            LDAP_SERVER,
            address=PRIMARY_ADDRESS1,
            base_dn='dc=domain,dc=net',
            bind_password=SHARE_SECRET,
            bind_user_id="cn=admin,cn=users,dc=domain,dc=net",
            client_cert_based_user_search="dc",
            display_name_attr_name="displayName",
            email=EMAIL_ADDRESS,
            frame_ip_attr_name=SECONDARY_ADDRESS2,
            group_member_attr="member",
            group_object_class=[
                "sggroup",
                "country",
                "group",
                "groupOfNames",
                "organization",
                "organizationalUnit"
            ],
            job_title_attr_name="title",
            office_location_attr_name="physicalDeliveryOfficeName",
            photo_attr_name="photo",
            port=389,
            protocol="ldap",
            secondary=[
                SECONDARY_ADDRESS1
            ],
            supported_method=[
                authentication_method
            ],
            timeout=10,
            user_id_attr="sAMAccountName",
            user_object_class=[
                "inetOrgPerson",
                "organizationalPerson",
                "person",
                "sguser"
            ],
            user_principal_name="userPrincipalName",
            auth_attribute="sgauth",
            comment="This is testing of LDAP Server"
        )
        ldap_server = LDAPServer(LDAP_SERVER)
        assert ldap_server.address == PRIMARY_ADDRESS1 and \
               ldap_server.email == EMAIL_ADDRESS and \
               ldap_server.base_dn == 'dc=domain,dc=net' and \
               ldap_server.user_id_attr == "sAMAccountName" and \
               ldap_server.user_principal_name == "userPrincipalName", LDAP_SERVER_CREATE_ERROR
        logging.info("LDAPServer created successfully.")
        ldap_server.update(mobile_attr_name=MOBILE_NUMBER, timeout=20,
                           user_principal_name="changeduserPrincipalName",
                           location_ref=location.href,
                           third_party_monitoring=third_party_monitoring.data)
        ldap_server = LDAPServer(LDAP_SERVER)
        assert ldap_server.mobile_attr_name == MOBILE_NUMBER and \
               ldap_server.user_principal_name == "changeduserPrincipalName" and \
               ldap_server.location_ref.href == location.href and \
               ldap_server.third_party_monitoring.snmp_trap, LDAP_SERVER_UPDATE_ERROR
        logging.info("LDAPServer updated successfully.")

        sms_http_channel = [
                               {
                                   "attr_name_message": "Message Text",
                                   "attr_name_phone": "Destination",
                                   "conn_timeout": 10000,
                                   "debug": False,
                                   "default_success": True,
                                   "follow_redirects": False,
                                   "http_parameters": "JnRlc3QgZmllbGQ9MTA=",
                                   "name": "test http sms",
                                   "post": False,
                                   "proxy_host": "127.0.0.1",
                                   "proxy_port": 0,
                                   "rank": 3.0,
                                   "timeout": 10000,
                                   "url": "http://127.0.0.1",
                                   "use_http_11": True
                               }
                           ]
        sms_script_channel = [
                                 {
                                     "conn_timeout": 10000,
                                     "debug": False,
                                     "name": "test script",
                                     "proxy_port": 10000,
                                     "rank": 1.0,
                                     "script_execution_path": ".",
                                     "script_path": ".",
                                     "timeout": 10000
                                 }
                             ]
        sms_smtp_channel = [
                               {
                                   "account": "test",
                                   "body": "[$message]",
                                   "close_socket": False,
                                   "conn_timeout": 10000,
                                   "debug": False,
                                   "from": "test@forcepoint.com",
                                   "local_hostname": "127.0.01",
                                   "name": "test smtp",
                                   "password": SHARE_SECRET,
                                   "rank": 2.0,
                                   "sms_gateway": "8888888888",
                                   "smtp_server_ref": smtp_server.href,
                                   "start_tls": False,
                                   "subject": "test subject",
                                   "timeout": 10000
                               }
                           ]
        tls_server_creds = list(TLSServerCredential.objects.all())[0]
        tls_cryptography_suite = list(TLSCryptographySuite.objects.all())[0]
        web_app = [WebApp.create(host_name="test_server",
                                 listening_address=PRIMARY_ADDRESS2,
                                 enabled=True,
                                 log_access=True,
                                 server_credentials_ref=tls_server_creds,
                                 ssl_session_id=True,
                                 tls_cipher_suites=tls_cryptography_suite,
                                 web_app_identifier="webswing"
                                 )]
        host = list(Host.objects.all())[0]
        data_context = list(DataContext.objects.all())[0]
        netflow_collector = [NetflowCollector(data_context, host, 2055,
                                              "tcp", "xml")]
        mgt_server = ManagementServer.create(
            MGT_SERVER_NAME,
            address=PRIMARY_ADDRESS1,
            alert_server=log_server,
            location_ref=location,
            announcement_enabled=True,
            announcement_message="Test message.",
            secondary=[SECONDARY_ADDRESS1],
            updates_check_enabled=True,
            license_update_enabled=True,
            updates_proxy_enabled=True,
            updates_proxy_address=PRIMARY_ADDRESS2,
            updates_proxy_authentication_enabled=True,
            updates_proxy_username=MGT_SERVER_NAME,
            updates_proxy_password=SHARE_SECRET,
            db_replication=True,
            tls_credentials=tls_server_creds,
            netflow_collector=netflow_collector,
            smtp_server_ref=smtp_server,
            sender_address=SECONDARY_ADDRESS2,
            sender_name="test_sender",
            snmp_gateways=PRIMARY_ADDRESS2,
            script_path="test_path",
            sms_http_channel=sms_http_channel,
            sms_smtp_channel=sms_smtp_channel,
            sms_script_channel=sms_script_channel,
            comment="This is to test SMTP Server"
        )
        assert mgt_server.announcement_enabled and SECONDARY_ADDRESS1 in mgt_server.secondary and \
               mgt_server.updates_check_enabled and mgt_server.license_update_enabled and \
               mgt_server.updates_proxy_enabled and \
               mgt_server.updates_proxy_address == PRIMARY_ADDRESS2 \
               and mgt_server.updates_proxy_username == MGT_SERVER_NAME and \
               mgt_server.db_replication and \
               mgt_server.snmp_gateways == PRIMARY_ADDRESS2, MGT_SERVER_CREATE_ERROR
        logging.info("ManagementServer created successfully.")
        mgt_server.update(db_replication=False, announcement_message="changed message",
                          web_app=web_app)
        mgt_server = ManagementServer(MGT_SERVER_NAME)

        assert mgt_server.web_app and not mgt_server.db_replication and \
               mgt_server.announcement_message == "changed message", MGT_SERVER_UPDATE_ERROR
        logging.info("ManagementServer updated successfully.")

        # EpoServer
        is_epo_server = False
        if is_smc_version_less_than_or_equal("7.0"):
            is_epo_server = True
            epo_server = EpoServer.create(
                EPO_SERVER_NAME,
                address=PRIMARY_ADDRESS3,
                epo_password=SHARE_SECRET,
                epo_login=EPO_SERVER_NAME,
                location_ref=location,
                secondary=[SECONDARY_ADDRESS3],
                third_party_monitoring=third_party_monitoring,
                comment="This is to test EpoServer."
            )
            monitoring = epo_server.third_party_monitoring
            assert epo_server.address == PRIMARY_ADDRESS3 and SECONDARY_ADDRESS3 in epo_server \
                .secondary and monitoring.monitoring_log_server_ref.href == log_server.href and \
                   monitoring.netflow and monitoring.snmp_trap, EPO_SERVER_CREATE_ERROR
            logging.info("EpoServer created successfully.")
            monitoring["snmp_trap"] = False
            monitoring["netflow"] = False
            epo_server.update(third_party_monitoring=monitoring,
                              epo_login="epo_login_changed")
            epo_server = EpoServer(EPO_SERVER_NAME)
            monitoring = epo_server.third_party_monitoring
            assert epo_server.epo_login == "epo_login_changed" and not monitoring.snmp_trap \
                   and not monitoring.netflow, EPO_SERVER_UPDATE_ERROR
            logging.info("EpoServer updated successfully.")

        # NtpServer
        ntp_server = NTPServer().create(NTP_SERVER_NAME,
                                        address=PRIMARY_ADDRESS1,
                                        ipv6_address=IPV6_ADDRESS,
                                        ntp_auth_key="ntp_auth_key",
                                        ntp_auth_key_id=65533,
                                        ntp_auth_key_type="MD5",
                                        ntp_host_name="test ntp",
                                        secondary=[SECONDARY_ADDRESS1],
                                        third_party_monitoring=third_party_monitoring,
                                        comment=NTP_SERVER_COMMENT
                                        )
        monitoring = ntp_server.third_party_monitoring
        assert ntp_server.address == PRIMARY_ADDRESS1 and \
               SECONDARY_ADDRESS1 in ntp_server.secondary and \
               monitoring.monitoring_log_server_ref.href == log_server.href and \
               monitoring.netflow and monitoring.snmp_trap and \
               ntp_server.ntp_auth_key_type == "MD5" and \
               ntp_server.ipv6_address == IPV6_ADDRESS, NTP_SERVER_CREATE_ERROR
        logging.info("NtpServer created successfully.")
        ntp_server.add_secondary([SECONDARY_ADDRESS2], True)
        monitoring["snmp_trap"] = False
        monitoring["netflow"] = False
        ntp_server.update(third_party_monitoring=monitoring)
        ntp_server = NTPServer(NTP_SERVER_NAME)
        assert not ntp_server.third_party_monitoring.snmp_trap and \
               not ntp_server.third_party_monitoring.netflow and \
               SECONDARY_ADDRESS2 in ntp_server.secondary, NTP_SERVER_UPDATE_ERROR
        logging.info("NtpServer update successfully.")

        # HttpProxy
        http_proxy = HttpProxy.create(
            HTTP_PROXY_NAME,
            proxy_port=8080,
            address=PRIMARY_ADDRESS4,
            username=HTTP_PROXY_NAME,
            password=SHARE_SECRET,
            secondary=[SECONDARY_ADDRESS4],
            third_party_monitoring=third_party_monitoring,
            comment=HTTP_PROXY_COMMENT)
        monitoring = http_proxy.third_party_monitoring
        assert http_proxy.address == PRIMARY_ADDRESS4 and \
               SECONDARY_ADDRESS4 in http_proxy.secondary and \
               monitoring.monitoring_log_server_ref.href == log_server.href and \
               monitoring.netflow and monitoring.snmp_trap and \
               http_proxy.http_proxy_username == HTTP_PROXY_NAME, HTTP_PROXY_CREATE_ERROR
        logging.info("HttpProxy created successfully.")
        http_proxy.add_secondary([SECONDARY_ADDRESS2], True)
        monitoring["snmp_trap"] = False
        monitoring["netflow"] = False
        http_proxy.update(third_party_monitoring=monitoring)
        http_proxy = HttpProxy(HTTP_PROXY_NAME)
        assert not http_proxy.third_party_monitoring.snmp_trap and \
               not http_proxy.third_party_monitoring.netflow and \
               SECONDARY_ADDRESS2 in http_proxy.secondary, HTTP_PROXY_UPDATE_ERROR
        logging.info("HttpProxy update successfully.")

        # LogServer
        test_log_server = LogServer.create(LOG_SERVER_NAME, address=PRIMARY_ADDRESS1,
                                           ipv6_address=IPV6_ADDRESS,
                                           secondary=[SECONDARY_ADDRESS1, SECONDARY_ADDRESS2],
                                           location_ref=location,
                                           netflow_collector=netflow_collector,
                                           log_disk_space_handling_mode="overwrite_oldest",
                                           backup_log_server=[log_server],
                                           comment=LOG_SERVER_COMMENT)
        assert test_log_server.address == PRIMARY_ADDRESS1 and \
               test_log_server.ipv6_address == IPV6_ADDRESS and \
               test_log_server.log_disk_space_handling_mode == "overwrite_oldest" and \
               test_log_server.backup_log_server[0].href == log_server.href and \
               not test_log_server.inactive, LOG_SERVER_CREATE_ERROR
        logging.info("LogServer created successfully.")
        test_log_server.update(inactive=True, secondary=[SECONDARY_ADDRESS1, SECONDARY_ADDRESS2],
                               backup_log_server=[])
        test_log_server = LogServer(LOG_SERVER_NAME)
        assert test_log_server.inactive and SECONDARY_ADDRESS2 in test_log_server.secondary \
               and not test_log_server.backup_log_server, LOG_SERVER_UPDATE_ERROR
        logging.info("LogServer updated successfully.")
    except BaseException as ex:
        logging.error(f"Exception:{ex}")
        return_code = 1
    finally:
        AuthenticationMethod(AUTH_METHOD_NAME1).delete()
        logging.info("AuthenticationMethod deleted successfully.")
        TacacsServer(TACACS_SERVER_NAME1).delete()
        TacacsServer(TACACS_SERVER_NAME2).delete()
        logging.info("TacacsServer deleted successfully.")
        AuthenticationMethod(AUTH_METHOD_NAME2).delete()
        logging.info("AuthenticationMethod deleted successfully.")
        RadiusServer(RADIUS_SERVER_NAME1).delete()
        RadiusServer(RADIUS_SERVER_NAME2).delete()
        logging.info("RadiusServer deleted successfully.")
        IcapServer(ICAP_SERVER_NAME).delete()
        logging.info("IcapServer deleted successfully.")
        ProxyServer(PROXY_SERVER_NAME).delete()
        logging.info("ProxyServer deleted successfully.")
        ActiveDirectoryServer(ACTIVE_DIRECTORY_SERVER).delete()
        logging.info("ActiveDirectoryServer deleted successfully.")
        LDAPServer(LDAP_SERVER).delete()
        logging.info("LDAPServer deleted successfully.")
        ManagementServer(MGT_SERVER_NAME).delete()
        logging.info("ManagementServer deleted successfully.")
        SmtpServer(SMTP_SERVER_NAME).delete()
        logging.info("SmtpServer deleted successfully.")
        if is_epo_server:
            EpoServer(EPO_SERVER_NAME).delete()
            logging.info("EpoServer deleted successfully.")
        NTPServer(NTP_SERVER_NAME).delete()
        logging.info("NtpServer deleted successfully.")
        HttpProxy(HTTP_PROXY_NAME).delete()
        logging.info("HttpProxy deleted successfully.")
        LogServer(LOG_SERVER_NAME).delete()
        logging.info("LogServer deleted successfully.")
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to use different type of servers - TacacsServer, '
                    'RadiusServer, IcapServer, SmtpServer, ProxyServer, ActiveDirectoryServer, '
                    'LDAPServer, ManagementServer, EpoServer, NtpServer, HttpProxy and LogServer.',
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
