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
Example script to show how to use SSL VPN Portal Elements.
"""
import argparse
import logging
import sys

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.core.engine import Engine, InternalEndpoint  # noqa
from smc.core.engines import Layer3Firewall  # noqa
from smc.vpn.elements import ConnectionType  # noqa
from smc.base.util import element_resolver  # noqa
from smc.vpn.ssl_vpn_portal import *  # noqa
from smc.administration.user_auth.servers import AuthenticationMethod  # noqa
from smc.administration.user_auth.users import InternalUser, InternalUserGroup  # noqa
from smc.administration.certificates.tls import TLSCryptographySuite  # noqa
import smc.api.exceptions  # noqa

SSLVPNSSODomain_NAME = "test_sslvpnsso_domain"
SSLVPNSSODomain_CREATE_ERROR = "Fail to create SSLVPNSSODomain."
SSLVPNSSODomain_UPDATE_ERROR = "Fail to update SSLVPNSSODomain."
ERROR_PROFILE_CREATE = "Fail to create SSLVPNServiceProfile."
ERROR_PROFILE_UPDATE = "Fail to update SSLVPNServiceProfile."
SSLVPN_SERVICE_PROFILE_NAME1 = "test_sslvpn_profile1"
SSLVPN_SERVICE_PROFILE_NAME2 = "test_sslvpn_profile2"
SSLVPN_SERVICE_PROFILE_NAME3 = "test_sslvpn_profile3"
SSLVPN_WEB_SERVICE_URL_REWRITE = "test_sslvpn_ws_url_rewrite"
SSLVPN_WEB_SERVICE_DNS_MAPPING = "test_sslvpn_ws_dns_mapping"
SSLVPN_WEB_SERVICE_FREE_FORM_URL = "test_sslvpn_ws_free_form_url"
SSL_VPN_CREDENTIALS = "test_sslvpn_credentials"
SSLVPN_PORTAL = "test_sslvpn_portal"
SSLVPN_PORTAL_POLICY = "test_sslvpn_portal_policy"
SSLVPNPORTAL_HOSTNAME_LIST = ["alias_portal.example.com", "portal.example.com"]
TEST_GATEWAY = 'test_gateway'
FW_NAME = 'myFW'

logging.getLogger()
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - [%(levelname)s] : %(message)s')


def delete_element(cls, name, log_message):
    if cls.objects.filter(name=name, exact_match=True):
        cls(name).delete()
        logging.info(log_message)


def main():
    return_code = 0
    try:
        arguments = parse_command_line_arguments()
        session.login(url=arguments.api_url, api_key=arguments.api_key,
                      login=arguments.smc_user,
                      pwd=arguments.smc_pwd, api_version=arguments.api_version)
        logging.info("session OK")
        logging.info("Creating Engine")
        engine = Layer3Firewall.create(name=FW_NAME,
                                       mgmt_ip="10.10.10.26",
                                       mgmt_interface=0,
                                       mgmt_network="10.10.10.0/24")
        engine.add_route("10.10.10.26", "0.0.0.0/0")
        engine.physical_interface.add_layer3_interface(interface_id=1,
                                                       address="120.10.10.11",
                                                       network_value="120.10.10.0/24")
        engine.physical_interface.add_layer3_interface(interface_id=2,
                                                       address="10.10.20.2",
                                                       network_value="10.10.20.0/24")
        logging.info("Engine created successfully.")
        logging.info("Creating SSLVPN Elements")
        logging.info("Creating SSLVPN SSO Domain")
        ssl_vpn_sso_domain = SSLVPNSSODomain.create(SSLVPNSSODomain_NAME, sso_mode="session_based")
        assert ssl_vpn_sso_domain.sso_mode == "session_based" and \
               ssl_vpn_sso_domain.timeout == 30, SSLVPNSSODomain_CREATE_ERROR
        logging.info("Created SSLVPNSSODomain successfully.")
        ssl_vpn_sso_domain.update(sso_mode="persistent", timeout=40)
        ssl_vpn_sso_domain = SSLVPNSSODomain(SSLVPNSSODomain_NAME)
        assert ssl_vpn_sso_domain.sso_mode == "persistent" and ssl_vpn_sso_domain.timeout == 40, \
            SSLVPNSSODomain_UPDATE_ERROR
        logging.info("Updated SSLVPNSSODomain successfully.")

        error = SSLVPNHostname("192.168.1.1")
        ssl_vpn_profile1 = SSLVPNServiceProfile.create(SSLVPN_SERVICE_PROFILE_NAME1,
                                                       ssl_vpn_profile_exception=[error])
        assert ssl_vpn_profile1.name == SSLVPN_SERVICE_PROFILE_NAME1 and len(
            ssl_vpn_profile1.ssl_vpn_profile_exception), ERROR_PROFILE_CREATE
        logging.info("SSLVPNServiceProfile created successfully.")
        ssl_vpn_profile2 = SSLVPNServiceProfile.create(SSLVPN_SERVICE_PROFILE_NAME2,
                                                       cookie_hiding="encrypt_all",
                                                       ssl_vpn_profile_exception=[error],
                                                       authentication_type="http",
                                                       ntlm_support=True)
        assert ssl_vpn_profile2.cookie_hiding == "encrypt_all" and \
               len(ssl_vpn_profile1.ssl_vpn_profile_exception) and \
               ssl_vpn_profile2.ntlm_support, ERROR_PROFILE_CREATE
        logging.info("SSLVPNServiceProfile created successfully.")
        ssl_vpn_profile2.update(ntlm_support=False)
        ssl_vpn_profile2 = SSLVPNServiceProfile(SSLVPN_SERVICE_PROFILE_NAME2)
        assert not ssl_vpn_profile2.ntlm_support, ERROR_PROFILE_UPDATE
        logging.info("SSLVPNServiceProfile updated successfully.")
        ssl_vpn_http_field = SSLVPNHttpField(http_field_name="password", http_field_value="pass")
        ssl_vpn_profile3 = SSLVPNServiceProfile.create(SSLVPN_SERVICE_PROFILE_NAME3,
                                                       login_page_url="/login",
                                                       password_input_name="pass",
                                                       post_request_url="/post",
                                                       ssl_vpn_http_field=[
                                                           ssl_vpn_http_field
                                                       ],
                                                       user_input_format="domain\\user",
                                                       user_input_name="user",
                                                       cookie_hiding="encrypt_all",
                                                       ssl_vpn_profile_exception=[error],
                                                       authentication_type="form",
                                                       )
        assert ssl_vpn_profile3.login_page_url == "/login" and \
               ssl_vpn_profile3.password_input_name == "pass" and \
               ssl_vpn_profile3.post_request_url == "/post" and \
               ssl_vpn_profile3.user_input_format == "domain\\user" and \
               ssl_vpn_profile3.authentication_type == "form", ERROR_PROFILE_CREATE
        logging.info("SSLVPNServiceProfile created successfully.")
        ssl_vpn_profile3.update(password_input_name="password", login_page_url="/new_login")
        ssl_vpn_profile3 = SSLVPNServiceProfile(SSLVPN_SERVICE_PROFILE_NAME3)
        assert ssl_vpn_profile3.password_input_name == "password" and \
               ssl_vpn_profile3.login_page_url == "/new_login", ERROR_PROFILE_UPDATE
        logging.info("SSLVPNServiceProfile updated successfully.")
        logging.info("Creating SSLVPN Services")
        logging.info("Creating SSLVPN Web Service URL Rewrite type")
        ssl_vpn_url_rewrite = SSLVPNWebService.create(
            name=SSLVPN_WEB_SERVICE_URL_REWRITE,
            routing_method="url_rewrite",
            title="RewriteTheWorld",
            start_page="/",
            internal_url="http://rootpath.com/",
            external_url="https://example.com",
            url_prefix="/http/internal_hidden/",
            ssl_vpn_service_profile=ssl_vpn_profile1.href,
            ssl_vpn_sso_domain=ssl_vpn_sso_domain)
        logging.info(f"SSLVPN Service {SSLVPN_WEB_SERVICE_URL_REWRITE} created successfully")
        logging.info("Updating SSLVPN Web Service URL Rewrite type")
        ssl_vpn_url_rewrite.update(start_page="/new_start_page/",
                                   ssl_vpn_service_profile=ssl_vpn_profile2.href)
        assert ssl_vpn_url_rewrite.start_page == "/new_start_page/" and \
               ssl_vpn_url_rewrite.ssl_vpn_service_profile == ssl_vpn_profile2.href, \
               "Fail to update SSLVPNWebService."
        logging.info(f"SSLVPN Service {SSLVPN_WEB_SERVICE_URL_REWRITE} updated successfully")
        logging.info(f"Checking SSLVPN Web Service URL Rewrite type")
        assert ssl_vpn_url_rewrite.title == "RewriteTheWorld" and \
               ssl_vpn_url_rewrite.internal_url == "http://rootpath.com/" and \
               ssl_vpn_url_rewrite.external_url == "https://example.com", \
               f"Fail to check {SSLVPN_WEB_SERVICE_URL_REWRITE}."
        assert ssl_vpn_url_rewrite.url_prefix == "/http/internal_hidden/" and \
               ssl_vpn_url_rewrite.ssl_vpn_sso_domain == ssl_vpn_sso_domain.href, \
               f"Fail to check {SSLVPN_WEB_SERVICE_URL_REWRITE}."
        logging.info(f"SSLVPN Service {SSLVPN_WEB_SERVICE_URL_REWRITE} Settings are OK")
        logging.info("Creating SSLVPN Web Service Free Form URL type")
        ssl_vpn_allowed_url = SSLVPNAllowedURL(url_host="example.com", port="80")
        ssl_vpn_allowed_url2 = SSLVPNAllowedURL(protocol="HTTPS",
                                                url_host="anotherexample.com",
                                                port="443")
        ssl_vpn_free_url = SSLVPNWebService.create(
            name=SSLVPN_WEB_SERVICE_FREE_FORM_URL,
            routing_method="free_url",
            ssl_vpn_service_profile=ssl_vpn_profile1.href,
            ssl_vpn_allowed_url=[ssl_vpn_allowed_url, ssl_vpn_allowed_url2])
        logging.info(f"SSLVPN Service {SSLVPN_WEB_SERVICE_FREE_FORM_URL} created successfully")
        logging.info("Checking SSLVPN Web Service Free Form URL type")
        assert ssl_vpn_free_url.ssl_vpn_service_profile == ssl_vpn_profile1.href and \
               len(ssl_vpn_free_url.ssl_vpn_allowed_url) == 2, "Fail to create SSLVPNWebService."
        logging.info(f"SSLVPN Service {SSLVPN_WEB_SERVICE_FREE_FORM_URL} Settings are OK")
        ssl_vpn_dns_mapping = SSLVPNWebService.create(
            name=SSLVPN_WEB_SERVICE_DNS_MAPPING,
            routing_method="dns_mapping",
            title="DNSMapping",
            start_page="/",
            internal_url="http://this.example.com/",
            external_url="https://that.example.com",
            ssl_vpn_service_profile=ssl_vpn_profile3.href,
            self_signed_certificate=True)
        logging.info(f"SSLVPN Service {SSLVPN_WEB_SERVICE_DNS_MAPPING} created successfully")
        logging.info("Checking SSLVPN Web Service DNS Mapping Settings")
        assert ssl_vpn_dns_mapping.title == "DNSMapping" and \
               ssl_vpn_dns_mapping.start_page == "/", "Fail to create SSLVPNWebService."
        assert ssl_vpn_dns_mapping.internal_url == "http://this.example.com/" and \
               ssl_vpn_dns_mapping.external_url == "https://that.example.com", \
               "Fail to create SSLVPNWebService."
        assert ssl_vpn_dns_mapping.ssl_vpn_service_profile == ssl_vpn_profile3.href and \
               ssl_vpn_dns_mapping.self_signed_certificate, "Fail to create SSLVPNWebService."
        logging.info(f"SSLVPN Service {SSLVPN_WEB_SERVICE_DNS_MAPPING} Settings are OK")
        logging.info("Creating SSLVPN Policy Example")
        sslvpn_policy = SSLVPNPolicy.create(name=SSLVPN_PORTAL_POLICY)
        logging.info(f"SSLVPN Policy {sslvpn_policy.name} created successfully")
        logging.info(f"Adding Rules to {sslvpn_policy.name} SSLVPN Policy")
        sslvpn_policy.sslvpn_rules.create(
            name="Rule1",
            ssl_vpn_web_service=[ssl_vpn_url_rewrite],
            authentication={"methods": [AuthenticationMethod('User password').href],
                            "require_auth": True,
                            "users": [InternalUserGroup(name="SSL VPN users").href]})
        sslvpn_policy.sslvpn_rules.create(
            name="Rule2", ssl_vpn_web_service=[ssl_vpn_free_url],
            authentication={"methods": [AuthenticationMethod('User password').href],
                            "require_auth": True,
                            "users": [InternalUser(name="Jennifer").href]})
        sslvpn_policy.sslvpn_rules.create(
            name="Rule3",
            ssl_vpn_web_service=[ssl_vpn_dns_mapping],
            authentication={"methods": [AuthenticationMethod('User password').href],
                            "require_auth": True,
                            "users": [InternalUser(name="Mike").href]})
        rulez = sslvpn_policy.sslvpn_rules
        assert len(rulez) == 3, logging.error(f"Expected 3 rules in SSLVPN Policy but"
                                              f" got {len(rulez)}")
        logging.info(f"Rules added to {sslvpn_policy.name} SSLVPN Policy")
        logging.info("Creating SSLVPN Portal Example")
        sslvpn_portal = SSLVPNPortal.create(
            name=SSLVPN_PORTAL,
            ssl_vpn_hostnames=SSLVPNPORTAL_HOSTNAME_LIST,
            self_signed_certificate=True,
            ssl_vpn_policy=sslvpn_policy)
        logging.info(f"SSLVPN Portal {sslvpn_portal.name} created successfully")
        logging.info("Checking SSLVPN Portal Example Settings")
        assert {item['ssl_vpn_hostname'] for item in sslvpn_portal.ssl_vpn_hostnames} == set(
            SSLVPNPORTAL_HOSTNAME_LIST), \
            "SSLVPN Portal Hostnames are not set correctly"
        assert sslvpn_portal.self_signed_certificate, \
            "SSLVPN Portal Self Signed Certificate is not set correctly"
        assert sslvpn_portal.ssl_vpn_policy == sslvpn_policy.href, \
            "SSLVPN Portal Policy is not set correctly"
        logging.info(f"SSLVPN Portal {sslvpn_portal.name} Settings are OK")
        logging.info(f"Assigning SSLVPN Portal {sslvpn_portal.name} to Engine Internal Gateway")
        sslvpn_portal_setting_dict = {
            "ssl_vpn_portal": sslvpn_portal.href,
            "port": 443
        }
        nist_crytptosuite = TLSCryptographySuite(
            "NIST (SP 800-52) Compatible SSL Cryptographic Algorithms")
        ssl_vpn_proxydict = {
            "ssl_3_0": True,
            "tls_1_0": True,
            "tls_1_1": True,
            "tls_1_2": True,
            "tls_cryptography_suite_set": nist_crytptosuite.href
        }
        engine_to_update = Engine(FW_NAME)
        ex_internal_gw = engine_to_update.vpn
        ep1 = ex_internal_gw.internal_endpoint.get_exact('120.10.10.11')
        ep1.update(enabled=True, ssl_vpn_portal=True)
        ssl_vpn_portal = Engine(FW_NAME).vpn.ssl_vpn_portal
        ssl_vpn_portal.update(ssl_vpn_portal_setting=[sslvpn_portal_setting_dict],
                              ssl_vpn_proxy=ssl_vpn_proxydict)
        logging.info(f"SSLVPN Portal {sslvpn_portal.name} assigned to Engine Internal Gateway")
        logging.info(f"Checking SSLVPN Portal {sslvpn_portal.name} Gateway Settings")
        ssl_vpn_portal = Engine(FW_NAME).vpn.ssl_vpn_portal
        assert ssl_vpn_portal.ssl_vpn_portal_setting[0]["ssl_vpn_portal"] == sslvpn_portal.href, \
            "SSLVPN Portal is not set correctly to Engine Internal Gateway"
        assert ssl_vpn_portal.ssl_vpn_portal_setting[0]["port"] == 443, \
            "SSLVPN Portal Port is not set correctly to Engine Internal Gateway"
        assert ssl_vpn_portal.ssl_vpn_proxy["renegociation_timeout"] == 7200, \
            "SSLVPN Proxy Renegociation Timeout is not set correctly to Engine Internal Gateway"
        assert ssl_vpn_portal.ssl_vpn_proxy["ssl_3_0"], \
            "SSLVPN Proxy SSL 3.0 is not set correctly to Engine Internal Gateway"
        assert ssl_vpn_portal.ssl_vpn_proxy["tls_1_0"], \
            "SSLVPN Proxy TLS 1.0 is not set correctly to Engine Internal Gateway"
        assert ssl_vpn_portal.ssl_vpn_proxy["tls_1_1"], \
            "SSLVPN Proxy TLS 1.1 is not set correctly to Engine Internal Gateway"
        assert ssl_vpn_portal.ssl_vpn_proxy["tls_1_2"], \
            "SSLVPN Proxy TLS 1.2 is not set correctly to Engine Internal Gateway"
        logging.info(f"SSLVPN Portal {sslvpn_portal.name} Gateway Settings are OK")

    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1

    finally:
        # Unset SSLVPN Portal on Engine Gateway to be able to remove it
        Engine(FW_NAME).vpn.vpn_client.update(ssl_vpn_portal_setting=[])
        delete_element(Engine, FW_NAME, "Deleted Engine successfully.")
        # Delete SSLVPN Portal Elements
        delete_element(SSLVPNPortal, SSLVPN_PORTAL, "Deleted SSLVPNPortal successfully.")
        delete_element(SSLVPNPolicy, SSLVPN_PORTAL_POLICY, "Deleted SSLVPNPolicy successfully.")
        delete_element(SSLVPNWebService, SSLVPN_WEB_SERVICE_URL_REWRITE,
                       "Deleted SSLVPNWebService successfully.")
        delete_element(SSLVPNWebService, SSLVPN_WEB_SERVICE_DNS_MAPPING,
                       "Deleted SSLVPNWebService successfully.")
        delete_element(SSLVPNWebService, SSLVPN_WEB_SERVICE_FREE_FORM_URL,
                       "Deleted SSLVPNWebService successfully.")
        delete_element(SSLVPNSSODomain, SSLVPNSSODomain_NAME,
                       "Deleted SSLVPNSSODomain successfully.")
        delete_element(SSLVPNServiceProfile, SSLVPN_SERVICE_PROFILE_NAME1,
                       "Deleted SSLVPNServiceProfile successfully.")
        delete_element(SSLVPNServiceProfile, SSLVPN_SERVICE_PROFILE_NAME2,
                       "Deleted SSLVPNServiceProfile successfully.")
        delete_element(SSLVPNServiceProfile, SSLVPN_SERVICE_PROFILE_NAME3,
                       "Deleted SSLVPNServiceProfile successfully.")
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to use SSL VPN Portal Elements.',
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
