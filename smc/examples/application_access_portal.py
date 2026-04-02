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
Example script to show how to use Application Access Portal Elements for SMC >= 7.5.0.
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
from smc.vpn.application_access_portal import *  # noqa
from smc.administration.user_auth.servers import AuthenticationMethod  # noqa
from smc.administration.user_auth.users import InternalUser, InternalUserGroup  # noqa
from smc.administration.certificates.tls import TLSCryptographySuite  # noqa
import smc.api.exceptions  # noqa
from smc.compat import is_api_version_more_than_or_equal  # noqa

ApplicationAccessSsoDomain_NAME = "test_applicationaccesssso_domain"
ApplicationAccessSsoDomain_CREATE_ERROR = "Fail to create ApplicationAccessSsoDomain."
ApplicationAccessSsoDomain_UPDATE_ERROR = "Fail to update ApplicationAccessSsoDomain."
ERROR_PROFILE_CREATE = "Fail to create ApplicationAccessServiceProfile."
ERROR_PROFILE_UPDATE = "Fail to update ApplicationAccessServiceProfile."
ApplicationAccess_SERVICE_PROFILE_NAME1 = "test_application_access_profile1"
ApplicationAccess_SERVICE_PROFILE_NAME2 = "test_application_access_profile2"
ApplicationAccess_SERVICE_PROFILE_NAME3 = "test_application_access_profile3"
ApplicationAccess_WEB_SERVICE_URL_REWRITE = "test_application_access_ws_url_rewrite"
ApplicationAccess_WEB_SERVICE_DNS_MAPPING = "test_application_access_ws_dns_mapping"
ApplicationAccess_WEB_SERVICE_FREE_FORM_URL = "test_application_access_ws_free_form_url"
Application_Access_CREDENTIALS = "test_application_access_credentials"
ApplicationAccess_PORTAL = "test_application_access_portal"
ApplicationAccess_PORTAL_POLICY = "test_application_access_portal_policy"
Application_Access_Portal_HOSTNAME_LIST = ["alias_portal.example.com", "portal.example.com"]
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
        if is_api_version_more_than_or_equal("7.5"):
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
            logging.info("Creating Application Access Elements")
            logging.info("Creating Application Access SSO Domain")
            application_access_sso_domain = ApplicationAccessSSODomain.create(ApplicationAccessSsoDomain_NAME, sso_mode="session_based")
            assert application_access_sso_domain.sso_mode == "session_based" and \
                   application_access_sso_domain.timeout == 30, ApplicationAccessSsoDomain_CREATE_ERROR
            logging.info("Created ApplicationAccessSSODomain successfully.")
            application_access_sso_domain.update(sso_mode="persistent", timeout=40)
            application_access_sso_domain = ApplicationAccessSSODomain(ApplicationAccessSsoDomain_NAME)
            assert application_access_sso_domain.sso_mode == "persistent" and application_access_sso_domain.timeout == 40, \
                ApplicationAccessSsoDomain_UPDATE_ERROR
            logging.info("Updated ApplicationAccessSsoDomain successfully.")

            error = ApplicationAccessHostname("192.168.1.1")
            application_access_profile1 = ApplicationAccessServiceProfile.create(ApplicationAccess_SERVICE_PROFILE_NAME1,
                                                           application_access_profile_exception=[error])
            assert application_access_profile1.name == ApplicationAccess_SERVICE_PROFILE_NAME1 and len(
                application_access_profile1.application_access_profile_exception), ERROR_PROFILE_CREATE
            logging.info("ApplicationAccessServiceProfile created successfully.")
            application_access_profile2 = ApplicationAccessServiceProfile.create(ApplicationAccess_SERVICE_PROFILE_NAME2,
                                                           cookie_hiding="encrypt_all",
                                                           application_access_profile_exception=[error],
                                                           authentication_type="http",
                                                           ntlm_support=True)
            assert application_access_profile2.cookie_hiding == "encrypt_all" and \
                   len(application_access_profile1.application_access_profile_exception) and \
                   application_access_profile2.ntlm_support, ERROR_PROFILE_CREATE
            logging.info("ApplicationAccessServiceProfile created successfully.")
            application_access_profile2.update(ntlm_support=False)
            application_access_profile2 = ApplicationAccessServiceProfile(ApplicationAccess_SERVICE_PROFILE_NAME2)
            assert not application_access_profile2.ntlm_support, ERROR_PROFILE_UPDATE
            logging.info("ApplicationAccessServiceProfile updated successfully.")
            application_access_http_field = ApplicationAccessHttpField(http_field_name="password", http_field_value="pass")
            application_access_profile3 = ApplicationAccessServiceProfile.create(ApplicationAccess_SERVICE_PROFILE_NAME3,
                                                           login_page_url="/login",
                                                           password_input_name="pass",
                                                           post_request_url="/post",
                                                           application_access_http_field=[
                                                               application_access_http_field
                                                           ],
                                                           user_input_format="domain\\user",
                                                           user_input_name="user",
                                                           cookie_hiding="encrypt_all",
                                                           application_access_profile_exception=[error],
                                                           authentication_type="form",
                                                           )
            assert application_access_profile3.login_page_url == "/login" and \
                   application_access_profile3.password_input_name == "pass" and \
                   application_access_profile3.post_request_url == "/post" and \
                   application_access_profile3.user_input_format == "domain\\user" and \
                   application_access_profile3.authentication_type == "form", ERROR_PROFILE_CREATE
            logging.info("ApplicationAccessServiceProfile created successfully.")
            application_access_profile3.update(password_input_name="password", login_page_url="/new_login")
            application_access_profile3 = ApplicationAccessServiceProfile(ApplicationAccess_SERVICE_PROFILE_NAME3)
            assert application_access_profile3.password_input_name == "password" and \
                   application_access_profile3.login_page_url == "/new_login", ERROR_PROFILE_UPDATE
            logging.info("ApplicationAccessServiceProfile updated successfully.")
            logging.info("Creating Application Access Services")
            logging.info("Creating Application Access Web Service URL Rewrite type")
            application_access_url_rewrite = ApplicationAccessWebService.create(
                name=ApplicationAccess_WEB_SERVICE_URL_REWRITE,
                routing_method="url_rewrite",
                title="RewriteTheWorld",
                start_page="/",
                internal_url="http://rootpath.com/",
                external_url="https://example.com",
                url_prefix="/http/internal_hidden/",
                application_access_service_profile=application_access_profile1.href,
                application_access_sso_domain=application_access_sso_domain)
            logging.info(f"Application Access Service {ApplicationAccess_WEB_SERVICE_URL_REWRITE} created successfully")
            logging.info("Updating ApplicationAccess Web Service URL Rewrite type")
            application_access_url_rewrite.update(start_page="/new_start_page/",
                                       application_access_service_profile=application_access_profile2.href)
            assert application_access_url_rewrite.start_page == "/new_start_page/" and \
                   application_access_url_rewrite.application_access_service_profile == application_access_profile2.href, \
                   "Fail to update ApplicationAccessWebService."
            logging.info(f"Application Access Service {ApplicationAccess_WEB_SERVICE_URL_REWRITE} updated successfully")
            logging.info(f"Checking Application Access Web Service URL Rewrite type")
            assert application_access_url_rewrite.title == "RewriteTheWorld" and \
                   application_access_url_rewrite.internal_url == "http://rootpath.com/" and \
                   application_access_url_rewrite.external_url == "https://example.com", \
                   f"Fail to check {ApplicationAccess_WEB_SERVICE_URL_REWRITE}."
            assert application_access_url_rewrite.url_prefix == "/http/internal_hidden/" and \
                   application_access_url_rewrite.application_access_sso_domain == application_access_sso_domain.href, \
                   f"Fail to check {ApplicationAccess_WEB_SERVICE_URL_REWRITE}."
            logging.info(f"Application Access Service {ApplicationAccess_WEB_SERVICE_URL_REWRITE} Settings are OK")
            logging.info("Creating Application Access Web Service Free Form URL type")
            application_access_allowed_url = ApplicationAccessAllowedURL(url_host="example.com", port="80")
            application_access_allowed_url2 = ApplicationAccessAllowedURL(protocol="HTTPS",
                                                    url_host="anotherexample.com",
                                                    port="443")
            application_access_free_url = ApplicationAccessWebService.create(
                name=ApplicationAccess_WEB_SERVICE_FREE_FORM_URL,
                routing_method="free_url",
                application_access_service_profile=application_access_profile1.href,
                application_access_allowed_url=[application_access_allowed_url, application_access_allowed_url2])
            logging.info(f"Application Access Service {ApplicationAccess_WEB_SERVICE_FREE_FORM_URL} created successfully")
            logging.info("Checking Application Access Web Service Free Form URL type")
            assert application_access_free_url.application_access_service_profile == application_access_profile1.href and \
                   len(application_access_free_url.application_access_allowed_url) == 2, "Fail to create ApplicationAccessWebService."
            logging.info(f"Application Access Service {ApplicationAccess_WEB_SERVICE_FREE_FORM_URL} Settings are OK")
            application_access_dns_mapping = ApplicationAccessWebService.create(
                name=ApplicationAccess_WEB_SERVICE_DNS_MAPPING,
                routing_method="dns_mapping",
                title="DNSMapping",
                start_page="/",
                internal_url="http://this.example.com/",
                external_url="https://that.example.com",
                application_access_service_profile=application_access_profile3.href,
                self_signed_certificate=True)
            logging.info(f"Application Access Service {ApplicationAccess_WEB_SERVICE_DNS_MAPPING} created successfully")
            logging.info("Checking Application Access Web Service DNS Mapping Settings")
            assert application_access_dns_mapping.title == "DNSMapping" and \
                   application_access_dns_mapping.start_page == "/", "Fail to create ApplicationAccessWebService."
            assert application_access_dns_mapping.internal_url == "http://this.example.com/" and \
                   application_access_dns_mapping.external_url == "https://that.example.com", \
                   "Fail to create ApplicationAccessWebService."
            assert application_access_dns_mapping.application_access_service_profile == application_access_profile3.href and \
                   application_access_dns_mapping.self_signed_certificate, "Fail to create ApplicationAccessWebService."
            logging.info(f"Application Access Service {ApplicationAccess_WEB_SERVICE_DNS_MAPPING} Settings are OK")
            logging.info("Creating Application Access Policy Example")
            sslvpn_policy = ApplicationAccessPolicy.create(name=ApplicationAccess_PORTAL_POLICY)
            logging.info(f"Application Access Policy {sslvpn_policy.name} created successfully")
            logging.info(f"Adding Rules to {sslvpn_policy.name} Application Access Policy")
            sslvpn_policy.application_access_rules.create(
                name="Rule1",
                application_access_web_service=[application_access_url_rewrite],
                authentication={"methods": [AuthenticationMethod('User password').href],
                                "require_auth": True,
                                "users": [InternalUserGroup(name="Application Access users").href]})
            sslvpn_policy.application_access_rules.create(
                name="Rule2", application_access_web_service=[application_access_free_url],
                authentication={"methods": [AuthenticationMethod('User password').href],
                                "require_auth": True,
                                "users": [InternalUser(name="Jennifer").href]})
            sslvpn_policy.application_access_rules.create(
                name="Rule3",
                application_access_web_service=[application_access_dns_mapping],
                authentication={"methods": [AuthenticationMethod('User password').href],
                                "require_auth": True,
                                "users": [InternalUser(name="Mike").href]})
            rulez = sslvpn_policy.application_access_rules
            assert len(rulez) == 3, logging.error(f"Expected 3 rules in Application Access Policy but"
                                                  f" got {len(rulez)}")
            logging.info(f"Rules added to {sslvpn_policy.name} Application Access Policy")
            logging.info("Creating Application Access Portal Example")
            sslvpn_portal = ApplicationAccessPortal.create(
                name=ApplicationAccess_PORTAL,
                application_access_hostnames=Application_Access_Portal_HOSTNAME_LIST,
                self_signed_certificate=True,
                application_access_policy=sslvpn_policy)
            logging.info(f"Application Access Portal {sslvpn_portal.name} created successfully")
            logging.info("Checking Application Access Portal Example Settings")
            assert {item['application_access_hostname'] for item in sslvpn_portal.application_access_hostnames} == set(
                Application_Access_Portal_HOSTNAME_LIST), \
                "Application Access Portal Hostnames are not set correctly"
            assert sslvpn_portal.self_signed_certificate, \
                "Application Access Portal Self Signed Certificate is not set correctly"
            assert sslvpn_portal.application_access_policy == sslvpn_policy.href, \
                "Application Access Portal Policy is not set correctly"
            logging.info(f"Application Access Portal {sslvpn_portal.name} Settings are OK")
            logging.info(f"Assigning Application Access Portal {sslvpn_portal.name} to Engine Internal Gateway")
            sslvpn_portal_setting_dict = {
                "application_access_portal": sslvpn_portal.href,
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
            ep1.update(enabled=True, application_access_portal=True)
            application_access_portal = Engine(FW_NAME).vpn.application_access_portal
            application_access_portal.update(application_access_portal_setting=[sslvpn_portal_setting_dict],
                                  ssl_vpn_proxy=ssl_vpn_proxydict)
            logging.info(f"Application Access Portal {sslvpn_portal.name} assigned to Engine Internal Gateway")
            logging.info(f"Checking Application Access Portal {sslvpn_portal.name} Gateway Settings")
            application_access_portal = Engine(FW_NAME).vpn.application_access_portal
            assert application_access_portal.application_access_portal_setting[0]["application_access_portal"] == sslvpn_portal.href, \
                "Application Access Portal is not set correctly to Engine Internal Gateway"
            assert application_access_portal.application_access_portal_setting[0]["port"] == 443, \
                "Application Access Portal Port is not set correctly to Engine Internal Gateway"
            assert application_access_portal.ssl_vpn_proxy["renegociation_timeout"] == 7200, \
                "Application Access Proxy Renegociation Timeout is not set correctly to Engine Internal Gateway"
            assert application_access_portal.ssl_vpn_proxy["ssl_3_0"], \
                "Application Access Proxy SSL 3.0 is not set correctly to Engine Internal Gateway"
            assert application_access_portal.ssl_vpn_proxy["tls_1_0"], \
                "Application Access Proxy TLS 1.0 is not set correctly to Engine Internal Gateway"
            assert application_access_portal.ssl_vpn_proxy["tls_1_1"], \
                "Application Access Proxy TLS 1.1 is not set correctly to Engine Internal Gateway"
            assert application_access_portal.ssl_vpn_proxy["tls_1_2"], \
                "Application Access Proxy TLS 1.2 is not set correctly to Engine Internal Gateway"
            logging.info(f"Application Access Portal {sslvpn_portal.name} Gateway Settings are OK")

    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1

    finally:
        if is_api_version_more_than_or_equal("7.5"):
            # Unset Application Access Portal on Engine Gateway to be able to remove it
            Engine(FW_NAME).vpn.vpn_client.update(application_access_portal_setting=[])
            delete_element(Engine, FW_NAME, "Deleted Engine successfully.")
            # Delete Application Access Portal Elements
            delete_element(ApplicationAccessPortal, ApplicationAccess_PORTAL, "Deleted ApplicationAccessPortal successfully.")
            delete_element(ApplicationAccessPolicy, ApplicationAccess_PORTAL_POLICY, "Deleted ApplicationAccessPolicy successfully.")
            delete_element(ApplicationAccessWebService, ApplicationAccess_WEB_SERVICE_URL_REWRITE,
                           "Deleted ApplicationAccessWebService successfully.")
            delete_element(ApplicationAccessWebService, ApplicationAccess_WEB_SERVICE_DNS_MAPPING,
                           "Deleted ApplicationAccessWebService successfully.")
            delete_element(ApplicationAccessWebService, ApplicationAccess_WEB_SERVICE_FREE_FORM_URL,
                           "Deleted ApplicationAccessWebService successfully.")
            delete_element(ApplicationAccessSSODomain, ApplicationAccessSsoDomain_NAME,
                           "Deleted ApplicationAccessSSODomain successfully.")
            delete_element(ApplicationAccessServiceProfile, ApplicationAccess_SERVICE_PROFILE_NAME1,
                           "Deleted ApplicationAccessServiceProfile successfully.")
            delete_element(ApplicationAccessServiceProfile, ApplicationAccess_SERVICE_PROFILE_NAME2,
                           "Deleted ApplicationAccessServiceProfile successfully.")
            delete_element(ApplicationAccessServiceProfile, ApplicationAccess_SERVICE_PROFILE_NAME3,
                           "Deleted ApplicationAccessServiceProfile successfully.")
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to use Application Access Portal Elements for SMC >= 7.5.0.',
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
