# Licensed under the Apache License, Version 2.0 (the "License"); you may
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

from smc.administration.certificates.tls import TLSServerCredential, TLSCryptographySuite
from smc.elements.other import Location
from smc.elements.servers import WebPortalServer, LogServer, WebApp

"""
Example script to show how to use Web Portal Server.
"""

from smc import session
from smc_info import SMC_URL, API_KEY, API_VERSION

WEB_SERVER_NAME = "web_server_test"
WEB_SERVER_PORTAL_CREATE_ERROR = "Failed to create web portal server with parameter."
WEB_SERVER_PORTAL_UPDATE_ERROR = "Failed to update web portal server."

if __name__ == "__main__":
    try:
        session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120,
                      api_version=API_VERSION)
        print("session OK")
        alert_server = list(LogServer.objects.all())[0]
        location = list(Location.objects.all())[0]
        tls_server_creds = list(TLSServerCredential.objects.all())[0]
        tls_cryptography_suite = list(TLSCryptographySuite.objects.all())[0]
        comment = "This is to test creation of web portal server."
        web_app = [WebApp.create(host_name="test_server",
                                 listening_address="5.5.5.5",
                                 enabled=True,
                                 log_access=True,
                                 server_credentials_ref=tls_server_creds,
                                 ssl_session_id=True,
                                 tls_cipher_suites=tls_cryptography_suite,
                                 web_app_identifier="webswing"
                                 )]
        # need to validate creation of WebPortalServer with external_pki_certificate_settings
        web_portal_server = WebPortalServer.create(WEB_SERVER_NAME,
                                                   alert_server=alert_server, address="5.5.5.5",
                                                   web_app=web_app,
                                                   announcement_enabled=True,
                                                   announcement_message="Test message",
                                                   comment=comment)
        for app in web_portal_server.web_app:
            if app['web_app_identifier'] == "webswing":
                web_app = app
                break
        assert web_portal_server.alert_server.href == alert_server.href and web_portal_server. \
            address == "5.5.5.5" and web_app.server_credentials_ref.href == tls_server_creds.href
        web_app.tls_cipher_suites.href == tls_cryptography_suite.\
            href, WEB_SERVER_PORTAL_CREATE_ERROR
        print("WebPortalServer created successfully.")
        web_portal_server.update(location_ref=location.href)
        web_portal_server = WebPortalServer(WEB_SERVER_NAME)
        assert web_portal_server.location_ref.href == location.href, WEB_SERVER_PORTAL_UPDATE_ERROR
        print("WebPortalServer updated successfully.")
    except BaseException as e:
        print("Exception:{}".format(e))
        exit(-1)
    finally:
        WebPortalServer(WEB_SERVER_NAME).delete()
        print("WebPortalServer deleted successfully.")
