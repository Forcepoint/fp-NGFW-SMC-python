#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
"""
Example script to show how to use Web Access Server.
"""
import argparse
import logging
import sys

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.compat import is_api_version_less_than  # noqa
from smc.administration.certificates.tls import TLSServerCredential, TLSCryptographySuite  # noqa
from smc.elements.other import Location  # noqa
from smc.elements.servers import WebPortalServer, WebAccessServer, LogServer, WebApp  # noqa

WEB_SERVER_NAME = "web_server_test"
WEB_SERVER_CREATE_ERROR = "Failed to create web access server with parameter."
WEB_SERVER_UPDATE_ERROR = "Failed to update web access server."

logging.getLogger()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - '
                                               '%(name)s - [%(levelname)s] : %(message)s')


def main():
    return_code = 0
    try:
        arguments = parse_command_line_arguments()
        session.login(url=arguments.api_url, api_key=arguments.api_key,
                      login=arguments.smc_user,
                      pwd=arguments.smc_pwd, api_version=arguments.api_version)
        logging.info("session OK")
        alert_server = list(LogServer.objects.all())[0]
        location = list(Location.objects.all())[0]
        tls_server_creds = list(TLSServerCredential.objects.all())[0]
        tls_cryptography_suite = list(TLSCryptographySuite.objects.all())[0]
        comment = "This is to test creation of web access server."
        web_app = [WebApp.create(host_name="test_server",
                                 listening_address="5.5.5.5",
                                 enabled=True,
                                 log_access=True,
                                 server_credentials_ref=tls_server_creds,
                                 ssl_session_id=True,
                                 tls_cipher_suites=tls_cryptography_suite,
                                 web_app_identifier="webswing"
                                 )]
        # need to validate creation of WebAccessServer with external_pki_certificate_settings
        web_access_server = WebPortalServer.create(WEB_SERVER_NAME,
                                                   alert_server=alert_server, address="5.5.5.5",
                                                   web_app=web_app,
                                                   announcement_enabled=True,
                                                   announcement_message="Test message",
                                                   comment=comment) \
            if is_api_version_less_than("7.3") else (
            WebAccessServer.create(WEB_SERVER_NAME,
                                   alert_server=alert_server, address="5.5.5.5",
                                   web_app=web_app,
                                   comment=comment))
        for app in web_access_server.web_app:
            if app['web_app_identifier'] == "webswing":
                web_app = app
                break
        assert web_access_server.alert_server.href == alert_server.href and web_access_server. \
            address == "5.5.5.5" and web_app.server_credentials_ref.href == tls_server_creds.href
        web_app.tls_cipher_suites.href == tls_cryptography_suite. \
            href, WEB_SERVER_CREATE_ERROR
        logging.info("WebAccessServer created successfully.")
        web_access_server.update(location_ref=location.href)
        web_access_server = WebPortalServer(WEB_SERVER_NAME) \
            if is_api_version_less_than("7.3") else WebAccessServer(WEB_SERVER_NAME)
        assert web_access_server.location_ref.href == location.href, WEB_SERVER_UPDATE_ERROR
        logging.info("WebAccessServer updated successfully.")
    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        if is_api_version_less_than("7.3"):
            WebPortalServer(WEB_SERVER_NAME).delete()
        else:
            WebAccessServer(WEB_SERVER_NAME).delete()
        logging.info("WebAccessServer deleted successfully.")
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to use Web Access Server',
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


if __name__ == "__main__":
    sys.exit(main())
