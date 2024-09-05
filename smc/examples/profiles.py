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
Example script to show how to use User Response and CustomPropertiesProfile.
"""
import argparse
import logging
import os
import sys
from enum import Enum

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.elements.profiles import UserResponseEntry, UserResponse, CustomPropertiesProfile  # noqa

# CustomPropertiesProfile
CUSTOM_PROPERTY_NAME = "test_custom_property"
CUSTOM_SCRIPT_FILE = "custom_script.zip"
CUSTOM_PROPERTIES_CREATE_ERROR = "Fail to create CustomPropertiesProfile"
CUSTOM_PROPERTIES_UPDATE_ERROR = "Fail to update CustomPropertiesProfile"

# UserResponse
USER_RESPONSE_NAME = "test_user_response"
CREATE_USER_RESPONSE_ERROR = "Fail to create user response."
UPDATE_USER_RESPONSE_ERROR = "Fail to update user response."
USER_RESPONSE_TEXT = "USER_RESPONSE_TEXT"
USER_RESPONSE_MESSAGE = """The connection was not allowed by the corporate security policy.\n\n
                            For more information, contact your helpdesk and provide the following de
                            tails:\n\nSource IP Address: {{SrcIP}}\nDestination IP Address: {{DstIP}
                            }\nRule: {{RuleTag}}
                        """
logging.getLogger()
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - '
                                                '%(name)s - [%(levelname)s] : %(message)s')


class Reason(Enum):
    CONN_BLOACKLIST = "conn_blacklisted"
    CONN_NOT_ALLOWED = "conn_not_allowed"
    DEEP_INSPECTION = "deep_inspection"
    URL_NOT_ALLOWED = "url_not_allowed"
    VIRUS_FOUND = "virus_found"
    DLP_BLOCK = "blocked_by_dlp"


class ResponseType(Enum):
    RESPONSE = "response_page"
    HTML = "html_page"
    TCPCLOSE = "tcp_close"
    REDIRECT = "url_redirect"


def main():
    return_code = 0

    try:
        arguments = parse_command_line_arguments()
        session.login(url=arguments.api_url, api_key=arguments.api_key,
                      login=arguments.smc_user,
                      pwd=arguments.smc_pwd, api_version=arguments.api_version)
        logging.info("session OK")
        user_response_entry = [UserResponseEntry.create(reason=Reason.CONN_BLOACKLIST.value,
                                                        response_type=ResponseType.RESPONSE.value,
                                                        user_response_message=USER_RESPONSE_MESSAGE,
                                                        user_response_title="Connection Not Allowed"
                                                        ),
                               UserResponseEntry.create(reason=Reason.CONN_NOT_ALLOWED.value,
                                                        response_type=ResponseType.HTML.value,
                                                        user_response_text=USER_RESPONSE_TEXT),
                               UserResponseEntry.create(reason=Reason.DEEP_INSPECTION.value,
                                                        response_type=ResponseType.TCPCLOSE.value),
                               UserResponseEntry.create(reason=Reason.URL_NOT_ALLOWED.value,
                                                        response_type=ResponseType.HTML.value,
                                                        user_response_text=USER_RESPONSE_TEXT),
                               UserResponseEntry.create(reason=Reason.VIRUS_FOUND.value,
                                                        response_type=ResponseType.RESPONSE.value,
                                                        user_response_message="Test response "
                                                                              "message",
                                                        user_response_title="File Blocked"),
                               UserResponseEntry.create(reason=Reason.DLP_BLOCK.value,
                                                        redirect="automatic",
                                                        response_type="url_redirect",
                                                        user_response_text="https://test.com")]
        user_response = UserResponse.create(name=USER_RESPONSE_NAME,
                                            user_response_entry=user_response_entry,
                                            comment="This is testing of user response.")

        is_valid_blocked_by_dlp = False
        is_valid_virus_found = False
        for entry in user_response.user_response_entry:
            if entry.reason == Reason.DLP_BLOCK.value:
                if entry.redirect == "automatic" and entry.type == ResponseType.REDIRECT.value and \
                        entry.user_response_text == "https://test.com":
                    is_valid_blocked_by_dlp = True
            if entry.reason == Reason.VIRUS_FOUND.value and \
                    entry.type == ResponseType.RESPONSE.value and \
                    entry.user_response_message == "Test response message" and \
                    entry.user_response_title == "File Blocked":
                is_valid_virus_found = True
        assert is_valid_virus_found and is_valid_blocked_by_dlp, CREATE_USER_RESPONSE_ERROR
        logging.info("Created UserResponse Successfully.")
        user_response = UserResponse(USER_RESPONSE_NAME)
        list_of_user_entry = user_response.user_response_entry
        for entry in list_of_user_entry:
            if entry.reason == Reason.DLP_BLOCK.value:
                entry.type = ResponseType.TCPCLOSE.value
        user_response.update(user_response_entry=list_of_user_entry)
        is_response_tcp_close = False
        for entry in list_of_user_entry:
            if entry.reason == Reason.DLP_BLOCK.value and entry.type == ResponseType.TCPCLOSE.value:
                is_response_tcp_close = True
                break
        assert is_response_tcp_close, UPDATE_USER_RESPONSE_ERROR
        logging.info("Updated UserResponse Successfully.")

        # CustomPropertiesProfile

        CUSTOM_PROPERTY = [
            {
                "data_type": "string",
                "name": "attribute1",
                "value": "value1"
            }
        ]
        # create CustomPropertiesProfile
        custom_properties_profile = CustomPropertiesProfile.create(name=CUSTOM_PROPERTY_NAME,
                                                                   custom_property=CUSTOM_PROPERTY)
        custom_script = custom_properties_profile.custom_script
        custom_script._import(
            custom_script_file_name="profiles.py")
        # export custom script
        custom_script.export(CUSTOM_SCRIPT_FILE)
        # delete custom script
        custom_script.delete()
        assert 'attribute1' in [property['name'] for property in
                                custom_properties_profile.custom_property] and os.path.exists(
            CUSTOM_SCRIPT_FILE) and os.stat(
            CUSTOM_SCRIPT_FILE).st_size > 0, CUSTOM_PROPERTIES_CREATE_ERROR
        logging.info("CustomPropertiesProfile created Successfully.")
        CUSTOM_PROPERTY.append({
            "data_type": "string",
            "name": "attribute2",
            "value": "value"
        })
        custom_properties_profile = CustomPropertiesProfile(CUSTOM_PROPERTY_NAME)

        custom_properties_profile.update(custom_property=CUSTOM_PROPERTY)
        custom_properties_profile = CustomPropertiesProfile(CUSTOM_PROPERTY_NAME)
        assert 'attribute2' in [custom_property['name'] for custom_property in
                                custom_properties_profile.custom_property], \
            CUSTOM_PROPERTIES_UPDATE_ERROR
        logging.info("CustomPropertiesProfile updated Successfully.")

    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        UserResponse(USER_RESPONSE_NAME).delete()
        logging.info("Deleted UserResponse Successfully.")
        CustomPropertiesProfile(CUSTOM_PROPERTY_NAME).delete()
        logging.info("CustomPropertiesProfile deleted Successfully.")
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to use profiles like User Response',
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
