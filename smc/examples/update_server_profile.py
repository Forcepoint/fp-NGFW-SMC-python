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
Example script to show how to use UpdateServerProfile
"""
import argparse
import logging
import sys

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.administration.certificates.tls import TLSProfile  # noqa
from smc.elements.other import UpdateServerProfile  # noqa

name = "test_update_server_profile"
message = "Testing of update server profile."
creation_error = "Failed to create update server profile with attribute."
update_error = "Failed to update server profile with retry attribute."
RETRY = 4
TIMEOUT = 30
URL = "https://autoupdate.ngfw.forcepoint.com/dynup.rss"

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

        logging.info("Check and delete if UpdateServerProfile is present.")
        if UpdateServerProfile.objects.filter(name=name, exact_match=True):
            UpdateServerProfile(name).delete()
            logging.info("Successfully deleted UpdateServerProfile.")
        tls_profile = list(TLSProfile.objects.all())[0]
        # create update server profile
        update_server_profile = UpdateServerProfile.create(name, retry=RETRY, timeout=TIMEOUT,
                                                           urls=[URL], tls_profile_ref=tls_profile,
                                                           comment=message)
        assert update_server_profile.retry == RETRY and update_server_profile.timeout == TIMEOUT, \
            creation_error
        logging.info("Successfully created UpdateServerProfile.")
        update_server_profile.update(retry=RETRY + 1)
        assert update_server_profile.retry == RETRY + 1, update_error
        logging.info("Successfully updated UpdateServerProfile.")
    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        UpdateServerProfile(name).delete()
        logging.info("Deleted UpdateServerProfile successfully.")
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to use UpdateServerProfile',
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
