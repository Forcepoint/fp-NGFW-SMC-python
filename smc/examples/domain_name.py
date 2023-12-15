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
Example script to show how to use DomainName.
"""
import argparse
import logging
import sys

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.compat import is_smc_version_less_than_or_equal  # noqa
from smc.elements.network import DomainName  # noqa

NOT_CREATED_MSG = "Fail to create domain name."
NOT_UPDATE_ERROR = "Fail to update an domain name."
DOMAIN_NAME = 'test_domain_name'
COMMENT = "This is testing of DomainName."

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
        if is_smc_version_less_than_or_equal("6.10"):
            domain_name = DomainName.create(DOMAIN_NAME,
                                            comment=COMMENT)
            logging.info("Successfully created DomainName")
        else:
            domain_name = DomainName.create(DOMAIN_NAME, domain_name_entry=["test1", "test2"],
                                            comment=COMMENT)
            assert "test1" in domain_name.domain_name_entry, NOT_CREATED_MSG
            logging.info("Successfully created DomainName")
            domain_name.update(domain_name_entry=["test1", "test2", "test3"])
            domain_name = DomainName(DOMAIN_NAME)
            assert "test3" in domain_name.domain_name_entry, NOT_UPDATE_ERROR
            logging.info("Successfully updated DomainName")
    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        DomainName(DOMAIN_NAME).delete()
        logging.info("Successfully deleted DomainName")
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to use DomainName',
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
