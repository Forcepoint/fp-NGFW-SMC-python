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
Example script to show system properties usage.
"""
import argparse
import logging
import sys

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.administration.system import System  # noqa

new_ebanner_text_value = 'Welcome in SMC!'
ebanner_text_system_key = 55
ebanner_text_name = 'export_banner_text'
get_ebanner_error_msg = '{} system_key does not point to {} global system property but on {}.'
update_ebanner_error_msg = '{} system property has not been set correctly: {}. It should have {}.'

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

        system = System()

        for system_property in system.system_properties():
            logging.info(f"system_property= {system_property}")

        logging.info(f"Retrieve {ebanner_text_name} system property "
                     f"from its system_key ({ebanner_text_system_key})...")
        ebanner_text_property = system.system_property(system_key=ebanner_text_system_key)
        assert ebanner_text_property.name == ebanner_text_name,\
            get_ebanner_error_msg.format(ebanner_text_system_key,
                                         ebanner_text_name, ebanner_text_property.name)

        logging.info(f"Update {ebanner_text_name} system property...")
        system.update_system_property(system_key=ebanner_text_system_key,
                                      new_value=new_ebanner_text_value)

        logging.info(f"Check the update {ebanner_text_name} system property...")
        ebanner_text_property = system.system_property(system_key=ebanner_text_system_key)

        assert ebanner_text_property.value == new_ebanner_text_value, \
            update_ebanner_error_msg.format(ebanner_text_name,
                                            ebanner_text_property.value, new_ebanner_text_value)

    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show system properties usage',
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
