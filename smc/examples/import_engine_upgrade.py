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
Example script to show how to use EngineUpgrade object.
-get all upgrade package
-import engine upgrade
    Example : python import_engine_upgrade.py /tmp/engine_remote_upgrade.zip
    where:
        /tmp/engine_remote_upgrade.zip : The complete path to the engine upgrade file
         to be imported
"""

# Python Base Import
import argparse
import logging
import sys
import re

# Python SMC Import
from os.path import exists
sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.administration.system import System  # noqa
from smc.api.exceptions import ActionCommandFailed  # noqa


FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
NOT_IMPORTED_ERR = "The upgrade package is not imported!."
ALREADY_IMPORTED_ERR = "The upgrade package has already been imported and downloaded. " \
                       "First delete the upgrade and then try again."
FORCE_IMPORT_FLAG = True

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
        if len(sys.argv) >= 2:
            IMPORT_UPGRADE_FILE = sys.argv[1]
            UPGRADE_VERSION = re.search(r'\d+.\d+.\d+',
                                        IMPORT_UPGRADE_FILE).group(0)
        else:
            logging.error("Engine upgrade zip file path is missing "
                          "from command line.")
            return_code = 1
        system = System()
        logging.info("retrieve all engine upgrade in desc order")
        upgrades = system.engine_upgrade()
        upgrade = upgrades.get_contains(UPGRADE_VERSION)
        logging.info(f"Engine upgrade version {UPGRADE_VERSION} is available ")
        logging.info(f"Import Engine Upgrade from a file : {IMPORT_UPGRADE_FILE}")
        # To test this condition we need import available in local directory
        if exists(IMPORT_UPGRADE_FILE):
            imported_packages = system.engine_upgrade_import(IMPORT_UPGRADE_FILE, FORCE_IMPORT_FLAG)
            upgrades = system.engine_upgrade()
            upgrade = upgrades.get_contains(UPGRADE_VERSION)
            assert ".zip" in upgrade.name, NOT_IMPORTED_ERR

    except ActionCommandFailed as exception:
        logging.error(f"Task failed: {str(exception)}")
        return_code = 1
    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1

    finally:
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to use EngineUpgrade object',
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
