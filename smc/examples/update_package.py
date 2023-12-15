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
Example script to show how to use UpdatePackage object.
-get all update package
-import update package
-activate imported update package
"""

# Python Base Import
import argparse
import logging
import sys
import time

# Python SMC Import
sys.path.append('../../')  # smc-python
from os.path import exists  # noqa
from smc import session  # noqa
from smc.administration.system import System  # noqa
from smc.api.exceptions import ActionCommandFailed  # noqa
from smc.base.model import LoadElement  # noqa

FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
UPDATE_PACKAGE_FILE = "/tmp/sgpkg-ips-2711t-5242.jar"
NOT_IMPORTED_ERR = "Update package is not correctly imported!"
NOT_ACTIVATED_ERR = "Update package is not correctly activated!"

logging.getLogger()
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - '
                                                '%(name)s - [%(levelname)s] : %(message)s')


def refresh_update_package(update_package_to_refresh, state):
    nb_iter = 0
    while nb_iter < 5 and update_package_to_refresh.state.lower() != state:
        logging.info('state {}'.format(update_package_to_refresh.state))
        time.sleep(5)
        update_package_to_refresh.data = LoadElement(update_package_to_refresh.href)
        nb_iter += 1


def main():
    return_code = 0
    try:
        arguments = parse_command_line_arguments()
        session.login(url=arguments.api_url, api_key=arguments.api_key,
                      login=arguments.smc_user,
                      pwd=arguments.smc_pwd, api_version=arguments.api_version)
        logging.info("session OK")

        system = System()

        next_update = None

        logging.info("retrieve all update packages in desc order")
        for update in system.update_package():
            logging.info(update)
            if update.state.lower() == "available":
                next_update = update

        # download and import next available update package received
        if next_update is not None:
            logging.info(f"download update package {next_update}..")
            poller = next_update.download(wait_for_finish=True)
            while not poller.done():
                poller.wait(5)
                logging.info(f'Percentage complete {poller.task.progress}')

            # refresh next_update after download ( needed to refresh "state" attribute)
            refresh_update_package(next_update, "imported")
            assert next_update.state.lower() == "imported", NOT_IMPORTED_ERR

            logging.info(f"activate update package:{next_update}")
            poller = next_update.activate(wait_for_finish=True)
            while not poller.done():
                poller.wait(10)
                logging.info(f'Percentage complete {poller.task.progress}')

            # refresh next_update after activation ( needed to refresh "state" attribute)
            refresh_update_package(next_update, "active")
            assert next_update.state.lower() == "active", NOT_ACTIVATED_ERR

        else:
            logging.info("The latest update package is already installed")

        # this part is not run in robot tests
        logging.info("Import update package from file")
        if exists(UPDATE_PACKAGE_FILE):
            imported_packages = system.update_package_import(UPDATE_PACKAGE_FILE)
            for update_package in imported_packages:
                logging.info(f"imported update package update package:{update_package}")

    except ActionCommandFailed as exception:
        logging.error("Task failed: " + str(exception))
        exit(-1)
    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1

    finally:
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to use UpdatePackage object',
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
