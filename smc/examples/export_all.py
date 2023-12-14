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
Example script to export all elements.
-follow the result and check result is valid zip file
-use exclude_trashed option
-import inconsistent import file. check exception
"""

# Python Base Import
import argparse
import sys
import logging
import zipfile

# Python SMC Import
sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.administration.system import System  # noqa
from smc.api.exceptions import ActionCommandFailed  # noqa
from smc.core.engines import Layer2Firewall  # noqa

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

        # try export all
        system = System()
        export_zip = "/tmp/export_test.zip"

        # check trashed host is in export (default case)
        # using the SMC Client need first to create a testHostTrashed Host and trash it
        system.export_elements(export_zip, timeout=5, max_tries=50)
        the_zip_file = zipfile.ZipFile(export_zip)
        data_xml = the_zip_file.open('exported_data.xml').read()
        assert data_xml.find('testHostTrashed'.encode()) > -1,\
            "Host testHostTrashed not found in export"

        # use exclude_trashed=true parameter and check trashed host NOT in export
        system.export_elements(export_zip, timeout=5, max_tries=50, exclude_trashed=True)
        the_zip_file = zipfile.ZipFile(export_zip)
        data_xml = the_zip_file.open('exported_data.xml').read()
        assert data_xml.find('testHostTrashed'.encode()) == -1, \
            "Host testHostTrashed found in export"

        valid_zip = the_zip_file.testzip()

        # check export all is valid
        if valid_zip is not None:
            logging.warning("Invalid zip file")
        else:
            logging.info("Zip file is valid")

        logging.info("Export firewall")
        # try export firewall
        l2FW = Layer2Firewall("Atlanta L2 FW")
        for interface in l2FW.interface:
            logging.info("interface=" + str(interface))
        l2FW.export("/tmp/Atlantal2FW.zip")

        # try import corrupted file
        logging.info("Import Corrupted file")
        try:
            system.import_elements("/tmp/WRONG_Atlantal2FW.zip")
        except ActionCommandFailed as exception:
            logging.warning("Import result: " + str(exception))

    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to export all elements',
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
