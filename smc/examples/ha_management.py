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
Example script to show how to use HA Management
-get HA Informations
-get HA Diagnostic
-set active or set standby
-full replication
-exclude
"""

# Python Base Import
import argparse
import logging
import sys
import time
sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.api.exceptions import HaCommandException  # noqa
from smc.core.ha_management import HAManagement  # noqa
from smc.elements.servers import ManagementServer  # noqa

DIAGNOSTIC_ERRORS = ["(Isolated)", "Login status: KO"]
DIAGNOSTIC_TITLE_OK = "No issues were detected while running the diagnostic."

logging.getLogger()
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - '
                                                '%(name)s - [%(levelname)s] : %(message)s')


def check_diag_issue(check_for=None):
    to_return = False
    diag = HAManagement().diagnostic()
    logging.info("diagnostic messages:")
    for infob in diag.message:
        logging.info(f"title:{infob.title}")
        for msg in infob.message:
            logging.info(f"msg:{msg}")
            if check_for is not None:
                for message in check_for:
                    if message in msg:
                        logging.info(f"=>>> Issue detected =>>> {msg}")
                        to_return = True

    logging.info("diagnostic errors and warnings:")
    infob = diag.errors_warnings
    logging.info(f"title:{infob.title}")
    if DIAGNOSTIC_TITLE_OK not in infob.title:
        logging.info(f"=>>> Issue detected =>>> {infob.title}")
        to_return = True
    for msg in infob.message:
        logging.info(f"msg:{msg}")
        if check_for is not None:
            for message in check_for:
                if message in msg:
                    logging.info(f"=>>> Issue detected =>>> {msg}")
                    to_return = True

    return to_return


def main():
    # URLSMC = "https://ec2-3-70-111-86.eu-central-1.compute.amazonaws.com:8082"
    # APIKEYSMC = "5s8ZwKHZFFas6NxPqQsec7Yp"
    # URLSMC = "http://localhost:8082"
    # APIKEYSMC = "HuphG4Uwg4dN6TyvorTR0001"

    return_code = 0
    try:
        arguments = parse_command_line_arguments()
        session.login(url=arguments.api_url, api_key=arguments.api_key,
                      login=arguments.smc_user,
                      pwd=arguments.smc_pwd, api_version=arguments.api_version)
        logging.info("session OK")

        ha = HAManagement()

        # get HA infos
        info = ha.get_ha()
        logging.info(info)

        # display HA diagnostic
        diag_status = check_diag_issue(DIAGNOSTIC_ERRORS)
        assert not diag_status, "Issue in HA detected!"

        # check there is an active server
        assert info.active_server is not None, "No active server !"

        # try to set active the already active server.. receive an http error 400
        try:
            result = ha.set_active(info.active_server)
        except HaCommandException as ex:
            assert ex.response.status_code == 400, \
                "Don't receive error when activating active server"

        # swap active server with first standby server
        stb_servers = info.standby_servers
        if stb_servers is not None:
            result = ha.set_active(stb_servers[0])
            logging.info(f"set active {stb_servers[0]}=>{result}")

        # wait for server to be active
        time.sleep(10)

        # refresh HA infos
        info = ha.get_ha()
        logging.info(info)

        # check there is an active server
        assert info.active_server is not None, "No active server !"

        # In case of emergency set standby on active server
        active_server = info.active_server
        result = ha.set_standby(active_server)
        logging.info(f"set standby {active_server}=>{result}")

        # wait for server to be stand by
        time.sleep(10)

        # refresh info
        info = ha.get_ha()
        first_standby_server = info.standby_servers[0]

        # check there is no active server
        assert info.active_server is None, "Still an active server !"

        # At this time there is no active server
        # retry activate "Management Server"
        code = 400
        mgt_server = ManagementServer("Management Server")
        retry = 0
        while code == 400 and retry < 20:
            try:
                result = ha.set_active(mgt_server)
                code = result.status_code
            except HaCommandException as ex:
                logging.info(f"Exception in HA_Management, msg : {ex.smcresult.msg}")
                code = ex.code
            logging.info(f"try activate {mgt_server}=>{result}")
            retry += 1
            time.sleep(10)

        # wait for server to be active
        retry = 0
        while info.active_server is None and retry < 20:
            logging.info(f"wait for server {mgt_server} to be active")
            time.sleep(10)
            retry += 1
            info = ha.get_ha()

        # refresh info
        info = ha.get_ha()
        first_standby_server = info.standby_servers[0]

        # perform full replication for first standby server
        result = ha.full_replication(first_standby_server)
        logging.info(f"full replication {first_standby_server}=>{result}")

        # display HA diagnostic and check if server is OK
        retry = 0
        while check_diag_issue(["(Isolated)", "Login status: KO"]) and retry < 20:
            logging.info("full replication still in progress..")
            time.sleep(10)
            retry += 1

        # exclude from replication first standby server
        result = ha.exclude(first_standby_server)
        logging.info(f"exclude {first_standby_server}=>{result}")

        # display HA diagnostic
        # At this time we should have an excluded replication issue
        diag_status = check_diag_issue(DIAGNOSTIC_ERRORS)
        assert diag_status, "Stand by server should be excluded !"

    except HaCommandException as ex:
        logging.error(f"Exception in HA_Management, msg : {ex.smcresult.msg}")
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
        description='Example script to show how to use HA Management',
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
