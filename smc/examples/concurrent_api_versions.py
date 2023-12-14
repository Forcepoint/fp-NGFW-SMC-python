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
Test concurrent creation of Host in parallel using all API versions.
"""
import argparse
import logging
import threading
import sys
import time

sys.path.append('../../')  # smc-python
from smc import manager, session_name  # noqa
from smc.api.session import available_api_versions, Session  # noqa
from smc.elements.network import Host  # noqa

error = []

logging.getLogger()
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - '
                                                '%(name)s - [%(levelname)s] : %(message)s')


def create_host_with_login_logout(api_version, arguments):
    try:
        # session name will be stored by thread local in session_name.name
        session_lt = Session(manager)
        session_lt.login(url=arguments.api_url, api_key=arguments.api_key, api_version=api_version)
        logging.info(f"Create host with session_name {session_name.name} API version {api_version}")

        host = Host.create(name=f"Host_{api_version}", address="10.1.1.1")
        time.sleep(2)
        host.delete()

        session_lt.logout()
        logging.info(f"Test done with API version {api_version}")
    except Exception as exc:
        error.append(f"An error happened with API version {api_version} || {exc}")


def test_multi_sessions_same_thread(versions, arguments):
    logging.info("Login/logout serialized tests:")
    api_version1 = versions[0]
    api_version2 = versions[1]

    # create 2 distinct user sessions
    session1 = Session(manager)
    session_name1 = session1.login(url=arguments.api_url, api_key=arguments.api_key,
                                   login=arguments.smc_user, pwd=arguments.smc_pwd,
                                   api_version=api_version1)
    logging.info(f"session1 OK:{session1.name}")
    session2 = Session(manager)
    # test second api version
    session_name2 = session2.login(url=arguments.api_url, api_key=arguments.api_key,
                                   login=arguments.smc_user, pwd=arguments.smc_pwd,
                                   api_version=api_version2)
    logging.info(f"session2 OK:{session2.name}")

    # use session 1
    session_name.name = session_name1
    logging.info(f"session 1 Create host with API version {api_version1}")
    host1 = Host.create(name=f"Host_{api_version1}", address="10.1.1.1")
    logging.info(f"session 1 GET host with API version {api_version1}")
    host1_addr = Host(name=f"Host_{api_version1}").data.address
    logging.info(f"session 1 host address: {host1_addr}")

    # use session 2
    session_name.name = session_name2
    logging.info(f"session 2 Create host with API version {api_version2}")
    host2 = Host.create(name=f"Host_{api_version2}", address="10.1.1.2")
    logging.info(f"session 2 GET host with API version {api_version2}")
    host2_addr = Host(name=f"Host_{api_version2}").data.address
    logging.info(f"session 2 host address: {host2_addr}")
    time.sleep(2)

    logging.info(f"session 1 Delete host with API version {api_version1}")
    session_name.name = session_name1
    host1.delete()
    logging.info(f"session 2 Delete host with API version {api_version2}")
    session_name.name = session_name2
    host2.delete()

    # logout session 1 and session 2
    logging.info(f"session 1 Logout with API version {api_version1}")
    session1.logout()
    logging.info(f"session 2 Logout with API version {api_version2}")
    session2.logout()


def main():
    """
    Main function of the program. Parse command line arguments
    and perform requested action.
    """
    arguments = parse_command_line_arguments()
    versions = available_api_versions(arguments.api_url)

    # test parallelized login/logout
    logging.info("Login/logout parallelized tests:")
    thread_current = threading.Thread(name="API_Current",
                                      target=create_host_with_login_logout,
                                      args=(versions[0], arguments))
    thread_legacy = threading.Thread(name="API_Legacy",
                                     target=create_host_with_login_logout,
                                     args=(versions[1], arguments))
    thread_lts = threading.Thread(name="API_LTS",
                                  target=create_host_with_login_logout,
                                  args=(versions[2], arguments))
    thread_current.start()
    thread_legacy.start()
    thread_lts.start()

    thread_current.join()
    thread_legacy.join()
    thread_lts.join()

    logging.info("Run create/delete host in // in all SMC API versions done")

    # test serialized login/logout
    try:
        test_multi_sessions_same_thread(versions=versions, arguments=arguments)
    except BaseException as e:
        error.append(e)

    if len(error) >= 1:
        for err in error:
            logging.error(err)
        return_code = 1
    else:
        return_code = 0
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Test concurrent creation of Host in parallel using all API versions',
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
