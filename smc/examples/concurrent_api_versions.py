#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Test concurrent creation of Host in parallel using all API versions.
"""
import argparse
import logging
import threading
import sys
import time
import smc.examples

from smc import manager, session_name
from smc.api.session import available_api_versions, Session
from smc.elements.network import Host
from smc_info import SMC_URL, API_KEY

sys.path.append('../')

error = []


def create_host_with_login_logout(api_version):
    try:
        # session name will be stored by thread local in session_name.name
        session_lt = Session(manager)
        session_lt.login(url=SMC_URL,
                         api_key=API_KEY,
                         verify=False,
                         timeout=120,
                         api_version=api_version)
        logging.info("Create host with session_name {} API version {}"
                     .format(session_name.name, api_version))
        host = Host.create(name="Host_{}".format(api_version),
                           address="10.1.1.1")
        time.sleep(2)
        host.delete()

        session_lt.logout()
        logging.info("Test done with API version {}".format(api_version))
    except Exception as exc:
        error.append("An error happened with API version {} || {}"
                     .format(api_version, exc))


def test_multi_sessions_same_thread(versions):
    logging.info("Login/logout serialized tests:")
    api_version1 = versions[0]
    api_version2 = versions[1]

    # create 2 distinct user sessions
    session1 = Session(manager)
    session_name1 = session1.login(url=SMC_URL,
                                   api_key=API_KEY,
                                   verify=False,
                                   timeout=120,
                                   api_version=api_version1)
    print("session1 OK:{}".format(session1.name))
    session2 = Session(manager)
    # test second api version
    session_name2 = session2.login(url=SMC_URL,
                                   api_key=API_KEY,
                                   verify=False,
                                   timeout=120,
                                   api_version=api_version2)
    print("session2 OK:{}".format(session2.name))

    # use session 1
    session_name.name = session_name1
    logging.info("session 1 Create host with API version {}".format(api_version1))
    host1 = Host.create(name="Host_{}".format(api_version1),
                        address="10.1.1.1")
    logging.info("session 1 GET host with API version {}".format(api_version1))
    host1_addr = Host(name="Host_{}".format(api_version1)).data.address

    # use session 2
    session_name.name = session_name2
    logging.info("session 2 Create host with API version {}".format(api_version2))
    host2 = Host.create(name="Host_{}".format(api_version2),
                        address="10.1.1.2")
    logging.info("session 2 GET host with API version {}".format(api_version2))
    host2_addr = Host(name="Host_{}".format(api_version2)).data.address
    time.sleep(2)

    logging.info("session 1 Delete host with API version {}".format(api_version1))
    session_name.name = session_name1
    host1.delete()
    logging.info("session 2 Delete host with API version {}".format(api_version2))
    session_name.name = session_name2
    host2.delete()

    # logout session 1 and session 2
    logging.info("session 1 Logout with API version {}".format(api_version1))
    session1.logout()
    logging.info("session 2 Logout with API version {}".format(api_version2))
    session2.logout()


def main():
    """
    Main function of the program. Parse command line arguments
    and perform requested action.
    """
    parse_command_line_arguments()
    versions = available_api_versions(SMC_URL)

    # test parallelized login/logout
    logging.info("Login/logout parallelized tests:")
    thread_current = threading.Thread(name="API_Current",
                                      target=create_host_with_login_logout,
                                      args={versions[0]})
    thread_legacy = threading.Thread(name="API_Legacy",
                                     target=create_host_with_login_logout,
                                     args={versions[1]})
    thread_lts = threading.Thread(name="API_LTS",
                                  target=create_host_with_login_logout,
                                  args={versions[2]})
    thread_current.start()
    thread_legacy.start()
    thread_lts.start()

    thread_current.join()
    thread_legacy.join()
    thread_lts.join()

    logging.info("Run create/delete host in // in all SMC API versions done")

    # test serialized login/logout
    try:
        test_multi_sessions_same_thread(versions=versions)
    except BaseException as e:
        error.append(e)

    if len(error) >= 1:
        for err in error:
            logging.error(err)
        return 1
    else:
        return 0


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='TEST DESCRIPTION',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        add_help=False)
    parser.add_argument(
        '-h', '--help',
        action='store_true',
        help='show this help message and exit')

    arguments = parser.parse_args()

    if arguments.help:
        parser.print_help()
        sys.exit(1)

    return arguments


if __name__ == '__main__':
    sys.exit(main())
