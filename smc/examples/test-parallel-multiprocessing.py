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
Example script to show how to use smc python in multiprocessing environment
-create hosts in parallel
-delete them
"""

# Python Base Import
import argparse
import logging
import sys
import urllib3
from multiprocessing import Process

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.elements.network import Host  # noqa
from smc import set_stream_logger  # noqa


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to use multiprocessing',
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


logging.getLogger()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - '
                                               '%(name)s - [%(levelname)s] : %(message)s')
arguments = parse_command_line_arguments()


def create_host(hostname: str, address: str) -> (Host, bool):
    session.login(url=arguments.api_url, api_key=arguments.api_key,
                  login=arguments.smc_user,
                  pwd=arguments.smc_pwd, api_version=arguments.api_version)
    logging.info("session OK")
    logging.info(f"Creating host {hostname}")
    host, created = Host.get_or_create(
        filter_key={
            "name": hostname,
        },
        name=hostname,
        address=address,
        with_status=True,
    )

    logging.info("logout to SMC")
    session.logout()

    if created:
        logging.info(f"HOST {hostname} CREATED")
    return host, created


def delete_host(hostname: str):
    session.login(url=arguments.api_url, api_key=arguments.api_key,
                  login=arguments.smc_user,
                  pwd=arguments.smc_pwd, api_version=arguments.api_version)
    logging.info("session OK")
    logging.info(f"Deleting host {hostname}")
    host = Host.get(name=hostname)
    host.delete()
    logging.info("logout to SMC")
    session.logout()
    logging.info(f"HOST {hostname} DELETED")
    return


def main():
    return_code = 0
    try:
        urllib3.disable_warnings()
        set_stream_logger(log_level=logging.INFO, format_string=None)
        procs = []

        logging.info("CREATE HOSTS")
        for one in range(2):
            proc = Process(target=create_host, args=(f"HOST_TEST_EMN_{one}", f"1.1.1.{one%254}"))
            procs.append(proc)
            proc.start()

        # complete the processes
        for proc in procs:
            proc.join()
        procs = []

        logging.info("DELETE HOSTS")
        for one in range(2):
            proc = Process(target=delete_host, args=(f"HOST_TEST_EMN_{one}",))
            procs.append(proc)
            proc.start()

        # complete the processes
        for proc in procs:
            proc.join()
    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        logging.info("Finally: processes terminated !")
    return return_code


if __name__ == '__main__':
    sys.exit(main())
