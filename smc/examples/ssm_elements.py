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
Example to show how to use create and delete SSM element objects in the SMC
"""
import argparse
import logging
import sys
sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.core.engines import Layer3Firewall  # noqa
from smc.elements.ssm import *  # noqa

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

        # Create SSH Profile with multiple algorithms
        profile = SSHProfile.create(name="testSSHProfile",
                                    cipher="aes256-ctr,aes128-ctr,aes192-ctr,"
                                           "aes128-gcm@openssh.com,aes192-cbc",
                                    kex="diffie-hellman-group-exchange-sha1,"
                                        "diffie-hellman-group14-sha1",
                                    mac="hmac-sha2-256,hmac-sha2-512,hmac-sha1-etm@openssh.com",
                                    comment="This is an example of creating an SSH Profile.")

        # Create SSH Known Host with IPv4 and IPv6 with ssh-ed25519 host key
        known_host = SSHKnownHosts.create(name="testKnownHost",
                                          host_key="ssh-ed25519 "
                                                   "AAAAC3NzaC1lZDI1NTE5AAAAIIhOmoNeLtMHh"
                                          "r2DlE2uXAqfiJi66TM9DTjvgGEy3ojv",
                                          sshkey_type="ssh-ed25519",
                                          ipaddress="1.2.3.4",
                                          ipv6_address="2607:a600:124:0203::4",
                                          port=22000,
                                          comment="This is an example of creating an SSH Known "
                                                  "Host.")

        # Create SSH Known Host List and add SSH Known Host to it
        known_host_list = SSHKnownHostsLists.create(name="testKnownHostList",
                                                    known_host=[known_host.href],
                                                    comment="This is an example of creating an SSH "
                                                            "Known Host List.")

        # Create empty SSH Known Host List
        empty_known_host_list = SSHKnownHostsLists.create(name="emptyKnownHostList")

        # create Layer3 FW with SSM enabled with Known Host Lists
        Layer3Firewall.create(name="testFw",
                              mgmt_ip="192.168.10.1",
                              mgmt_network="192.168.10.0/24",
                              sidewinder_proxy_enabled=True,
                              known_host_lists=[known_host_list.href, empty_known_host_list.href])

    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        # Delete SSH Profile and firewall
        SSHProfile("testSSHProfile").delete()
        Layer3Firewall("testFw").delete()

        # Delete Known Host Lists and Known Host
        SSHKnownHostsLists("testKnownHostList").delete()
        SSHKnownHostsLists("emptyKnownHostList").delete()
        SSHKnownHosts("testKnownHost").delete()

        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to use create and delete SSM element objects in '
                    'the SMC',
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
