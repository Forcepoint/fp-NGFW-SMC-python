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
Example script to show how to use Multilink Element
"""

# Python Base Import
import argparse
import logging
import sys

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.elements.netlink import StaticNetlink, MultilinkMember, Multilink  # noqa
from smc.elements.network import Network, Router  # noqa
from smc.vpn.elements import ConnectionType  # noqa

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

        # create multi link
        # get first connection type
        connection_type = list(ConnectionType.objects.all())[0]
        network1 = Network("net-10.1.16.0/24")
        network2 = Network("net-172.31.16.0/24")
        router1 = Router("Etisalat Dubai Router")
        router2 = Router("Du Dubai Router")
        snl1 = StaticNetlink.create(name="SNL_Premier-ISP",
                                    provider_name="ISP1",
                                    output_speed=40000,
                                    input_speed=40000,
                                    probe_address=["10.1.16.1"],
                                    network=[network1],
                                    gateway=router1,
                                    connection_type=connection_type,
                                    )
        snl2 = StaticNetlink.create(name="SNL_Second-ISP",
                                    provider_name="ISP2",
                                    output_speed=50000,
                                    input_speed=50000,
                                    probe_address=["172.31.16.1"],
                                    network=[network2],
                                    gateway=router2,
                                    connection_type=connection_type,
                                    )

        logging.info(f'SNL1\n{snl1.data.data}')
        logging.info(f'SNL2\n{snl2.data.data}')

        logging.info(f'SNL1.network\n{snl1.network}')
        logging.info(f'SNL2.network\n{snl2.network}')
        l_ml_member = list()
        l_ml_member.append(MultilinkMember.create(netlink=snl1, netlink_role='active',
                                                  ip_range='10.1.16.1-10.1.16.254'))
        l_ml_member.append(MultilinkMember.create(netlink=snl2, netlink_role='standby',
                                                  ip_range='172.31.16.1-172.31.16.254'))

        oml = Multilink.create(name="OML_TEST",
                               multilink_members=l_ml_member)
        logging.info(f'oml={str(oml)} members={oml.members}')

        logging.info("delete elements..")
        oml = Multilink.get(name="OML_TEST")
        oml.delete()
    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        snl1 = StaticNetlink.get(name="SNL_Premier-ISP")
        snl1.delete()
        snl2 = StaticNetlink.get(name="SNL_Second-ISP")
        snl2.delete()
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to use Multilink Element',
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
