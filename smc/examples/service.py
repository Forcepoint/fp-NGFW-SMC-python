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
Example script to show how to use Ethernet, RPC, ICMP and ICMPIPv6 services.
"""
import argparse
import logging
import sys

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.elements.group import EthernetServiceGroup, RpcServiceGroup  # noqa
from smc.elements.protocols import ProtocolAgent  # noqa
from smc.elements.service import EthernetService, RPCService, ICMPService, ICMPIPv6Service  # noqa

ETHERNET_SERVICE_CREATE_ERROR = "Fail to create an EthernetService."
ETHERNET_SERVICE_UPDATE_ERROR = "Fail to update an EthernetService."
ETHERNET_SERVICE_NAME = 'test_ethernet_service'
COMMENT1 = "This is testing of EthernetService."
ETHERNET_SERVICE_GROUP_CREATE_ERROR = "Fail to create an EthernetServiceGroup."
ETHERNET_SERVICE_GROUP_UPDATE_ERROR = "Fail to update an EthernetServiceGroup."
ETHERNET_SERVICE_GROUP_NAME = 'test_ethernet_service_group'
COMMENT2 = "This is testing of EthernetServiceGroup."

# RPCService
RPC_SERVICE_NAME = "test_rpc_service"
RPC_SERVICE_COMMENT = "This is to test rpc service."
CREATE_RPC_ERROR = "Fail to create RPCService."
UPDATE_RPC_ERROR = "Fail to update RPCService."
RPC_GROUP_NAME = "test_rpc_service_group"
RPC_GROUP_MSG = "This is to test rpc service group."
CREATE_RPC_GROUP_ERROR = "Fail to create RpcServiceGroup."
UPDATE_RPC_GROUP_ERROR = "Fail to update RpcServiceGroup."

# ICMPService
ICMP_SERVICE_NAME = "test_icmp_service"
ICMP_SERVICE_CREATE_ERROR = "Fail to create an ICMPService."
ICMP_SERVICE_UPDATE_ERROR = "Fail to update an ICMPService."
ICMP_SERVICE_COMMENT = "This is testing of icmp service comment."

# ICMPIPv6Service
ICMPIPV6_SERVICE_NAME = "test_icmpipv6_service"
ICMPIPV6_SERVICE_CREATE_ERROR = "Fail to create an ICMPIPv6Service."
ICMPIPV6_SERVICE_UPDATE_ERROR = "Fail to update an ICMPIPv6Service."
ICMPIPV6_SERVICE_COMMENT = "This is testing of icmpipv6 service comment."

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
        protocol = list(ProtocolAgent.objects.all())[0]
        ethernet_service = EthernetService.create(ETHERNET_SERVICE_NAME, frame_type="eth2",
                                                  protocol_agent_ref=protocol, value1='1',
                                                  value2='2', comment=COMMENT1)
        assert ethernet_service.value1 == '0x1' and ethernet_service.value2 == '0x2' and \
               ethernet_service.protocol_agent_ref.href == \
               protocol.href, ETHERNET_SERVICE_CREATE_ERROR
        logging.info("Successfully created EthernetService.")
        ethernet_service.update(value1=int('3', 16), value2=int('4', 16))
        ethernet_service = EthernetService(ETHERNET_SERVICE_NAME)
        assert ethernet_service.value1 == '0x3' and ethernet_service.value2 == \
               '0x4', ETHERNET_SERVICE_UPDATE_ERROR
        logging.info("Successfully updated EthernetService.")
        ethernet_service_group = EthernetServiceGroup.create(ETHERNET_SERVICE_GROUP_NAME,
                                                             members=[ethernet_service],
                                                             comment=COMMENT2)
        assert ethernet_service_group.members[
                   0] == ethernet_service.href, ETHERNET_SERVICE_GROUP_CREATE_ERROR
        logging.info("Successfully created EthernetServiceGroup.")
        ethernet_service_group.empty_members()
        ethernet_service_group = EthernetServiceGroup(ETHERNET_SERVICE_GROUP_NAME)
        assert not ethernet_service_group.members, ETHERNET_SERVICE_GROUP_UPDATE_ERROR
        logging.info("Successfully updated EthernetServiceGroup.")

        # Rpc Service
        rpc_service = RPCService.create(RPC_SERVICE_NAME, program_number=1000, transport="both",
                                        comment=RPC_SERVICE_COMMENT)
        assert rpc_service.transport == "both" and \
               rpc_service.program_number == "1000", CREATE_RPC_ERROR
        rpc_service.update(transport="udp", program_number=1001)
        rpc_service = RPCService(RPC_SERVICE_NAME)
        assert rpc_service.transport == "udp" and \
               rpc_service.program_number == "1001", UPDATE_RPC_ERROR
        rpc_service_group = RpcServiceGroup.create(RPC_GROUP_NAME, members=[rpc_service],
                                                   comment=RPC_GROUP_MSG)
        assert rpc_service_group.members[0] == rpc_service.href, CREATE_RPC_GROUP_ERROR
        first_service = list(RPCService.objects.all())[0]
        rpc_service_group.update_members([first_service], append_lists=True)
        rpc_service_group = RpcServiceGroup(RPC_GROUP_NAME)
        assert len(rpc_service_group.members) == 2, UPDATE_RPC_GROUP_ERROR

        # ICMPService
        icmp_service = ICMPService.create(name=ICMP_SERVICE_NAME, icmp_type=3, icmp_code=7,
                                          comment=ICMP_SERVICE_COMMENT)
        assert icmp_service.icmp_type == 3 and \
               icmp_service.icmp_code == 7, ICMP_SERVICE_CREATE_ERROR
        icmp_service.update(icmp_type=4, icmp_code=8)
        icmp_service = ICMPService(ICMP_SERVICE_NAME)
        assert icmp_service.icmp_type == 4 and \
               icmp_service.icmp_code == 8, ICMP_SERVICE_UPDATE_ERROR

        # ICMPIPv6Service
        icmpipv6_service = ICMPIPv6Service.create(name=ICMPIPV6_SERVICE_NAME, icmp_type=3,
                                                  icmp_code=7, comment=ICMPIPV6_SERVICE_COMMENT)
        assert icmpipv6_service.icmp_type == 3 and \
               icmpipv6_service.icmp_code == 7, ICMPIPV6_SERVICE_CREATE_ERROR
        icmpipv6_service.update(icmp_type=4, icmp_code=8)
        icmpipv6_service = ICMPIPv6Service(ICMPIPV6_SERVICE_NAME)
        assert icmpipv6_service.icmp_type == 4 and \
               icmpipv6_service.icmp_code == 8, ICMPIPV6_SERVICE_UPDATE_ERROR
    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        EthernetServiceGroup(ETHERNET_SERVICE_GROUP_NAME).delete()
        logging.info("Successfully deleted EthernetServiceGroup")
        EthernetService(ETHERNET_SERVICE_NAME).delete()
        logging.info("Successfully deleted EthernetService")
        RpcServiceGroup(RPC_GROUP_NAME).delete()
        logging.info(f"successfully deleted RpcServiceGroup: {RPC_GROUP_NAME}.")
        RPCService(RPC_SERVICE_NAME).delete()
        logging.info(f"successfully deleted RPCService: {RPC_SERVICE_NAME}")
        ICMPService(ICMP_SERVICE_NAME).delete()
        logging.info("successfully deleted ICMPService.")
        ICMPIPv6Service(ICMPIPV6_SERVICE_NAME).delete()
        logging.info("successfully deleted ICMPIPv6Service.")
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to use Ethernet, RPC, ICMP and ICMPIPv6 services.',
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
