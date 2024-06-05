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
from smc.administration.user_auth.servers import ActiveDirectoryServer, DomainController  # noqa
from smc.administration.user_auth.users import ExternalLdapUserDomain  # noqa
from smc.elements.network import Network, AddressRange  # noqa

from smc import session  # noqa
from smc.elements.group import EthernetServiceGroup, RpcServiceGroup  # noqa
from smc.elements.protocols import ProtocolAgent  # noqa
from smc.elements.service import EthernetService, RPCService, ICMPService, ICMPIPv6Service, \
    IntegratedUserIdService, IntegratedUisIgnoreValue, TCPService  # noqa

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

# IntegratedUserIdService
INTEGRATED_UIS_NAME = "test_integrated_user_id_service"
INTEGRATED_UIS_MSG = "This is to test of IntegratedUserIdService."
INTEGRATED_UIS_CREATE_ERROR = "Fail to create IntegratedUserIdService."
INTEGRATED_UIS_UPDATE_ERROR = "Fail to update IntegratedUserIdService."
ACTIVE_DIRECTORY_SERVER = "test_active_directory_server"
LDAP_DOMAIN = "test_ldapdomain"
IP_ADDRESS1 = "192.168.1.1"
IP_ADDRESS2 = "192.168.1.2"
QUERY_TIME = 3600
POLLING_INTERVAL = 1

# TcpService
TCP_SERVICE_NAME = "test_tcp_service"
CREATE_TCP_SERVICE_ERROR = "Fail to create TCPService."
UPDATE_TCP_SERVICE_ERROR = "Fail to update TCPService."
SRC_MIN = 10
SRC_MAX = 20
DST_MIN = 20
DST_MAX = 30

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

        # IntegratedUserIdService
        # create domain controller
        domain_controller = DomainController("test_user", IP_ADDRESS2, "SHARE_SECRET",
                                             expiration_time=28800, server_type="dc")
        # create active directory server
        active_directory_server = ActiveDirectoryServer.create(
            ACTIVE_DIRECTORY_SERVER,
            address=IP_ADDRESS1,
            auth_ipaddress=IP_ADDRESS2,
            base_dn='dc=domain,dc=net',
            bind_password="test@12345",
            bind_user_id="cn=admin,cn=users,dc=domain,dc=net",
            client_cert_based_user_search="dc",
            domain_controller=[
                domain_controller],
            frame_ip_attr_name=IP_ADDRESS2,
            comment="This is testing of Active Directory Server"
        )
        list_of_iuis_ignore = []
        address_range = list(AddressRange.objects.all())[0]
        list_of_iuis_ignore.append(IntegratedUisIgnoreValue.create(iuis_ignore_ip=IP_ADDRESS1,
                                                                   iuis_ignore_user="test_user1"))
        list_of_iuis_ignore.append(
            IntegratedUisIgnoreValue.create(ne_ref=address_range, iuis_ignore_user="test_user2"))

        iuis_domain = ExternalLdapUserDomain.create(name=LDAP_DOMAIN,
                                                    ldap_server=[active_directory_server],
                                                    isdefault=True)
        integrated_uis = IntegratedUserIdService.create(INTEGRATED_UIS_NAME,
                                                        iuis_domain=iuis_domain,
                                                        iuis_ignore=list_of_iuis_ignore,
                                                        iuis_initial_query_time=QUERY_TIME,
                                                        iuis_polling_interval=POLLING_INTERVAL,
                                                        comment=INTEGRATED_UIS_MSG)
        assert integrated_uis.iuis_domain.href == iuis_domain.href and \
               integrated_uis.iuis_polling_interval == POLLING_INTERVAL and \
               integrated_uis.iuis_initial_query_time == QUERY_TIME and \
               len(integrated_uis.iuis_ignore) == 2, INTEGRATED_UIS_CREATE_ERROR
        logging.info("successfully created IntegratedUserIdService.")
        network = list(Network.objects.all())[0]
        list_of_iuis_ignore.append(
            IntegratedUisIgnoreValue.create(ne_ref=network, iuis_ignore_user="test_user3"))
        list_of_iuis_ignore = [ignore.data for ignore in list_of_iuis_ignore]
        integrated_uis.update(iuis_polling_interval=POLLING_INTERVAL + 1,
                              iuis_initial_query_time=QUERY_TIME - 600,
                              iuis_ignore=list_of_iuis_ignore)
        integrated_uis = IntegratedUserIdService(INTEGRATED_UIS_NAME)
        assert integrated_uis.iuis_domain.href == iuis_domain.href and \
               integrated_uis.iuis_polling_interval == POLLING_INTERVAL + 1 and \
               integrated_uis.iuis_initial_query_time == QUERY_TIME - 600 and \
               len(integrated_uis.iuis_ignore) == 3, INTEGRATED_UIS_UPDATE_ERROR
        logging.info("successfully updated IntegratedUserIdService.")

        # TCPService
        pa = ProtocolAgent("SSM DNS Proxy (TCP)")
        tcp_service = TCPService.create(TCP_SERVICE_NAME,
                                        min_dst_port=DST_MIN,
                                        max_dst_port=DST_MAX,
                                        min_src_port=SRC_MIN,
                                        max_src_port=SRC_MAX,
                                        protocol_agent=pa,
                                        comment="This is to test TcpService.")
        assert tcp_service.min_dst_port == DST_MIN and tcp_service.max_dst_port == DST_MAX and \
               tcp_service.max_src_port == SRC_MAX and tcp_service.min_src_port == SRC_MIN and \
               tcp_service.protocol_agent.href == pa.href and \
               '1' not in [pa_values.value for pa_values in
                           tcp_service.protocol_agent_values], CREATE_TCP_SERVICE_ERROR
        logging.info("Successfully created TCPService.")
        tcp_service = TCPService(TCP_SERVICE_NAME)
        for pa_value in tcp_service.protocol_agent_values:
            tcp_service.protocol_agent_values.update(name=pa_value.name, value=1)

        tcp_service.update(min_dst_port=SRC_MIN,
                           max_dst_port=SRC_MAX,
                           min_src_port=DST_MIN,
                           max_src_port=DST_MAX,
                           comment="This is to test TcpService")
        tcp_service = TCPService(TCP_SERVICE_NAME)
        assert tcp_service.min_dst_port == SRC_MIN and tcp_service.max_dst_port == SRC_MAX and \
               tcp_service.max_src_port == DST_MAX and tcp_service.min_src_port == DST_MIN and \
               tcp_service.protocol_agent.href == pa.href and \
               '0' not in [pa_value.value for pa_value in
                           tcp_service.protocol_agent_values], UPDATE_TCP_SERVICE_ERROR
        logging.info("Successfully updated TCPService.")
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
        IntegratedUserIdService(INTEGRATED_UIS_NAME).delete()
        logging.info("successfully deleted IntegratedUserIdService.")
        ExternalLdapUserDomain(LDAP_DOMAIN).delete()
        ActiveDirectoryServer(ACTIVE_DIRECTORY_SERVER).delete()
        TCPService(TCP_SERVICE_NAME).delete()
        logging.info("successfully deleted TCPService.")

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
