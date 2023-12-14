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
Example script to show how to use BGP stuff like BGPProfile.
"""
import argparse
import logging
import sys

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.elements.network import Network  # noqa
from smc.routing.access_list import IPAccessList, IPv6AccessList  # noqa
from smc.routing.bgp import BGPProfile, BGPAggregationEntry, RedistributionEntry, BGPPeering, \
    BGPConnectionProfile  # noqa
from smc.routing.bgp_access_list import ASPathAccessList  # noqa
from smc.routing.prefix_list import IPPrefixList, IPv6PrefixList  # noqa
from smc.routing.route_map import RouteMap  # noqa

NOT_CREATED_MSG = "Failed to create BGPProfile."
CREATE_ERROR_BGP_PEERING = "Failed to create BGPPeering."
UPDATE_ERROR_BGP_PEERING = "Failed to update BGPPeering."
UPDATE_ERROR = "Failed to update an BGPProfile."
NAME = 'BGP_Profile'
RM_NAME = 'route_map_test'
PEERING_NAME = "bgp_peering_test"
BGP_PEERING_MSG = "Testing of BGP Peering"
INTERNAL_DISTANCE = 100
EXTERNAL_DISTANCE = 200
LOCAL_DISTANCE = 50
ENABLED = True
REDISTRIBUTION_TYPE = "kernel"

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

        network = list(Network.objects.all())[0]
        aggregation_entry = BGPAggregationEntry.create("aggregate_as_set", network)
        bgp_profile = BGPProfile.create(
            name=NAME,
            internal_distance=INTERNAL_DISTANCE,
            external_distance=EXTERNAL_DISTANCE,
            local_distance=LOCAL_DISTANCE,
            subnet_distance=[(network, INTERNAL_DISTANCE)],
            aggregation_entry=[
                aggregation_entry.data],
            redistribution_entry=[
                RedistributionEntry.create("kernel", enabled=ENABLED,
                                           filter_type=None).data,
                RedistributionEntry.create("static", enabled=ENABLED,
                                           filter_type=None).data])
        aggregation_entry = bgp_profile.aggregation_entry[0]
        for entry in bgp_profile.redistribution_entry:
            if entry.data["type"] == REDISTRIBUTION_TYPE:
                assert entry.data["enabled"] == ENABLED, NOT_CREATED_MSG
                break
        assert bgp_profile.internal_distance == INTERNAL_DISTANCE and bgp_profile.external_distance\
               == EXTERNAL_DISTANCE and aggregation_entry.data.get("subnet") == \
               aggregation_entry.data["subnet"], NOT_CREATED_MSG
        logging.info("BGPProfile is successfully created.")
        bgp_profile = BGPProfile(NAME)
        bgp_profile.update(internal=EXTERNAL_DISTANCE, external=INTERNAL_DISTANCE,
                           local=INTERNAL_DISTANCE)
        assert bgp_profile.internal_distance == EXTERNAL_DISTANCE and \
               bgp_profile.external_distance == INTERNAL_DISTANCE and \
               bgp_profile.local_distance == INTERNAL_DISTANCE, UPDATE_ERROR
        logging.info("BGPProfile is successfully updated.")

        # checking BGPPeering
        # create route map
        route_map = RouteMap.create(RM_NAME)
        ip_accesss_inbound = IPAccessList.create(name='aclv4_inbound', entries=[
            {'subnet': '1.1.1.0/24', 'action': 'permit'}])

        ip_accesss_outbound = IPAccessList.create(name='aclv4_outbound', entries=[
            {'subnet': '1.1.1.0/24', 'action': 'permit'}])

        acl6 = IPv6AccessList.create(name='aclv6', entries=[
            {'subnet': '2001:db8:1::1/128', 'action': 'permit'}])

        prefix = IPPrefixList.create(name='ipprefix', entries=[
            {'subnet': '10.0.0.0/8', 'min_prefix_length': 16, 'max_prefix_length': 32,
             'action': 'deny'}])

        prefix6 = IPv6PrefixList.create(name='ipprefixipv6', entries=[
            {'subnet': 'ab00::/64', 'min_prefix_length': 65, 'max_prefix_length': 128,
             'action': 'deny'}])
        aspath = ASPathAccessList.create(name='aspath', entries=[
            {'expression': '123-456', 'action': 'permit'},
            {'expression': '1234-567', 'action': 'deny'}])
        connection_profile_ref = list(BGPConnectionProfile.objects.all())[0]
        bgp_peering = BGPPeering.create(
            PEERING_NAME,
            connection_profile_ref=connection_profile_ref,
            md5_password=PEERING_NAME,
            local_as_option="prepend",
            local_as_value=10,
            max_prefix_option="warning_only",
            max_prefix_value=12,
            send_community="standard",
            connected_check="enabled",
            orf_option="send",
            next_hop_self=True,
            override_capability=True,
            dont_capability_negotiate=True,
            remote_private_as=True,
            route_reflector_client=False,
            soft_reconfiguration=True,
            ttl_option="disabled",
            ttl_value=None,
            inbound_rm_filter=route_map,
            outbound_rm_filter=route_map,
            default_originate=True,
            inbound_ip_filter=ip_accesss_inbound,
            inbound_ipv6_filter=acl6,
            inbound_ipprefix_filter=prefix,
            inbound_ipv6prefix_filter=prefix6,
            inbound_aspath_filter=aspath,
            outbound_ip_filter=ip_accesss_outbound,
            outbound_ipv6_filter=acl6,
            outbound_ipprefix_filter=prefix,
            outbound_ipv6prefix_filter=prefix6,
            outbound_aspath_filter=aspath,
            comment=BGP_PEERING_MSG
        )
        assert bgp_peering.local_as_option == "prepend" and bgp_peering.local_as_value == "10" and \
               bgp_peering.max_prefix_option == "warning_only" and bgp_peering.max_prefix_value == \
               12 and bgp_peering.inbound_rm_filter == route_map.href, CREATE_ERROR_BGP_PEERING
        # check inbound filter
        assert bgp_peering.inbound_rm_filter == route_map.href and bgp_peering.inbound_ip_filter ==\
               ip_accesss_inbound.href and bgp_peering.inbound_ipv6_filter == acl6.href and \
               bgp_peering.inbound_ipprefix_filter == prefix.href and \
               bgp_peering.inbound_ipv6prefix_filter == prefix6.href and \
               bgp_peering.inbound_aspath_filter == aspath.href, CREATE_ERROR_BGP_PEERING

        # check outbound filter
        assert bgp_peering.outbound_ip_filter == ip_accesss_outbound.href and \
               bgp_peering.outbound_ipv6_filter == acl6.href and \
               bgp_peering.outbound_ipprefix_filter == prefix.href and \
               bgp_peering.outbound_ipv6prefix_filter == prefix6.href and \
               bgp_peering.outbound_aspath_filter == aspath.href and \
               bgp_peering.outbound_rm_filter == route_map.href, CREATE_ERROR_BGP_PEERING

        logging.info(f"Successfully created BGPPeering:{PEERING_NAME}")
        bgp_peering = BGPPeering(PEERING_NAME)
        bgp_peering.update(bfd_enabled=True,
                           bfd_interval=750,
                           bfd_min_rx=500,
                           bfd_multiplier=3,
                           bfd_passive_mode=True)
        assert bgp_peering.bfd_enabled and bgp_peering.bfd_interval == 750 and \
               bgp_peering.bfd_min_rx == 500 and bgp_peering.bfd_multiplier \
               == 3, UPDATE_ERROR_BGP_PEERING
        logging.info("Successfully updated BGPPeering")

    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1

    finally:
        BGPProfile(NAME).delete()
        logging.info(f"BGPProfile {NAME} is deleted successfully.")
        BGPPeering(PEERING_NAME).delete()
        logging.info(f"BGPProfile {PEERING_NAME} is deleted successfully.")
        RouteMap(RM_NAME).delete()
        logging.info(f"RouteMap {RM_NAME} is deleted successfully.")
        IPAccessList('aclv4_inbound').delete()
        IPAccessList('aclv4_outbound').delete()
        IPv6AccessList('aclv6').delete()
        IPPrefixList('ipprefix').delete()
        IPv6PrefixList('ipprefixipv6').delete()
        ASPathAccessList('aspath').delete()
        logging.info("Successfully deleted all AccessList filter")
        session.logout()

    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to use BGP stuff like BGPProfile.',
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
