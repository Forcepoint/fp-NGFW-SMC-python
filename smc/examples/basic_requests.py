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
Example to show how to use SMCRequest to create, update and delete data in SMC
this is low level interface and can be used for elements not yet supported
"""

import argparse
import sys
import logging
sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.api.common import SMCRequest  # noqa
from smc.base.util import merge_dicts  # noqa
from smc.core.engines import Layer3Firewall  # noqa

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

        # Create NTP server
        ntp_server_json = {
            "address": "192.168.1.200",
            "comment": "NTP Server created by the SMC API",
            "name": "NTP Server",
            "ntp_auth_key_type": "none"
        }
        new_ntp_server = SMCRequest(href=session.entry_points.get("ntp"),
                                    json=ntp_server_json).create()
        ntp_server = SMCRequest(href=new_ntp_server.href).read()

        # create Layer3 FW with NTPServer and timezone
        Layer3Firewall.create(name="myFw",
                              mgmt_ip="192.168.10.1",
                              mgmt_network="192.168.10.0/24",
                              extra_opts={"ntp_settings": {"ntp_enable": True,
                                                           "ntp_server_ref": [new_ntp_server.href]},
                                          "timezone": "Europe/Paris"}
                              )

        # Update NTP server settings and timezone for the Firewall
        # Disable NTP Server
        engine = Layer3Firewall("myFw")
        merge_dicts(engine.data, {"ntp_settings": {"ntp_enable": False,
                                                   "ntp_server_ref": []}})
        # Remove timezone
        engine.data.pop("timezone", None)
        engine.update(json=engine.data,
                      etag=engine.etag)

        # Create LLDP Profile
        lldp_profile_json = {
            "name": "NewLLDPProfile",
            "hold_time_multiplier": 4,
            "transmit_delay": 30,
            "chassis_id": True,
            "management_address": True,
            "port_description": True,
            "port_id": True,
            "system_capabilities": True,
            "system_description": True,
            "system_name": True,
            "time_to_live": True
        }
        new_lldp_profile = SMCRequest(href=session.entry_points.get("lldp_profile"),
                                      json=lldp_profile_json).create()

        # create Layer3 FW with LLDPProfile
        lldp_profile = SMCRequest(href=new_lldp_profile.href).read()
        Layer3Firewall.create(name="myFw_lldp",
                              mgmt_ip="192.168.10.1",
                              mgmt_network="192.168.10.0/24",
                              extra_opts={"lldp_profile_ref": new_lldp_profile.href}
                              )

        # add physical interface
        fw = Layer3Firewall("myFw_lldp")
        fw.physical_interface.add_layer3_interface(interface_id=1,
                                                   address="10.10.10.1",
                                                   network_value="10.10.10.0/24")
        # Update LLDP profile
        interface = fw.physical_interface.get(1)
        merge_dicts(interface.data, {"lldp_mode": "send_and_receive"})
        interface.update(json=interface.data,
                         etag=interface.etag)
    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        # Delete NTP server and Firewall
        Layer3Firewall("myFw").delete()
        request = SMCRequest(href=new_ntp_server.href, headers={"if-match": ntp_server.etag})
        request.delete()

        # Delete LLDP Profile and Firewall
        Layer3Firewall("myFw_lldp").delete()
        request = SMCRequest(href=new_lldp_profile.href, headers={"if-match": lldp_profile.etag})
        request.delete()
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to use SMCRequest to create, update and delete data'
                    'in SMC',
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
