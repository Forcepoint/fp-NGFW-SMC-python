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
Example script to show how to use GatewayProfile
"""
import argparse
import logging
import sys

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.vpn.elements import GatewayProfile  # noqa

gateway_profile_name = "test_gateway_profile"
attribute_name = 'aes128_for_ike'
message = "Testing of gateway profile."
creation_error = "Failed to create gateway profile with {} attribute."
update_error = "Failed to update gateway profile with {} attribute."
capabilities = {
    'sha2_ike_hash_length': 256,
    'sha2_ipsec_hash_length': 256,
    'aes128_for_ike': False,
    'aes128_for_ipsec': True,
    'aes256_for_ike': True,
    'aes256_for_ipsec': True,
    'aes_gcm_256_for_ipsec': True,
    'aes_gcm_for_ipsec': True,
    'aes_xcbc_for_ipsec': True,
    'aggressive_mode': True,
    'ah_for_ipsec': True,
    'blowfish_for_ike': True,
    'blowfish_for_ipsec': True,
    'des_for_ike': True,
    'des_for_ipsec': True,
    'dh_group_14_for_ike': True,
    'dh_group_15_for_ike': True,
    'dh_group_16_for_ike': True,
    'dh_group_17_for_ike': True,
    'dh_group_18_for_ike': True,
    'dh_group_19_for_ike': True,
    'dh_group_1_for_ike': True,
    'dh_group_20_for_ike': True,
    'dh_group_21_for_ike': True,
    'dh_group_2_for_ike': True,
    'dh_group_5_for_ike': True,
    'dss_signature_for_ike': True,
    'ecdsa_signature_for_ike': True,
    'esp_for_ipsec': True,
    'external_for_ipsec': True,
    'forward_client_vpn': True,
    'forward_gw_to_gw_vpn': True,
    'ike_v1': True,
    'ike_v2': True,
    'ipcomp_deflate_for_ipsec': True,
    'main_mode': True,
    'md5_for_ike': True,
    'md5_for_ipsec': True,
    'null_for_ipsec': True,
    'pfs_dh_group_14_for_ipsec': True,
    'pfs_dh_group_15_for_ipsec': True,
    'pfs_dh_group_16_for_ipsec': True,
    'pfs_dh_group_17_for_ipsec': True,
    'pfs_dh_group_18_for_ipsec': True,
    'pfs_dh_group_19_for_ipsec': True,
    'pfs_dh_group_1_for_ipsec': True,
    'pfs_dh_group_20_for_ipsec': True,
    'pfs_dh_group_21_for_ipsec': True,
    'pfs_dh_group_2_for_ipsec': True,
    'pfs_dh_group_5_for_ipsec': True,
    'pre_shared_key_for_ike': True,
    'rsa_signature_for_ike': True,
    'sa_per_host': True,
    'sa_per_net': True,
    'sha1_for_ike': True,
    'sha1_for_ipsec': True,
    'sha2_for_ike': True,
    'sha2_for_ipsec': True,
    'triple_des_for_ike': True,
    'triple_des_for_ipsec': True,
    'vpn_client_dss_signature_for_ike': True,
    'vpn_client_ecdsa_signature_for_ike': True,
    'vpn_client_rsa_signature_for_ike': True,
    'vpn_client_sa_per_host': True,
    'vpn_client_sa_per_net': True
}

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

        logging.info("Check and delete if gateway profile is present.")
        if GatewayProfile.objects.filter(name=gateway_profile_name, exact_match=True):
            GatewayProfile(gateway_profile_name).delete()
            logging.info("Successfully deleted gateway profile.")
        # create gateway profile
        gateway_profile = GatewayProfile.create(gateway_profile_name, comment=message,
                                                capabilities=capabilities)
        logging.info("Successfully created gateway profile.")
        assert not gateway_profile.capabilities.get(attribute_name), creation_error.format(
            attribute_name)
        gateway_profile.capabilities.update(aes128_for_ike=True)
        gateway_profile.update(capabilities=gateway_profile.capabilities)
        assert gateway_profile.capabilities.get(attribute_name), update_error.format(attribute_name)
        for cap_attribute, value in gateway_profile.capabilities.items():
            if cap_attribute == 'external_for_ipsec':
                continue
            assert value, creation_error.format(cap_attribute)
        # update all boolean cap attribute
        all_cap_attribute = gateway_profile.capabilities
        logging.info("Updating all attributes of capability of False.")
        for cap_attribute, value in gateway_profile.capabilities.items():
            if cap_attribute == 'external_for_ipsec':
                continue
            if type(value) is bool:
                all_cap_attribute[cap_attribute] = False

        gateway_profile.update(capabilities=all_cap_attribute)
        for cap_attribute, value in gateway_profile.capabilities.items():
            if cap_attribute == 'external_for_ipsec':
                continue
            if type(value) is bool:
                assert not value, creation_error.format(cap_attribute)
        logging.info("Validated all boolean attributes of capabilities are updated.")

    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        GatewayProfile(gateway_profile_name).delete()
        logging.info("Deleted GatewayProfile Successfully.")
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to use GatewayProfile',
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
