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
Example script to show how to use VPNProfile
"""
from smc import session
from smc.vpn.elements import VPNProfile
from smc_info import *

vpn_profile_name = "test_vpn_profile"
attribute_name = 'aes128_for_ike'
message = "Testing of vpn profile."
creation_error = "Failed to create vpn profile with {} attribute."
update_error = "Failed to update vpn profile with {} attribute."
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

if __name__ == '__main__':
    session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120, api_version=API_VERSION)
    print("session OK")

try:
    print("Check and delete if vpn profile is present.")
    if VPNProfile.objects.filter(name=vpn_profile_name, exact_match=True):
        VPNProfile(vpn_profile_name).delete()
        print("Successfully deleted vpn profile.")
    # create vpn profile
    vpn_profile = VPNProfile.create(vpn_profile_name, capabilities=capabilities,
                                    cn_authentication_for_mobile_vpn=False,
                                    disable_anti_replay=False, disable_path_discovery=False,
                                    hybrid_authentication_for_mobile_vpn=False, keep_alive=False,
                                    preshared_key_for_mobile_vpn=False, sa_life_time=86400,
                                    sa_to_any_network_allowed=False, trust_all_cas=True,
                                    tunnel_life_time_kbytes=0,
                                    tunnel_life_time_seconds=28800, comment=message)
    print("Successfully created vpn profile.")
    assert not vpn_profile.capabilities.get(attribute_name), creation_error.format(
        attribute_name)
    vpn_profile.capabilities.update(aes128_for_ike=True)
    vpn_profile.update(capabilities=vpn_profile.capabilities)
    assert vpn_profile.capabilities.get(attribute_name), update_error.format(attribute_name)
    for cap_attribute, value in vpn_profile.capabilities.items():
        if cap_attribute == 'external_for_ipsec':
            continue
        assert value, creation_error.format(cap_attribute)
    # update all boolean cap attribute
    all_cap_attribute = vpn_profile.capabilities
    print("Updating all attributes of capability of False.")
    for cap_attribute, value in vpn_profile.capabilities.items():
        if cap_attribute == 'external_for_ipsec':
            continue
        if type(value) is bool:
            all_cap_attribute[cap_attribute] = False

    vpn_profile.update(capabilities=all_cap_attribute)
    for cap_attribute, value in vpn_profile.capabilities.items():
        if cap_attribute == 'external_for_ipsec':
            continue
        if type(value) is bool:
            assert not value, creation_error.format(cap_attribute)
    print("Validated all boolean attributes of capabilities are updated.")

except Exception as e:
    print("Exception is: {}".format(str(e)))
    exit(1)
finally:
    VPNProfile(vpn_profile_name).delete()
    print("Deleted VPNProfile Successfully.")
    session.logout()
