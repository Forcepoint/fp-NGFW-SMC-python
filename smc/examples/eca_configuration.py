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
ECA configuration

Create an ECA Client Configuration

        Create an ECA client config
        :param str, name: Name of ECA client configuration
        :param list, eca_ca_ref: ECA TLS Certificate Authority Reference list
        :param bool, autodiscovery: if True advertise engine contact address to ECA client
        :param str admin_domain: domain to apply (default: Shared Domain)
        :rtype: eca_client_config

Enable and configure ECA (Endpoint Context Agent) on a Firewall

        Enable Endpoint Integration with Forcepoint Endpoint Context Agent
        on this engine.
        :param str eca_client_config: name of ECA client configuration
        :param list eca_client_network_ref: List of source network or zone
        :param list eca_server_network_ref: List of destination network or zone
        :param list enabled_interface: List of listening interfaces (nic id and address)
        :param list listened_zone_ref: List of zones to listen on
        :param int listening_port: default 9111
        :return: None
"""

import argparse
import logging
import sys
sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.administration.certificates.tls import TLSCertificateAuthority  # noqa
from smc.core.engines import Engine  # noqa
from smc.core.addon import EndpointIntegration  # noqa
from smc.elements.network import Network, Zone  # noqa
from smc.administration.eca_client_config import EcaEndpointSettings, EcaClientConfig, \
    EcaOperatingSystemSituation, create_eca_os_situation_dict, EndpointApplication, \
    ECAExecutable  # noqa

ECA_SETTING_NAME = "test_eca_endpoint_settings"
ECA_SETTING_CREATE_ERROR = "Fail to create eca endpoint settings."
ECA_SETTING_UPDATE_ERROR = "Fail to update eca endpoint settings."

# EndpointApplication
ECA_APPLICATION_NAME = "test_eca_application"
ECA_MD5_HASH = "76dea970d89477ed03dc5289f297443c"
ECA_SHA256_HASH = "54a6483b8aca55c9df2a35baf71d9965ddfd623468d81d51229bd5eb7d1e1c1b"
ECA_VERSION_NUMBER = "1.0.24"
ECA_PRODUCT_NAME = "fp-NGFW-smc-python"
ECA_FILE_NAME = "test_file"
CREATE_ERROR_EP = "Fail to create Endpoint Application."
UPDATE_ERROR_EP = "Fail to update Endpoint Application."


logging.getLogger()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - '
                                               '%(name)s - [%(levelname)s] : %(message)s')


def main():
    return_code = 0
    try:
        arguments = parse_command_line_arguments()
        session.login(url=arguments.api_url, api_key=arguments.api_key,
                      login=arguments.smc_user,
                      pwd=arguments.smc_pwd, api_version=arguments.api_version)
        logging.info("session OK")
        # ECA Client Configuration Creation
        logging.info("Creation of ECA Client Configuration")
        eca_ca_ref = TLSCertificateAuthority("Stonesoft Root CA")
        eca_client_config_new = EcaClientConfig.create(name="eca client test",
                                                       eca_ca_ref=[eca_ca_ref],
                                                       auto_discovery=True)
        logging.info("Exporting ECA Client configuration")
        eca_client_config_new.export_client_config(filename="/tmp/eca_client_test.xml")
        eca_client_config_content = eca_client_config_new.export_client_config()
        logging.info("Activation and configuration of ECA on an Engine")
        eng2 = Engine("Santa Clara")
        eng2_ei = eng2.endpoint_integration
        zone1 = Zone("External")
        network1 = Network("Any network")
        network2 = Network("Atlanta Internal Network")
        interface = eng2.interface.get(0)
        ip = interface.addresses[0][0]
        nicid = interface.interface_id
        enabled_interface = {"address": ip, "nicid": nicid}
        eng2_ei.enable(eca_client_config=eca_client_config_new,
                       eca_client_network_ref=[network1],
                       eca_server_network_ref=[network2],
                       enabled_interface=[enabled_interface],
                       listened_zone_ref=[zone1])
        eng2.update()
        logging.info("Disabling configuration of ECA on an Engine")
        eng2_ei.disable()
        eng2.update()
        eca_settings_situations = create_eca_os_situation_dict()
        eca_settings_situations['Windows Server 2022'] = True
        eca_endpoint_setting = EcaEndpointSettings.create(name=ECA_SETTING_NAME,
                                                          client_av_disabled=False,
                                                          client_av_enabled=True,
                                                          client_av_unknown=False,
                                                          eca_os_dict=eca_settings_situations,
                                                          local_firewall_disabled=False,
                                                          local_firewall_enabled=True,
                                                          local_firewall_unknown=False,
                                                          os_update_time_days=1,
                                                          os_update_time_enabled=True,
                                                          os_update_time_operator="less_than",
                                                          os_update_unknown=True)
        assert eca_endpoint_setting.client_av_enabled() and \
               not eca_endpoint_setting.client_av_disabled() and \
               eca_endpoint_setting.local_firewall_enabled() and \
               eca_endpoint_setting.os_update_time_days() == 1 and \
               eca_endpoint_setting.os_update_unknown() and \
               eca_endpoint_setting.os_update_time_operator() \
               == "less_than", ECA_SETTING_CREATE_ERROR
        eca_endpoint_setting.update(client_av_enabled=False,
                                    local_firewall_disabled=True,
                                    os_update_time_days=2,
                                    os_update_time_enabled=False,
                                    os_update_time_operator="more_than")
        eca_endpoint_setting = EcaEndpointSettings(ECA_SETTING_NAME)
        assert not eca_endpoint_setting.client_av_enabled() and \
               eca_endpoint_setting.local_firewall_disabled() and \
               eca_endpoint_setting.os_update_time_days() == 2 and \
               not eca_endpoint_setting.os_update_time_enabled() and \
               eca_endpoint_setting.os_update_time_operator() == \
               "more_than", ECA_SETTING_UPDATE_ERROR
        # EndpointApplication
        eca_executable = ECAExecutable.create(file_name=ECA_FILE_NAME, md5_hash=ECA_MD5_HASH,
                                              product_name=ECA_PRODUCT_NAME,
                                              sha256_hash=ECA_SHA256_HASH,
                                              version_number=ECA_VERSION_NUMBER)
        ep = EndpointApplication.create(name=ECA_APPLICATION_NAME,
                                        version_number=ECA_VERSION_NUMBER, file_name=ECA_FILE_NAME,
                                        product_name=ECA_PRODUCT_NAME,
                                        signer_name="FP",
                                        eca_custom_situation_type="signer_information",
                                        comment="This is to test endpoint application.")
        assert ep.product_name == ECA_PRODUCT_NAME and ep.signer_name == "FP" and \
               ep.eca_custom_situation_type == "signer_information" and \
               ep.version_number == ECA_VERSION_NUMBER, CREATE_ERROR_EP
        logging.info(f"Successfully created EndpointApplication.")
        ep = EndpointApplication(ECA_APPLICATION_NAME)
        ep.update(eca_custom_situation_type="executable_list",
                  eca_executable=[eca_executable])
        ep = EndpointApplication(ECA_APPLICATION_NAME)
        assert ep.eca_custom_situation_type == "executable_list" and \
               ep.eca_executable[0].file_name == ECA_FILE_NAME and \
               ep.eca_executable[0].md5_hash == ECA_MD5_HASH and \
               ep.eca_executable[0].product_name == ECA_PRODUCT_NAME and \
               ep.eca_executable[0].sha256_hash == ECA_SHA256_HASH and \
               ep.eca_executable[0].version_number == ECA_VERSION_NUMBER, UPDATE_ERROR_EP
        logging.info(f"Successfully updated EndpointApplication.")

    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        EcaClientConfig("eca client test").delete()
        EcaEndpointSettings(ECA_SETTING_NAME).delete()
        EndpointApplication(ECA_APPLICATION_NAME).delete()
        logging.info(f"Successfully deleted EndpointApplication.")
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to create an ECA Client Configuration',
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
