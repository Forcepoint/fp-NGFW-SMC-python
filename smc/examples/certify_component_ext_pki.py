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
Example script to show the use of Single and Cluster Firewalls
"""
# Python Base Import
import argparse
import logging
import sys
sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.administration.system import System  # noqa
from smc.core.engines import Layer3Firewall, FirewallCluster  # noqa
from smc.core.external_pki import PkiCertificateSettings  # noqa
from smc.elements.servers import LogServer  # noqa

engine_name = "myFw"

logging.getLogger()
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - '
                                                '%(name)s - [%(levelname)s] : %(message)s')


def test_smc_ca():
    logging.info("-----get smc CAs ---")
    system = System()

    system_cas = system.smc_certificate_authority()
    for ca in system_cas:
        logging.info(f"CA={ca.name} {ca.certificate_state}")

    logging.info("-----create new smc CAs ---")
    system.import_new_certificate_authority_certificate("c:/tmp/ca3.crt")
    logging.info("new CA imported.")

    for ca in system.smc_certificate_authority():
        cert = ca.export_certificate()
        logging.info(f"CA={ca.name} {cert[0:26]}")

    logging.info("---- un trust ca ----")
    try:
        for ca in system.smc_certificate_authority():
            if ca.certificate_state != "active":
                ca.un_trust()
                logging.info(f"un-trust ca {ca.name}")
    except Exception as ex:
        print(f"Exception:{ex}")


def test_log_server_cert_settings():
    for log_server in LogServer.objects.all():
        logging.info(f"LS={log_server}")
    log_server = LogServer.get("LogServer1")
    # log_server.pki_export_certificate_request("c:/tmp/log.csr")
    # logging.info("csr exported for log server")

    # log_server.pki_import_certificate("c:/tmp/log.crt")
    # logging.info("cert imported for log server")

    # log_server.pki_export_certificate("c:/tmp/copy_log.crt")
    # logging.info("cert exported for log server")
    logging.info("-----get settings---")
    logging.info(f"cert type: {log_server.pki_certificate_settings().certificate_type}")
    logging.info(f"subject_name: {log_server.pki_certificate_settings().subject_name}")
    logging.info(f"subject_alt_name: {log_server.pki_certificate_settings().subject_alt_name}")
    logging.info(f"check_revocation: {log_server.pki_certificate_settings().check_revocation}")
    logging.info(f"ignore_revocation_on_failure: "
                 f"{log_server.pki_certificate_settings().ignore_revocation_on_failure}")

    # set certificate settings
    # logging.info("-----test update---")
    # log_server.pki_certificate_settings().certificate_type = "ecdsa_sha_512"
    # log_server.pki_certificate_settings().subject_name = "cn=testName"
    # # log_server.pki_certificate_settings().subject_alt_name = "testAltName"
    # log_server.pki_certificate_settings().check_revocation = True
    # log_server.pki_certificate_settings().ignore_revocation_on_failure = True
    # log_server.update()
    #
    # settings = log_server.pki_certificate_settings()
    # logging.info(f"cert type: {settings.certificate_type}")
    # logging.info(f"subject_name: {settings.subject_name}")
    # logging.info(f"subject_alt_name: {settings.subject_alt_name}")
    # logging.info(f"check_revocation: {settings.check_revocation}")
    # logging.info(f"ignore_revocation_on_failure: {settings.ignore_revocation_on_failure}")

    # logging.info("----get certificate info---")
    # info = log_server.pki_certificate_info()
    # logging.info(f"certificate authority: {info["certificate_authority"]}")
    # logging.info(f"subject_alt_name: {info.subject_alt_name}")
    # logging.info(f"expiration_date: {info.expiration_date}")
    # logging.info(f"valid_from: {info.valid_from}")

    # logging.info("--- test pki_start_certificate_renewal ---") # log server should be started
    # log_server.pki_renew_certificate()
    # log_server.pki_export_certificate_request("c:/tmp/log_renew.csr")
    # logging.info("csr exported for log server")


def test_single_fw_pki():
    ext_pki_node = PkiCertificateSettings.create(subject_name="cn=nodeSingle",
                                                 subject_alt_name="nodePKIa").data
    single_fw = Layer3Firewall.create(name="test single_pki",
                                      mgmt_ip="192.168.10.1",
                                      mgmt_network="192.168.10.0/24",
                                      ntp_settings=None,
                                      node_definition={"name": "nodeAA",
                                                       "disable": False,
                                                       "nodeid": 1,
                                                       "external_pki_certificate_settings":
                                                           ext_pki_node},
                                      extra_opts={"is_cert_auto_renewal": True},
                                      )
    logging.info(f"single fw {single_fw.name} created!")
    # for node in single_fw.nodes:
    #     settings = node.pki_certificate_settings()
    #     logging.info(f"  engine cert type = {settings.certificate_type}")
    #     logging.info(f"  engine cert dns = {settings.subject_alt_name}")
    single_fw.delete()


def test_single_fw():
    single_fw = Layer3Firewall.create(name="test single",
                                      mgmt_ip="192.168.10.13",
                                      mgmt_network="192.168.10.0/24",
                                      ntp_settings=None,
                                      extra_opts={"is_cert_auto_renewal": True},
                                      )
    logging.info(f"single fw created {single_fw.name}!")
    single_fw.delete()


def test_fw_cluster_pki():
    ext_pki_node1 = PkiCertificateSettings.create(subject_name="cn=node1a",
                                                  subject_alt_name="node11a").data
    ext_pki_node2 = PkiCertificateSettings.create(subject_name="cn=node2a",
                                                  subject_alt_name="node22a").data
    ext_pki_node3 = PkiCertificateSettings.create(subject_name="cn=node3a",
                                                  subject_alt_name="node33a").data
    engine_cluster = FirewallCluster.create(
        name="mycluster_pki",
        cluster_virtual="1.1.1.1",
        cluster_mask="1.1.1.0/24",
        network_value="1.1.1.0/24",
        interface_id=0,
        cluster_nic=0,
        macaddress="02:02:02:02:02:02",
        nodes=[
            {"address": "1.1.1.2", "network_value": "1.1.1.0/24", "nodeid": 1},
            {"address": "1.1.1.3", "network_value": "1.1.1.0/24", "nodeid": 2},
            {"address": "1.1.1.4", "network_value": "1.1.1.0/24", "nodeid": 3},
        ],
        nodes_definition=[
            {"name": "nodeAAA", "disable": False, "nodeid": 1,
             "external_pki_certificate_settings": ext_pki_node1,
             "comment": "blabla"},
            {"name": "nodeBBB", "disable": False, "nodeid": 2,
             "external_pki_certificate_settings": ext_pki_node2},
            {"name": "nodeCCC", "disable": False, "nodeid": 3,
             "external_pki_certificate_settings": ext_pki_node3},
        ],
        ntp_settings=None,
        timezone="Europe/Paris",
        domain_server_address=["1.1.1.1"],
        enable_antivirus=True,
        enable_gti=True,
        default_nat=True,
        extra_opts={"is_cert_auto_renewal": True},
    )
    logging.info(f"cluster fw {engine_cluster.name} created!")
    # for node in engine_cluster.nodes:
    #     settings = node.pki_certificate_settings()
    #     logging.info(f"  engine cert type = {settings.certificate_type}")
    #     logging.info(f"  engine cert dns = {settings.subject_alt_name}")
    engine_cluster.delete()


def test_fw_cluster():
    engine_cluster = FirewallCluster.create(
        name="mycluster",
        cluster_virtual="1.1.1.11",
        cluster_mask="1.1.1.0/24",
        network_value="1.1.1.0/24",
        interface_id=0,
        cluster_nic=0,
        macaddress="02:02:02:02:02:02",
        nodes=[
            {"address": "1.1.1.12", "network_value": "1.1.1.0/24", "nodeid": 1},
            {"address": "1.1.1.13", "network_value": "1.1.1.0/24", "nodeid": 2},
            {"address": "1.1.1.14", "network_value": "1.1.1.0/24", "nodeid": 3},
        ],
        nodes_definition=[
            {"name": "nodeAA", "disable": False, "nodeid": 1,
             "comment": "blabla"},
            {"name": "nodeBB", "disable": False, "nodeid": 2},
            {"name": "nodeCC", "disable": False, "nodeid": 3},
        ],
        ntp_settings=None,
        timezone="Europe/Paris",
        domain_server_address=["1.1.1.1"],
        enable_antivirus=True,
        enable_gti=True,
        default_nat=True,
        extra_opts={"is_cert_auto_renewal": True},
    )
    logging.info("cluster fw created {engine_cluster.name}!")
    engine_cluster.delete()


def main():
    return_code = 0
    arguments = parse_command_line_arguments()

    try:
        session.login(url=arguments.api_url, api_key=arguments.api_key,
                      login=arguments.smc_user,
                      pwd=arguments.smc_pwd, api_version=arguments.api_version)
        logging.info("session OK")

        # test_smc_ca()
        # test_log_server_cert_settings()

        test_single_fw()
        test_single_fw_pki()
        test_fw_cluster()
        test_fw_cluster_pki()

    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        logging.info("Finally: Cleaning...")
        # reconnect to new session in case login refresh was not done automatically
        # SMC return 404 instead of 401 case
        session.logout()
        session.login(url=arguments.api_url, api_key=arguments.api_key,
                      login=arguments.smc_user,
                      pwd=arguments.smc_pwd, api_version=arguments.api_version)
        logging.info("Login Ok")
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show the use of Single and Cluster Firewalls',
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
