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
Example script to show how to use Servers
-get logserver
-create Netflow collector
-add Netflow collectors to log server
-remove a Netflow collector from log server
"""
# Python Base Import

from smc import session
from smc.administration.system import System
from smc.core.engines import Layer3Firewall, FirewallCluster
from smc.core.external_pki import PkiCertificateSettings
from smc.elements.servers import LogServer
from smc_info import SMC_URL, API_KEY, API_VERSION

engine_name = "myFw"


def test_smc_ca():
    print("-----get smc CAs ---")
    system = System()

    system_cas = system.smc_certificate_authority()
    for ca in system_cas:
        print("CA={} {}".format(ca.name, ca.certificate_state))

    print("-----create new smc CAs ---")
    system.import_new_certificate_authority_certificate("c:/tmp/ca3.crt")
    print("new CA imported.")

    for ca in system.smc_certificate_authority():
        cert = ca.export_certificate()
        print("CA={} {}".format(ca.name, cert[0:26]))

    print("---- un trust ca ----")
    try:
        for ca in system.smc_certificate_authority():
            if ca.certificate_state != "active":
                ca.un_trust()
                print("un-trust ca {}".format(ca.name))
    except Exception as ex:
        print(ex)


def test_log_server_cert_settings():
    for log_server in LogServer.objects.all():
        print("LS={}".format(log_server))
    log_server = LogServer.get("LogServer1")
    # log_server.pki_export_certificate_request("c:/tmp/log.csr")
    # print("csr exported for log server")

    # log_server.pki_import_certificate("c:/tmp/log.crt")
    # print("cert imported for log server")

    # log_server.pki_export_certificate("c:/tmp/copy_log.crt")
    # print("cert exported for log server")
    print("-----get settings---")
    print("cert type: {}".format(log_server.pki_certificate_settings().certificate_type))
    print("subject_name: {}".format(log_server.pki_certificate_settings().subject_name))
    print("subject_alt_name: {}".format(log_server.pki_certificate_settings().subject_alt_name))
    print("check_revocation: {}".format(log_server.pki_certificate_settings().check_revocation))
    print("ignore_revocation_on_failure: {}".format(log_server.pki_certificate_settings()
                                                    .ignore_revocation_on_failure))

    # set certificate settings
    # print("-----test update---")
    # log_server.pki_certificate_settings().certificate_type = "ecdsa_sha_512"
    # log_server.pki_certificate_settings().subject_name = "cn=testName"
    # # log_server.pki_certificate_settings().subject_alt_name = "testAltName"
    # log_server.pki_certificate_settings().check_revocation = True
    # log_server.pki_certificate_settings().ignore_revocation_on_failure = True
    # log_server.update()
    #
    # settings = log_server.pki_certificate_settings()
    # print("cert type: {}".format(settings.certificate_type))
    # print("subject_name: {}".format(settings.subject_name))
    # print("subject_alt_name: {}".format(settings.subject_alt_name))
    # print("check_revocation: {}".format(settings.check_revocation))
    # print("ignore_revocation_on_failure: {}".format(settings.ignore_revocation_on_failure))

    # print("----get certificate info---")
    # info = log_server.pki_certificate_info()
    # print("certificate authority: {}".format(info["certificate_authority"]))
    # print("subject_alt_name: {}".format(info.subject_alt_name))
    # print("expiration_date: {}".format(info.expiration_date))
    # print("valid_from: {}".format(info.valid_from))

    # print("--- test pki_start_certificate_renewal ---") # log server should be started
    # log_server.pki_renew_certificate()
    # log_server.pki_export_certificate_request("c:/tmp/log_renew.csr")
    # print("csr exported for log server")


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
    print("single fw {} created!".format(single_fw.name))
    # for node in single_fw.nodes:
    #     settings = node.pki_certificate_settings()
    #     print("  engine cert type = {}".format(settings.certificate_type))
    #     print("  engine cert dns = {}".format(settings.subject_alt_name))
    single_fw.delete()


def test_single_fw():
    single_fw = Layer3Firewall.create(name="test single",
                                      mgmt_ip="192.168.10.13",
                                      mgmt_network="192.168.10.0/24",
                                      ntp_settings=None,
                                      extra_opts={"is_cert_auto_renewal": True},
                                      )
    print("single fw created {}!".format(single_fw.name))
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
    print("cluster fw {} created!".format(engine_cluster.name))
    # for node in engine_cluster.nodes:
    #     settings = node.pki_certificate_settings()
    #     print("  engine cert type = {}".format(settings.certificate_type))
    #     print("  engine cert dns = {}".format(settings.subject_alt_name))
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
    print("cluster fw created {}!".format(engine_cluster.name))
    engine_cluster.delete()


if __name__ == "__main__":
    session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120, api_version=API_VERSION)
    print("session OK")

try:

    # test_smc_ca()
    # test_log_server_cert_settings()

    test_single_fw()
    test_single_fw_pki()
    test_fw_cluster()
    test_fw_cluster_pki()

except Exception as e:
    print(e)
finally:
    print("Finally: Cleaning...")
    # reconnect to new session in case login refresh was not done automatically
    # SMC return 404 instead of 401 case
    session.logout()
    session.login(url=SMC_URL,
                  api_key=API_KEY,
                  verify=False,
                  timeout=120,
                  api_version=API_VERSION)
    print("Login Ok")
