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
Example script to show monitoring status usage.
"""

# Python Base Import

# Python SMC Import
import smc.examples

from smc import session
from smc.administration.monitoring_status import MonitoringStatus
from smc.compat import min_smc_version
from smc.core.engines import Layer3Firewall, Layer3VirtualEngine
from smc.elements.servers import ManagementServer
from smc.vpn.policy import PolicyVPN
from smc_info import SMC_URL, API_KEY, API_VERSION

if __name__ == "__main__":

    session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120, api_version=API_VERSION)

    print("session OK")

    try:
        # get status for Firewall
        fw = Layer3Firewall("Plano")
        status = MonitoringStatus.get_status(href=fw.href)
        print("Firewall status monitoring={}".format(status))
        print("History is {}".format(status.history))
        # get SDWAN status in result
        for sub_status in status.result:
            sub_status = MonitoringStatus.get_status(href=sub_status.get("href"))
            print("sub status monitoring={}".format(sub_status))

        # get Nodes status
        for node in fw.nodes:
            status = MonitoringStatus.get_status(href=node.href)
            print("Node status monitoring={}".format(status))

        # get status for Mgt Server
        mgt = ManagementServer.objects.first()
        status = MonitoringStatus.get_status(href=mgt.href)
        print("status monitoring={}".format(status))

        # get status for virtual firewall and nodes
        virtual = Layer3VirtualEngine.objects.first()
        status = MonitoringStatus.get_status(href=virtual.href)
        print("status monitoring={}".format(status))
        for node in virtual.nodes:
            status = MonitoringStatus.get_status(href=node.href)
            print("Node status monitoring={}".format(status))
            # master_node field exists since SMC 6.10 (all api versions)
            if min_smc_version("6.10"):
                print("Master Node={}".format(status.master_node))

        vpn = PolicyVPN("Corporate VPN")
        status = MonitoringStatus.get_status(href=vpn.href)
        print("vpn status monitoring={}".format(status))

        # get tunnel status in result
        for sub_status in status.result:
            sub_status = MonitoringStatus.get_status(href=sub_status.get("href"))
            print("tunnel status monitoring={}".format(sub_status))

    except Exception as e:
        print("Error:{}".format(e))
        exit(-1)
    finally:
        session.logout()
