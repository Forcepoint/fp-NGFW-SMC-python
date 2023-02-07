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
example to configure ztna addon
"""

import sys
import smc.examples

from smc import session
from smc.core.engines import Layer3Firewall
from smc_info import SMC_URL, API_KEY, API_VERSION

if __name__ == "__main__":
    session.login(url=SMC_URL, api_key=API_KEY, verify=False,
                  timeout=120, api_version=API_VERSION)
    print("session OK")

    try:
        print("creating fw ztna_fw")
        Layer3Firewall("ztna_fw").delete()
    except Exception:
        pass

try:
    Layer3Firewall.create(name="ztna_fw",
                          mgmt_ip="192.168.10.1",
                          mgmt_network="192.168.10.0/24")

    engine = Layer3Firewall("ztna_fw")
    print("ztna connector initial status: ", engine.ztna_connector.status)
    print("now configuring ztna")
    engine.ztna_connector.enable(
        bgkey="aaaa:bbbb:cccc", datacenter="ddc1", auto_update=True)
    engine.update()

    engine_get = Layer3Firewall("ztna_fw")
    print("ztna connector status: ", engine_get.ztna_connector.status)
except BaseException as exc:
    print("ex={}".format(exc))
    sys.exit(-1)
finally:
    Layer3Firewall("ztna_fw").delete()
    print("deleting fw ztna_fw")
    session.logout()
