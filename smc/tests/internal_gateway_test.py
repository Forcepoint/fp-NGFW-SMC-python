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
Backup gateways of an Internal Gateway. Offline: the gateway is built from raw
data and every server call is patched.
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "smc-monitoring"))

from smc.api.exceptions import UnsupportedEngineFeature  # noqa
from smc.base.model import ElementCache  # noqa
from smc.core import engine as engine_module  # noqa
from smc.core.engine import InternalGateway  # noqa

GATEWAY_HREF = "http://smc/elements/single_fw/1/internal_gateway/10"
BACKUP_20 = "http://smc/elements/single_fw/2/internal_gateway/20"
BACKUP_30 = "http://smc/elements/single_fw/3/internal_gateway/30"


def offline_gateway(data, href=GATEWAY_HREF):
    gateway = InternalGateway(name="fw Primary", href=href, type="internal_gateway")
    gateway.data = ElementCache(data)
    return gateway


class InternalGatewayBackupGatewaysTest(unittest.TestCase):

    def test_backup_gateways_keep_the_failover_order(self):
        gateway = offline_gateway({"backup_gateways": [BACKUP_30, BACKUP_20]})
        with mock.patch.object(engine_module.Element, "from_href", side_effect=lambda h: h):
            self.assertEqual(gateway.backup_gateways, [BACKUP_30, BACKUP_20])

    def test_backup_gateways_are_empty_when_the_api_omits_them(self):
        self.assertEqual(offline_gateway({}).backup_gateways, [])

    def test_update_backup_gateways_sends_hrefs_in_the_given_order(self):
        gateway = offline_gateway({})
        backup = offline_gateway({}, href=BACKUP_30)
        with mock.patch.object(engine_module, "is_api_version_less_than", return_value=False), \
                mock.patch.object(InternalGateway, "update") as update:
            gateway.update_backup_gateways([backup, BACKUP_20])
        update.assert_called_once_with(backup_gateways=[BACKUP_30, BACKUP_20])

    def test_update_backup_gateways_with_an_empty_list_removes_them(self):
        gateway = offline_gateway({"backup_gateways": [BACKUP_20]})
        with mock.patch.object(engine_module, "is_api_version_less_than", return_value=False), \
                mock.patch.object(InternalGateway, "update") as update:
            gateway.update_backup_gateways([])
        update.assert_called_once_with(backup_gateways=[])

    def test_update_backup_gateways_is_refused_before_api_7_6(self):
        gateway = offline_gateway({})
        with mock.patch.object(engine_module, "is_api_version_less_than",
                               side_effect=lambda version: version == "7.6"), \
                mock.patch.object(InternalGateway, "update") as update:
            with self.assertRaises(UnsupportedEngineFeature):
                gateway.update_backup_gateways([BACKUP_20])
        update.assert_not_called()


if __name__ == "__main__":
    unittest.main()
