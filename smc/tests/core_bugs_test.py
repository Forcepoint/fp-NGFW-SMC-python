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
Regression guards for latent bugs in smc.core: bulk engine creation without interfaces or with
LLDP and link usage profiles in extra_opts, NTP settings creation, HA management and automatic
rules settings accessors, node waiter status without any value, modem APN interface on SMC < 7.5, interface option unset with
an address and contact address names containing an underscore. Objects are built offline;
I/O is mocked.
"""
import unittest
from typing import Any
from unittest import mock

from smc.base.model import ElementCache
from smc.api.exceptions import InterfaceNotFound, UpdateElementFailed
from smc.core.contact_address import ContactAddressNode
from smc.core.engine import Engine
from smc.core.engines import FirewallCluster, Layer3Firewall
from smc.core.general import NTPSettings
from smc.core.ha_management import HADiagnostic, HAInfo, InfoBlock
from smc.core.interfaces import InterfaceEditor, ModemInterface
from smc.core.policy import AutomaticRulesSettings
from smc.core.waiters import NodeWaiter


def _create_kwargs(create_bulk: Any, **kwargs: Any) -> Any:
    with mock.patch.object(Engine, "_create", return_value={}) as create, \
            mock.patch("smc.core.engines.ElementCreator"), \
            mock.patch("smc.core.engines.min_smc_version", return_value=False):
        create_bulk(name="fw", **kwargs)
    return create.call_args.kwargs


class CoreBugsTest(unittest.TestCase):

    def test_create_bulk_accepts_interfaces_omitted(self) -> None:
        for create_bulk in (Layer3Firewall.create_bulk, FirewallCluster.create_bulk):
            self.assertEqual([], _create_kwargs(create_bulk)["physical_interfaces"])
        kwargs = _create_kwargs(Layer3Firewall.create_bulk,
                                interfaces=[{"interface_id": 1000, "type": "tunnel_interface"}])
        self.assertEqual(["tunnel_interface"], [key for i in kwargs["physical_interfaces"] for key in i])

    def test_create_bulk_takes_link_usage_profile_ref_from_extra_opts(self) -> None:
        kwargs = _create_kwargs(Layer3Firewall.create_bulk, interfaces=[],
                                extra_opts={"link_usage_profile_ref": "http://smc/lup/1"})
        self.assertEqual("http://smc/lup/1", kwargs["link_usage_profile"])
        self.assertNotIn("link_usage_profile_ref", kwargs)

    def test_cluster_create_bulk_takes_both_profiles_from_extra_opts(self) -> None:
        kwargs = _create_kwargs(FirewallCluster.create_bulk, interfaces=[],
                                extra_opts={"lldp_profile_ref": "http://smc/lldp/1",
                                            "link_usage_profile_ref": "http://smc/lup/1"})
        self.assertEqual(("http://smc/lldp/1", "http://smc/lup/1"),
                         (kwargs["lldp_profile"], kwargs["link_usage_profile"]))

    def test_ntp_settings_create_returns_independent_instances(self) -> None:
        first = NTPSettings.create(ntp_enable=True, ntp_servers=[mock.Mock(href="http://smc/ntp/1")])
        second = NTPSettings.create(ntp_enable=False, ntp_servers=[])
        self.assertIsInstance(first, NTPSettings)
        self.assertEqual({"ntp_settings": {"ntp_enable": True, "ntp_server_ref": ["http://smc/ntp/1"]}},
                         first.data)
        self.assertFalse(second.ntp_enable)
        self.assertNotIn("data", vars(NTPSettings))
        with mock.patch("smc.core.general.Element.from_href", side_effect=lambda href: href):
            self.assertEqual((True, ["http://smc/ntp/1"]), (first.ntp_enable, first.ntp_servers))
            engine = mock.Mock(data=ElementCache({"ntp_settings": {"ntp_enable": True,
                                                                    "ntp_server_ref": ["http://smc/ntp/2"]}}))
            self.assertEqual((True, ["http://smc/ntp/2"]),
                             (NTPSettings(engine).ntp_enable, NTPSettings(engine).ntp_servers))

    def test_ha_management_setters_store_the_value(self) -> None:
        info = HAInfo({})
        info.connected_server = info.active_server = "http://smc/mgt/1"
        info.standby_servers = []
        block = InfoBlock({})
        block.title, block.message = "t", ["m"]
        diag = HADiagnostic({})
        diag.status, diag.execution_message = "ok", ["e"]
        diag.errors_warnings = diag.durations = {"title": "w"}
        diag.message = [{"title": "b"}]
        self.assertEqual({"connected_server": "http://smc/mgt/1", "active_server": "http://smc/mgt/1",
                          "standby_servers": []}, info.data)
        self.assertEqual(("t", ["m"]), (block.title, block.message))
        self.assertEqual(("ok", ["e"]), (diag.status, diag.execution_message))
        self.assertEqual(("w", "w", "b"),
                         (diag.errors_warnings.title, diag.durations.title, diag.message[0].title))

    def test_automatic_rules_settings_getters_read_the_settings(self) -> None:
        settings = AutomaticRulesSettings(mock.Mock(data={"automatic_rules_settings": {
            "allow_auth_traffic": True, "allow_no_nat": False, "log_level": "none"}}))
        self.assertEqual((True, False, "none", None),
                         (settings.allow_auth_traffic, settings.allow_no_nat, settings.log_level,
                          settings.allow_icmp_traffic_for_route_probing()))

    def test_node_waiter_status_is_none_when_no_value_is_set(self) -> None:
        waiter = NodeWaiter.__new__(NodeWaiter)
        waiter.value = ("status", "state")
        waiter._desired_status = "Online"
        waiter._resource = mock.Mock(**{"status.return_value": mock.Mock(status=None, state=None)})
        self.assertIsNone(waiter._get_status())
        waiter._resource.status.return_value = mock.Mock(status=None, state="Offline")
        self.assertEqual("Offline", waiter._get_status())

    def test_modem_apn_interface_on_existing_interfaces_raises_update_element_failed(self) -> None:
        with mock.patch("smc.core.interfaces.is_smc_version_more_than_or_equal", return_value=False):
            modem = ModemInterface(interface_id="0")
            modem.data["interfaces"] = [{"single_node_interface": {}}]
            with self.assertRaises(UpdateElementFailed):
                modem.add_apn_interface(apn="internet", interfaces=[{"dynamic_index": 1}])

    def test_set_unset_with_address_and_no_interface_raises_interface_not_found(self) -> None:
        editor = InterfaceEditor(mock.Mock(data={"physicalInterfaces": []}))
        with self.assertRaises(InterfaceNotFound):
            editor.set_unset(None, "backup_mgt", address="1.1.1.1")

    def test_contact_address_node_name_may_contain_an_underscore(self) -> None:
        node = ContactAddressNode(name="Switch Interface SWP_0_10.0.0.1", href="http://smc/ca")
        self.assertEqual(("SWP_0", "10.0.0.1"), (node.interface_id, node.interface_ip))
        node = ContactAddressNode(name="Interface 12_3.3.3.3", href="http://smc/ca")
        self.assertEqual(("12", "3.3.3.3"), (node.interface_id, node.interface_ip))


if __name__ == "__main__":
    unittest.main()
