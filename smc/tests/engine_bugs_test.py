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
Regression guards for latent bugs of smc/core/engine.py (setters calling a
missing dict method, reversed isinstance() arguments, missing imports, swapped
arguments, bool returned instead of a list). Offline: objects are built from
raw data and every server call is patched.
"""
import contextlib
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "smc-monitoring"))

from smc.administration.access_rights import AccessControlList, GrantedElementPermissions  # noqa
from smc.api.exceptions import MissingRequiredInput  # noqa
from smc.base.model import ElementCache  # noqa
from smc.core import engine as engine_module  # noqa
from smc.core.engine import (  # noqa
    VPN,
    CloudGroup,
    DHCPClientConfiguration,
    EnabledInterfaceEntry,
    Engine,
    IdleTimeout,
    LinkUsageExceptionRules,
    MultipingTest,
)
from smc.vpn.elements import LinkUsageProfile  # noqa

ENGINE_HREF = "http://smc/elements/single_fw/1"


VERSION_CHECKS = ("min_smc_version", "is_smc_version_less_than", "is_smc_version_equal",
                  "is_smc_version_less_than_or_equal", "is_smc_version_more_than_or_equal",
                  "is_api_version_less_than", "is_api_version_less_than_or_equal")


def patch_versions(stack):
    """Pretend a recent SMC: min_smc_version() True, every "less than/equal" check False."""
    for check in VERSION_CHECKS:
        stack.enter_context(mock.patch.object(engine_module, check,
                                              return_value=check == "min_smc_version"))


def offline_engine(data):
    engine = Engine("fw", href=ENGINE_HREF, type="single_fw")
    engine.data = ElementCache(data)
    return engine


class EngineBugsTest(unittest.TestCase):

    def test_multiping_setters_store_the_new_values(self):
        test = MultipingTest({"value": ["1.1.1.1"], "enabled_interface": None})
        test.target_addresses = ["2.2.2.2"]
        test.enabled_interfaces = [EnabledInterfaceEntry({"address": "10.0.0.1", "nicid": "0"})]
        self.assertEqual(test.target_addresses, ["2.2.2.2"])
        self.assertEqual(test.data["enabled_interface"], [{"address": "10.0.0.1", "nicid": "0"}])
        test.enabled_interfaces = []
        self.assertIsNone(test.data["enabled_interface"])

    def test_link_usage_exception_destinations_setter_accepts_a_list(self):
        rule = LinkUsageExceptionRules(destinations="any")
        rule.destinations = ["http://smc/elements/host/1"]
        self.assertEqual(rule.destinations, {"dst": ["http://smc/elements/host/1"]})

    def test_cloud_group_create_resolves_engine_elements_to_hrefs(self):
        with mock.patch.object(engine_module, "ElementCreator") as creator:
            CloudGroup.create("group", elements=[offline_engine({}), "http://smc/raw"])
        json = creator.call_args[0][1]
        self.assertEqual(json["element"], [ENGINE_HREF, "http://smc/raw"])

    def test_engine_create_accepts_a_link_usage_profile_element_or_href(self):
        profile = LinkUsageProfile("lup", href="http://smc/elements/link_usage_profile/1")
        for value, expected in ((profile, profile.href), ("http://smc/href", "http://smc/href")):
            with contextlib.ExitStack() as stack:
                patch_versions(stack)
                stack.enter_context(mock.patch.object(engine_module.Node, "_create", return_value={}))
                cfg = Engine._create("fw", "firewall_node", [], log_server_ref="http://smc/log",
                                     link_usage_profile=value)
            self.assertEqual(cfg["link_usage_profile_ref"], expected)

    def test_engine_create_resolves_the_log_server_only_when_one_is_visible(self):
        log_server = mock.Mock(href="http://smc/elements/log_server/1")
        for visible, expected in ((log_server, {"log_server_ref": log_server.href}), (None, {})):
            with contextlib.ExitStack() as stack:
                self._patch_log_server_lookup(stack, visible, smc_7_5_1=True)
                cfg = Engine._create("fw", "firewall_node", [])
            self.assertEqual({k: v for k, v in cfg.items() if k == "log_server_ref"}, expected)

    def test_engine_create_without_visible_log_server_fails_before_smc_7_5_1(self):
        with contextlib.ExitStack() as stack:
            self._patch_log_server_lookup(stack, None, smc_7_5_1=False)
            with self.assertRaises(MissingRequiredInput):
                Engine._create("fw", "firewall_node", [])

    @staticmethod
    def _patch_log_server_lookup(stack, visible, smc_7_5_1):
        patch_versions(stack)
        stack.enter_context(mock.patch.object(engine_module, "is_smc_version_more_than_or_equal",
                                              return_value=smc_7_5_1))
        stack.enter_context(mock.patch.object(engine_module.Node, "_create", return_value={}))
        objects = stack.enter_context(mock.patch.object(engine_module.LogServer, "objects"))
        objects.first.return_value = visible

    def test_known_host_lists_raises_missing_required_input_without_sidewinder(self):
        for data in ({"sidewinder_proxy_enabled": False}, {}):
            with self.assertRaises(MissingRequiredInput):
                offline_engine(data).known_host_lists

    def test_known_host_lists_returns_the_configured_lists(self):
        engine = offline_engine({"sidewinder_proxy_enabled": True,
                                 "known_host_lists_ref": ["http://smc/khl/1", "http://smc/khl/2"]})
        with mock.patch.object(engine_module.Element, "from_href", side_effect=lambda href: href):
            self.assertEqual(["http://smc/khl/1", "http://smc/khl/2"], engine.known_host_lists)

    def test_granted_permissions_iterates_the_granted_acl_hrefs(self):
        acl = mock.Mock(href="http://smc/acl/1")
        permissions = GrantedElementPermissions({"granted_access_control_list": [acl.href]})
        with mock.patch.object(Engine, "permissions", new_callable=mock.PropertyMock,
                               return_value=permissions), \
                mock.patch.object(AccessControlList, "objects") as objects:
            objects.all.return_value = [acl]
            self.assertEqual(list(offline_engine({}).granted_permissions), [acl])

    def test_blacklist_show_uses_block_list_query_on_api_7_and_later(self):
        from smc_monitoring.monitors.block_list import BlockListQuery
        from smc_monitoring.monitors import blacklist
        engine = offline_engine({})
        with mock.patch.object(engine_module, "is_api_version_less_than", return_value=False), \
                mock.patch.object(BlockListQuery, "fetch_as_element", return_value=iter(["new"])):
            self.assertEqual(list(engine.blacklist_show()), ["new"])
        # non-regression: API < 7.0 still uses BlacklistQuery
        with mock.patch.object(engine_module, "is_api_version_less_than", return_value=True), \
                mock.patch.object(blacklist, "is_smc_version_less_than", return_value=True), \
                mock.patch.object(blacklist.BlacklistQuery, "fetch_as_element",
                                  return_value=iter(["old"])):
            self.assertEqual(list(engine.blacklist_show()), ["old"])

    def test_generate_certificate_passes_certificate_then_signing_ca(self):
        vpn = VPN(offline_engine({}), internal_gateway=mock.Mock())
        with mock.patch.object(engine_module.GatewayCertificate, "_create_from_cert") as create:
            vpn.generate_certificate("cn", signing_ca="ca", certificate="cert")
        create.assert_called_once_with(vpn, "cert", "ca")

    def test_idle_timeout_add_works_on_engine_without_connection_timeout(self):
        engine = offline_engine({})
        timeouts = IdleTimeout(engine)
        self.assertEqual(timeouts.data, {"connection_timeout": {}})
        timeouts.add("tcp")
        self.assertEqual(engine.data["connection_timeout"], [{"protocol": "tcp", "timeout": 1800}])
        self.assertTrue(timeouts._contains("tcp"))

    def test_idle_timeout_add_rejects_an_unknown_protocol_with_value_error(self):
        timeouts = IdleTimeout(offline_engine({"connection_timeout": []}))
        with self.assertRaises(ValueError):
            timeouts.add("bogus")

    def test_dhcp_client_address_ranges_return_the_stored_ranges(self):
        config = DHCPClientConfiguration({"restricted_address_list": ["1.1.1.1-1.1.1.2"],
                                          "proxy_arp_address_list": ["2.2.2.1-2.2.2.2"]})
        self.assertEqual(config.restricted_address_ranges, ["1.1.1.1-1.1.1.2"])
        self.assertEqual(config.proxy_arp_address_ranges, ["2.2.2.1-2.2.2.2"])
        empty = DHCPClientConfiguration({})
        self.assertFalse(empty.restricted_address_ranges)
        self.assertFalse(empty.proxy_arp_address_ranges)


if __name__ == "__main__":
    unittest.main()
