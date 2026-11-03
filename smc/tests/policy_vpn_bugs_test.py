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
Regression guards for latent bugs in policy rules and VPN elements: QoS link selection
values, rule section and insert point creation with only an insert point, the explicit proxy
sub policy of a rule action, the link usage exception accessors and the web services of SSL VPN
and Application Access rules. Objects are built offline; I/O methods are mocked.
"""
import unittest
from unittest import mock

from smc.base.model import Element, ElementCache
from smc.policy.qos import LinkSelection
from smc.policy.rule import IPv4Rule
from smc.policy.rule_elements import Action
from smc.vpn.application_access_portal import ApplicationAccessRule
from smc.vpn.elements import LinkUsageException, LinkUsageProfile
from smc.vpn.ssl_vpn_portal import SSLVPNRule

RULES_HREF = "http://smc/policy/1/rules"


def _created_params(method_name: str, **kwargs: object) -> object:
    rules = IPv4Rule(href=RULES_HREF)
    with mock.patch("smc.policy.rule.ElementCreator") as creator, \
            mock.patch("smc.policy.rule.is_api_version_more_than_or_equal", return_value=False):
        getattr(rules, method_name)(name="n", **kwargs)
    return creator.call_args.kwargs["params"]


class PolicyVpnBugsTest(unittest.TestCase):

    def test_link_selection_values_are_plain_attributes(self):
        link_selection = LinkSelection(bandwidth=1, jitter=2, latency=3, packet_loss=4, stability=5)
        for name in ("bandwidth", "jitter", "latency", "packet_loss", "stability"):
            self.assertNotIn(name, vars(LinkSelection))  # no dead method shadowed by the value
        # non-regression: values and JSON unchanged
        self.assertEqual((1, 2, 3, 4, 5), (link_selection.bandwidth, link_selection.jitter,
                                           link_selection.latency, link_selection.packet_loss,
                                           link_selection.stability))
        self.assertEqual({"jitter": 2, "latency": 3, "bandwidth": 1, "packet_loss": 4, "stability": 5},
                         link_selection.link_selection)

    def test_create_rule_section_accepts_insert_point_alone(self) -> None:
        self.assertEqual({"insert_point": "ip"},
                         _created_params("create_rule_section", insert_point="ip"))
        self.assertEqual({"after": "t", "insert_point": "ip"},
                         _created_params("create_rule_section", insert_point="ip", after="t"))

    def test_create_insert_point_accepts_insert_point_alone(self) -> None:
        self.assertEqual({"insert_point": "ip"},
                         _created_params("create_insert_point", insert_point="ip"))
        self.assertEqual({"before": "t", "insert_point": "ip"},
                         _created_params("create_insert_point", insert_point="ip", before="t"))

    def test_explicit_proxy_sub_policy_is_read_without_sub_policy(self) -> None:
        rule = mock.Mock(data={"action": {"explicit_proxy_sub_policy": "http://smc/sub/1"}})
        with mock.patch.object(Element, "from_href", return_value="resolved") as from_href:
            self.assertEqual("resolved", Action(rule).explicit_proxy_sub_policy)
        from_href.assert_called_once_with("http://smc/sub/1")

    def test_link_usage_exception_accessors_read_data(self) -> None:
        preference = mock.Mock(preference=2, qos_class="http://smc/qos/1")
        exception = LinkUsageException(mock.Mock(href="http://smc/lt/1"), [preference])
        self.assertEqual("http://smc/lt/1", exception.link_type())
        self.assertEqual([{"preference": 2, "qos_class": "http://smc/qos/1"}],
                         exception.link_usage_preference())

    def test_link_usage_profile_link_usage_exception_reads_data(self) -> None:
        profile = LinkUsageProfile(name="p")
        profile.data = ElementCache({"link_usage_exception": [{"link_type": "x"}]})
        self.assertEqual([{"link_type": "x"}], profile.link_usage_exception)

    def test_ssl_vpn_web_service_resolves_rule_services(self) -> None:
        rule = SSLVPNRule(href="http://smc/rule/1")
        rule.data = ElementCache({"ssl_vpn_web_service": ["http://smc/ws/1"]})
        with mock.patch.object(Element, "from_href", return_value="ws1") as from_href:
            self.assertEqual(["ws1"], rule.ssl_vpn_web_service)
        from_href.assert_called_once_with("http://smc/ws/1")

    def test_application_access_web_service_resolves_rule_services(self) -> None:
        rule = ApplicationAccessRule(href="http://smc/rule/1")
        rule.data = ElementCache({"application_access_web_service": ["http://smc/ws/1"]})
        with mock.patch.object(Element, "from_href", return_value="ws1") as from_href:
            self.assertEqual(["ws1"], rule.application_access_web_service)
        from_href.assert_called_once_with("http://smc/ws/1")


if __name__ == "__main__":
    unittest.main()
