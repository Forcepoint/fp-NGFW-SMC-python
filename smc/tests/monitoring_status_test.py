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
Regression guard for MonitoringStatus.status_type_by_link_type.

Pins the "type" token vocabulary confirmed against a live SMC's OpenAPI
spec, so a typo or stale rename fails here instead of silently falling
back to MonitoringStatus. Not auto-discovery: update KNOWN_SELF_LINK_TYPES
when the server adds or renames a type.
"""
import unittest

from smc.administration.monitoring_status import (
    MonitoringStatus,
    status_type_by_link_type,
)

# "self" link "type" tokens confirmed against a live SMC's OpenAPI spec.
# Not every token has a smc-python subclass.
KNOWN_SELF_LINK_TYPES = frozenset([
    "admin_status",
    "application_health_status",
    "elasticsearch_cluster_status",
    "endpoint_tunnel_status",
    "engine_cluster_status",
    "engine_node_status",
    "gateway_tunnel_status",
    "generic_vpn_status",
    "netlink_element_status",
    "rbvpn_tunnel_status",
    "sdwan_branch_status",
    "sdwan_branch_tunnel_status",
    "smc_server_status",
    "status",
    "vpn_broker_connectivity_status",
    "vpn_broker_endpoint_tunnel_status",
    "vpn_broker_gateway_tunnel_status",
    "vpn_broker_status",
    "vpn_status",
])


class TestStatusTypeByLinkType(unittest.TestCase):

    def test_keys_are_known_self_link_types(self):
        unknown = set(status_type_by_link_type) - KNOWN_SELF_LINK_TYPES
        self.assertFalse(
            unknown,
            "status_type_by_link_type has key(s) outside the confirmed "
            "self-link type vocabulary (typo, or the server has renamed a "
            "type since this list was pinned): {}".format(sorted(unknown)))

    def test_values_are_distinct_monitoring_status_subclasses(self):
        classes = list(status_type_by_link_type.values())
        for klass in classes:
            self.assertTrue(
                issubclass(klass, MonitoringStatus),
                "{} is not a MonitoringStatus subclass".format(klass))
        self.assertEqual(
            len(classes), len(set(classes)),
            "status_type_by_link_type maps more than one token to the same "
            "class")

    def test_application_health_status_is_intentionally_unmapped(self):
        # no ApplicationHealthStatus class - must stay on the base class
        self.assertNotIn("application_health_status", status_type_by_link_type)


if __name__ == "__main__":
    unittest.main()
