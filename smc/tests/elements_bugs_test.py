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
Regression guards for latent bugs in network elements: Ethernet service creation without
value2, TLS match on failed validation without extra matches, Server Pool NetLink weight and
Server Pool creation with missing optional arguments, the URL list application port setter
and blacklist entries whose source equals their destination. Objects are built offline;
I/O is mocked.
"""
import unittest
from typing import Any, Callable
from unittest import mock

from smc.base.model import ElementCache
from smc.elements.netlink import IpNetLinkWeight, ServerPool
from smc.elements.network import URLListApplication
from smc.elements.other import prepare_blacklist
from smc.elements.service import EthernetService
from smc.elements.situations import TLSMatchSituation


def _created_json(target: str, create: Callable[..., object], **kwargs: object) -> Any:
    with mock.patch(target) as creator:
        create(**kwargs)
    return creator.call_args.args[1]


class ElementsBugsTest(unittest.TestCase):

    def test_ethernet_service_create_accepts_value2_omitted(self) -> None:
        json = _created_json("smc.elements.service.ElementCreator", EthernetService.create,
                             name="8021q frame", value1="0x8100")
        self.assertEqual(33024, json["value1"])
        self.assertIsNone(json["value2"])
        json = _created_json("smc.elements.service.ElementCreator", EthernetService.create,
                             name="llc", frame_type="llc", value1="0x42", value2="0x43")
        self.assertEqual((0x42, 0x43), (json["value1"], json["value2"]))

    def test_tls_match_validation_failed_without_matches_uses_validation_failed_only(self) -> None:
        with mock.patch("smc.elements.situations.fetch_entry_point", return_value="http://smc/ep"), \
                mock.patch("smc.elements.situations.TLSMatchSituationContext"), \
                mock.patch("smc.elements.situations.ElementCreator"), \
                mock.patch("smc.elements.situations._retrieve_parameter_from_name"), \
                mock.patch("smc.elements.situations.SMCRequest") as request:
            TLSMatchSituation.create(name="t", match_certificate_validation="validation_failed")
        self.assertEqual(["http://smc/ep/79059"],
                         request.call_args_list[0].kwargs["json"]["sub_situations"])

    def test_ip_netlink_weight_without_netlink_nor_network_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            IpNetLinkWeight.create(ipaddress="1.1.1.1")
        netlink = mock.Mock(href="http://smc/nl/1", data={"network_ref": ["http://smc/net/1"]})
        weight = IpNetLinkWeight.create(ipaddress="1.1.1.1", netlink=netlink)
        self.assertEqual("http://smc/net/1", weight.data["network_ref"])

    def test_server_pool_create_accepts_missing_lists(self) -> None:
        json = _created_json("smc.elements.netlink.ElementCreator", ServerPool.create, name="p")
        self.assertEqual(([], []), (json["ip_netlink_weight"], json["members_list"]))
        json = _created_json("smc.elements.netlink.ElementCreator", ServerPool.create, name="p",
                             ip_netlink_weight=[mock.Mock(data={"w": 1})],
                             members_list=[mock.Mock(data={"m": 1})])
        self.assertEqual(([{"w": 1}], [{"m": 1}]), (json["ip_netlink_weight"], json["members_list"]))

    def test_url_list_application_port_setter_stores_a_list(self) -> None:
        url_list = URLListApplication(name="u")
        url_list.data = ElementCache({})
        url_list.application_port = [mock.Mock(data={"port_from": 80})]
        self.assertEqual([{"port_from": 80}], url_list.data["application_port"])

    def test_prepare_blacklist_keeps_both_end_points_when_source_equals_destination(self) -> None:
        self.assertEqual(
            {"end_point1": {"address_mode": "any", "port1": 80, "port2": 80,
                            "port_mode": "predefined_tcp"},
             "end_point2": {"address_mode": "any"},
             "duration": 3600},
            prepare_blacklist("any", "any", src_port1=80))
        json = prepare_blacklist("1.1.1.1/32", "any", dst_port1=3, dst_port2=30)
        self.assertEqual(["end_point1", "end_point2", "duration"], list(json))
        self.assertEqual(
            {"end_point1": {"address_mode": "address", "ip_network": "1.1.1.1/32"},
             "end_point2": {"address_mode": "any", "port1": 3, "port2": 30,
                            "port_mode": "predefined_tcp"},
             "duration": 3600},
            json)


if __name__ == "__main__":
    unittest.main()
