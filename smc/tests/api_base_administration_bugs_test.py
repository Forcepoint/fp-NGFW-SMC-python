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
Regression tests for latent bugs found while typing smc.api (session, configloader),
smc.administration (tasks, system_properties, monitoring_status) and smc.base.model.
Each test builds its objects without an SMC server and failed before the matching fix.
"""
import os
import tempfile
import threading
import unittest
from unittest import mock

import requests

from smc.administration.monitoring_status import EngineNodeStatus
from smc.administration.system_properties import SystemProperty
from smc.administration.tasks import TaskOperationPoller
from smc.api.configloader import load_from_file
from smc.api.exceptions import ConfigLoadError
from smc.api.session import Session
from smc.base.model import Element, ElementCache, SubElement, lookup_class


class ApiBaseAdministrationBugsTest(unittest.TestCase):

    def test_get_session_reuses_existing_session_without_connection_pool(self) -> None:
        session = Session()
        session._params = {"api_version": "7.4"}
        session._session = requests.Session()
        response = mock.Mock(status_code=200, headers={"Authorization": "token"})
        with mock.patch.object(requests.Session, "post", return_value=response):
            result = session._get_session({"url": "https://127.0.0.1:8082/7.4/login"})
        self.assertIs(result, session._session)
        self.assertIsNotNone(session._connpool)
        self.assertEqual("token", session._token)

    def test_config_load_error_message_contains_parser_error(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".smcrc", delete=False) as f:
            f.write("[other]\nsmc_address=1.1.1.1\n")
        try:
            with self.assertRaises(ConfigLoadError) as ctx:
                load_from_file(f.name)
        finally:
            os.remove(f.name)
        self.assertIn("No section: 'smc'", str(ctx.exception))

    def test_stop_works_on_python_3_9_and_later(self) -> None:
        poller = TaskOperationPoller({"follower": "http://task", "type": "task"})
        release = threading.Event()
        poller._done = threading.Event()
        poller._thread = threading.Thread(target=release.wait, daemon=True)
        poller._thread.start()
        try:
            poller.stop()
            self.assertTrue(poller._done.is_set())
        finally:
            release.set()
            poller._thread.join()

    def test_system_property_refs_resolves_elements(self) -> None:
        prop = SystemProperty(href="http://prop", name="ntp_settings")
        prop.data = ElementCache({"refs": ["http://ref1"]})
        with mock.patch("smc.base.model.ElementFactory", return_value="element") as factory:
            self.assertEqual(["element"], prop.refs)
        factory.assert_called_once_with("http://ref1")

    def test_engine_node_status_installed_policy_is_none_when_not_sent(self) -> None:
        with mock.patch("smc.administration.monitoring_status.min_smc_version", return_value=True):
            self.assertIsNone(EngineNodeStatus().installed_policy)
            # non-regression: a value received from the server is returned and printed as before
            status = EngineNodeStatus(installed_policy="Policy")
        self.assertEqual("Policy", status.installed_policy)
        self.assertIn("installed_policy = 'Policy'", str(status))

    def test_lookup_class_without_type_returns_default(self) -> None:
        self.assertIs(Element, lookup_class(None))
        self.assertIs(SubElement, lookup_class(None, SubElement))


if __name__ == "__main__":
    unittest.main()
