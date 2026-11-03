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
Regression guard for the smc_monitoring entry properties: a field missing from
the websocket record gives the documented default instead of raising.
No SMC needed.
"""
import os
import sys
import unittest
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "smc-monitoring"))

from smc_monitoring.models.calendar import TimeFormat  # noqa: E402
from smc_monitoring.models.constants import LogField  # noqa: E402
from smc_monitoring.monitors.alerts import Alert  # noqa: E402
from smc_monitoring.monitors.blacklist import BlacklistEntry  # noqa: E402
from smc_monitoring.monitors.block_list import BlockListEntry  # noqa: E402
from smc_monitoring.monitors.connections import Connection  # noqa: E402
from smc_monitoring.monitors.routes import RoutingView  # noqa: E402


class TimeFormatTest(unittest.TestCase):

    def test_unspecified_times_are_zero(self):
        self.assertEqual(TimeFormat().start_time, 0)
        self.assertEqual(TimeFormat().end_time, 0)
        time_format = TimeFormat()
        time_format.data = {}
        self.assertEqual(time_format.start_time, 0)
        self.assertEqual(time_format.end_time, 0)

    def test_each_time_depends_on_its_own_bound(self):
        open_start = TimeFormat(start_ms=0, end_ms=1000)
        self.assertEqual(open_start.start_time, 0)
        self.assertIsInstance(open_start.end_time, datetime)
        open_end = TimeFormat(start_ms=1000, end_ms=0)
        self.assertIsInstance(open_end.start_time, datetime)
        self.assertEqual(open_end.end_time, 0)


class EntryPropertiesTest(unittest.TestCase):

    def test_alert_ports(self):
        alert = Alert(**{str(LogField.SPORT): "1234", str(LogField.DPORT): 443})
        self.assertEqual((alert.source_port, alert.destination_port), (1234, 443))
        self.assertEqual((Alert().source_port, Alert().destination_port), (0, 0))

    def test_block_list_durations(self):
        for entry_class in (BlacklistEntry, BlockListEntry):
            self.assertEqual(entry_class(BlacklistEntryDuration="60").duration, 60)
            self.assertEqual(entry_class().duration, 0)

    def test_connection_first_fetch(self):
        self.assertTrue(Connection(first_fetch=True).first_fetch)
        self.assertIsNone(Connection().first_fetch)

    def test_route_metric(self):
        self.assertEqual(RoutingView(**{str(LogField.ROUTEMETRIC): "10"}).route_metric, 10)
        self.assertEqual(RoutingView().route_metric, 0)


if __name__ == "__main__":
    unittest.main()
