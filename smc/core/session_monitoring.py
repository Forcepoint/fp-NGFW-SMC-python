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
A session monitoring result contains all the values for the requested session monitoring.
"""


class EngineSessionMonitoringType:
    """
    Session Monitoring types supported by Engine call Engine.get_session_monitoring
    """
    ROUTING = "routing_monitoring"
    CONNECTION = "connection_monitoring"
    BLOCKLIST = "blocklist_monitoring"
    USER = "user_monitoring"
    VPNSA = "vpnsa_monitoring"
    SSLVPN = "sslvpn_monitoring"
    NEIGHBOR = "neighbor_monitoring"


class SessionMonitoringResult:
    """
    Session Monitoring Result

    sesmon_type : value from EngineSessionMonitoringType
    is_all : true if all existing value has been retrieved
    result : all entries
    """
    def __init__(self, sesmon_type, sesmon_entry):
        self.sesmon_type = sesmon_type
        for k in sesmon_entry:
            if k == "is_all":
                self.isAll = sesmon_entry[k]
            else:
                self.result = sesmon_entry[k]
