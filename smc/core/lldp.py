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

from smc.base.model import Element, ElementCreator


class LLDPProfile(Element):
    """
    LLDP Profile represents a set of attributes used for configuring LLDP(Link Layer Discovery
    Protocol). LLDP information is advertised by devices at a fixed interval in the form of
    LLDP data units represented by TLV structures.
    """

    typeof = "lldp_profile"

    @property
    def transmit_delay(self):
        """
        The transmit delay determines the delay between
        any two consecutive LLDP advertisement frames.
        """
        return self.data.get("transmit_delay")

    @transmit_delay.setter
    def transmit_delay(self, value):
        self.data.update(transmit_delay=value)

    @property
    def hold_time_multiplier(self):
        """
        Represents the multiplier to apply to the advertisement interval.
        The product of the advertisement interval and the hold time multiplier
        gives cache life time for the learned LLDP information, after which it is discarded.
        """
        return self.data.get("hold_time_multiplier")

    @hold_time_multiplier.setter
    def hold_time_multiplier(self, value):
        self.data.update(hold_time_multiplier=value)

    @property
    def chassis_id(self):
        """
        TLV field: Chassis ID. The MAC address of the first Ethernet port (Always enabled)
        """
        return self.data.get("chassis_id")

    @property
    def port_id(self):
        """
        TLV field: Port ID. The name that the SNMP Agent uses for the interface
        (Always enabled)
        """
        return self.data.get("port_id")

    @property
    def time_to_live(self):
        """
        TLV field: Time to Live.	Automatically calculated based on transmit delay
        and hold time multiplier (Always enabled)
        """
        return self.data.get("time_to_live")

    @property
    def port_description(self):
        """
        TLV field: Port Description. The description that the SNMP Agent uses for the interface
        (Always enabled)
        """
        return self.data.get("port_description")

    @property
    def system_name(self):
        """
        TLV field: System Name. The system name that the SNMP Agent uses
        """
        return self.data.get("system_name")

    @system_name.setter
    def system_name(self, value):
        self.data.update(system_name=value)

    @property
    def system_description(self):
        """
        TLV field: System Description. The system description that the SNMP Agent uses
        """
        return self.data.get("system_description")

    @system_description.setter
    def system_description(self, value):
        self.data.update(system_description=value)

    @property
    def system_capabilities(self):
        """
        TLV field: System Capabilities. Capability bit-map. Depends on the interface type
        """
        return self.data.get("system_capabilities")

    @system_capabilities.setter
    def system_capabilities(self, value):
        self.data.update(system_capabilities=value)

    @property
    def management_address(self):
        """
        TLV Field: Management Address IP addresses of the control interfaces
        """
        return self.data.get("management_address")

    @management_address.setter
    def management_address(self, value):
        self.data.update(management_address=value)

    @classmethod
    def create(
            cls,
            name,
            transmit_delay,
            hold_time_multiplier,
            system_name,
            system_description,
            system_capabilities,
            management_address,
            comment=None
            ):
        """
        Create a LLDPProfile.
        :param str name: name of TLS Profile
        :param int transmit_delay: The transmit delay determines the delay between
        any two consecutive LLDP advertisement frames.
        :param int hold_time_multiplier: Represents the multiplier to apply to
        the advertisement interval.
        :param bool system_name: The system name that the SNMP Agent uses
        :param bool system_description: The system description that the SNMP Agent uses
        :param bool system_capabilities: Capability bit-map. Depends on the interface type
        :param bool management_address: Management Address IP addresses of the control interfaces
        :param str comment: optional comment
        :raises CreateElementFailed: failed to create element with reason
        :raises ElementNotFound: specified element reference was not found
        :rtype: TLSProfile
        """
        json = {
            "name": name,
            "transmit_delay": transmit_delay,
            "hold_time_multiplier": hold_time_multiplier,
            "chassis_id": True,
            "port_id": True,
            "time_to_live": True,
            "port_description": True,
            "system_name": system_name,
            "system_description": system_description,
            "system_capabilities": system_capabilities,
            "management_address": management_address,
            "comment": comment,
        }

        return ElementCreator(cls, json)
