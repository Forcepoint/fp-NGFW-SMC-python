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
Module representing a global system property in SMC.
"""
from smc.base.model import SubElement


class SystemProperty(SubElement):
    """
    Represents a global system property for this Management Server.
    """
    typeof = 'system_property'

    def __init__(self, **kwargs):
        super(SubElement, self).__init__(**kwargs)

    @property
    def value(self):
        """
        Value for this system property.
        For boolean value property, 'true' or 'false' will be returned.
        For numeric value property, the numeric value will be returned in string.
        """
        return self.data.get('value')

    @property
    def system_key(self):
        """
        Unique numeric identifier of the system property.
        This value will never be changed!
        """
        return self.data.get('system_key')

    @property
    def default_value(self):
        """
        Default value for this system property.
        For boolean value property, 'true' or 'false' will be returned.
        For numeric value property, the numeric value will be returned in string.
        """
        return self.data.get('default_value')

    @property
    def refs(self):
        """
        Possible element references.
        Especially for SMC appliance global system properties ('snmp_settings' or 'ntp_settings')
        """
        return [Element.from_href(ref) for ref in self.data.get('refs', [])]

    def __str__(self):
        return "{} / {} system property with value: {} and default_value: {}."\
            .format(self.name, self.system_key, self.value, self.default_value)
