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
Engine advanced setting functionality such as LogModeration. These are common settings that are
located under the SMC Advanced Settings.
"""
from smc.base.structs import NestedDict


class LogModeration(NestedDict):
    """
    This is the definition of Log Compression for the engine or for an interface. You can also
    configure Log Compression to save resources on the engine. By default, each generated
    Antispoofing and Discard log entry is logged separately and displayed as a separate entry in the
    Logs view. Log Compression allows you to define the maximum number of separately logged entries.
    When the defined limit is reached, a single Antispoofing log entry or Discard log entry is
    logged. The single entry contains information on the total number of the generated Antispoofing
    log entries or Discard log entries. After this, logging returns to normal and all the generated
    entries are once more logged and displayed separately.
    """

    def __init__(self, engine):
        ars = {'log_moderation': engine.data.get("log_moderation", {})}
        super(LogModeration, self).__init__(data=ars)

    def add(self, burst=None, log_event=None, rate=None):
        """
        Add log_moderation setting entry on interface or engine.
        :param str burst: The maximum number of matching entries in a single burst. The default
        value for Antispoofing entries is 1000. By default, Discard log entries are not compressed.
        :param int log_event: Log Moderation Event Type:
                            1. antispoofing: Antispoofing entry (L3 engine only)
                            2. discard: discard entry.
        :param int rate: The maximum number of entries per second. The default value for
        Antispoofing entries is 100 entries /s. By default, Discard log entries are not compressed.

        """
        if self.contains(log_event):
            self.remove(log_event)
        self.data.get('log_moderation').append(
            {'burst': burst, 'log_event': log_event, 'rate': rate})

    def get(self, log_event):
        """
        Return log_moderation entry with specific log_event
        :param str log_event: Log Moderation Event Type:
                            1. antispoofing: Antispoofing entry (L3 engine only)
                            2. discard: discard entry.
        :rtype dict
        """
        for log_setting in self.data.get('log_moderation'):
            if log_setting['log_event'] == log_event:
                return log_setting
        return None

    def remove(self, log_event):
        """
        Remove the specific log_moderation setting.
        :param str log_event: Log Moderation Event Type:
                            1. antispoofing: Antispoofing entry (L3 engine only)
                            2. discard: discard entry.
        """
        for log_setting in self.data.get('log_moderation'):
            if log_setting['log_event'] == log_event:
                self.data['log_moderation'].remove(log_setting)
                break

    def contains(self, log_event):
        """
        Check if specific log_moderation settings are present.
        :param int log_event: Log Moderation Event Type:
                            1. antispoofing: Antispoofing entry (L3 engine only)
                            2. discard: discard entry.
        """
        for log_setting in self.data.get('log_moderation'):
            if log_setting['log_event'] == log_event:
                return True
        return False
