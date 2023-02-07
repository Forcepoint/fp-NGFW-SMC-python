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
Module representing read-only upcoming events in SMC
"""
from smc.base.model import Element


class UpcomingEvents(object):
    """
    List of all upcoming events for this Management Server.
    """

    def __init__(self, upcoming_events):
        self.upcoming_events = []
        for event in upcoming_events["events"]:
            self.upcoming_events.append(UpcomingEvent(event))

    def __iter__(self):
        return iter(self.upcoming_events)

    def __len__(self):
        return len(self.upcoming_events)

    def __getitem__(self, index):
        return self.upcoming_events[index]


class UpcomingEvent(object):
    """
    Represents an upcoming event:
    - the date when the event will occur
    - the situation of the event
    - the impacted element
    - the possible resources
    an SMC event which will occur soon like certificate expiration, license expiration,
    scheduled task failure, ...
    """

    typeof = "upcoming_event"

    def __init__(self, data):
        self.data = data

    @property
    def event_date(self):
        """
        The upcoming event date: either the date when the event will occur
        or the upcoming event creation date.

        :rtype: int
        """
        return self.data.get("event_date")

    @property
    def info(self):
        """
        Possible more info for the upcoming event.

        :rtype: str
        """
        return self.data.get("info")

    @property
    def impacted_element(self):
        """
        The direct impacted element for this upcoming event.

        :rtype: Element
        """
        return Element.from_href(self.data.get("impacted_element"))

    @property
    def situation(self):
        """
        The upcoming event situation which describes the context of the event.

        :rtype: Situation
        """
        return Element.from_href(self.data.get("situation"))

    @property
    def impacted_resources(self):
        """
        The optional impacted resources for this upcoming event.

        :rtype: list(Element)
        """
        return [Element.from_href(resource) for resource in self.data.get("impacted_resources", [])]

    def __getattr__(self, key):
        if "typeof" not in key and key in self.data:
            return self.data[key]
        raise AttributeError("%r object has no attribute %r" % (self.__class__, key))

    def __str__(self):
        sb = []
        sb.append("date='{}'".format(self.event_date))
        sb.append("impacted element='{}'".format(self.impacted_element))
        sb.append("impacted resources='{}'".format(self.impacted_resources))
        sb.append("situation='{}'".format(self.situation))
        sb.append("info='{}'".format(self.info))
        return ", ".join(sb)


class UpcomingEventsPolicy(object):
    """
    Represents the upcoming event policy.
    List of inspection situation uri with its threshold in days.
    Note: to be able to update it, you need to be superuser.
    """

    def __init__(self, upcoming_event_policy):
        self.upcoming_event_policy = []
        for event in upcoming_event_policy["entries"]:
            self.upcoming_event_policy.append(UpcomingEventsPolicyEntry(event))

    def __iter__(self):
        return iter(self.upcoming_event_policy)

    def __len__(self):
        return len(self.upcoming_event_policy)

    def __getitem__(self, index):
        return self.upcoming_event_policy[index]


class UpcomingEventsPolicyEntry(object):
    """
    Represents an entry for the upcoming event policy:
    inspection policy uri with its threshold in days.
    """

    typeof = "upcoming_event_policy_entry"

    def __init__(self, data):
        self.data = data

    @property
    def situation(self):
        """
        The linked upcoming situation.

        :rtype: Situation
        """
        return Element.from_href(self.data.get("situation"))

    @situation.setter
    def situation(self, situation):
        self.data.update(situation=situation)

    @property
    def threshold_in_days(self):
        """
        The global threshold in days for the upcoming event.
        If the situation is confirmed, the event will be raised during this amount of time.
        """
        return self.data.get("threshold_in_days")

    @threshold_in_days.setter
    def threshold_in_days(self, threshold):
        self.data.update(threshold_in_days=threshold)

    @property
    def enabled(self):
        """
        Flag to determinate if this situation must be considered as upcoming event.
        This flag will be global for the whole SMC.
        """
        return self.data.get("enabled")

    @enabled.setter
    def enabled(self, enabled):
        self.data.update(enabled=enabled)

    def __getattr__(self, key):
        if "typeof" not in key and key in self.data:
            return self.data[key]
        raise AttributeError("%r object has no attribute %r" % (self.__class__, key))

    def __str__(self):
        sb = []
        sb.append("situation='{}'".format(self.situation))
        sb.append("threshold_in_days='{}'".format(self.threshold_in_days))
        sb.append("enabled='{}'".format(self.enabled))
        return ", ".join(sb)


class UpcomingEventIgnoreSettings(object):
    """
    Represents the upcoming event ignore settings for the current administrator.
    List of inspection situation uri with possible resource uris.
    Note: all upcoming events linked to the situation uri will be filtered.
    """

    typeof = "upcoming_event_ignore_settings"

    def __init__(self, data):
        self.data = data

    @property
    def entries(self):
        """
        The list of inspection situation to filter.

        :rtype: List(Situation)
        """
        return [Element.from_href(situation) for situation in self.data.get("entries")]

    @entries.setter
    def entries(self, value):
        self.data.update(entries=value)

    def __getattr__(self, key):
        if "typeof" not in key and key in self.data:
            return self.data[key]
        raise AttributeError("%r object has no attribute %r" % (self.__class__, key))

    def __str__(self):
        sb = []
        for entry in self.entries:
            sb.append("situation='{}'".format(entry))
        return ", ".join(sb)
