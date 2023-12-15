from smc.base.model import Element
from smc.base.structs import NestedDict
from smc.base.util import element_resolver


class ElementWithLocation:

    @property
    def location_ref(self):
        """
        The location of server
        :rtype Location:
        """
        return Element.from_href(self.data.get("location_ref"))


class NodeElement(ElementWithLocation):
    @property
    def tools_profile_ref(self):
        """
        Allows you to add commands to the element’s right-click menu.
        :rtype DeviceToolsProfile
        """
        return Element.from_href(self.data.get("tools_profile_ref"))

    @property
    def third_party_monitoring(self):
        """
        This represents Monitoring Settings for Third Party Monitoring.
        """
        return ThirdPartyMonitoring(self.data.get("third_party_monitoring"))

    @property
    def secondary(self):
        """
        If the device has additional IP addresses, you can enter them here instead of creating
        additional elements for the other IP addresses. The secondary IP addresses are valid in
        policies and in routing and antispoofing. You can add several IPv4 and IPv6 addresses
        (one by one)
        :rtype list
        """
        return self.data.get("secondary")

    def add_secondary(self, address, append_lists=False):
        """
        Add secondary IP addresses to this host element. If append_list
        is True, then add to existing list. Otherwise overwrite.

        :param list address: ip addresses to add in IPv4 or IPv6 format
        :param bool append_list: add to existing or overwrite (default: append)
        :return: None
        """
        self.update(secondary=address, append_lists=append_lists)


class ThirdPartyMonitoring(NestedDict):
    """
    This represents Monitoring Settings for Third Party Monitoring.
    """

    def __init__(self, data):
        super(ThirdPartyMonitoring, self).__init__(data=data)

    @classmethod
    def create(cls,
               encoding="UTF-8",
               logging_profile_ref=None,
               monitoring_log_server_ref=None,
               netflow=False,
               probing_profile_ref=None,
               snmp_trap=False,
               time_zone="Europe/Paris"
               ):
        """
        :param str encoding: The log reception the encoding.
        :param LoggingProfile logging_profile_ref: Activates syslog reception from this device. You
            must select the Logging Profile that contains the definitions for converting the syslog
            entries to log entries.You must also select the Time Zone in which the device is located
            By default, the local time zone of the computer you are using is selected.Not Required.
        :param LogServer monitoring_log_server_ref: Select the Monitoring Log Server that monitors
            this device (third-party monitoring).You must select a Log Server to activate the other
            options. Not Required.
        :param bool netflow: Activates NetFlow (v6 and v16) and IPFIX (NetFlow v20) data reception
            from this device. Not Required.
        :param ProbingProfile probing_profile_ref: Activates status monitoring for this device. You
            must also select the Probing Profile that contains the definitions for the monitoring.
            When you select this option, the element is added to the tree in the System Status view.
            Not Required.
        :param bool snmp_trap: Activates SNMP trap reception from this device. The data that the
            device sends must be formatted according to the MIB definitions currently active in the
            system. Not Required.
        :param str time_zone: The log reception the time zone.
        """
        data = {
            "encoding": encoding,
            "logging_profile_ref": element_resolver(logging_profile_ref),
            "monitoring_log_server_ref": element_resolver(monitoring_log_server_ref),
            "probing_profile_ref": element_resolver(probing_profile_ref),
            "snmp_trap": snmp_trap,
            "time_zone": time_zone,
            "netflow": netflow,
        }
        return cls(data)

    @property
    def encoding(self):
        """
        The log reception the encoding.
        :rtype str
        """
        return self.data.get("encoding")

    @property
    def snmp_trap(self):
        """
        Activates SNMP trap reception from this device. The data that the device sends must be
        formatted according to the MIB definitions currently active in the system.
        :rtype bool
        """
        return self.data.get("snmp_trap")

    @property
    def netflow(self):
        """
        Activates NetFlow (v6 and v16) and IPFIX (NetFlow v20) data reception from this device.
        :rtype bool
        """
        return self.data.get("netflow")

    @property
    def time_zone(self):
        """
        The log reception the time zone.
        :rtype str
        """
        return self.data.get("time_zone")

    @property
    def logging_profile_ref(self):
        """
        Activates syslog reception from this device.
        :rtype LoggingProfile
        """
        return Element.from_href(self.data.get("logging_profile_ref"))

    @property
    def monitoring_log_server_ref(self):
        """
        Monitoring Log Server that monitors this device (third-party monitoring)
        :rtype LogServer
        """
        return Element.from_href(self.data.get("monitoring_log_server_ref"))

    @property
    def probing_profile_ref(self):
        """
        Probing Profile that contains the definitions for the monitoring.
        :rtype ProbingProfile
        """
        return Element.from_href(self.data.get("probing_profile_ref"))


class IpAddressMixin:

    @property
    def address(self):
        """
        Single valid IPv4 address.
        :rtype str
        """
        return self.data.get("address")

    @property
    def ipv6_address(self):
        """
        Single valid IPv6 address.
        :rtype str
        """
        return self.data.get("ipv6_address")


class MultiContactServer(IpAddressMixin, NodeElement):
    """
    Represents Multi contact Servers.
    """


class IPv6Node(IpAddressMixin, NodeElement):
    """
    Represents IPv6 node elements.
    """
