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

from __future__ import annotations

from collections import namedtuple
from typing import Any, Iterator, List, Optional, Union
import pytz

from smc.base.util import save_to_file
from smc.core.advanced_settings import LogModeration
from smc.core.lldp import LLDPProfile
from smc.core.policy import AutomaticRulesSettings
from smc.elements.helpers import domain_helper, location_helper
from smc.base.model import Element, SubElement, lookup_class, ElementCreator, \
    ElementRef, ElementCache

from smc.api.exceptions import (
    UnsupportedEngineFeature,
    UnsupportedInterfaceType,
    EngineCommandFailed,
    SMCConnectionError, CreateElementFailed, UpdateElementFailed, CertificateExportError,
    CertificateImportError, UnsupportedSidewinderType, SnortConfigurationImportError,
    SnortConfigurationExportError
)
from smc.core.node import Node, HardwareStatus
from smc.core.resource import Snapshot, PendingChanges
from smc.core.interfaces import InterfaceOptions, PhysicalInterface, DHCPRelay
from smc.core.collection import (
    InterfaceCollection,
    LoopbackCollection,
    PhysicalInterfaceCollection,
    TunnelInterfaceCollection,
    VPNBrokerInterfaceCollection,
    ModemInterfaceCollection,
    VirtualPhysicalInterfaceCollection,
    SwitchInterfaceCollection,
)
from smc.administration.tasks import Task, TaskOperationPoller
from smc.administration.certificates.tls_common import certificate_content
from smc.elements.group import ConnectionSynchronizationGroup
from smc.elements.other import prepare_block_list, prepare_blacklist, Location, Geolocation
from smc.elements.network import Alias
from smc.vpn.elements import VPNSite, LinkUsageProfile
from smc.routing.bgp import DynamicRouting
from smc.routing.pim import PIMSettings
from smc.routing.ospf import OSPFProfile
from smc.core.route import Antispoofing, Routing, RouteIterable, PolicyRoute
from smc.core.session_monitoring import SessionMonitoringResult
from smc.core.contact_address import ContactAddressCollection
from smc.core.general import DNSRelay, Layer2Settings, DefaultNAT, SNMP, RankedDNSAddress, \
    NTPSettings
from smc.core.addon import (
    AntiVirus,
    FileReputation,
    SidewinderProxy,
    UrlFiltering,
    Sandbox,
    TLSInspection,
    ClientInspection,
    ZTNAConnector,
    EndpointIntegration
)
from smc.elements.servers import LogServer, DHCPServer, SamlSettings
from smc.base.collection import create_collection, sub_collection
from smc.base.util import element_resolver
from smc.administration.access_rights import AccessControlList, Permission, \
    GrantedElementPermissions
from smc.base.decorators import cacheable_resource
from smc.administration.certificates.vpn import GatewayCertificate, GatewayCertificateRequest
from smc.base.structs import BaseIterable, NestedDict
from smc.elements.profiles import SNMPAgent
from smc.elements.ssm import SSHKnownHostsLists
from smc.compat import (is_smc_version_less_than_or_equal, is_api_version_less_than_or_equal, \
    min_smc_version, is_api_version_less_than, is_smc_version_equal, is_smc_version_less_than,
                        is_smc_version_more_than_or_equal)


class TestEntry(NestedDict):
    """
    Represents the parent TestEntry element.
    """
    def __init__(self, data: Any) -> None:
        super(TestEntry, self).__init__(data=data)

    @property
    def test_active(self) -> bool:
        """
        Flag to know if the test is active?
        :rtype: bool
        """
        return self.data.get("test_active") == "True"

    @property
    def test_interval(self) -> int:
        """
        Represents the time in seconds to specify how often the test is run. The minimum interval is 4
        seconds and the maximum is 86,400 seconds (one day).
        Note: Running a test too frequently can increase overhead.
        By default: 60s.
        :rtype: int
        """
        return int(self.data.get("test_interval"))

    @property
    def online_state(self) -> bool:
        """
        Is the test executed when the engine is Online?
        :rtype: bool
        """
        return self.data.get("online_state") == "True"

    @property
    def offline_state(self) -> bool:
        """
        Is the test executed when the engine is Offline?
        :rtype: bool
        """
        return self.data.get("offline_state") == "True"

    @property
    def standby_state(self) -> bool:
        """
        Is the test executed when the engine is Standby?
        :rtype: bool
        """
        return self.data.get("standby_state") == "True"

    @property
    def test_action(self) -> str:
        """
        Represents the action the tester takes if a test fails:
         - none: no state transition is performed.
         - offline: the test switches the node offline. However, the tester does not
           turn offline the last active node in a cluster or nodes in the Locked Online state.
         - forceoffline: the node is forced to an offline state, even if it is the last
           node online in a cluster or if it is in the Locked Online state. Use in cases in which a
           complete cut in traffic is a better option than a partially working Firewall.
         - forcespeed: (Inline Pair Link Speed test only) if the test finds that the
           pair of inline ports have different speed/duplex settings, the speed/duplex on the higher
           speed/full duplex link is set to match the lower speed/half duplex setting on the other
           port. Correct and reliable operation requires identical settings.
        :rtype: str
        """
        return self.data.get("test_action")

    @property
    def alert_notification(self) -> bool:
        """
        Alert notification if test fails?
        :rtype: bool
        """
        return self.data.get("alert_notification") == "True"

    @property
    def snmp_notification(self) -> bool:
        """
        SNMP notification if test fails?
        :rtype: bool
        """
        return self.data.get("snmp_notification") == "True"


class FileSystemTest(TestEntry):
    """
    This represents the definition of the File system space available on a NGFW.
    It tests the free disk space on a hard disk partition.
    Note! Do not use this test on appliances that use a flash card instead of a hard disk.
    """
    typeof = "filesystemspace_test"

    def __init__(self, data: Any) -> None:
        super(FileSystemTest, self).__init__(data=data)

    @classmethod
    def create(cls, test_active: bool, test_interval: int, online_state: bool, test_action: str,
               on_partition: str, free_space: int, **kw) -> FileSystemTest:
        """
        :param bool test_active: Flag to know if the test is active?
        :param int test_interval: Represents the time in seconds to specify how often the test is run.
        :param bool online_state: Is the test executed when the engine is Online?
        :param str test_action: Represents the action the tester takes if a test fails.
        :param str on_partition: The partition name to be monitored. A directory name may also be used instead of a partition name.
        :param int free_space: Represents the minimum amount of Free Space in kilobytes.
        """
        json = {
            "name": cls.typeof,
            "test_active": test_active,
            "test_interval": test_interval,
            "online_state": online_state,
            "test_action": test_action,
            "on_partition": on_partition,
            "free_space": free_space
        }
        json.update(kw)

        return cls(json)

    @property
    def on_partition(self) -> str:
        """
        The partition name to be monitored. A directory name may also be used instead of a partition name.
        :rtype: str
        """
        return self.data.get("on_partition")

    @property
    def free_space(self) -> int:
        """
        Represents the minimum amount of Free Space in kilobytes. When the amount of free space drops below
        this amount, the engine executes the chosen action.
        :rtype: int
        """
        return int(self.data.get("free_space"))


class ExternalTest(TestEntry):
    """
    This represents the definition of an external test to be executed on a NGFW. It runs a custom
    script stored on the engine. If the script returns the code zero (0), the test is considered
    successful, otherwise the test is considered failed. <b>Caution!</b> This test allows
    administrators who have permissions to edit the properties of Engines to run arbitrary commands
    in the Engine operating system.
    """
    typeof = "external_test"

    def __init__(self, data: Any) -> None:
        super(ExternalTest, self).__init__(data=data)

    @classmethod
    def create(cls, test_active: bool, test_interval: int, online_state: bool, test_action: str,
               retry_count: int, test_timeout: int, command_line: str, **kw) -> ExternalTest:
        """
        :param bool test_active: Flag to know if the test is active?
        :param int test_interval: Represents the time in seconds to specify how often the test is run.
        :param bool online_state: Is the test executed when the engine is Online?
        :param str test_action: Represents the action the tester takes if a test fails.
        :param int retry_count: Represents the Retry Count to configure the number of times the Tester tries to execute the test.
        :param int test_timeout: Represents the Test Timeout in milliseconds.
        :param str command_line: Represents the script path in the Command Line field.
        """
        json = {
            "name": cls.typeof,
            "test_active": test_active,
            "test_interval": test_interval,
            "online_state": online_state,
            "test_action": test_action,
            "retry_count": retry_count,
            "test_timeout": test_timeout,
            "command_line": command_line
        }
        json.update(kw)

        return cls(json)

    @property
    def retry_count(self) -> int:
        """
        Represents the Retry Count to configure the number of times the Tester tries to execute the test.
        Note! We recommend always setting the retry count to more than 1 to avoid creating
         overly sensitive tests that burden the system unnecessarily.
        :rtype: int
        """
        return int(self.data.get("retry_count"))

    @property
    def test_timeout(self) -> int:
        """
        Represents the Test Timeout in milliseconds.
         - If the test being run does not return a response in the specified time, the test is considered to have failed.
         - Avoid overly short timeout values. We recommend a timeout of 500 - 1000 ms depending on the external test script.
        :rtype: int
        """
        return int(self.data.get("test_timeout"))

    @property
    def command_line(self) -> str:
        """
        Represents the script path in the Command Line field.
         - Example /usr/local/bin/connectivity.sh
        Note! The external script must return an exit code of 0 (zero) if it succeeds.
        Any non-zero return value is considered a failure.
        Caution! This test allows administrators who have permissions to edit the properties of
         Engines to run arbitrary commands in the Engine operating system.
        :rtype: str
        """
        return self.data.get("command_line")


class InlinePairlinkSpeedTest(TestEntry):
    """
    This represents the Inline Pair Link Speed test.
    It checks whether the network settings (speed/duplex) match on the two ports that form the inline
    pair and can force both ports to use the same settings.

    :param bool test_active: Flag to know if the test is active?
    :param int test_interval: Represents the time in seconds to specify how often the test is run.
    :param bool online_state: Is the test executed when the engine is Online?
    :param str test_action: Represents the action the tester takes if a test fails.
    :param int test_timeout: Represents Test Timeout in milliseconds. Default value is 30 seconds.
    """
    typeof = "inline_test"

    def __init__(self, data: Any) -> None:
        super(InlinePairlinkSpeedTest, self).__init__(data=data)

    @classmethod
    def create(cls, test_active: bool, test_interval: int, online_state: bool, test_action: str,
               test_timeout: int, **kw) -> InlinePairlinkSpeedTest:
        """
        :param bool test_active: Flag to know if the test is active?
        :param int test_interval: Represents the time in seconds to specify how often the test is run.
        :param bool online_state: Is the test executed when the engine is Online?
        :param str test_action: Represents the action the tester takes if a test fails.
        :param int test_timeout: Represents Test Timeout in milliseconds. Default value is 30 seconds.
        """
        json = {
            "name": cls.typeof,
            "test_active": test_active,
            "test_interval": test_interval,
            "online_state": online_state,
            "test_action": test_action,
            "test_timeout": test_timeout
        }
        json.update(kw)

        return cls(json)

    @property
    def test_timeout(self) -> int:
        """
        Represents Test Timeout in milliseconds. Default value is 30 seconds.
        :rtype: int
        """
        return int(self.data.get("test_timeout"))


class SwapFreeTest(TestEntry):
    """
    This is the definition of the Free Swap Space test. It checks the available swap space on the hard disk.
    Note! Do not use this test on appliances that use a flash card instead of a hard disk.
    """
    typeof = "freeswapspace_test"

    def __init__(self, data: Any) -> None:
        super(SwapFreeTest, self).__init__(data=data)

    @classmethod
    def create(cls, test_active: bool, test_interval: int, online_state: bool, test_action: str,
               free_space: int, **kw) -> SwapFreeTest:
        """
        :param bool test_active: Flag to know if the test is active?
        :param int test_interval: Represents the time in seconds to specify how often the test is run.
        :param bool online_state: Is the test executed when the engine is Online?
        :param str test_action: Represents the action the tester takes if a test fails.
        :param int free_space: Represents the minimum amount of Free Space in kilobytes.
        """
        json = {
            "name": cls.typeof,
            "test_active": test_active,
            "test_interval": test_interval,
            "online_state": online_state,
            "test_action": test_action,
            "free_space": free_space
        }
        json.update(kw)

        return cls(json)

    @property
    def free_space(self) -> int:
        """
        Represents the minimum amount of Free Space in kilobytes. When the amount of free space drops below
        this amount, the engine executes the chosen action.
        :rtype: int
        """
        return int(self.data.get("free_space"))


class InterfaceTest(TestEntry):
    """
    Parent class for Interface Link and Multiping Test.

    :param bool test_active: Flag to know if the test is active?
    :param int test_interval: Represents the time in seconds to specify how often the test is run.
    :param bool online_state: Is the test executed when the engine is Online?
    :param str test_action: Represents the action the tester takes if a test fails.
    :param int nicid: Represents the Interface ID on which the test is run representing.
    """

    def __init__(self, data: Any) -> None:
        super(InterfaceTest, self).__init__(data=data)

    @property
    def nicid(self) -> str:
        """
        Represents the Interface ID on which the test is run representing:
         - all: All Physical Interfaces, Modem Interfaces (Single Firewalls only), ADSL
                Interfaces (Single Firewalls only), and Wireless Interfaces (Single Firewalls only).
         - all_with_cvi: (Clusters only) ALL with CVI.
         - A single Physical Interface, a Modem Interface (Single Firewalls only), an ADSL Interface
           (single firewalls only), or a Wireless Interface (Single Firewalls only) interface ID.
         Note! (Firewalls only) Only the first interface that belongs to an Aggregated Link is
         shown in the list of interfaces. However, the Link Status test checks the status of both
         interfaces in the Aggregated Link.
        :rtype: int
        """
        return self.data.get("nicid")


class EnabledInterfaceEntry(NestedDict):
    """
    Represents the enabled interface.
    """

    def __init__(self, data: Any) -> None:
        super(EnabledInterfaceEntry, self).__init__(data=data)

    @classmethod
    def create(cls, address: str, nicid: str) -> EnabledInterfaceEntry:
        """
        :param str address: the IPv4 address.
        :param str nicid: the interface nic id in string format.
        """
        return cls({
            "address": address,
            "nicid": nicid
        })


class LinkStatusTest(InterfaceTest):
    """
    This represents the definition of Interface Link test.
    It checks whether a network port reports the link as up or down.
     - The link of a Modem Interface (Single Firewalls only) is up if a modem reports that a call
       is in progress.
     - The link of an ADSL interface (Single Firewalls only) is up when the ADSL modem is
       connected to a Digital Subscriber Line Access Multiplexer (DSLM), and the ADSL modem
       reports that the connection is working.
     - The link of a Wireless Interface (Single Firewalls only) is up when the related firewall
       engine has been configured and is working.
     - The status of Aggregated Links (Firewalls only) depends on the link mode. An Aggregated
       Link in High-Availability Mode is up if one of the interfaces that belong to the Aggregated
       Link is up. An Aggregated Link in Load-Balancing Mode is up if both the interfaces that
       belong to the Aggregated Link are up.
    """
    typeof = "linkstatus_test"

    def __init__(self, data: Any) -> None:
        super(LinkStatusTest, self).__init__(data=data)

    @classmethod
    def create(cls, test_active: bool, test_interval: int, online_state: bool, test_action: str,
               nicid: str, down_ratio: int, **kw) -> LinkStatusTest:
        """
        :param bool test_active: Flag to know if the test is active?
        :param int test_interval: Represents the time in seconds to specify how often the test is run.
        :param bool online_state: Is the test executed when the engine is Online?
        :param str test_action: Represents the action the tester takes if a test fails.
        :param int nicid: Represents the Interface ID on which the test is run representing.
        :param int down_ratio: Represents the ratio used to determine if an aggregated link used in Load Balancing mode is down.
        """
        json = {
            "name": cls.typeof,
            "test_active": test_active,
            "test_interval": test_interval,
            "online_state": online_state,
            "test_action": test_action,
            "nicid": nicid,
            "down_ratio": down_ratio
        }
        json.update(kw)

        return cls(json)

    @property
    def down_ratio(self) -> int:
        """
        Represents the ratio used to determine if an aggregated link used in Load Balancing mode is down.
        Will be ignored for not aggregated links or links not configured in Load balancing mode.
        - 0: Not set
        - x (Values in 15, 20, 25, 30, 35, 40, 45, 50): Aggregated link in load
          balancing mode is considered as down when x % of its interfaces are down
        :rtype: int
        """
        return int(self.data.get("down_ratio"))


class MultipingTest(InterfaceTest):
    """
    This represents the definition of a Multiping test.
    It sends out a series of ping requests to determine whether there is connectivity through a
    network link. Only IPv4 addresses are supported as target addresses for the Multiping test.
    """
    typeof = "multiping_test"

    def __init__(self, data: Any) -> None:
        super(MultipingTest, self).__init__(data=data)

    @classmethod
    def create(cls, test_active: bool, test_interval: int, online_state: bool, test_action: str,
               nicid: str, retry_count: int, test_timeout: int, target_addresses: list[str],
               enabled_interfaces: list[EnabledInterfaceEntry], **kw) -> MultipingTest:
        """
        :param bool test_active: Flag to know if the test is active?
        :param int test_interval: Represents the time in seconds to specify how often the test is run.
        :param bool online_state: Is the test executed when the engine is Online?
        :param str test_action: Represents the action the tester takes if a test fails.
        :param int nicid: Represents the Interface ID on which the test is run representing.
        :param int retry_count: Represents the Retry Count to configure the number of times the Tester tries to execute the test.
        :param int test_timeout: Represents the Test Timeout in milliseconds.
        :param list[str] target_addresses: Represents the Target Addresses of ICMP echo requests.
        :param list[EnabledInterfaceEntry] enabled_interfaces: Represents the Source Addresses
          from their interface IDs/IP Addresses for the test.
        """
        json = {
            "name": cls.typeof,
            "test_active": test_active,
            "test_interval": test_interval,
            "online_state": online_state,
            "test_action": test_action,
            "nicid": nicid,
            "retry_count": retry_count,
            "test_timeout": test_timeout,
            "value": target_addresses,
            "enabled_interface": [entry.data for entry in enabled_interfaces] if enabled_interfaces else None
        }
        json.update(kw)

        return cls(json)

    @property
    def retry_count(self) -> int:
        """
        Represents the Retry Count to configure the number of times the Tester tries to execute the test.
        We recommend always setting the retry count to more than 1 to avoid creating overly sensitive
        tests that burden the system unnecessarily.
        :rtype: int
        """
        return int(self.data.get("retry_count"))

    @property
    def test_timeout(self) -> int:
        """
        Represents the Test Timeout in milliseconds. If the test being run does not return a response in the
        specified time, the test is considered to have failed. Avoid overly short timeout values. By default 500ms.
        :rtype: int
        """
        return int(self.data.get("test_timeout"))

    @property
    def target_addresses(self) -> list[str]:
        """
        Represents the Target Addresses of ICMP echo requests. Only IPv4 addresses are supported. The test
        is considered failed if none of the target addresses responds.
        :rtype: list[str]
        """
        return self.data.get("value")

    @target_addresses.setter
    def target_addresses(self, value: list[str]) -> None:
        self.data.set("value", value)

    @property
    def enabled_interfaces(self) -> list[EnabledInterfaceEntry]:
        """
        Represents the Source Addresses from their interface IDs/IP Addresses for the test:
         - DEFAULT: no source address is forced on the test. The source IP address is selected
          automatically based on the standard routing rules.<br>
          On a cluster, if the Physical Interface that routes the ping packet out has an NDI (Node
          Dedicated IP Address), this address is used as the source address. Otherwise, the NDI
          selected as Default IP for Outgoing Traffic is used.
         - A single Physical Interface, a VLAN Interface, a Modem Interface (Single Firewalls only),
          an ADSL Interface (single firewalls only), or an SSID Interface (Single Firewalls only).
          If the Node ID selection is ALL, each node uses the IP address of the selected interface
          as the source IP address for the test. If a single node is selected in Node ID on a
          cluster, the source address and the multiping test itself apply to that node only.
        :rtype: list[EnabledInterfaceEntry]
        """
        return [EnabledInterfaceEntry(entry) for entry in self.data.get("enabled_interface", [])]

    @enabled_interfaces.setter
    def enabled_interfaces(self, value: list[EnabledInterfaceEntry]) -> None:
        self.data.set("enabled_interface", None)
        if value:
            enabled_interfaces = []
            for enabled_interface in value:
                enabled_interfaces.append(enabled_interface.data)
            self.data.set("enabled_interface", enabled_interfaces)


class LinkUsageExceptionRules(NestedDict):
    def __init__(self, destinations: Any = None, services: Any = None, sources: Any = None,
                 isp_link_ref: Any = None, comment: Optional[str] = None) -> None:
        """
        LinkUsageExceptionRules
        Set to engine if Link usage profile is set to engine in routing

        :param list destinations: list of destinations
        :param list services: list of services
        :param list sources: list of sources
        :param object isp_link: object type can be static netlink, dynamic netlink,
         Outbound multilink or Server Pool
        :param str comment: simple comment
        Example:

        :raises Errors
        :return: None
        """
        if sources == "any":
            sources = {"any": True}
        if destinations == "any":
            destinations = {"any": True}
        if services == "any":
            services = {"any": True}
        if type(sources) is list:
            value_list = []
            for val in sources:
                v = element_resolver(val)
                value_list.append(v)
            sources_json = {}
            sources_json.update(src=value_list)
            sources = sources_json
        if type(services) is list:
            value_list = []
            for val in services:
                v = element_resolver(val)
                value_list.append(v)
            services_json = {}
            services_json.update(service=value_list)
            services = services_json
        if type(destinations) is list:
            value_list = []
            for val in destinations:
                v = element_resolver(val)
                value_list.append(v)
            destinations_json = {}
            destinations_json.update(dst=value_list)
            destinations = destinations_json
        dc = dict(
            sources=sources,
            destinations=destinations,
            services=services,
            isp_link_ref=element_resolver(isp_link_ref),
            comment=comment
        )
        super(LinkUsageExceptionRules, self).__init__(data=dc)

    @property
    def isp_link_ref(self) -> Any:
        """
        isp_link
        :rtype: isp_link
        """
        return (
            self.get("isp_link_ref")
         )

    @isp_link_ref.setter
    def isp_link_ref(self, value: Any) -> None:
        self.update(isp_link_ref=value)

    @property
    def comment(self) -> Optional[str]:
        """
        comment.
        :rtype: str
        """
        return self.get("comment")

    @comment.setter
    def comment(self, value: Optional[str]) -> None:
        self.update(comment=value)

    @property
    def destinations(self) -> Any:
        return self.get("destinations")

    @destinations.setter
    def destinations(self, value: Any) -> None:
        if value == "any":
            value = {"any": "true"}
            self.update(destinations=value)
        else:
            value_list = []
            for val in value:
                v = element_resolver(val)
                value_list.append(v)
            destinations_json = {}
            destinations_json(dst=value_list)
            self.update(destinations=destinations_json)

    @property
    def sources(self) -> Any:
        return self.get("sources")

    @sources.setter
    def sources(self, value: Any) -> None:
        if value == "any":
            value = {"any": "true"}
        self.update(sources=value)

    @property
    def services(self) -> Any:
        return self.get("services")

    @services.setter
    def services(self, value: Any) -> None:
        if value == "any":
            value = {"any": "true"}
        self.update(services=value)


class CloudGroup(Element):
    """
    Represents the Cloud Auto-Scaled Group.
    A list of Cloud Firewalls.
    """
    typeof = 'scale_set'

    @classmethod
    def create(
        cls,
        name: str,
        elements: list[Any] = [],
        is_monitored: bool = False,
        comment: Optional[str] = None,
    ) -> CloudGroup:
        """
        Create will return the Cloud Auto-Scaled Group configuration as a dict that is a
        representation of the Cloud Auto-Scaled Group.

        :param name: name of the Cloud Auto-Scaled Group
        :param elements: the list of Cloud Firewalls beloging to the Cloud Auto-Scaled Group
        :param is_monitored: Flag to specify if the Cloud Auto-Scaled Group needs to be monitored
        :param comment: comment of the Cloud Auto-Scaled Group
        """
        json = {
            "name": name,
        }
        cloud_fw_uris = []
        if elements:
            for element in elements:
                cloud_fw_uris.append(element.href if isinstance(Engine, element)
                                     else element)

        json.update(is_monitored=is_monitored,
                    element=cloud_fw_uris, comment=comment)  # Add rest of kwargs

        return ElementCreator(cls, json)

    @property
    def is_monitored(self) -> bool:
        return getattr(self, "is_monitored", False)

    @property
    def elements(self) -> list[Any]:
        return [Element.from_href(element) for element in getattr(self, "element", [])]

    def clean(self) -> None:
        """
        Removes all inactive Cloud FW from scale set.
        If no active Cloud Firewalls are there, the Cloud Auto-Scaled Group is removed.
        """
        self.make_request(
            EngineCommandFailed,
            method="delete",
            resource="clean",
            headers={"Etag": self.etag}
        )

    def refresh(
            self,
            timeout: int = 3,
            wait_for_finish: bool = False,
            preserve_connections: bool = True,
            generate_snapshot: bool = True,
            **kw: Any,
    ) -> TaskOperationPoller:
        """
        Refresh existing policy on specified Cloud Auto-Scaled Group. This is an asynchronous
        call that will return a 'follower' link that can be queried to
        determine the status of the task.
        ::

            poller = engine.refresh(wait_for_finish=True)
            while not poller.done():
                poller.wait(5)
                print('Percentage complete {}%'.format(poller.task.progress))

        :param int timeout: timeout between queries
        :param bool wait_for_finish: poll the task waiting for status
        :param bool preserve_connections: flag to preserve connections (True by default)
        :param bool generate_snapshot: flag to generate snapshot (True by default)
        :raises TaskRunFailed: refresh failed, possibly locked policy
        :rtype: TaskOperationPoller
        """
        kw.update({"params": {"generate_snapshot": generate_snapshot,
                              "preserve_connections": preserve_connections}})
        return Task.execute(self, "refresh", timeout=timeout, wait_for_finish=wait_for_finish, **kw)

    def upload(
            self,
            policy: Optional[str] = None,
            timeout: int = 5,
            wait_for_finish: bool = False,
            preserve_connections: bool = True,
            generate_snapshot: bool = True,
            **kw: Any,
    ) -> TaskOperationPoller:
        """
        Upload policy to Cloud Auto-Scaled Group. This is used when a new policy is required
        for a Cloud Auto-Scaled Group, or this is the first time a policy is pushed to a
        Cloud Auto-Scaled Group.
        If an engine already has a policy and the intent is to re-push, then
        use :py:func:`refresh` instead.
        The policy argument can use a wildcard * to specify in the event a full
        name is not known::

            engine = Engine('myfw')
            task = engine.upload('Amazon*', wait_for_finish=True)
            for message in task.wait():
                print(message)

        :param str policy: name of policy to upload to Cloud Auto-Scaled Group; if None, current
            policy
        :param bool wait_for_finish: poll the task waiting for status
        :param int timeout: timeout between queries
        :param bool preserve_connections: flag to preserve connections (True by default)
        :param bool generate_snapshot: flag to generate snapshot (True by default)
        :raises TaskRunFailed: upload failed with reason
        :rtype: TaskOperationPoller
        """
        return Task.execute(
            self,
            "upload",
            params={
                "filter": policy,
                "preserve_connections": preserve_connections,
                "generate_snapshot": generate_snapshot,
            },
            timeout=timeout,
            wait_for_finish=wait_for_finish,
            **kw
        )

    @property
    def pending_changes(self) -> PendingChanges:
        """
        Pending changes provides insight into changes on an engine that are
        pending approval or disapproval. Feature requires SMC >= v6.2.

        :raises UnsupportedEngineFeature: SMC version >= 6.2 is required to
            support pending changes
        :rtype: PendingChanges
        """
        if "pending_changes" in self.data.links:
            return PendingChanges(self)
        raise UnsupportedEngineFeature(
            f"Pending changes is an unsupported feature on this engine: {self.type}"
        )


class Engine(Element):
    """
    An engine is the top level representation of a firewall, IPS
    or virtualized software.

    Engine can be referenced directly and will be loaded when attributes
    are accessed::

        >>> from smc.core.engine import Engine
        >>> engine = Engine('testfw')
        >>> print(engine.href)
        http://1.1.1.1:8082/6.1/elements/single_fw/39550

    Generically search for engines of all types::

        >>> list(Engine.objects.all())
        [Layer3Firewall(name=i-06145fc6c59a04335 (us-east-2a)), FirewallCluster(name=sg_vm),
        Layer3VirtualEngine(name=ve-5), MasterEngine(name=master-eng)]

    Or only search for specific engine types::

        >>> from smc.core.engines import Layer3Firewall
        >>> list(Layer3Firewall.objects.all())
        [Layer3Firewall(name=i-06145fc6c59a04335 (us-east-2a))]

    Engine types are defined in :class:`smc.core.engines`.
    """

    typeof = "engine_clusters"

    @classmethod
    def _create(
        cls,
        name: str,
        node_type: str,
        physical_interfaces: list[Any],
        nodes: int = 1,
        nodes_definition: list = [],
        loopback_ndi: Optional[Any] = None,
        log_server_ref: Optional[str] = None,
        domain_server_address: Optional[list] = None,
        enable_antivirus: bool = False,
        enable_gti: bool = False,
        sidewinder_proxy_enabled: bool = False,
        known_host_lists: list = [],
        default_nat: Optional[Any] = None,
        location_ref: Optional[str] = None,
        enable_ospf: Optional[bool] = None,
        ospf_profile: Optional[Any] = None,
        snmp_agent: Optional[Any] = None,
        comment: Optional[str] = None,
        ntp_settings: Optional[Any] = None,
        timezone: Optional[str] = None,
        lldp_profile: Optional[Any] = None,
        link_usage_profile: Optional[Any] = None,
        discard_quic_if_cant_inspect: bool = True,
        ssm_advanced_setting: Optional[Any] = None,
        scan_detection: Optional[Any] = None,
        static_multicast_route: Optional[Any] = None,
        pim_settings: Optional[Any] = None,
        web_authentication: Optional[Any] = None,
        nat64_settings: Optional[Any] = None,
        saml_settings: Optional[Any] = None,
        **kw: Any,
    ) -> dict[str, Any]:
        """
        Create will return the engine configuration as a dict that is a
        representation of the engine. The creating class will also add
        engine specific requirements before constructing the request
        and sending to SMC (which will serialize the dict to json).

        :param name: name of engine
        :param str node_type: comes from class attribute of engine type
        :param dict physical_interfaces: physical interface list of dict
        :param int nodes: number of nodes for engine
        :param list nodes_definition: list of definition for each node
        :param str log_server_ref: href of log server
        :param default_nat: (optional) Whether to enable default NAT for outbound.
          Accepted values are:
           'true': use Default NAT Address for Traffic from Internal Networks |
           'false': don't use Default NAT Address for Traffic from Internal Networks |
           'automatic': use Default NAT Address for Traffic from Internal Networks if the firewall has a default route
        :param list domain_server_address: dns addresses
        :param NTPSettings ntp_settings: ntp settings
        :param LLDPProfile lldp_profile: LLDP Profile represents a set of attributes used for
        configuring LLDP
        :param bool discard_quic_if_cant_inspect: (optional) discard or allow QUIC
         if inspection is not possible
        :param list(SidewinderProxyAdvancedSettings) ssm_advanced_setting: Sidewinder proxy advanced
            settings.
        :param dict,ScanDetection scan_detection: This represents the definition of Scan Detection
            on a NGFW.
        :param list(dict),list(StaticMulticastRoute) static_multicast_route: Represents Firewall
            multicast routing entry for Static/IGMP Proxy multicast routing modes.
        :param PIM/dict pim_settings: This represents the PIM Multicast routing settings.
        :param WebAuthentication/dict web_authentication: This represents the Browser-Based User
            Authentication settings for a NGFW.
        :param Nat64Settings/dict nat64_settings: This represents the NAT64 settings for a NGFW.
        :param list of SamlSettings saml_settings: SAML settings for the Web Authentication.
        """
        node_list = []
        for nodeid in range(1, nodes + 1):  # start at nodeid=1
            node_name = name + " node " + str(nodeid)
            if nodes_definition and nodes_definition.__len__() > 0:
                node_definition = nodes_definition[nodeid-1]
                node_name = node_definition.pop("name", node_name)
                comment = node_definition.pop("comment", None)
                disable = node_definition.pop("disable", False)
                settings = node_definition.pop("external_pki_certificate_settings", None)
                node_list.append(Node._create(node_name, node_type, nodeid, loopback_ndi,
                                              settings,
                                              disable,
                                              comment))
            else:
                node_list.append(Node._create(node_name, node_type, nodeid, loopback_ndi))

        domain_server_list = []
        if domain_server_address:
            for num, server in enumerate(domain_server_address):
                try:
                    domain_server = {"rank": num, "ne_ref": server.href}
                except AttributeError:
                    domain_server = {"rank": num, "value": server}

                domain_server_list.append(domain_server)

        # Set log server reference, if not explicitly provided
        if not log_server_ref and node_type != "virtual_fw_node":
            log_server_ref = LogServer.objects.first().href

        base_cfg = {
            "name": name,
            "nodes": node_list,
            "domain_server_address": domain_server_list,
            "log_server_ref": log_server_ref,
            "physicalInterfaces": physical_interfaces,
        }

        if enable_antivirus:
            antivirus = {
                "antivirus": {
                    "antivirus_enabled": True,
                    "antivirus_update": "daily",
                    "virus_log_level": "stored",
                    "virus_mirror": "update.nai.com/Products/CommonUpdater",
                }
            }
            base_cfg.update(antivirus)

        if enable_gti:
            # gti_settings element replaced since smc 6.6 and api 6.6
            # and since smc 6.7 and api 6.5
            if is_smc_version_less_than_or_equal("6.6") \
                    and is_api_version_less_than_or_equal("6.5"):
                gti = {"gti_settings": {"file_reputation_context": "gti_cloud_only"}}
            else:
                gti = {"file_reputation_settings": {"file_reputation_context": "gti_cloud_only"}}
            base_cfg.update(gti)

        if sidewinder_proxy_enabled:
            base_cfg.update(sidewinder_proxy_enabled=True)
            # We only want to set known host lists when SSM is enabled
            if known_host_lists:
                if isinstance(known_host_lists, list):
                    base_cfg.update(known_host_lists_ref=known_host_lists)
                else:
                    split_known_host_lists = known_host_lists.split(",")
                    base_cfg.update(known_host_lists_ref=split_known_host_lists)

        if default_nat:
            base_cfg.update(default_nat=str(default_nat).lower())

        if location_ref:
            base_cfg.update(location_ref=location_helper(location_ref) if location_ref else None)

        if snmp_agent:
            snmp_agent_ref = SNMPAgent(snmp_agent.pop("snmp_agent_ref")).href
            base_cfg.update(snmp_agent_ref=snmp_agent_ref, **snmp_agent)

        if enable_ospf:
            if not ospf_profile:  # get default profile
                ospf_profile = OSPFProfile("Default OSPFv2 Profile").href
            ospf = {
                "dynamic_routing": {"ospfv2": {"enabled": True, "ospfv2_profile_ref": ospf_profile}}
            }
            base_cfg.update(ospf)

        if link_usage_profile:
            if isinstance(LinkUsageProfile, link_usage_profile):
                base_cfg.update(link_usage_profile_ref=link_usage_profile.href)
            # is already a href
            else:
                base_cfg.update(link_usage_profile_ref=link_usage_profile)

        if ntp_settings is not None:
            if isinstance(ntp_settings, dict):
                base_cfg.update(ntp_settings=ntp_settings)
            else:
                base_cfg.update(ntp_settings.data)

        if timezone is not None:
            # check timezone is valid
            if timezone in pytz.all_timezones:
                timezone = {"timezone": timezone}
                base_cfg.update(timezone)
            else:
                raise CreateElementFailed(
                    "Timezone is invalid:" + timezone
                )

        if min_smc_version("6.6") and lldp_profile is not None:
            if isinstance(lldp_profile, LLDPProfile):
                base_cfg.update(lldp_profile_ref=lldp_profile.href)
            # is already a href
            else:
                base_cfg.update(lldp_profile_ref=lldp_profile)

        if min_smc_version("7.0"):
            if discard_quic_if_cant_inspect:
                discard_quic = {"discard_quic_if_cant_inspect": "true"}
            else:
                discard_quic = {"discard_quic_if_cant_inspect": "false"}
            base_cfg.update(discard_quic)
        if ssm_advanced_setting:
            base_cfg.update(ssm_advanced_setting=[setting.data for setting in ssm_advanced_setting])

        if scan_detection:
            scan_detection = scan_detection.data if isinstance(scan_detection,
                                                               NestedDict) else scan_detection
            base_cfg.update(scan_detection=scan_detection)

        if static_multicast_route:
            static_multicast_route = [route.data if isinstance(route,
                                                               NestedDict) else route for route in
                                      static_multicast_route]
            base_cfg.update(static_multicast_route=static_multicast_route)

        if pim_settings:
            pim_settings = pim_settings.data \
                if isinstance(pim_settings, PIMSettings) else pim_settings
            base_cfg.update(pim_settings=pim_settings)

        if web_authentication:
            web_authentication = web_authentication.data \
                if isinstance(web_authentication, WebAuthentication) else web_authentication
            base_cfg.update(web_authentication=web_authentication)

        if nat64_settings:
            nat64_settings = nat64_settings.data \
                if isinstance(nat64_settings, Nat64Settings) else nat64_settings
            base_cfg.update(ipv6_transition_mechanism=nat64_settings)

        if (is_smc_version_more_than_or_equal("7.4.0")
                and saml_settings and isinstance(saml_settings, list)):
            base_cfg["enable_saml_for_bba"] = True
            base_cfg["saml_settings"] = [
                s.expand() for s in saml_settings
            ]

        base_cfg.update(kw, comment=comment)  # Add rest of kwargs
        return base_cfg

    @property
    def type(self) -> str:
        if not self._meta:
            self.href
        return self._meta.type

    @property
    def version(self) -> Optional[str]:
        """
        Version of this engine. Can be none if the engine has not been
        initialized yet.

        :rtype: str or None
        """
        return getattr(self, "engine_version", None)

    @property
    def installed_policy(self) -> Optional[str]:
        """
        Return the name of the policy installed on this engine. If
        no policy, None will be returned.

        :rtype: str or None
        """
        for node in self.nodes:
            return node.health.installed_policy

    def rename(self, name: str) -> None:
        """
        Rename the firewall engine, nodes, and internal gateway (VPN gw)

        :return: None
        """
        for node in self.nodes:
            node.rename(name)
        self.update(name=name)
        self.vpn.rename(name)

    @property
    def log_server(self) -> Optional[LogServer]:
        """
        Log server for this engine.

        :return: The specified log server
        :rtype: LogServer
        """
        return Element.from_href(self.log_server_ref)  # type: ignore[return-value]

    @log_server.setter
    def log_server(self, value: Any) -> None:
        self.data.update(log_server_ref=location_helper(value))

    @property
    def location(self) -> Optional[Location]:
        """
        The location for this engine. May be None if no specific
        location has been assigned.

        :param value: location to assign engine. Can be name, str href,
            or Location element. If name, it will be automatically created
            if a Location with the same name doesn't exist.
        :raises UpdateElementFailed: failure to update element
        :return: Location element or None
        """
        location = Element.from_href(self.location_ref)
        if location and location.name == "Default":
            return None
        return location  # type: ignore[return-value]

    @location.setter
    def location(self, value: Any) -> None:
        self.data.update(location_ref=location_helper(value))

    @property
    def geolocation(self) -> Optional[Geolocation]:
        """
        Return the geolocation for the given engine. This attribute requires
        at least SMC version >= 6.5.x. If no geolocation is assigned or the
        SMC is not a correct version this will return None.
        If setting a new geolocation, call update() after modification.

        Example::

            >>> from smc.elements.other import Geolocation
            >>> engine = Engine('azure')

            >>> geo = Geolocation.create(name='MyGeo', latitude='44.97997', longitude='-93.26384')
            >>> geo
            Geolocation(name=MyGeo)
            >>> engine.geolocation = geo
            >>> engine.update()
            >>> engine.geolocation
            Geolocation(name=MyGeo)

        :param Geolocation value: Geolocation to assign engine. Can be str
            href or type Geolocation element.
        :rtype: Geolocation or None
        """
        return self.from_href(getattr(self, "geolocation_ref", None))  # type: ignore[return-value]

    @geolocation.setter
    def geolocation(self, value: Any) -> None:
        self.data.update(geolocation_ref=element_resolver(value))

    @property
    def default_nat(self) -> DefaultNAT:
        """
        Configure default nat on the engine. Default NAT provides automatic
        NAT without the requirement to add specific NAT rules. This is a
        more common configuration for outbound traffic. Inbound traffic
        will still require specific NAT rules for redirection.

        :rtype: DefaultNAT
        """
        if "default_nat" in self.data:
            return DefaultNAT(self)
        raise UnsupportedEngineFeature("This engine type does not support default NAT.")

    @property
    def dns(self) -> RankedDNSAddress:
        """
        Current DNS entries for the engine. Add and remove DNS entries.
        This resource is iterable and yields instances of
        :class:`smc.core.addon.DNSEntry`.
        Example of adding entries::

            >>> from smc.elements.servers import DNSServer
            >>> server = DNSServer.create(name='mydnsserver', address='10.0.0.1')
            >>> engine.dns.add(['8.8.8.8', server])
            >>> engine.update()
            'http://172.18.1.151:8082/6.4/elements/single_fw/948'
            >>> list(engine.dns)
            [DNSEntry(rank=0,value=8.8.8.8,ne_ref=None),
             DNSEntry(rank=1,value=None,ne_ref=DNSServer(name=mydnsserver))]

        :rtype: RankedDNSAddress
        """
        return RankedDNSAddress(self.data.get("domain_server_address", []))

    @property
    def snmp(self) -> SNMP:
        """
        SNMP engine settings. SNMP is supported on all engine types,
        however can be enabled only on NDI interfaces (interfaces that
        have assigned addresses).

        :rtype: SNMP
        """
        if not self.type.startswith("virtual"):
            return SNMP(self)
        raise UnsupportedEngineFeature(
            "SNMP is not supported directly on this engine type. If this "
            "is a virtual engine, SNMP is configured on the master engine."
        )

    @property
    def ntp_settings(self) -> NTPSettings:
        """
        NTP settings definition for the engine
        :rtype: NTPSettings
        """
        return NTPSettings(self)

    @property
    def automatic_rules_settings(self) -> AutomaticRulesSettings:
        """
        Represents the container for all automatic rules settings for a cluster.
        Example of using automatic rules settings:
            >>> engine = Engine("testme")
            >>> automatic_rules_settings=engine.automatic_rules_settings
            >>> update_automatic_rules_settings(allow_auth_traffic=False, allow_no_nat=False)
            >>> engine.update()
            >>> engine.automatic_rules_settings.allow_auth_traffic
                False
            >>> engine.automatic_rules_settings.allow_listening_interfaces_to_dns_relay_port
                True
        :rtype: AutomaticRulesSettings
        """
        return AutomaticRulesSettings(self)

    @property
    def connection_timeout(self) -> IdleTimeout:
        """
        This is definition of timeout by protocol or by TCP connection state. You can define general
        timeouts for removing idle connections from the state table, including non-TCP
        communications that are handled like connections. The timeout prevents wasting engine
        resources on storing information about abandoned connections. Timeouts are a normal way to
        clear traffic information with protocols that have no closing mechanism.Timeouts do not
        affect active connections. The connections are kept in the state table as long as the
        interval of packets within a connection is shorter than the timeouts set.
        Example of using idle time out settings:
            >>> engine = Engine("testme")
            >>> connection_timeout=engine.connection_timeout
            >>> connection_timeout.add('tcp_syn_seen',120)
            >>> engine.connection_timeout.data
                {'connection_timeout': [{'protocol': 'tcp', 'timeout': 1800}, {'protocol': 'udp',
                'timeout': 50}, {'protocol': 'icmp', 'timeout': 5}, {'protocol': 'other', 'timeout':
                 180}, {'protocol': 'tcp_syn_seen', 'timeout': 120}]}
            >>> engine.update()
            >>> engine.connection_timeout.data
            >>> connection_timeout.remove('tcp_syn_seen')
                {'connection_timeout': [{'protocol': 'tcp', 'timeout': 1800}, {'protocol': 'udp',
                'timeout': 50}, {'protocol': 'icmp', 'timeout': 5}, {'protocol': 'other', 'timeout':
                 180}]}
        :rtype: IdleTimeout
        """
        return IdleTimeout(self)

    @property
    def local_log_storage(self) -> LocalLogStorageSettings:
        """
        Local Log Storage Settings for not virtual engines.
        Example of using local log storage settings:
            >>> engine = Engine("testme")
            >>> local_log_storage=engine.local_log_storage
            >>> local_log_storage.local_log_storage_activated
                True
            >>> local_log_storage.lls_max_time
                10
            >>> local_log_storage.update(lls=20_max_time)
            >>> engine.update()
            >>> local_log_storage=engine.local_log_storage
            >>> local_log_storage.lls_max_time
                20
        :rtype LocalLogStorageSettings
        """
        if self.type == "virtual_fw":
            raise UnsupportedEngineFeature(
                "Local Log Storage settings are not supported on virtual engines.")

        return LocalLogStorageSettings(self)

    @property
    def log_moderation(self) -> LogModeration:
        """
        This is the definition of Log Compression for the engine or for an interface. You can also
        configure Log Compression to save resources on the engine. By default, each generated
        Antispoofing and Discard log entry is logged separately and displayed as a separate entry in
        the Logs view. Log Compression allows you to define the maximum number of separately logged
        entries.When the defined limit is reached, a single Antispoofing log entry or Discard log
        entry is logged. The single entry contains information on the total number of the generated
        Antispoofing log entries or Discard log entries. After this, logging returns to normal and
        all the generated entries are once more logged and displayed separately.
        Example of using log moderation settings:
            >>> engine = Engine("testme")
            >>> log_moderation_obj=engine.log_moderation
            >>> log_moderation_obj.get(1)["rate"]
                100
            >>> log_moderation_obj.get(1)["burst"]
                1000
            >>> log_moderation_obj.add(rate=200,burst=1100,log_event=2)
            >>> engine.update(log_spooling_policy='discard')
            >>> log_moderation_obj=engine.log_moderation
            >>> log_moderation_obj.get(2)["rate"]
                200
            >>> log_moderation_obj.get(2)["burst"]
                1100
        :rtype LogModeration
        """
        return LogModeration(self)

    @property
    def antivirus(self) -> AntiVirus:
        """
        AntiVirus engine settings. Note that for virtual engines
        the AV settings are configured on the Master Engine.
        Get current status::

            engine.antivirus.status

        :raises UnsupportedEngineFeature: Invalid engine type for AV
        :rtype: AntiVirus
        """
        if not self.type.startswith("virtual"):
            return AntiVirus(self)
        raise UnsupportedEngineFeature(
            "Antivirus is not supported directly on this engine type. If this "
            "is a virtual engine, AV is configured on the master engine."
        )

    @property
    def file_reputation(self) -> FileReputation:
        """
        File reputation status on engine. Note that for virtual engines
        the AV settings are configured on the Master Engine.
        Get current status::

            engine.file_reputation.status

        :raises UnsupportedEngineFeature: Invalid engine type for file rep
        :rtype: FileReputation
        """
        if not self.type.startswith("virtual"):
            return FileReputation(self)
        raise UnsupportedEngineFeature(
            "GTI should be enabled on the Master Engine not directly on the " "virtual engine."
        )

    @property
    def sidewinder_proxy(self) -> SidewinderProxy:
        """
        Configure Sidewinder Proxy settings on this engine. Sidewinder
        proxy is supported on layer 3 engines and require SMC and engine
        version >= 6.1.
        Get current status::

            engine.sidewinder_proxy.status

        :raises UnsupportedEngineFeature: requires layer 3 engine
        :rtype: SidewinderProxy
        """
        if "sidewinder_proxy_enabled" in self.data:
            return SidewinderProxy(self)
        raise UnsupportedEngineFeature(
            "Sidewinder Proxy requires a layer 3 engine and version >= v6.1."
        )

    @property
    def known_host_lists(self) -> SSHKnownHostsLists:
        """
        Configure SSH known host lists on the engine. Can only be set
        if Sidewinder Proxy is enabled.

        :raises MissingRequiredInput: requires sidewinder proxy to be enabled
        :rtype: KnownHostLists
        """
        if self.data["sidewinder_proxy_enabled"] and "known_host_lists_ref" in self.data:
            return SSHKnownHostsLists(self)
        raise MissingRequiredInput(
            "SSH Known Host Lists require Sidewinder Proxy to be enabled."
        )

    @property
    def url_filtering(self) -> UrlFiltering:
        """
        Configure URL Filtering settings on the engine.
        Get current status::

            engine.url_filtering.status

        :raises UnsupportedEngineFeature: not supported on virtual engines
        :rtype: UrlFiltering
        """
        if not self.type.startswith("virtual"):
            return UrlFiltering(self)
        raise UnsupportedEngineFeature(
            "Enabling URL Filtering should be done on the Master Engine, not "
            "directly on the virtual engine."
        )

    @property
    def ztna_connector(self) -> ZTNAConnector:
        if not min_smc_version("7.0"):
            raise UnsupportedEngineFeature("Need at least 7.0 version of the SMC")

        if is_smc_version_more_than_or_equal("7.5.0"):
            raise UnsupportedEngineFeature("From SMC 7.5.0, ZTNA add-on support ends")

        if self.type not in ("single_fw", "fw_cluster", "virtual_fw"):
            raise UnsupportedEngineFeature(
                "Enabling ZTNA Connector should be done only on single_fw, "
                "fw_cluster or virtual_fw")

        return ZTNAConnector(self)

    @property
    def sandbox(self) -> Sandbox:
        """
        Configure sandbox settings on the engine.
        Get current status::

            engine.sandbox.status

        :raises UnsupportedEngineFeature: not supported on virtual engine
        :rtype: Sandbox
        """
        if not self.type.startswith("virtual"):
            return Sandbox(self)
        raise UnsupportedEngineFeature(
            "Enabling sandbox should be done on the Master Engine, not "
            "directly on the virtual engine."
        )

    @property
    def endpoint_integration(self) -> EndpointIntegration:
        """
        Endpoint Integration status on engine. Note that for master engines
        the endpoint integrations settings are configured on Virtual Engines.
        Get current status::

            engine.endpoint_integration.status

        :raises UnsupportedEngineFeature: Invalid engine type for file rep
        :rtype: EndpointIntegration
        """
        if not self.type.startswith("master"):
            return EndpointIntegration(self)
        raise UnsupportedEngineFeature(
            "Endpoint Integration cannot be configured on master engine"
        )

    @property
    def test_entries(self) -> list[TestEntry]:
        """
        Represents the list of TestEntry.
        """
        tests = self.data.get("tests", [])
        result = []
        for test in tests:
            if "multiping_test" in test:
                result.append(MultipingTest(test["multiping_test"]))
            elif "external_test" in test:
                result.append(ExternalTest(test["external_test"]))
            elif "inline_test" in test:
                result.append(InlinePairlinkSpeedTest(test["inline_test"]))
            elif "filesystemspace_test" in test:
                result.append(FileSystemTest(test["filesystemspace_test"]))
            elif "freeswapspace_test" in test:
                result.append(SwapFreeTest(test["freeswapspace_test"]))
            elif "linkstatus_test" in test:
                result.append(LinkStatusTest(test["linkstatus_test"]))
        return result

    def add_test_entry(self, test_entry: TestEntry) -> None:
        """
        Adds a new test entry.
        """
        self.data.get("tests", []).append({test_entry.typeof: test_entry.data})

    def set_test_entries(self, test_entries: list[TestEntry]) -> None:
        """
        Sets test entries
        """
        self.data.data["tests"] = None
        if test_entries:
            new_tests = []
            for test in test_entries:
                new_tests.append({test.typeof: test.data})
            self.data.data["tests"] = new_tests

    @property
    def dns_relay(self) -> DNSRelay:
        """
        Enable, disable or get status for the DNS Relay Service
        on this engine. You must still separately configure the
        :class:`smc.elements.profiles.DNSRelayProfile` that the
        engine references.

        :raises UnsupportedEngineFeature: unsupported feature on
            this engine type.
        :rtype: DNSRelay
        """
        if "dns_relay_interface" in self.data:
            return DNSRelay(self)
        raise UnsupportedEngineFeature("DNS Relay requires a layer 3 engine and version >= v6.2.")

    @property
    def tls_inspection(self) -> TLSInspection:
        """
        TLS Inspection settings manage certificates assigned to the
        engine for TLS server decryption (inbound) and TLS client
        decryption (outbound). In order to enable either, you must
        first assign certificates to the engine.
        Example of adding TLSServerCredentials to an engine::

            >>> engine = Engine('myfirewall')
            >>> tls = TLSServerCredential('server2.test.local')
            >>> engine.tls_inspection.add_tls_credential([tls])
            >>> engine.tls_inspection.server_credentials
            [TLSServerCredential(name=server2.test.local)]

        :rtype: TLSInspection
        """
        return TLSInspection(self)

    @property
    def client_inspection(self) -> ClientInspection:
        """
        Client TLS Inspection settings manage certificates assigned to the
        engine for TLS client decryption (outbound). In order to enable either, you must
        first assign certificates to the engine.
        Example of adding ClientInspection to an engine::

            >>> engine = Engine('myfirewall')
            >>> tls = ClientInspection('client.test.local')
            >>> engine.client_inspection.enable(tls)
            >>> engine.update()

        :rtype: ClientInspection
        """
        return ClientInspection(self)

    @property
    def ospf(self) -> Any:
        return self.dynamic_routing.ospf

    @property
    def bgp(self) -> Any:
        return self.dynamic_routing.bgp

    @property
    def dynamic_routing(self) -> DynamicRouting:
        """
        Dynamic Routing entry point. Access BGP, OSPF configurations

        :raises UnsupportedEngineFeature: Only supported on layer 3 engines
        :rtype: DynamicRouting
        """
        if "dynamic_routing" in self.data:
            return DynamicRouting(self)
        raise UnsupportedEngineFeature("Dynamic routing is only supported on layer 3 engine types")

    @property
    def pim_settings(self) -> Optional[PIMSettings]:
        """
        PIM Multicast Routing entry point.

        :rtype: PIM, None if not defined
        """
        if "pim_settings" in self.data:
            return PIMSettings(self)
        else:
            return None

    @pim_settings.setter
    def pim_settings(self, value: Any) -> None:
        mode = None if value is None else "pim_ipv4"
        if isinstance(value, PIMSettings):
            self.data.update(multicast_routing_mode=mode,
                             pim_settings=value.data)
        else:
            self.data.update(multicast_routing_mode=mode,
                             pim_settings=value)

    @property
    def l2fw_settings(self) -> Layer2Settings:
        """
        Layer 2 Firewall Settings make it possible for a layer 3 firewall
        to run specified interfaces in layer 2 mode. This requires that
        a layer 2 interface policy is assigned to the engine and that
        inline_l2fw interfaces are created.

        :raises UnsupportedEngineFeature: requires layer 3 engine
        :rtype: Layer2Settings
        """
        if "l2fw_settings" in self.data:
            return Layer2Settings(self)
        raise UnsupportedEngineFeature(
            "Layer2FW settings are only supported on layer 3 engines using "
            "engine and SMC version >= 6.3"
        )

    @property
    def nodes(self) -> Any:
        """
        Return a list of child nodes of this engine. This can be
        used to iterate to obtain access to node level operations
        ::

            >>> print(list(engine.nodes))
            [Node(name=myfirewall node 1)]
            >>> engine.nodes.get(0)
            Node(name=myfirewall node 1)


        :return: nodes for this engine
        :rtype: SubElementCollection(Node)
        """
        resource = sub_collection(self.get_relation("nodes"), Node)
        resource._load_from_engine(self, "nodes")
        return resource

    @property
    def granted_permissions(self) -> Iterator[Optional[AccessControlList]]:
        """
        Retrieve the access control list permissions for this engine instance.
        ::

            >>> from smc.core.engine import Engine
            >>> engine = Engine('myfirewall')
            >>> for x in engine.permissions.granted_permissions:
            ...   print(x)
            ...
            AccessControlList(name=ALL Elements)
            AccessControlList(name=ALL Firewalls)

        :raises UnsupportedEngineFeature: requires SMC version >= 6.1
        :return: access control list permissions
        :rtype: list(AccessControlList)
        """
        acl_list = list(AccessControlList.objects.all())

        def acl_map(elem_href: str) -> Optional[Any]:
            for elem in acl_list:
                if elem.href == elem_href:
                    return elem
            return None
        for acl in self.permissions.granted_access_control_list:
            yield (acl_map(acl))

    @property
    def permissions(self) -> GrantedElementPermissions:
        """
        Retrieve the permissions for this engine instance.
        :rtype: GrantedElementPermissions

        .. note:: This method has changed in fp-NGFW-SMC-python >= 1.0.24 so need to make your
            script compatible with this change."
            .. seealso:: :class:`smc.administration.access_rights.GrantedElementPermissions`.
        """
        data = self.make_request(UnsupportedEngineFeature, resource="permissions")
        return GrantedElementPermissions(data)

    @permissions.setter
    def permissions(self, permissions: Any) -> None:
        """
        Update the permissions for this engine instance.
        Example to update permission:
            >>> algiers = Engine('Algiers')
            >>> all_elements_acl = AccessControlList('ALL Elements').href
            >>> all_fws_acl = AccessControlList('ALL Engines').href
            >>> permissions_object = algiers.permissions
            >>> permissions_object.update(granted_access_control_list=[all_elements_acl,
            >>> all_fws_acl])
            >>> algiers.permissions = permissions_object

        Example to create permission:
            >>> admin_user=list(AdminUser.objects.all())[0]
            >>> admin_domain=list(AdminDomain.objects.all())[0]
            >>> roles=list(Role.objects.all())
            >>> cluster_ref = algiers.href
            >>> all_elements_acl = AccessControlList('ALL Elements')
            >>> all_fws_acl = AccessControlList('ALL Engines')
            >>> role_container = [AdminRoleContainer.create(roles=roles,
            >>> granted_domain=admin_domain,admin=admin_user)]
            >>> permissions_object = GrantedElementPermissions.create(cluster_ref=cluster_ref,
            >>> granted_access_control_list=[all_elements_acl, all_fws_acl],
            >>> role_containers=role_container)
            >>> algiers.permissions = permissions_object

        .. note:: This method has changed in fp-NGFW-SMC-python >= 1.0.24, so need to make your
            script compatible with this change."
        .. seealso:: :py:class:`smc.administration.access_rights.GrantedElementPermissions` and
                     :py:class:`smc.administration.access_rights.AdminRoleContainer`

        :param permissions: permissions object
        """
        if is_smc_version_equal("7.0"):
            raise UpdateElementFailed("Update permission is not supported in smc 7.0.")
        etag = self.make_request(UnsupportedEngineFeature, resource="permissions",
                                 raw_result=True).etag.strip('"')
        self.make_request(UnsupportedEngineFeature, resource="permissions", method="update",
                          json=permissions.data, etag=etag)

    @property
    def pending_changes(self) -> PendingChanges:
        """
        Pending changes provides insight into changes on an engine that are
        pending approval or disapproval. Feature requires SMC >= v6.2.

        :raises UnsupportedEngineFeature: SMC version >= 6.2 is required to
            support pending changes
        :rtype: PendingChanges
        """
        if "pending_changes" in self.data.links:
            return PendingChanges(self)
        raise UnsupportedEngineFeature(
            "Pending changes is an unsupported feature on this engine: {}".format(self.type)
        )

    @property
    def lbfilters(self) -> list[LBFilter]:
        """
        Load balancing filter list
        :raises UnsupportedEngineFeature: Invalid engine type
        :rtype: list LBFilter
        """
        if self.type.endswith("cluster"):
            return [LBFilter(**lbfilter) for lbfilter in self.data.data["lbfilter"]]
        raise UnsupportedEngineFeature(
            "Available only for cluster engine"
        )

    @lbfilters.setter
    def lbfilters(self, lbfilter: Any) -> None:
        """
        Update the lbfilter list for this engine instance.
        Load balancing filter list
        :param list LBFilter lbfilter: Load balancing filter list
        :raises UnsupportedEngineFeature: Invalid engine type
        """
        if self.type.endswith("cluster"):
            self.data.data["lbfilter"] = []
            for filter in lbfilter:
                self.data.data["lbfilter"].append(filter.data)
        else:
            raise UnsupportedEngineFeature(
                "Available only for cluster engine"
            )

    @property
    def lbfilter_useports(self) -> bool:
        """
        Load Balancing Filter use ports
        :raises UnsupportedEngineFeature: Invalid engine type
        :rtype: bool
        """
        if self.type.endswith("cluster"):
            return self.data.data["lbfilter_useports"]
        raise UnsupportedEngineFeature(
            "Available only for cluster engine"
        )

    @lbfilter_useports.setter
    def lbfilter_useports(self, lbfilter_useports: Any) -> None:
        """
        Update the lbfilter_useports value for this engine instance.
        :param bool useports: the use ports value
        """
        if self.type.endswith("cluster"):
            self.data.data["lbfilter_useports"] = lbfilter_useports
        else:
            raise UnsupportedEngineFeature(
                "Available only for cluster engine"
            )

    def alias_resolving(self) -> Iterator[Alias]:
        """
        Alias definitions with resolved values as defined on this engine.
        Aliases can be used in rules to simplify multiple object creation
        ::

            fw = Engine('myfirewall')
            for alias in fw.alias_resolving():
                print(alias, alias.resolved_value)
            ...
            (Alias(name=$$ Interface ID 0.ip), [u'10.10.0.1'])
            (Alias(name=$$ Interface ID 0.net), [u'10.10.0.0/24'])
            (Alias(name=$$ Interface ID 1.ip), [u'10.10.10.1'])

        :return: generator of aliases
        :rtype: Alias
        """
        alias_list = list(Alias.objects.all())
        for alias in self.make_request(resource="alias_resolving"):
            yield Alias._from_engine(alias, alias_list)

    def blacklist(self, src: str, dst: str, duration: int = 3600, **kw: Any) -> None:
        """
        Add blacklist entry to engine node by name. For blacklist to work,
        you must also create a rule with action "Apply Blacklist".

        :param src: source address, with cidr, i.e. 10.10.10.10/32 or 'any'
        :param dst: destination address with cidr, i.e. 1.1.1.1/32 or 'any'
        :param int duration: how long to blacklist in seconds
        :raises EngineCommandFailed: blacklist failed during apply
        :return: None

        .. note:: This method requires SMC version >= 6.4 and SMC version <7.0
        since this version, "blacklist" is renamed "block_list"
        """

        json_bl_entry = prepare_blacklist(src, dst, duration, **kw)
        if not is_api_version_less_than_or_equal("6.3"):
            json_bl_entry = {"entries": [json_bl_entry]}

        if is_api_version_less_than("7.0"):
            resource = "blacklist"
        else:
            resource = "block_list"

        self.make_request(
            EngineCommandFailed,
            method="create",
            resource=resource,
            json=json_bl_entry,
        )

    def block_list(self, src: str, dst: str, duration: int = 3600, **kw: Any) -> None:
        """
        Add block_list entry to engine node by name. For block_list to work,
        you must also create a rule with action "Apply Blocklist".

        :param src: source address, with cidr, i.e. 10.10.10.10/32 or 'any'
        :param dst: destination address with cidr, i.e. 1.1.1.1/32 or 'any'
        :param int duration: how long to block list in seconds
        :raises EngineCommandFailed: block list failed during apply
        :return: None
        .. note:: This method requires SMC version >= 7.0
        """

        json_bl_entry = prepare_block_list(src, dst, duration, **kw)
        if not is_api_version_less_than_or_equal("6.3"):
            json_bl_entry = {"entries": [json_bl_entry]}

        self.make_request(
            EngineCommandFailed,
            method="create",
            resource="block_list",
            json=json_bl_entry,
        )

    def block_list_bulk(self, block_list: Any) -> None:
        """
        Add block_list entries to the engine node in bulk. For block_list to work,
        you must also create a rule with action "Apply Blocklist".
        First create your block_list entries using :class:`smc.elements.other.Blocklist`
        then provide the block_list to this method.

        :param Blocklist block_list : pre-configured block_list entries

        .. note:: This method requires SMC version >= 7.0
        """
        self.make_request(
            EngineCommandFailed, method="create", resource="block_list", json=block_list.entries
        )

    def blacklist_bulk(self, block_list: Any) -> None:
        """
        Add block list entries to the engine node in bulk. For block list to work,
        you must also create a rule with action "Apply Block List".
        First create your block_list entries using :class:`smc.elements.other.Blacklist`
        then provide the block list to this method.

        :param Blacklist block_list : pre-configured block list entries

        .. note:: This method requires SMC version >= 6.4 and SMC version <7.0
        since this version, "blacklist" is renamed "block_list"
        """
        if is_api_version_less_than("7.0"):
            resource = "blacklist"
        else:
            resource = "block_list"

        self.make_request(EngineCommandFailed,
                          method="create",
                          resource=resource,
                          json=block_list.entries)

    def block_list_flush(self) -> None:
        """
        Flush entire block list for engine

        :raises EngineCommandFailed: flushing block list failed with reason
        :return: None
        .. note:: This method requires SMC version >= 7.0
        """
        self.make_request(EngineCommandFailed, method="delete", resource="flush_block_list")

    def blacklist_flush(self) -> None:
        """
        Flush entire blacklist for engine

        :raises EngineCommandFailed: flushing blacklist failed with reason
        :return: None
        .. note:: This method requires SMC version < 7.0
        since this version, "blacklist" is renamed "block_list"
        """
        if is_api_version_less_than("7.0"):
            self.make_request(EngineCommandFailed, method="delete", resource="flush_blacklist")
        else:
            self.make_request(EngineCommandFailed, method="delete", resource="flush_block_list")

    def block_list_show(self, **kw: Any) -> Iterator[Any]:
        """
        .. versionadded:: 0.5.6
            Requires pip install smc-python-monitoring

        Block list show requires that you install the smc-python-monitoring
        package. To obtain Blocklist entries from the engine you need to
        use this extension to plumb the websocket to the session. If you
        need more granular controls over the block_list such as filtering by
        source and destination address, use the smc-python-monitoring
        package directly.
        Blocklist entries that are returned from this generator have a
        delete() method that can be called to simplify removing entries.
        A simple query would look like::

            for bl_entry in engine.block_list_show():
                print(bl_entry)

        :param kw: keyword arguments passed to block list query. Common setting
            is to pass max_recv=20, which specifies how many "receive" batches
            will be retrieved from the SMC for the query. At most, 200 results
            can be returned in a single query. If max_recv=5, then 1000 results
            can be returned if they exist. If less than 1000 events are available,
            the call will be blocking until 5 receives has been reached.
        :return: generator of results
        :rtype: :class:`smc_monitoring.monitors.block_list.BlockListQuery`
        """
        try:
            from smc_monitoring.monitors.block_list import BlockListQuery
        except ImportError:
            pass
        else:
            query = BlockListQuery(self.name)
            for record in query.fetch_as_element(**kw):
                yield record

    def blacklist_show(self, **kw: Any) -> Iterator[Any]:
        """
        .. versionadded:: 0.5.6
            Requires pip install smc-python-monitoring

        Blacklist show requires that you install the smc-python-monitoring
        package. To obtain Blacklist entries from the engine you need to
        use this extension to plumb the websocket to the session. If you
        need more granular controls over the blacklist such as filtering by
        source and destination address, use the smc-python-monitoring
        package directly.
        Blacklist entries that are returned from this generator have a
        delete() method that can be called to simplify removing entries.
        A simple query would look like::

            for bl_entry in engine.blacklist_show():
                print(bl_entry)

        :param kw: keyword arguments passed to blacklist query. Common setting
            is to pass max_recv=20, which specifies how many "receive" batches
            will be retrieved from the SMC for the query. At most, 200 results
            can be returned in a single query. If max_recv=5, then 1000 results
            can be returned if they exist. If less than 1000 events are available,
            the call will be blocking until 5 receives has been reached.
        :return: generator of results
        :rtype: :class:`smc_monitoring.monitors.blacklist.BlacklistEntry`

        .. note:: This method requires SMC version < 7.0
        since this version, "blacklist" is renamed "block_list"
        """
        try:
            from smc_monitoring.monitors.blacklist import BlacklistQuery
        except ImportError:
            pass
        else:
            if is_api_version_less_than("7.0"):
                query = BlacklistQuery(self.name)
            else:
                query = BlockListQuery(self.name)

            for record in query.fetch_as_element(**kw):
                yield record

    def remove_alternative_policies(self) -> None:
        """
        Remove all alternative policies on engine.
        """
        self.update(href=self.get_relation("remove_alternative_policies"), etag=None)

    @property
    def link_usage_exception_rules(self) -> list[LinkUsageExceptionRules]:
        """
        A collection of link_usage_exception_rules

        :rtype: list(LinkUsageExceptionRules)
        """
        return [LinkUsageExceptionRules(**nc) for nc in self.data.get("link_usage_exception_rules",
                                                                      [])]

    def add_link_usage_exception_rules(self, link_usage_exception_rules: list[LinkUsageExceptionRules]) -> None:
        """
        Add link_usage_exception_rules/s to this engine.

        :param link_usage_exception_rules: link_usage_exception_rules/s to add to engine
        :type link_usage_exception_rules: list(link_usage_exception_rules)
        :raises UpdateElementFailed: failed updating engine
        :return: None
        """
        if "link_usage_exception_rules" not in self.data:
            self.data["link_usage_exception_rules"] = {"link_usage_exception_rules": []}

        for p in link_usage_exception_rules:
            self.data["link_usage_exception_rules"].append(p.data)
        self.update()

    def remove_link_usage_exception_rules(self, link_usage_exception_rules: LinkUsageExceptionRules) -> bool:
        """
        Remove a link_usage_exception_rules from this engine.

        :param link_usage_exception_rules link_usage_exception_rules: element to remove
        :return: remove element if it exists and return bool
        :rtype: bool
        """
        _link_usage_exception_rules = []
        changed = False
        for nf in self.link_usage_exception_rules:
            if nf != link_usage_exception_rules:
                _link_usage_exception_rules.append(nf.data)
            else:
                changed = True

        if changed:
            self.data["link_usage_exception_rules"] = _link_usage_exception_rules
            self.update()

        return changed

    def query_route(self, source_ref: Optional[str] = None, destination_ref: Optional[str] = None,
                    source_ip: Optional[str] = None, destination_ip: Optional[str] = None) -> list[Routing]:
        """
        Allows querying a route for the specific supported engine Options:
        A. Using Query Parameters:
            source_ip: the IP Address A.B.C.D corresponding to the source query ip address.
            destination_ip: the IP Address A.B.C.D corresponding to the destination query ip address
        B. Using payload to be able to specify source network element uri
            and/or destination network element uri.
        Find route for source to destination using ip address
            >>> engine = Engine('Plano')
            >>> engine.query_route(source_ip='0.0.0.0', destination_ip= '0.0.0.0')
            [Routing(name=Interface 1,level=None,type=routing), Routing(name=net-172.31.14.0/24,
            level=None,type=routing), Routing(name=AT&T Plano Router,level=None,type=routing),
             Routing(name=Any network,level=None,type=routing)]
        Find the route using query route with ref
            >>> list_of_routing = list(Host.objects.all())
            >>> host1 = list_of_routing[0]
            >>> host2 = list_of_routing[1]
            >>> engine.query_route(source_ref=host1.href, destination_ref=host2.href)
        :param str source_ref: specify source network element uri
        :param str destination_ref: destination network element uri
        :param str source_ip: source ip address
        :param str destination_ip: destination ip address
        :return list(Routing): the result pages containing the result routing.
        """
        json = {}
        if source_ref:
            json.update(source_ref=source_ref)
        if destination_ref:
            json.update(destination_ref=destination_ref)
        if source_ip:
            json.update(source_ip=source_ip)
        if destination_ip:
            json.update(destination_ip=destination_ip)
        result = self.make_request(EngineCommandFailed, method="read", resource="query_route",
                                   json=json)
        return [Routing(routing) for entry in result for routing in entry['entry']]

    def add_route(self, gateway: Optional[str] = None, network: Optional[str] = None, payload: Optional[dict[str, Any]] = None) -> None:
        """
        Add a route to engine. Specify gateway and network.
        If this is the default gateway, use a network address of
        0.0.0.0/0.

        .. note: This will fail if the gateway provided does not have a
                 corresponding interface on the network.

        :param str gateway: gateway of an existing interface
        :param str network: network address in cidr format
        :param href payload: the payload to add route with href of element
           Example:
               {"gateway_ip": X.Y.Z.Z, "network_ip": A.B.C.D}
               OR
               {"gateway_ref": href, "network_ref": href}
        :raises EngineCommandFailed: invalid route, possibly no network
        :return: None
        """
        if payload:
            self.make_request(
                EngineCommandFailed, method="create", resource="add_route", json=payload
            )
        else:
            # Doing simple add route
            self.make_request(
                EngineCommandFailed,
                method="create",
                resource="add_route",
                params={"gateway": gateway, "network": network},
                payload={},
            )

    @property
    def policy_route(self) -> PolicyRoute:
        """
        Configure policy based routes on the engine.
        ::

            engine.policy_route.create(
                source='172.18.2.0/24', destination='192.168.3.0/24',
                gateway_ip='172.18.2.1')

        :rtype: PolicyRoute
        """
        if "policy_route" in self.data:
            return PolicyRoute(self)
        raise UnsupportedEngineFeature("Policy routing is only supported on layer 3 engine types")

    @property
    def routing(self) -> Routing:
        """
        Find all routing nodes within engine::

            for routing in engine.routing.all():
                for routes in routing:
                    ...

        Or just retrieve a routing configuration for a single
        interface::

            interface = engine.routing.get(0)

        :return: top level routing node
        :rtype: Routing
        """
        return Routing(href=self.get_relation("routing"))

    @property
    def routing_monitoring(self) -> RouteIterable:
        """
        Return route table for the engine, including
        gateway, networks and type of route (dynamic, static).
        Calling this can take a few seconds to retrieve routes
        from the engine.

        Find all routes for engine resource::

            >>> engine = Engine('sg_vm')
            >>> for route in engine.routing_monitoring:
            ...   route
            ...
            Route(route_network=u'0.0.0.0', route_netmask=0, route_gateway=u'10.0.0.1',
                  route_type=u'Static', dst_if=1, src_if=-1)
            ...

        :raises EngineCommandFailed: routes cannot be retrieved
        :return: list of route elements
        :rtype: SerializedIterable(Route)
        """
        try:
            result = self.make_request(EngineCommandFailed, resource="routing_monitoring")

            return RouteIterable(result)
        except SMCConnectionError:
            raise EngineCommandFailed("Timed out waiting for routes")

    def get_session_monitoring(self, sesmon_type: str, full: bool = True) -> Optional[SessionMonitoringResult]:
        """
        Available for all SMC API Versions but only for SMC Version above 7.1 (7.1 included)

        Return session monitoring for the requested session monitoring type  for the engine
        Find all routes for engine resource::

        :param sesmon_type requested session monitoring type. Possible value are defined
                           in session_monitoring.EngineSessionMonitoringType
        :optional param full ( default value is true ). When set to false, juste retrieve
                            the log key of each entry ( timestamp, component id, event id ).
        :raises EngineCommandFailed : session monitoring result cannot be retrieved
        :return: list of session monitoring entries : session_monitoring.SessionMonitoringResult
        :rtype: SerializedIterable(Route)

        Example:

        from smc.core.session_monitoring import EngineSessionMonitoringType
        engine.get_session_monitoring(EngineSessionMonitoringType.CONNECTION)
        """
        if is_smc_version_less_than_or_equal("7.0"):
            raise UnsupportedEngineFeature("Need at least 7.1 version of the SMC")
        try:
            params = None
            if not full:
                params = dict()
                params["full"] = False
            result = self.make_request(EngineCommandFailed, resource=sesmon_type, params=params)
            if result:
                return SessionMonitoringResult(sesmon_type, result)
            return None
        except SMCConnectionError:
            raise EngineCommandFailed(f"Timed out waiting for {sesmon_type}")

    @property
    def antispoofing(self) -> Antispoofing:
        """
        Antispoofing interface information. By default is based on routing
        but can be modified.
        ::

            for entry in engine.antispoofing.all():
                print(entry)

        :return: top level antispoofing node
        :rtype: Antispoofing
        """
        return Antispoofing(href=self.get_relation("antispoofing"))

    @property
    def internal_gateway(self) -> VPN:
        """
        Engine level VPN gateway information. This is a link from
        the engine to VPN level settings like VPN Client, Enabling/disabling
        an interface, adding VPN sites, etc.
        Example of adding a new VPN site to the engine's site list with
        associated networks::

            >>> network = Network.get_or_create(name='mynetwork', ipv4_network='1.1.1.0/24')
            Network(name=mynetwork)
            >>> engine.internal_gateway.vpn_site.create(name='mynewsite', site_element=[network])
            VPNSite(name=mynewsite)

        :raises UnsupportedEngineFeature: internal gateway is only supported on layer 3
            engine types.
        :return: this engines internal gateway
        :rtype: InternalGateway
        """
        return self.vpn

    @property
    def replica_internal_gateway(self) -> list[ReplicaInternalGateway]:
        """
        Replica Internal Gateway for this engine. This property returns a list
        of ReplicaInternalGateway objects. Replica gateways are linked to internal
        gateways from other engines and are used in VPN configurations where one
        engine replicates the gateway configuration of another.

        :raises FetchElementFailed: Replica internal gateway not found
        :return: list of ReplicaInternalGateway objects for this engine
        :rtype: list(ReplicaInternalGateway)
        """
        return [ReplicaInternalGateway(**gw) for gw in self.make_request(resource="replica_internal_gateway")]

    def create_replica_internal_gateway(self, linked_gateway: Any, name: Optional[str] = None) -> Optional[ReplicaInternalGateway]:
        """
        Create a replica internal gateway on this engine. A replica gateway is linked to
        an internal gateway from another engine and is used in VPN configurations.

        :param str name: Name for the replica internal gateway (optional)
        :param linked_gateway: The internal gateway to link to. Can be an InternalGateway
                              object, InternalEndpoint object, or an href string
        :type linked_gateway: InternalGateway or str
        :raises ActionCommandFailed: When creation fails
        :return: The created ReplicaInternalGateway
        :rtype: ReplicaInternalGateway

        Example::

            >>> saint_paul_fw = Engine('Saint Paul')
            >>> santa_clara_fw = Engine('Santa Clara')
            >>> santa_clara_gw = santa_clara_fw.internal_gateway
            >>> replica_gw = saint_paul_fw.create_replica_internal_gateway(
            ...     name='Santa Clara Replica',
            ...     linked_gateway=santa_clara_gw,
            ... )
            >>> print(replica_gw.name)
            Santa Clara Replica
        """
        # Get the href from the linked_gateway object if it's not already a string
        if hasattr(linked_gateway, 'href'):
            linked_gateway_ref = linked_gateway.href
        else:
            linked_gateway_ref = linked_gateway

        data = {
            "linked_gateway_ref": linked_gateway_ref
        }

        if name:
            data.update(name=name)
        result = self.make_request(
            method="create",
            resource="replica_internal_gateway",
            json=data
        )

        if result:
            return ReplicaInternalGateway(href=result.get('href', f"{self.href}/replica_internal_gateway"), data=result)

        for gw in self.replica_internal_gateway:
            if name and name in gw.name:
                return gw
            elif not name:
                if gw.name == gw.data.display_name:
                    return gw

        return None

    @property
    def all_vpns(self) -> list[VPN]:
        """
        Engine level all VPN gateway information.
        Example:
            >>> list_of_all_internal_gateways=engine.all_vpns
            >>> first_vpn_instance= list_of_all_internal_gateways[0]
            >>> first_vpn_instance.name
        :raises UnsupportedEngineFeature: internal gateway is only supported on layer 3
            engine types.
        :return: list of engine internal gateways
        :rtype: List of All VPN Gateway Configuration
        """
        result = self.make_request(UnsupportedEngineFeature,
                                   resource="internal_gateway")
        return [VPN(self, InternalGateway(**gateway)) for gateway in result]

    def create_internal_gateway(self, name: str, antivirus: Optional[Any] = None,
                                auto_certificate: Optional[Any] = None,
                                auto_site_content: Optional[Any] = None,
                                dhcp_relay: Optional[Any] = None,
                                end_point: Optional[list[Any]] = None,
                                firewall: Optional[Any] = None,
                                gateway_profile: Optional[Any] = None,
                                ssl_vpn_portal_setting: Optional[list[Any]] = None,
                                ssl_vpn_proxy: Optional[dict[str, Any]] = None,
                                ssl_vpn_tunneling: Optional[dict[str, Any]] = None,
                                trust_all_cas: Optional[Any] = None,
                                trusted_certificate_authorities: Optional[Any] = None,
                                vpn_client_mode: Optional[str] = None,
                                **kwargs: Any) -> None:
        """
        Create internal gateway
        Example of creating internal gateway:
            >>> engine.create_internal_gateway("test")
        :param str name: Name of the internal gateway
        :param str antivirus: Antivirus
        :param str auto_certificate: Automated RSA Certificate Management
        :param str auto_site_content: Indicates whether the site content is
            automatically generated from the routing view.
        :param str dhcp_relay: DHCP Relay.
        :param List end_point: List of end-points.
        :param str firewall: Firewall
        :param str gateway_profile: Gateway Profile
        :param List ssl_vpn_portal_setting: SSL VPN Settings for the Portal.
        :param Dict ssl_vpn_proxy: vpn proxy
        :param Dict ssl_vpn_tunneling: SSL VPN Settings for the VPN Client.
        :param str trust_all_cas: Indicates if the EndPoint trust all VPN Certificate Authorities.
        :param str trusted_certificate_authorities: List of trusted VPN Certificate Authorities.
            Valid only if the EndPoint does not trust all VPN CAs.
        :param str vpn_client_mode: VPN Client Mode
            accepted values given below:
            *no
            *ipsec
            *ssl
            *both
        :raises UnsupportedEngineFeature: internal gateway is only supported on layer 3 engine types
        :return: None
        :rtype: None
        """
        json = {"name": name}
        if antivirus:
            json.update(antivirus=antivirus)

        if auto_certificate:
            json.update(auto_certificate=auto_certificate)

        if auto_site_content:
            json.update(auto_site_content=auto_site_content)

        if isinstance(dhcp_relay, DHCPClientConfiguration):
            json.update(dhcp_relay=dhcp_relay.data)
        elif dhcp_relay:
            json.update(dhcp_relay=dhcp_relay)

        if end_point:
            json.update(end_point=end_point)

        if firewall:
            json.update(firewall=firewall)
        if gateway_profile:
            json.update(gateway_profile=gateway_profile)

        if ssl_vpn_portal_setting:
            json.update(ssl_vpn_portal_setting=ssl_vpn_portal_setting)

        if ssl_vpn_proxy:
            json.update(ssl_vpn_proxy=ssl_vpn_proxy)

        if ssl_vpn_tunneling:
            json.update(ssl_vpn_tunneling=ssl_vpn_tunneling)
        if trust_all_cas:
            json.update(trust_all_cas=trust_all_cas)

        if trusted_certificate_authorities:
            json.update(
                trusted_certificate_authorities=trusted_certificate_authorities)

        if vpn_client_mode:
            json.update(vpn_client_mode=vpn_client_mode)
        if kwargs:
            json.update(**kwargs)

        self.make_request(
            UnsupportedEngineFeature,
            method="create",
            resource="internal_gateway",
            json=json,
        )

    @cacheable_resource
    def vpn(self) -> VPN:
        """
        VPN configuration for the engine.

        :raises: UnsupportedEngineFeature: VPN is only supported on layer 3
            engines.
        :rtype: VPN
        """
        return VPN(self)

    @property
    def vpn_endpoint(self) -> Any:
        """
        A VPN endpoint is an address assigned to a layer 3 interface
        that can be enabled to turn on VPN capabilities. As an interface
        may have multiple IP addresses assigned, the endpoints are
        returned based on the address. Endpoints are properties of the
        engines Internal Gateway.

        :raises UnsupportedEngineFeature: only supported on layer 3 engines
        :rtype: SubElementCollection(InternalEndpoint)
        """
        return self.vpn.internal_endpoint

    @property
    def vpn_mappings(self) -> VPNMappingCollection:
        """
        .. versionadded:: 0.6.0
            Requires SMC version >= 6.3.4

        VPN policy mappings (by name) for this engine. This is a shortcut
        method to determine which VPN policies are used by the firewall.

        :raises UnsupportedEngineFeature: requires a layer 3 firewall and
            SMC version >= 6.3.4.
        :rtype: VPNMappingCollection(VPNMapping)
        """
        return VPNMappingCollection(
            self.make_request(UnsupportedEngineFeature, resource="vpn_mapping")
        )

    @property
    def virtual_resource(self) -> Any:
        """
        Available on a Master Engine only.

        To get all virtual resources call::

            engine.virtual_resource.all()

        :raises UnsupportedEngineFeature: master engine only
        :rtype: CreateCollection(VirtualResource)
        """
        resource = create_collection(
            self.get_relation("virtual_resources", UnsupportedEngineFeature), VirtualResource
        )
        resource._load_from_engine(self, "virtualResources")
        return resource

    @property
    def contact_addresses(self) -> ContactAddressCollection:
        """
        Contact addresses are NAT addresses that are assigned to interfaces.
        These are used when a component needs to communicate with another
        component through a NAT'd connection. For example, if a firewall is
        known by a pubic address but the interface uses a private address,
        you would assign the public address as a contact address for that
        interface.

        .. note:: Contact addresses are only supported with SMC >= 6.2.

        Obtain all eligible interfaces for contact addressess::

            >>> engine = Engine('dingo')
            >>> for ca in engine.contact_addresses:
            ...   ca
            ...
            ContactAddressNode(interface_id=11, interface_ip=10.10.10.20)
            ContactAddressNode(interface_id=120, interface_ip=120.120.120.100)
            ContactAddressNode(interface_id=0, interface_ip=1.1.1.1)
            ContactAddressNode(interface_id=12, interface_ip=3.3.3.3)
            ContactAddressNode(interface_id=12, interface_ip=17.17.17.17)

        .. seealso:: :py:mod:`smc.core.contact_address`

        This is set to a private method because the logic doesn't make sense with
        respects to how this is configured under the SMC.

        :rtype: ContactAddressCollection(ContactAddressNode)
        """
        return ContactAddressCollection(self.get_relation("contact_addresses"))

    @property
    def interface_options(self) -> InterfaceOptions:
        """
        Interface options specify settings related to setting primary/
        backup management, outgoing, and primary/backup heartbeat
        interfaces. For example, set primary management interface
        (this unsets it from the currently assigned interface)::

            engine.interface_options.set_primary_mgt(10)

        Obtain the primary management interface::

            print(engine.interface_options.primary_mgt)

        :rtype: InterfaceOptions
        """
        return InterfaceOptions(self)

    @property
    def interface(self) -> InterfaceCollection:
        """
        Get all interfaces, including non-physical interfaces such
        as tunnel or capture interfaces. These are returned as Interface
        objects and can be used to load specific interfaces to modify, etc.
        ::

            for interfaces in engine.interface:
                ......

        :rtype: InterfaceCollection

        See :class:`smc.core.interfaces.Interface` for more info
        """
        return InterfaceCollection(self)

    @property
    def physical_interface(self) -> PhysicalInterfaceCollection:
        """
        Returns a PhysicalInterface. This property can be used to
        add physical interfaces to the engine. For example::

            engine.physical_interface.add_inline_interface(....)
            engine.physical_interface.add_layer3_interface(....)

        :raises UnsupportedInterfaceType: engine doesn't support this type
        :rtype: PhysicalInterfaceCollection
        """
        return PhysicalInterfaceCollection(self)

    @property
    def virtual_physical_interface(self) -> VirtualPhysicalInterfaceCollection:
        """Master Engine virtual instance only

        A virtual physical interface is for a master engine virtual instance.
        This interface type is just a subset of a normal physical interface
        but for virtual engines. This interface only sets Auth_Request and
        Outgoing on the interface.

        To view all interfaces for a virtual engine::

            for intf in engine.virtual_physical_interface:
                print(intf)

        :raises UnsupportedInterfaceType: supported on virtual engines only
        :rtype: VirtualPhysicalInterfaceCollection
        """
        return VirtualPhysicalInterfaceCollection(self)

    @property
    def tunnel_interface(self) -> TunnelInterfaceCollection:
        """
        Get only tunnel interfaces for this engine node.

        :raises UnsupportedInterfaceType: supported on layer 3 engine only
        :rtype: TunnelInterfaceCollection
        """
        return TunnelInterfaceCollection(self)

    @property
    def vpn_broker_interface(self) -> VPNBrokerInterfaceCollection:
        """
        Get only vpn broker interfaces for this engine node.

        :raises UnsupportedInterfaceType: supported on layer 3 engine only
        :rtype: VPNBrokerInterfaceCollection
        """
        return VPNBrokerInterfaceCollection(self)

    @property
    def loopback_interface(self) -> LoopbackCollection:
        """
        Retrieve any loopback interfaces for this engine.
        Loopback interfaces are only supported on layer 3 firewall types.

        Retrieve all loopback addresses::

            for loopback in engine.loopback_interface:
                print(loopback)

        :raises UnsupportedInterfaceType: supported on layer 3 engine only
        :rtype: LoopbackCollection
        """
        if self.type in ("single_fw", "fw_cluster", "virtual_fw"):
            return LoopbackCollection(self)
        raise UnsupportedInterfaceType(
            "Loopback addresses are only supported on layer 3 firewall types"
        )

    @property
    def upload_result(self) -> Any:
        return self.make_request(UnsupportedEngineFeature, resource="upload_result")

    @property
    def modem_interface(self) -> ModemInterfaceCollection:
        """
        Get only modem interfaces for this engine node.

        :raises: UnsupportedInterfaceType: modem interfaces are only supported
            on layer 3 engines
        :return: list of dict entries with href,name,type, or None
        """
        return ModemInterfaceCollection(self)

    @property
    def adsl_interface(self) -> Any:
        """
        Get only adsl interfaces for this engine node.

        :raises UnsupportedInterfaceType: adsl interfaces are only supported
            on layer 3 engines
        :return: list of dict entries with href,name,type, or None
        """
        return self.make_request(UnsupportedInterfaceType, resource="adsl_interface")

    @property
    def wireless_interface(self) -> Any:
        """
        Get only wireless interfaces for this engine node.

        :raises UnsupportedInterfaceType: wireless interfaces are only
            supported on layer 3 engines
        :return: list of dict entries with href,name,type, or None
        """
        return self.make_request(UnsupportedInterfaceType, resource="wireless_interface")

    @property
    def switch_physical_interface(self) -> SwitchInterfaceCollection:
        """
        Get only switch physical interfaces for this engine node.
        This is an iterable property::

            for interface in engine.switch_physical_interface:
                ...

        Or you can fetch a switch port interface/module directly
        by using the generic interface property::

            engine.interface.get('SWP_0')

        Or through this property directly::

            engine.switch_physical_interface.get('SWP_0')

        :raises UnsupportedInterfaceType: switch interfaces are only
            supported on specific firewall models
        :return: list of dict entries with href,name,type, or None
        """
        return SwitchInterfaceCollection(self)

    @property
    def lldp_profile(self) -> Optional[LLDPProfile]:
        """
        It represents a set of attributes used for configuring LLDP(Link Layer Discovery Protocol).
        LLDP information is advertised by devices at a fixed interval in the form of LLDP data units
        represented by TLV structures.

        :param value: LLDP Profile to assign engine. Can be str href, or LLDPProfile element.
        :raises UpdateElementFailed: failure to update element
        :return: LLDPProfile element or None
        """
        return Element.from_href(self.lldp_profile_ref)

    @lldp_profile.setter
    def lldp_profile(self, value: Any) -> None:
        if min_smc_version("6.6"):
            if isinstance(value, LLDPProfile):
                self.data.update(lldp_profile=value.href)
            else:
                self.data.update(lldp_profile=value)

    @property
    def link_usage_profile(self) -> Optional[LinkUsageProfile]:
        """
        Represent link usage profile
        :param value: Link usage profile to assign engine. Can be str href,
        or LinkUsageProfile element.
        :raises UpdateElementFailed: failure to update element
        :return: LinkUsageProfile element or None
        """
        return Element.from_href(self.link_usage_profile_ref)

    @link_usage_profile.setter
    def link_usage_profile(self, value: Any) -> None:
        if isinstance(value, LinkUsageProfile):
            self.data.update(link_usage_profile_ref=value.href)
        else:
            self.data.update(link_usage_profile_ref=value)

    @property
    def discard_quic_if_cant_inspect(self) -> Optional[bool]:
        """
        Discard or allow QUIC if inspection is impossible

        :rtype: bool
        """
        if not self.type.startswith("master"):
            return self.data.get("discard_quic_if_cant_inspect")
        raise UnsupportedEngineFeature(
            "This engine type does not support discard_quic_if_cant_inspect.")

    @discard_quic_if_cant_inspect.setter
    def discard_quic_if_cant_inspect(self, value: Any) -> None:
        if min_smc_version("7.0"):
            self.data["discard_quic_if_cant_inspect"] = value

    @property
    def administrator_authentication_method(self) -> Optional[str]:
        """
        Authentication method for administrator

        :rtype: AuthenticationMethod
        """
        if not self.type.startswith("virtual"):
            return self.data.get("admin_auth_method")
        raise UnsupportedEngineFeature(
            "This engine type does not support administrator_authentication_method.")

    @property
    def allow_root_login(self) -> Optional[str]:
        """
        Administrator Authentication: root password login
        - allow: Allow Root Password Login.
        - disable_pwd_ssh: Disable Root Password Login through SSH.
        - disable: Disable all root password logins, including console (to be used carefully).

        :rtype: str
        """
        if not self.type.startswith("virtual"):
            return self.data.get("allow_root_login")
        raise UnsupportedEngineFeature(
            "This engine type does not support allow_root_login.")

    @property
    def ssh_passwordless_login(self) -> Optional[str]:
        """
        Administrator Authentication: SSH Passwordless Logins
        - allow: Allow.
        - deny: Deny.

        :rtype: str
        """
        if not self.type.startswith("virtual"):
            return self.data.get("ssh_passwordless_login")
        raise UnsupportedEngineFeature(
            "This engine type does not support ssh_passwordless_login.")

    @staticmethod
    def supports_radius_authentication_settings() -> bool:
        return (not is_api_version_less_than_or_equal("7.0")
                and not is_smc_version_equal("7.2.0")
                and not is_smc_version_less_than("7.1.4"))

    @administrator_authentication_method.setter
    def administrator_authentication_method(self, value: Any) -> None:
        if not self.type.startswith("virtual"):
            if Engine.supports_radius_authentication_settings():
                self.data["admin_auth_method"] = value

    @allow_root_login.setter
    def allow_root_login(self, value: Any) -> None:
        """
        Administrator Authentication: root password login
        - allow: Allow Root Password Login.
        - disable_pwd_ssh: Disable Root Password Login through SSH.
        - disable: Disable all root password logins, including console (to be used carefully).
        """
        if not self.type.startswith("virtual"):
            if Engine.supports_radius_authentication_settings():
                self.data["allow_root_login"] = value

    @ssh_passwordless_login.setter
    def ssh_passwordless_login(self, value: Any) -> None:
        """
        Administrator Authentication: SSH Passwordless Logins
        - allow: Allow.
        - deny: Deny.
        """
        if not self.type.startswith("virtual"):
            if Engine.supports_radius_authentication_settings():
                self.data["ssh_passwordless_login"] = value

    def add_interface(self, interface: Any, **kw: Any) -> None:
        """
        Add interface is a lower level option to adding interfaces directly
        to the engine. The interface is expected to be an instance of
        Layer3PhysicalInterface, Layer2PhysicalInterface, TunnelInterface,
        or ClusterInterface. The engines instance cache is flushed after
        this call is made to provide an updated cache after modification.

        .. seealso:: :class:`smc.core.engine.interface.update_or_create`

        :param PhysicalInterface,TunnelInterface interface: instance of
            pre-created interface
        :return: None
        """
        params = None
        if "params" in kw:
            params = kw.pop("params")
        if "dhcp_relay" in interface.data:
            if isinstance(interface.data["dhcp_relay"], DHCPRelay):
                interface.data["dhcp_relay"] = interface.data["dhcp_relay"].data
        if "dhcpv6_relay" in interface.data:
            if isinstance(interface.data["dhcpv6_relay"], DHCPRelay):
                interface.data["dhcpv6_relay"] = interface.data["dhcpv6_relay"].data

        self.make_request(
            EngineCommandFailed,
            method="create",
            href=self.get_relation(interface.typeof),
            json=interface,
            params=params,
        )
        self._del_cache()

    def refresh(
            self,
            timeout: int = 3,
            wait_for_finish: bool = False,
            preserve_connections: bool = True,
            generate_snapshot: bool = True,
            **kw: Any,
    ) -> TaskOperationPoller:
        """
        Refresh existing policy on specified device. This is an asynchronous
        call that will return a 'follower' link that can be queried to
        determine the status of the task.
        ::

            poller = engine.refresh(wait_for_finish=True)
            while not poller.done():
                poller.wait(5)
                print('Percentage complete {}%'.format(poller.task.progress))
            assert poller.is_success(), logging.error("Timeout error during policy refresh")

        :param int timeout: timeout between queries
        :param bool wait_for_finish: poll the task waiting for status
        :param bool preserve_connections: flag to preserve connections (True by default)
        :param bool generate_snapshot: flag to generate snapshot (True by default)
        :raises TaskRunFailed: refresh failed, possibly locked policy
        :rtype: TaskOperationPoller
        """
        kw.update({"params": {"generate_snapshot": generate_snapshot,
                              "preserve_connections": preserve_connections}})
        return Task.execute(self, "refresh", timeout=timeout, wait_for_finish=wait_for_finish, **kw)

    def upload(
            self,
            policy: Optional[str] = None,
            timeout: int = 5,
            wait_for_finish: bool = False,
            preserve_connections: bool = True,
            generate_snapshot: bool = True,
            **kw: Any,
    ) -> TaskOperationPoller:
        """
        Upload policy to engine. This is used when a new policy is required
        for an engine, or this is the first time a policy is pushed to an
        engine.
        If an engine already has a policy and the intent is to re-push, then
        use :py:func:`refresh` instead.
        The policy argument can use a wildcard * to specify in the event a full
        name is not known::

            engine = Engine('myfw')
            task = engine.upload('Amazon*', wait_for_finish=True)
            for message in task.wait():
                print(message)

        :param str policy: name of policy to upload to engine; if None, current
            policy
        :param bool wait_for_finish: poll the task waiting for status
        :param int timeout: timeout between queries
        :param bool preserve_connections: flag to preserve connections (True by default)
        :param bool generate_snapshot: flag to generate snapshot (True by default)
        :raises TaskRunFailed: upload failed with reason
        :rtype: TaskOperationPoller
        """
        return Task.execute(
            self,
            "upload",
            params={
                "filter": policy,
                "preserve_connections": preserve_connections,
                "generate_snapshot": generate_snapshot,
            },
            timeout=timeout,
            wait_for_finish=wait_for_finish,
            **kw
        )

    def upload_alternative_slot(
            self,
            alternative_slot: Optional[int] = None,
            policy: Optional[str] = None,
            timeout: int = 5,
            wait_for_finish: bool = False,
            generate_snapshot: bool = True,
            **kw: Any,
    ) -> TaskOperationPoller:
        """
        Upload policy to engine alternative slot. This is used when multiple
        policies are required for an engine.
        If an engine already has a policy and the intent is to re-push, then
        use :py:func:`refresh` instead.
        The policy argument can use a wildcard * to specify in the event a full
        name is not known::

            engine = Engine('myfw')
            task = engine.upload_alternative_slot(1, 'Amazon*', wait_for_finish=True)
            for message in task.wait():
                print(message)

        :param int alternative_slot: Slot of policy to upload to engine(1 to 3)
        :param str policy: name of policy to upload to engine; if None, current
            policy
        :param bool wait_for_finish: poll the task waiting for status
        :param int timeout: timeout between queries
        :param bool generate_snapshot: flag to generate snapshot (True by default)
        :raises TaskRunFailed: upload failed with reason
        :rtype: TaskOperationPoller
        """
        return Task.execute(
            self,
            "upload",
            params={
                "alternative_slot": alternative_slot,
                "filter": policy,
                "generate_snapshot": generate_snapshot,
            },
            timeout=timeout,
            wait_for_finish=wait_for_finish,
            **kw
        )

    def generate_snapshot(self, filename: str = "snapshot.zip") -> None:
        """
        Generate and retrieve a policy snapshot from the engine
        This is blocking as file is downloaded

        :param str filename: name of file to save file to, including directory
            path
        :raises EngineCommandFailed: snapshot failed, possibly invalid filename
            specified
        :return: None
        """
        try:
            self.make_request(EngineCommandFailed, resource="generate_snapshot", filename=filename)

        except IOError as e:
            raise EngineCommandFailed("Generate snapshot failed: {}".format(e))

    @property
    def snapshots(self) -> Any:
        """
        References to policy based snapshots for this engine, including
        the date the snapshot was made

        :raises EngineCommandFailed: failure downloading, or IOError
        :rtype: SubElementCollection(Snapshot)
        """
        return sub_collection(self.get_relation("snapshots", EngineCommandFailed), Snapshot)

    def __unicode__(self) -> str:
        return u"{0}(name={1})".format(lookup_class(self.type).__name__, self.name)

    def ldap_replication(self, enable: bool) -> None:
        """
        Enable or disable LDAP replication

        :raises EngineCommandFailed: the LDAP replication is already enabled or disabled
        :param boolean enable: True enable the LDAP replication False disable it
        """

        self.make_request(
            EngineCommandFailed,
            method="update",
            resource="ldap_replication",
            params={"enable": enable},
        )

    def join_domain(self, user_name: str, password: str, engine_name: str, ad_server_ref: str) -> Any:
        """
        Executes a join to an Active Directory domain command for the current cluster.

        :raises EngineCommandFailed: the join command has failed.
        """

        return self.make_request(
            EngineCommandFailed,
            method="update",
            resource="join_domain",
            json={"username": user_name, "password": password, "engine_name": engine_name, "ad_server_ref": ad_server_ref},
            raw_result=True
        )

    def unjoin_domain(self, user_name: str, password: str) -> Any:
        """
        Executes an unjoin from an Active Directory domain command for the current cluster.

        :raises EngineCommandFailed: the unjoin command has failed.
        """

        return self.make_request(
            EngineCommandFailed,
            method="update",
            resource="unjoin_domain",
            json={"username": user_name, "password": password},
            raw_result=True
        )

    def generate_and_sign_user_authentication_certificate(self, subject_alt_name: Optional[str] = None, key_length: Optional[int] = None) -> Task:
        """
        Generate and internally sign User Authentication certificate.
        :param subject_alt_name: Subject Alternative Name to be included in the certificate.
              Possible examples:
                 * DNS:foo
                 * IP:10.2.2.2
                 * email:foo@corp.com
                 * URI:http://corp.com,RID:1.4
                 * DNS:foo,IP:10.2.2.2,email:foo@corp.com
        :param key_length: Key length for the certificate.

        :raises CertificateExportError: error exporting certificate
        """
        if (is_smc_version_more_than_or_equal("7.5.0")
                and subject_alt_name):
            json = {"key_length": key_length, "subject_alt_name": subject_alt_name}
        else:
            json = {"key_length": key_length}
        return Task.execute(
            self,
            "web_auth_https_generate_and_sign_certificate",
            json=json,
            wait_for_finish=True
        )

    def delete_user_authentication_certificate(self) -> None:
        """
        Delete the certificate if any is defined for this component.
        """
        self.make_request(method="delete",
                          resource="web_auth_https_delete_certificate")

    def delete_user_authentication_certificate_request(self) -> None:
        """
        Delete the certificate request if any is defined for this component.
        """
        self.make_request(method="delete",
                          resource="web_auth_https_delete_certificate_request")

    def export_user_authentication_certificate(self, filename: Optional[str] = None) -> Optional[bytes]:
        """
         Export the certificate if any is defined for this component.
         """
        result = self.make_request(
            CertificateExportError, raw_result=True, resource="web_auth_https_export_certificate"
        )

        if filename is not None:
            save_to_file(filename, result.content)
            return

        return result.content

    def generate_user_authentication_certificate_request(self, subject_alt_name: Optional[str] = None, key_length: Optional[int] = None) -> Any:
        """
        Export the certificate request for the node when working external CA.
        This can return None if the engine type does not have a certificate request.

        :raises CertificateExportError: error exporting certificate
        :rtype: str or None
        """
        if (is_smc_version_more_than_or_equal("7.5.0")
                and subject_alt_name):
            json = {"key_length": key_length, "subject_alt_name": subject_alt_name}
        else:
            json = {"key_length": key_length}
        return self.make_request(
            CertificateExportError,
            method="create",
            resource="web_auth_https_generate_certificate_request",
            json=json
        )

    def export_user_authentication_certificate_request(self, filename: Optional[str] = None) -> Optional[bytes]:
        """
         Export the certificate request if any is defined for this component.
         """
        result = self.make_request(
            CertificateExportError, raw_result=True,
            resource="web_auth_https_export_certificate_request"
        )

        if filename is not None:
            save_to_file(filename, result.content)
            return

        return result.content

    def user_authentication_import_certificate(self, certificate: Any) -> None:
        """
        Import a valid certificate. Certificate can be either a file path
        or a string of the certificate. If string certificate, it must include
        the -----BEGIN CERTIFICATE----- string.

        :param str certificate: fully qualified path or string
        :raises CertificateImportError: failure to import cert with reason
        :raises IOError: file not found, permissions, etc.
        """
        self.make_request(
            CertificateImportError,
            method="create",
            resource="web_auth_https_import_certificate",
            headers={"content-type": "multipart/form-data"},
            files={
                # decode certificate or use it as it is
                "signed_certificate": certificate_content(certificate)
            },
        )

    @property
    def is_snort_enabled(self) -> bool:
        """
        Return true if snort is enable else false.
        :rtype: bool
        """
        return self.data.get("is_snort_enabled", False)

    def snort_configuration_file_import(self, file_name: str) -> None:
        """
        Allows importing a specified Snort Configuration file for the specified Engine.
        :param str file_name: Name of the snort configuration file(Full Path).

        Example: snort import and export
            >>> engine=Engine("Algiers")
            >>> print(engine.is_snort_enabled)
                False
            >>> engine.snort_enable_disable()
            >>> print(engine.is_snort_enabled)
                True
            >>> engine.snort_configuration_file_import(file_name=./test_snort_config.zip)
            >>> engine.snort_configuration_file_export(file_name=./test_snort_config.zip)
            >>> engine.snort_configuration_file_delete()
        """
        self.make_request(SnortConfigurationImportError,
                          method="create",
                          resource="snort_configuration_file_import",
                          files={"file": open(file_name, 'rb')},
                          raw_result=True,
                          )

    def snort_configuration_file_export(self, file_name: str) -> None:

        self.make_request(SnortConfigurationExportError,
                          raw_result=True, resource="snort_configuration_file_export",
                          filename=file_name)

    def snort_configuration_file_delete(self) -> None:
        """
        It will delete the Snort Configuration from a particular engine.
        """
        self.make_request(EngineCommandFailed, method="delete",
                          resource="snort_configuration_file_delete")

    def snort_enable_disable(self) -> None:
        """
        Toggle enable disable state of snort.
        """
        self.update(is_snort_enabled=not self.data.get("is_snort_enabled", False))

    def get_hardware_status(self, subsystems: Optional[List[str]] = None) -> dict[str, Any]:
        """
        Returns dict representation hardware status.
        :param str engine_name: The name of engine to get hardware status
        :param list(str) subsystems: List of subsystem to get hardware status.
            like sandbox_subsystem, cloud_sync, filesystem, logging_subsystem
        Example:
            >>> status_list = ["sandbox_subsystem", "cloud_sync", "filesystem"]
            >>> dict_of_status = get_hardware_status(subsystems=status_list)
            >>> print(dict_of_status)
            >>> {'Atlanta node 1': {'File Systems': {
                                     'Data': {'Size': '494 MB',
                                              'Usage': '7.0%',
                                              'status': 'OK'},
                                     'Spool': {'Size': '2463 MB',
                                               'Usage': '3.3%',
                                               'status': 'OK'},
                                     'Swap': {'Size': '494 MB',
                                              'Usage': '0.0%',
                                              'status': 'OK'},
                                     'Tmp': {'Size': '997 MB',
                                             'Usage': '96.7%',
                                             'status': 'WARNING'}},
                                    'Sandbox': {'Cloud connection': {'status': '1'}}},
                 'Atlanta node 2': {'File Systems': {
                                    'Data': {'Size': '494 MB',
                                             'Usage': '7.0%',
                                             'status': 'OK'},
                                    'Spool': {'Size': '2463 MB',
                                              'Usage': '3.3%',
                                              'status': 'OK'},
                                    'Swap': {'Size': '494 MB',
                                             'Usage': '0.0%',
                                             'status': 'OK'},
                                    'Tmp': {'Size': '997 MB',
                                            'Usage': '96.7%',
                                            'status': 'WARNING'}},
                                    'Sandbox': {'Cloud connection': {'status': '1'}}}}

        :rtype: dict
        """
        json_result = {}

        for node in self.nodes:
            json_result[node.name] = {}

            for item in node.hardware_status:
                if subsystems and item.name not in subsystems:
                    continue
                json_result[node.name][item.name] = {}

                for status in item.items:
                    statuses = {}
                    for sub_status in status.get("statuses", []):
                        statuses.update({sub_status["param"]: sub_status["value"]})

                    json_result[node.name][item.name][status["name"]] = \
                        {'status': status["status"], **statuses}

        return json_result

    @property
    def ssm_advanced_setting(self) -> list[SidewinderProxyAdvancedSettings]:
        """
        Sidewinder Proxy Advanced Settings.
        :rtype: list(SidewinderProxyAdvancedSettings)
        """
        return [SidewinderProxyAdvancedSettings(setting) for setting in
                self.data.get("ssm_advanced_setting", [])]

    @property
    def scan_detection(self) -> ScanDetectionSetting:
        """
        This represents the definition of Scan Detection on a NGFW.
        :rtype: ScanDetectionSetting
        """
        return ScanDetectionSetting(self.data.get("scan_detection"))

    @property
    def static_multicast_route(self) -> list[StaticMulticastRoute]:
        """
        Represents Firewall multicast routing entry for Static/IGMP Proxy multicast routing modes.
        :rtype: list(StaticMulticastRoute)
        """
        return [StaticMulticastRoute(route) for route in
                self.data.get("static_multicast_route", [])]

    @property
    def web_authentication(self) -> WebAuthentication:
        """
        The Browser-Based User Authentication settings
        :rtype: WebAuthentication
        """
        return WebAuthentication(self.data.get("web_authentication", {}))

    @property
    def nat64_settings(self) -> Nat64Settings:
        """
        The NAT64 settings
        :rtype: Nat64Settings
        """
        return Nat64Settings(self.data.get("ipv6_transition_mechanism", {}))

    @property
    def saml_settings(self) -> list[SamlSettings]:
        """
        Represents the SAML settings. Either for the user authentication (BBA) or the
        SSL VPN Portal configuration.
        :rtype: list(SamlSettings):
        """
        return [SamlSettings(data) for data in self.data.get("saml_settings", [])]

    def configure_saml_settings_for_user_authentication(self, saml_settings_entries: Optional[list[Any]]) -> None:
        """
        Configure SAML settings for user authentication (BBA). If saml_settings
        are defined, we enable the SAML for BBA otherwise we disable it.
        """
        self._configure_saml_settings_for(saml_settings_entries, False)

    def configure_saml_settings_for_application_access(self, saml_settings_entries: Optional[list[Any]]) -> None:
        """
        Configure SAML settings for Application Access portal. If saml_settings
        are defined, we enable the SAML for Application Access portal otherwise we disable it.
        """
        self._configure_saml_settings_for(saml_settings_entries, True)

    def _configure_saml_settings_for(self, saml_settings_entries: Optional[list[Any]], application_access: bool) -> None:
        """
        Configure SAML settings for BBA (user authentication) or Application access portal.
        If saml_settings are defined, we enable the SAML otherwise we disable it.
        """
        if application_access:
            enable_attribute = "enable_saml_for_application_access"
            saml_usage = "app_access"
        else:
            enable_attribute = "enable_saml_for_bba"
            saml_usage = "bba"
        new_saml_settings_entries = [s for s in self.data.get("saml_settings", [])
                                     if s.get("usage") != saml_usage]

        if saml_settings_entries:
            for entry in saml_settings_entries:
                entry["saml_setting_usage"] = saml_usage
                new_saml_settings_entries.append(entry)
        self.data[enable_attribute] = (saml_settings_entries is not None
                                       and len(saml_settings_entries) > 0)
        self.data["saml_settings"] = new_saml_settings_entries


    def save_initial_configuration(self, time_zone: str, keyboard: str, enable_ssh: bool = False,
                             root_password: Optional[str] = None,
                             initial_policy_ref: Optional[str] = None,
                             install_on_server: bool = False,
                             export_to_base64: bool = False) -> Any:
        """
        Saves the initial configuration for all nodes of the cluster.

        :param time_zone: Time zone to set on all nodes.
        :param keyboard: Keyboard layout to set on all nodes.
        :param bool enable_ssh: Enable SSH on all nodes.
        :param str root_password: Root password to set on all nodes.
        :param str initial_policy_ref: Reference to the initial policy to set on all nodes.
        :param bool install_on_server: Whether to upload engine config on install server.
        :param bool export_to_base64: Whether to export to base64.
        :return byte array of the zip containing configuration files for all nodes.
        .. note:: This method requires SMC version >= 7.1
        """
        payload= {
            "time_zone": time_zone,
            "keyboard": keyboard,
            "enable_ssh": enable_ssh,
            "root_password": root_password,
            "initial_policy_ref": initial_policy_ref,
            "install_on_server": install_on_server,
            "export_to_base64": export_to_base64
        }
        return self.make_request(
            EngineCommandFailed, method="create", resource="save_initial_configuration",
            json=payload,
            raw_result=True
        )

class VPNMappingCollection(BaseIterable):
    def __init__(self, vpns: Any) -> None:
        mappings = vpns.get("vpnMappings")
        _mappings = []
        if mappings:
            for entry in mappings:
                vpn_mapping = entry.get("vpn_mapping_entry")
                vpn_mapping.setdefault("gateway_nodes_usage", {})
                _mappings.append(VPNMapping(**vpn_mapping))
        super(VPNMappingCollection, self).__init__(_mappings)


class VPNMapping(namedtuple("VPNMapping", "gateway_ref vpn_ref gateway_nodes_usage")):
    """
    A VPN Mapping represents Policy Based VPNs associated with this engine.
    This simplifies finding references where an engine is used within a VPN
    without iterating through existing VPNs to find the engine.
    """

    __slots__ = ()

    @property
    def internal_gateway(self) -> Any:
        """
        Return the engines internal gateway as element

        :rtype: InternalGateway
        """
        return Element.from_href(self.gateway_ref)

    @property
    def vpn(self) -> Any:
        """
        The VPN policy for this engine mapping

        :rtype: PolicyVPN
        """
        return Element.from_href(self.vpn_ref)

    @property
    def is_central_gateway(self) -> bool:
        """
        Is this engine a central gateway in the VPN policy

        :rtype: bool
        """
        return "central_gateway_node_ref" in self.gateway_nodes_usage

    @property
    def _central_gateway(self) -> Optional[str]:
        """
        Return the central gateway tree node as href. This can be used
        to simplify removal of the element from the specified VPN.
        You must first open the VPN policy then save and close.

        :return: GatewayTreeNode href
        :rtype: str
        """
        return self.gateway_nodes_usage.get("central_gateway_node_ref", None)

    @property
    def is_satellite_gateway(self) -> bool:
        """
        Is this engine a satellite gateway in the VPN policy

        :rtype: bool
        """
        return "satellite_gateway_node_ref" in self.gateway_nodes_usage

    @property
    def _satellite_gateway(self) -> Optional[str]:
        """
        Return the satellite gateway tree node href. This can be used
        to simplify removal of the element from the specified VPN.
        You must first open the VPN policy then save and close.

        :return: GatewayTreeNode href
        :rtype: str
        """
        return self.gateway_nodes_usage.get("satellite_gateway_node_ref", None)

    @property
    def is_mobile_gateway(self) -> bool:
        """
        Is the engine specified as a mobile gateway in the Policy VPN
        configuration

        :rtype: bool
        """
        return "mobile_gateway_node_ref" in self.gateway_nodes_usage

    @property
    def _mobile_gateway(self) -> Optional[str]:
        """
        Return the mobile gateway tree href. This can be used
        to simplify removal of the element from the specified VPN.
        You must first open the VPN policy then save and close.

        :return: GatewayTreeNode href
        :rtype: str
        """
        return self.gateway_nodes_usage.get("mobile_gateway_node_ref", None)

    def __str__(self) -> str:
        return str("VPNMapping(vpn={})".format(self.vpn))


class VPN(object):
    """
    VPN is the top level interface to all engine based VPN settings.
    To enable IPSEC, SSL or SSL VPN on the engine, enable on the
    endpoint.
    """

    def __init__(self, engine: Any, internal_gateway: Optional[InternalGateway] = None) -> None:
        self.engine = engine
        if internal_gateway:
            self.internal_gateway = internal_gateway
        else:
            result = self.engine.make_request(UnsupportedEngineFeature,
                                              resource="internal_gateway")
            self.internal_gateway = InternalGateway(**result[0])

    def rename(self, name: str) -> None:
        """
        Rename the internal gateway.

        :param str name: new name for internal gateway
        :return: None
        """
        self.internal_gateway.rename(name)  # Engine update changes this ETag

    def remove(self) -> None:
        """
        Rename the internal gateway.

        :param str name: new name for internal gateway
        :return: None
        """
        self.internal_gateway.delete()  # Engine update changes this ETag

    @property
    def name(self) -> str:
        return self.internal_gateway.name

    @property
    def vpn_client(self) -> InternalGateway:
        """
        VPN Client settings for this engine.

        Alias for internal_gateway.

        :rtype: InternalGateway
        """
        return self.internal_gateway

    @property
    def ssl_vpn_portal(self) -> InternalGateway:
        """
        SSL VPN Portal settings for this engine.
        Deprecated since SMC >= 7.5.0 use application_access_portal instead

        Alias for internal_gateway.

        :rtype: InternalGateway
        """
        return self.internal_gateway

    @property
    def application_access_portal(self) -> InternalGateway:
        """
        SSL VPN Portal settings for this engine.

        Alias for internal_gateway.

        :rtype: InternalGateway
        """
        return self.internal_gateway

    @property
    def sites(self) -> Any:
        """
        VPN sites configured for this engine. Using sub element
        methods simplify fetching sites of interest::

            engine = Engine('sg_vm')
            mysite = engine.vpn.sites.get_contains('inter')
            print(mysite)

        :rtype: CreateCollection(VPNSite)
        """
        return create_collection(self.internal_gateway.get_relation("vpn_site"), VPNSite)

    def add_site(self, name: str, site_elements: Optional[list[Any]] = None,
                 vpn_references: Optional[list[dict[str, Any]]] = None,
                 is_automatic: bool = False) -> VPNSite:
        """
        Add a VPN site with site elements to this engine.
        VPN sites identify the sites with protected networks
        to be included in the VPN.
        Add a network and new VPN site::

            >>> net = Network.get_or_create(name='wireless', ipv4_network='192.168.5.0/24')
            >>> engine.vpn.add_site(name='wireless', site_elements=[net])
            VPNSite(name=wireless)
            >>> list(engine.vpn.sites)
            [VPNSite(name=dingo - Primary Site), VPNSite(name=wireless)]

        :param str name: name for VPN site
        :param list site_elements: network elements for VPN site
        :type site_elements: list(str,Element)
        :param list(dict) vpn_references: Set of associations Site-VPN.
        :raises ElementNotFound: if site element is not found
        :raises UpdateElementFailed: failed to add vpn site
        :rtype: VPNSite

        .. note:: Update is immediate for this operation.
        """
        site_elements = site_elements if site_elements else []
        return self.sites.create(name, site_elements, vpn_references, is_automatic=is_automatic)

    @property
    def internal_endpoint(self) -> Any:
        """
        Internal endpoints to enable VPN for the engine.

        :rtype: SubElementCollection(InternalEndpoint)
        """
        return sub_collection(
            self.internal_gateway.get_relation("internal_endpoint"), InternalEndpoint
        )

    @property
    def loopback_endpoint(self) -> Any:
        """
        Internal Loopback endpoints to enable VPN for the engine.

        :rtype: SubElementCollection(InternalEndpoint)
        """
        return sub_collection(
            self.internal_gateway.get_relation("loopback_endpoint"), InternalEndpoint
        )

    @property
    def gateway_profile(self) -> Any:
        """
        Gateway Profile for this VPN. This is only a valid setting
        on layer 3 firewalls.

        :rtype: GatewayProfile
        """
        return Element.from_href(self.internal_gateway.gateway_profile)

    @property
    def gateway_settings(self) -> Any:
        """
        A gateway settings profile defines VPN specific settings related
        to timers such as negotiation retries (min, max) and mobike
        settings. Gateway settings are only present on layer 3 FW
        types.

        :rtype: GatewaySettings

        .. note::
            This can return None on layer 3 firewalls if VPN is not
            enabled.
        """
        return Element.from_href(self.engine.data.get("gateway_settings_ref"))

    @property
    def gateway_certificate(self) -> list[GatewayCertificate]:
        """
        A Gateway Certificate is used by the engine for securing
        communications such as VPN. You can also check the expiration,
        view the signing CA and renew the certificate from this element.

        :return: GatewayCertificate
        :rtype: list
        """
        return [
            GatewayCertificate.from_href(cert.get('href'))
            for cert in self.internal_gateway.make_request(resource="gateway_certificate")
        ]

    @property
    def gateway_certificate_request(self) -> list[GatewayCertificateRequest]:
        """
        A Gateway Certificate request is a gateway certificate that need to be signed internally
        or externally using external CA

        :return: GatewayCertificateRequest
        :rtype: list
        """
        return [
            GatewayCertificateRequest.from_href(cert.get('href'))
            for cert in self.internal_gateway.make_request(resource="gateway_certificate_request")
        ]

    def generate_certificate(
            self,
            common_name: str,
            organization: str = "Forcepoint",
            public_key_algorithm: str = "rsa",
            signature_algorithm: str = "rsa_sha_512",
            key_length: int = 2048,
            signing_ca: Optional[Any] = None,
            certificate: Optional[Any] = None,
    ) -> GatewayCertificate:
        """
        Generate an internal gateway certificate used for VPN on this engine.
        Certificate request should be an instance of VPNCertificate.

        :param: str common_name: common name for certificate
        :param: str organization: organization for certificate
        :param str public_key_algorithm: public key type to use. Valid values
            rsa, dsa, ecdsa.
        :param str signature_algorithm: signature algorithm. Valid values
            dsa_sha_1, dsa_sha_224, dsa_sha_256, rsa_md5, rsa_sha_1, rsa_sha_256,
            rsa_sha_384, rsa_sha_512, ecdsa_sha_1, ecdsa_sha_256, ecdsa_sha_384,
            ecdsa_sha_512. (Default: rsa_sha_512)
        :param int key_length: length of key. Key length depends on the key
            type. For example, RSA keys can be 1024, 2048, 3072, 4096. See SMC
            documentation for more details.
        :param str,VPNCertificateCA signing_ca: by default will use the
            internal RSA CA
        :param str, certificate : used directly call another _create_from_cert
        :raises CertificateError: error generating certificate
        :return: GatewayCertificate
        """
        if certificate:
            return GatewayCertificate._create_from_cert(self, signing_ca, certificate)
        else:
            return GatewayCertificate._create(
                self, common_name, organization, public_key_algorithm, signature_algorithm,
                key_length, signing_ca
            )

    @property
    def ssl_vpn_portal_setting(self) -> Any:
        """
        SSL VPN Portal settings for this Engine Internal Gateway.
        Deprecated since SMC >= 7.5.0 use application_access_portal_setting instead

        :rtype: List
        """
        return self.internal_gateway.ssl_vpn_portal_setting

    @property
    def application_access_portal_setting(self) -> Any:
        """
        SSL VPN Portal settings for this Engine Internal Gateway.

        :rtype: List
        """
        return self.internal_gateway.application_access_portal_setting

    @property
    def ssl_vpn_proxy(self) -> Any:
        """
        SSL VPN Proxy for SSL VPN PORTAL in Engine Internal Gateway

        :rtype: Dict
        """
        return self.internal_gateway.ssl_vpn_proxy

    @property
    def ssl_vpn_tunneling(self) -> Any:
        """
        SSL VPN VPN client tunneling setting in Engine Internal Gateway.

        :rtype: Dict
        """
        return self.internal_gateway.ssl_vpn_tunneling

    def __repr__(self) -> str:
        return "VPN(name={})".format(self.name)


class InternalGateway(SubElement):
    """
    InternalGateway represents the VPN Client configuration
    endpoint on the NGFW. Settings under Internal Gateway
    reflect client settings such as requiring antivirus,
    windows firewall and setting the VPN client mode.

        View settings through an engine reference::

            >>> engine = Engine('dingo')
            >>> vpn = engine.vpn
            >>> vpn.name
            u'dingo Primary'
            >>> vpn.vpn_client.firewall
            False
            >>> vpn.vpn_client.antivirus
            False
            >>> vpn.vpn_client.vpn_client_mode
            u'ipsec'
        Introduced all_vpns property to get list all vpn instances, Each vpn instance associated
        only one internal gateway to make code backward compatible.
            >>> list_of_all_internal_gateways=engine.all_vpns
            >>> first_vpn_instance= list_of_all_internal_gateways[0]
            >>> first_vpn_instance.name
            u'dingo Primary'
            >>> first_vpn_instance.vpn_client.firewall
            False
            >>> first_vpn_instance.vpn_client.antivirus
            False
            >>> first_vpn_instance.vpn_client.vpn_client_mode
            u'ipsec'
        Enable client AV and windows FW::

            engine.vpn.vpn_client.update(
                firewall=True, antivirus=True)

    :ivar bool firewall: require windows firewall
    :ivar bool antivirus: require client antivirus
    :ivar str vpn_client_mode:
    """

    typeof = "internal_gateway"

    def rename(self, name: str) -> None:
        self._del_cache()  # Engine update changes this ETag
        self.update(name="{} Primary".format(name))

    def remove(self) -> None:
        """
        Remove Internal Gateway from this engine.
        """
        self.delete()

    @property
    def internal_endpoint(self) -> Any:
        """
        Internal endpoints to enable VPN for the engine.

        :rtype: SubElementCollection(InternalEndpoint)
        """
        return sub_collection(self.get_relation("internal_endpoint"), InternalEndpoint)

    @property
    def vpn_site(self) -> Any:
        """
        A VPN site defines a collection of IP's or networks that
        identify address space that is defined on the other end of
        the VPN tunnel.

        :rtype: CreateCollection(VPNSite)
        """
        return create_collection(self.get_relation("vpn_site"), VPNSite)

    @property
    def dhcp_client_config(self) -> DHCPClientConfiguration:
        """
        The DHCP relay settings
        :rtype: DHCPClientConfiguration
        """
        return DHCPClientConfiguration(self.data.get("dhcp_relay", {}))

    @property
    def ssl_vpn_portal_setting(self) -> Any:
        """
        SSL VPN Portal settings for this engine.
        Deprecated since SMC >= 7.5.0 use application_access_portal_setting instead

        :rtype: List
        """
        return self.data.get("ssl_vpn_portal_setting")

    @property
    def application_access_portal_setting(self) -> Any:
        """
        SSL VPN Portal settings for this engine.

        :rtype: List
        """
        return self.data.get("application_access_portal_setting")

    @property
    def ssl_vpn_proxy(self) -> Any:
        """
        SSL VPN proxy settings for this engine.

        :rtype: Dict
        """
        return self.data.get("ssl_vpn_proxy")

    @property
    def ssl_vpn_tunneling(self) -> Any:
        """
        SSL VPN tunneling settings for this engine.

        :rtype: SSLVPNPortal
        """
        return self.data.get("ssl_vpn_tunneling")


class InternalEndpoint(SubElement):
    """
    An Internal Endpoint is an interface mapping that enables VPN on the
    associated interface.
    This also defines what type of VPN to enable such as IPSEC, SSL VPN,
    or SSL VPN Portal.

    To see all available internal endpoint (VPN gateways) on a particular
    engine, use an engine reference::

        >>> engine = Engine('sg_vm')
        >>> for e in engine.vpn.internal_endpoint:
        ...   print(e)
        ...
        InternalEndpoint(name=10.0.0.254)
        InternalEndpoint(name=172.18.1.254)

    You can also retrieve an internal endpoint directly and operate on it, for
    example, enabling it as a VPN endpoint::

        engine = Engine('sg_vm')
        my_interface = engine.vpn.internal_endpoint.get_exact('10.0.0.254')
        my_interface.update(enabled=True)

    Multiple attributes can be updated by calling `update`::

        my_interface.update(enabled=True,ipsec_vpn=True,force_nat_t=True,ssl_vpn_portal=False,ssl_vpn_tunnel=False)

    Available attributes:

    :ivar bool enabled: enable this interface as a VPN endpoint
        (default: False)
    :ivar bool nat_t: enable NAT-T (default: False)
    :ivar bool force_nat_t: force NAT-T (default: False)
    :ivar bool ssl_vpn_portal: enable SSL VPN portal on the interface
        (default: False)
    :ivar bool ssl_vpn_tunnel: enable SSL VPN tunnel on the interface
        (default: False)
    :ivar bool ipsec_vpn: enable IPSEC VPN on the interface (default: False)
    :ivar bool udp_encapsulation: Allow UDP encapsulation (default: False)
    :ivar str balancing_mode: VPN load balancing mode. Valid options are:
        'standby', 'aggregate', 'active' (default: 'active')
    """

    @property
    def name(self) -> Optional[str]:
        """
        Get the name from deducted name
        """
        return self.data.get("deducted_name")

    @property
    def interface_id(self) -> Any:
        """
        Interface ID for this VPN endpoint

        :return: str interface id
        """
        return self.physical_interface.interface_id

    @property
    def physical_interface(self) -> PhysicalInterface:
        """
        Physical interface for this endpoint.

        :rtype: PhysicalInterface
        """
        return PhysicalInterface(href=self.data.get("physical_interface"))


class ReplicaInternalGateway(SubElement):
    """
    ReplicaInternalGateway represents a replica of an internal gateway from another
    engine. This is used in VPN configurations where one engine needs to reference
    the gateway configuration of another engine.

    A replica internal gateway is linked to an actual internal gateway on a different
    engine via the linked_gateway_ref property.

    Example of accessing replica internal gateways::

        >>> engine = Engine('myengine')
        >>> for replica_gw in engine.replica_internal_gateway:
        ...     print(replica_gw.name)
        ...     print(replica_gw.linked_gateway)
        ...

    :ivar str name: Name of the replica internal gateway
    :ivar str linked_gateway_ref: Reference to the original internal gateway
    """

    typeof = "replica_internal_gateway"

    @property
    def name(self) -> str:
        """
        Get the name of the replica internal gateway.
        Returns 'name' if provided, otherwise falls back to 'display_name'.

        API naming convention:
        - With name: "Saint Paul - Test Replica Gateway"
          (engine name + user-provided name)
        - Without name: "Saint Paul - Replica of Santa Clara VPN Gateway"
          (engine name + auto-generated description in display_name)

        :return: gateway name
        :rtype: str
        """
        return self.data.get("name") or self.data.get("display_name", "")

    def rename(self, name: str) -> None:
        """
        Rename this replica internal gateway.

        :param str name: new name for the replica gateway
        :return: None
        """
        self._del_cache()  # Engine update changes this ETag
        self.update(name=name)

    def remove(self) -> None:
        """
        Remove this Replica Internal Gateway from the engine.

        :return: None
        """
        self.delete()

    @property
    def linked_gateway(self) -> Any:
        """
        The original internal gateway that this replica is linked to.
        This gateway exists on a different engine.

        :return: InternalGateway element
        :rtype: InternalGateway
        """
        return Element.from_href(self.data.get("linked_gateway_ref"))

    @property
    def replica_internal_endpoint(self) -> Any:
        """
        Replica internal endpoints associated with this replica gateway.

        :rtype: SubElementCollection(ReplicaInternalEndpoint)
        """
        return sub_collection(
            self.get_relation("replica_internal_endpoint"), ReplicaInternalEndpoint
        )

    def create_replica_endpoint(self, linked_endpoint: Any,
                                interface_ip_address: str) -> Optional[ReplicaInternalEndpoint]:
        """
        Create a replica internal endpoint on this replica gateway.

        A replica endpoint links to an actual internal endpoint from the source gateway
        and uses a local interface IP address from this engine.

        :param linked_endpoint: The source internal endpoint to link to (from the original gateway).
                               Can be an InternalEndpoint object or an href string.
        :type linked_endpoint: InternalEndpoint or str
        :param str interface_ip_address: The IP address of the local interface to use for this
                                         replica endpoint
        :raises ActionCommandFailed: When creation fails
        :return: The created ReplicaInternalEndpoint
        :rtype: ReplicaInternalEndpoint

        Example::

            >>> engine = Engine('plano')
            >>> replica_gw = engine.replica_internal_gateway[0]
            >>> source_endpoint = InternalEndpoint(href='http://...')  # From source gateway
            >>> replica_endpoint = replica_gw.create_replica_endpoint(
            ...     linked_endpoint=source_endpoint,
            ...     interface_ip_address='192.168.1.1'
            ... )
            >>> print(replica_endpoint.name)
            192.168.1.1
        """
        if hasattr(linked_endpoint, 'href'):
            linked_endpoint_ref = linked_endpoint.href
        else:
            linked_endpoint_ref = linked_endpoint


        data = {
            "linked_endpoint_ref": linked_endpoint_ref,
            "interface_ip_address": interface_ip_address,
        }

        self.make_request(
            method="create",
            resource="replica_internal_endpoint",
            json=data
        )

        self.data.pop('replica_internal_endpoint', None)
        for endpoint in self.replica_internal_endpoint:
            if endpoint.interface_ip_address == interface_ip_address:
                return endpoint


        return None


class ReplicaInternalEndpoint(SubElement):
    """
    A Replica Internal Endpoint is a copy of an internal endpoint from another
    engine's internal gateway. This is used in VPN configurations where endpoints
    from one engine need to be referenced by another engine.

    Example::

        >>> engine = Engine('myengine')
        >>> replica_gw = engine.replica_internal_gateway[0]
        >>> for endpoint in replica_gw.replica_internal_endpoint:
        ...     print(endpoint.name)
        ...     print(endpoint.interface_ip_address)
        ...     print(endpoint.linked_endpoint)
        ...

    :ivar str interface_ip_address: IP address of the interface
    :ivar str linked_endpoint_ref: Reference to the original internal endpoint
    """

    typeof = "replica_internal_endpoint"

    @property
    def name(self) -> Optional[str]:
        """
        Get the name from deducted name or name field.

        :return: endpoint name
        :rtype: str
        """
        return self.data.get("deducted_name") or self.data.get("name")

    @property
    def interface_ip_address(self) -> Optional[str]:
        """
        IP address of the interface for this replica endpoint.

        :return: IP address
        :rtype: str
        """
        return self.data.get("interface_ip_address")

    @property
    def linked_endpoint(self) -> Any:
        """
        The original internal endpoint that this replica is linked to.
        This endpoint exists on a different engine's internal gateway.

        :return: InternalEndpoint element
        :rtype: InternalEndpoint
        """
        return Element.from_href(self.data.get("linked_endpoint_ref"))

    @property
    def linked_endpoint_ref(self) -> Optional[str]:
        """
        Reference (href) to the original internal endpoint.

        :return: href to the linked endpoint
        :rtype: str
        """
        return self.data.get("linked_endpoint_ref")


class VirtualResource(SubElement):
    """
    A Virtual Resource is a container placeholder for a virtual engine
    within a Master Engine. When creating a virtual engine, each virtual
    engine must have a unique virtual resource for mapping. The virtual
    resource has an identifier (vfw_id) that specifies the engine ID for
    that instance.

    This is called as a resource of an engine. To view all virtual
    resources::

        list(engine.virtual_resource.all())

    Available attributes:

    :ivar int connection_limit: Maximum number of connections for this virtual
        engine. 0 means unlimited (default: 0)
    :ivar bool show_master_nic: Show the master engine NIC id's in the virtual
        engine.

    When updating this element, make modifications and call update()
    """

    typeof = "virtual_resource"

    def create(
            self,
            name: str,
            vfw_id: int,
            domain: str = "Shared Domain",
            show_master_nic: bool = False,
            connection_limit: int = 0,
            comment: Optional[str] = None,
    ) -> str:
        """
        Create a new virtual resource. Called through engine
        reference::

            engine.virtual_resource.create(....)

        :param str name: name of virtual resource
        :param int vfw_id: virtual fw identifier
        :param str domain: name of domain to install, (default Shared)
        :param bool show_master_nic: whether to show the master engine NIC ID's
               in the virtual instance
        :param int connection_limit: whether to limit number of connections for
            this instance
        :return: href of new virtual resource
        :rtype: str
        """
        allocated_domain = domain_helper(domain)
        json = {
            "name": name,
            "connection_limit": connection_limit,
            "show_master_nic": show_master_nic,
            "vfw_id": vfw_id,
            "comment": comment,
            "allocated_domain_ref": allocated_domain,
        }

        return ElementCreator(self.__class__, json=json, href=self.href)

    @property
    def allocated_domain_ref(self) -> Any:
        """
        Domain that this virtual engine is allocated in. 'Shared Domain' is
        is the default if no domain is specified.
        ::

            >>> for resource in engine.virtual_resource:
            ...   resource, resource.allocated_domain_ref
            ...
            (VirtualResource(name=ve-1), AdminDomain(name=Shared Domain))
            (VirtualResource(name=ve-8), AdminDomain(name=Shared Domain))

        :return: AdminDomain element
        :rtype: AdminDomain
        """
        return Element.from_href(self.data.get("allocated_domain_ref"))

    def set_admin_domain(self, admin_domain: Any) -> None:
        """
        Virtual Resources can be members of an Admin Domain to provide
        delegated administration features. Assign an admin domain to
        this resource. Admin Domains must already exist.

        :param str,AdminDomain admin_domain: Admin Domain to add
        :return: None
        """
        admin_domain = element_resolver(admin_domain)
        self.data["allocated_domain_ref"] = admin_domain

    @property
    def vfw_id(self) -> Optional[int]:
        """
        Read-Only virtual engine identifier. This is unique per virtual engine
        and is set when the virtual resource is created.

        :return: vfw id
        :rtype: int
        """
        return self.data.get("vfw_id")


class LBFilter(NestedDict):
    """
    This represents the Load Balancing Filter.
    """

    def __init__(self, action: str, ip_descriptor: str, replace_ip: str, nodeid: int,
                 ignore_other: bool = False, nat_enforce: bool = False,
                 use_ipsec: bool = False, use_ports: bool = False) -> None:
        data = {"action": action, "ignore_other": ignore_other, "ip_descriptor": ip_descriptor,
                "nat_enforce": nat_enforce, "nodeid": nodeid, "replace_ip": replace_ip,
                "use_ipsec": use_ipsec, "use_ports": use_ports}
        super(LBFilter, self).__init__(data=data)

    @classmethod
    def create(cls, nodeid: int, ip_descriptor: str, replace_ip: str,
               action: str = "replace", ignore_other: bool = False, nat_enforce: bool = False,
               use_ipsec: bool = False, use_ports: bool = False) -> LBFilter:
        """
        Create a LB Filter.

        :param int nodeid: Node Id in case of node action
        :param str ip_descriptor: Represents the IPNetwork or the IPAddressRange
        :param str replace_ip: Address in case of replace action.
        :param str action: Action for the filter.
                           possible values are: none, replace, node, select_none, replace_offset
        :param bool ignore_other: Tell that other entries might not be concerned.
        :param bool nat_enforce: Tells NAT to enforce translated packet headers
                                 to the same hash value to the matching packet.
        :param bool use_ipsec: Tells the engine that this entry has to be handled with
                               special care because part of VPN
        :param bool use_ports: Defines whether to use port numbers
                               when calculating the hash value for the packet.

        :rtype: LBFilter
        """
        return LBFilter(action=action, ignore_other=ignore_other, ip_descriptor=ip_descriptor,
                        nat_enforce=nat_enforce, nodeid=nodeid, replace_ip=replace_ip,
                        use_ipsec=use_ipsec, use_ports=use_ports)

    @property
    def action(self) -> str:
        """
        Action for the filter.
        possible values are: none, replace, node, select_none, replace_offset
        :rtype: str
        """
        return self.get("action")

    @action.setter
    def action(self, value: str) -> None:
        self.update(action=value)

    @property
    def ip_descriptor(self) -> str:
        """
        Represents the IPNetwork or the IPAddressRange

        :rtype: str
        """
        return self.get("ip_descriptor")

    @ip_descriptor.setter
    def ip_descriptor(self, value: str) -> None:
        self.update(ip_descriptor=value)

    @property
    def replace_ip(self) -> str:
        """
        Address in case of replace action.

        :rtype: str
        """
        return self.get("replace_ip")

    @replace_ip.setter
    def replace_ip(self, value: str) -> None:
        self.update(replace_ip=value)

    @property
    def use_ipsec(self) -> bool:
        """
        Tells the engine that this entry has to be handled with
        special care because part of VPN

        :rtype: bool
        """
        return self.get("use_ipsec")

    @use_ipsec.setter
    def use_ipsec(self, value: bool) -> None:
        self.update(use_ipsec=value)

    @property
    def use_ports(self) -> bool:
        """
        Defines whether to use port numbers
        when calculating the hash value for the packet.

        :rtype: bool
        """
        return self.get("use_ports")

    @use_ports.setter
    def use_ports(self, value: bool) -> None:
        self.update(use_ports=value)

    @property
    def nat_enforce(self) -> bool:
        """
        Tells NAT to enforce translated packet headers
        to the same hash value to the matching packet.

        :rtype: bool
        """
        return self.get("nat_enforce")

    @nat_enforce.setter
    def nat_enforce(self, value: bool) -> None:
        self.update(nat_enforce=value)

    @property
    def ignore_other(self) -> bool:
        """
        Tell that other entries might not be concerned.

        :rtype: bool
        """
        return self.get("ignore_other")

    @ignore_other.setter
    def ignore_other(self, value: bool) -> None:
        self.update(ignore_other=value)


class IdleTimeout(NestedDict):
    """
    This is definition of timeout by protocol or by TCP connection state. You can define general
    timeouts for removing idle connections from the state table, including non-TCP communications
    that are handled like connections. The timeout prevents wasting engine resources on storing
    information about abandoned connections. Timeouts are a normal way to clear traffic information
    with protocols that have no closing mechanism.Timeouts do not affect active connections.
    The connections are kept in the state table as long as the interval of packets within a
    connection is shorter than the timeouts set.
    """
    default_protocol_values = {"tcp": 1800, "udp": 50, "icmp": 5, "other": 180, "tcp_closing": 60,
                               "tcp_syn_seen": 15, "tcp_fin_wait_1": 60, "tcp_fin_wait_2": 60,
                               "tcp_time_wait": 60, "tcp_close_wait": 60, "tcp_last_ack": 10,
                               "tcp_syn_ack_seen": 15, "tcp_time_wait_ack": 60,
                               "tcp_closing_ack": 60, "tcp_close_wait_ack": 60,
                               "tcp_last_ack_wait": 10, "tcp_syn_fin_seen": 15,
                               "tcp_syn_return": 15,
                               "ipsec_established": 72
                               }

    def __init__(self, engine: Engine) -> None:
        ars = {"connection_timeout": engine.data.get("connection_timeout", {})}
        super(IdleTimeout, self).__init__(data=ars)

    def add(self, name: str, timeout: Optional[int] = None) -> None:
        """
        Add a timeout setting for the new protocol.
        :param str name: name of the protocol.
        :param int timeout: timeout value.
        """
        if name in self.default_protocol_values:
            if not timeout:
                timeout = self.default_protocol_values[name]
            self.data.get('connection_timeout').append({'protocol': name, 'timeout': timeout})
        else:
            raise ("Invalid protocol found : {}".format(name))

    def remove(self, name: str) -> None:
        """
        Remove the timeout setting for specific protocols on the engine.
        :param str name: namr of the protocol to be removed.
        """
        for protocol in self.data.get('connection_timeout'):
            if name == protocol['protocol']:
                self.data['connection_timeout'].remove(protocol)
                break

    def _contains(self, name: str) -> bool:
        """
        Check if specific protocol settings are present in the engine.
        :param str name: name of protocol.
        """
        for protocol in self.data.get('connection_timeout'):
            if name == protocol['protocol']:
                return True
        return False


class LocalLogStorageSettings(NestedDict):
    """
    Local Log Storage Settings for not virtual engines.
    """

    def __init__(self, engine: Engine) -> None:
        ars = engine.data.get("local_log_storage", {})
        super(LocalLogStorageSettings, self).__init__(data=ars)

    @property
    def lls_guaranteed_free_percent(self) -> Optional[int]:
        """
        Minimum amount of spool space that must be left available for other uses in percentage
        """
        return self.data.get("lls_guaranteed_free_percent")

    @property
    def lls_guaranteed_free_size_in_mb(self) -> Optional[int]:
        """
        Minimum amount of spool space that must be left available for other uses in MegaBytes
        """
        return self.data.get("lls_guaranteed_free_size_in_mb")

    @property
    def lls_max_time(self) -> Optional[int]:
        """
        The maximum amount of hours before the stored logs are deleted.
        """
        return self.data.get("lls_max_time")

    @property
    def local_log_storage_activated(self) -> Optional[bool]:
        """
        Activate the Local Log Storage feature. At least one of the Guaranteed free disk partition
        values must be set up.
        """
        return self.data.get("local_log_storage_activated")


class HAForSingleEngine(object):
    """
    High availability configuration on the single engine. Access through an engine reference::

        engine.ha_settings.ha_backup_unit
        engine.ha_settings.set_ha_backup_unit(pos='1234567890-1234567890')
        engine.ha_settings.disable_ha_backup_unit()

        engine.ha_settings.connection_sync_mode
        engine.ha_settings.set_connection_sync(ha_connection_sync_interface=0,
                                               connection_sync_group=connection_sync_group_name)
        engine.ha_settings.disable_connection_sync()

    When making changes to the HA configuration, any methods
    called that change the configuration also require that
    engine.update() is called once changes are complete. This way
    you can make multiple changes without refreshing the engine cache.

    :ivar ConnectionSynchronizationGroup connection_sync_group: ConnectionSynchronizationGroup
    reference for this engine. Applicable when HA mode is connection_sync.
    """

    connection_sync_group = ElementRef("connection_sync_group")

    def __init__(self, data: Optional[Any] = None) -> None:
        self.data = data if data else ElementCache()

    @property
    def ha_backup_unit_mode(self) -> Optional[str]:
        """
        Get high availability backup unit mode for this engine

        :return: str or None
        """
        return self.data.get("ha_backup_unit_mode")

    @property
    def connection_sync_mode(self) -> Optional[str]:
        """
        Get connection synchronization for external high availability mode for this engine

        :return: str or None
        """
        return self.data.get("connection_sync_mode")

    @property
    def pos(self) -> Optional[str]:
        """
        proof of serial for hugh availability.
        Applicable when HA backup unit mode is enabled.

        :rtype: str or None
        """
        return self.data.get("ha_pos_for_backup_unit")

    @property
    def sync_interface(self) -> Optional[int]:
        """
        ID of the interface for unicast state
        Applicable when HA mode is connection_sync.

        :rtype: int or None
        """
        return self.data.get("ha_connection_sync_interface")

    def disable_ha_backup_unit(self) -> None:
        """
        Disable HA backup unit mode on this engine.

        :return: None
        """
        self.data.update(ha_backup_unit_mode='disabled')

    def disable_connection_sync(self) -> None:
        """
        Disable connection synchronization for external high availability on this engine.

        :return: None
        """
        self.data.update(connection_sync_mode='disabled')

    def set_ha_backup_unit(self, pos: Optional[str] = None) -> None:
        """
        Enable high availability backup unit on this engine.
        Disable connection synchronization for external high availability.

        :param str pos: proof of serial for pairing
        :return: None
        """
        self.data.update(ha_backup_unit_mode='enabled', ha_pos_for_backup_unit=pos,
                         connection_sync_mode='disabled')

    def set_connection_sync(self, connection_sync_group: Any,
                            ha_connection_sync_interface: Any) -> None:
        """
        Enable connection synchronization for external high availability on this engine.
        Disable high availability backup unit.

        :param str,ConnectionSynchronizationGroup connection_sync_group:
         ConnectionSynchronizationGroup element or str href
        :param str ha_connection_sync_interface: ID of the interface for unicast state
        synchronization
        :raises ElementNotFound: ConnectionSynchronizationGroup not found
        :return: None
        """
        if isinstance(connection_sync_group, str):
            sync_group = ConnectionSynchronizationGroup(connection_sync_group).href
        else:
            sync_group = connection_sync_group.href

        self.data.update(connection_sync_mode='enabled', connection_sync_group=sync_group,
                         ha_connection_sync_interface=ha_connection_sync_interface,
                         ha_backup_unit_mode='disabled')


class SidewinderProxyAdvancedSettings(NestedDict):
    """
    Represents Sidewinder Proxy Advanced settings.
    """
    types = ("SHARED", "HTTP", "SSH", "TCP", "UDP")

    def __init__(self, data: Any) -> None:
        super(SidewinderProxyAdvancedSettings, self).__init__(data=data)

    @classmethod
    def create(cls, sidewinder_type: Optional[str] = None, attribute: Optional[str] = None,
               value: Optional[str] = None) -> SidewinderProxyAdvancedSettings:
        """
        :param str sidewinder_type: The allowed Sidewinder Types:
                1. SHARED - Shared setting - will set the value for all proxies.
                2. HTTP - HTTP proxy.  Sets the value for the HTTP Proxy.
                3. SSH - SSH proxy.  Sets the value for the SSH Proxy.
                4. TCP - TCP proxy.  Sets the value for the TCP Proxy.
                5. UDP - UDP proxy.  Sets the value for the UDP Proxy.
            Required.
        :param str attribute: The attribute or name of the setting.
        :param str value: The value of the setting.
        """
        if sidewinder_type not in cls.types:
            raise UnsupportedSidewinderType("Invalid sidewinder proxy advanced settings type.")
        json = {
            "type": sidewinder_type,
            "attribute": attribute,
            "value": value
        }
        return cls(json)


class ScanDetectionSetting(NestedDict):
    """
    This represents the definition of Scan Detection on a NGFW. Before an attack, potential
    attackers may scan the network for open ports. When you enable Scan Detection on a Firewall,
    IPS engine, Layer 2 Firewall, Master NGFW Engine, or Virtual Security Engine, the number of
    connections or connection attempts within a time window is counted. If the number of events hits
    the threshold, an alert is generated.
    """

    def __init__(self, data: Any) -> None:
        super(ScanDetectionSetting, self).__init__(data=data)

    @classmethod
    def create(cls, alert_ref: Optional[Any] = None, severity: int = 1,
               log_level: str = "stored",
               scan_detection_type: str = "default off", scan_detection_icmp_events: int = 220,
               scan_detection_icmp_timewindow: int = 1, scan_detection_icmp_unit: str = "minute",
               scan_detection_tcp_events: int = 220, scan_detection_tcp_timewindow: int = 1,
               scan_detection_tcp_unit: str = "minute",
               scan_detection_udp_events: int = 220, scan_detection_udp_timewindow: int = 1,
               scan_detection_udp_unit: str = "minute") -> ScanDetectionSetting:
        """
        :param alert_ref: If you selected Alert as the Log Level, enter the Alert.
            Required if Alert chosen.
        :param severity: If Log Level is set to Alert, allows you to override the severity defined
            in the Alert element.
            1. Info
            2-4: Low
            5-7: High
            8-10: Critical
        :param log_level: The Log Level
            none: Does not create any log entry.
            transient: Creates a log entry that is displayed in the Current Events mode in the Logs
                view (if someone is viewing it at the moment) but is not stored.
            stored: Creates a log entry that is stored on the Log Server.</li>
            essential: Creates a log entry that is shown in the Logs view and saved for further use.
                When the Log Server is unavailable, log entries are temporarily stored on the engine
                When the engine is running out of space to store the log entries, it begins
                discarding log data in the order of importance. Monitoring data is discarded first
                followedby log entries marked as Transient and Stored, and finally log entries
                marked as Essential.The Alert entries are the last log entries to be discarded.
                Note! The settings for storing the logs temporarily on the engine are defined in the
                log spooling policy.
            alert: Triggers the alert you add to the Alert field.
        :param scan_detection_type: The Type of Scan detection:
            1. off: Scan Detection is not enabled.
            2. default off: Scan Detection is not enabled, but you can override this setting in
                individual Access rules. This is the default setting.
            3. default on: Scan Detection is enabled. You can override this setting in individual
                Access rules if scan detection is not needed or to avoid false positives.</li>
        :param scan_detection_icmp_events: The ICMP Scan Events sensitivity.
        :param scan_detection_icmp_timewindow: The ICMP Time windows in seconds.
        :param scan_detection_icmp_unit: The ICMP Scan time window unit, By default in minutes.
            1. second
            2. minute
            3. hour
        :param scan_detection_tcp_events: The TCP Scan Events sensitivity.
        :param scan_detection_tcp_timewindow: The TCP Time windows in seconds.
        :param scan_detection_tcp_unit: The TCP Scan time window unit, By default in minutes.
            1. second
            2. minute
            3. hour
        :param scan_detection_udp_events: The UDP Scan Events sensitivity.
        :param scan_detection_udp_timewindow: The UDP Time windows in seconds.
        :param scan_detection_udp_unit: The UDP Scan time window unit, By default in minutes.
            1. second
            2. minute
            3. hour
        """

        json = {
            "log_level": log_level,
            "scan_detection_icmp_events": scan_detection_icmp_events,
            "scan_detection_icmp_timewindow": scan_detection_icmp_timewindow,
            "scan_detection_icmp_unit": scan_detection_icmp_unit,
            "scan_detection_tcp_events": scan_detection_tcp_events,
            "scan_detection_tcp_timewindow": scan_detection_tcp_timewindow,
            "scan_detection_tcp_unit": scan_detection_tcp_unit,
            "scan_detection_type": scan_detection_type,
            "scan_detection_udp_events": scan_detection_udp_events,
            "scan_detection_udp_timewindow": scan_detection_udp_timewindow,
            "scan_detection_udp_unit": scan_detection_udp_unit,
        }
        if log_level == "alert":
            json.update(alert_ref=element_resolver(alert_ref), severity=severity)
        return cls(json)


class StaticMulticastRoute(NestedDict):
    """
    Represents Firewall multicast routing entry for Static/IGMP Proxy multicast routing modes.
    """

    def __init__(self, data: Any) -> None:
        super(StaticMulticastRoute, self).__init__(data=data)

    @classmethod
    def create(cls, source_ip: Optional[str] = None, source_interface: Optional[str] = None,
               dest_ip: Optional[str] = None,
               dest_interface: Optional[list[str]] = None) -> StaticMulticastRoute:
        """
        :param source_ip: The Source IP Address.`
        :param source_interface: The Source Interface given by its ID.
        :param dest_ip: The Destination IP Address.
        :param list(str) dest_interface: The Destination Interfaces given by their ID.
        :rtype: StaticMulticastRoute
        """

        json = {
            "source_ip": source_ip,
            "source_interface": source_interface,
            "dest_ip": dest_ip,
            "dest_interface": dest_interface
        }
        return cls(json)


class WebAuthentication(NestedDict):
    """
    The Browser-Based User Authentication settings
    """

    def __init__(self, data: Any) -> None:
        super(WebAuthentication, self).__init__(data=data)

    @classmethod
    def create(cls, all_interfaces: bool = True, authentication_idle_timeout: int = 3600,
               authentication_timeout: int = 3600, enabled_interface: Optional[list[Any]] = None,
               enforce_https: bool = False, http_port: Optional[int] = None,
               https_port: Optional[int] = None, keep_alive_rate: int = 30, key_length: int = 0,
               page_ref: Optional[Any] = None, session_handling: bool = False,
               use_cert_bba: bool = False, tls_profile: Optional[Any] = None) -> WebAuthentication:
        """
        :param bool all_interfaces: Flag to tell if we restrict listening interfaces. or if listen
            on all interfaces. Ignored if HTTP or HTTPS are not enabled
        :param int authentication_idle_timeout: Authentication Idle Time Out (seconds).
        :param int authentication_timeout: Authentication Time Out (seconds).
        :param enabled_interface: List of listening interfaces Ignored if HTTP or HTTPS are not
            enabled.
        :param bool enforce_https: Flag telling if HTTPS must be enforced. Ignored if HTTP or HTTPS
            are not enabled.
        :param int http_port: Port on which HTTP listens. If None, HTTP is not enabled.
        :param int https_port: Port on which HTTPS listens. If null, HTTPS is not enabled.
        :param int keep_alive_rate: Refresh status every X seconds. If null, it is disabled.
            Ignored if HTTP or HTTPS are not enabled.
        :param int key_length: Key length for certificate. Specified by username, together with
            subject name. Ignored if HTTP or HTTPS are not enabled
        :param WebAuthHtmlPage page_ref: Get template for login page. May be null if nothing is
            defined. Ignored if HTTP or HTTPS are not enabled.
        :param bool session_handling: Enable session handling. Ignored if HTTP or HTTPS are not
            enabled
        :param bool use_cert_bba: Use Certificate Base Authentication. Ignored if HTTP or HTTPS are
            not enabled.
        :param TLSProfile tls_profile: TLS Profile used Certificates Based Authentication.
            Ignored if HTTP or HTTPS are not enabled
        :rtype: WebAuthentication
        """
        enabled_interface = enabled_interface if enabled_interface else []
        json = {
            "all_interfaces": all_interfaces,
            "authentication_idle_timeout": authentication_idle_timeout,
            "authentication_timeout": authentication_timeout,
            "key_length": key_length,
            "enforce_https": enforce_https,
            "page_ref": element_resolver(page_ref),
            "session_handling": session_handling,
            "enabled_interface": enabled_interface,
            "use_cert_bba": use_cert_bba
        }

        if https_port or http_port:
            json.update(keep_alive_rate=keep_alive_rate)
            if https_port:
                json.update(tls_profile=element_resolver(tls_profile), https_port=https_port)
            if http_port:
                json.update(http_port=http_port)

        return cls(json)


class Nat64Settings(NestedDict):
    """
    The NAT 64 settings:
    IPv6 transition mechanisms enable communication between devices that have only IPv4 addresses
    and devices that have only IPv6 address. They can also enable limited IPv4 top
    IPv4 communication over IPv6 only network connections.
    These translation mechanisms do the translation between IPv4 and IPv6 addresses.
    * The IPv6 transition mechanism feature is not supported on Virtual Engines.
    * Only one translation mode can be activated at a time.
    * In order to use these translation mechanisms Secure SD-WAN engine must have at least
    one IPv4 address and at least one IPv6 address.
    * Protocols with separate control and data or media connections and connections that use
    IPv4 or IPv6 addresses in the payload will not work through these translation mechanisms.
    * IPv6 prefixes used in the translations must not overlap with the engines own IPv6 addresses.
    * Translation in the transition mechanisms support only unicast communication.
    * Translated connections traverse through Secure SD-WAN as two separate connections.
    However, depending on the translation mode, either IPv4 or IPv6 packets to and
    from translation are handled without creating rules manually.
    * Use of translation can lead to Path MTU discovery related problems if there are
    any faults in the way the networks in the path work.
    """

    def __init__(self, data: Any) -> None:
        super(Nat64Settings, self).__init__(data=data)

    @classmethod
    def create(cls, clat_local_ipv6_prefix_ip: str, clat_local_ipv6_prefix_ref: Any,
               clat_remote_ipv6_prefix_ip: str, clat_remote_ipv6_prefix_ref: Any,
               nat64_local_pools_ref: Any, nat64_ipv6_prefix_ip: str, nat64_ipv6_prefix_ref: Any,
               nat64_mapping: list[Any], siit_eam_ipv6_pool_ip: str, siit_eam_ipv6_pool_ref: Any,
               siit_eam_mapping: list[Any], mode: str = "none") -> Nat64Settings:
        """
        :param str clat_local_ipv6_prefix_ip: For 464XLAT CLAT mode, the local
        IPv6 prefix address.
        :param Network clat_local_ipv6_prefix_ref: For 464XLAT CLAT mode, the local
        IPv6 prefix element.
        :param str clat_remote_ipv6_prefix_ip: For 464XLAT CLAT mode, the remote
        IPv6 prefix address.
        :param Network clat_remote_ipv6_prefix_ref: For 464XLAT CLAT mode, the remote
        IPv6 prefix element.
        :param list of Network nat64_local_pools_ref: For NAT64 mode, the Networks for
        local IPv4 pools.
        :param str nat64_ipv6_prefix_ip: For NAT64 mode, the IPv6 prefix address.
        :param Network nat64_ipv6_prefix_ref: For NAT64 mode, the IPv6 prefix element.
        :param list of Nat64Mapping nat64_mapping: For NAT64 mode, the list of static mappings.
        :param str siit_eam_ipv6_pool_ip: For SIIT EAM mode, the default IPv6 pool address.
        :param Network siit_eam_ipv6_pool_ref: For SIIT EAM mode, the default IPv6 pool element.
        :param list of SiitMapping siit_eam_mapping: For SIIT EAM mode, the list of mappings.
        :param str mode:
         * nat64: NAT64 is a stateful IPv6 to IPv4 translation mechanism defined in RFC 6146.
         When NAT64 mechanism is activated, access rules that control traffic are made in the
         IPv6 side. IPv6 traffic with destination address matching the configured prefix will go
         to NAT64 translation.
         There is no need to create any rules for this traffic in the IPv4 access rules.
         All traffic configured to the IPv4 pool will go to translation.
           - NAT64 supports only unicast UDP, TCP, and ICMP traffic.
           - NAT64 can not be used with active-active clustering.
           - In the RFC 6877, NAT64 is referred as 464XLAT PLAT.
           - Due to RFC 6146 compliant NAT functionality, size of the IPv4 pool will set
           strict limit to maximum number of connections.
           - Due to RFC 6146 compliant NAT implementation, there will be additional
           connection state for the NAT processing.
           - Local IPv4 pool addresses must not overlap with the engines own addresses
           or NAT addresses used in IPv4 rules.
         * 464xlat_clat: Client side translation of RFC 6877. Used together with 464XLAT PLAT at
         the other edge of IPv6 only network in order to allow IPv4 traffic through IPv6
         only network. When used, local IPv4 addresses are detected based on the configured
         routing. Access rules controlling the traffic must be made in the IPv4 access rules.
         There is no need to create any rules for translated traffic in the IPv6 access rules.
         In the IPv4 side, traffic which does not have any route will be sent to translation.
         In the IPv6 side, the traffic from the remote IPv6 prefix to the local IPv6
         prefix will be sent to translation.
         * siit_eam: Stateless IPv4/IPv6 translation as defined in RFC 7757.
         When used without defining any explicit address mapping entries, same as SIIT,
         access rules controlling the traffic must be made in the IPv4 access rules.
         There is no need to create any rules for translated traffic in the IPv6 access rules.
         In the IPv4 side, traffic which does not have any route will be sent to translation.
         In the IPv6 side, traffic which will have valid IPv4 route after translation are sent
         to translation.
        :rtype: Nat64Settings
        """
        json = {
            "clat_local_ipv6_prefix_ip": clat_local_ipv6_prefix_ip,
            "clat_local_ipv6_prefix_ref": element_resolver(clat_local_ipv6_prefix_ref),
            "clat_remote_ipv6_prefix_ip": clat_remote_ipv6_prefix_ip,
            "clat_remote_ipv6_prefix_ref": element_resolver(clat_remote_ipv6_prefix_ref),
            "nat64_local_pools_ref": element_resolver(nat64_local_pools_ref),
            "nat64_ipv6_prefix_ip": nat64_ipv6_prefix_ip,
            "nat64_ipv6_prefix_ref": element_resolver(nat64_ipv6_prefix_ref),
            "nat64_mapping": nat64_mapping,
            "siit_eam_ipv6_pool_ip": siit_eam_ipv6_pool_ip,
            "siit_eam_ipv6_pool_ref": element_resolver(siit_eam_ipv6_pool_ref),
            "siit_eam_mapping": siit_eam_mapping,
            "mode": mode
        }

        return cls(json)

    @property
    def clat_local_ipv6_prefix_ip(self) -> Optional[str]:
        """
        For 464XLAT CLAT mode, the local
        IPv6 prefix address.
        :rtype: str
        """
        return self.data.get("clat_local_ipv6_prefix_ip")

    @property
    def clat_local_ipv6_prefix_ref(self) -> Any:
        """
        For 464XLAT CLAT mode, the local
        IPv6 prefix element.
        :rtype: Network
        """
        return Element.from_href(self.data.get("clat_local_ipv6_prefix_ref"))

    @property
    def clat_remote_ipv6_prefix_ip(self) -> Optional[str]:
        """
        For 464XLAT CLAT mode, the remote
        IPv6 prefix address.
        :rtype: str
        """
        return self.data.get("clat_remote_ipv6_prefix_ip")

    @property
    def clat_remote_ipv6_prefix_ref(self) -> Any:
        """
        For 464XLAT CLAT mode, the remote
        IPv6 prefix element.
        :rtype: Network
        """
        return Element.from_href(self.data.get("clat_remote_ipv6_prefix_ref"))

    @property
    def nat64_local_pools_ref(self) -> list[Any]:
        """
        For NAT64 mode, the Networks for
        local IPv4 pools.

        :return: list of Network
        """
        return [Element.from_href(e) for e in self.data.get("nat64_local_pools_ref")]

    @property
    def nat64_ipv6_prefix_ip(self) -> Optional[str]:
        """
        For NAT64 mode, the IPv6 prefix address.
        :rtype: str
        """
        return self.data.get("nat64_ipv6_prefix_ip")

    @property
    def nat64_ipv6_prefix_ref(self) -> Any:
        """
        For NAT64 mode, the IPv6 prefix element.
        :rtype: Network
        """
        return Element.from_href(self.data.get("nat64_ipv6_prefix_ref"))

    @property
    def siit_eam_ipv6_pool_ip(self) -> Optional[str]:
        """
        For SIIT EAM mode, the default IPv6 pool address.
        :rtype: str
        """
        return self.data.get("siit_eam_ipv6_pool_ip")

    @property
    def siit_eam_ipv6_pool_ref(self) -> Any:
        """
        For SIIT EAM mode, the default IPv6 pool element.
        :rtype: Network
        """
        return Element.from_href(self.data.get("siit_eam_ipv6_pool_ref"))

    @property
    def mode(self) -> Optional[str]:
        """
        the mode:
          * nat64
          * 464xlat_clat
          * siit_eam
        :rtype: str
        """
        return self.data.get("mode")

    @property
    def nat64_mapping(self) -> list[Nat64Mapping]:
        """
        For NAT64 mode, the list of static mappings.
        :return: list of Nat64Mapping or empty if not defined.
        """
        return [Nat64Mapping(entry) for entry in
                self.data.get("nat64_mapping", [])]

    @property
    def siit_eam_mapping(self) -> list[SiitMapping]:
        """
        For SIIT EAM mode, the list of mappings.
        :return: list of SiitMapping or empty if not defined.
        """
        return [SiitMapping(entry) for entry in
                self.data.get("siit_eam_mapping", [])]


class Nat64Mapping(NestedDict):
    """
    The NAT 64 mapping
    """
    def __init__(self, data: Any) -> None:
        super(Nat64Mapping, self).__init__(data=data)

    @classmethod
    def create(cls, nat64_mapping_ipv6_address: str, nat64_mapping_ipv6_port: int,
               nat64_mapping_protocol_ref: Any, nat64_mapping_ipv4_address: str,
               nat64_mapping_ipv4_port: int, rank: int, comment: str) -> Nat64Mapping:
        """
        :param str nat64_mapping_ipv6_address: the IPv6 address.
        :param int nat64_mapping_ipv6_port: the port for IPv6 part.
        :param ServiceIP nat64_mapping_protocol_ref: Protocol, as a referenced ServiceIP element.
        :param str nat64_mapping_ipv4_address: the IPv4 address.
        :param int nat64_mapping_ipv4_port: the port for IPv4 part.
        :param int rank: the rank for ordering mappings
        If not set, it means any.
        :param str comment
        :rtype: dict
        """
        data = {
            "nat64_mapping_ipv6_address": nat64_mapping_ipv6_address,
            "nat64_mapping_ipv6_port": nat64_mapping_ipv6_port,
            "nat64_mapping_protocol_ref": element_resolver(nat64_mapping_protocol_ref),
            "nat64_mapping_ipv4_address": nat64_mapping_ipv4_address,
            "nat64_mapping_ipv4_port": nat64_mapping_ipv4_port,
            "rank": rank,
            "comment": comment
        }
        return cls(data)

    @property
    def nat64_mapping_ipv6_address(self) -> Optional[str]:
        """
        the IPv6 address.
        :rtype: str
        """
        return self.data.get("nat64_mapping_ipv6_address")

    @property
    def nat64_mapping_ipv6_port(self) -> int:
        """
        the port for IPv6 part.
        :rtype: int
        """
        return int(self.data.get("nat64_mapping_ipv6_port"))

    @property
    def nat64_mapping_protocol_ref(self) -> Any:
        """
        the Protocol, as a referenced ServiceIP element.
        :rtype: int
        """
        return Element.from_href(self.data.get("nat64_mapping_protocol_ref"))

    @property
    def nat64_mapping_ipv4_address(self) -> Optional[str]:
        """
        the IPv4 address.
        :rtype: str
        """
        return self.data.get("nat64_mapping_ipv4_address")

    @property
    def nat64_mapping_ipv4_port(self) -> int:
        """
        the port for IPv4 part.
        :rtype: int
        """
        return int(self.data.get("nat64_mapping_ipv4_port"))

    @property
    def rank(self) -> int:
        """
        the rank for ordering mappings.
        :rtype: int
        """
        return int(self.data.get("rank"))

    @property
    def comment(self) -> Optional[str]:
        """
        the comment.
        :rtype: str
        """
        return self.data.get("comment")


class SiitMapping(NestedDict):
    """
    The mapping for SIIT EAM mode.
    """

    def __init__(self, data: Any) -> None:
        super(SiitMapping, self).__init__(data=data)

    @classmethod
    def create(cls, siit_eam_mapping_ipv6_prefix: str, siit_eam_mapping_ipv4_network: str,
               rank: int, comment: str) -> SiitMapping:
        """
        :param str siit_eam_mapping_ipv6_prefix: the IPv6 prefix.
        :param str siit_eam_mapping_ipv4_network: the IPv4 network.
        :param int rank: the rank for ordering mappings
        If not set, it means any.
        :param str comment
        :rtype: dict
        """
        data = {
            "siit_eam_mapping_ipv6_prefix": siit_eam_mapping_ipv6_prefix,
            "siit_eam_mapping_ipv4_network": siit_eam_mapping_ipv4_network,
            "rank": rank,
            "comment": comment
        }
        return cls(data)

    @property
    def siit_eam_mapping_ipv6_prefix(self) -> Optional[str]:
        """
        the IPv6 prefix.
        :rtype: str
        """
        return self.data.get("siit_eam_mapping_ipv6_prefix")

    @property
    def siit_eam_mapping_ipv4_network(self) -> Optional[str]:
        """
        the IPv4 network.
        :rtype: str
        """
        return self.data.get("siit_eam_mapping_ipv4_network")

    @property
    def rank(self) -> int:
        """
        the rank for ordering mappings.
        :rtype: int
        """
        return int(self.data.get("rank"))

    @property
    def comment(self) -> Optional[str]:
        """
        the comment.
        :rtype: str
        """
        return self.data.get("comment")


class DHCPClientConfiguration(NestedDict):
    """
    Represents the DHCP Configuration element, for VPN CLients only.<br>
    There is to separate DHCP Servers and Interfaces, so switching is needed if the configuration
    goes from Direct to Relay mode.
    """

    def __init__(self, data: Any) -> None:
        super(DHCPClientConfiguration, self).__init__(data=data)

    @classmethod
    def create(cls, dhcp_client_mode: Optional[int] = None,
               restricted_address_enabled: bool = False,
               restricted_address_ranges: Optional[str] = None,
               dhcp_client_interfaces: Optional[list[str]] = None,
               dhcp_servers: Optional[list[DHCPServer]] = None, proxy_arg_enabled: bool = False,
               proxy_arp_address_ranges: Optional[str] = None,
               dhcp_add_info: Optional[int] = None) -> DHCPClientConfiguration:
        """
        :param int dhcp_client_mode: the DHCP Mode. Accepted values:
         - 0: Disabled
         - 1: Direct
         - 2: Relay
        :param bool restricted_address_enabled: flag to tell if restricted addresses can be used.
        :param str restricted_address_list: Only usefull if the restricted_address_enabled flag is set to true.
        the value can come from a value entred in the SMC (or API) or an automatically generated IP Address range.
        The format is: x.x.x.x-x.x.x.x; x.x.x.x-x.x.x.x
        :param list of str dhcp_client_interfaces: the relay interface IP Addresses used when DHCP Relay is selected.
        :param list(DHPCServer) dhcp_servers: the DHCP Servers for Direct mode.
        :param bool proxy_arg_enabled: flag to tell if arp entry addresses can be used.
        :param str proxy_arp_address_list: Only usefull if the proxy_arg_enabled flag is set to true.
        the value can come from a value entred in the SMC (or API) or an automatically generated IP Address range.
        The format is: x.x.x.x-x.x.x.x; x.x.x.x-x.x.x.x
        :param int dhcp_add_info: Tell if the user want to add information to DHCP. Accepted values:
          - 0: None
          - 1: Add User information
          - 2: Add Group information

        :rtype: DHCPClientConfiguration
        """

        json = {
            "dhcp_client_mode": dhcp_client_mode,
            "dhcp_server_ref": element_resolver(dhcp_servers),
            "dhcp_client_interface": dhcp_client_interfaces,
            "restricted_address_enabled": restricted_address_enabled,
            "restricted_address_list": restricted_address_ranges,
            "use_arp_proxy_enabled": proxy_arg_enabled,
            "proxy_arp_address_list": proxy_arp_address_ranges,
            "dhcp_add_info": dhcp_add_info,
        }
        return cls(json)

    @property
    def dhcp_client_mode(self) -> int:
        """
        the DHCP Mode. Accepted values:
         - 0: Disabled
         - 1: Direct
         - 2: Relay
        :rtype: int
        """
        return self.data.get("dhcp_client_mode")

    @property
    def dhcp_servers(self) -> list[DHCPServer]:
        """
        the DHCP Servers for Direct mode.
        :rtype: list of DHCPServer
        """
        return [Element.from_href(href) for href in self.data.get("dhcp_server_ref", [])]

    @property
    def dhcp_client_interfaces(self) -> list[str]:
        """
        The relay interface IP Addresses used when DHCP Relay is selected.
        :rtype: list of string representing interface IP addresses
        """
        return self.data.get("dhcp_client_interface", [])

    @property
    def restricted_address_enabled(self) -> bool:
        """
        flag to tell if restricted addresses can be used.
        :rtype: bool
        """
        return bool(self.data.get("restricted_address_enabled", False))

    @property
    def restricted_address_ranges(self) -> list[str]:
        """
        Only usefull if the restricted_address_enabled flag is set to true.
        the value can come from a value entred in the SMC (or API) or
        an automatically generated IP Address range.
        The format is: x.x.x.x-x.x.x.x; x.x.x.x-x.x.x.x
        :rtype: list of string representing address ranges
        """
        return bool(self.data.get("restricted_address_list", []))

    @property
    def proxy_arp_enabled(self) -> bool:
        """
        flag to tell if arp entry addresses can be used.
        :rtype: bool
        """
        return bool(self.data.get("use_arp_proxy_enabled", False))

    @property
    def proxy_arp_address_ranges(self) -> list[str]:
        """
        Only usefull if the proxy_arg_enabled flag is set to true.
        the value can come from a value entred in the SMC (or API) or
        an automatically generated IP Address range.
        The format is: x.x.x.x-x.x.x.x; x.x.x.x-x.x.x.x
        :rtype: list of string representing address ranges
        """
        return bool(self.data.get("proxy_arp_address_list", []))

    @property
    def dhcp_add_info(self) -> int:
        """
        Tell if the user want to add information to DHCP. Accepted values:
          - 0: None
          - 1: Add User information
          - 2: Add Group information
        :rtype: int
        """
        return self.data.get("dhcp_add_info")
