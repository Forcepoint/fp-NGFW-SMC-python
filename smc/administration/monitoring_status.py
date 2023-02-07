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
Module that controls aspects of the getting Monitoring Status
To get Monitoring Status for VPN and tunnels, do::

    >>> vpn = PolicyVPN("Corporate VPN")
    >>> status = MonitoringStatus.get_status(href=vpn.href)
    >>> print("vpn status monitoring={}".format(status))
    vpn status monitoring=VPNStatus=>_health_in_percent = 69, _jitter_in_ms = 3, _latency_in_ms = 71

    >>> # get tunnel status in result
    >>> for sub_status in status.result:
    >>>     sub_status = MonitoringStatus.get_status(href=sub_status.get("href"))
    >>>     print("tunnel status monitoring={}".format(sub_status))
    ...
    tunnel status monitoring=VPNGatewayTunnelStatus=>_gatewayA = Helsinki VPN Gateway, _gatewayB =..
    ...
"""
import logging
from smc.api.common import fetch_entry_point, SMCRequest
from smc.api.exceptions import NotMonitored
from smc.base.model import Element
from smc.compat import min_smc_version
from smc.core.resource import History

logger = logging.getLogger(__name__)


class MonitoringStatus(object):
    """
    MonitoringStatus represents the base class for all statuses returned by
    get_monitoring_status(href) for the element href
    Valid attributes (read-only) are:

    :ivar name: name of the element described by href
    :ivar monitoring_state:
        INITIAL     For an Engine Node: Status not yet received.
                    For a Composite Status: Composite Status value is not yet computed.
        READY       For an Engine Node: Status is received.
                    For a Composite Status: Composite Status value is computed.
        NO_STATUS   For an Engine Node: No status received for the node during initial timeout.
        TIMEOUT     For an Engine Node: Status was not received in time.
        ERROR       Not used.
        SERVER_ERROR For an Engine Node: Status poll from log server failed.
        DELETED     Status is deleted
        DUMMY       For an Engine Node: Status is a dummy Status for Demo mode.
                    For a Composite Status: Status is a dummy Status for Demo mode.
    :ivar monitoring_status:
        ANY         Refers to any Status.
        NOT_MONITORED Indicates that Status element has currently Not Monitored Status.
        UNKNOWN     For an Engine Node: Node has not sent status (or timeout).
                    For a Composite Status: All children are unknown.
        OK          For an Engine Node: Status is OK.
                    For a Composite Status: All children are OK.
        PARTIAL_OK  For a Composite Status: Some children are OK and others are unknown.
        WARNING     For a Composite Status: Some children have warning.
        ERROR       For an Engine Node: Status is KO.
                    For a Composite Status: Some children are KO.
        IDLE        For a VPN Node: Status is STANDBY.
                    Composite: All children are STANDBY.
    :ivar result: The API's links of the children or SDWAN Branch Status if exists

    """

    def __init__(self, **data):
        for d, v in data.items():
            # Made the code SMC 7.1 compatible
            if min_smc_version('7.1') and d == 'child':
                setattr(self, 'result', v)
            setattr(self, d, v)

    @property
    def name(self):
        """
        name of the element described by href
        """
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def monitoring_state(self):
        """
        The monitoring state:

        ***INITIAL*** For an Engine Node: Status not yet received.
                      For a Composite Status: Composite Status value is not yet computed.
        ***READY*** For an Engine Node: Status is received.
                    For a Composite Status: Composite Status value is computed.
        ***NO_STATUS*** For an Engine Node: No status received for the node during initial timeout.
        ***TIMEOUT*** For an Engine Node: Status was not received in time.
        ***ERROR*** Not used.
        ***SERVER_ERROR*** For an Engine Node: Status poll from log server failed.
        ***DELETED*** Status is deleted.
        ***DUMMY*** For an Engine Node: Status is a dummy Status for Demo mode.
                    For a Composite Status: Status is a dummy Status for Demo mode.

        :return: The monitoring state.
        :rtype: str
        """
        return self._monitoring_state

    @monitoring_state.setter
    def monitoring_state(self, value):
        self._monitoring_state = value

    @property
    def monitoring_status(self):
        """
        The monitoring status:

        ***ANY*** Refers to any Status.
        ***NOT_MONITORED*** Indicates that Status element has currently Not Monitored Status.
        ***UNKNOWN*** For an Engine Node: Node has not sent status (or timeout).
                      For a Composite Status: All children are unknown.
        ***OK*** For an Engine Node: Status is OK. For a Composite Status: All children are OK.
        ***PARTIAL_OK*** For a Composite Status: Some children are OK and others are unknown.
        ***WARNING*** For a Composite Status: Some children have warning.
        ***ERROR*** For an Engine Node: Status is KO. For a Composite Status: Some children are KO.
        ***IDLE*** For a VPN Node: Status is STANDBY. Composite: All children are STANDBY.

        :return: The monitoring status.
        :rtype: str
        """
        return self._monitoring_status

    @monitoring_status.setter
    def monitoring_status(self, value):
        self._monitoring_status = value

    @property
    def result(self):
        """
        :return: The API's links of the children or SDWAN Branch Status if exists
        :rtype: list str
        """
        return self._result

    @property
    def history(self):
        """
        This function returns a history object.
        :return: history object.
        :rtype: History
        """
        if min_smc_version('7.1'):
            for link_dict in self.link:
                if link_dict['rel'] == 'history':
                    history_link = link_dict['href']
                    result = SMCRequest(method="create", href=history_link).create()
                    return History(**result.json)

    @result.setter
    def result(self, value):
        self._result = value

    @staticmethod
    def __get_status_type(data):
        """
        :return: status class related to data
        :rtype: MonitoringStatus
        """
        # status by default
        result = MonitoringStatus
        for st in status_type:
            find = True
            nb_found = 0
            for attr in data:
                # don't check attributes from superclass
                if hasattr(MonitoringStatus, attr):
                    continue
                # if attribute from data not in status type, we continue to next type
                if not hasattr(st, attr):
                    find = False
                    break
                nb_found += 1
            if find and nb_found > 0:
                result = st
                break
        return result

    @staticmethod
    def get_status(href):
        """
        Return Monitoring Status for the given href element
        :param str href: the uri of the element to retrieve the status
        :raises NotMonitored: the element is not monitored
        :rtype: MonitoringStatus
        """
        if min_smc_version('7.1') and 'monitoring_status' in href:
            result = SMCRequest(method="read", href=href).read()
        else:
            monitoring_json = {"value": href}
            result = SMCRequest(method="create", json=monitoring_json,
                                href=fetch_entry_point("monitoring_status")).create()
        if result.code == 400:
            raise NotMonitored(result.msg)
        status = MonitoringStatus.__get_status_type(result.json)
        return status(**result.json)

    def __str__(self):
        result = "{}=>".format(self.__class__.__name__)
        for attr in vars(self):
            result += "{} = {}, ".format(attr, getattr(self, attr))
        return result


class ServerStatus(MonitoringStatus):
    """
    This represents an SMC Server Status (Class ServerStatus).<br/>
    Field from the StatusDTO map the normal server status.

    For an SMC Server, additionnal information is provided about:
    - replication states ( detailed content depend on server role )
    - resource monitoring common to all servers ( memory only currenlty )
    """

    @property
    def replication_status(self):
        return self._replication_status

    @replication_status.setter
    def replication_status(self, value):
        self._replication_status = value

    @property
    def replication_info(self):
        return self._replication_info

    @replication_info.setter
    def replication_info(self, value):
        self._replication_info = value

    @property
    def memory_used(self):
        return self._memory_used

    @memory_used.setter
    def memory_used(self, value):
        self._memory_used = value

    @property
    def memory_info(self):
        return self._memory_info

    @memory_info.setter
    def memory_info(self, value):
        self._memory_info = value


class EngineNodeStatus(MonitoringStatus):
    """
    This represents the Node Status.
    For a node, this structure describes the
    state, version, current policy, ... of the specified Node.
    """

    @property
    def installed_policy(self):
        """
        :return: The Last Uploaded Policy.
        :rtype: str
        """
        return self._installed_policy

    def installed_policy(self, value):
        self._installed_policy = value

    @property
    def installed_policy_ref(self):
        """
        :return: The reference to Last Uploaded Policy.
        :rtype: Policy
        """
        return Element.from_href(self._installed_policy_ref)

    @installed_policy_ref.setter
    def installed_policy_ref(self, value):
        self._installed_policy_ref = value

    @property
    def last_upload_time(self):
        """
        :return: The Upload Time of the Last Uploaded Policy.
        :rtype: str
        """
        return self._last_upload_time

    @last_upload_time.setter
    def last_upload_time(self, value):
        self._last_upload_time = value

    @property
    def active_policy(self):
        """
        :return: The Currently Active Policy.
        :rtype: str
        """
        return self._active_policy

    @active_policy.setter
    def active_policy(self, value):
        self._active_policy = value

    @property
    def active_policy_ref(self):
        """
        :return: The reference to Currently Active Policy.
        :rtype: Policy
        """
        return Element.from_href(self._active_policy_ref)

    @active_policy_ref.setter
    def active_policy_ref(self, value):
        self._active_policy_ref = value

    @property
    def local_alternative_policy_activation_time(self):
        """
        :return: The timestamp when Active Policy was activated, if it is a Local Alternative
        Policy.
        :rtype: long
        """
        return self._local_alternative_policy_activation_time

    @local_alternative_policy_activation_time.setter
    def local_alternative_policy_activation_time(self, value):
        self._local_alternative_policy_activation_time = value

    @property
    def configuration_status(self):
        """
        :return: The Configuration status:
        -*Initial* no initial configuration file is yet generated.
        -*Declared* initial configuration file is generated.
        -*Configured* initial configuration is done with the engine.
        -*Installed* policy is installed on the engine.
        :rtype: str
        """
        return self._configuration_status

    @configuration_status.setter
    def configuration_status(self, value):
        self._configuration_status = value

    @property
    def hw_info(self):
        """
        :return: The information about the hardware.
        :rtype: str
        """
        return self._hw_info

    @hw_info.setter
    def hw_info(self, value):
        self._hw_info = value

    @property
    def engine_node_status(self):
        """
        :return: The engine status ("Not Monitored"/"Unknown"/"Online"/"Going Online"/
        "Locked Online"/"Going Locked Online"/"Offline"/"Going Offline"/"Locked Offline"/
        "Going Locked Offline"/"Standby"/"Going Standby"/"No Policy Installed"
        :rtype: str
        """
        return self._engine_node_status

    @engine_node_status.setter
    def engine_node_status(self, value):
        self._engine_node_status = value

    @property
    def dyn_up(self):
        """
        :return: The dynamic update package received.
        :rtype: str
        """
        return self._dyn_up

    @dyn_up.setter
    def dyn_up(self, value):
        self._dyn_up = value

    @property
    def platform(self):
        """
        :return: The engine platform.
        :rtype: str
        """
        return self._platform

    @platform.setter
    def platform(self, value):
        self._platform = value

    @property
    def version(self):
        """
        :return: The engine version.
        :rtype: str
        """
        return self._version

    @version.setter
    def version(self, value):
        self._version = value

    @property
    def local_alternative_policies(self):
        """
        :return: The Local Alternative Policies.
        :rtype: list str
        """
        return self._local_alternative_policies

    @local_alternative_policies.setter
    def local_alternative_policies(self, value):
        self._local_alternative_policies = value

    @property
    def master_node(self):
        """
        Used by Virtual Firewall Node
        :return: master node.
        :rtype: MasterNode
        """
        return Element.from_href(self._master_node)

    @master_node.setter
    def master_node(self, master_node):
        self._master_node = master_node


class SDWANBranchStatus(MonitoringStatus):
    """
    This represents the SDWAN branch Status.
    """

    @property
    def health_in_percent(self):
        """
        :return: SDWAN Branch Health in percent
        :rtype: int
        """
        return self._health_in_percent

    @health_in_percent.setter
    def health_in_percent(self, value):
        self._health_in_percent = value


class SDWANBranchToBranchStatus(MonitoringStatus):
    """
    This represents the SDWAN branch to branch Status.
    """

    @property
    def health_in_percent(self):
        """
        :return: SDWAN Branch Health in percent
        :rtype: int
        """
        return self._health_in_percent

    @health_in_percent.setter
    def health_in_percent(self, value):
        self._health_in_percent = value

    @property
    def traffic_in_bits_per_sec(self):
        """
        :return: SDWAN Branch to Branch Traffic in bits per second
        :rtype: long
        """
        return self._traffic_in_bits_per_sec

    @traffic_in_bits_per_sec.setter
    def traffic_in_bits_per_sec(self, value):
        self._traffic_in_bits_per_sec = value

    @property
    def packet_loss_in_permyriad(self):
        """
        :return: SDWAN Branch to Branch Packet loss in permyriad (per ten thousands)
        :rtype: int
        """
        return self._packet_loss_in_permyriad

    @packet_loss_in_permyriad.setter
    def packet_loss_in_permyriad(self, value):
        self._packet_loss_in_permyriad = value

    @property
    def latency_in_ms(self):
        """
        :return: SDWAN Branch to Branch Latency in  milliseconds
        :rtype: int
        """
        return self._latency_in_ms

    @latency_in_ms.setter
    def latency_in_ms(self, value):
        self._latency_in_ms = value

    @property
    def jitter_in_ms(self):
        """
        :return: SDWAN Branch to Branch Jitter in  milliseconds
        :rtype: int
        """
        return self._jitter_in_ms

    @jitter_in_ms.setter
    def jitter_in_ms(self, value):
        self._jitter_in_ms = value


class SDWANNetlinkElementStatus(MonitoringStatus):
    """
    This represents the SDWAN Netlink element Status.
    """

    @property
    def inbound_traffic_in_bits_per_sec(self):
        """
        :return: Inbound traffic in bits per second
        :rtype: long
        """
        return self._inbound_traffic_in_bits_per_sec

    @inbound_traffic_in_bits_per_sec.setter
    def inbound_traffic_in_bits_per_sec(self, value):
        self._inbound_traffic_in_bits_per_sec = value

    @property
    def outbound_traffic_in_bits_per_sec(self):
        """
        :return: Outbound traffic in bits per second
        :rtype: long
        """
        return self._outbound_traffic_in_bits_per_sec

    @outbound_traffic_in_bits_per_sec.setter
    def outbound_traffic_in_bits_per_sec(self, value):
        self._outbound_traffic_in_bits_per_sec = value

    @property
    def connection_count(self):
        """
        :return: Connection Count
        :rtype: long
        """
        return self._connection_count

    @connection_count.setter
    def connection_count(self, value):
        self._connection_count = value

    @property
    def packet_loss_in_permyriad(self):
        """
        :return: Packet loss in permyriad (per ten thousands)
        :rtype: long
        """
        return self._packet_loss_in_permyriad

    @packet_loss_in_permyriad.setter
    def packet_loss_in_permyriad(self, value):
        self._packet_loss_in_permyriad = value


class VPNStatus(MonitoringStatus):
    """
    This represents the VPN Status
    """

    @property
    def vpn_status_code(self):
        """
        :return: The Monitoring VPN Status Code.
        :rtype: str
        """
        return self._vpn_status_code

    @vpn_status_code.setter
    def vpn_status_code(self, value):
        self._vpn_status_code = value

    @property
    def health_in_percent(self):
        """
        :return: VPN Health in percent.
        :rtype: str
        """
        return self._health_in_percent

    @health_in_percent.setter
    def health_in_percent(self, value):
        self._health_in_percent = value

    @property
    def traffic_in_bits_per_sec(self):
        """
        :return: VPN Traffic in bits per second
        :rtype: long
        """
        return self._traffic_in_bits_per_sec

    @traffic_in_bits_per_sec.setter
    def traffic_in_bits_per_sec(self, value):
        self._traffic_in_bits_per_sec = value

    @property
    def packet_loss_in_permyriad(self):
        """
        :return: VPN Packet loss in permyriad (per ten thousands)
        :rtype: int
        """
        return self._packet_loss_in_permyriad

    @packet_loss_in_permyriad.setter
    def packet_loss_in_permyriad(self, value):
        self._packet_loss_in_permyriad = value

    @property
    def latency_in_ms(self):
        """
        :return: VPN Latency in  milliseconds
        :rtype: int
        """
        return self._latency_in_ms

    @latency_in_ms.setter
    def latency_in_ms(self, value):
        self._latency_in_ms = value

    @property
    def jitter_in_ms(self):
        """
        :return: VPN Jitter in  milliseconds
        :rtype: int
        """
        return self._jitter_in_ms

    @jitter_in_ms.setter
    def jitter_in_ms(self, value):
        self._jitter_in_ms = value


class VPNGatewayTunnelStatus(VPNStatus):
    """
    This represents the Monitoring Status for a Gateway Tunnel.
    """

    @property
    def gatewayA(self):
        """
        :return: Name of Gateway A
        :rtype: str
        """
        return self._gatewayA

    @gatewayA.setter
    def gatewayA(self, value):
        self._gatewayA = value

    @property
    def gatewayB(self):
        """
        :return: Name of Gateway B
        :rtype: str
        """
        return self._gatewayB

    @gatewayB.setter
    def gatewayB(self, value):
        self._gatewayB = value


class VPNEndpointTunnelStatus(VPNGatewayTunnelStatus):
    """
    This represents the Monitoring Status for an endpoint tunnel.
    """

    @property
    def endpointA(self):
        """
        :return: Name of Endpoint A
        :rtype: str
        """
        return self._endpointA

    @endpointA.setter
    def endpointA(self, value):
        self._endpointA = value

    @property
    def endpointB(self):
        """
        :return: Name of Endpoint B
        :rtype: str
        """
        return self._endpointB

    @endpointB.setter
    def endpointB(self, value):
        self._endpointB = value


# order is important, set at first Status with the commons fields
# first status with all data fields matching will be returned
status_type = [ServerStatus, EngineNodeStatus, SDWANBranchStatus, SDWANBranchToBranchStatus,
               SDWANNetlinkElementStatus, VPNStatus, VPNGatewayTunnelStatus,
               VPNEndpointTunnelStatus]
