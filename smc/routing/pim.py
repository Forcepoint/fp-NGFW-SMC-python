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
You can configure dynamic multicast routing using a variant of the PIM protocol on Engines,
Virtual Engines, and Engine Clusters.
Three variants of PIM are supported: PIM sparse mode (PIM-SM), PIM dense mode (PIM-DM),
and PIM source-specific multicast (PIM-SSM), and the mode can be set separately for different
multicast groups. The variant to use depends on many factors, such as the network topology,
the number of recipients, and what the existing infrastructure supports.

Use PIM-SM when multicast traffic needs to travel greater logical distances; over WAN links,
for example. There is usually intermittent multicast traffic.
Use PIM-DM when there are a lot of potential recipients and the logical distances are short;
within a WAN, for example. There is usually a high, constant load of multicast traffic.
Messages are flooded over the network, so this is not always the most efficient use of bandwidth.
Use PIM-SSM when you want receivers to be able to specify the source IP address of the requested
multicast stream. This is the most efficient use of bandwidth, but all devices and client
applications must have support for IGMPv3 and this variant of PIM. However,
SSM mapping allows IGMPv2 requests to be converted into IGMPv3 requests.
"""
from smc.base.model import Element, ElementCreator, ElementCache, ElementRef, SubElement
from smc.base.structs import NestedDict
from smc.base.util import element_resolver


class PIMSettings(object):
    """
    PIM represents the PIM configuration on a given engine.
    """

    pim_profile = ElementRef("pim_profile_ref")

    def __init__(self, engine):
        self.data = engine.get("data", {}).get("pim_settings", {})

    @classmethod
    def create(cls, pim_profile_ref, mroute_preference="best_match_preferred", rp_priority=64,
               bsr_priority=64, rp_candidate_interface=None, bsr_candidate_interface=None,
               sm_rp_candidate_entry=[]):
        """
        :param PIMIPv4Profile pim_profile_ref: The PIM IPv4 profile.
        :param str mroute_preference: the MRoute preference:
          * best_match_preferred: The Best Match Preferred mode.
          * mroute_preferred: The MRoute Preferred mode.
        :param int rp_priority: The RP Priority. The default value is 64.
        :param int bsr_priority: The BSR Priority. The default value is 64.
        :param RpCandidateInterfaceEntry rp_candidate_interface: the RP interface reference.
        :param BsrCandidateInterfaceEntry bsr_candidate_interface: the BSR interface reference.
        :param SMRPCandidateEntry sm_rp_candidate_entry: the PIM-SM Bootstrap Settings
        RP Candidate entries
        :rtype: dict
        """
        data = {
            "pim_settings": {
                "pim_profile_ref": element_resolver(pim_profile_ref),
                "rp_candidate_interface": rp_candidate_interface,
                "bsr_candidate_interface": bsr_candidate_interface,
                "sm_rp_candidate_entry": sm_rp_candidate_entry,
                "mroute_preference": mroute_preference,
                "rp_priority": rp_priority,
                "bsr_priority": bsr_priority
            }
        }
        return cls({"data": data})

    @property
    def mroute_preference(self):
        """
        Get the MRoute preference:
          * best_match_preferred: The Best Match Preferred mode.
          * mroute_preferred: The MRoute Preferred mode.

        :return: str or None
        """
        return self.data.get("mroute_preference")

    @property
    def rp_priority(self):
        """
        Get The RP Priority. The default value is 64.

        :return: str or None
        """
        return int(self.data.get("rp_priority"))

    @property
    def bsr_priority(self):
        """
        Get The BSR Priority. The default value is 64.

        :return: str or None
        """
        return int(self.data.get("bsr_priority"))

    @property
    def rp_candidate_interface(self):
        """
        The PIM IPv4 Multicast Group Entries.

        :return: RpCandidateInterfaceEntry or None if not defined
        """
        rp_candidate_interface_json = self.data.get("rp_candidate_interface")
        if rp_candidate_interface_json:
            return RpCandidateInterfaceEntry(rp_candidate_interface_json)
        else:
            return None

    @property
    def bsr_candidate_interface(self):
        """
        the BSR interface reference.

        :return: BsrCandidateInterfaceEntry or None if not defined
        """
        bsr_candidate_interface_json = self.data.get("bsr_candidate_interface")
        if bsr_candidate_interface_json:
            return BsrCandidateInterfaceEntry(bsr_candidate_interface_json)
        else:
            return None

    @property
    def sm_rp_candidate_entry(self):
        """
        the PIM-SM Bootstrap Settings

        :return: list of SMRPCandidateEntry
        """
        return [SMRPCandidateEntry(entry) for entry in
                self.data.get("sm_rp_candidate_entry", [])]


class IGMPQuerierSettings(Element):
    """
    You might need to select a specific IGMP Querier Settings element, for example,
    to troubleshoot multicast accessibility on hosts,
    or if some hosts use an earlier IGMP version.
    Select an IGMP Querier Settings element according to the downstream network environment.
    The element defines the IGMP version and query parameters.
    """

    typeof = "igmp_querier_settings"

    @classmethod
    def create(cls, name, igmp_version, query_interval=125, robustness=2, comment=None):
        """
        Create an IGMP Querier Settings element to be applied on the engine.
        You can configure IGMP-based multicast forwarding for a specified Engine element.

        IGMP-based multicast forwarding (IGMP proxying) is implemented on the Engine based
        on RFC 4605.
        IGMP-based multicast forwarding is only supported in tree topology networks.
        RFC 4605 includes support for source-specific multicast (SSM) with IGMP version 3.
        SSM is not supported with IGMP-based multicast forwarding.
        However, you can configure Access rules that filter multicast traffic based on the source.

        The engine maintains a membership database of the subscriptions from the downstream networks
        and sends unsolicited reports or leaves on the upstream interface when
        the subscription database changes.
        It also sends IGMP membership reports when queried on the upstream interface.

        :param str name: name of this IGMP Querier Settings
        :param str igmp_version: IGMP version
        :param int query_interval: specify how often the hello packet is sent in seconds.
        This option is not supported when IGMP Version is IGMPv1.
        :param int robustness: specify the robustness value. If you expect packet loss in the
        network, increase this value to send more IGMP messages.
        This option is not supported when IGMP Version is IGMPv1 or when
        the IGMP Querier Settings element is used for PIM.
        :param str comment: optional string comment
        :raises CreateElementFailed: unable to create IGMP Querier Settings
        :return: instance with meta
        :rtype: IGMPQuerierSettings
        """

        json = {"name": name, "igmp_version": igmp_version,
                "query_interval": query_interval, "robustness": robustness, "comment": comment}

        return ElementCreator(cls, json)

    @property
    def igmp_version(self):
        """
        The IGMP version among:
        * igmpv1: IGMP v1.
        * igmpv2: IGMP v2.
        * igmpv3: IGMP v3.

        :return: IGMP version
        :rtype: int
        """
        return int(self.data.get("igmp_version"))

    @property
    def query_interval(self):
        """
        how often the hello packet is sent in seconds.
        This option is not supported when IGMP Version is IGMPv1.

        :return: Query Interval
        :rtype: int
        """
        return int(self.data.get("query_interval"))

    @property
    def robustness(self):
        """
        the robustness value. If you expect packet loss in the
        network, increase this value to send more IGMP messages.
        This option is not supported when IGMP Version is IGMPv1 or when
        the IGMP Querier Settings element is used for PIM.

        :return: robustness
        :rtype: int
        """
        return int(self.data.get("robustness"))


class PIMIPv4InterfaceSettings(Element):
    """
    Defines the PIM IPv4 interface settings for Engine multicast routing.
    """

    typeof = "pim_ipv4_interface_settings"

    igmp_querier_settings_ref = ElementRef("igmp_querier_settings_ref")

    @classmethod
    def create(cls, name, igmp_querier_settings_ref, dr_priority=1,
               zbr=None, random_delay=5, comment=None):
        """
        Create a PIM IPv4 interface settings for Engine multicast routing.
        You can configure PIM multicast forwarding for a specified Engine element.

        :param str name: name of this PIM IPv4 Interface Settings
        :param str igmp_querier_settings_ref: IGMP Querier Settings element.
        The element defines the IGMP version and query parameters.
        :param int dr_priority: specify the designated router (DR) priority
        that is advertised in hello messages. By default: 1
        :param int zbr: specify the multicast groups for zone border routers (ZBR).
        To specify multiple multicast groups, separate them with a comma.
        The listed multicast groups do not pass through the interface.
        :param int random_delay: specify the random delay before hello messages are sent.
        The delay prevents PIM routers from receiving multiple hello messages at the same time.
        By default: 5
        :param str comment: optional string comment
        :raises CreateElementFailed: unable to create PIM Interface Settings
        :return: instance with meta
        :rtype: PIMIPv4InterfaceSettings
        """

        json = {
            "name": name,
            "dr_priority": dr_priority,
            "zbr": zbr,
            "random_delay": random_delay,
            "comment": comment,
        }

        igmp_querier_settings_ref_ref = element_resolver(igmp_querier_settings_ref)
        json.update(igmp_querier_settings_ref=igmp_querier_settings_ref_ref)

        return ElementCreator(cls, json)

    @property
    def dr_priority(self):
        """
        the designated router (DR) priority
        that is advertised in hello messages. By default: 1

        :return: the designated router (DR) priority
        :rtype: int
        """
        return int(self.data.get("dr_priority"))

    @property
    def zbr(self):
        """
        the multicast groups for zone border routers (ZBR).
        To specify multiple multicast groups, separate them with a comma.
        The listed multicast groups do not pass through the interface.

        :return: ZBR
        :rtype: int
        """
        return int(self.data.get("zbr"))

    @property
    def random_delay(self):
        """
        The random delay before hello messages are sent.
        The delay prevents PIM routers from receiving multiple hello messages at the same time.
        By default: 5

        :return: The random delay
        :rtype: int
        """
        return int(self.data.get("random_delay"))


class PIMIPv4Profile(Element):
    """
    Defines the PIM IPv4 Profile for Engine multicast routing.
    """
    typeof = "pim_ipv4_profile"

    @classmethod
    def create(cls, name, pim_multicast_group_entry=[], hello_interval=30,
               joined_prune=60, spt_switch_threshold_unit='packets', spt_switch_threshold=0,
               spt_switch_interval=100, smart_multicast_antispoofing=True, comment=None):
        """
        Create a PIM IPv4 Profile for Engine multicast routing.
        You can configure PIM multicast forwarding for a specified Engine element.

        :param str name: name of this PIM IPv4 Profile
        :param PIMIPv4MulticastGroupEntry pim_multicast_group_entry: list of PIM IPv4 Multicast
        group entries.
        :param int hello_interval: specify how often hello messages are sent in seconds.
        :param int joined_prune: specify how often joined/prune messages are sent in seconds.
        :param str spt_switch_threshold_unit: The PIM-SM SPT switch threshold unit.
         The default value is packets.
          * packets: Packets unit.
          * kbps: Kbit/s unit.
          * infinite: Infinite unit. In this case, the SPT Switch threshold value is not considered.
        :param str spt_switch_interval: specify how frequently the SPT switch threshold
        state is checked in seconds.
        :param bool smart_multicast_antispoofing: When selected, antispoofing rules are
          automatically configured to avoid inadvertently blocking multicast traffic.
          We recommend that you enable this option.
        :param str comment: optional string comment
        :raises CreateElementFailed: unable to create PIM IPv4 Profile
        :return: instance with meta
        :rtype: PIMIPv4Profile
        """

        return ElementCreator(cls, {
            "name": name,
            "pim_multicast_group_entry": pim_multicast_group_entry,
            "hello_interval": hello_interval,
            "joined_prune": joined_prune,
            "spt_switch_threshold_unit": spt_switch_threshold_unit,
            "spt_switch_threshold": spt_switch_threshold,
            "spt_switch_interval": spt_switch_interval,
            "smart_multicast_antispoofing": smart_multicast_antispoofing,
            "comment": comment,
        })

    @property
    def hello_interval(self):
        """
        how often hello messages are sent in seconds.

        :return: how often hello messages are sent in seconds.
        :rtype: int
        """
        return int(self.data.get("hello_interval"))

    @property
    def joined_prune(self):
        """
        how often joined/prune messages are sent in seconds.

        :return: how often joined/prune messages are sent in seconds.
        :rtype: int
        """
        return int(self.data.get("joined_prune"))

    @property
    def spt_switch_threshold_unit(self):
        """
        The PIM-SM SPT switch threshold unit.
         The default value is packets.
          * packets: Packets unit.
          * kbps: Kbit/s unit.
          * infinite: Infinite unit. In this case, the SPT Switch threshold value is not considered.

        :return: The PIM-SM SPT switch threshold unit.
        :rtype: int
        """
        return int(self.data.get("spt_switch_threshold_unit"))

    @property
    def spt_switch_interval(self):
        """
        how frequently the SPT switch threshold
        state is checked in seconds.

        :return: how frequently the SPT switch threshold
        state is checked in seconds.
        :rtype: int
        """
        return int(self.data.get("spt_switch_interval"))

    @property
    def smart_multicast_antispoofing(self):
        """
        When selected, antispoofing rules are automatically configured
        to avoid inadvertently blocking multicast traffic.

        :return: When selected, antispoofing rules are automatically configured to avoid
        inadvertently blocking multicast traffic.
        :rtype: int
        """
        return int(self.data.get("smart_multicast_antispoofing"))

    @property
    def pim_multicast_group_entry(self):
        """
        The PIM IPv4 Multicast Group Entries.

        :return: list of PIMIPv4MulticastGroupEntry
        """
        return [PIMIPv4MulticastGroupEntry(entry) for entry in
                self.data.get("pim_multicast_group_entry", [])]


class PIMIPv4MulticastGroupEntry(NestedDict):
    """
    Represents the PIM IPv4 Multicast Group Entry.
    """

    def __init__(self, data):
        super(PIMIPv4MulticastGroupEntry, self).__init__(data)

    @classmethod
    def create(cls, multicast_ip_network, multicast_group_ref, mode, mapping):
        """
        :param str multicast_ip_network: The manual Multicast IPv4 Network.
         Otherwise, please specify a Network element as Multicast element.
        :param NetworkElement multicast_group_ref: The Network element used as multicast group.
         Otherwise, please specify a manual Multicast IPv4 Network.
        :param str mode: The Multicast group mode:
          * 'pim_sm': PIM-SM mode.
          * 'pim_ssm': PIM-SSM mode.
          * 'pim_dm': PIM-DM mode.
        :param str mapping: The Multicast group RP or Mapping:
          * For 'pim_sm' mode, it represents the RP IPv4 Unicast address.
          * For 'pim_ssm' mode, it represents either the IPv4 Unicast address
            list separated by comma either the DNS suffix.
        :rtype: dict
        """
        data = {
            "multicast_ip_network": multicast_ip_network,
            "multicast_group_ref": element_resolver(multicast_group_ref),
            "mode": mode,
            "mapping": mapping
        }
        return cls(data)


class RpCandidateInterfaceEntry(NestedDict):
    """
    Represents the RP Candidate listening Interface.
    """

    def __init__(self, data):
        super(RpCandidateInterfaceEntry, self).__init__(data)

    @classmethod
    def create(cls, nicid, address):
        """
        :param str nicid: the interface nic id in string format.
        :param str address: the IPv4 address.
        :rtype: dict
        """
        data = {
            "nicid": nicid,
            "address": address
        }
        return cls(data)


class BsrCandidateInterfaceEntry(NestedDict):
    """
    Represents the BSR Candidate listening Interface.
    """

    def __init__(self, data):
        super(BsrCandidateInterfaceEntry, self).__init__(data)

    @classmethod
    def create(cls, nicid, address):
        """
        :param str nicid: the interface nic id in string format.
        :param str address: the IPv4 address.
        :rtype: dict
        """
        data = {
            "nicid": nicid,
            "address": address
        }
        return cls(data)


class SMRPCandidateEntry(NestedDict):
    """
    Represents the BSR Candidate listening Interface.
    """

    def __init__(self, data):
        super(SMRPCandidateEntry, self).__init__(data)

    @classmethod
    def create(cls, rp_multicast_group_ref, multicast_ip_network):
        """
        :param Network rp_multicast_group_ref: The Multicast Group network element.
         Otherwise, please specify a manual Multicast IPv4 Network.
        :param str multicast_ip_network: The manual Multicast IPv4 Network.
         Otherwise, please specify a Network element as Multicast element.
        :rtype: dict
        """
        data = {
            "rp_multicast_group_ref": element_resolver(rp_multicast_group_ref),
            "multicast_ip_network": multicast_ip_network
        }
        return cls(data)
