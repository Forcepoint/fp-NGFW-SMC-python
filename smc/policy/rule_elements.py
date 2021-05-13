from smc.base.model import Element, ElementCreator
from smc.base.structs import NestedDict
from smc.api.exceptions import ElementNotFound, InvalidRuleValue
from smc.base.util import element_resolver
from smc.compat import is_api_version_less_than_or_equal


class RuleElement(object):
    """
    Rule Element encapsulates actions for source, destination and
    service fields.
    """

    @property
    def is_any(self):
        """
        Is the field set to any

        :rtype: bool
        """
        return "any" in self

    def set_any(self):
        """
        Set field to any
        """
        self.clear()
        self.update({"any": True})

    @property
    def is_none(self):
        """
        Is the field set to none

        :rtype: bool
        """
        return "none" in self

    def set_none(self):
        """
        Set field to none
        """
        self.clear()
        self.update({"none": True})

    def add(self, data):
        """
        Add a single entry to field.

        Entries can be added to a rule using the href of the element
        or by loading the element directly. Element should be of type
        :py:mod:`smc.elements.network`.
        After modifying rule, call :py:meth:`~.save`.

        Example of adding entry by element::

            policy = FirewallPolicy('policy')
            for rule in policy.fw_ipv4_nat_rules.all():
                if rule.name == 'therule':
                    rule.sources.add(Host('myhost'))
                    rule.save()

        .. note:: If submitting type Element and the element cannot be
                  found, it will be skipped.

        :param data: entry to add
        :type data: Element or str
        """
        if self.is_none or self.is_any:
            self.clear()
            self.data[self.typeof] = []

        try:
            self.get(self.typeof).append(element_resolver(data))
        except ElementNotFound:
            pass

    def add_many(self, data):
        """
        Add multiple entries to field. Entries should be list format.
        Entries can be of types relavant to the field type. For example,
        for source and destination fields, elements may be of type
        :py:mod:`smc.elements.network` or be the elements direct href,
        or a combination of both.

        Add several entries to existing rule::

            policy = FirewallPolicy('policy')
            for rule in policy.fw_ipv4_nat_rules.all():
                if rule.name == 'therule':
                    rule.sources.add_many([Host('myhost'),
                                          'http://1.1.1.1/hosts/12345'])
                    rule.save()

        :param list data: list of sources

        .. note:: If submitting type Element and the element cannot be
                  found, it will be skipped.
        """
        assert isinstance(data, list), "Incorrect format. Expecting list."
        if self.is_none or self.is_any:
            self.clear()
            self.data[self.typeof] = []

        data = element_resolver(data, do_raise=False)
        self.data[self.typeof] = data

    def __eq__(self, other):
        if isinstance(self, type(other)):
            if self.is_none or self.is_any:
                if self.is_none and other.is_none or self.is_any and other.is_any:
                    return True
                return False
            if other.is_none or other.is_any:  # Current sources not any or none
                return False
            if set(self.all_as_href()) == set(other.all_as_href()):
                return True
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def update_field(self, elements):
        """
        Update the field with a list of provided values but only if the values
        are different. Return a boolean indicating whether a change was made
        indicating whether `save` should be called. If the field is currently
        set to any or none, then no comparison is made and field is updated.

        :param list elements: list of elements in href or Element format
            to compare to existing field
        :rtype: bool
        """
        changed = False
        if isinstance(elements, list):
            if self.is_any or self.is_none:
                self.add_many(elements)
                changed = True
            else:
                _elements = element_resolver(elements, do_raise=False)
                if set(self.all_as_href()) ^ set(_elements):
                    self.data[self.typeof] = _elements
                    changed = True

        if (
            changed
            and self.rule
            and (
                isinstance(self, (Source, Destination))
                and self.rule.typeof in ("fw_ipv4_nat_rule", "fw_ipv6_nat_rule")
            )
        ):
            # Modify NAT cell if necessary
            self.rule._update_nat_field(self)

        return changed

    def all_as_href(self):
        """
        Return all elements without resolving to :class:`smc.elements.network`
        or :class:`smc.elements.service`. Just raw representation as href.

        :return: elements in href form
        :rtype: list
        """
        if not self.is_any and not self.is_none:
            return [element for element in self.get(self.typeof)]
        return []

    def all(self):
        """
        Return all destinations for this rule. Elements returned
        are of the object type for the given element for further
        introspection.

        Search the fields in rule::

            for sources in rule.sources.all():
                print('My source: %s' % sources)

        :return: elements by resolved object type
        :rtype: list(Element)
        """
        if not self.is_any and not self.is_none:
            return [Element.from_href(href) for href in self.get(self.typeof)]
        return []


class Destination(RuleElement, NestedDict):
    """
    Destination fields for a rule.
    """

    typeof = "dst"

    def __init__(self, rule=None):
        dests = dict(none=True) if not rule else rule.data.get("destinations")
        self.rule = rule
        super(Destination, self).__init__(data=dests)


class Source(RuleElement, NestedDict):
    """
    Source fields for a rule
    """

    typeof = "src"

    def __init__(self, rule=None):
        sources = dict(none=True) if not rule else rule.data.get("sources")
        self.rule = rule
        super(Source, self).__init__(data=sources)


class Service(RuleElement, NestedDict):
    """
    Service fields for a rule
    """

    typeof = "service"

    def __init__(self, rule=None):
        services = dict(none=True) if not rule else rule.data.get("services")
        self.rule = rule
        super(Service, self).__init__(data=services)


class Action(NestedDict):
    """
    This represents the action associated with the rule.
    """

    def __init__(self, rule=None):
        if rule is None:
            if is_api_version_less_than_or_equal("6.5"):
                action = dict(action="allow")
            else:
                action = dict(action=["allow"])
            conn_tracking = ConnectionTracking()
            action.update(connection_tracking_options=conn_tracking.data)
            action.update(scan_detection="undefined")
        else:
            action = rule.data.get("action", {})
        super(Action, self).__init__(data=action)

    @property
    def action(self):
        """
        Action set for this rule

        :param str value: allow\\|discard\\|continue\\|refuse\\|jump\\|apply_vpn
                          \\|enforce_vpn\\|forward_vpn\\|blacklist
        :rtype: str
        """
        return self.get("action")

    @action.setter
    def action(self, value):
        self.update(action=value)

    @property
    def connection_tracking_options(self):
        """
        Enables connection tracking.
        The firewall allows or discards packets according to the selected Connection
        Tracking mode. Reply packets are allowed as part of the allowed connection
        without an explicit Access rule. Protocols that use a dynamic port assignment
        must be allowed using a Service with the appropriate Protocol Agent for that
        protocol (in Access rules and NAT rules).

        :rtype: ConnectionTracking
        """
        return ConnectionTracking(self)

    @property
    def decrypting(self):
        """
        .. versionadded:: 0.6.0
            Requires SMC version >= 6.3.3

        Whether the decryption is enabled on this rule.

        :param bool value: True, False, None (inherit from continue rule)
        :rtype: bool
        """
        return self.get("decrypting")

    @decrypting.setter
    def decrypting(self, value):
        self.update(decrypting=value)

    @property
    def deep_inspection(self):
        """
        Selects traffic that matches this rule for checking against the Inspection
        Policy referenced by this policy. Traffic is inspected as the Protocol that
        is attached to the Service element in this rule.

        :param bool value: True, False, None (inherit from continue rule)
        :rtype: bool
        """
        return self.get("deep_inspection")

    @deep_inspection.setter
    def deep_inspection(self, value):
        self.update(deep_inspection=value)

    @property
    def file_filtering(self):
        """
        (IPv4 Only) Inspects matching traffic against the File Filtering policy.
        Selecting this option should also activates the Deep Inspection option.
        You can further adjust virus scanning in the Inspection Policy.

        :param bool value: True, False, None (inherit from continue rule)
        :rtype: bool
        """
        return self.get("file_filtering")

    @file_filtering.setter
    def file_filtering(self, value):
        self.update(file_filtering=value)

    @property
    def dos_protection(self):
        """
        Enable or disable DOS protection mode

        :param bool value: True, False, None (inherit from continue rule)
        :rtype: bool
        """
        return self.get("dos_protection")

    @dos_protection.setter
    def dos_protection(self, value):
        self.update(dos_protection=value)

    @property
    def antispam(self):
        """
        Enable or disable anti-spam

        :param bool value: True, False, None (inherit from continue rule)
        :rtype: bool
        """
        return self.get("antispam")

    @antispam.setter
    def antispam(self, value):
        self.update(antispam=value)

    @property
    def scan_detection(self):
        """
        Enable or disable Scan Detection for traffic that matches the
        rule. This overrides the option set in the Engine properties.

        Enable scan detection on this rule::

            for rule in policy.fw_ipv4_access_rules.all():
                rule.action.scan_detection = 'on'

        :param str value: on\\|off\\|undefined
        :return: scan detection setting (on,off,undefined)
        :rtype: str
        """
        return self.get("scan_detection")

    @scan_detection.setter
    def scan_detection(self, value):
        if value in ("on", "off", "undefined"):
            self.update(scan_detection=value)

    @property
    def sub_policy(self):
        """
        Sub policy is used when ``action=jump``.

        :rtype: FirewallSubPolicy
        """
        if "sub_policy" in self:
            return Element.from_href(self.get("sub_policy"))

    @sub_policy.setter
    def sub_policy(self, value):
        self.update(sub_policy=element_resolver(value))

    @property
    def user_response(self):
        """
        Read-only user response setting
        """
        return self.get("user_response")

    @property
    def vpn(self):
        """
        Return vpn reference. Only used if 'enforce_vpn', 'apply_vpn',
        or 'forward_vpn' is the action type.

        :param PolicyVPN value: set the policy VPN for VPN action
        :rtype: PolicyVPN
        """
        if "vpn" in self:
            return Element.from_href(self.get("vpn"))

    @vpn.setter
    def vpn(self, value):
        self.update(vpn=element_resolver(value))

    @property
    def mobile_vpn(self):
        """
        Mobile VPN only applies to engines that support VPN and that
        have the action of 'enforce_vpn', 'apply_vpn' or 'forward_vpn'
        set. This will enable mobile VPN traffic on this VPN rule.

        :param boolean value: set mobile vpn on or off
        :rtype: boolean
        """
        return self.get("mobile_vpn")

    @mobile_vpn.setter
    def mobile_vpn(self, value):
        self.update(mobile_vpn=value)


class ConnectionTracking(NestedDict):
    """
    Connection tracking settings can be configured on a per rule basis to
    control settings such as enforced MSS and how to handle connection states.

    Configuring a rule to enable MSS and set connection state tracking to
    normal::

        for rule in policy.fw_ipv4_access_rules.all():
            rule.action.connection_tracking_options.mss_enforced = True
            rule.action.connection_tracking_options.state = 'normal'
            rule.action.connection_tracking_options.mss_enforced_min_max = (1400, 1450)
            rule.action.connection_tracking_options.sync_connections = True
            rule.save()
    """

    def __init__(self, rule=None):
        if rule is None:
            ct = dict(mss_enforced=False, mss_enforced_max=0, mss_enforced_min=0, timeout=-1)
        else:
            ct = rule.data.get("connection_tracking_options", {})
        super(ConnectionTracking, self).__init__(data=ct)

    @property
    def mss_enforced(self):
        """
        Is MSS enforced

        :param bool value: True, False
        :return: bool
        """
        return self.get("mss_enforced")

    @mss_enforced.setter
    def mss_enforced(self, value):
        self.update(mss_enforced=value)

    @property
    def mss_enforced_min_max(self):
        """
        Allows entering the Minimum and Maximum value for the MSS in bytes.
        Headers are not included in the MSS value; MSS concerns only the
        payload portion of the packet.

        :param tuple int value: tuple containing (min, max) in bytes
        :return: (min, max) values
        :rtype: tuple
        """
        return (self.get("mss_enforced_min"), self.get("mss_enforced_max"))

    @mss_enforced_min_max.setter
    def mss_enforced_min_max(self, value):
        if isinstance(value, tuple):
            minimum, maximum = value
            self.update(mss_enforced_min=minimum)
            self.update(mss_enforced_max=maximum)

    @property
    def state(self):
        """
        Connection tracking mode. See documentation for
        more info.

        :param str value: no,loose,normal,strict
        :return: str
        """
        return self.get("state")

    @state.setter
    def state(self, value):
        self.update(state=value)

    @property
    def timeout(self):
        """
        The timeout (in seconds) after which inactive connections are closed.
        This timeout only concerns idle connections. Connections are not cut
        because of timeouts while the hosts are still communicating.

        :param int value: time in seconds
        :return: int
        """
        return self.get("timeout")

    @timeout.setter
    def timeout(self, value):
        """
        Set the idle timeout for connections in seconds

        :param int value: idle connection timeout
        """
        self.update(timeout=value)

    @property
    def sync_connections(self):
        """
        Are sync connections enabled for this engine. If
        None, then this is set to inherit from a continue
        rule.

        :return True, False, None (inherit from continue rule)
        """
        return self.get("sync_connections")

    @sync_connections.setter
    def sync_connections(self, value):
        self.update(sync_connections=value)


class LogOptions(NestedDict):
    """
    Log Options represent the settings related to per rule logging.

    Example of obtaining a rule reference and turning logging on
    for a particular rule::

        policy = FirewallPolicy('smcpython')
        for rule in policy.fw_ipv4_access_rules.all():
            if rule.name == 'foo':
                rule.options.log_accounting_info_mode = True
                rule.options.log_level = 'stored'
                rule.options.application_logging = 'enforced'
                rule.options.user_logging = 'enforced'
                rule.save()
    """

    def __init__(self, rule=None):
        if rule is None:
            logopts = dict(
                log_accounting_info_mode=False,
                log_closing_mode=True,
                log_level="undefined",
                log_payload_additionnal=False,
                log_payload_excerpt=False,
                log_payload_record=False,
                log_severity=-1,
            )
        else:
            logopts = rule.data.get("options", {})
        super(LogOptions, self).__init__(data=logopts)

    @property
    def application_logging(self):
        """
        Stores information about Application use. You can log spplication
        use even if you do not use Applications for access control.

        :param str value: off\\|default\\|enforced
        :return: str
        """
        return self.get("application_logging")

    @application_logging.setter
    def application_logging(self, value):
        if value in ("off", "default", "enforced"):
            self.update(application_logging=value)

    @property
    def log_accounting_info_mode(self):
        """
        Both connection opening and closing are logged and information
        on the volume of traffic is collected. This option is not
        available for rules that issue alerts.
        If you want to create reports that are based on traffic volume,
        you must select this option for all rules that allow traffic that
        you want to include in the reports.

        :param bool value: log accounting information (bits/bytes transferred)
        :return: bool
        """
        return self.get("log_accounting_info_mode")

    @log_accounting_info_mode.setter
    def log_accounting_info_mode(self, value):
        self.update(log_accounting_info_mode=value)

    @property
    def log_closing_mode(self):
        """
        Specifying False means no log entries are created when
        connections are closed. True will mean both connection
        opening and closing are logged, but no information is
        collected on the volume of traffic.

        :param bool value: enable/disable accounting data
        :return: bool
        """
        return self.get("log_closing_mode")

    @log_closing_mode.setter
    def log_closing_mode(self, value):
        self.update(log_closing_mode=value)

    @property
    def log_level(self):
        """
        Configure per rule logging. It is recommended to configure an
        Any/Any/Any/Continue rule in position 1 if global logging is
        required. This can be used to override any global logging setting.

        :param str value: none\\|stored\\|transient\\|essential\\|alert\\|undefined
        :return: str
        """
        return self.get("log_level")

    @log_level.setter
    def log_level(self, value):
        if value in ("none", "stored", "transient", "essential", "alert"):
            self.update(log_level=value)
        if not self.log_accounting_info_mode:
            self.log_accounting_info_mode = True

    @property
    def log_payload_additional(self):
        """
        Stores packet payload extracted from the traffic. The collected
        payload provides information for some of the additional log fields
        depending on the type of traffic.

        :param bool value: True, False
        :return: bool
        """
        return self.get("log_payload_additionnal")

    @log_payload_additional.setter
    def log_payload_additional(self, value):
        self.update(log_payload_additionnal=value)

    @property
    def log_payload_excerpt(self):
        """
        Stores an excerpt of the packet that matched. The maximum recorded
        excerpt size is 4 KB. This allows quick viewing of the payload in
        the logs view.

        :param bool value: collect excerpt or not
        :return: bool
        """
        return self.get("log_payload_excerpt")

    @log_payload_excerpt.setter
    def log_payload_excerpt(self, value):
        self.update(log_payload_excerpt=value)

    @property
    def log_payload_record(self):
        """
        Records the traffic up to the limit that is set in the Record
        Length field.

        :param bool value: True, False
        :return: bool
        """
        return self.get("log_payload_record")

    @log_payload_record.setter
    def log_payload_record(self, value):
        self.update(log_payload_record=value)

    @property
    def log_severity(self):
        """
        Read only log severity level

        :return: str
        """
        return self.get("log_severity")

    @property
    def user_logging(self):
        """
        Stores information about Users when they are used as the Source
        or Destination of an Access rule.
        You must select this option if you want Users to be referenced by
        name in log entries, statistics, reports, and user monitoring.
        Otherwise, only the IP address associated with the User at the time
        the log was created is stored.

        :param str value: off\\|default\\|enforced
        :return: str
        """
        return self.get("user_logging")

    @user_logging.setter
    def user_logging(self, value):
        if value in ("off", "default", "enforced"):
            self.update(user_logging=value)


class SourceVpn(NestedDict):

    type_list = ("normal", "no_vpn", "mobile_vpn")

    """
    This represents The Match VPN Options.
    The rule matches traffic from specific VPNs.
    A sub part of Firewall Access Rule used for matching the source VPN.
    """

    def __init__(self, rule=None):
        if rule is None:
            match_vpn_options = dict(match_type="no_vpn", match_vpns=[])
        else:
            match_vpn_options = rule.data.get("match_vpn_options", {})
        super(SourceVpn, self).__init__(data=match_vpn_options)

    def __eq__(self, other):
        if isinstance(other, SourceVpn):
            if self.match_type != other.match_type:
                return False
            for values in "match_vpns":
                if set(self.data.get(values, [])) != set(other.data.get(values, [])):
                    return False
            return True
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return "{}(match_type={} match_vpns={})".format(
            self.__class__.__name__, self.match_type, self.match_vpns
        )

    @property
    def match_vpns(self):
        """
        The possible list of match vpns in case of normal match.

        :return: list value: vpns or None
        """
        vpns = self.get("match_vpns")
        return [Element.from_href(vpn) for vpn in vpns] if vpns is not None else None

    @match_vpns.setter
    def match_vpns(self, value):
        self.update(match_vpns=value)

    @property
    def match_type(self):
        """
        Matches traffic based on the source VPN:
        normal: the rule only matches traffic from the specified VPNs.
        no_vpn: the rule only matches non-VPN traffic.
        mobile_vpn: the rule only matches traffic from IPsec VPN client.

        :return: str
        """
        return self.get("match_type")

    @match_type.setter
    def match_type(self, value):
        if value in self.type_list:
            self.update(match_type=value)
        else:
            raise InvalidRuleValue(
                "match_type attribute {} is invalid! Should be part of {}".format(
                    value, self.type_list
                )
            )


class AuthenticationOptions(NestedDict):
    """
    Authentication options are set on a per rule basis and dictate
    whether a user requires identification to match.
    """

    def __init__(self, rule=None):
        if rule is None:
            auth = dict(methods=[], require_auth=False, users=[])
        else:
            auth = rule.data.get("authentication_options", {})
        super(AuthenticationOptions, self).__init__(data=auth)

    def __eq__(self, other):
        if isinstance(other, AuthenticationOptions):
            if self.require_auth != other.require_auth:
                return False
            for values in ("users", "methods"):
                if set(self.data.get(values, [])) != set(other.data.get(values, [])):
                    return False
            return True
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    @property
    def methods(self):
        """
        Read only authentication methods enabled

        :return: list value: auth methods enabled
        """
        return [Element.from_href(method) for method in self.get("methods")]

    @property
    def require_auth(self):
        """
        Ready only authentication required

        :return: boolean
        """
        return self.get("require_auth")

    @property
    def timeout(self):
        """
        Timeout between authentications

        :return: int
        """
        return self.get("timeout")

    @property
    def users(self):
        """
        List of users required to authenticate

        :return: list
        """
        return [Element.from_href(user) for user in self.get("users", [])]


class TimeRange(object):
    """
    Represents a time range setting for a given rule.
    Time ranges can currently be set up to support rules based
    on starting month and ending month. At that time the rule
    will be disabled automatically.
    """

    def __init__(self, data):
        self.data = data

    @property
    def day_ranges(self):
        """
        Not Yet Implemented
        """
        pass

    @property
    def month_range_start(self):
        """
        Starting month for rule validity. Use this with month_range_end.

        :param str jan,feb,mar,apr,may,jun,jul,aug,sep,oct,nov,dec
        """
        return self.data.get("month_range_start")

    @month_range_start.setter
    def month_range_start(self, value):
        self.data["month_range_start"] = value

    @property
    def month_range_end(self):
        """
        Set month end range. Use this with month_range_start.

        :param str jan,feb,mar,apr,may,jun,jul,aug,sep,oct,nov,dec
        """
        return self.data.get("month_range_end")

    @month_range_end.setter
    def month_range_end(self, value):
        self.data["month_range_end"] = value


class MatchExpression(Element):
    """
    A match expression is used in the source / destination / service fields to group
    together elements into an 'AND'ed configuration. For example, a normal rule might
    have a source field that could include network=172.18.1.0/24 and zone=Internal
    objects. A match expression enables you to AND these elements together to enforce
    the match requires both. Logically it would be represented as
    (network 172.18.1.0/24 AND zone Internal).

        >>> from smc.elements.network import Host, Zone
        >>> from smc.policy.rule_elements import MatchExpression
        >>> from smc.policy.layer3 import FirewallPolicy
        >>> match = MatchExpression.create(name='mymatch', network_element=Host('kali'),
                                           zone=Zone('Mail'))
        >>> policy = FirewallPolicy('smcpython')
        >>> policy.fw_ipv4_access_rules.create(name='myrule', sources=[match],
                                               destinations='any', services='any')
        'http://172.18.1.150:8082/6.2/elements/fw_policy/261/fw_ipv4_access_rule/2099740'
        >>> rule = policy.search_rule('myrule')
        ...
        >>> for source in rule[0].sources.all():
        ...   print(source, source.values())
        ...
        MatchExpression(name=MatchExpression _1491760686976_2) [Zone(name=Mail), Host(name=kali)]

    Match expressions can also be used on service fields by providing values for service
    and service ports as follows::

        match = MatchExpression.create(name='mymatch', service=ApplicationSituation('FTP'),
                                       service_ports='TCPService('Any TCP Service')')

    If the service match expression requires ANY ports, you can use the string of 'any' to provide
    this logic::

        match = MatchExpression.create(name='mymatch', service=ApplicationSituation('FTP'),
                                       service_ports='any')

    Once the service match expression is created, you can use that in the policy rule::

        policy.fw_ipv4_access_rules.create(name='myrule', sources='any', destinations='any',
                                           services=[match], action=['discard'])
    """

    typeof = "match_expression"

    @classmethod
    def create(
        cls,
        name,
        user=None,
        network_element=None,
        domain_name=None,
        zone=None,
        executable=None,
        service=None,
        service_ports="any",
    ):
        """
        Create a match expression

        :param str name: name of match expression
        :param str user: name of user or user group
        :param Element network_element: valid network element type, i.e. host, network, etc
        :param DomainName domain_name: domain name network element
        :param Zone zone: zone to use
        :param str executable: name of executable or group
        :param service: any service type, i.e. TCPService, UDPService, ApplicationSituation
        :param str,Element service_ports: specify the service ports for the given service. Provide
            'ANY' as the value if the match expression requires a service/application and ANY ports
        :raises ElementNotFound: specified object does not exist
        :return: instance with meta
        :rtype: MatchExpression
        """
        ref_list = []
        if user:
            pass
        if network_element:
            ref_list.append(network_element.href)
        if domain_name:
            ref_list.append(domain_name.href)
        if zone:
            ref_list.append(zone.href)
        if executable:
            pass
        if service:
            ref_list.append(service.href)

        json = {"name": name, "ref": ref_list}

        if service:
            try:
                json.setdefault("ref", []).append(service_ports.href)  # Assume Element
            except AttributeError:
                json.update(service_port_selection="any")

        return ElementCreator(cls, json)

    def values(self):
        return [Element.from_href(ref) for ref in self.data.get("ref")]
