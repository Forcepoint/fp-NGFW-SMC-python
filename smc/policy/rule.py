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
Rule module is a base class for all access control and NAT rules.

::

    Policy (base)
          |
    FirewallPolicy ----> fw_ipv4_access_rules
                                 |
                                 |
                    IPv4Rule / IPv4NATRule (smc.policy.rule.Rule)
                       |            |
                        ------------
                            |
                           name
                           comment
                           sources (smc.policy.rule_elements.Source)
                           destinations (smc.policy.rule_elements.Destination)
                           services (smc.policy.rule_elements.Service)
                           action (smc.policy.rule_elements.Action)
                           authentication_options (smc.policy.rule_elements.AuthenticationOptions)
                           match_vpn_options (smc.policy.rule_elements.SourceVpn)
                           is_disabled
                           disable
                           enable
                           options (smc.policy.rule_elements.LogOptions)
                                    parent_policy
                                    tag
                                     ...

Examples of rule operations::

    >>> from smc.policy.layer3 import FirewallPolicy
    >>> from smc.policy.rule_elements import LogOptions
    >>> from smc.policy.rule_elements import Action
    >>> from smc.elements.other import Alias
    ...
    >>> options = LogOptions()
    >>> options.log_accounting_info_mode=True
    >>> options.log_level='stored'
    ...
    >>> policy = FirewallPolicy('AWS_Default')
    >>> options = LogOptions()
    >>> options.log_accounting_info_mode=True
    >>> options.log_level='stored'
    >>> policy.fw_ipv4_access_rules.create(name='mylogrule',services='any',sources='any',
                                           destinations='any',actions='continue',
                                           log_options=options)
    'http://172.18.1.150:8082/6.2/elements/fw_policy/272/fw_ipv4_access_rule/2099703'
    ...
    >>> actions = Action()
    >>> actions.deep_inspection = True
    >>> actions.file_filtering=False
    >>> actions.network_application_latency_monitoring=False
    ...
    >>> policy.fw_ipv4_access_rules.create(name='outbound',sources=[Alias('$$ Interface ID 1.net')],
                                           destinations='any',services='any',
                                           action=actions,log_options=options)
    'http://172.18.1.150:8082/6.2/elements/fw_policy/272/fw_ipv4_access_rule/2099704'
    >>> for rule in policy.fw_ipv4_access_rules.all():
    ...   print(rule)
    ...
    IPv4Rule(name=outbound)
    IPv4Rule(name=mylogrule)
    ...
    >>> policy.search_rule('outbound')
    [IPv4Rule(name=outbound)]
    ...
    >>> policy.fw_ipv4_access_rules.create(name='discard at bottom', sources='any',
                                           destinations='any',services='any',
                                           action='discard',add_pos=50)
    'http://172.18.1.150:8082/6.2/elements/fw_policy/272/fw_ipv4_access_rule/2099705'
    >>> for rule in policy.fw_ipv4_access_rules.all():
    ...   print(rule, rule.name, rule.action.action)
    ...
    IPv4Rule(name=outbound) outbound allow
    IPv4Rule(name=mylogrule) mylogrule allow
    IPv4Rule(name=discard at bottom) discard at bottom discard

.. note:: SMC version >= 6.6.0 requires the use of a list of strings for rule actions
"""
from smc.base.model import Element, SubElement, ElementCreator
from smc.elements.other import LogicalInterface
from smc.api.exceptions import (
    ElementNotFound,
    MissingRequiredInput,
    CreateRuleFailed,
    PolicyCommandFailed,
)
from smc.policy.rule_elements import (
    Action,
    LogOptions,
    Destination,
    Source,
    Service,
    AuthenticationOptions,
    SourceVpn, SituationMatchPart, ActionMixin,
)
from smc.base.util import element_resolver
from smc.base.decorators import cacheable_resource
from smc.core.resource import History
from smc.compat import (get_best_version, is_api_version_less_than_or_equal,
                        is_api_version_more_than_or_equal, is_smc_version_more_than_or_equal)


class Rule(object):
    """
    Top level rule construct with methods required to modify common
    behavior of any rule types. To retrieve a rule, access by reference::

        policy = FirewallPolicy('mypolicy')
        for rule in policy.fw_ipv4_nat_rules.all():
            print(rule.name, rule.comment, rule.is_disabled)
    """

    @property
    def name(self):
        """
        Name attribute of rule element
        """
        return self._meta.name if self._meta.name else "Rule @%s" % self.tag

    @property
    def history(self):
        """
        .. versionadded:: 0.6.3
            Requires SMC version >= 6.5

        Obtain the history of this element. This will not chronicle every
        modification made over time, but instead a current snapshot with
        historical information such as when the element was created, by
        whom, when it was last modified and it's current state.

        :raises ResourceNotFound: If not running SMC version >= 6.5
        :rtype: History
        """
        return History(**self.make_request(resource="history"))

    def move_rule_after(self, other_rule):
        """
        Add this rule after another. This process will make a copy of
        the existing rule and add after the specified rule. If this
        raises an exception, processing is stopped. Otherwise the original
        rule is then deleted.
        You must re-retrieve the new element after running this operation
        as new references will be created.

        :param other_rule Rule: rule where this rule will be positioned after
        :raises CreateRuleFailed: failed to duplicate this rule, no move
            is made
        """
        self.make_request(
            CreateRuleFailed, href=other_rule.get_relation("add_after"), method="create", json=self
        )
        self.delete()

    def move_rule_before(self, other_rule):
        """
        Move this rule after another. This process will make a copy of
        the existing rule and add after the specified rule. If this
        raises an exception, processing is stopped. Otherwise the original
        rule is then deleted.
        You must re-retrieve the new element after running this operation
        as new references will be created.

        :param other_rule Rule: rule where this rule will be positioned before
        :raises CreateRuleFailed: failed to duplicate this rule, no move
            is made
        """
        self.make_request(
            CreateRuleFailed, href=other_rule.get_relation("add_before"), method="create", json=self
        )
        self.delete()

    @cacheable_resource
    def action(self):
        """
        Action for this rule.

        :rtype: Action
        """
        return Action(self)

    @cacheable_resource
    def options(self):
        """
        Options for this rule.

        :rtype: LogOptions
        """
        return LogOptions(self)

    @cacheable_resource
    def authentication_options(self):
        """
        Read only authentication options field

        :rtype: AuthenticationOptions
        """
        return AuthenticationOptions(self)

    @cacheable_resource
    def match_vpn_options(self):
        """
        Read only match vpn options field

        :rtype: SourceVpn
        """
        return SourceVpn(self)

    @property
    def comment(self):
        """
        Optional comment for this rule.

        :param str value: string comment
        :rtype: str
        """
        return self.data.get("comment")

    @comment.setter
    def comment(self, value):
        self.data["comment"] = value

    @property
    def is_rule_section(self):
        """
        Is this rule considered a rule section

        :rtype: bool
        """
        return not any(field for field in ("sources", "destinations") if field in self.data)

    @property
    def is_disabled(self):
        """
        Whether the rule is enabled or disabled

        :param bool value: True, False
        :rtype: bool
        """
        return self.data.get("is_disabled")

    def disable(self):
        """
        Disable this rule
        """
        self.data["is_disabled"] = True

    def enable(self):
        """
        Enable this rule
        """
        self.data["is_disabled"] = False

    @cacheable_resource
    def sources(self):
        """
        Sources assigned to this rule

        :rtype: Source
        """
        return Source(self)

    @cacheable_resource
    def destinations(self):
        """
        Destinations for this rule

        :rtype: Destination
        """
        return Destination(self)

    @cacheable_resource
    def services(self):
        """
        Services assigned to this rule

        :rtype: Service
        """
        return Service(self)

    @property
    def parent_policy(self):
        """
        Read-only name of the parent policy

        :return: :class:`smc.base.model.Element` of type policy
        """
        return Element.from_href(self.data.get("parent_policy"))

    def save(self):
        """
        After making changes to a rule element, you must call save
        to apply the changes. Rule changes are made to cache before
        sending to SMC.

        :raises PolicyCommandFailed: failed to save with reason
        :return: href of this rule
        :rtype: str
        """
        return self.update()

    def update(self,
               validate=True,
               sources=None,
               destinations=None,
               services=None,
               action=None,
               **kwargs):
        """
        update a rule

        :param sources: source/s for rule
        :type sources: str, list[Element] str can be "any" or json
        :param destinations: destination/s for rule
        :type destinations: str, list[Element] str can be "any" or json
        :param services: service/s for rule
        :type services: str, list[Element] str can be "any" or json
        :param bool validate: validate the policy before update; default True
        :return: href of this rule
        :rtype: str
        :param action: action/s for rule
        :type action: str, list[str] since API 6.6, json
        """

        rule_values = self.update_targets(sources, destinations, services)

        if action is not None:
            # action still compatible with json
            if isinstance(action, dict):
                # Api 6.5 compatibility
                if is_api_version_less_than_or_equal("6.5"):
                    if isinstance(action["action"], list):
                        action["action"] = action["action"][0]
                else:
                    if isinstance(action["action"], str):
                        action["action"] = [action["action"]]

                rule_values.update(action=action)
            else:
                rule_action = self._get_action(action)
                rule_values.update(action=rule_action.data)

        if 'options' in kwargs and 'endpoint_executable_logging' in kwargs['options']:
            kwargs['options']['eia_executable_logging'] = \
                kwargs['options'].pop('endpoint_executable_logging')

        rule_values.update(kwargs)

        if not validate:
            rule_values.update(params={"validate": False})
        result = super(Rule, self).update(PolicyCommandFailed, **rule_values)
        try:
            del self._cache
        except AttributeError:
            pass
        return result

    @property
    def tag(self):
        """
        Value of rule tag. Read only.

        :return: rule tag
        :rtype: str
        """
        return self.data.get("tag")

    # @property
    # def time_range(self):
    #    """
    #    Time range/s assigned to this rule. May be None if
    #    no time range configured.

    #    :return: :py:class:`smc.policy.rule_elements.TimeRange`
    #    """
    #    time_range = self.data.get('time_range')
    #    if time_range:
    #        return TimeRange(self.data.get('time_range'))


class RuleCommon(object):
    """
    Functionality common to all rules
    """

    def create_rule_section(self, name, add_pos=None, insert_point=None,
                            after=None, before=None, background_color=None):
        """
        Create a rule section in a Firewall Policy. To specify a specific numbering
        position for the rule section, use the `add_pos` field. If no position or
        before/after is specified, the rule section will be placed at the top which
        will encapsulate all rules below.
        Create a rule section for the relavant policy::

            policy = FirewallPolicy('mypolicy')
            policy.fw_ipv4_access_rules.create_rule_section(name='attop')
            # For NAT rules
            policy.fw_ipv4_nat_rules.create_rule_section(name='mysection', add_pos=5)

        :param str name: create a rule section by name
        :param int add_pos: position to insert the rule, starting with position 1.
            If the position value is greater than the number of rules, the rule is
            inserted at the bottom. If add_pos is not provided, rule is inserted in
            position 1. Mutually exclusive with ``after`` and ``before`` params.
        :param str insert_point: specific insert point where to add the rule.
        :param str after: Rule tag to add this rule after. Mutually exclusive with
            ``add_pos`` and ``before`` params.
        :param str before: Rule tag to add this rule before. Mutually exclusive with
            ``add_pos`` and ``after`` params.
        :param str background_color: the background color of the rule section.
            in hexadecimal format (#RRGGBB)
        :raises MissingRequiredInput: when options are specified the need additional
            setting, i.e. use_vpn action requires a vpn policy be specified.
        :raises CreateRuleFailed: rule creation failure
        :return: the created ipv4 rule
        :rtype: IPv4Rule
        """
        href = self.href
        params = None
        if add_pos is not None:
            href = self.add_at_position(add_pos)
        elif before or after:
            params = self.add_before_after(before, after)

        if insert_point:
            params.update(insert_point=insert_point)

        json = {"comment": name}
        if (is_api_version_more_than_or_equal("7.1") and
                is_smc_version_more_than_or_equal("7.1.7") and
                background_color):
            json.update(background_color=background_color)

        return ElementCreator(
            self.__class__,
            exception=CreateRuleFailed,
            href=href,
            params=params,
            json=json,
        )

    def create_insert_point(self, name, insert_point_type="normal", add_pos=None,
                            insert_point=None, after=None, before=None, background_color=None):
        """
        Create an insert point in a Template Firewall Policy. If no position or
        before/after is specified, the insert point will be placed at the top

        Create an insert point for the relevant template policy::

            policy = FirewallPolicy('mypolicy')
            policy.fw_ipv4_access_rules.create_insert_point(name="my insert point",
                                                            insert_point_type="normal",
                                                            after=section.tag)

        :param str name: name of the insert point
        :param str insert_point_type: type of the insert point:
            - "automatic": automatic rules insert point
            - "normal": normal insert point
        :param int add_pos: position to insert the rule, starting with position 1.
            If the position value is greater than the number of rules, the rule is
            inserted at the bottom. If add_pos is not provided, rule is inserted in
            position 1. Mutually exclusive with ``after`` and ``before`` params.
        :param str insert_point: specific insert point where to add the rule.
        :param str after: Rule tag to add this insert point after. Mutually exclusive with
            ``before`` and 'add_pos' params.
        :param str before: Rule tag to add this insert point before. Mutually exclusive with
            ``after`` and 'add_pos' params.
        :param str background_color: the background color of the rule section.
            in hexadecimal format (#RRGGBB)
        :raises CreateRuleFailed: rule creation failure
        :return: the created ipv4 rule
        :rtype: IPv4Rule, IPv6Rule..
        """
        href = self.href
        params = None
        if add_pos is not None:
            href = self.add_at_position(add_pos)
        elif before or after:
            params = self.add_before_after(before, after)

        if insert_point:
            params.update(insert_point=insert_point)

        json = {"name": name, "type": insert_point_type}
        if background_color:
            json.update(background_color=background_color)

        return ElementCreator(
            self.__class__,
            exception=CreateRuleFailed,
            href=href,
            params=params,
            json=json
        )

    def add_at_position(self, pos):
        if pos <= 0:
            pos = 1
        rules = self.make_request(href=self.href)
        if rules:
            if len(rules) >= pos:  # Position somewhere in the list
                for position, entry in enumerate(rules):
                    if position + 1 == pos:
                        return self.__class__(**entry).get_relation("add_before")
            else:  # Put at the end
                last_rule = rules.pop()
                return self.__class__(**last_rule).get_relation("add_after")
        return self.href

    def add_before_after(self, before=None, after=None):
        params = {}

        if after:
            params.update(after=after)
        elif before:
            params.update(before=before)

        return params

    def update_targets(self, sources=None, destinations=None, services=None, situations=None):

        if isinstance(sources, Source):
            source = sources
        else:
            source = Source()
            if sources is not None:
                source.clear()
                if isinstance(sources, str) and sources.lower() == "any":
                    source.set_any()
                # still allow json as parameter
                elif isinstance(sources, dict):
                    source.unset_any()
                    source.add_many(sources.get("src"))
                else:
                    source.unset_any()
                    source.add_many(sources)
            else:
                source.set_none()

        if isinstance(destinations, Destination):
            destination = destinations
        else:
            destination = Destination()
            if destinations is not None:
                destination.clear()
                if isinstance(destinations, str) and destinations.lower() == "any":
                    destination.set_any()
                # still allow json as parameter
                elif isinstance(destinations, dict):
                    destination.unset_any()
                    destination.add_many(destinations.get("dst"))
                else:
                    destination.unset_any()
                    destination.add_many(destinations)
            else:
                destination.set_none()

        if isinstance(services, Service):
            service = services
        else:
            service = Service()
            if services is not None:
                service.clear()
                if isinstance(services, str) and services.lower() == "any":
                    service.set_any()
                # still allow json as parameter
                elif isinstance(services, dict):
                    service.unset_any()
                    service.add_many(services.get("service"))
                else:
                    service.unset_any()
                    service.add_many(services)
            else:
                service.set_none()

        if isinstance(situations, SituationMatchPart):
            situation = situations
        else:
            situation = SituationMatchPart()
            if situations is not None:
                situation.clear()
                if isinstance(situations, str) and situations.lower() == "any":
                    situation.set_any()
                # still allow json as parameter
                elif isinstance(situations, dict):
                    situation.unset_any()
                    situation.add_many(situations.get("situation"))
                else:
                    situation.unset_any()
                    situation.add_many(situations)
            else:
                situation.set_none()

        e = {}
        if sources is not None:
            e.update(sources=source.data)
        if destinations is not None:
            e.update(destinations=destination.data)
        if services is not None:
            e.update(services=service.data)
        if situations is not None:
            e.update(situations=situation.data)
        return e

    def update_logical_if(self, logical_interfaces):
        e = {}
        if logical_interfaces is None:
            e.update(logical_interfaces={"any": True})
        else:
            try:
                logicals = []
                for interface in logical_interfaces:
                    logicals.append(LogicalInterface(interface).href)
                e.update(logical_interfaces={"logical_interface": logicals})

            except ElementNotFound:
                raise MissingRequiredInput(
                    "Cannot find Logical interface specified " ": {}".format(logical_interfaces)
                )
        return e

    def get_action(self):
        """
        Return action instance.
        rtype: Action
        """
        return Action()

    def _get_action(self, action):
        """
        Get the action field for a rule. In SMC 6.6 actions have to be in list
        format whereas in SMC < 6.6 they were string.

        :param str,list action: provided action in create constructor
        :rtype: Action
        :raises CreateRuleFailed: invalid rule based on rule
        """
        versioned_method = get_best_version(
            ("6.5", self._get_action_6_5), ("6.6", self._get_action_6_6)
        )
        return versioned_method(action)

    def _get_action_6_6(self, action):
        if isinstance(action, ActionMixin):
            rule_action = action
            if isinstance(action.action, str):
                rule_action.action = [action.action]
        else:
            rule_action = self.get_action()
            if isinstance(action, str):
                rule_action.action = [action]
            else:
                rule_action.action = action

        valid_action = False
        if isinstance(rule_action.action, list):
            valid_action = all(_action in self._actions for _action in rule_action.action)
        else:
            valid_action = rule_action.action in self._actions

        if not valid_action:
            raise CreateRuleFailed(
                "Action specified is not valid for this "
                "rule type; action: {}".format(rule_action.action)
            )

        return rule_action

    def _get_action_6_5(self, action):
        """
        Get the action field for a rule. In SMC 6.6 actions have to be in list
        format whereas in SMC < 6.6 they were string.

        :param str,list action: provided action in create constructor
        :rtype: Action
        :raises CreateRuleFailed: invalid rule based on rule
        """
        if isinstance(action, ActionMixin):
            rule_action = action
            if isinstance(action.action, list):
                rule_action.action = action.action[0]
        else:
            rule_action = self.get_action()
            if isinstance(action, str):
                rule_action.action = action
            elif isinstance(action, list):
                rule_action.action = action[0]
            else:
                raise CreateRuleFailed(
                    "Action specified should be a str " "rule type; action: {}".format(action)
                )

        valid_action = False
        if isinstance(rule_action.action, list):
            valid_action = all(_action in self._actions for _action in rule_action.action)
        else:
            valid_action = rule_action.action in self._actions

        if not valid_action:
            raise CreateRuleFailed(
                "Action specified is not valid for this "
                "rule type; action: {}".format(rule_action.action)
            )

        return rule_action

    @property
    def background_color(self):
        """
        Background color in hexadecimal format (#RRGGBB).
        Applicable for rule section and insert point.
        """
        return self.data.get("background_color", None)

    def is_locked(self):
        """
        Locked flag for this rule.
        """
        return self.data.get("locked", None)

    def lock(self, reason_for=None):
        """
        .. Requires SMC version >= 6.10.10 or >= 7.0.2 or >= 7.1.0

        Locks this rule with an optional reason.

        :raises ResourceNotFound: If not running on supported SMC version
        """
        if reason_for:
            return self.make_request(method="update",
                                     resource="lock",
                                     params={"reason_for": reason_for})
        else:
            return self.make_request(method="update", resource="lock")

    def unlock(self):
        """
        .. Requires SMC version >= 6.10.10 or >= 7.0.2 or >= 7.1.0

        Unlocks this rule.

        :raises ResourceNotFound: If not running on supported SMC version
        """
        return self.make_request(method="update", resource="unlock")


class IPv4Rule(RuleCommon, Rule, SubElement):
    """
    Represents an IPv4 Rule for a layer 3 engine.

    Create a rule::

        policy = FirewallPolicy('mypolicy')
        policy.fw_ipv4_access_rules.create(name='smcpython',
                                           sources='any',
                                           destinations='any',
                                           services='any')

    Sources and Destinations can be one of any valid network element types defined
    in :py:class:`smc.elements.network`.

    Source entries by href::

        sources=['http://1.1.1.1:8082/elements/network/myelement',
                 'http://1.1.1.1:8082/elements/host/myhost'], etc

    Source entries using network elements::

        sources=[Host('myhost'), Network('thenetwork'), AddressRange('range')]

    Services have a similar syntax and can take any type of :py:class:`smc.elements.service`
    or  the element href or both::

            services=[TCPService('myservice'),
                      'http://1.1.1.1/8082/elements/tcp_service/mytcpservice',
                      'http://1.1.1.1/8082/elements/udp_server/myudpservice'], etc

    You can obtain services and href for the elements by using the
    :py:class:`smc.base.collection` collections::

        >>> services = list(TCPService.objects.filter('80'))
        >>> for service in services:
        ...   print(service, service.href)
        ...
       (TCPService(name=tcp80443), u'http://172.18.1.150:8082/6.1/elements/tcp_service/3535')
       (TCPService(name=HTTP to Web SaaS), u'http://172.18.1.150:8082/6.1/elements/tcp_service/589')
       (TCPService(name=HTTP), u'http://172.18.1.150:8082/6.1/elements/tcp_service/440')

    Services by application (get all facebook applications)::

        >>> applications = Search.objects.entry_point('application_situation').filter('facebook')
        >>> print(list(applications))
        [ApplicationSituation(name=Facebook-Plugins-Share-Button),
         ApplicationSituation(name=Facebook-Plugins]
        ...

    Sources / Destinations and Services can also take the string value 'any' to
    allow all. For example::

        sources='any'
    """

    typeof = "fw_ipv4_access_rule"
    _actions = (
        "allow",
        "discard",
        "continue",
        "refuse",
        "jump",
        "apply_vpn",
        "enforce_vpn",
        "forward_vpn",
        "blacklist",
        "block_list",
        "forced_next_hop",
        "explicit_proxy_jump"
    )

    def create(
        self,
        name,
        sources=None,
        destinations=None,
        services=None,
        action="allow",
        log_options=None,
        authentication_options=None,
        match_vpn_options=None,
        connection_tracking=None,
        is_disabled=False,
        vpn_policy=None,
        mobile_vpn=False,
        add_pos=None,
        insert_point=None,
        after=None,
        before=None,
        sub_policy=None,
        comment=None,
        validate=True,
        **kw
    ):
        """
        Create a layer 3 firewall rule

        .. versionchanged:: 0.7.0
            Action field now requires a list of actions as strings when using API
            version >= 6.6
        Example::
            Api version <=6.5 action is a string
            rule_vpn = p.fw_ipv4_access_rules.create( name="newrule_vpn",
                                                      sources=[Network("London Internal Network")],
                                                      destinations=[Network("net-172.31.14.0/24")],
                                                      services="any",
                                                      action="apply_vpn",
                                                      vpn_policy=vpn)
            Api version >=6.6 action is a list
            vpn_actions = Action()
            vpn_actions.action = ['allow', 'apply_vpn']
            p.fw_ipv4_access_rules.create(name='',
                                          sources=[Network("London Internal Network")],
                                          destinations=[Network("net-172.31.14.0/24")],
                                          services='any',
                                          action=vpn_actions,
                                          vpn_policy=vpn)

        :param str name: name of rule
        :param sources: source/s for rule
        :type sources: Source, list[str, Element]
        :param destinations: destination/s for rule
        :type destinations: Destination, list[str, Element]
        :param services: service/s for rule
        :type services: Service, list[str, Element]
        :param action: allow,continue,discard,refuse,enforce_vpn,
            apply_vpn,forward_vpn, blacklist, forced_next_hop (default: allow)
        :type action: Action,str,list[str]
        :param LogOptions log_options: LogOptions object
        :param ConnectionTracking connection_tracking: custom connection tracking settings
        :param AuthenticationOptions authentication_options: options for auth if any
        :param SourceVpn match_vpn_options: rule matches traffic from specific VPNs
        :param PolicyVPN,str vpn_policy: policy element or str href; required for
            enforce_vpn, use_vpn and apply_vpn actions
        :param bool mobile_vpn: if using a vpn action, you can set mobile_vpn to True and
            omit the vpn_policy setting if you want this VPN to apply to any mobile VPN based
            on the policy VPN associated with the engine
        :param str,Element sub_policy: sub policy required when rule has an action of 'jump'.
            Can be the FirewallSubPolicy element or href.
        :param int add_pos: position to insert the rule, starting with position 1. If
            the position value is greater than the number of rules, the rule is inserted at
            the bottom. If add_pos is not provided, rule is inserted in position 1. Mutually
            exclusive with ``after`` and ``before`` params.
        :param str insert_point: specific insert point where to add the rule.
        :param str after: Rule tag to add this rule after. Mutually exclusive with ``add_pos``
            and ``before`` params.
        :param str before: Rule tag to add this rule before. Mutually exclusive with ``add_pos``
            and ``after`` params.
        :param str comment: optional comment for this rule
        :param bool validate: validate the inspection policy during rule creation. Default: True
        :raises MissingRequiredInput: when options are specified the need additional
            setting, i.e. use_vpn action requires a vpn policy be specified.
        :raises CreateRuleFailed: rule creation failure
        :return: the created ipv4 rule
        :rtype: IPv4Rule
        """
        rule_values = self.update_targets(sources, destinations, services)

        rule_action = self._get_action(action)

        if any(vpn in rule_action.action for vpn in ("apply_vpn", "enforce_vpn", "forward_vpn")):
            if vpn_policy is None and not mobile_vpn:
                raise MissingRequiredInput(
                    "You must either specify a vpn_policy or set "
                    "mobile_vpn when using a rule with a VPN action"
                )
            if mobile_vpn:
                rule_action.mobile_vpn = True
            else:
                try:
                    vpn = element_resolver(vpn_policy)  # VPNPolicy
                    rule_action.vpn = vpn
                except ElementNotFound:
                    raise MissingRequiredInput(
                        "Cannot find VPN policy specified: {}, ".format(vpn_policy)
                    )

        elif "jump" in rule_action.action:
            try:
                rule_action.sub_policy = element_resolver(sub_policy)
            except ElementNotFound:
                raise MissingRequiredInput(
                    "Cannot find sub policy specified: {} ".format(sub_policy)
                )

        log_options = LogOptions() if not log_options else log_options

        if connection_tracking is not None:
            rule_action.connection_tracking_options.update(**connection_tracking)

        auth_options = (
            AuthenticationOptions() if not authentication_options else authentication_options
        )

        match_vpn_data = None if not match_vpn_options else match_vpn_options.data

        rule_values.update(
            name=name,
            comment=comment,
            action=rule_action.data,
            options=log_options.data,
            authentication_options=auth_options.data,
            match_vpn_options=match_vpn_data,
            is_disabled=is_disabled,
            **kw
        )

        params = {"validate": False} if not validate else {}
        href = self.href
        if add_pos is not None:
            href = self.add_at_position(add_pos)
        elif before or after:
            params.update(**self.add_before_after(before, after))

        if insert_point:
            params.update(insert_point=insert_point)

        return ElementCreator(
            self.__class__, exception=CreateRuleFailed, href=href, params=params, json=rule_values
        )


class IPv4Layer2Rule(RuleCommon, Rule, SubElement):
    """
    Create IPv4 rules for Layer 2 Firewalls

    Example of creating an allow all rule::

        policy = Layer2Policy('mylayer2')
        policy.layer2_ipv4_access_rules.create(name='myrule',
                                               sources='any',
                                               destinations='any',
                                               services='any')
    """

    typeof = "layer2_ipv4_access_rule"
    _actions = ("allow", "continue", "discard", "refuse", "jump", "blacklist", "block_list")

    def create(
        self,
        name,
        sources=None,
        destinations=None,
        services=None,
        action="allow",
        is_disabled=False,
        logical_interfaces=None,
        add_pos=None,
        insert_point=None,
        after=None,
        before=None,
        comment=None,
        validate=True,
        sub_policy=None,
        **kw
    ):
        """
        Create an IPv4 Layer 2 Engine rule

        .. versionchanged:: 0.7.0
            Action field now requires a list of actions as strings when using SMC
            version >= 6.6.0

        :param str name: name of rule
        :param sources: source/s for rule
        :type sources: list[str, Element]
        :param destinations: destination/s for rule
        :type destinations: list[str, Element]
        :param services: service/s for rule
        :type services: list[str, Element]
        :param str, Action action: \\|allow\\|continue\\|discard\\|refuse\\|blacklist
        :param bool is_disabled: whether to disable rule or not
        :param list logical_interfaces: logical interfaces by name
        :param int add_pos: position to insert the rule, starting with position 1. If
            the position value is greater than the number of rules, the rule is inserted at
            the bottom. If add_pos is not provided, rule is inserted in position 1. Mutually
            exclusive with ``after`` and ``before`` params.
        :param str insert_point: specific insert point where to add the rule.
        :param str after: Rule tag to add this rule after. Mutually exclusive with ``add_pos``
            and ``before`` params.
        :param str before: Rule tag to add this rule before. Mutually exclusive with ``add_pos``
            and ``after`` params.
        :param str comment: optional comment for this rule
        :param bool validate: validate the inspection policy during rule creation. Default: True
        :param str,Element sub_policy: sub policy required when rule has an action of 'jump'.
            Can be the IPSSubPolicy element or href.
        :raises MissingRequiredInput: when options are specified the need additional
            setting, i.e. use_vpn action requires a vpn policy be specified.
        :raises CreateRuleFailed: rule creation failure
        :return: newly created rule
        :rtype: IPv4Layer2Rule
        """
        rule_values = self.update_targets(sources, destinations, services)

        rule_action = self._get_action(action)

        if "jump" in rule_action.action:
            try:
                rule_action.sub_policy = element_resolver(sub_policy)
            except ElementNotFound:
                raise MissingRequiredInput(
                    "Cannot find sub policy specified: {} ".format(sub_policy)
                )

        rule_values.update(
            self.update_logical_if(logical_interfaces),
            name=name,
            comment=comment,
            action=rule_action.data,
            is_disabled=is_disabled,
            **kw
        )

        params = {"validate": False} if not validate else {}

        href = self.href
        if add_pos is not None:
            href = self.add_at_position(add_pos)
        elif before or after:
            params.update(**self.add_before_after(before, after))

        if insert_point:
            params.update(insert_point=insert_point)

        return ElementCreator(
            self.__class__, exception=CreateRuleFailed, href=href, params=params, json=rule_values
        )


class IPSRule(IPv4Layer2Rule):
    """
    Create IPS Rule

    Example of creating an allow all rule::

        ips_policy = IPSPolicy("myIPSPolicy1")
        rule1 = ips_policy.ips_ipv4_access_rules.create(
                                                         name="ips_jump_rule",
                                                         sources="any",
                                                         destinations="any",
                                                         services=[TCPService("SSH")],
                                                         action="allow"
                                                        )
    """

    typeof = "ips_ipv4_access_rules"


class EthernetRule(RuleCommon, Rule, SubElement):
    """
    Ethernet Rule represents a policy on a layer 2 or IPS engine.

    If logical_interfaces parameter is left blank, 'any' logical
    interface is used.

    Create an ethernet rule for a layer 2 policy::

        policy = Layer2Policy('layer2policy')
        policy.layer2_ethernet_rules.create(name='l2rule',
                                            logical_interfaces=['dmz'],
                                            sources='any',
                                            action='discard')
    """

    typeof = "ethernet_rule"
    _actions = ("allow", "discard")

    def create(
        self,
        name,
        sources=None,
        destinations=None,
        services=None,
        action="allow",
        is_disabled=False,
        logical_interfaces=None,
        add_pos=None,
        insert_point=None,
        after=None,
        before=None,
        comment=None,
        validate=True,
        **kw
    ):
        """
        Create an Ethernet rule

        .. versionchanged:: 0.7.0
            Action field now requires a list of actions as strings when using SMC
            version >= 6.6.0

        :param str name: name of rule
        :param sources: source/s for rule
        :type sources: list[str, Element]
        :param destinations: destination/s for rule
        :type destinations: list[str, Element]
        :param services: service/s for rule
        :type services: list[str, Element]
        :param str action: \\|allow\\|continue\\|discard\\|refuse\\|blacklist
        :param bool is_disabled: whether to disable rule or not
        :param list logical_interfaces: logical interfaces by name
        :param int add_pos: position to insert the rule, starting with position 1. If
            the position value is greater than the number of rules, the rule is inserted at
            the bottom. If add_pos is not provided, rule is inserted in position 1. Mutually
            exclusive with ``after`` and ``before`` params.
        :param str insert_point: specific insert point where to add the rule.
        :param str after: Rule tag to add this rule after. Mutually exclusive with ``add_pos``
            and ``before`` params.
        :param str before: Rule tag to add this rule before. Mutually exclusive with ``add_pos``
            and ``after`` params.
        :param bool validate: validate the inspection policy during rule creation. Default: True
        :raises MissingRequiredInput: when options are specified the need additional
            setting, i.e. use_vpn action requires a vpn policy be specified.
        :raises CreateRuleFailed: rule creation failure
        :return: newly created rule
        :rtype: EthernetRule
        """
        rule_values = self.update_targets(sources, destinations, services)

        rule_action = self._get_action(action)

        rule_values.update(
            self.update_logical_if(logical_interfaces),
            name=name,
            comment=comment,
            action=rule_action.data,
            is_disabled=is_disabled,
            **kw
        )

        params = {"validate": False} if not validate else {}

        href = self.href
        if add_pos:
            href = self.add_at_position(add_pos)
        elif before or after:
            params.update(**self.add_before_after(before, after))

        if insert_point:
            params.update(insert_point=insert_point)

        return ElementCreator(
            self.__class__, exception=CreateRuleFailed, href=href, params=params, json=rule_values
        )


class IPv6Rule(IPv4Rule):
    """
    IPv6 access rule defines sources and destinations that must be
    in IPv6 format.

    .. note:: It is possible to submit a source or destination in
              IPv4 format, however this will fail validation when
              attempting to push policy.
    """

    typeof = "fw_ipv6_access_rule"


class IPv6Layer2Rule(IPv4Layer2Rule):
    """
    IPv6 access rule defines sources and destinations that must be
    in IPv6 format.

    .. note:: It is possible to submit a source or destination in
              IPv4 format, however this will fail validation when
              attempting to push policy.
    """

    typeof = "layer2_ipv6_access_rule"
