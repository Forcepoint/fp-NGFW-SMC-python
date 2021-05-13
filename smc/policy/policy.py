"""
Policy module represents the classes required to obtaining and manipulating
policies within the SMC.

Policy is the top level base class for all policy subclasses such as
:py:class:`smc.policy.layer3.FirewallPolicy`,
:py:class:`smc.policy.layer2.Layer2Policy`,
:py:class:`smc.policy.ips.IPSPolicy`,
:py:class:`smc.policy.inspection.InspectionPolicy`,
:py:class:`smc.policy.file_filtering.FileFilteringPolicy`

Policy represents actions that are common to all policy types, however for
options that are not possible in a policy type, the method is overridden to
return None. For example, 'upload' is not called on a template policy, but
instead on the policy referencing that template. Therefore 'upload' is
overidden.

.. note:: It is not required to call open() and save() on SMC API >= 6.1. It is
          also optional on earlier versions but if longer running operations are
          needed, calling open() will lock the policy from test_external modifications
          until save() is called.
"""
import collections
from smc.api.exceptions import PolicyCommandFailed
from smc.administration.tasks import Task
from smc.base.model import Element, lookup_class, ElementRef


class Policy(Element):
    """
    Policy is the base class for all policy types managed by the SMC.
    This base class is not intended to be instantiated directly.

    Subclasses should implement create(....) individually as each subclass will likely
    have different input requirements.

    All generic methods that are policy level, such as 'open', 'save', 'force_unlock',
    'export', and 'upload' are encapsulated into this base class.

    :ivar Element template: The template associated with this policy. Can be None
    :ivar InspectionPolicy inspection_policy: related inspection policy
    :ivar FileFilteringPolicy file_filtering_policy: related file policy
    """

    template = ElementRef("template")
    inspection_policy = ElementRef("inspection_policy")
    file_filtering_policy = ElementRef("file_filtering_policy")

    def upload(
        self,
        engine,
        timeout=5,
        wait_for_finish=False,
        preserve_connections=True,
        generate_snapshot=True,
        **kw
    ):
        """
        Upload policy to specific device. Using wait for finish
        returns a poller thread for monitoring progress::

            policy = FirewallPolicy('_NSX_Master_Default')
            poller = policy.upload('myfirewall', wait_for_finish=True)
            while not poller.done():
                poller.wait(3)
                print(poller.task.progress)
            print("Task finished: %s" % poller.message())

        :param str engine: name of device to upload policy to
        :param bool preserve_connections: flag to preserve connections (True by default)
        :param bool generate_snapshot: flag to generate snapshot (True by default)
        :raises: TaskRunFailed
        :return: TaskOperationPoller
        """
        return Task.execute(
            self,
            "upload",
            params={"filter": engine},
            json={
                "preserve_connections": preserve_connections,
                "snapshot_creation": generate_snapshot,
            },
            timeout=timeout,
            wait_for_finish=wait_for_finish,
            **kw
        )

    def force_unlock(self):
        """
        Forcibly unlock a locked policy

        :return: None
        """
        self.make_request(PolicyCommandFailed, method="create", resource="force_unlock")

    def search_rule(self, search):
        """
        Search a rule for a rule tag or name value
        Result will be the meta data for rule (name, href, type)

        Searching for a rule in specific policy::

            f = FirewallPolicy(policy)
            search = f.search_rule(searchable)

        :param str search: search string
        :return: rule elements matching criteria
        :rtype: list(Element)
        """
        result = self.make_request(resource="search_rule", params={"filter": search})

        if result:
            results = []
            for data in result:
                typeof = data.get("type")
                if "ethernet" in typeof:
                    klazz = lookup_class("ethernet_rule")
                elif typeof in ["ips_ipv4_access_rule", "l2_interface_ipv4_access_rule"]:
                    klazz = lookup_class("layer2_ipv4_access_rule")
                else:
                    klazz = lookup_class(typeof)
                results.append(klazz(**data))
            return results
        return []

    def rule_counters(self, engine=None, duration_type="one_week", duration=0, start_time=0):
        """
        .. versionadded:: 0.5.6
            Obtain rule counters for this policy. Requires SMC >= 6.2

        Rule counters can be obtained for a given policy and duration for
        those counters can be provided in duration_type. A custom start
        range can also be provided.

        :param Engine engine: the target engine to obtain rule counters from
        :param str duration_type: duration for obtaining rule counters. Valid
            options are: one_day, one_week, one_month, six_months, one_year,
            custom, since_last_upload
        :param int duration: if custom set for duration type, specify the
            duration in seconds (Default: 0)
        :param int start_time: start time in milliseconds (Default: 0)
        :raises: ActionCommandFailed
        :return: list of rule counter objects
        :rtype: RuleCounter
        """
        json = {
            "duration_type": duration_type,
            "target_ref": engine.href if engine else None,
            "duration": duration,
        }

        return [
            RuleCounter(**rule)
            for rule in self.make_request(method="create", resource="rule_counter", json=json)
        ]


class InspectionPolicy(Policy):
    """
    The Inspection Policy references a specific inspection policy that is a property
    (reference) to either a FirewallPolicy, IPSPolicy or Layer2Policy. This policy
    defines specific characteristics for threat based prevention.
    In addition, exceptions can be made at this policy level to bypass scanning based
    on the rule properties.
    """

    typeof = "inspection_template_policy"

    def export(self):
        pass  # Not valid for inspection policy

    def upload(self):
        pass  # Not valid for inspection policy


class RuleCounter(collections.namedtuple("RuleCounter", "hits rule_ref total_hits")):
    """
    Rule counter representing hits for a specific rule.

    :param int hits: The number of times where the rule has been used on
        the engine. If not specified, that means the rule has not been uploaded
        or unknown on the engine.
    :param rule_ref: rule reference to obtain the rule
    :param Rule rule: resolved rule_ref to element
    :param total_hits: total number of hits over the duration
    """

    __slots__ = ()

    def __new__(cls, rule_ref, hits=0, total_hits=0):  # @ReservedAssignment
        return super(RuleCounter, cls).__new__(cls, hits, rule_ref, total_hits)

    @property
    def rule(self):
        """
        Return the Rule element for this rule counter. A rule may be from
        the policy or the policy template.

        :rtype: Rule
        """
        return Element.from_href(self.rule_ref)
