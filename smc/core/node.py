"""
Node level actions for an engine. Once an engine is loaded, all methods
and resources are available to that particular engine.

For example, to load an engine and run node level commands::

    engine = Engine('myfw')
    for node in engine.nodes:
        node.reboot()
        node.bind_license()
        node.go_online()
        node.go_offline()
        ...
        ...
"""
import collections
from smc.base.util import save_to_file, b64encode
from smc.base.model import SubElement, Element, ElementList
from smc.compat import get_best_version
from smc.core.sub_interfaces import LoopbackInterface
from smc.api.exceptions import LicenseError, NodeCommandFailed
from smc.base.structs import SerializedIterable, NestedDict


class Node(SubElement):
    """
    Node settings to make each engine node controllable individually.
    Obtain a reference to a Node by loading an Engine resource.
    Engine will have a 'has-a' relationship with node and stored as the
    nodes attribute.
    ::

        >>> for node in engine.nodes:
        ...   node
        ...
        Node(name=fwcluster node 1)
        Node(name=fwcluster node 2)

    """

    @property
    def type(self):
        """
        Node type
        """
        return self._meta.type

    @property
    def version(self):
        """
        Engine version. If the node is not yet initialized, this
        will return None.

        :return: str or None
        """
        return self.data.get("engine_version")

    def rename(self, name):
        """
        Rename this node

        :param str name: new name for node
        """
        self.update(name="{} node {}".format(name, self.nodeid))

    @property
    def nodeid(self):
        """
        ID of this node
        """
        return self.data.get("nodeid")

    def update(self, *args, **kw):
        # Delete cache from engine reference
        super(Node, self).update(*args, **kw)
        self._engine._del_cache()

    @classmethod
    def _create(cls, name, node_type, nodeid=1, loopback_ndi=None):
        """
        Create the node/s for the engine. This isn't called directly,
        instead it is used when engine.create() is called

        :param str name: name of node
        :param str node_type: based on engine type specified
        :param int nodeid: used to identify which node
        :param list LoopbackInterface loopback_ndi: optional loopback
            interface for node.
        """
        loopback = loopback_ndi if loopback_ndi else []
        node = {
            node_type: {
                "activate_test": True,
                "disabled": False,
                "loopback_node_dedicated_interface": loopback,
                "name": name + " node " + str(nodeid),
                "nodeid": nodeid,
            }
        }
        return node

    @property
    def loopback_interface(self):
        """
        Loopback interfaces for this node. This will return
        empty if the engine is not a layer 3 firewall type::

            >>> engine = Engine('dingo')
            >>> for node in engine.nodes:
            ...   for loopback in node.loopback_interface:
            ...     loopback
            ...
            LoopbackInterface(address=172.20.1.1, nodeid=1, rank=1)
            LoopbackInterface(address=172.31.1.1, nodeid=1, rank=2)
            LoopbackInterface(address=2.2.2.2, nodeid=1, rank=3)

        :rtype: list(LoopbackInterface)
        """
        for lb in self.data.get("loopback_node_dedicated_interface", []):
            yield LoopbackInterface(lb, self._engine)

    def fetch_license(self):
        """
        Fetch the node level license

        :raises LicenseError: fetching license failure with reason
        :return: None
        """
        self.make_request(LicenseError, method="create", resource="fetch")

    def bind_license(self, license_item_id=None):
        """
        Auto bind license, uses dynamic if POS is not found

        :param str license_item_id: license id
        :raises LicenseError: binding license failed, possibly no licenses
        :return: None
        """
        params = {"license_item_id": license_item_id}
        self.make_request(LicenseError, method="create", resource="bind", params=params)

    def unbind_license(self):
        """
        Unbind a bound license on this node.

        :raises LicenseError: failure with reason
        :return: None
        """
        self.make_request(LicenseError, method="create", resource="unbind")

    def cancel_unbind_license(self):
        """
        Cancel unbind for license

        :raises LicenseError: unbind failed with reason
        :return: None
        """
        self.make_request(LicenseError, method="create", resource="cancel_unbind")

    def initial_contact(
        self,
        enable_ssh=True,
        time_zone=None,
        keyboard=None,
        install_on_server=None,
        filename=None,
        as_base64=False,
    ):
        """
        Allows to save the initial contact for for the specified node

        :param bool enable_ssh: flag to know if we allow the ssh daemon on the
               specified node
        :param str time_zone: optional time zone to set on the specified node
        :param str keyboard: optional keyboard to set on the specified node
        :param bool install_on_server: optional flag to know if the generated
            configuration needs to be installed on SMC Install server
            (POS is needed)
        :param str filename: filename to save initial_contact to
        :param bool as_base64: return the initial config in base 64 format. Useful
            for cloud based engine deployments as userdata
        :raises NodeCommandFailed: IOError handling initial configuration data
        :return: initial contact text information
        :rtype: str
        """
        result = self.make_request(
            NodeCommandFailed,
            method="create",
            raw_result=True,
            resource="initial_contact",
            params={"enable_ssh": enable_ssh},
        )

        if result.content:
            if as_base64:
                result.content = b64encode(result.content)

            if filename:
                try:
                    save_to_file(filename, result.content)
                except IOError as e:
                    raise NodeCommandFailed(
                        "Error occurred when attempting to save initial "
                        "contact to file: {}".format(e)
                    )
        return result.content

    def dynamic_element_update(self, name_cache_object):
        """"""
        return self.make_request(
            NodeCommandFailed,
            method="create",
            resource="dynamic_element_update",
            headers={"content-type": "multipart/form-data"},
            files={"update_file": name_cache_object.serialize()},
        )

    @property
    def interface_status(self):
        """
        Obtain the interface status for this node. This will return an
        iterable that provides information about the existing interfaces.
        Retrieve a single interface status::

            >>> node = engine.nodes[0]
            >>> node
            Node(name=ngf-1065)
            >>> node.interface_status
            <smc.core.node.InterfaceStatus object at 0x103b2f310>
            >>> node.interface_status.get(0)
            InterfaceStatus(aggregate_is_active=False, capability=u'Normal Interface',
                flow_control=u'AutoNeg: off Rx: off Tx: off',
                interface_id=0, mtu=1500, name=u'eth0_0', port=u'Copper',
                speed_duplex=u'1000 Mb/s / Full / Automatic', status=u'Up')

        Or iterate and get all interfaces::

            >>> for stat in node.interface_status:
            ...   stat
            ...
            InterfaceStatus(aggregate_is_active=False, capability=u'Normal Interface', ...
            ...

        :raises NodeCommandFailed: failure to retrieve current status
        :rtype: InterfaceStatus
        """
        result = self.make_request(NodeCommandFailed, resource="appliance_status")
        return InterfaceStatus(result.get("interface_statuses", []))

    @property
    def hardware_status(self):
        """
        Obtain hardware statistics for various areas of this node.

        See :class:`~HardwareStatus` for usage.

        :raises NodeCommandFailed: failure to retrieve current status
        :rtype: HardwareStatus
        """
        result = self.make_request(NodeCommandFailed, resource="appliance_status")
        return HardwareStatus(result.get("hardware_statuses", []))

    @property
    def health(self):
        """
        Basic status for individual node. Specific information such as node
        name dynamic package version, configuration status, platform and
        version.

        :rtype: ApplianceStatus
        """
        appliance_status = self.make_request(NodeCommandFailed, resource="status")
        return ApplianceStatus(appliance_status)

    def appliance_info(self):
        """
        .. versionadded:: 0.5.7
            Requires SMC version >= 6.3

        Retrieve appliance info for this engine.

        :raises NodeCommandFailed: Appliance info not supported on
            this node
        :rtype: ApplianceInfo
        """
        if "appliance_info" in self.data:
            return ApplianceInfo(**self.data["appliance_info"])
        else:
            raise NodeCommandFailed("Appliance information is not available on this engine")

    def status(self):
        """
        Basic status for individual node. Specific information such as node
        name dynamic package version, configuration status, platform and
        version.

        :rtype: ApplianceStatus
        """
        result = self.make_request(NodeCommandFailed, resource="status")

        return ApplianceStatus(result)

    def go_online(self, comment=None):
        """
        Executes a Go-Online operation on the specified node
        typically done when the node has already been forced offline
        via :func:`go_offline`

        :param str comment: (optional) comment to audit
        :raises NodeCommandFailed: online not available
        :return: None
        """
        self.make_request(
            NodeCommandFailed, method="update", resource="go_online", params={"comment": comment}
        )

    def go_offline(self, comment=None):
        """
        Executes a Go-Offline operation on the specified node

        :param str comment: optional comment to audit
        :raises NodeCommandFailed: offline not available
        :return: None
        """
        self.make_request(
            NodeCommandFailed, method="update", resource="go_offline", params={"comment": comment}
        )

    def go_standby(self, comment=None):
        """
        Executes a Go-Standby operation on the specified node.
        To get the status of the current node/s, run :func:`status`

        :param str comment: optional comment to audit
        :raises NodeCommandFailed: engine cannot go standby
        :return: None
        """
        self.make_request(
            NodeCommandFailed, method="update", resource="go_standby", params={"comment": comment}
        )

    def lock_online(self, comment=None):
        """
        Executes a Lock-Online operation on the specified node

        :param str comment: comment for audit
        :raises NodeCommandFailed: cannot lock online
        :return: None
        """
        self.make_request(
            NodeCommandFailed, method="update", resource="lock_online", params={"comment": comment}
        )

    def lock_offline(self, comment=None):
        """
        Executes a Lock-Offline operation on the specified node
        Bring back online by running :func:`go_online`.

        :param str comment: comment for audit
        :raises NodeCommandFailed: lock offline failed
        :return: None
        """
        self.make_request(
            NodeCommandFailed, method="update", resource="lock_offline", params={"comment": comment}
        )

    def reset_user_db(self, comment=None):
        """
        Executes a Send Reset LDAP User DB Request operation on this
        node.

        :param str comment: comment to audit
        :raises NodeCommandFailed: failure resetting db
        :return: None
        """
        self.make_request(
            NodeCommandFailed,
            method="update",
            resource="reset_user_db",
            params={"comment": comment},
        )

    def debug(self, filter_enabled=False):
        """
        View all debug settings for this node. This will return a
        debug object. View the debug object repr to identify settings
        to enable or disable and submit the object to :meth:`set_debug`
        to enable settings.

        Add filter_enabled=True argument to see only enabled settings

        :param bool filter_enabled: returns all enabled diagnostics
        :raises NodeCommandFailed: failure getting diagnostics
        :rtype: Debug

        .. seealso:: :class:`~Debug` for example usage
        """
        params = {"filter_enabled": filter_enabled}
        result = self.make_request(NodeCommandFailed, resource="diagnostic", params=params)
        return Debug(result.get("diagnostics"))

    def set_debug(self, debug):
        """
        Set the debug settings for this node. This should be a modified
        :class:`~Debug` instance. This will take effect immediately on
        the specified node.

        :param Debug debug: debug object with specified settings
        :raises NodeCommandFailed: fail to communicate with node
        :return: None

        .. seealso:: :class:`~Debug` for example usage
        """
        self.make_request(
            NodeCommandFailed, method="create", resource="send_diagnostic", json=debug.serialize()
        )

    def reboot(self, comment=None):
        """
        Send reboot command to this node.

        :param str comment: comment to audit
        :raises NodeCommandFailed: reboot failed with reason
        :return: None
        """
        self.make_request(
            NodeCommandFailed, method="update", resource="reboot", params={"comment": comment}
        )

    def power_off(self):
        """
        .. versionadded:: 0.5.6
            Requires engine version >=6.3

        Power off engine.

        :raises NodeCommandFailed: online not available
        :return: None
        """
        self.make_request(NodeCommandFailed, method="update", resource="power_off")

    def reset_to_factory(self):
        """
        .. versionadded:: 0.5.6
            Requires engine version >=6.3

        Reset the engine to factory defaults.

        :raises NodeCommandFailed: online not available
        :return: None
        """
        self.make_request(NodeCommandFailed, method="update", resource="reset_to_factory")

    def sginfo(self, include_core_files=False, include_slapcat_output=False, filename="sginfo.gz"):
        """
        Get the SG Info of the specified node. Optionally provide
        a filename, otherwise default to 'sginfo.gz'. Once you run
        gzip -d <filename>, the inner contents will be in .tar format.

        :param include_core_files: flag to include or not core files
        :param include_slapcat_output: flag to include or not slapcat output
        :raises NodeCommandFailed: failed getting sginfo with reason
        :return: string path of download location
        :rtype: str
        """
        params = {
            "include_core_files": include_core_files,
            "include_slapcat_output": include_slapcat_output,
        }

        result = self.make_request(
            NodeCommandFailed, raw_result=True, resource="sginfo", filename=filename, params=params
        )

        return result.content

    def ssh(self, enable=True, comment=None):
        """
        Enable or disable SSH

        :param bool enable: enable or disable SSH daemon
        :param str comment: optional comment for audit
        :raises NodeCommandFailed: cannot enable SSH daemon
        :return: None
        """
        self.make_request(
            NodeCommandFailed,
            method="update",
            resource="ssh",
            params={"enable": enable, "comment": comment},
        )

    def change_ssh_pwd(self, pwd=None, comment=None):
        """
        Executes a change SSH password operation on the specified node

        :param str pwd: changed password value
        :param str comment: optional comment for audit log
        :raises NodeCommandFailed: cannot change ssh password
        :return: None
        """
        self.make_request(
            NodeCommandFailed,
            method="update",
            resource="change_ssh_pwd",
            params={"comment": comment},
            json={"value": pwd},
        )

    def time_sync(self):
        """
        Send a time sync command to this node.

        :raises NodeCommandFailed: time sync not supported on node
        :return: None
        """
        self.make_request(NodeCommandFailed, method="update", resource="time_sync")

    def certificate_info(self):
        """
        Get the certificate info of this node. This can return None if the
        engine type does not directly have a certificate, like a virtual engine
        where the master engine manages certificates.

        :return: dict with links to cert info
        """
        return self.make_request(resource="certificate_info")


class ApplianceStatus(NestedDict):
    """
    Appliance status attributes define specifics about the hardware platform
    itself, including version, dynamic package, current configuration status
    and installed policy.
    Retrieve appliance status for engine nodes::

        for node in engine.nodes:
            node.health

    .. versionchanged:: 1.0.1
        added master_node since SMC version >= 6.10 API6.10, 6.9, 6.8
    """

    def __init__(self, data):
        super(ApplianceStatus, self).__init__(data=data)

    def __str__(self):
        str = ""
        for key in self:
            str += "{} = {}; ".format(key, self[key])
        return str

    @property
    def dyn_up(self):
        """
        :return: str dyn_up: Dynamic update package version
        """
        return self.get("dyn_up")

    @property
    def name(self):
        """
        :return: str name: Name of engine
        """
        return self.get("name")

    @property
    def platform(self):
        """
        :return: str platform: Underlying platform, x86, etc
        """
        return self.get("platform")

    @property
    def version(self):
        """
        :return: str version: Version of software installed
        """
        return self.get("version")

    @property
    def configuration_status(self):
        """
        Valid values:
            * Initial (no initial configuration file is yet generated)
            * Declared (initial configuration file is generated)
            * Configured (initial configuration is done with the engine)
            * Installed (policy is installed on the engine)

        :return: str configuration_status: configuration status
        """
        return self.get("configuration_status")

    @property
    def status(self):
        """
        str status:

        Valid values:
            Not Monitored/Unknown/Online/Going Online/Locked Online/
            Going Locked Online/Offline/Going Offline/Locked Offline/
            Going Locked Offline/Standby/Going Standby/No Policy Installed

        :return:
        """
        return self.get("status")

    @property
    def state(self):
        """
        Valid values:
            INITIAL/READY/ERROR/SERVER_ERROR/NO_STATUS/TIMEOUT/
            DELETED/DUMMY
        :return: str state: state of the Node
        """
        return self.get("state")

    @property
    def installed_policy(self):
        """
        :return: str installed_policy: Installed policy by name
        """
        return self.get("installed_policy")

    @property
    def master_node(self):
        """
        The master engine node for a virtual engine

        :return: MasterNode: the master node or None
        """
        return (
            Element.from_href(self.get("master_node"))
            if self.get("master_node") is not None
            else None
        )


ApplianceInfo = collections.namedtuple(
    "ApplianceInfo",
    "cloud_id cloud_type first_upload_time hardware_version initial_contact_time product_name "
    "initial_license_remaining_days proof_of_serial software_features software_version",
)

"""
Appliance specific information about the given engine node.
Appliance info is specific to the engine itself and will provide additional
details about the hardware model, applied license features, if the engine
has made initial contact and when initial policy upload was made.

    Retrieve appliance info engine nodes::

        engine = Engine('dingo')
        for node in engine.nodes:
            node.appliance_info()

:ivar str cloud_id: N/A
:ivar str cloud_type: N/A
:ivar long first_upload_time: policy first upload time in ms
:ivar float hardware_version: hardware version of appliance
:ivar long initial_contact_time: when node contacted SMC, in ms
:ivar int intial_license_remaining_days: validity in days of current license
:ivar str product_name: name of hardware model
:ivar str proof_of_serial: proof of serial for this hardware
:ivar str software_features: feature string
:ivar str software_version: initial software version on base image
"""
ApplianceInfo.__new__.__defaults__ = (None,) * len(ApplianceInfo._fields)


InternalInterfaceStatus = collections.namedtuple(
    "InterfaceStatus",
    "aggregate_is_active capability flow_control interface_id mtu name port speed_duplex "
    "status aggregate_mode aggregate_slaves aggregate_master aggregate_master_status",
)
InternalInterfaceStatus.__new__.__defaults__ = (None,) * len(InternalInterfaceStatus._fields)


class InterfaceStatus(SerializedIterable):
    """
    An iterable that provides a collections interface to interfaces
    and current status on the specified node.

    Interface status fields:

    :ivar bool aggregate_is_active: Is link aggregation enabled on this interface
    :ivar str capability: What type of interface this is, i.e. "Normal Interface"
    :ivar str flow_control: Autonegotiation, etc
    :ivar int interface_id: Physical interface id
    :ivar int mtu: Max transmission unit
    :ivar str name: Name of the interface, i.e. eth0_0, etc
    :ivar str port: Type of physical port, i.e. Copper, Fiber
    :ivar str speed_duplex: Negotiated speed on the interface
    :ivar str status: Status of interface, Up, Down, etc.
    """

    def __init__(self, status):
        data = status.get("interface_status")
        super(InterfaceStatus, self).__init__(data, InternalInterfaceStatus)

    def get(self, interface_id):
        """
        Get a specific interface by the interface id

        :param int interface_id: interface ID
        :rtype: InterfaceStatus
        """
        return super(InterfaceStatus, self).get(interface_id=interface_id)


def item_status_6_6(item):
    for items in item.items:
        statuses = items.get("statuses")
        if statuses:
            for status in statuses:
                yield Status_6_6(**status)


def item_status_6_7(item):
    for items in item.items:
        statuses = items.get("statuses")
        item_status = items.get("status")
        if statuses:
            for status in statuses:
                yield (item_status, Status_6_7(**status))


label_6_7 = collections.namedtuple("Label", "name status items")
label_6_6 = collections.namedtuple("Label", "name items")
Status_6_7 = collections.namedtuple("Status", "label param sub_system value")
Status_6_6 = collections.namedtuple("Status", "label param status sub_system value")

"""
Status fields for hardware status. These fields have generic titles which
are used to represent the field and values for each hardware type.

:ivar str label: name for this field
:ivar str param: field this measures
:ivar int status: unused
:ivar str sub_system: category for this hardware status
:ivar str value: value for this field
"""


class HardwareStatus(SerializedIterable):
    """
    Provides an interface to methods that simplify viewing
    hardware statuses on this node.
    Example of usage::

        >>> engine = Engine('sg_vm')
        >>> node = engine.nodes[0]
        >>> node
        Node(name=ngf-1065)
        >>> node.hardware_status
        HardwareStatus(Anti-Malware, File Systems, GTI Cloud, Sandbox, Logging subsystem,
                       MLC Connection, Web Filtering)
        >>> node.hardware_status.filesystem
        HardwareCollection(File Systems, items: 5)
        >>> for stats in node.hardware_status.filesystem:
        ...   stats
        ...
        Status(label=u'Root', param=u'Partition Size', status=-1, sub_system=u'File Systems',
               value=u'600 MB')
        Status(label=u'Data', param=u'Usage', status=-1, sub_system=u'File Systems',
               value=u'6.3%')
        Status(label=u'Data', param=u'Size', status=-1, sub_system=u'File Systems',
               value=u'1937 MB')
        Status(label=u'Spool', param=u'Usage', status=-1, sub_system=u'File Systems',
               value=u'4.9%')
        Status(label=u'Spool', param=u'Size', status=-1, sub_system=u'File Systems',
               value=u'9729 MB')
        Status(label=u'Tmp', param=u'Usage', status=-1, sub_system=u'File Systems',
               value=u'0.0%')
        Status(label=u'Tmp', param=u'Size', status=-1, sub_system=u'File Systems',
               value=u'3941 MB')
        Status(label=u'Swap', param=u'Usage', status=-1, sub_system=u'File Systems',
               value=u'0.0%')
        Status(label=u'Swap', param=u'Size', status=-1, sub_system=u'File Systems',
               value=u'1887 MB')

        Since SMC-API >= v6.7
        ('OK', Status(label='Swap', param='Size', sub_system='File Systems', value='494 MB'))
        ('WARNING', Status(label='Tmp', param='Usage', sub_system='File Systems', value='96.7%'))
        ('WARNING', Status(label='Tmp', param='Size', sub_system='File Systems', value='997 MB'))

        >>> for stats in node.hardware_status.sandbox_subsystem:
        ...   stats
        ...
        ('WARNING', Status(label='Cloud connection', param='status', sub_system='Sandbox',
                           value='1'))

    """

    def __init__66(self, status):
        data = status.get("hardware_statuses")
        super(HardwareStatus, self).__init__(data, label_6_6)

    def __init__67(self, status):
        data = status.get("hardware_statuses")
        super(HardwareStatus, self).__init__(data, label_6_7)

    def __init__(cls, *args, **kwargs):
        versioned_method = get_best_version(("6.6", cls.__init__66), ("6.7", cls.__init__67))
        versioned_method(*args, **kwargs)

    def __repr__(self):
        items = [item.name for item in self]
        return "%s(%s)" % (self.__class__.__name__, ",".join(items))

    @property
    def logging_subsystem(cls, *args, **kwargs):
        """
        A collection of logging subsystem statuses

        :rtype: Status
        """
        versioned_method = get_best_version(
            ("6.6", cls._logging_subsystem_6_6), ("6.7", cls._logging_subsystem_6_7)
        )
        return versioned_method(*args, **kwargs)

    def _logging_subsystem_6_6(self):
        for item in self:
            if item.name.startswith("Logging"):
                for s in item_status_6_6(item):
                    yield s

    def _logging_subsystem_6_7(self):
        for item in self:
            if item.name.startswith("Logging"):
                for s in item_status_6_7(item):
                    yield s

    @property
    def sandbox_subsystem(cls, *args, **kwargs):
        """
        A collection of sandbox subsystem statuses

        :rtype: Status
        """
        versioned_method = get_best_version(
            ("6.6", cls._sandbox_subsystem_6_6), ("6.7", cls._sandbox_subsystem_6_7)
        )
        return versioned_method(*args, **kwargs)

    def _sandbox_subsystem_6_6(self):
        for item in self:
            if item.name.startswith("Sandbox"):
                for s in item_status_6_6(item):
                    yield s

    def _sandbox_subsystem_6_7(self):
        for item in self:
            if item.name.startswith("Sandbox"):
                for s in item_status_6_7(item):
                    yield s

    @property
    def filesystem(cls, *args, **kwargs):
        """
        A collection of filesystem related statuses

        :rtype: Status
        """
        versioned_method = get_best_version(
            ("6.6", cls._filesystem_6_6), ("6.7", cls._filesystem_6_7)
        )
        return versioned_method(*args, **kwargs)

    def _filesystem_6_6(self):
        for item in self:
            if item.name.startswith("File System"):
                for s in item_status_6_6(item):
                    yield s

    def _filesystem_6_7(self):
        for item in self:
            if item.name.startswith("File System"):
                for s in item_status_6_7(item):
                    yield s


class Debug(object):
    """
    Debug settings that can be enabled on the engine. To view available
    options, print the repr of this object. All diagnostic values can
    be set as an attribute of this class instance. Set the values to
    either True or False and submit this object back to the node to
    change settings. Setting changes are in effect immediately and
    does not require a policy push.
    Example usage::

        >>> node = engine.nodes[0]
        >>> node
        Node(name=ngf-1065)
        >>> debug = node.debug()
        >>> debug
        Debug(access_guardian=False, accounting=False, anti_malware=False, authentication=False,
            blacklisting=False, browser_based_user_authentication=False, cluster_daemon=False,
            cluster_protocol=False, connection_tracking=False, data_synchronization=False,
            dhcp_client=False, dhcp_relay=False, dhcp_service=False, dns_resolution=False,
            dynamic_routing=False, endpoint_integration=False, file_reputation=False,
            inspection=False, invalid=False, ipsec_vpn=False, licensing=False,
            load_balancing_filter=False, log_server=False, logging_system=False, management=False,
            mcafee_logon_collector=False, monitoring=False, multicast_routing=False, nat=False,
            netlink_incoming_ha=False, packet_filtering=False, protocol_agent=False,
            radius_forwarder=False, sandbox=False, server_pool_load_balancing=False, snmp=False,
            ssl_vpn=False, ssl_vpn_portal=False, ssl_vpn_session_manager=False,
            state_synchronisation=False, syslog=False, system_utilities=False, tester=False,
            user_agent=False, wireless_access_point=False)
            >>> debug.management=True
            >>> debug.sandbox=True
            >>> node.set_debug(debug)
    """

    _attr_map = {}

    def __init__(self, diag):
        for diagnostic in diag:
            setting = diagnostic.get("diagnostic")
            name = setting.get("name")
            escaped_key = name.replace(" ", "_").replace("-", "_").lower()
            setattr(self, escaped_key, setting.get("enabled"))
            self._attr_map[escaped_key] = name

    def __setattr__(self, key, value):
        if not isinstance(value, bool):
            raise ValueError("Attributes can only be True or False.")
        super(Debug, self).__setattr__(key, value)

    def serialize(self):
        debug = [{"enabled": v, "name": self._attr_map.get(k)} for k, v in self.__dict__.items()]
        return {"diagnostics": [{"diagnostic": item} for item in debug]}

    def __repr__(self):
        keys = sorted(self.__dict__)
        items = ("{}={!r}".format(k, self.__dict__[k]) for k in keys)
        return "{}({})".format(type(self).__name__, ", ".join(items))


class MasterNode(Node):
    """
    This represents an individual Master NGFW Engine node in the Security Management Client,
    representing a device that runs firewall software as part of a Master NGFW Engine.
    """

    typeof = "master_node"
