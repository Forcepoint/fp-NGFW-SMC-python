"""
Module that controls aspects of the System itself, such as updating dynamic
packages, updating engines, applying global block lists, etc.

To load the configuration for system, do::

    >>> from smc.administration.system import System
    >>> system = System()
    >>> system.smc_version
    '6.2.0 [10318]'
    >>> system.last_activated_package
    '881'
    >>> for pkg in system.update_package():
    ...   print(pkg)
    ...
    UpdatePackage(name=Update Package 889)
    UpdatePackage(name=Update Package 888)
    UpdatePackage(name=Update Package 887)

"""
import time
import logging

from smc.administration.upcoming_event import UpcomingEvents, UpcomingEventsPolicy, \
    UpcomingEventIgnoreSettings
from smc.compat import is_api_version_less_than_or_equal, is_api_version_less_than, \
    is_smc_version_less_than
from smc.elements.other import prepare_blacklist, prepare_block_list
from smc.administration.system_properties import SystemProperty
from smc.elements.other import prepare_blacklist
from smc.base.model import SubElement, Element, ElementCreator
from smc.administration.updates import EngineUpgrade, UpdatePackage
from smc.administration.license import Licenses
from smc.administration.tasks import Task
from smc.base.util import millis_to_utc, extract_self
from smc.base.collection import sub_collection
from smc.api.common import fetch_entry_point
from smc.api.exceptions import ResourceNotFound, ActionCommandFailed

logger = logging.getLogger(__name__)


class System(SubElement):
    """
    System level operations such as SMC version, time, update packages,
    and updating engines
    """

    def __init__(self):
        entry = fetch_entry_point("system")
        super(System, self).__init__(href=entry)

    @property
    def smc_version(self):
        """
        Return the SMC version
        """
        return self.make_request(resource="smc_version").get("value")

    @property
    def smc_time(self):
        """
        Return the SMC time as datetime object in UTC

        :rtype datetime
        """
        return millis_to_utc(int(self.make_request(resource="smc_time").get("value")))

    @property
    def massive_license_bind(self):
        """
        Bind licenses on all unlicensed nodes

        """
        return self.make_request(method="create", resource="massive_license_bind").get("value")

    @property
    def last_activated_package(self):
        """
        Return the last activated package by id

        :raises ActionCommandFailed: failure to retrieve resource
        """
        return self.make_request(resource="last_activated_package").get("value")

    def empty_trash_bin(self):
        """
        Empty system level trash bin

        :raises ActionCommandFailed: failed removing trash
        :return: None
        """
        self.make_request(method="delete", resource="empty_trash_bin")

    def update_package(self):
        """
        Show all update packages on SMC.

        To find specific updates available from the returned
        collection, use convenience methods::

            system = System()
            updates = system.update_package()
            updates.get_contains('1027')

        :raises ActionCommandFailed: failure to retrieve resource
        :rtype: SubElementCollection(UpdatePackage)
        """
        return sub_collection(self.get_relation("update_package"), UpdatePackage)

    def update_package_import(self, import_update_package_file):
        """
        Import update package into SMC. Specify the fully qualified path
        to the update package file.

        :param str import_update_package_file: system level path to update package file
        :return: list imported UpdatePackage
        """
        update_packages_elements = []
        with open(import_update_package_file, "rb") as file:
            update_packages = self.make_request(
                               method="create",
                               resource="import_package",
                               files={"package_file": file},
                               raw_result=True
                               )

            logger.info("import update package task succeeded")
            for update in update_packages.json:
                href = extract_self(update.get("link"))
                update_package = UpdatePackage(href=href,
                                               name=update.get("name"),
                                               type="update_package")
                update_packages_elements.append(update_package)

        return update_packages_elements

    def engine_upgrade_import(self, import_engine_upgrade_file, force_import=False):
        """
        Import upgrade package into SMC. Specify the fully qualified path
        to the upgrade package file.

        :param str import_engine_upgrade_file: system level path to upgrade package file
        :param boolean force_import: force import when certificate that signed
        the zip file has expired.
        :return: list imported EngineUpgrade
        """
        engine_upgrade_element = []
        with open(import_engine_upgrade_file, "rb") as file:
            engine_upgrades = self.make_request(
                method="create",
                resource="import_upgrade",
                files={"upgrade_file": file},
                raw_result=True,
                params={'force_import': force_import}
            )
            logger.info("import engine upgrade task succeeded, engine_upgrade_file : {}"
                        .format(import_engine_upgrade_file))
            # check smc version and process api response with compatible version
            if is_smc_version_less_than("7.0"):
                for upgrade in engine_upgrades.json:
                    href = extract_self(engine_upgrades.json[upgrade]["link"])
                    engine_upgrade = EngineUpgrade(href=href,
                                                   name=engine_upgrades.json[upgrade]["name"],
                                                   type="engine_upgrade")
                    engine_upgrade_element.append(engine_upgrade)
            else:
                for upgrade in engine_upgrades.json:
                    href = extract_self(upgrade["link"])
                    engine_upgrade = EngineUpgrade(href=href,
                                                   name=upgrade["name"],
                                                   type="engine_upgrade")
                    engine_upgrade_element.append(engine_upgrade)
        return engine_upgrade_element

    def engine_upgrade(self):
        """
        List all engine upgrade packages available

        To find specific upgrades available from the returned
        collection, use convenience methods::

            system = System()
            upgrades = system.engine_upgrade()
            upgrades.get_contains('6.2')
            upgrades.get_all_contains('6.2')

        :param engine_version: Version of engine to retrieve
        :raises ActionCommandFailed: failure to retrieve resource
        :rtype: SubElementCollection(EngineUpgrade)
        """
        return sub_collection(self.get_relation("engine_upgrade"), EngineUpgrade)

    def system_properties(self):
        """
        List all global system properties available.

        To find specific system property available from the returned
        collection, use convenience methods:

            system = System()
            system_properties = system.system_properties()
            system_properties.get_contains('enable_pci')

        :rtype: SubElementCollection(SystemProperty)
        """
        return sub_collection(self.get_relation('system_properties'), SystemProperty)

    def system_property(self, system_key):
        """
        Retrieve the global system property from its system key (unique id).
        Otherwise BaseException.

            system = System()
            system_property = system.system_property(system_key=8)

        :rtype: SystemProperty
        """
        return Element.from_href(self.get_relation('system_properties')+'/{}'.format(system_key))

    def update_system_property(self, system_key, new_value):
        """
        Update the global system property from its system key (unique id)
        with the specified value (str).
        If the system property does not exist a BaseException is thrown.

            system = System()
            system.update_system_property(system_key=8, value="0")
        """
        return self.system_property(system_key=system_key).update(value=new_value)

    def uncommitted(self):
        pass

    def clean_invalid_filters(self):
        pass

    def block_list(self, src, dst, duration=3600, **kw):
        """
        Add block_list to all defined engines.
        Use the cidr netmask at the end of src and dst, such as:
        1.1.1.1/32, etc.

        :param src: source of the entry
        :param dst: destination of block list entry
        :raises ActionCommandFailed: block list apply failed with reason
        :return: None

        .. seealso:: :class:`smc.core.engine.Engine.block_list`. Applying
            a blacklist at the system level will be a global blacklist entry
            versus an engine specific entry.

        .. note:: If more advanced blacklist is required using source/destination
            ports and protocols (udp/tcp), use kw to provide these arguments. See
            :py:func:`smc.elements.other.prepare_blacklist` for more details.

        .. note:: This method requires SMC version >= 7.0
        """
        json = {"entries": [prepare_block_list(src, dst, duration, **kw)]}
        self.make_request(
            method="create", resource="block_list", json=json
        )

    def blacklist(self, src, dst, duration=3600, **kw):
        """
        Add blacklist to all defined engines.
        Use the cidr netmask at the end of src and dst, such as:
        1.1.1.1/32, etc.

        :param src: source of the entry
        :param dst: destination of blacklist entry
        :raises ActionCommandFailed: blacklist apply failed with reason
        :return: None

        .. seealso:: :class:`smc.core.engine.Engine.blacklist`. Applying
            a blacklist at the system level will be a global blacklist entry
            versus an engine specific entry.

        .. note:: If more advanced blacklist is required using source/destination
            ports and protocols (udp/tcp), use kw to provide these arguments. See
            :py:func:`smc.elements.other.prepare_blacklist` for more details.

        .. note:: This method requires SMC version < 7.0
        since this version, "blacklist" is renamed "block_list"
        """
        if is_api_version_less_than("7.0"):
            resource = "blacklist"
            json = {"entries": [prepare_blacklist(src, dst, duration, **kw)]}
        else:
            resource = "block_list"
            json = {"entries": [prepare_block_list(src, dst, duration, **kw)]}

        self.make_request(
                method="create",
                resource=resource,
                json=json
            )

    @property
    def licenses(self):
        """
        List of all engine related licenses
        This will provide details related to whether the license is bound,
        granted date, expiration date, etc.
        ::

            >>> for license in system.licenses:
            ...    if license.bound_to.startswith('Management'):
            ...        print(license.proof_of_license)
            abcd-efgh-ijkl-mnop

        :raises ActionCommandFailed: failure to retrieve resource
        :rtype: list(Licenses)
        """
        return Licenses(self.make_request(resource="licenses"))

    def license_fetch(self, proof_of_serial):
        """
        Request a license download for the specified POS (proof of serial).

        :param str proof_of_serial: proof of serial number of license to fetch
        :raises ActionCommandFailed: failure to retrieve resource
        """
        return self.make_request(
            resource="license_fetch", params={"proofofserial": proof_of_serial}
        )

    def license_install(self, license_file):
        """
        Install a new license.

        :param str license_file: fully qualified path to the
            license jar file.
        :raises: ActionCommandFailed
        :return: None
        """
        self.make_request(
            method="update",
            resource="license_install",
            files={"license_file": open(license_file, "rb")},
        )

    def license_details(self):
        """
        This represents the license details for the SMC. This will include
        information with regards to the POL/POS, features, type, etc

        :raises ActionCommandFailed: failure to retrieve resource
        :return: dictionary of key/values
        """
        return self.make_request(resource="license_details")

    def license_check_for_new(self):
        """
        Launch the check and download of licenses on the Management Server.
        This task can be long so call returns immediately.

        :raises ActionCommandFailed: failure to retrieve resource
        """
        return self.make_request(resource="license_check_for_new")

    def delete_license(self):
        raise NotImplementedError

    # @ReservedAssignment
    def visible_virtual_engine_mapping(self, filter=None):
        """
        Mappings for master engines and virtual engines

        :param str filter: filter to search by engine name
        :raises ActionCommandFailed: failure to retrieve resource
        :return: list of dict items related to master engines and virtual
            engine mappings
        """
        return self.make_request(
            resource="visible_virtual_engine_mapping", params={"filter": filter}
        )

    # @ReservedAssignment
    def visible_security_group_mapping(self, filter=None):
        """
        Return all security groups assigned to VSS container types. This
        is only available on SMC >= 6.5.

        :param str filter: filter for searching by name
        :raises ActionCommandFailed: element not found on this version of SMC
        :raises ResourceNotFound: unsupported method on SMC < 6.5
        :return: dict
        """
        if "visible_security_group_mapping" not in self.data.links:
            raise ResourceNotFound("This entry point is only supported on SMC >= 6.5")

        return self.make_request(
            resource="visible_security_group_mapping", params={"filter": filter}
        )

    def references_by_element(self, element_href):
        """
        Return all references to element specified.

        :param str element_href: element reference
        :return: list of references where element is used
        :rtype: list(dict)
        """
        result = self.make_request(
            method="create", resource="references_by_element", json={"value": element_href}
        )
        return result

    def export_elements(
            self,
            filename="export_elements.zip",
            typeof="all",
            timeout=5,
            max_tries=36,
            exclude_trashed=None
    ):
        """
        Export elements from SMC.

        Valid types are:
        all (All Elements)|nw (Network Elements)|ips (IPS Elements)|
        sv (Services)|rb (Security Policies)|al (Alerts)|
        vpn (VPN Elements)

        :param type: type of element
        :param filename: Name of file for export
        :raises TaskRunFailed: failure during export with reason
        :rtype: DownloadTask
        """
        valid_types = ["all", "nw", "ips", "sv", "rb", "al", "vpn"]
        if typeof not in valid_types:
            typeof = "all"

        return Task.download(
            self,
            "export_elements",
            filename,
            timeout=timeout,
            max_tries=max_tries,
            params={"recursive": True, "type": typeof, "exclude_trashed": exclude_trashed},
        )

    def active_alerts_ack_all(self):
        """
        Acknowledge all active alerts in the SMC. Only valid for
        SMC version >= 6.2.

        :raises ActionCommandFailed: Failure during acknowledge with reason
        :return: None
        """
        self.make_request(method="delete", resource="active_alerts_ack_all")

    def import_elements(self, import_file):
        """
        Import elements into SMC. Specify the fully qualified path
        to the import file.

        :param str import_file: system level path to file
        :raises: ActionCommandFailed
        :return: None
        """
        import_follower = Task(
            self.make_request(
                method="create",
                resource="import_elements",
                files={"import_file": open(import_file, "rb")}
            )
        )
        in_progress = import_follower.data.in_progress
        progress = import_follower.progress
        while in_progress is True:
            time.sleep(1)
            logger.info("XML import task progress: {}%".format(progress))
            in_progress = import_follower.update_status().data.in_progress
            progress = import_follower.update_status().progress
            succeed = import_follower.update_status().success
            last_message = import_follower.update_status().last_message

        if not succeed:
            logger.error("XML Import task failed: {}".format(last_message))
            raise ActionCommandFailed(last_message)

        logger.info("XML import task succeeded")

    def force_unlock(self, element):
        return self.make_request(
            method="create", resource="force_unlock", json={"value": element.href}
        )

    def unlicensed_components(self):
        raise NotImplementedError

    @property
    def mgt_integration_configuration(self):
        """
        Retrieve the management API configuration for 3rd party integration
        devices.

        :raises ActionCommandFailed: failure to retrieve resource
        """
        return self.make_request(resource="mgt_integration_configuration")

    def upcoming_event(self):
        """
        Allows to retrieve the upcoming events.

        :return: UpcomingEvents
        """
        return UpcomingEvents(self.make_request(resource="upcoming_event"))

    def upcoming_event_policy(self):
        """
        Allows to retrieve the upcoming events.

        :return: UpcomingEventPolicy
        """
        return UpcomingEventsPolicy(self.make_request(resource="upcoming_event_policy"))

    def update_upcoming_event_policy(self, upcoming_event_policy):
        """
        Allows to change the upcoming event policy.
        As a note, only super users are able to perform such operation.

        :param upcoming_event_policy: UpcomingEventsPolicy to update
        :return None
        """
        self.make_request(
            method="update",
            resource="upcoming_event_policy",
            json=self.create_upcoming_event_policy_payload(upcoming_event_policy))

    @staticmethod
    def create_upcoming_event_policy_payload(upcoming_event_policy):
        json = {"entries": []}
        entries = []
        for entry in upcoming_event_policy.upcoming_event_policy:
            entries.append(entry.data)
        json.update(entries=entries)
        return json

    def upcoming_event_ignore_settings(self):
        """
        Allows to retrieve the upcoming event ignore settings.

        :return: UpcomingEventIgnoreSettings
        """
        return UpcomingEventIgnoreSettings(
            self.make_request(resource="upcoming_event_ignore_settings"))

    def update_upcoming_event_ignore_settings(self, situations_to_ignore):
        """
        Allows to change the upcoming event ignore settings for the current administrator.
        As a note, all upcoming events linked to the situation will be filtered.

        :param list situations_to_ignore: list of Situations to ignore
        :return None
        """
        self.make_request(
            method="update",
            resource="upcoming_event_ignore_settings",
            json=self.create_upcoming_event_ignore_settings_payload(situations_to_ignore))

    @staticmethod
    def create_upcoming_event_ignore_settings_payload(situations_to_ignore):
        json = {"entries": []}
        entries = []
        for situation in situations_to_ignore:
            entries.append(situation.href)
        json.update(entries=entries)
        return json


class AdminDomain(Element):
    """
    Administrative domain element. Domains are used to provide object
    based segmentation within SMC. If domains are in use, you can
    log in directly to a domain to modify contents within that domain.

    Find all available domains::

        >>> list(AdminDomain.objects.all())
        [AdminDomain(name=Shared Domain)]

    .. note:: Admin Domains require and SMC license.
    """

    typeof = "admin_domain"

    @classmethod
    def create(cls, name, comment=None):
        """
        Create a new Admin Domain element for SMC objects.

        Example::

            >>> AdminDomain.create(name='mydomain', comment='mycomment')
            >>> AdminDomain(name=mydomain)

        :param str name: name of domain
        :param str comment: optional comment
        :raises CreateElementFailed: failed creating element with reason
        :return: instance with meta
        :rtype: AdminDomain
        """
        json = {"name": name, "comment": comment}

        return ElementCreator(cls, json)
