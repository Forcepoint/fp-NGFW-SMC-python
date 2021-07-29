"""
Module that controls aspects of the System itself, such as updating dynamic
packages, updating engines, applying global blacklists, etc.

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
from datetime import datetime
from smc.elements.other import prepare_blacklist
from smc.base.model import SubElement, Element, ElementCreator
from smc.administration.updates import EngineUpgrade, UpdatePackage
from smc.administration.license import Licenses
from smc.administration.tasks import Task
from smc.base.util import millis_to_utc
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

    def update_package_import(self):
        pass

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

    def uncommitted(self):
        pass

    def system_properties(self):
        """
        List of all properties applied to the SMC

        :raises ActionCommandFailed: failure to retrieve resource
        """
        return self.make_request(resource="system_properties")

    def clean_invalid_filters(self):
        pass

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
        """
        self.make_request(
            method="create", resource="blacklist", json=prepare_blacklist(src, dst, duration, **kw)
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
                files={"import_file": open(import_file, "rb")},
            )
        )
        in_progress = import_follower.data.in_progress
        progress = import_follower.progress
        while in_progress is True:
            time.sleep(1)
            logger.info(
                "[{}] XML Import task => {}%".format(
                    "{:%H:%M:%S.%f}".format(datetime.now())[:-3], progress
                )
            )
            in_progress = import_follower.update_status().data.in_progress
            progress = import_follower.update_status().progress
            succeed = import_follower.update_status().success
            last_message = import_follower.update_status().last_message

        if not succeed:
            logger.info(
                "[{}] XML Import task failed:{}".format(
                    "{:%H:%M:%S.%f}".format(datetime.now())[:-3], last_message
                )
            )
            raise ActionCommandFailed(last_message)

        logger.info(
            "[{}] XML Import task succeed".format("{:%H:%M:%S.%f}".format(datetime.now())[:-3])
        )

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
