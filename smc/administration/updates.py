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
Functionality related to updating dynamic update packages and
engine upgrades
"""
from smc.base.model import SubElement
from smc.administration.tasks import Task


class PackageMixin(object):
    """
    Manages downloads and activations of update packages and software
    upgrades
    """

    def download(self, timeout=5, wait_for_finish=False):
        """
        Download Package or Engine Update

        :param int timeout: timeout between queries
        :raises TaskRunFailed: failure during task status
        :rtype: TaskOperationPoller
        """
        return Task.execute(self, "download", timeout=timeout, wait_for_finish=wait_for_finish)

    def activate(self, resource=None, force_upgrade=False, timeout=3, wait_for_finish=False):
        """
        Activate this package on the SMC

        :param list resource: node href's to activate on. Resource is only
               required for software upgrades
        :param query parameter 'force_upgrade' flag to know if we need to force
               the upgrade (for instance trusted certificate has expired)
        :param int timeout: timeout between queries
        :raises TaskRunFailed: failure during activation (downloading, etc)
        :rtype: TaskOperationPoller
        """
        return Task.execute(
            self,
            "activate",
            params={"force_upgrade": force_upgrade},
            json={"resource": resource},
            timeout=timeout,
            wait_for_finish=wait_for_finish,
        )

    @property
    def release_notes(self):
        """
        HTTP location of the release notes
        """
        return self.data.get("release_notes")


class EngineUpgrade(PackageMixin, SubElement):
    """
    Engine Upgrade package management

    For example, to check engine upgrades and find a specific
    one, then download for installation::

        system = System()
        upgrades = system.engine_upgrade()
        package = upgrades.get_contains('6.2')

        poller = package.download(wait_for_finish=True)
        while not poller.done():
            print(poller.result(3))
        print("Finished download: %s" % poller.result())
        package.activate()

    """

    @property
    def release_date(self):
        """
        Release date for this engine upgrade
        """
        return self.data.get("release_date")

    @property
    def version(self):
        """
        Engine upgrade version
        """
        return self.data.get("version")

    @property
    def platform(self):
        """
        Platform for this engine upgrade
        """
        return self.data.get("platform")


class UpdatePackage(PackageMixin, SubElement):
    """
    Container for managing update packages on SMC

    Download and activate a package::

        system = System()
        packages = system.update_package()
        dynup = packages.get_contains('1007')

        poller = dynup.download(wait_for_finish=True)
        while not poller.done():
            print(poller.result(3))
        print("Finished download: %s" % poller.result())
        package.activate()

    """

    typeof = "update_package"

    @property
    def activation_date(self):
        """
        Date this update was activated, if any

        :rtype: str
        """
        return self.data.get("activation_date")

    @property
    def package_id(self):
        """
        ID of the package. These will increment as new versions
        are released.

        :rtype: str
        """
        return self.data.get("package_id")

    @property
    def release_date(self):
        """
        Date of release

        :rtype: str
        """
        return self.data.get("release_date")

    @property
    def state(self):
        """
        State of this package as string. Valid states are available, imported, active.
        If the package is available, you can execute a download. If the package is
        imported, you can activate.

        :rtype: str
        """
        return self.data.get("state")
