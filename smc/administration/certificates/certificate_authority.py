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
Module representing certificate authority in SMC
"""

from smc.administration.tasks import TaskOperationPoller
from smc.api.exceptions import TaskRunFailed
from smc.base.model import SubElement, Element
from smc.base.util import save_to_file
from smc.api.exceptions import CertificateExportError


class CertificateAuthority(Element):
    """
    this class represents a Certificate Authority in SMC
    """

    typeof = 'certificate_authority'

    @property
    def certificate_state(self):
        """
        represents the state of the certificate authority.
        :rtype: str
        """
        return self.data.get("certificate_state")

    def un_trust(self):
        task = self.make_request(
            TaskRunFailed, method="update", resource="untrust"
        )
        return TaskOperationPoller(
            task=task, wait_for_finish=True
        )

    def export_certificate(self, filename=None):
        """
        Export the certificate for the given Certificate Authority.
        :raises CertificateExportError: error exporting certificate
        :rtype: str
        """
        result = self.make_request(
            CertificateExportError, raw_result=True, resource="certificate"
        )

        if filename is not None:
            save_to_file(filename, result.content)
            return

        return result.content

    def duplicate(self, name):
        raise NotImplementedError(f"This method is not supported for {self.__class__.__name__}")

    def export(self, name):
        raise NotImplementedError(f"This method is not supported for {self.__class__.__name__}")

    def add_category(self, name):
        raise NotImplementedError(f"This method is not supported for {self.__class__.__name__}")

    def categories(self, name):
        raise NotImplementedError(f"This method is not supported for {self.__class__.__name__}")

    def rename(self, name):
        raise NotImplementedError(f"This method is not supported for {self.__class__.__name__}")
