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


from smc.base.model import SubElement
from smc.base.util import save_to_file
from smc.api.exceptions import CertificateExportError


class CertificateAuthority(SubElement):
    """
    this class represents a Certificate Authority in SMC
    """

    typeof = 'certificate_authority'

    def __init__(self, **kwargs):
        super(SubElement, self).__init__(**kwargs)

    @property
    def name(self):
        """
        represents the name of the certificate authority.
        :rtype: str
        """
        return self.get("name")

    @property
    def certificate_state(self):
        """
        represents the state of the certificate authority.
        :rtype: str
        """
        return self.get("certificate_state")

    def un_trust(self):
        self.make_request(resource="untrust")

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
