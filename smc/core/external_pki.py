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
External PKI functionality for components having a certificate like Mgt server
 or log server or engine node.
To commit the change on certificate settings, you must call .update() on the component.
The subject_alt_name cannot be changed after certificate has been generated once.

The certificate info is read only.

For example, update revocation check in certificate settings:

    log_server.pki_certificate_settings().ignore_revocation_on_failure = True
    log_server.update()

    node.pki_certificate_info()

"""
from smc.base.structs import NestedDict
from smc.compat import is_smc_version_less_than


class PkiCertificateSettings(NestedDict):
    """
    Represents the settings of a component for generating a certificate
    request in case of external PKI installation.
    """

    def __init__(self, component):
        settings = component.data["external_pki_certificate_settings"]
        super(PkiCertificateSettings, self).__init__(data=settings)

    @classmethod
    def create(cls, subject_name, subject_alt_name):
        """
        Create a new definition of certificate settings
        :param subject_name
        :param subject_alt_name:
        """
        cls.data = {"external_pki_certificate_settings": {
            "certificate_type": "ecdsa_sha_512",
            "subject_name": subject_name,
            "subject_alt_name": subject_alt_name}
                    }
        return cls

    @property
    def certificate_type(self):
        """
        represents the type of certificate.

        :rtype: str ecdsa_sha_384,ecdsa_sha_512
        """
        return self.get("certificate_type")

    @certificate_type.setter
    def certificate_type(self, value):
        if not is_smc_version_less_than("6.10"):
            self.update(certificate_type=value)

    @property
    def check_revocation(self):
        """
        indicates if revocation should be checked.
        :rtype: bool
        """
        return self.get("check_revocation")

    @check_revocation.setter
    def check_revocation(self, value):
        if not is_smc_version_less_than("6.10"):
            self.update(check_revocation=value)

    @property
    def ignore_revocation_on_failure(self):
        """
        indicates if revocation should be ignored in case of failure.
        :rtype: bool
        """
        return self.get("ignore_revocation_on_failure")

    @ignore_revocation_on_failure.setter
    def ignore_revocation_on_failure(self, value):
        if not is_smc_version_less_than("6.10"):
            self.update(ignore_revocation_on_failure=value)

    @property
    def subject_name(self):
        """
        indicates if revocation should be ignored in case of failure.
        :rtype: str
        """
        return self.get("subject_name")

    @subject_name.setter
    def subject_name(self, value):
        if not is_smc_version_less_than("6.10"):
            self.update(subject_name=value)

    @property
    def subject_alt_name(self):
        """
        indicates if revocation should be ignored in case of failure.
        :rtype: str
        """
        return self.get("subject_alt_name")

    @subject_alt_name.setter
    def subject_alt_name(self, value):
        if not is_smc_version_less_than("6.10"):
            self.update(subject_alt_name=value)


class PkiCertificateInfo(NestedDict):
    """
    Represents the certificate for the current a component.
    This is available only in case of external PKI installation.
    """

    def __init__(self, data=None, **meta):
        super(PkiCertificateInfo, self).__init__(data, **meta)

    @property
    def certificate_authority(self):
        """
        represents the name of the certificate authority used to sign this
        certificate.
        :rtype: str
        """
        return self.get("certificate_authority")

    @property
    def certificate(self):
        """
        represents the Certificate as clear text.
        :rtype: str
        """
        return self.get("certificate")

    @property
    def valid_from(self):
        """
        indicates the Certificate validity start date
        :rtype: str
        """
        return self.get("valid_from")

    @property
    def expiration_date(self):
        """
        indicates the Certificate expiration date
        :rtype: str
        """
        return self.get("expiration_date")

    @property
    def subject_name(self):
        """
        return the set of X509GeneralName representing the certificate subject name
        :rtype: str
        """
        return self.get("subject_name")

    @property
    def subject_alt_name(self):
        """
        return the set of X509GeneralName representing the certificate subject alt name
        :rtype: str
        """
        return self.get("subject_alt_name")

    @property
    def signature_algorithm(self):
        """
        return the signature algorithm
        :rtype: str
        """
        return self.get("signature_algorithm")
