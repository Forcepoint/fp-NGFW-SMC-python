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
VPN Certificates are used by NGFW to identify the engines for VPN clients
and other VPN related connections. Each gateway certificate is signed by
a VPN CA and uses the default internal CA by default.
"""
from smc.base.model import Element, ElementCreator, SubElement, ElementRef
from smc.administration.certificates.tls_common import ImportExportCertificate
from smc.api.exceptions import CertificateError, SMCOperationFailure, CertificateImportError
from smc.base.util import element_resolver


class VPNCertificateCA(ImportExportCertificate, Element):
    """
    A VPN CA certificate is used to within VPN Profiles to validate
    site-to-site or client VPN connections. By default SMC will use
    an internal CA. Use this method to create your own CA as a trusted
    endpoint CA.

    :ivar str certificate: base64 encoded certificate for this CA
    :ivar bool crl_checking_enabled: whether CRL checking is turned on
    :ivar bool internal_ca: is this an internal CA (default: false)
    :ivar bool oscp_checking_enabled: is OSCP validation enabled
    """

    typeof = "vpn_certificate_authority"

    @classmethod
    def create(cls, name, certificate):
        """
        Create a new external VPN CA for signing internal gateway
        certificates.

        :param str name: Name of VPN CA
        :param str certificate: file name, path or certificate string.
        :raises CreateElementFailed: Failed creating cert with reason
        :rtype: VPNCertificateCA
        """
        json = {"name": name, "certificate": certificate}

        return ElementCreator(cls, json)


class GatewayCertificate(SubElement):
    """
    A Gateway Certificate repesents a certificate assigned to a
    NGFW certificate used for VPN endpoints. Gateway certificates
    are typically renewed automatically when the auto renew option
    is set on the engine. However you can also optionally force
    renew a gateway certificate, export, check the expiration, or
    find the certificate authority that signed this gateway certificate.

    :ivar certificate_authority: CA for this GatewayCertificate
    """

    typeof = "gateway_certificate"
    certificate_authority = ElementRef("certificate_authority")

    @staticmethod
    def _create(
            self,
            common_name,
            organization,
            public_key_algorithm="rsa",
            signature_algorithm="rsa_sha_512",
            key_length=2048,
            signing_ca=None,
    ):
        """
        Internal method called as a reference from the engine.vpn
        node
        """

        if signing_ca is None:
            signing_ca = VPNCertificateCA.objects.filter("Internal RSA").first()
        json = {
            "common_name": common_name,
            "organization": organization,
            "public_key_algorithm": public_key_algorithm,
            "signature_algorithm": signature_algorithm,
            "public_key_length": key_length,
        }
        if signing_ca != "external":
            cert_auth = element_resolver(signing_ca)
            json.update(certificate_authority_href=cert_auth)
        return ElementCreator(
            GatewayCertificate,
            exception=CertificateError,
            href=self.internal_gateway.get_relation("generate_certificate"),
            json=json
        )

    @staticmethod
    def _create_from_cert(
            self,
            certificate,
            signing_ca=None,
    ):
        """
        Internal method called as a reference from the engine.vpn
        node using certificate directly
        """
        if signing_ca is None:
            signing_ca = VPNCertificateCA.objects.filter("Internal RSA").first()

        cert_auth = element_resolver(signing_ca)

        return ElementCreator(
            GatewayCertificate,
            exception=CertificateError,
            href=self.internal_gateway.get_relation("generate_certificate"),
            json={
                "certificate": certificate,
                "certificate_authority_href": cert_auth,
            },
        )

    @property
    def valid_from(self):
        """
        The date of gateway certificate valid from.
        :return: Date of valid from gateway certificate
        :rtype: str
        """
        return self.data.valid_from

    @property
    def certificate(self):
        return self.certificate_base64

    def renew(self):
        """
        Call renew link from gateway certificate
        :return: message, detail, status or nothing
        :rtype: str
        """
        return self.make_request(SMCOperationFailure, resource="renew")

    @property
    def public_key_algorithm(self):
        """
        The Public Key Algorithm.Can be one of the following:
        * dsa
        * rsa
        * ecdsa
        :return: name of public key algorithm
        :rtype: str
        """
        return self.data.public_key_algorithm

    @property
    def signature_algorithm(self):
        """
        The Signature Algorithm.Can be one of the following:
        * dsa_sha_1
        * dsa_sha_224
        * dsa_rsa_256
        * rsa_md5
        * rsa_sha_1
        * rsa_sha_256
        * rsa_sha_384
        * rsa_sha_512
        * ecdsa_sha_1
        * ecdsa_sha_256
        * ecdsa_sha_384
        * ecdsa_sha_512
        :return: name of signature algorithm
        :rtype: str
        """
        return self.data.signature_algorithm

    @property
    def subject_alt_name(self):
        """
        Subject alt name
        :return: list of subject_alt_name
        :rtype: list(subject_alt_name)
        """
        return self.data.subject_alt_name

    @property
    def expiration(self):
        """
        Gateway certificate expiration date
        :return: certificate expiration date
        :rtype: str
        """
        return self.expiration_date

    def export_certificate(self, filename=None):
        export_result = ImportExportCertificate.export_certificate(self, filename)
        return export_result


class GatewayCertificateRequest(SubElement):
    """
    A Gateway Certificate Request repesents a certificate that need to be signed
    either by internal certificate authority or external certificate authority.

    :ivar certificate_authority: CA for this GatewayCertificate
    """

    typeof = "gateway_certificate_request"

    @property
    def comment(self):
        return self.data.comment

    @property
    def key_length(self):
        return self.data.key_length

    @property
    def request(self):
        return self.certificate_base64

    @property
    def signature_algorithm(self):
        """
        The Signature Algorithm.Can be one of the following:
        * dsa_sha_1
        * dsa_sha_224
        * dsa_rsa_256
        * rsa_md5
        * rsa_sha_1
        * rsa_sha_256
        * rsa_sha_384
        * rsa_sha_512
        * ecdsa_sha_1
        * ecdsa_sha_256
        * ecdsa_sha_384
        * ecdsa_sha_512
        :return: name of signature algorithm
        :rtype: str
        """
        return self.data.signature_algorithm

    @property
    def public_key_algorithm(self):
        """
        The Public Key Algorithm.Can be one of the following:
        * dsa
        * rsa
        * ecdsa
        :return: name of public key algorithm
        :rtype: str
        """
        return self.data.public_key_algorithm

    def export_certificate_request(self, filename=None):
        export_result = ImportExportCertificate.export_certificate(self, filename)
        return export_result

    def import_certificate_request(self, certificate):
        self.make_request(
            CertificateImportError,
            method="create",
            resource="certificate_import",
            json={
                "certificate": certificate
            }
        )

    def self_sign(self):
        """
        Self sign the certificate in 'request' state.
        :raises ActionCommandFailed: failed to sign with reason
        """
        return self.make_request(method="create", resource="self_sign")
