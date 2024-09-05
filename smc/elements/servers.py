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
Module that represents server based configurations
"""
from smc.api.common import SMCRequest, _get_session
from smc.api.exceptions import CreateElementFailed, SMCOperationFailure, CertificateImportError, \
    CertificateExportError, CertificateError, UnsupportedEngineFeature, UnsupportedAttribute
from smc.base.decorators import deprecated
from smc.base.model import SubElement, ElementCreator, Element, ElementRef
from smc.base.structs import NestedDict
from smc.compat import is_smc_version_less_than, is_smc_version_less_than_or_equal, \
    is_api_version_less_than_or_equal, is_smc_version_equal
from smc.elements.common import MultiContactServer, NodeElement, IPv6Node
from smc.elements.helpers import location_helper
from smc.elements.other import ContactAddress, Location
from smc.base.util import element_resolver, save_to_file
from smc.administration.certificates import tls
from smc.administration.certificates.tls_common import pem_as_string
from smc.core.external_pki import PkiCertificateSettings, PkiCertificateInfo


class MultiContactAddress(SubElement):
    """
    A MultiContactAddress is a location and contact address pair which
    can have multiple addresses. Server elements such as Management
    and Log Server can have configured locations with multiple addresses
    per location.

    Use this server reference to create, add or remove contact addresses
    from servers::

        mgt_server = ManagementServer.objects.first()
        mgt_server.contact_addresses.update_or_create(
            location='mylocation', addresses=['1.1.1.1', '1.1.1.2'])

    Or remove by location::

        mgt_server.contact_addresses.delete('mylocation')

    """

    @property
    def _cas(self):
        return self.data.get("multi_contact_addresses", []) or self.data.get(
            "contact_addresses", []
        )

    def __iter__(self):
        for address in self._cas:
            yield ContactAddress(**address)

    def __contains__(self, location_href):
        for location in self._cas:
            if location.get("location_ref") == location_href:
                return True
        return False

    def get(self, location_name):
        """
        Get a contact address by location name

        :param str location_name: name of location
        :return: return contact address element or None
        :rtype: ContactAddress
        """
        location_ref = location_helper(location_name, search_only=True)
        if location_ref:
            for location in self:
                if location.location_ref == location_ref:
                    return location

    def delete(self, location_name):
        """
        Remove a given location by location name. This operation is
        performed only if the given location is valid, and if so,
        `update` is called automatically.

        :param str location: location name or location ref
        :raises UpdateElementFailed: failed to update element with reason
        :rtype: bool
        """
        updated = False
        location_ref = location_helper(location_name, search_only=True)
        if location_ref in self:
            self._cas[:] = [loc for loc in self if loc.location_ref != location_ref]
            self.update()
            updated = True
        return updated

    def update_or_create(
            self, location, contact_addresses, with_status=False, overwrite_existing=False, **kw
    ):
        """
        Update or create a contact address and location pair. If the
        location does not exist it will be automatically created. If the
        server already has a location assigned with the same name, the
        contact address specified will be added if it doesn't already
        exist (Management and Log Server can have multiple address for a
        single location).

        :param list(str) contact_addresses: list of contact addresses for
            the specified location
        :param str location: location to place the contact address in
        :param bool overwrite_existing: if you want to replace existing
            location to address mappings set this to True. Otherwise if
            the location exists, only new addresses are appended
        :param bool with_status: if set to True, a 3-tuple is returned with
            (Element, modified, created), where the second and third tuple
            items are booleans indicating the status
        :raises UpdateElementFailed: failed to update element with reason
        :rtype: MultiContactAddress
        """
        updated, created = False, False
        location_ref = location_helper(location)
        if location_ref in self:
            for loc in self:
                if loc.location_ref == location_ref:
                    if overwrite_existing:
                        loc["addresses"][:] = contact_addresses
                        updated = True
                    else:
                        for ca in contact_addresses:
                            if ca not in loc.addresses:
                                loc["addresses"].append(ca)
                                updated = True
        else:
            self.data.setdefault("multi_contact_addresses", []).append(
                dict(addresses=contact_addresses, location_ref=location_ref)
            )
            created = True

        if updated or created:
            self.update()
        if with_status:
            return self, updated, created
        return self


class ContactAddressMixin(object):
    """
    Mixin class to provide an interface to contact addresses on the
    management and log server.
    Contact addresses on servers can contain multiple IP's for a single
    location.
    """

    @property
    def contact_addresses(self):
        """
        Provides a reference to contact addresses used by this server.

        Obtain a reference to manipulate or iterate existing contact
        addresses::

            >>> from smc.elements.servers import ManagementServer
            >>> mgt_server = ManagementServer.objects.first()
            >>> for contact_address in mgt_server.contact_addresses:
            ...   contact_address
            ...
            ContactAddress(location=Default,addresses=[u'1.1.1.1'])
            ContactAddress(location=foolocation,addresses=[u'12.12.12.12'])

        :rtype: MultiContactAddress
        """
        return MultiContactAddress(
            href=self.get_relation("contact_addresses"), type=self.typeof, name=self.name
        )

    def add_contact_address(self, contact_address, location):
        """
        Add a contact address to the Log Server::

            server = LogServer('LogServer 172.18.1.25')
            server.add_contact_address('44.44.44.4', 'ARmoteLocation')

        :param str contact_address: IP address used as contact address
        :param str location: Name of location to use, will be created if
               it doesn't exist
        :raises ModificationFailed: failed adding contact address
        :return: None
        """
        return self.contact_addresses.update_or_create(location, [contact_address])

    def remove_contact_address(self, location):
        """
        Remove contact address by name of location. You can obtain all contact
        addresses by calling :func:`contact_addresses`.

        :param str location: str name of location, will be created if it
            doesn't exist
        :raises ModificationFailed: failed removing contact address
        :return: None
        """
        return self.contact_addresses.delete(location)


class WebApp(NestedDict):
    """
    Represents a Web Application parameter.
    """

    def __init__(self, data):
        super(WebApp, self).__init__(data=data)

    @classmethod
    def create(cls,
               enabled=False,
               eca_enabled=False,
               listening_address=None,
               log_access=False,
               port=8083,
               server_credentials_ref=None,
               session_timeout=300,
               ssl_session_id=False,
               tls_cipher_suites=None,
               standalone_enabled=False,
               web_app_identifier=None,
               host_name=None,
               ):
        """
        :param bool enabled: If the Web Application is enabled or not.
        :param bool eca_enabled: Indicates if ECA Rollout evaluation is enabled in SMC Download
            pages (SMC Downloads has to be enabled )
        :param str listening_address: The Web Application listening address, null if listening on
            all addresses.
        :param bool log_access: Indicates whether access to this Web Application are logged.
        :param int port: The port on which the Web Application listens for connections.
        :param TLSServerCredential server_credentials_ref: TLS Credentials of server.
        :param int session_timeout: Session Timeout for Webswing.
        :param bool ssl_session_id: Indicates whether session ID must be used with SSL.
        :param TLSCryptographySuite tls_cipher_suites: TLS Cipher suite.
        :param bool standalone_enabled: Indicates if Standalone client bundles download are enabled
            in SMC Download pages (SMC Downloads has to be enabled )
        :param str web_app_identifier: The Web Application Identifier.
        :param str host_name: The Web Application host name, null if none.
        """
        web_app_data = {
            "enabled": enabled,
            "host_name": host_name,
            "listening_address": listening_address,
            "log_access": log_access,
            "port": port,
            "server_credentials_ref": element_resolver(server_credentials_ref),
            "session_timeout": session_timeout,
            "ssl_session_id": ssl_session_id,
            "tls_cipher_suites": element_resolver(tls_cipher_suites),
            "eca_enabled": eca_enabled,
            "standalone_enabled": standalone_enabled,
            "web_app_identifier": web_app_identifier
        }
        return cls(web_app_data)

    @property
    def enabled(self):
        return self.data.get("enabled")

    @property
    def host_name(self):
        return self.data.get("host_name")

    @property
    def listening_address(self):
        return self.data.get("listening_address")

    @property
    def log_access(self):
        return self.data.get("log_access")

    @property
    def port(self):
        return self.data.get("port")

    @property
    def server_credentials_ref(self):
        return Element.from_href(self.data.get("server_credentials_ref"))

    @property
    def session_timeout(self):
        return self.data.get("session_timeout")

    @property
    def tls_cipher_suites(self):
        return Element.from_href(self.data.get("tls_cipher_suites"))

    @property
    def eca_enabled(self):
        return self.data.get("eca_enabled")

    @property
    def standalone_enabled(self):
        return self.data.get("standalone_enabled")

    @property
    def web_app_identifier(self):
        return self.data.get("web_app_identifier")


class TlsSettings(NestedDict):

    def __init__(self, data):
        super(TlsSettings, self).__init__(data=data)

    @classmethod
    def create(cls, use_internal_credentials=None, tls_credentials=None):
        """
        TLS credentials used for Elasticsearch/Log Forwarding If useInternalCredentials is set to
        FALSE, this attribute will be read. If this field is set to null, no authentication will
        be requested.
        :param bool use_internal_credentials: Indicate if we need to use the server's internal TLS
            credentials for Elasticsearch/Log Forwarding TRUE if we want to use internal credentials
            FALSE if we want to use the tlsServerCredentials attribute.
        :param TLSServerCredential tls_credentials: TLS credentials used for Elasticsearch/Log
            Forwarding If useInternalCredentials is set to FALSE, this attribute will be read.
            If this field is set to null, no authentication will be requested.
        """
        data = {
            "use_internal_credentials": use_internal_credentials,
            "tls_credentials": element_resolver(tls_credentials)
        }
        return cls(data)

    @property
    def use_internal_credentials(self):
        return self.data.get("use_internal_credentials")

    @property
    def tls_credentials(self):
        return Element.from_href(self.data.get("tls_credentials"))


class ExternalPki:

    def pki_certificate_settings(self):
        """
        Get the certificate info of this component when working with External PKI.

        :rtype: PkiCertificateSettings
        """
        if "external_pki_certificate_settings" in self.data:
            return PkiCertificateSettings(self)
        raise UnsupportedEngineFeature(
            "External PKI certificate settings are only supported when using "
            "external PKI installation mode."
        )

    def pki_export_certificate_request(self, filename=None):
        """
        Export the certificate request for the component when working with an External PKI.
        This can return None if the component does not have a certificate request.

        :raises CertificateExportError: error exporting certificate
        :rtype: str or None
        """
        result = self.make_request(
            CertificateExportError, raw_result=True, resource="pki_export_certificate_request"
        )

        if filename is not None:
            save_to_file(filename, result.content)
            return

        return result.content

    def pki_import_certificate(self, certificate):
        """
        Import a valid certificate. Certificate can be either a file path
        or a string of the certificate. If string certificate, it must include
        the -----BEGIN CERTIFICATE----- string.

        :param str certificate: fully qualified path or string
        :raises CertificateImportError: failure to import cert with reason
        :raises IOError: file not found, permissions, etc.
        :return: None
        """
        self.make_request(
            CertificateImportError,
            method="create",
            resource="pki_import_certificate",
            headers={"content-type": "multipart/form-data"},
            files={
                # decode certificate or use it as it is
                "signed_certificate": open(certificate, "rb")
                if not pem_as_string(certificate)
                else certificate
            },
        )

    def pki_renew_certificate(self):
        """
        Start renewal process on component when using external PKI mode.
        It generates new private key and prepare a new certificate request.
        """
        self.make_request(
            CertificateError,
            method="update",
            resource="pki_start_certificate_renewal",
        )

    def pki_certificate_info(self):
        """
        Get the certificate info of this component when working with External PKI.
        This can return None if the component does not directly have a certificate.

        :rtype: PkiCertificateInfo
        """
        result = self.make_request(
            CertificateError, resource="pki_certificate_info"
        )
        return PkiCertificateInfo(result)

    def pki_delete_certificate_request(self):
        """
        Delete the certificate request if any is defined for this component.
        """
        self.make_request(method="delete",
                          resource="pki_delete_certificate_request")

    @property
    def external_pki_certificate_settings(self):
        """
        Get the certificate info of this component when working with External PKI.
        :rtype: PkiCertificateSettings
        """
        return PkiCertificateSettings(self)


class ManagementLogServerMixin(MultiContactServer, ExternalPki):

    @property
    def log_disk_space_handling_mode(self):
        """
        Mode chosen to handle extra logs when disk runs out of space.
        :rtype: str
        """
        return self.data.get("log_disk_space_handling_mode")

    @property
    @deprecated("elasticsearch_authentication_settings")
    def es_tls_settings(self):
        """
        Elasticsearch TLS Settings.
        :rtype: TlsSettings
        """
        return _ElasticsearchCompatibility.es_tls_settings_property(
            self.data,
            "elasticsearch_authentication_settings")

    @property
    def elasticsearch_authentication_settings(self):
        """
        Elasticsearch authentication settings.
        """
        return _ElasticsearchCompatibility.authentication_settings_property(
            self.data,
            "elasticsearch_authentication_settings",
            None)

    @property
    def forwarding_tls_settings(self):
        """
        Log Forwarding TLS Settings.
        :rtype: TlsSettings
        """
        return TlsSettings(self.data.get("forwarding_tls_settings"))

    @property
    def netflow_collector(self):
        """
        A collection of NetflowCollector

        :rtype: list(NetflowCollector)DomainController
        """
        return [NetflowCollector(**nc) for nc in self.data.get("netflow_collector", [])]

    def add_netflow_collector(self, netflow_collectors):
        """
        Add netflow collector/s to this log server.

        :param netflow_collectors: netflow_collector/s to add to log server
        :type netflow_collectors: list(netflow_collectors)
        :raises UpdateElementFailed: failed updating log server
        :return: None
        """
        if "netflow_collector" not in self.data:
            self.data["netflow_collector"] = {"netflow_collector": []}

        for p in netflow_collectors:
            self.data["netflow_collector"].append(p.data)
        self.update()

    def remove_netflow_collector(self, netflow_collector):
        """
        Remove a netflow collector from this log server.

        :param NetflowCollector netflow_collector: element to remove
        :return: remove element if it exists and return bool
        :rtype: bool
        """
        _netflow_collector = []
        changed = False
        for nf in self.netflow_collector:
            if nf != netflow_collector:
                _netflow_collector.append(nf.data)
            else:
                changed = True

        if changed:
            self.data["netflow_collector"] = _netflow_collector
            self.update()

        return changed

    @property
    def uiid(self):
        """
        Installation ID (aka UUID).
        :rtype: str
        """
        return self.data.get("uiid")

    @property
    def announcement_message(self):
        return self.data.get("announcement_message")


class ManagementServer(ContactAddressMixin, Element, ManagementLogServerMixin):
    """
    Management Server configuration. Most configuration settings are better set
    through the SMC, such as HA, however this object can be used to do simple
    tasks such as add a contact addresses to the Management Server when a security
    engine needs to communicate over NAT.

    It's easiest to get the management server reference through a collection::

        >>> ManagementServer.objects.first()
        ManagementServer(name=Management Server)
    """

    typeof = "mgt_server"

    @classmethod
    def create(
            cls,
            name,
            address=None,
            ipv6_address=None,
            alert_server=None,
            location_ref=None,
            web_app=None,
            announcement_enabled=False,
            announcement_message=None,
            external_pki_certificate_settings=None,
            uiid=None,
            tools_profile_ref=None,
            secondary=None,
            updates_check_enabled=False,
            license_update_enabled=False,
            updates_proxy_enabled=False,
            updates_proxy_address=None,
            updates_proxy_port=82,
            updates_proxy_authentication_enabled=False,
            updates_proxy_username=None,
            updates_proxy_password=None,
            db_replication=False,
            tls_profile=None,
            tls_credentials=None,
            es_tls_settings=None,
            elasticsearch_authentication_settings=None,
            forwarding_tls_settings=None,
            netflow_collector=None,
            mgt_integration_container=None,
            smtp_server_ref=None,
            sender_address=None,
            sender_name=None,
            snmp_gateways=None,
            script_path=None,
            sms_http_channel=None,
            sms_smtp_channel=None,
            sms_script_channel=None,
            radius_method="eap-md5",
            tacacs_method="mschap",
            comment=None
    ):
        """
        This represents a Management Server. A system component that stores all information about
        the configurations of all NGFW Engines,and other components in the Stonesoft Management
        Center, monitors their state, and provides access for Management Clients when administrators
        want to change the configurations or command the engines. The most important component in
        the system.
        :param str name: Name of the Management Server.
        :param str address: Single valid IPv4 address. Required.
        :param str ipv6_address: IPv6 address.
        :param LogServer alert_server: Specify the Log Server to which you want the Management
            Server to send its logs. Required.
        :param Location location_ref: Location of the server.
        :param list(WebApp) web_app: Mgt Server can be configured to define several Web Applications
            like webclient, webswing.
        :param bool announcement_enabled: Is announcement enabled for Mgt Server:Announcements
            in the Mgt Server element are shown for all users that connect to that Mgt Server.
            Not Required.
        :param str announcement_message: The announcement message for Mgt Server.
        :param PkiCertificateSettings external_pki_certificate_settings: Certificate Settings for
            External PKI mode.
        :param str uiid: Mgt Server Installation ID (aka UUID).
        :param tools_profile tools_profile_ref: Allows you to add commands to the element’s
            right-click menu.
        :param list(str) secondary: If the device has additional IP addresses, you can enter them
            here instead of creating additional elements for the other IP addresses. The secondary
            IP addresses are valid in policies and in routing and antispoofing. You can add several
            IPv4 and IPv6 addresses (one by one)
        :param bool updates_check_enabled: Are you notified of new dynamic updates?
        :param bool license_update_enabled: Select Generate and Install New Licenses Automatically
            to automatically regenerate and install the licenses required for upgrading system
            components to a major new release.
        :param bool updates_proxy_enabled: If the connection from the Management Server to the
            Internet servers requires a proxy server, select Use Proxy Server for HTTPS Connection.
        :param updates_proxy_address: If the connection from the Management Server to the Internet
            servers requires a proxy server, select an FQDN as proxy address.
        :param int updates_proxy_port: If the connection from the Management Server to the Internet
            servers requires a proxy server, select a port as proxy port.
        :param bool updates_proxy_authentication_enabled: If the connection from the Management
            Server to the Internet servers requires a proxy server with authentication.
        :param str updates_proxy_username: If the connection from the Management Server to the
            Internet servers requires a proxy server with authentication, select an users's name.
        :param str updates_proxy_password: If the connection from the Management Server to the
            Internet servers requires a proxy server with authentication, select an users's password
        :param bool db_replication: Disable automatic database replication.
        :param TLSProfile tls_profile: Select the TLS Profile to be used for admin login with Client
            Certificate authentication.
        :param TLSServerCredential tls_credentials: Select the Credentials to be used for admin
            login with Client Certificate authentication.
        :param TlsSettings es_tls_settings: Elasticsearch TLS Settings. Not null when we decide to
            override the ES Tls Settings in the Log Server or Management Server.
        :param dict elasticsearch_authentication_settings: if we want to override defined
               authentication setting of Elasticsearch Server (> 7.1)
               dict : method: None, basic, api_key, certificate
                      api_key : api_key
                      certificate : es_tls_settings aside
                      basic : login, password
        :param TlsSettings forwarding_tls_settings: Log Forwarding TLS Settings. Should be NULL if
            no Log Forwarding has been defined for this Log Server. Not required
        :param list(NetflowCollector) netflow_collector: Log Servers can be configured to forward
            log data to external hosts. You can define which type of log data you want to forward
            and in which format. You can also use Filters to specify in detail which log data is
            forwarded.
        :param list mgt_integration_container: Mgt Server can be configured to define several
            Management Integration instances.
        :param SmtpServer smtp_server_ref: The SMTP Server used for sending emails.
        :param str sender_address: The sender email address.
        :param str sender_name: The sender name.
        :param str snmp_gateways: The SNMP gateway.
        :param str script_path: The custom alert script path.
        :param list sms_http_channel: The SMS HTTP channels.
        :param list sms_smtp_channel: The SMS SMTP channels.
        :param list sms_script_channel: The SMS Script channels.
        :param str radius_method: Radius Method used in authentication when using Radius Server for
            authenticating administrators. One of the following values:
            "pap","chap", "mschap", "mschap2", "eap-md5" Default is eap-md5.
        :param str tacacs_method:Tacacs Method used in authentication when using Tacas Server for
            authenticating administrators.One of the following values: "ascii","pap","chap","mschap"
            Default is mschap.
        :param str comment: optional comment.
        """

        web_app = web_app if web_app else []
        netflow_collector = netflow_collector if netflow_collector else []
        json = {
            "name": name,
            "address": address,
            "ipv6_address": ipv6_address,
            "alert_server_ref": element_resolver(alert_server),
            "location_ref": element_resolver(location_ref),
            "secondary": secondary if secondary else [],
            "uiid": uiid,
            "tools_profile_ref": element_resolver(tools_profile_ref),
            "web_app": [app.data for app in web_app],
            "updates_check_enabled": updates_check_enabled,
            "license_update_enabled": license_update_enabled,
            "updates_proxy_enabled": updates_proxy_enabled,
            "updates_proxy_address": updates_proxy_address,
            "updates_proxy_port": updates_proxy_port,
            "updates_proxy_authentication_enabled": updates_proxy_authentication_enabled,
            "updates_proxy_username": updates_proxy_username,
            "updates_proxy_password": updates_proxy_password,
            "db_replication": db_replication,
            "tls_profile": element_resolver(tls_profile),
            "tls_credentials": element_resolver(tls_credentials),
            "netflow_collector": [netflow.data for netflow in netflow_collector],
            "mgt_integration_container": mgt_integration_container,
            "smtp_server_ref": element_resolver(smtp_server_ref),
            "sender_address": sender_address,
            "sender_name": sender_name,
            "snmp_gateways": snmp_gateways,
            "script_path": script_path,
            "sms_http_channel": sms_http_channel if sms_http_channel else [],
            "sms_smtp_channel": sms_smtp_channel if sms_smtp_channel else [],
            "sms_script_channel": sms_script_channel if sms_script_channel else [],
            "radius_method": radius_method,
            "tacacs_method": tacacs_method,
            "announcement_enabled": announcement_enabled,
            "announcement_message": announcement_message,
            "comment": comment
        }
        if forwarding_tls_settings:
            json.update(forwarding_tls_settings=forwarding_tls_settings)
        if external_pki_certificate_settings:
            json.update(external_pki_certificate_settings=external_pki_certificate_settings.data)
        _ElasticsearchCompatibility.create_helper(json,
                                                  "elasticsearch_authentication_settings",
                                                  es_tls_settings,
                                                  elasticsearch_authentication_settings)
        return ElementCreator(cls, json)

    def update(self, *exception, **kwargs):
        super().update(*exception,
                       **_ElasticsearchCompatibility.update_helper(
                           "elasticsearch_authentication_settings",
                           **kwargs))

    @property
    def alert_server_ref(self):
        """
        Specify the Log Server to which you want the Mgt Server to send its logs
        :rtype: LogServer
        """
        return Element.from_href(self.data.get("alert_server_ref"))

    @property
    def web_app(self):
        """
        Represents a Web Application parameter.
        :rtype: list(WebApp):
        """
        return [WebApp(data) for data in self.data.get("web_app")]

    @property
    def updates_check_enabled(self):
        """
        Are you notified of new dynamic updates?
        :rtype: bool
        """
        return self.data.get("updates_check_enabled")

    @property
    def license_update_enabled(self):
        """
        Select Generate and Install New Licenses Automatically to automatically regenerate and
            install the licenses required for upgrading system components to a major new release.
        :rtype: bool
        """
        return self.data.get("license_update_enabled")

    @property
    def updates_proxy_enabled(self):
        """
        If the connection from the Management Server to the Internet servers requires a proxy server
            , select Use Proxy Server for HTTPS Connection.
        :rtype: bool
        """
        return self.data.get("updates_proxy_enabled")

    @property
    def updates_proxy_address(self):
        """
        FQDN as proxy address
        :rtype: str
        """
        return self.data.get("updates_proxy_address")

    @property
    def updates_proxy_port(self):
        """
        Proxy server port.
        :rtype: int
        """
        return self.data.get("updates_proxy_port")

    @property
    def updates_proxy_authentication_enabled(self):
        """
        If the connection from the Management Server to the Internet servers requires a proxy server
            with authentication.
        :rtype: bool
        """
        return self.data.get("updates_proxy_authentication_enabled")

    @property
    def updates_proxy_username(self):
        """
        Proxy server authentication username.
        :rtype: str
        """
        return self.data.get("updates_proxy_username")

    @property
    def updates_proxy_password(self):
        """
        Proxy server authentication password.
        :rtype: str
        """
        return self.data.get("updates_proxy_password")

    @property
    def db_replication(self):
        """
        Disable automatic database replication?
        :rtype: bool
        """
        return self.data.get("db_replication")

    @property
    def tls_profile(self):
        """
        TLS Profile to be used for admin login with Client Certificate authentication.
        :rtype: TLSProfile.
        """
        return Element.from_href(self.data.get("tls_profile"))

    @property
    def tls_credentials(self):
        """
        Credentials to be used for admin login with Client Certificate authentication.
        :rtype: TLSServerCredential
        """
        return Element.from_href(self.data.get("tls_credentials"))

    @property
    def mgt_integration_container(self):
        """
        Several Management Integration instances.
        :rtype: list
        """
        return self.data.get("mgt_integration_container")

    @property
    def smtp_server_ref(self):
        """
        The SMTP Server used for sending emails.
        :rtype: SmtpServer
        """
        return Element.from_href(self.data.get("smtp_server_ref"))

    @property
    def sender_address(self):
        """
        The sender email address.
        :rtype: str
        """
        return self.data.get("sender_address")

    @property
    def sender_name(self):
        """
        The sender name.
        :rtype: str
        """
        return self.data.get("sender_name")

    @property
    def snmp_gateways(self):
        """
        The SNMP gateway.
        :rtype: str
        """
        return self.data.get("snmp_gateways")

    @property
    def script_path(self):
        """
        The custom alert script path.
        :rtype: str
        """
        return self.data.get("script_path")

    @property
    def sms_http_channel(self):
        """
        The SMS HTTP channels.
        :rtype: list
        """
        return self.data.get("sms_http_channel")

    @property
    def sms_smtp_channel(self):
        """
        The SMS SMTP channels.
        :rtype: list
        """
        return self.data.get("sms_smtp_channel")

    @property
    def sms_script_channel(self):
        """
        The SMS Script channels.
        :rtype: list
        """
        return self.data.get("sms_script_channel")

    def restart_web_access(self):
        """
        Restart Web Access on Mgt Server.
        :raises SMCOperationFailure: failed to restart SMC Web Access
        :return: None
        """
        if not is_smc_version_less_than("7.1.0") and not is_api_version_less_than_or_equal("7.0"):
            return self.make_request(
                SMCOperationFailure,
                method="update",
                resource="restart_web_access"
            )


class DataContext(Element):
    """
    This represents the Data Context.
    """

    typeof = "data_context"

    @property
    def info_data_tag(self):
        return self.data.get("info_data_tag")


class NetflowCollector(NestedDict):
    """
    Represents a Netflow collector.
    This is a sub part of Log Server entity.
    Log Servers can be configured to forward log data to external hosts. You can define which type
    of log data you want to forward and in which format. You can also use Filters to specify in
    detail which log data is forwarded.
    """

    def __init__(
            self,
            data_context,
            host,
            netflow_collector_port,
            netflow_collector_service,
            netflow_collector_version,
            filter=None,
            tls_profile=None,
            tlsIdentity=None,
            kafka_topic=None,
    ):
        dc = dict(
            data_context=element_resolver(data_context),
            filter=element_resolver(filter),
            host=element_resolver(host),
            netflow_collector_port=netflow_collector_port,
            netflow_collector_service=netflow_collector_service,
            netflow_collector_version=netflow_collector_version,
            tls_profile=tls_profile,
            tlsIdentity=tlsIdentity,
            kafkaTopic=kafka_topic
        )
        super(NetflowCollector, self).__init__(data=dc)

    def __str__(self):
        str = ""
        str += f"data_context = {self.data_context}; "
        str += f"filter = {self.filter}; "
        str += f"host = {self.host}; "
        str += f"netflow_collector_port = {self.netflow_collector_port}; "
        str += f"netflow_collector_service = {self.netflow_collector_service}; "
        str += f"netflow_collector_version = {self.netflow_collector_version}; "
        str += f"kafkaTopic = {self.kafkaTopic};"

        return str

    @property
    def data_context(self):
        """
        The type of log data that is forwarded.
        :rtype: DataContext
        """
        return (
            Element.from_href(self.get("data_context"))
            if self.get("data_context") is not None
            else None
        )

    @property
    def filter(self):
        """
        An optional local filter that defines which log data is forwarded. The
        local filter is only applied to the log data that matches the Log
        Forwarding rule.
        :rtype: FilterExpression
        """
        return Element.from_href(self.get("filter")) if self.get("filter") is not None else None

    @property
    def host(self):
        """
        The Host element that represents the target host to which the log
        data is forwarded.
        :rtype: Host
        """
        return Element.from_href(self.get("host")) if self.get("host") is not None else None

    @property
    def netflow_collector_port(self):
        """
        The Port that is used for log forwarding. The default port used by
        IPFIX/NetFlow data collectors is 2055.<br/>
        <b>Note!</b> If you have to define an Access rule that allows traffic to the
        target host, make sure that the Port you select is also used as the
        Port in the Access rule.
        :rtype: int
        """
        return self.data["netflow_collector_port"]

    @property
    def netflow_collector_service(self):
        """
        The network protocol for forwarding the log data (udp/tcp/tcp_with_tls).<br/>
        <b>Note!</b> If you have to define an Access rule that allows traffic to the
        target host, make sure that the Service you specify is also used as
        the Service in the Access rule.
        :rtype: str
        """
        return self.data["netflow_collector_service"]

    @property
    def netflow_collector_version(self):
        """
        The format for forwarding the log data:
        <ul>
        <li><i>cef</i>: Logs are forwarded in CEF format.</li>
        <li><i>csv</i>: Logs are forwarded in CSV format.</li>
        <li><i>leef</i>: Logs are forwarded in LEEF format.</li>
        <li><i>netflow_v11</i>: Logs are forwarded in NetFlow format.
                                The supported version is NetFlow v16.</li>
        <li><i>ipfix</i>: Logs are forwarded in IPFIX (NetFlow v16) format.</li>
        <li><i>xml</i>: Logs are forwarded in XML format.</li>
        <li><i>esm</i>: Logs are forwarded in McAfee ESM format.</li>
        </ul>
        <b> Only csv, xml and esm are supported for Audit Forwarding from Mgt Server</b>
        :rtype: str
        """
        return self.data["netflow_collector_version"]

    @property
    def tls_profile(self):
        """
        TLS information required to establish TLS connection to SysLog servers
        *Mandatory* when service is "tcp_with_tls"
        :rtype: TlSProfile
        """
        return Element.from_href(self.get("tls_profile")) \
            if self.get("tls_profile") is not None else None

    @property
    def tlsIdentity(self):
        """
        Field/value pair used to insure server identity when connecting to Sys Log server using TLS
        *Optional* If not provided, server identity is not checked
        This is ignored if service is not tcp_with_tls

        :rtype:
        """
        return self.data["tlsIdentity"]

    @property
    def kafka_topic(self):
        """
        Kafka Topic: used only in the case forwarding logs through KAFKA.
        :rtype str
        """
        return self.data["kafkaTopic"]


class DataContext(Element):
    """
    This represents the Data Context.
    """
    typeof = "data_context"

    @property
    def info_data_tag(self):
        return self.data.get("info_data_tag")


class LogServer(ContactAddressMixin, Element, ManagementLogServerMixin):
    """
    Log Server elements are used to receive log data from the security engines
    Most settings on Log Server generally do not need to be changed, however it
    may be useful to set a contact address location and IP mapping if the Log Server
    needs to be reachable from an engine across NAT

     It's easiest to get the log server reference through a collection::

        >>> LogServer.objects.first()
        LogServer(name=LogServer 172.18.1.150)
    """

    typeof = "log_server"

    @classmethod
    def create(
            cls,
            name,
            address=None,
            ipv6_address=None,
            location_ref=None,
            external_pki_certificate_settings=None,
            uiid="N/A",
            tools_profile_ref=None,
            secondary=None,
            es_tls_settings=None,
            elasticsearch_authentication_settings=None,
            forwarding_tls_settings=None,
            netflow_collector=None,
            log_disk_space_handling_mode=None,
            backup_log_server=None,
            channel_port=3020,
            inactive=False,
            comment=None
    ):
        """
        Log Server elements are used to receive log data from the security engines Most settings on
        Log Server generally do not need to be changed, however it may be useful to set a contact
        address location and IP mapping if the Log Server needs to be reachable from an engine
        across NAT
        :param str name: Name of the Log Server.
        :param str address: Single valid IPv4 address. Required.
        :param str ipv6_address: IPv6 address.
        :param Location location_ref: Location of the server.
        :param PkiCertificateSettings external_pki_certificate_settings: Certificate Settings for
            External PKI mode.
        :param str uiid: Mgt Server Installation ID (aka UUID).
        :param tools_profile tools_profile_ref: Allows you to add commands to the element’s
            right-click menu.
        :param list(str) secondary: If the device has additional IP addresses, you can enter them
            here instead of creating additional elements for the other IP addresses. The secondary
            IP addresses are valid in policies and in routing and antispoofing. You can add several
            IPv4 and IPv6 addresses (one by one)
        :param TlsSettings es_tls_settings: Elasticsearch TLS Settings. Not null when we decide to
            override the ES Tls Settings in the Log Server or Management Server.
        :param dict elasticsearch_authentication_settings: if we want to override defined
               authentication setting of Elasticsearch Server (> 7.1)
               dict : method: None, basic, api_key, certificate
                      api_key : api_key
                      certificate : es_tls_settings aside
                      basic : login, password
        :param TlsSettings forwarding_tls_settings: Log Forwarding TLS Settings. Should be NULL if
            no Log Forwarding has been defined for this Log Server. Not required
        :param list(NetflowCollector) netflow_collector: Log Servers can be configured to forward
            log data to external hosts. You can define which type of log data you want to forward
            and in which format. You can also use Filters to specify in detail which log data is
            forwarded.
        :param str log_disk_space_handling_mode: Mode chosen to handle extra logs when disk runs out
            of space.
        :param list(LogServer) backup_log_server: You can specify several backup Log Servers. The
            same Log Server can simultaneously be the main Log Server for some components and a
            backup Log Server for components that primarily use another Log Server. You can also set
            Log Servers to be backup Log Servers for each other so that whenever one goes down, the
            other Log Server is used. If Domain elements have been configured, a Log Server and its
            backup Log Server(s) must belong to the same Domain.
            Caution: If the log volumes are very high, make sure that the backup Log Server can
            handle the traffic load in fail-over situations.
        :param int channel_port: Log Server's TCP Port Number. We recommend using default port 3020
            if possible. To use a non-standard port, manually add Access rules to allow
            communications using the new port from the NGFW Engines to the Log Server.
        :param bool inactive: Is excluded from Log Browsing, Reporting and Statistics.
        :param str comment: optional comment.
        """

        netflow_collector = netflow_collector if netflow_collector else []
        backup_log_server = backup_log_server if backup_log_server else []
        json = {
            "name": name,
            "address": address,
            "ipv6_address": ipv6_address,
            "location_ref": element_resolver(location_ref),
            "secondary": secondary if secondary else [],
            "uiid": uiid,
            "tools_profile_ref": element_resolver(tools_profile_ref),
            "netflow_collector": [netflow.data for netflow in netflow_collector],
            "log_disk_space_handling_mode": log_disk_space_handling_mode,
            "backup_log_server": element_resolver(backup_log_server),
            "channel_port": channel_port,
            "inactive": inactive,
            "comment": comment
        }
        if forwarding_tls_settings:
            json.update(forwarding_tls_settings=forwarding_tls_settings)
        if external_pki_certificate_settings:
            json.update(external_pki_certificate_settings=external_pki_certificate_settings.data)
        _ElasticsearchCompatibility.create_helper(json,
                                                  "elasticsearch_authentication_settings",
                                                  es_tls_settings,
                                                  elasticsearch_authentication_settings)
        return ElementCreator(cls, json)

    def update(self, *exception, **kwargs):
        super().update(*exception,
                       **_ElasticsearchCompatibility.update_helper(
                           "elasticsearch_authentication_settings",
                           **kwargs))

    @property
    def backup_log_server(self):
        """
        Several backup Log Servers.
        :rtype list(LogServer)
        """
        return [Element.from_href(server) for server in self.data.get("backup_log_server", [])]

    @property
    def channel_port(self):
        """
        Log Server's TCP Port Number.
        :rtype int
        """
        return self.data.get("channel_port")

    @property
    def inactive(self):
        """
        Is excluded from Log Browsing, Reporting and Statistics.
        :rtype bool
        """
        return self.data.get("inactive")


class HttpProxy(Element, NodeElement):
    """
    An HTTP Proxy based element. Used in various areas of the configuration
    such as engine properties to define proxies for File Reputation, etc.

    """

    typeof = "http_proxy"

    @classmethod
    def create(
            cls,
            name,
            address,
            proxy_port=8080,
            username=None,
            password=None,
            secondary=None,
            third_party_monitoring=None,
            tools_profile_ref=None,
            comment=None,
    ):
        """
        Create a new HTTP Proxy service. Proxy must define at least
        one primary address but can optionally also define a list
        of secondary addresses.

        :param str name: Name of the proxy element
        :param str address: Primary address for proxy
        :param int proxy_port: proxy port (default: 8080)
        :param str username: optional username for authentication (default: None)
        :param str password: password for username if defined (default: None)
        :param list secondary: secondary list of proxy server addresses
        :param ThirdPartyMonitoring third_party_monitoring: The optional Third Party Monitoring
            configuration.
        :param DeviceToolsProfile tools_profile_ref: Allows you to add commands to the element’s
            right-click menu. Not Required.
        :param str comment: optional comment
        :raises CreateElementFailed: Failed to create the proxy element
        :rtype: HttpProxy
        """
        json = {
            "name": name,
            "address": address,
            "comment": comment,
            "http_proxy_port": proxy_port,
            "http_proxy_username": username if username else "",
            "http_proxy_password": password if password else "",
            "secondary": secondary if secondary else [],
            "tools_profile_ref": element_resolver(tools_profile_ref),
        }
        if third_party_monitoring:
            json.update(third_party_monitoring=third_party_monitoring.data)

        return ElementCreator(cls, json)

    @property
    def address(self):
        """
        Single valid IPv4 address.
        :rtype str
        """
        return self.data.get("address")

    @property
    def http_proxy_username(self):
        """
        Username for authentication.
        :rtype str
        """
        return self.data.get("http_proxy_username")

    @property
    def http_proxy_port(self):
        """
        Listening proxy port.
        :rtype int
        """
        return self.data.get("http_proxy_port")


class DNSServer(Element):
    """
    There are some cases in which you must define an External DNS Server
    element.

    * For dynamic DNS (DDNS) updates with a Multi-Link configuration.
    * If you want to use a DNS server for resolving malware signature mirrors.
    * If you want to use a DNS server for resolving domain names and URL filtering
      categorization services on Firewalls, IPS engines, and Layer 2 Firewalls.

    You can also optionally use External DNS Server elements to specify the DNS servers
    to which the firewall forwards DNS requests when you configure DNS relay.

    :ivar int time_to_live: how long a DNS entry can be cached
    :ivar int update_interval: how often DNS entries can be updated
    """

    typeof = "dns_server"

    @classmethod
    def create(
            cls, name, address, time_to_live=20, update_interval=10, secondary=None, comment=None
    ):
        """
        Create a DNS Server element.

        :param str name: Name of DNS Server
        :param str address: IP address for DNS Server element
        :param int time_to_live: Defines how long a DNS entry can be cached
            before querying the DNS server again (default: 20)
        :param int update_interval: Defines how often the DNS entries can be
            updated to the DNS server if the link status changes constantly
            (default: 10)
        :param list secondary: a secondary set of IP address for this element
        :raises CreateElementFailed: Failed to create with reason
        :rtype: DNSServer
        """
        json = {
            "name": name,
            "address": address,
            "comment": comment,
            "time_to_live": time_to_live,
            "update_interval": update_interval,
            "secondary": secondary if secondary else [],
        }

        return ElementCreator(cls, json)


class DHCPServer(Element):
    """
    A DHCP Server based element. Used in various areas to define External DHCP Server.
    """

    typeof = "dhcp_server"
    location = ElementRef("location_ref")

    @classmethod
    def create(cls, name, address=None, ipv6_address=None, location=None, comment=None):
        """
        Create a DHCP Server element.

        :param str name: Name of DHCP Server
        :param str address: IPv4 address for DHCP Server element
        :param str ipv6_address: IPv6 address for DHCP Server element
        :param str location: Specifies the location for the server if there is a NAT
            device between the server and other SMC components.
        :param str comment: Comment for DHCP Server element
        :raises CreateElementFailed: Failed to create with reason
        :rtype: DHCPServer
        """
        json = {"name": name, "address": address, "ipv6_address": ipv6_address, "comment": comment}

        if location:
            json.update(location_ref=element_resolver(location))

        return ElementCreator(cls, json)


class ProxyServer(ContactAddressMixin, Element, MultiContactServer):
    """
    A ProxyServer element is used in the firewall policy to provide the ability to
    send HTTP, HTTPS, FTP or SMTP traffic to a next hop proxy.
    There are two types of next hop proxies, 'Generic' and 'Forcepoint AP Web".

    Example of creating a configuration for a Forcepoint AP-Web proxy redirect::

        server = ProxyServer.update_or_create(name='myproxy',
            address='1.1.1.1', proxy_service='forcepoint_ap-web_cloud',
            fp_proxy_key='mypassword', fp_proxy_key_id=3, fp_proxy_user_id=1234,
            inspected_service=[{'service_type': 'HTTP', 'port': '80'}])

    Create a Generic Proxy forward service::

        server = ProxyServer.update_or_create(name='generic', address='1.1.1.1,1.1.1.2',
            inspected_service=[{'service_type': 'HTTP', 'port': 80},
                               {'service_type': 'HTTPS', 'port': 8080}])

    Inspected services take a list of keys `service_type` and `port`. Service type key values
    are 'HTTP', 'HTTPS', 'FTP' and 'SMTP'. Port value is the port for the respective protocol.

    :param str http_proxy: type of proxy configuration, either generic or forcepoint_ap-web_cloud
    """

    typeof = "proxy_server"

    @classmethod
    def create(
            cls,
            name,
            address,
            secondary=None,
            ipv6_address=None,
            balancing_mode="ha",
            proxy_service="generic",
            location=None,
            add_x_forwarded_for=False,
            trust_host_header=False,
            inspected_service=None,
            third_party_monitoring=None,
            tools_profile_ref=None,
            comment=None,
            **kw
    ):
        """
        Create a Proxy Server element

        :param str name: name of proxy server element
        :param str address: address of element. Can be a single FQDN or comma separated
            list of IP addresses
        :param list secondary: List of secondary IP addresses
        :param str ipv6_address: Single valid IPv6 address.
        :param str balancing_mode: how to balance traffic, valid options are
            ha (first available server), src, dst, srcdst (default: ha)
        :param str proxy_service: which proxy service to use for next hop, options
            are generic or forcepoint_ap-web_cloud
        :param Location location: location for this proxy server
        :param bool add_x_forwarded_for: add X-Forwarded-For header when using the
            Generic Proxy forwarding method (default: False)
        :param bool trust_host_header: trust the host header when using the Generic
            Proxy forwarding method (default: False)
        :param dict inspected_service: inspection services dict. Valid keys are
            service_type and port. Service type valid values are HTTP, HTTPS, FTP or SMTP
            and are case sensitive
        :param ThirdPartyMonitoring third_party_monitoring: The optional Third Party Monitoring
            configuration.
        :param DeviceToolsProfile tools_profile_ref: Allows you to add commands to the element’s
            right-click menu. Not Required.
        :param str comment: optional comment
        :param kw: keyword arguments are used to collect settings when the proxy_service
            value is forcepoint_ap-web_cloud. Valid keys are `fp_proxy_key`,
            `fp_proxy_key_id`, `fp_proxy_user_id`. The fp_proxy_key is the password value.
            All other values are of type int
        """
        json = {
            "name": name,
            "secondary": secondary or [],
            "balancing_mode": balancing_mode,
            "http_proxy": proxy_service,
            "ipv6_address": ipv6_address,
            "inspected_service": inspected_service,
            "trust_host_header": trust_host_header,
            "add_x_forwarded_for": add_x_forwarded_for,
            "location_ref": element_resolver(location),
            "tools_profile_ref": element_resolver(tools_profile_ref),
            "comment": comment
        }
        addresses = address.split(",")
        json.update(address=addresses.pop(0))
        json.update(ip_address=addresses if "ip_address" not in kw else kw["ip_address"])

        if proxy_service == "forcepoint_ap-web_cloud":
            for key in ("fp_proxy_key", "fp_proxy_key_id", "fp_proxy_user_id"):
                if key not in kw:
                    raise CreateElementFailed(
                        "Missing required fp key when adding a "
                        "proxy server to forward to forcepoint. Missing key: %s" % key
                    )
                json[key] = kw.get(key)

        if third_party_monitoring:
            json.update(third_party_monitoring=third_party_monitoring.data)

        return ElementCreator(cls, json)

    @property
    def proxy_service(self):
        """
        The proxy service for this proxy server configuration

        :rtype: str
        """
        return self.data.get("http_proxy")

    @property
    def ip_address(self):
        """
        List of IP Addresses to be used in addition to the 'address' field to allow using multiple
            IP Addresses for the element.

        :rtype: list(str)
        """
        return self.data.get("ip_address")

    @property
    def balancing_mode(self):
        """
        How to balance traffic, valid options are ha (first available server), src, dst, srcdst
            (default: ha)
        :rtype: str
        """
        return self.data.get("balancing_mode")

    @property
    def trust_host_header(self):
        """
        Trust the host header when using the Generic Proxy forwarding method (default: False)
        :rtype: bool
        """
        return self.data.get("trust_host_header")

    @property
    def add_x_forwarded_for(self):
        """
        Add X-Forwarded-For header when using the Generic Proxy forwarding method (default: False)
        :rtype: bool
        """
        return self.data.get("add_x_forwarded_for")

    @property
    def fp_proxy_key(self):
        """
        Password of Customer ID used in HTTP/HTTPS properties.
        :rtype: str
        """
        return self.data.get("fp_proxy_key", None)

    @property
    def fp_proxy_key_id(self):
        """
        Key ID in case of Web-Gateway choice
        :rtype: int
        """
        return self.data.get("fp_proxy_key_id", None)

    @property
    def fp_proxy_user_id(self):
        """
        Customer ID used in HTTP/HTTPS properties.
        :rtype: str
        """
        return self.data.get("fp_proxy_user_id", None)

    @classmethod
    def update_or_create(cls, with_status=False, **kwargs):
        element, updated, created = super(ProxyServer, cls).update_or_create(
            defer_update=True, **kwargs
        )

        if not created:
            if (
                    "proxy_service" in element.data
                    and element.http_proxy != element.data["proxy_service"]
            ):
                element.data["http_proxy"] = element.data.pop("proxy_service")
                updated = True
            if "address" in kwargs:
                if "," in element.data.get("address"):
                    addresses = element.data.pop("address").split(",")
                    element.data["address"] = addresses.pop(0)
                    # Remainder is ip_address attribute
                    if set(addresses) ^ set(element.data.get("ip_address", [])):
                        element.data["ip_address"] = addresses
                    updated = True

            inspected_service = kwargs.pop("inspected_service", None)
            if inspected_service is not None:
                service_keys = set([k.get("service_type") for k in inspected_service])
                element_keys = set(
                    [k.get("service_type") for k in element.data.get("inspected_service", [])]
                )
                if service_keys ^ element_keys:
                    element.data["inspected_service"] = inspected_service
                    updated = True
            if updated:
                element.update()

        if with_status:
            return element, updated, created
        return element

    @property
    def inspected_services(self):
        """
        The specified services for inspection. An inspected service is a
        reference to a protocol that can be forwarded for inspection, such
        as HTTP, HTTPS, FTP and SMTP.

        :rtype: list(InspectedService)
        """
        return [
            InspectedService(**service)
            for service in self.make_request(resource="inspected_services")
        ]


class InspectedService(SubElement):
    """
    This represents the service defined for inspection for a
    ProxyServer element.

    :ivar str service_type: the service type for inspection
    :ivar int port: the port for this service
    """

    pass


class ElasticsearchCluster(ContactAddressMixin, Element):
    """
    An ElasticsearchCluster server type element.
    """

    typeof = "elasticsearch_cluster"
    location = ElementRef("location_ref")

    @classmethod
    def create(
            cls,
            name,
            addresses,
            port=9200,
            es_retention_period=30,
            es_shard_number=0,
            es_replica_number=0,
            enable_cluster_sniffer=False,
            location=None,
            comment=None,
            tls_profile=None,
            es_tls_settings=None,
            authentication_settings=None,
            product=None
    ):
        """
        Create a Elasticsearch Cluster Server element.

        :param str name: Name of Elasticsearch Cluster
        :param list,str addresses: str comma-separated list or list
         of one or more FQDNs or IP addresses
        :param int port: Default port is 9200
        :param int es_retention_period: How much time logs will be kept
        30days default
        :param int es_shard_number: Auto by default, number of shards
        :param int es_replica_number : number of ES replicas
        :param bool enable_cluster_sniffer : Enable cluster sniffer (False
        default)
        :param str location: Specifies the location for the server if there
        is a NAT device between the server and other SMC components.
        :param str comment: Comment for Elasticsearch cluster Server element
        :param str tls_profile: tls profile name to use
        :param TlsSettings es_tls_settings: Elasticsearch TLS Settings.
        :param dict authentication_settings:
        method: str can be none, basic, api_key or certificate
        for basic
            login : elasticsearch user login
            password : elasticsearch user password
        for api_key:
            api_key: elasticsearch api key for user
        :raises CreateElementFailed: Failed to create with reason
        :param: str product: product type can be elasticsearch or opensearch (default:elasticsearch)
        :rtype: ElasticsearchCluster
        """
        json = {
            "name": name,
            "port": port,
            "es_retention_period": es_retention_period,
            "es_shard_number": es_shard_number,
            "es_replica_number": es_replica_number,
            "es_enable_cluster_sniffer": enable_cluster_sniffer,
            "comment": comment,
        }

        if isinstance(addresses, str):
            addresses_lst = addresses.split(",")
        else:
            addresses_lst = addresses
        json.update(addresses=addresses_lst)
        if location:
            location_href = Location(location).href
            json.update(location_ref=location_href)
        if tls_profile:
            tls_profile_ref = tls.TLSProfile(tls_profile).href
            json.update(tls_profile=tls_profile_ref)
        _ElasticsearchCompatibility.create_helper(json,
                                                  "authentication_settings",
                                                  es_tls_settings,
                                                  authentication_settings,
                                                  product)
        return ElementCreator(cls, json)

    def update(self, *exception, **kwargs):
        super().update(*exception,
                       **_ElasticsearchCompatibility.update_helper(
                           "authentication_settings",
                           **kwargs))

    @property
    def port(self):
        """
        The port on which connection is established on Elasticsearch Cluster nodes.
        :rtype: int
        """
        return self.data.get("port")

    @property
    @deprecated("authentication_settings")
    def es_tls_settings(self):
        """
        Elasticsearch TLS Settings.
        :rtype: TlsSettings
        """
        return _ElasticsearchCompatibility.es_tls_settings_property(
            self.data,
            "authentication_settings")

    @property
    def authentication_settings(self):
        """
        Elasticsearch authentication settings.
        """
        return _ElasticsearchCompatibility.authentication_settings_property(
            self.data,
            "authentication_settings",
            {
                "method": "none"
            })

    @property
    def addresses(self):
        """
        The list of hostnames / IP addresses (at least one) used to establish connection to the
            Elasticsearch Cluster.
        :rtype: list(str)
        """
        return self.data.get("addresses")

    @property
    def es_retention_period(self):
        """
        Retention period (in days) for logs in Elasticsearch cluster.
        :rtype: int
        """
        return self.data.get("es_retention_period")

    @property
    def es_shard_number(self):
        """
        The number of shards for the fwlogsandalerts indices, a strictly positive number, or auto
            (default value).
        :rtype: int
        """
        return self.data.get("es_shard_number")

    @property
    def es_enable_cluster_sniffer(self):
        """
        Enabling the cluster sniffer. Default: false.
        :rtype: bool
        """
        return self.data.get("es_enable_cluster_sniffer")


class _ElasticsearchCompatibility:
    @staticmethod
    def _supports_authentication_settings() -> bool:
        return (not is_api_version_less_than_or_equal("7.0")
                and not is_smc_version_equal("7.1.1"))

    @staticmethod
    def _uses_es_tls_settings_settings() -> bool:
        return is_api_version_less_than_or_equal("7.1")

    @staticmethod
    def _support_product() -> bool:
        return not is_smc_version_less_than("7.1.3")

    @classmethod
    def create_helper(cls,
                      json,
                      authentication_property_name: str,
                      tls_settings=None,
                      authentication_settings=None,
                      product=None):
        """Backward-compatibility function for Elasticsearch-related components' create method"""
        if (not tls_settings and authentication_settings
                and cls._uses_es_tls_settings_settings()):
            # Forward-compatibility of authentication settings in lower versions
            method = authentication_settings["method"]
            if method == "none":
                pass
            elif method == "certificate":
                credentials = authentication_settings.get("tls_credentials")
                tls_settings = TlsSettings.create(credentials is None, credentials)
            elif not cls._supports_authentication_settings():
                raise UnsupportedAttribute(f"Unsupported authentication method {method} in this "
                                           f"API version")
        if tls_settings:
            # Backward-compatibility for deprecated es_tls_settings
            if cls._uses_es_tls_settings_settings():
                # Below 7.2 use es_tls_settings as-is
                json.update(es_tls_settings=tls_settings)
                # Since 7.1.2 add authentication method as well
                if cls._supports_authentication_settings():
                    authentication_settings = {
                        "method": "certificate"
                    }
            else:
                # 7.2 and above -> transform es_tls_settings into authentication_settings
                authentication_settings = cls._convert_tls_settings(tls_settings)
        if authentication_settings:
            if cls._supports_authentication_settings():
                json.update({authentication_property_name: authentication_settings})
        # 7.1.3 and above -> product can be elasticsearch (default or opensearch)
        if product:
            if cls._support_product():
                if product is not None:
                    json.update(product=product)
                else:
                    json.update({"product": "elasticsearch"})
            else:
                raise UnsupportedAttribute(f"Unsupported parameter product in this "
                                           f"SMC version")

    @classmethod
    def update_helper(cls,
                      authentication_property_name: str,
                      **kwargs):
        """Backward-compatibility function for Elasticsearch-related components' update"""
        # Backward-compatibility of deprecated "es_tls_settings" with version 7.2 and above
        if not cls._uses_es_tls_settings_settings() and "es_tls_settings" in kwargs:
            kwargs.update({
                authentication_property_name: cls._convert_tls_settings(
                    kwargs.pop("es_tls_settings"))})
        # Forward-compatibility of authentication settings in lower versions
        if cls._uses_es_tls_settings_settings() and authentication_property_name in kwargs:
            # Extract info from supported authentication method below 7.1.1 (certificate or none)
            if not cls._supports_authentication_settings():
                authentication_settings = kwargs.pop(authentication_property_name)
                if authentication_settings:
                    method = authentication_settings.get("method")
                    if method == "none":
                        kwargs.update(es_tls_settings=None)
                    elif method == "certificate":
                        credentials = authentication_settings.get("tls_credentials")
                        kwargs.update(es_tls_settings=TlsSettings.create(credentials is None,
                                                                         credentials))
                else:
                    kwargs.update(es_tls_settings=None)
            else:
                authentication_settings = kwargs.get(authentication_property_name)
                method = authentication_settings.get("method") if authentication_settings \
                    else "none"
                if method == "none":
                    kwargs.update(es_tls_settings=None)
                elif method == "certificate":
                    credentials = authentication_settings.pop("tls_credentials")
                    kwargs.update(
                        es_tls_settings=TlsSettings.create(credentials is None, credentials))
        if not cls._support_product() and "product" in kwargs:
            raise UnsupportedAttribute(f"Unsupported parameter product in this "
                                       f"SMC version")
        return kwargs

    @staticmethod
    def _convert_tls_settings(tls_settings: TlsSettings):
        """Convert TLS Settings to equivalent Elasticsearch Authentication Settings"""
        return {
            "method": "certificate",
            "tls_credentials": None if tls_settings.use_internal_credentials else
            tls_settings.tls_credentials.href
        } if tls_settings else None

    @classmethod
    def es_tls_settings_property(cls,
                                 data,
                                 authentication_property_name: str):
        """Backward-compatibility function for Elasticsearch-related components' es_tls_settings
        property"""
        if cls._uses_es_tls_settings_settings():
            tls_settings = data.get("es_tls_settings")
            return TlsSettings(tls_settings) if tls_settings else None
        else:
            # Backward-compatibility: craft TlsSettings out of authentication_settings
            authentication_settings = data.get(authentication_property_name)
            if authentication_settings and authentication_settings.get("method") == "certificate":
                credentials = authentication_settings.get("tls_credentials")
                return TlsSettings.create(credentials is None, credentials)
            else:
                return None

    @classmethod
    def authentication_settings_property(cls,
                                         data,
                                         property_name: str,
                                         default_value):
        authentication_settings = data.get(property_name)
        # Backward compatibility below 7.2
        if cls._uses_es_tls_settings_settings():
            tls_settings = data.get("es_tls_settings")
            if tls_settings:
                authentication_settings = cls._convert_tls_settings(TlsSettings(tls_settings))
            # No TLS settings and below 7.1.2 => none
            elif not cls._supports_authentication_settings():
                authentication_settings = default_value
        return authentication_settings


class NTPServer(Element, IPv6Node):
    """
    This represents an NTP server: A Network Element that represents an NTP instance of server.
    """

    typeof = "ntp"

    @property
    def ntp_host_name(self):
        """
        The NTP Host Name (Not Required)
        """
        return self.data.get("ntp_host_name")

    @property
    def ntp_auth_key_type(self):
        """
        The NTP Authentication Key Type (Required)
        Possible values are:
        - none
        - md5
        - sha1
        - sha256
        """
        return self.data.get("ntp_auth_key_type")

    @property
    def ntp_auth_key_id(self):
        """
        The NTP Authentication Key ID (Not Required)
        value between 1 - 65534
        """
        return self.data.get("ntp_auth_key_id")

    @property
    def ntp_auth_key(self):
        """
        The NTP Authentication Key (Not Required)
        """
        return self.data.get("ntp_auth_key")

    @classmethod
    def create(
            cls,
            name,
            address,
            ipv6_address=None,
            ntp_host_name=None,
            ntp_auth_key_type="none",
            ntp_auth_key_id=None,
            ntp_auth_key=None,
            secondary=None,
            third_party_monitoring=None,
            tools_profile_ref=None,
            comment=None
    ):
        """
        Create NTP server

        :param str name: name for the Element
        :param str address: The NTP address (Required)
        :param str ipv6_address: Single valid IPv6 address.
        :param str ntp_host_name: NTP server name to use
        :param str ntp_auth_key_type:The NTP Authentication Key Type (Required)
        possible values are (none, md5, sha1, sha256)
        :param str ntp_auth_key_id:The NTP Authentication Key ID (Not Required)
        value between 1 - 65534
        :param str ntp_auth_key:The NTP Authentication Key (Not Required)
        :param list secondary: secondary ip address (optional)
        :param ThirdPartyMonitoring third_party_monitoring: The optional Third Party Monitoring
            configuration.
        :param DeviceToolsProfile tools_profile_ref: Allows you to add commands to the element’s
            right-click menu. Not Required.
        :param str comment: comment for the element

        :raises CreateElementFailed: Failed to create with reason
        :rtype: NTPServer
        """
        ntp_server_json = {
            "address": address,
            "ipv6_address": ipv6_address,
            "comment": comment,
            "name": name,
            "ntp_host_name": ntp_host_name,
            "ntp_auth_key_type": ntp_auth_key_type,
            "ntp_auth_key_id": ntp_auth_key_id,
            "ntp_auth_key": ntp_auth_key,
            "secondary": secondary if secondary else [],
            "tools_profile_ref": element_resolver(tools_profile_ref),
        }

        if third_party_monitoring:
            ntp_server_json.update(third_party_monitoring=third_party_monitoring.data)
        return ElementCreator(cls, ntp_server_json)


class AuthenticationServerMixin(Element, MultiContactServer):
    """
    This mixin class provide interface to a TACACS+/RADIUS Authentication Server.
    """

    @classmethod
    def create(
            cls,
            name,
            address=None,
            ipv6_address=None,
            clear_text=False,
            location_ref=None,
            provided_method=None,
            retries=2,
            timeout=10,
            secondary=None,
            shared_secret=None,
            port=49,
            third_party_monitoring=None,
            tools_profile_ref=None,
            comment=None
    ):
        """
        :param str name: Name of the TacacsServer/RadiusServer.
        :param str address: Single valid IPv4 address. Required.
        :param str ipv6_address: Single valid IPv6 address
        :param bool clear_text: Select Accepted by Firewall if you want the Firewall to accept
            unencrypted replies from the TACACS+ authentication server. Not Required.
        :param Location location_ref: The location of TacacsServer/RadiusServer.
        :param list(AuthenticationMethod) provided_method: Specify provided Authentication methods.
            Not Required.
        :param int retries: Specify the number of times Firewalls try to connect to the RADIUS or
            TACACS+ authentication server if the connection fails. Required.
        :param int timeout: Specify the time (in seconds) that Firewalls wait for the RADIUS or
            TACACS+ authentication server to reply. Not Required.
        :param list(str) secondary: If the device has additional IP addresses, you can enter them
            here instead of creating additional elements for the other IP addresses. The secondary
            IP addresses are valid in policies and in routing and antispoofing. You can add several
            IPv4 and IPv6 addresses (one by one)
        :param str shared_secret: Specify the Shared Secret that you have defined for RADIUS clients
            on the Active Directory server.
        :param int port: Specify the port number if the server communicates on a port other than the
            default port. The predefined Firewall Template allows the engines to connect to the
            default port. If you change to a custom port, you must add a new IPv4 Access Rule to
            allow the traffic. Not Required.
        :param ThirdPartyMonitoring third_party_monitoring: The optional Third Party Monitoring
            configuration.
        :param tools_profile tools_profile_ref: Allows you to add commands to the element’s
            right-click menu. Not Required.
        :param str comment: optional comment.
        """

        json = {
            "name": name,
            "address": address,
            "ipv6_address": ipv6_address,
            "location_ref": element_resolver(location_ref),
            "retries": retries,
            "timeout": timeout,
            "secondary": secondary,
            "shared_secret": shared_secret,
            "port": port,
            "tools_profile_ref": element_resolver(tools_profile_ref),
            "comment": comment
        }
        if cls.typeof == "tacacs_server":
            json.update(clear_text=clear_text)

        if third_party_monitoring:
            json.update(third_party_monitoring=third_party_monitoring.data)
        provided_method = provided_method if provided_method else []
        json.update(provided_method=[element_resolver(method) for method in provided_method])

        return ElementCreator(cls, json)

    @property
    def provided_method(self):
        """
        Provided Authentication methods.
        :rtype list(AuthenticationMethod)
        """
        return [Element.from_href(method) for method in self.data.get("provided_method")]

    @property
    def timeout(self):
        """
         Specify the time (in seconds) that Firewalls wait for the TACACS+/RADIUS authentication
            server to reply
         :rtype Time out value
        """
        return self.data.get("timeout")

    @property
    def shared_secret(self):
        """
        Shared secrete text
        :rtype str
        """
        return self.data.get("shared_secret")

    @property
    def port(self):
        """
        Specify the port number if the server communicates on a port other than the default port.
        :rtype int
        """
        return self.data.get("port")


class WebPortalServer(Element, MultiContactServer, ExternalPki):
    """
    This represents a Web Portal Server. A component of the Management Center responsible for
    browsing logs, Policy Snapshots and reports from a Web Browser.
    """
    typeof = "web_portal_server"

    @classmethod
    def create(
            cls,
            name,
            address=None,
            ipv6_address=None,
            alert_server=None,
            location_ref=None,
            web_app=None,
            announcement_enabled=False,
            announcement_message=None,
            external_pki_certificate_settings=None,
            uiid=None,
            tools_profile_ref=None,
            secondary=None,
            comment=None
    ):
        """
        This represents a Web Portal Server. A component of the Management Center responsible for
            browsing logs, Policy Snapshots and reports from a Web Browser.
        :param str name: Name of the Web Portal Server.
        :param str address: Single valid IPv4 address. Required.
        :param str ipv6_address: IPv6 address.
        :param LogServer alert_server: Specify the Log Server to which you want the Web Portal
            Server to send its logs. Required.
        :param Location location_ref: Location of the server.
        :param list(WebApp) web_app: Web Portal Server can be configured to define several Web
        Application like webclient, webswing.
        :param bool announcement_enabled: Is announcement enabled for WebPortal Server:Announcements
            in the Web Portal Server element are shown for all users that connect to that Web Portal
            Server.Not Required.
        :param str announcement_message: The announcement message for WebPortal users.
        :param PkiCertificateSettings external_pki_certificate_settings: Certificate Settings for
            External PKI mode.
        :param str uiid: Web Portal Server Installation ID (aka UUID).
        :param tools_profile tools_profile_ref: Allows you to add commands to the element’s
            right-click menu.
        :param list(str) secondary: If the device has additional IP addresses, you can enter them
            here instead of creating additional elements for the other IP addresses. The secondary
            IP addresses are valid in policies and in routing and antispoofing. You can add several
            IPv4 and IPv6 addresses (one by one)
        :param str comment: optional comment.
        """

        web_app = web_app if web_app else []
        json = {
            "name": name,
            "address": address,
            "ipv6_address": ipv6_address,
            "alert_server": element_resolver(alert_server),
            "location_ref": element_resolver(location_ref),
            "secondary": secondary if secondary else [],
            "external_pki_certificate_settings": external_pki_certificate_settings,
            "uiid": uiid,
            "tools_profile_ref": tools_profile_ref,
            "web_app": [app.data for app in web_app],
            "comment": comment
        }
        if is_smc_version_less_than("7.1"):
            json.update(announcement_enabled=announcement_enabled,
                        announcement_message=announcement_message)
        return ElementCreator(cls, json)

    @property
    def web_app(self):
        """
        Represents a Web Application parameter.
        :rtype list(WebApp):
        """
        return [WebApp(data) for data in self.data.get("web_app")]

    @property
    def alert_server(self):
        """
        Specify the Log Server to which you want the Web Portal Server to send its logs
        rtype LogServer
        """
        return Element.from_href(self.data.get("alert_server"))

    @property
    def uiid(self):
        return self.data.get("uiid")

    @property
    def external_pki_certificate_settings(self):
        """
        Certificate Settings for External PKI mode.
        return PkiCertificateSettings
        """
        return PkiCertificateSettings(self)

    @property
    def announcement_message(self):
        return self.data.get("announcement_message")


class TacacsServer(AuthenticationServerMixin, ContactAddressMixin):
    """
    This represents a TACACS Server.An external authentication server can be any server that
    supports either the RADIUS or the TACACS+ protocol, including Microsoft Active Directory servers
    External authentication servers are integrated with the help of Active Directory Server, RADIUS
    Authentication Server, TACACS+ Authentication Server, and Authentication Method elements. The
    RADIUS Authentication Server and TACACS+ Authentication Server elements define the settings
    necessary for connecting to an external authentication server. The Authentication Method
    elements define an authentication method, and can include several RADIUS Authentication Servers
    or TACACS+ Authentication Servers that support the method and can be used as backups to each
    other.
    """
    typeof = "tacacs_server"

    @property
    def clear_text(self):
        """
        Select Accepted by Firewall if you want the Firewall to accept unencrypted replies from the
            TACACS+ authentication server.
        :rtype bool
        """
        return self.data.get("clear_text")


class RadiusServer(AuthenticationServerMixin, ContactAddressMixin):
    """
    This represents a RADIUS Server. It is an Authentication server using RADIUS authentication
    method. It can be used as authentication method for Administrators. An external authentication
    server can be any server that supports either the RADIUS or the TACACS+ protocol, including
    Microsoft Active Directory servers. External authentication servers are integrated with the help
    of Active Directory Server, RADIUS Authentication Server, TACACS+ Authentication Server, and
    Authentication Method elements. The RADIUS Authentication Server Server elements define the
    settings necessary for connecting to an external authentication server. The Authentication
    Method elements define an authentication method, and can include several RADIUS Authentication
    Servers or TACACS+ Authentication Servers that support the method and can be used as backups
    to each other.
    """
    typeof = "radius_server"


class IcapServer(Element, MultiContactServer):
    """
    This represents an ICAP server: A Network Element that represents an ICAP instance of server.
    """
    typeof = "icap"

    @classmethod
    def create(
            cls,
            name,
            address=None,
            ipv6_address=None,
            icap_include_xhdrs=False,
            icap_path=None,
            icap_port=1344,
            icap_secure=False,
            icap_xhdr_clientip=None,
            icap_xhdr_serverip=None,
            icap_xhdr_username=None,
            tls_profile_ref=None,
            location_ref=None,
            secondary=None,
            third_party_monitoring=None,
            tools_profile_ref=None,
            comment=None
    ):
        """
        :param str name: Name of the IcapServer.
        :param str address: Single valid IPv4 address. Required.
        :param str ipv6_address: Single valid IPv6 address.
        :param bool icap_include_xhdrs:Include X-Headers or not.
        :param str icap_path: The path to the service. Not Required. Defaults to "reqmod".
        :param int icap_port: The port on which the ICAP server is listening.Defaults to 1344, or
            11344 for Secure
        :param bool icap_secure: Secure ICAP Enabled. Not Required.
        :param str icap_xhdr_clientip: X-Header Client IP. Not Required. Defaults to "X-Client-IP"
        :param str icap_xhdr_serverip: X-Header Server IP. Not Required. Defaults to "X-Server-IP"
        :param str icap_xhdr_username: X-Header Username. Not Required. Defaults to
            "X-Authenticated-User"
        :param TLSProfile tls_profile_ref: Represents a TLS Profile Contains common parameters for
            establishing TLS based connections.
        :param Location location_ref: The location of TacacsServer/RadiusServer.
        :param list(str) secondary: If the device has additional IP addresses, you can enter them
            here instead of creating additional elements for the other IP addresses. The secondary
            IP addresses are valid in policies and in routing and antispoofing. You can add several
            IPv4 and IPv6 addresses (one by one)
        :param ThirdPartyMonitoring third_party_monitoring: The optional Third Party Monitoring
            configuration.
        :param DeviceToolsProfile tools_profile_ref: Allows you to add commands to the element’s
            right-click menu. Not Required.
        :param str comment: optional comment.
        """

        json = {
            "name": name,
            "address": address,
            "ipv6_address": ipv6_address,
            "location_ref": element_resolver(location_ref),
            "tools_profile_ref": element_resolver(tools_profile_ref),
            "icap_include_xhdrs": icap_include_xhdrs,
            "icap_path": icap_path,
            "icap_port": icap_port,
            "icap_secure": icap_secure,
            "icap_xhdr_clientip": icap_xhdr_clientip,
            "icap_xhdr_serverip": icap_xhdr_serverip,
            "icap_xhdr_username": icap_xhdr_username,
            "tls_profile_ref": element_resolver(tls_profile_ref),
            "secondary": secondary,
            "comment": comment
        }

        if third_party_monitoring:
            json.update(third_party_monitoring=third_party_monitoring.data)
        return ElementCreator(cls, json)

    @property
    def icap_port(self):
        """
        The port on which the ICAP server is listening.
        :rtype int
        """
        return self.data.get("icap_port")

    @property
    def icap_include_xhdrs(self):
        """
        Include X-Headers or not.
        :rtype bool
        """
        return self.data.get("icap_include_xhdrs")

    @property
    def icap_path(self):
        """
        The path to the service. Not Required. Defaults to "reqmod".
        """
        return self.data.get("icap_path")

    @property
    def icap_secure(self):
        """
        Secure ICAP Enabled.
        :rtype bool
        """
        return self.data.get("icap_secure")

    @property
    def icap_xhdr_clientip(self):
        """
        X-Header Client IP.
        :rtype str
        """
        return self.data.get("icap_xhdr_clientip")

    @property
    def icap_xhdr_serverip(self):
        """
        X-Header Server IP.
        :rtype str
        """
        return self.data.get("icap_xhdr_serverip")

    @property
    def icap_xhdr_username(self):
        """
        X-Header Username.
        :rtype str
        """
        return self.data.get("icap_xhdr_username")

    @property
    def tls_profile_ref(self):
        """
        Represents a TLS Profile Contains common parameters for establishing TLS based connections.
        :rtype TLSProfile
        """
        return Element.from_href(self.data.get("tls_profile_ref"))


class SmtpServer(Element, ContactAddressMixin, MultiContactServer):
    """
    This represents a Simple Mail Transfer Protocol (SMTP) server. Server used to process
        notifications by e-mails.
    """
    typeof = "smtp_server"

    @classmethod
    def create(
            cls,
            name,
            address=None,
            ipv6_address=None,
            port=25,
            email_sender_address=None,
            email_sender_name=None,
            location_ref=None,
            secondary=None,
            third_party_monitoring=None,
            tools_profile_ref=None,
            comment=None
    ):
        """
        This represents a Simple Mail Transfer Protocol (SMTP) server. Server used to process
        notifications by e-mails.
        :param str name: Name of the SmtpServer.
        :param str address: Single valid IPv4 address. Required.
        :param str ipv6_address: Single valid IPv6 address.
        :param int port: The port on which the SMTP server is listening. default port 25.Required
        :param str email_sender_address: E-mail address to be used in the From field of the e-mail.
            This default value can be overridden in the properties of the element where the SMTP
            Server is used.Not Required.
        :param str email_sender_name: Name to be used in the From field of the e-mail. This default
            value can be overridden in the properties of the element where the SMTP Server is used.
            Not Required.
        :param Location location_ref: The location of SmtpServer.
        :param list(str) secondary: If the device has additional IP addresses, you can enter them
            here instead of creating additional elements for the other IP addresses. The secondary
            IP addresses are valid in policies and in routing and antispoofing. You can add several
            IPv4 and IPv6 addresses (one by one)
        :param ThirdPartyMonitoring third_party_monitoring: The optional Third Party Monitoring
            configuration.
        :param DeviceToolsProfile tools_profile_ref: Allows you to add commands to the element’s
            right-click menu. Not Required.
        :param str comment: optional comment.
        """

        json = {
            "name": name,
            "address": address,
            "ipv6_address": ipv6_address,
            "location_ref": element_resolver(location_ref),
            "tools_profile_ref": element_resolver(tools_profile_ref),
            "port": port,
            "email_sender_address": email_sender_address,
            "email_sender_name": email_sender_name,
            "secondary": secondary,
            "comment": comment
        }

        if third_party_monitoring:
            json.update(third_party_monitoring=third_party_monitoring.data)
        return ElementCreator(cls, json)

    @property
    def port(self):
        """
        The port on which the SMTP server is listening.
        :rtype int
        """
        return self.data.get("port")

    @property
    def email_sender_address(self):
        """
        E-mail address to be used in the From field of the e-mail.
        :rtype str
        """
        return self.data.get("email_sender_address")

    @property
    def email_sender_name(self):
        """
        Name to be used in the From field of the e-mail.
        :rtype str
        """
        return self.data.get("email_sender_name")


class EpoServer(Element, ContactAddressMixin, IPv6Node):
    """
    This represents an ePO server: A Network Element that represents an ePO instance of server.
    """
    typeof = "epo"

    @classmethod
    def create(
            cls,
            name,
            address=None,
            ipv6_address=None,
            epo_password=None,
            epo_login=None,
            epo_port=8444,
            location_ref=None,
            secondary=None,
            third_party_monitoring=None,
            tools_profile_ref=None,
            comment=None
    ):
        """
        This represents an ePO server: A Network Element that represents an ePO instance of server.
        :param str name: Name of the EpoServer.
        :param str address: Single valid IPv4 address. Required.
        :param str ipv6_address: Single valid IPv6 address.
        :param str epo_password: The ePO password Must be entered in clear. If filled with stars,the
            field won't be updated. Required.
        :param str epo_login: The ePO login user name.
        :param int epo_port: The ePO port.
        :param Location location_ref: The location of EpoServer.
        :param list(str) secondary: If the device has additional IP addresses, you can enter them
            here instead of creating additional elements for the other IP addresses. The secondary
            IP addresses are valid in policies and in routing and antispoofing. You can add several
            IPv4 and IPv6 addresses (one by one)
        :param ThirdPartyMonitoring third_party_monitoring: The optional Third Party Monitoring
            configuration.
        :param DeviceToolsProfile tools_profile_ref: Allows you to add commands to the element’s
            right-click menu. Not Required.
        :param str comment: optional comment.
        """
        if not is_smc_version_less_than_or_equal("7.0"):
            raise UnsupportedEngineFeature(
                "EpoServer is not supported in smc version greater than 7.0")
        json = {
            "name": name,
            "address": address,
            "ipv6_address": ipv6_address,
            "epo_password": epo_password,
            "epo_login": epo_login,
            "location_ref": element_resolver(location_ref),
            "tools_profile_ref": element_resolver(tools_profile_ref),
            "epo_port": epo_port,
            "secondary": secondary,
            "comment": comment
        }

        if third_party_monitoring:
            json.update(third_party_monitoring=third_party_monitoring.data)
        return ElementCreator(cls, json)

    @property
    def epo_port(self):
        """
        The ePO port.
        :rtype: int
        """
        return self.data.get("epo_port")

    @property
    def epo_login(self):
        """
        The ePO login user name.
        :rtype: str
        """
        return self.data.get("epo_login")
