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
Engine feature add on functionality such as default NAT, Antivirus,
File Reputation, etc. These are common settings that are located under
the SMC AddOn or General properties.

Property features will have a common interface allowing you to `enable`,
`disable` and check `status` from the engine reference. When property
features are modified, they are done so against a local copy of the server
intsance. To commit the change, you must call .update() on the engine instance.

For example, to view status of antivirus, given a specific engine::

    engine.antivirus.status

Then enable or disable::

    engine.antivirus.enable()
    engine.antivirus.disable()
    engine.update()

..note:: Engine property settings require that you call engine.update() after
    making / queuing your changes.
"""
from smc.api.common import SMCRequest, fetch_entry_point
from smc.base.model import Element
from smc.base.structs import NestedDict
from smc.compat import is_api_version_less_than
from smc.elements.network import Network, Zone
from smc.elements.profiles import SandboxService, SandboxDataCenter
from smc.elements.tags import TrustedCATag
from smc.base.util import element_resolver


# TODO: This module feels like a mess, too many code paths. Options can
# inherit similar enable/disable/off/on, etc, whatever makes sense


def get_proxy(http_proxy):
    if http_proxy:
        proxies = [element_resolver(proxy) for proxy in http_proxy]
    else:
        proxies = []
    return proxies


class AntiVirus(NestedDict):
    """
    Antivirus settings for the engine. In order to use AV,
    you must also have DNS server addresses configured on
    the engine.

    Enable AV, use a proxy for updates and adjust update
    schedule::

        engine.antivirus.enable()
        engine.antivirus.update_frequency('daily')
        engine.antivirus.update_day('tu')
        engine.antivirus.log_level('transient')
        engine.antivirus.http_proxy('10.0.0.1', proxy_port=8080, user='foo', password='password')
        engine.update()

    :ivar bool antivirus_enabled: is antivirus enabled
    :ivar str antivirus_http_proxy: http proxy settings
    :ivar bool antivirus_http_proxy_enabled: is http proxy enabled
    :ivar int antivirus_proxy_port: http proxy port
    :ivar str antivirus_proxy_user: http proxy user
    :ivar str antivirus_update: how often to update
    :ivar str antivirus_update_day: if update set to weekly, which day to update
    :ivar int antivirus_update_time: time to update av signatures
    :ivar str virus_log_level: antivirus logging level

    .. note:: You must call engine.update() to commit any changes.
    """

    def __init__(self, engine):
        av = engine.data.get("antivirus", {})
        super(AntiVirus, self).__init__(data=av)

    def update_frequency(self, when):
        """
        Set the update frequency. By default this is daily.

        :param str antivirus_update: how often to check for updates. Valid options
            are: 'never','1hour', 'startup', 'daily', 'weekly'
        """
        if when in ("never", "1hour", "startup", "daily", "weekly"):
            self.update(antivirus_update=when)

    def update_day(self, day):
        """
        Update the day when updates should occur.

        :param str day: only used if 'weekly' is specified. Which day
            or week to perform update. Valid options: mo, tu, we, th,
            fr, sa, su.
        """
        if day in ("mo", "tu", "we", "th", "fr", "sa", "su"):
            self.update(antivirus_update_day=day)

    def log_level(self, level):
        """
        Set the log level for antivirus alerting.

        :param str log_level: none,transient,stored,essential,alert
        """
        if level in ("none", "transient", "stored", "essential", "alert"):
            self.update(virus_log_level=level)

    def http_proxy(self, proxy, proxy_port, user=None, password=None):
        """
        .. versionadded:: 0.5.7
            Requires SMC and engine version >= 6.4

        Set http proxy settings for Antivirus updates.

        :param str proxy: proxy IP address
        :param str,int proxy_port: proxy port
        :param str user: optional user for authentication
        """
        self.update(
            antivirus_http_proxy=proxy,
            antivirus_proxy_port=proxy_port,
            antivirus_proxy_user=user if user else "",
            antivirus_proxy_password=password if password else "",
            antivirus_http_proxy_enabled=True,
        )

    def disable(self):
        """
        Disable antivirus on the engine
        """
        self.update(antivirus_enabled=False)

    @property
    def status(self):
        """
        Status of AV on this engine

        :rtype: bool
        """
        return self.get("antivirus_enabled", False)

    def enable(self):
        """
        Enable antivirus on the engine
        """
        self.update(
            antivirus_enabled=True,
            virus_mirror="update.nai.com/Products/CommonUpdater"
            if not self.get("virus_mirror")
            else self.virus_mirror,
            antivirus_update_time=self.antivirus_update_time
            if self.get("antivirus_update_time")
            else 21600000,
        )

    def __repr__(self):
        return "{0}(enabled={1})".format(self.__class__.__name__, self.status)


class FileReputation(NestedDict):
    """
    Configure the engine to use File Reputation capabilities.

    Enable file reputation and specify outbound http proxies for
    queries::

        engine.file_reputation.enable(http_proxy=[HttpProxy('myproxy')])
        engine.update()

    :ivar str file_reputation_context: file reputation context, either
        gti_cloud_only or disabled

    .. note:: You must call engine.update() to commit any changes.
    """

    def __init__(self, engine):
        gti = engine.data.get("gti_settings") or engine.data.get("file_reputation_settings", {})
        super(FileReputation, self).__init__(data=gti)

    def disable(self):
        """
        Disable any file reputation on the engine.
        """
        self.update(file_reputation_context="disabled")

    @property
    def status(self):
        """
        Return the status of File Reputation on this engine.

        :rtype: bool
        """
        if self.file_reputation_context == "disabled":
            return False
        return True

    @property
    def http_proxy(self):
        """
        Return any HTTP Proxies that are configured for File
        Reputation.

        :return: list of http proxy instances
        :rtype: list(HttpProxy)
        """
        return [Element.from_href(proxy) for proxy in self.get("http_proxy")]

    def enable(self, http_proxy=None):
        """
        Enable GTI reputation on the engine. If proxy servers
        are needed, provide a list of proxy elements.

        :param http_proxy: list of proxies for GTI connections
        :type http_proxy: list(str,HttpProxy)
        """
        self.update(file_reputation_context="gti_cloud_only", http_proxy=get_proxy(http_proxy))

    def __repr__(self):
        return "{0}(enabled={1})".format(self.__class__.__name__, self.status)


class SidewinderProxy(object):
    """
    Sidewinder status on this engine. Sidewinder proxy can only be
    enabled on specific engine types and also requires SMC and
    engine version >= 6.1.

    Enable Sidewinder proxy::

        engine.sidewinder_proxy.enable()

    .. note:: You must call engine.update() to commit any changes.
    """

    def __init__(self, engine):
        self.engine = engine

    def enable(self):
        """
        Enable Sidewinder proxy on the engine
        """
        self.engine.data["sidewinder_proxy_enabled"] = True

    def disable(self):
        """
        Disable Sidewinder proxy on the engine
        """
        self.engine.data["sidewinder_proxy_enabled"] = False

    @property
    def status(self):
        """
        Status of Sidewinder proxy on this engine

        :rtype: bool
        """
        return self.engine.data["sidewinder_proxy_enabled"]

    def __repr__(self):
        return "{0}(enabled={1})".format(self.__class__.__name__, self.status)


class UrlFiltering(NestedDict):
    """
    Enable URL Filtering on the engine.

    Enable Url Filtering with next hop proxies::

        engine.url_filtering.enable(http_proxy=[HttpProxy('myproxy')])
        engine.update()

    Disable Url Filtering::

        engine.url_filtering.disable()
        engine.update()

    .. note:: You must call engine.update() to commit any changes.
    """

    def __init__(self, engine):
        ts = engine.data.get("ts_settings", {})
        super(UrlFiltering, self).__init__(data=ts)

    @property
    def http_proxy(self):
        """
        Return any HTTP Proxies that are configured for Url
        Filtering.

        :return: list of http proxy instances
        :rtype: list(HttpProxy)
        """
        return [Element.from_href(proxy) for proxy in self.get("http_proxy")]

    def enable(self, http_proxy=None):
        """
        Enable URL Filtering on the engine. If proxy servers
        are needed, provide a list of HTTPProxy elements.

        :param http_proxy: list of proxies for GTI connections
        :type http_proxy: list(str,HttpProxy)
        """
        self.update(ts_enabled=True, http_proxy=get_proxy(http_proxy))

    def disable(self):
        """
        Disable URL Filtering on the engine
        """
        self.update(ts_enabled=False)

    @property
    def status(self):
        """
        Return the status of URL Filtering on the engine

        :rtype: bool
        """
        return self.get("ts_enabled", False)

    def __repr__(self):
        return "{0}(enabled={1})".format(self.__class__.__name__, self.status)


class Sandbox(NestedDict):
    """
    Engine based sandbox settings. Sandbox can be configured for
    local (on prem) or cloud based sandbox. To create file filtering
    policies that use sandbox, you must first enable it and
    provide license keys on the engine.

    Enable cloud sandbox on the engine, specifying a proxy for outbound
    connections::

        engine.sandbox.enable(
            license_key='123',
            license_token='456',
            http_proxy=[HttpProxy('myproxy')])

    .. note:: You must call engine.update() to commit any changes.
    """

    def __init__(self, engine):
        self.engine = engine
        sb = engine.data.get("sandbox_settings", {})
        super(Sandbox, self).__init__(data=sb)

    @property
    def status(self):
        """
        Status of sandbox on this engine

        :rtype: bool
        """
        if "sandbox_type" in self.engine.data:
            if self.engine.sandbox_type == "none":
                return False
            return True
        return False  # Tmp, attribute missing on newly created engines

    def disable(self):
        """
        Disable the sandbox on this engine.
        """
        self.engine.data.update(sandbox_type="none")
        self.engine.data.pop("cloud_sandbox_settings", None)  # pre-6.3
        self.engine.data.pop("sandbox_settings", None)

    def enable(
            self,
            license_key="",
            license_token="",
            sandbox_type="cloud_sandbox",
            service="Automatic",
            http_proxy=None,
            sandbox_data_center="Automatic",
    ):
        """
        Enable sandbox on this engine. Provide a valid license key
        and license token obtained from your engine licensing.
        Requires SMC version >= 6.3.

        .. note:: Cloud sandbox is a feature that requires an engine license.

        :param str license_key: license key for specific engine
        :param str license_token: license token for specific engine
        :param str sandbox_type: 'local_sandbox', 'cloud_sandbox', 'forcepoint_sandbox' or 'atd'
        :param str,SandboxService service: a sandbox service element from SMC. The service
            defines which location the engine is in and which data centers to use.
            The default is to use the 'US Data Centers' profile if undefined.
        :param str,SandboxDataCenter sandbox_data_center: sandbox data center to use
            if the service specified does not exist. Requires SMC >= 6.4.3
        :return: None
        """
        service = element_resolver(SandboxService(service), do_raise=False) or element_resolver(
            SandboxService.create(
                name=service, sandbox_data_center=SandboxDataCenter(sandbox_data_center)
            )
        )

        self.update(
            sandbox_license_key=license_key,
            sandbox_license_token=license_token,
            sandbox_service=service,
            http_proxy=get_proxy(http_proxy),
        )

        self.engine.data.setdefault("sandbox_settings", {}).update(self.data)
        self.engine.data.update(sandbox_type=sandbox_type)

    @property
    def http_proxy(self):
        """
        Return any HTTP Proxies that are configured for Sandbox.
        :return: list of http proxy instances
        :rtype: list(HttpProxy)
        """
        return [Element.from_href(proxy) for proxy in self.get("http_proxy")]

    @staticmethod
    def get_permalink(engine_key, file_id):
        """
        Return a report url for Sandbox.
        :param str engine_key: the engine node key for the report generated
        :param str file_id: given from the logs
        :return: report url or error message
        :rtype: str
        """
        result = SMCRequest(method="get", params={"engine_node_key": engine_key,
                                                  "file_id": file_id},
                            href=fetch_entry_point("sandbox_report_permalink")).read()
        if result.code == 200:
            return result.json['value']
        else:
            return result.msg

    def __repr__(self):
        return "{0}(enabled={1})".format(self.__class__.__name__, self.status)


class TLSInspection(object):
    """
    TLS Inspection settings control settings for doing inbound
    TLS decryption and outbound client TLS decryption. This
    provides an interface to manage TLSServerCredentials and
    TLSClientCredentials assigned to the engine.

    .. note:: You must call engine.update() to commit any changes.
    """

    def __init__(self, engine):
        self.engine = engine

    @property
    def server_credentials(self):
        """
        Return a list of assigned (if any) TLSServerCredentials
        assigned to this engine.

        :rtype: list(TLSServerCredential)
        """
        return [Element.from_href(credential) for credential in self.engine.server_credential]

    def add_tls_credential(self, credentials):
        """
        Add a list of TLSServerCredential to this engine.
        TLSServerCredentials can be in element form or can also
        be the href for the element.

        :param credentials: list of pre-created TLSServerCredentials
        :type credentials: list(str,TLSServerCredential)
        :return: None
        """
        for cred in credentials:
            href = element_resolver(cred)
            if href not in self.engine.server_credential:
                self.engine.server_credential.append(href)

    def remove_tls_credential(self, credentials):
        """
        Remove a list of TLSServerCredentials on this engine.

        :param credentials: list of credentials to remove from the
            engine
        :type credentials: list(str,TLSServerCredential)
        :return: None
        """
        for cred in credentials:
            href = element_resolver(cred)
            if href in self.engine.server_credential:
                self.engine.server_credential.remove(href)


class ZTNAConnector:
    """
    Enable ZTNA Connector on the engine.

        engine.ztna_connector.enable(bgkey="xxx:yyy:zzz", datacenter="ddd")
        engine.update()

    Disable ZTNA Connector:

        engine.ztna_connector.disable()
        engine.update()

    .. note:: You must call engine.update() to commit any changes.
    """

    def __init__(self, engine):
        self.engine = engine

    def enable(self, bgkey, datacenter, auto_update):
        """
        Enable ZTNA Connector on the engine.

        :param str bgkey: connector installer key
        :param str datacenter: datacenter accessed via this connector
        :param bool auto_update: install automatically the latest version
        """
        self.engine.data.update(ztna_connector_settings={
            "bgkey": bgkey,
            "datacenter": datacenter,
            "auto_update": auto_update
        })

    def disable(self):
        """
        Disable ZTNA Connector on the engine.
        """
        self.engine.data.pop("ztna_connector_settings", None)

    @property
    def status(self):
        """
        Return the status (enabled/disabled) of ZTNA Connector on the engine

        :rtype: bool
        """
        return "ztna_connector_settings" in self.engine.data

    @property
    def bgkey(self):
        "get ztna installation key or None"
        if not self.status:
            return None
        settings = self.engine.data.get("ztna_connector_settings")
        return settings.get("bgkey")

    @property
    def datacenter(self):
        "get ztna datacenter or None"
        if not self.status:
            return None
        settings = self.engine.data.get("ztna_connector_settings")
        return settings.get("datacenter")

    @property
    def auto_update(self):
        "get ztna auto_update or None"
        if not self.status:
            return None
        settings = self.engine.data.get("ztna_connector_settings")
        return settings.get("auto_update")

    def __repr__(self):
        return "{0}(enabled={1})".format(self.__class__.__name__, self.status)


class ClientInspection(object):
    def __init__(self, engine):
        self.engine = engine

    @property
    def status(self):
        """
        Whether client based decryption is enabled or disabled.

        :rtype: bool
        """
        if is_api_version_less_than('7.0'):
            return self.engine.tls_client_protection is not None \
                   and len(self.engine.tls_client_protection) > 0
        else:
            return self.engine.tls_client_protection is not None

    def enable(self, ca_for_signing, tls_trusted_ca_tags=None, tls_trusted_cas=None):
        """
        Enable client decryption. Provide a valid client protection
        CA that the engine will use to decrypt.

        :param ca_for_signing: tls_signing_certificate_authority
        :param tls_trusted_ca_tags: optional trusted_ca_tag array
        :param tls_trusted_cas: optional tls_certificate_authority array
        :return: None
        """
        assert ca_for_signing is not None, "Please provide a ClientProtectionCA!"

        if not tls_trusted_cas and not tls_trusted_ca_tags:
            # put as default all trusted ca tags
            tls_trusted_ca_tags = [TrustedCATag('All Trusted CAs')]

        if is_api_version_less_than('7.0'):
            self.engine.data.update(tls_client_protection=[
                {'ca_for_signing_ref': element_resolver(ca_for_signing),
                 'tls_trusted_ca_tag_ref': element_resolver(tls_trusted_ca_tags),
                 'tls_trusted_ca_ref': element_resolver(tls_trusted_cas),
                 'proxy_usage': 'tls_inspection'}])
        else:
            self.engine.data.update(tls_client_protection={
                'ca_for_signing_ref': element_resolver(ca_for_signing),
                'tls_trusted_ca_tag_ref': element_resolver(tls_trusted_ca_tags),
                'tls_trusted_ca_ref': element_resolver(tls_trusted_cas),
                'proxy_usage': 'tls_inspection'})

    def disable(self):
        """
        Disable client decryption.

        :return: None
        """
        self.engine.data.update(tls_client_protection=None)

    @property
    def ca_for_signing(self):
        """
        Return the Client Protection Certificate Authority assigned
        to this engine. The CA is used to provide decryption services
        to outbound client connections.

        :rtype: ClientProtectionCA or None if not defined
        """
        if self.status:
            if is_api_version_less_than('7.0'):
                return Element.from_href(self.engine
                                         .tls_client_protection[0]['ca_for_signing_ref'])
            else:
                return Element.from_href(self.engine
                                         .tls_client_protection['ca_for_signing_ref'])
        else:
            return None

    @property
    def tls_trusted_ca_tags(self):
        """
        Return the TLS trusted CA tags.

        :rtype: TrustedCATag array or [] if not defined
        """
        if self.status:
            if is_api_version_less_than('7.0'):
                return [Element.from_href(tag)
                        for tag in self.engine.tls_client_protection[0]['tls_trusted_ca_tag_ref']]
            else:
                return [Element.from_href(tag)
                        for tag in self.engine.tls_client_protection['tls_trusted_ca_tag_ref']]
        else:
            return []

    @property
    def tls_trusted_cas(self):
        """
        Return the TLS trusted CAs.

        :rtype: TLSCertificateAuthority array or [] if not defined
        """
        if self.status:
            if is_api_version_less_than('7.0'):
                return [Element.from_href(ca)
                        for ca in self.engine.tls_client_protection[0]['tls_trusted_ca_ref']]
            else:
                return [Element.from_href(ca)
                        for ca in self.engine.tls_client_protection['tls_trusted_ca_ref']]
        else:
            return []

    def __str__(self):
        return 'ClientInspection for {}'.format(self.engine.name)


class EndpointIntegration(NestedDict):
    """
    Engine ECA settings..

        engine.EndpointIntegration.enable(
            license_key='123',
            license_token='456',
            http_proxy=[HttpProxy('myproxy')])

    .. note:: You must call engine.update() to commit any changes.
    """

    def __init__(self, engine):
        self.engine = engine
        eca = engine.data.get("eca_settings", {})
        super(EndpointIntegration, self).__init__(data=eca)

    @property
    def status(self):
        """
        Status of Endpoint Integration on this engine

        :rtype: bool
        """
        if "eca_settings" in self.engine.data:
            return True
        return False

    def disable(self):
        """
        Disable the Endpoint Integration on this engine.
        """
        self.engine.data.pop("eca_settings", None)

    def enable(
            self,
            eca_client_config=None,
            eca_client_network_ref=None,
            eca_server_network_ref=None,
            enabled_interface=None,
            listened_zone_ref=None,
            listening_port=9111,
    ):
        """
        Enable Endpoint Integration with Forcepoint Endpoint Context Agent
        on this engine.
        :param str eca_client_config: name of ECA client configuration
        :param list eca_client_network_ref: List of source network or zone
        :param list eca_server_network_ref: List of destination network or zone
        :param list enabled_interface: List of listening interfaces (nic id and address)
        :param list listened_zone_ref: List of zones to listen on
        :param int listening_port: default 9111
        :return: None
        """
        eca_client_config_ref = element_resolver(eca_client_config)
        eca_client_network_ref_list = []
        eca_server_network_ref_list = []
        listened_zone_ref_list = []
        if eca_client_network_ref is not None:
            for e in eca_client_network_ref:
                i = element_resolver(e)
                eca_client_network_ref_list.append(i)
        if eca_server_network_ref is not None:
            for e in eca_server_network_ref:
                i = element_resolver(e)
                eca_server_network_ref_list.append(i)
        if listened_zone_ref is not None:
            for e in listened_zone_ref:
                i = element_resolver(e)
                listened_zone_ref_list.append(i)
        self.update(
            eca_client_config=eca_client_config_ref,
            eca_client_network_ref=eca_client_network_ref_list,
            eca_server_network_ref=eca_server_network_ref_list,
            enabled_interface=enabled_interface,
            listened_zone_ref=listened_zone_ref_list,
            listening_port=listening_port,
        )

        self.engine.data.setdefault("eca_settings", {}).update(self.data)

    @property
    def eca_client_config(self):
        """
        Return eca_client_config that is configured for ECA.
        :return: eca_client_config object
        :rtype: object(eca_client_config)
        """
        config = self.get("eca_client_config")
        return Element.from_href(config)

    def __repr__(self):
        return "{0}(enabled={1})".format(self.__class__.__name__, self.status)
