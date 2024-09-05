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
Profiles are templates used in other parts of the system to provide default
functionality for specific feature sets. For example, to enable DNS Relay on
an engine you must specify a DNSRelayProfile to use which defines the common
settings (or sub-settings) for that feature.

A DNS Relay Profile allows multiple DNS related mappings that can be configured.
Example usage::

    >>> from smc.elements.profiles import DNSRelayProfile
    >>> profile = DNSRelayProfile('mynewprofile')

.. note:: If the DNSRelayProfile does not exist, it will automatically be
    created when a DNS relay rule is added to the DNSRelayProfile instance.

Add a fixed domain answer rule::

    >>> profile.fixed_domain_answer.add([('microsoft3.com', 'foo.com'), ('microsoft4.com',)])
    >>> profile.fixed_domain_answer.all()
    [{u'domain_name': u'microsoft3.com', u'translated_domain_name': u'foo.com'},
    {u'domain_name': u'microsoft4.com'}]

Translate hostnames (not fqdn) to a specific IP address::

    >>> profile.hostname_mapping.add([('hostname1,hostname2', '1.1.1.12')])
    >>> profile.hostname_mapping.all()
    [{u'hostnames': u'hostname1,hostname2', u'ipaddress': u'1.1.1.12'}]

Translate an IP address to another::

    >>> profile.dns_answer_translation.add([('12.12.12.12', '172.18.1.20')])
    >>> profile.dns_answer_translation.all()
    [{u'translated_ipaddress': u'172.18.1.20', u'original_ipaddress': u'12.12.12.12'}]

Specify a DNS server to handle specific domains::

    >>> profile.domain_specific_dns_server.add([('myfoo.com', '172.18.1.20')])
    >>> profile.domain_specific_dns_server.all()
    [{u'dns_server_addresses': u'172.18.1.20', u'domain_name': u'myfoo.com'}]

"""
from smc.base.model import Element, ElementCreator
from smc.api.exceptions import ElementNotFound, UnsupportedAttribute, UnsupportedSMCVersion
from smc.base.structs import NestedDict
from smc.base.util import element_resolver
from smc.compat import is_smc_version_less_than
from smc.elements.common import MultiContactServer


class DNSRule(object):
    """
    DNSRule is the parent class for all DNS relay rules.
    """

    __slots__ = "profile"

    def __init__(self, profile):
        self.profile = profile

    def add(self, instance, answers):
        key, left, right = instance._attr
        json = [dict(zip([left, right], d)) for d in answers]
        try:
            self.profile.data[key].extend(json)
            self.profile.update()
        except ElementNotFound:
            j = {"name": self.profile.name, key: json}
            return ElementCreator(self.profile.__class__, j)

    def all(self):
        """
        Return all entries

        :rtype: list(dict)
        """
        attribute = self._attr[0]
        return self.profile.data.get(attribute, [])


class FixedDomainAnswer(DNSRule):
    """
    Direct requests for specific domains to IPv4 addresses, IPv6
    addresses, fully qualified domain names (FQDNs), or empty DNS replies
    """

    _attr = ("fixed_domain_answer", "domain_name", "translated_domain_name")

    def add(self, answers):
        """
        Add a fixed domain answer. This should be a list of
        two-tuples, the first entry is the domain name, and
        the second is the translated domain value::

            profile = DNSRelayProfile('dnsrules')
            profile.fixed_domain_answer.add([
                ('microsoft.com', 'foo.com'), ('microsoft2.com',)])

        :param answers: (domain_name, translated_domain_name)
        :type answers: tuple[str, str]
        :raises UpdateElementFailed: failure to add to SMC
        :return: None

        .. note:: translated_domain_name can be none, which will cause
            the NGFW to return NXDomain for the specified domain.
        """
        super(FixedDomainAnswer, self).add(self, answers)


class HostnameMapping(DNSRule):
    """
    Statically map host names, aliases for host names, and unqualified
    names (a host name without the domain suffix) to IPv4 or IPv6
    addresses
    """

    _attr = ("hostname_mapping", "hostnames", "ipaddress")

    def add(self, answers):
        """
        Map specific hostname to specified IP address. Provide a list
        of two-tuples. The first entry is the hostname/s to translate
        (you can provide multiple comma separated values). The second
        entry should be the IP address to map the hostnames to::

            profile = DNSRelayProfile('dnsrules')
            profile.hostname_mapping.add([('hostname1,hostname2', '1.1.1.1')])

        :param answers: (hostnames, ipaddress), hostnames can be a
            comma separated list.
        :type answers: tuple[str, str]
        :raises UpdateElementFailed: failure to add to SMC
        :return: None
        """
        super(HostnameMapping, self).add(self, answers)


class DomainSpecificDNSServer(DNSRule):
    """
    Forward DNS requests to different DNS servers based on
    the requested domain.
    """

    _attr = ("domain_specific_dns_server", "domain_name", "dns_server_addresses")

    def add(self, answers):
        """
        Relay specific domains to a specified DNS server. Provide
        a list of two-tuple with first entry the domain name to relay
        for. The second entry is the DNS server that should handle the
        query::

            profile = DNSRelayProfile('dnsrules')
            profile.domain_specific_dns_server.add([('myfoo.com', '172.18.1.20')])

        :param answers: (domain_name, dns_server_addresses), dns server
            addresses can be a comma separated string
        :type answers: tuple[str, str]
        :raises UpdateElementFailed: failure to add to SMC
        :return: None
        """
        super(DomainSpecificDNSServer, self).add(self, answers)


class DNSAnswerTranslation(DNSRule):
    """
    Map IPv4 addresses resolved by external DNS servers to IPv4
    addresses in the internal network.
    """

    _attr = ("dns_answer_translation", "original_ipaddress", "translated_ipaddress")

    def add(self, answers):
        """
        Takes an IPv4 address and translates to a specified IPv4 value.
        Provide a list of two-tuple with the first entry providing the
        original address and second entry specifying the translated address::

            profile = DNSRelayProfile('dnsrules')
            profile.dns_answer_translation.add([('12.12.12.12', '172.18.1.20')])

        :param answers: (original_ipaddress, translated_ipaddress)
        :type answers: tuple[str, str]
        :raises UpdateElementFailed: failure to add to SMC
        :return: None
        """
        super(DNSAnswerTranslation, self).add(self, answers)


class DNSRelayProfile(Element):
    """
    DNS Relay Settings specify a profile to handle how the engine will
    interpret DNS queries. The engine can act as a DNS relay, rewrite
    DNS queries or redirect domains to the specified DNS servers.
    """

    typeof = "dns_relay_profile"

    @property
    def fixed_domain_answer(self):
        """
        Add a fixed domain answer entry.

        :rtype: FixedDomainAnswer
        """
        return FixedDomainAnswer(self)

    @property
    def hostname_mapping(self):
        """
        Add a hostname to IP mapping

        :rtype: HostnameMapping
        """
        return HostnameMapping(self)

    @property
    def domain_specific_dns_server(self):
        """
        Add domain to DNS server mapping

        :rtype: DomainSpecificDNSServer
        """
        return DomainSpecificDNSServer(self)

    @property
    def dns_answer_translation(self):
        """
        Add a DNS answer translation

        :rtype: DNSAnswerTranslation
        """
        return DNSAnswerTranslation(self)


class SNMPAgent(Element):
    """
    Minimal implementation of SNMPAgent
    """

    typeof = "snmp_agent"

    @classmethod
    def create(
            cls,
            name,
            snmp_users=[],
            trap_destinations=[],
            snmp_monitoring_contact=None,
            snmp_monitoring_listening_port=161,
            snmp_version="v3",
            monitoring_user_names=[],
            trap_user_name=None,
            comment=None,
    ):
        json = {
            "boot": False,
            "go_offline": False,
            "go_online": False,
            "hardware_alerts": False,
            "name": name,
            "policy_applied": False,
            "shutdown": False,
            "snmp_monitoring_contact": snmp_monitoring_contact,
            "snmp_monitoring_listening_port": snmp_monitoring_listening_port,
            "snmp_monitoring_user_name": monitoring_user_names,
            "snmp_trap_destination": trap_destinations,
            "snmp_user_name": snmp_users,
            "snmp_version": snmp_version,
            "user_login": False,
            "snmp_trap_user_name": trap_user_name,
            "comment": comment
        }

        return ElementCreator(cls, json)


class SandboxService(Element):
    typeof = "sandbox_service"

    @classmethod
    def create(cls, name, sandbox_data_center, portal_username=None, comment=None):
        """
        Create a Sandbox Service element
        :param str name: name of Sandbox Service, if custom must be the same as data center
        :param str,SandboxDataCenter sandbox_data_center: Object or name of sandbox data center
        :param str portal_username: the username of the portal
        :param str comment: optional comment for service
        :raises CreateElementFailed: failure creating element with reason
        :return: instance with meta
        :rtype: SandboxService
        """
        json = {
            "name": name,
            "sandbox_data_center": element_resolver(sandbox_data_center),
            "portal_username": portal_username if portal_username else "",
            "comment": comment,
        }
        return ElementCreator(cls, json)

    @property
    def sandbox_license_key(self):
        """
        Sandbox License Key.
        :rtype: str
        """
        return self.data.get("sandbox_license_key")

    @property
    def sandbox_license_token(self):
        """
        License Token.
        :rtype: str
        """
        return self.data.get("sandbox_license_token")

    @property
    def sandbox_data_center(self):
        """
        Sandbox Data Center
        :rtype: SandboxDataCenter
        """
        return self.from_href(self.data.get("sandbox_data_center"))


class SandboxDataCenter(Element):
    typeof = "sandbox_data_center"
    """
    Create a Sandbox Data Center element
    :param str name: name of Sandbox Data Center
    :param str hostname: The host name of the sandbox server.
    :param str,TlsProfile Name or Object of Tls profile used
    :param str api_key: The api key for sandbox datacenter
    :param str api_url: The api url for sandbox datacenter
    :param str portal_url: optional portal_url for the sandbox datacenter
    :param str comment: optional comment for service
    :raises CreateElementFailed: failure creating element with reason
    :return: instance with meta
    :rtype: SandboxDataCenter
    """

    @classmethod
    def create(cls, name, hostname, tls_profile, sandbox_type=None, api_key=None, api_url=None,
               portal_url=None, comment=None):
        """
        Create a Sandbox Datacenter element
        """
        json = {
            "name": name,
            "hostname": hostname,
            "tls_profile": element_resolver(tls_profile),
            "api_key": api_key,
            "api_url": api_url if api_url else "",
            "portal_url": portal_url if portal_url else "",
            "comment": comment,
        }
        # api_key is available started 7.1
        if not is_smc_version_less_than("7.1"):
            json.update(api_key=api_key)
            json.update(sandbox_type=sandbox_type)
            return ElementCreator(cls, json)
        else:
            raise UnsupportedSMCVersion("Sandbox Datacenter only permitted in smc version > 7.1")

    @property
    def hostname(self):
        """Sandbox Service Hostname"""
        return self.data.get("hostname")

    @property
    def server_url(self):
        """Sandbox Data Center Server URL"""
        return self.data.get("server_url")

    @property
    def portal_url(self):
        """Sandbox Data Center Portal URL"""
        return self.data.get("portal_url")

    @property
    def api_url(self):
        """Sandbox Data Center API URL."""
        return self.data.get("api_url")

    @property
    def sandbox_type(self):
        """
        Sandbox Data Center Type.
            1. forcepoint_sandbox
            2. cloud_sandbox or local_sandbox
        """
        if is_smc_version_less_than("7.1"):
            raise UnsupportedAttribute("Unsupported Attribute, sandbox_type is available in "
                                       "smc version > 7.1")
        return self.data.get("sandbox_type")

    @property
    def tls_profile(self):
        """Represents a TLS Profile."""
        return self.from_href(self.data.get("tls_profile"))

    @property
    def api_key(self):
        """Sandbox Data Center API Key"""
        if is_smc_version_less_than("7.1"):
            raise UnsupportedAttribute("Unsupported Attribute, sandbox_type is available in "
                                       "smc version > 7.1")
        return self.data.get("api_key")


class UserIDService(Element, MultiContactServer):
    """
    Represents a User ID Service element.
    """
    typeof = "user_id_service"

    @classmethod
    def create(
            cls,
            name,
            address=None,
            ipv6_address=None,
            cache_expiration=300,
            connect_timeout=10,
            monitored_user_domains=None,
            tls_field="DNSName",
            tls_value=None,
            tls_profile=None,
            port=5000,
            address_list=None,
            third_party_monitoring=None,
            comment=None
    ):
        """
        :param str name: Name of user id service.
        :param str address: IP addresses to contact the User ID Service.
        :param str ipv6_address: Single valid IPv6 address to contact the User ID Service.
        :param int cache_expiration: The time in seconds for the cache expiration on the engine.
        :param int connect_timeout: The time in seconds for the connection from the engine to time
        out.
        :param List monitored_user_domains: Specific user domains to check. If not defined, it uses
        all known user domains by User ID service.
        :param str tls_field: This id field from Field/value pair used to insure server identity
        when connecting to User ID service using TLS.
        :param str tls_value: This id value from Field/value pair used to insure server identity
        when connecting to User ID service using TLS
        :param TLSProfile tls_profile: TLS information required to establish TLS connection to the
        User ID service.
        :param int port: The port on which the User ID Service communicates with the Firewall. If
        you change the port from the default, you must configure the same port in the User ID
        Service Properties on the Windows system. You must also change the rule that allows
        communication between the Firewall and the User ID Service.
        :param List address_list: List of additional IP addresses to contact the User ID Service.
        You can add several IPv4 and IPv6 addresses (one by one).
        You must select the Logging Profile that contains the definitions for converting the syslog
        entries to log entries.You must also select the Time Zone in which the device is located.
        By default, the local time zone of the computer you are using is selected
        :param ThirdPartyMonitoring third_party_monitoring: The optional Third Party Monitoring
            configuration.
        :param str comment: comment
        :return UserIDService
        """
        json = {
            "name": name,
            "monitored_user_domains": monitored_user_domains,
            "address": address,
            "ipv6_address": ipv6_address,
            "cache_expiration": cache_expiration,
            "connect_timeout": connect_timeout,
            "port": port,
            "list": address_list,
            "tls_identity": {"tls_field": tls_field,
                             "tls_value": tls_value
                             },
            "tls_profile": element_resolver(tls_profile),
            "comment": comment,
        }
        if third_party_monitoring:
            json.update(third_party_monitoring=third_party_monitoring.data)
        return ElementCreator(cls, json)

    @property
    def tls_profile(self):
        """Represents a TLS Profile."""
        return self.from_href(self.data.get("tls_profile"))

    @property
    def tls_identity(self):
        """
        Field/value pair used to insure server identity when connecting to User ID service using TLS
        """
        return self.data.get("tls_identity")

    @property
    def monitored_user_domains(self):
        """
        Specific user domains to check. If not defined, it uses all known user domains by User ID
        service.
        """
        return self.data.get("monitored_user_domains")

    @property
    def cache_expiration(self):
        """
        The time in seconds for the cache expiration on the engine.
        """
        return self.data.get("cache_expiration")

    @property
    def connect_timeout(self):
        """
        The time in seconds for the connection from the engine to time out.
        """
        return self.data.get("connect_timeout")

    @property
    def port(self):
        """
        The port on which the User ID Service communicates with the Firewall.
        """
        return self.data.get("port")

    @property
    def list(self):
        """
        List of additional IP addresses to contact the User ID Service.
        """
        return self.data.get("list")


class UserResponseEntry(NestedDict):
    """
    This represents an entry in a User Response.
    """

    def __init__(self, data):
        super(UserResponseEntry, self).__init__(data)

    @classmethod
    def create(
            cls,
            reason=None,
            response_type=None,
            user_response_text=None,
            user_response_message=None,
            user_response_title=None,
            redirect=None
    ):
        """
        :param str reason: Reason for sending a response one from given below.
            1. conn_blacklisted
            2. conn_not_allowed
            3. deep_inspection
            4. url_not_allowed
            5. virus_found
            6. blocked_by_dlp
        :param str response_type: Type of response.
            1. tcp_close
            2. response_page
            3. html_page
            4. url_redirect
        :param str user_response_text: Html user response to be sent.
        :param str user_response_message: The user response message.
        :param str user_response_title: User response title.
        :param str redirect: For URL redirect response: automatic or manual redirection.
        :return UserResponseEntry
        """
        json = {
            "reason": reason,
            "type": response_type,
            "user_response_text": user_response_text,
            "user_response_message": user_response_message,
            "user_response_title": user_response_title,
            "redirect": redirect
        }
        return cls(json)


class UserResponse(Element):
    """
    This represents a User Response. It defines additional notification actions for rule matches,
    such as redirecting access to a forbidden URL to a page on an internal web server instead.
    """
    typeof = "user_response"

    @classmethod
    def create(
            cls,
            name,
            user_response_entry=None,
            comment=None
    ):
        """
        :param str name: Name of user id service.
        :param list(UserResponseEntry) user_response_entry: This represents an entry in a User
            Response.
        :param str comment: Optional comment.
        :return UserResponse
        """
        json = {
            "name": name,
            "user_response_entry": user_response_entry,
            "comment": comment
        }
        return ElementCreator(cls, json)

    @property
    def user_response_entry(self):
        """
        This represents an entry in a User Response.
        :rtype: list(UserResponseEntry)
        """
        return [UserResponseEntry(response) for response in
                self.data.get("user_response_entry", [])]


class WebAuthHtmlPage(Element):
    """
    Represents the Browser-Based User Authentication HTML Page in case of not authorized page.
    """
    typeof = "web_authentication_page"


class CustomPropertiesProfile(Element):
    """
    This represents a Custom Properties Profile Element
    """
    typeof = "custom_properties_profile"

    @classmethod
    def create(
            cls,
            name,
            custom_property=None,
            property_type="custom",
            comment=None
    ):
        """
        :param str name: Name of custom property profile.
        :param list(custom_property) custom_property: List of properties.
        :param str property_type: Template used by the profile
            possible values are:
                1. azure: Dedicated profile for Azure. Contains a specific script to resolve FQDN.
                    No other properties are needed.
                2. custom: Customizable profile. (used for AWS) User may provide a custom script and
                    sets custom properties.
        :param str comment: Optional comment.
        :return CustomPropertiesProfile
        """

        json = {
            "name": name,
            "custom_property": custom_property,
            "type": property_type,
            "comment": comment
        }
        return ElementCreator(cls, json)

    @property
    def custom_script(self):
        """
        Instance of custom script.
        """
        return CustomScript(self)

    @property
    def custom_property(self):
        """
        Return list custom properties.
        :rtype: dict
        """
        return self.data.get("custom_property", [])


class CustomScript(object):

    def __init__(self, custom_script_profile):
        """
        This defines custom script operation.
        :param CustomPropertiesProfile custom_script_profile: Instance of CustomPropertiesProfile.
        """
        self.custom_script_profile = custom_script_profile

    def _import(self, custom_script_file_name):
        """
        Import a specified custom script for the specified custom properties profile element.
        :param str script_name: The script name to be used to upload the script to the engine file
            system.
        :param str custom_script_file_name: Custom script file path to be imported.
        """
        with open(custom_script_file_name, "rb") as file:
            self.custom_script_profile.make_request(
                method="update",
                resource="custom_script",
                files={"custom_script": file},
                raw_result=True,
            )

    def delete(self):
        """
        Deletes custom script from custom properties profile.
        """
        self.custom_script_profile.make_request(
            method="delete",
            resource="custom_script"
        )

    def export(self, file_name):
        """
        Export compressed file of custom script.
        :param str file_name: Custom script with file name in custom properties profile.
        """
        self.custom_script_profile.make_request(
            resource="custom_script",
            filename=file_name,
            raw_result=True,
        )
