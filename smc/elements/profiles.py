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
from smc.api.exceptions import ElementNotFound, UnsupportedAttribute
from smc.base.util import element_resolver
from smc.compat import is_smc_version_less_than


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
        trap_user_names=[],
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
        }

        return ElementCreator(cls, json)


class SandboxService(Element):
    typeof = "sandbox_service"

    @classmethod
    def create(cls, name, sandbox_data_center, portal_username=None, comment=None):
        """
        Create a Sandbox Service element
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


class UserIDService(Element):
    """
    Represents a User ID Service element.
    """
    typeof = "user_id_service"

    @classmethod
    def create(
            cls,
            name,
            address=None,
            cache_expiration=300,
            connect_timeout=10,
            monitored_user_domains=None,
            netflow=False,
            snmp_trap=False,
            tls_field="DNSName",
            tls_value=None,
            tls_profile=None,
            port=5000,
            address_list=None,
            encoding="UTF-8",
            logging_profile=None,
            monitoring_log_server=None,
            probing_profile=None,
            time_zone="Europe/Paris",
            comment=None
    ):
        """
        :param str name: Name of user id service.
        :param str address: IP addresses to contact the User ID Service.
        :param int cache_expiration: The time in seconds for the cache expiration on the engine.
        :param int connect_timeout: The time in seconds for the connection from the engine to time
        out.
        :param List monitored_user_domains: Specific user domains to check. If not defined, it uses
        all known user domains by User ID service.
        :param bool netflow: Activates NetFlow (v6 and v16) and IPFIX (NetFlow v20) data reception
        from this device.
        :param bool snmp_trap: Activates SNMP trap reception from this device. The data that the
        device sends must be formatted according to the MIB definitions currently active in the
        system.
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
        :param encoding:
        :param ThirdPartyLoggingProfile logging_profile: Activates syslog reception from this device
        You must select the Logging Profile that contains the definitions for converting the syslog
        entries to log entries.You must also select the Time Zone in which the device is located.
        By default, the local time zone of the computer you are using is selected
        :param LogServer monitoring_log_server: Monitoring Log Server that monitors this device
        (third-party monitoring).You must select a Log Server to activate the other options.
        :param probing_profile: Activates status monitoring for this device. You must also select
        the Probing Profile that contains the definitions for the monitoring. When you select this
        option, the element is added to the tree in the System Status view.
        :param time_zone:
        :param str comment: comment
        :return UserIDService
        """
        json = {
            "name": name,
            "monitored_user_domains": monitored_user_domains,
            "address": address,
            "cache_expiration": cache_expiration,
            "connect_timeout": connect_timeout,
            "port": port,
            "list": address_list,
            "tls_identity": {"tls_field": tls_field,
                             "tls_value": tls_value
                             },
            "tls_profile": element_resolver(tls_profile),
            "third_party_monitoring": {
                "encoding": encoding,
                "logging_profile_ref": element_resolver(logging_profile),
                "monitoring_log_server_ref": element_resolver(monitoring_log_server),
                "probing_profile_ref": element_resolver(probing_profile),
                "netflow": netflow,
                "time_zone": time_zone,
                "snmp_trap": snmp_trap
            },
            "comment": comment,
        }

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
    def address(self):
        """
        IP addresses to contact the User ID Service.
        """
        return self.data.get("address")

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

    @property
    def third_party_monitoring(self):
        """
        This represents Monitoring Settings for Third Party Monitoring.
        """
        return self.data.get("third_party_monitoring")
