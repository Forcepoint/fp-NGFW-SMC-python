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
VPN Elements are used in conjunction with Policy or Route Based VPN configurations.
VPN elements consist of external gateway and VPN site settings that identify 3rd party
gateways to be used as a VPN termination endpoint.

There are several ways to create an external gateway configuration.
A step by step process which first creates a network element to be used in a
VPN site, then creates the ExternalGatway, an ExternalEndpoint for the gateway,
and inserts the VPN site into the configuration::

    Network.create(name='mynetwork', ipv4_network='172.18.1.0/24')
    gw = ExternalGateway.create(name='mygw')
    gw.external_endpoint.create(name='myendpoint', address='10.10.10.10')
    gw.vpn_site.create(name='mysite', site_element=[Network('mynetwork')])

You can also use the convenience method `update_or_create` on the ExternalGateway
to fully provision in a single step. Note that the ExternalEndpoint and VPNSite also
have an `update_or_create` method to limit the update to those respective
configurations (SMC version 6.4.x)::

    >>> from smc.elements.network import Network
    >>> from smc.vpn.elements import ExternalGateway
    >>> network = Network.get_or_create(name='network-172.18.1.0/24', ipv4_network='172.18.1.0/24')
    >>>
    >>> g = ExternalGateway.update_or_create(name='newgw',
        external_endpoint=[
            {'name': 'endpoint1', 'address': '1.1.1.1', 'enabled': True},
            {'name': 'endpoint2', 'address': '2.2.2.2', 'enabled': True}],
        vpn_site=[{'name': 'sitea', 'site_element':[network]}])
    >>> g
    ExternalGateway(name=newgw)
    >>> for endpoint in g.external_endpoint:
    ...   endpoint
    ...
    ExternalEndpoint(name=endpoint1 (1.1.1.1))
    ExternalEndpoint(name=endpoint2 (2.2.2.2))
    >>> for site in g.vpn_site:
    ...   site, site.site_element
    ...
    (VPNSite(name=sitea), [Network(name=network-172.18.1.0/24)])

In SMC version >= 6.5, you can also provide the `connection_type_ref` parameter when defining
the external gateway::


    .. note:: When calling `update_or_create` from the ExternalGateway, providing the
        parameters for external_endpoints and vpn_site is optional.

"""

from smc.api.exceptions import ElementNotFound
from smc.base.model import SubElement, Element, ElementRef, ElementCreator
from smc.base.collection import create_collection
from smc.base.util import element_resolver, element_default
from smc.elements.helpers import location_helper
from smc.base.structs import SerializedIterable
from smc.elements.other import ContactAddress, Location


class GatewaySettings(Element):
    """
    Gateway settings define various VPN related settings that
    are applied at the firewall level such as negotiation
    timers and mobike settings. A gateway setting is a property
    of an engine::

        engine = Engine('myfw')
        engine.vpn.gateway_settings
    """

    typeof = "gateway_settings"

    @classmethod
    def create(
        cls,
        name,
        negotiation_expiration=200000,
        negotiation_retry_timer=500,
        negotiation_retry_max_number=32,
        negotiation_retry_timer_max=7000,
        certificate_cache_crl_validity=90000,
        mobike_after_sa_update=False,
        mobike_before_sa_update=False,
        mobike_no_rrc=True,
    ):
        """
        Create a new gateway setting profile.

        :param str name: name of profile
        :param int negotiation_expiration: expire after (ms)
        :param int negotiation_retry_timer: retry time length (ms)
        :param int negotiation_retry_max_num: max number of retries allowed
        :param int negotiation_retry_timer_max: maximum length for retry (ms)
        :param int certificate_cache_crl_validity: cert cache validity (seconds)
        :param boolean mobike_after_sa_update: Whether the After SA flag is set
            for Mobike Policy
        :param boolean mobike_before_sa_update: Whether the Before SA flag is
            set for Mobike Policy
        :param boolean mobike_no_rrc: Whether the No RRC flag is set for
            Mobike Policy
        :raises CreateElementFailed: failed creating profile
        :return: instance with meta
        :rtype: GatewaySettings
        """
        json = {
            "name": name,
            "negotiation_expiration": negotiation_expiration,
            "negotiation_retry_timer": negotiation_retry_timer,
            "negotiation_retry_max_number": negotiation_retry_max_number,
            "negotiation_retry_timer_max": negotiation_retry_timer_max,
            "certificate_cache_crl_validity": certificate_cache_crl_validity,
            "mobike_after_sa_update": mobike_after_sa_update,
            "mobike_before_sa_update": mobike_before_sa_update,
            "mobike_no_rrc": mobike_no_rrc,
        }

        return ElementCreator(cls, json)


class GatewayProfile(Element):
    """
    Gateway Profiles describe the capabilities of a Gateway, i.e. supported
    cipher, hash, etc. Gateway Profiles of Internal Gateways are read-only
    and computed from the firewall version and FIPS mode.
    Gateway Profiles of External Gateways are user-defined.
    """

    typeof = "gateway_profile"

    @classmethod
    def create(cls, name, capabilities=None, comment=None):
        """
        Create new GatewayProfile
        :param str name: name of the gateway profile.
        :param dict capabilities: Capabilities are all boolean values that specify features or
        cryptography features to enable or disable on this gateway profile.
        Following additional boolean attributes can be set:
            sha2_ike_hash_length
            sha2_ipsec_hash_length
            aes128_for_ike
            aes128_for_ipsec
            aes256_for_ike
            aes256_for_ipsec
            aes_gcm_256_for_ipsec
            aes_gcm_for_ipsec
            aes_xcbc_for_ipsec
            aggressive_mode
            ah_for_ipsec
            blowfish_for_ike
            blowfish_for_ipsec
            des_for_ike
            des_for_ipsec
            dh_group_14_for_ike
            dh_group_15_for_ike
            dh_group_16_for_ike
            dh_group_17_for_ike
            dh_group_18_for_ike
            dh_group_19_for_ike
            dh_group_1_for_ike
            dh_group_20_for_ike
            dh_group_21_for_ike
            dh_group_2_for_ike
            dh_group_5_for_ike
            dss_signature_for_ike
            ecdsa_signature_for_ike
            esp_for_ipsec
            external_for_ipsec
            forward_client_vpn
            forward_gw_to_gw_vpn
            ike_v1
            ike_v2
            ipcomp_deflate_for_ipsec
            main_mode
            md5_for_ike
            md5_for_ipsec
            null_for_ipsec
            pfs_dh_group_14_for_ipsec
            pfs_dh_group_15_for_ipsec
            pfs_dh_group_16_for_ipsec
            pfs_dh_group_17_for_ipsec
            pfs_dh_group_18_for_ipsec
            pfs_dh_group_19_for_ipsec
            pfs_dh_group_1_for_ipsec
            pfs_dh_group_20_for_ipsec
            pfs_dh_group_21_for_ipsec
            pfs_dh_group_2_for_ipsec
            pfs_dh_group_5_for_ipsec
            pre_shared_key_for_ike
            rsa_signature_for_ike
            sa_per_host
            sa_per_net
            sha1_for_ike
            sha1_for_ipsec
            sha2_for_ike
            sha2_for_ipsec
            triple_des_for_ike
            triple_des_for_ipsec
            vpn_client_dss_signature_for_ike
            vpn_client_ecdsa_signature_for_ike
            vpn_client_rsa_signature_for_ike
            vpn_client_sa_per_host
            vpn_client_sa_per_net
        :param str comment: comment message
        :return GatewayProfile: instance with metadata
        :rtype: GatewayProfile
        """
        json = {'name': name, 'comment': comment}
        if capabilities:
            json.update(capabilities=capabilities)
        return ElementCreator(cls, json=json)

    @property
    def capabilities(self):
        """
        Capabilities are all boolean values that specify features or cryptography features to enable
        or disable on this gateway profile.To update or change these values, you can use the built
        in `update` with a key of 'capabilities' and dict value of attributes, i.e::
            gateway_profile = GatewayProfile('myGatewayProfile')
            pprint(gateway_profile.capabilities) # <-- show all options
            gateway_profile.update(capabilities={'sha2_for_ipsec': True, 'sha2_for_ike': True})

        :rtype: dict
        """
        return self.data.get("capabilities", {})


class ExternalGateway(Element):
    """
    External Gateway defines an VPN Gateway for a non-SMC managed device.
    This will specify details such as the endpoint IP, and VPN site
    protected networks. Example of manually provisioning each step::

        Network.create(name='mynetwork', ipv4_network='172.18.1.0/24')
        gw = ExternalGateway.create(name='mygw')
        gw.external_endpoint.create(name='myendpoint', address='10.10.10.10')
        gw.vpn_site.create(name='mysite', site_element=[Network('mynetwork')])

    :ivar GatewayProfile gateway_profile: A gateway profile will define the
        capabilities (i.e. crypto) allowed for this VPN.
    """

    typeof = "external_gateway"
    gateway_profile = ElementRef("gateway_profile")

    @classmethod
    def create(cls, name, trust_all_cas=True, gateway_profile=None, **kwargs):
        """
        Create new External Gateway

        :param str name: name of test_external gateway
        :param bool trust_all_cas: whether to trust all internal CA's
               (default: True)
        :param GatewayProfile,href gateway_profile: optional gateway profile, otherwise
            default
        :return: instance with meta
        :rtype: ExternalGateway
        """
        json = {
            "name": name,
            "trust_all_cas": trust_all_cas,
            "gateway_profile": element_resolver(gateway_profile)
            if gateway_profile
            else element_default(GatewayProfile, "Default"),
        }
        json.update(kwargs)

        return ElementCreator(cls, json)

    @classmethod
    def update_or_create(
        cls, name, external_endpoint=None, vpn_site=None, trust_all_cas=True, with_status=False
    ):
        """
        Update or create an ExternalGateway. The ``external_endpoint`` and
        ``vpn_site`` parameters are expected to be a list of dicts with key/value
        pairs to satisfy the respective elements create constructor. VPN Sites will
        represent the final state of the VPN site list. ExternalEndpoint that are
        pre-existing will not be deleted if not provided in the ``external_endpoint``
        parameter, however existing elements will be updated as specified.

        :param str name: name of external gateway
        :param list(dict) external_endpoint: list of dict items with key/value
            to satisfy ExternalEndpoint.create constructor
        :param list(dict) vpn_site: list of dict items with key/value to satisfy
            VPNSite.create constructor
        :param bool with_status: If set to True, returns a 3-tuple of
            (ExternalGateway, modified, created), where modified and created
            is the boolean status for operations performed.
        :raises ValueError: missing required argument/s for constructor argument
        :rtype: ExternalGateway
        """
        if external_endpoint:
            for endpoint in external_endpoint:
                if "name" not in endpoint:
                    raise ValueError(
                        "External endpoints are configured " "but missing the name parameter."
                    )

        if vpn_site:
            for site in vpn_site:
                if "name" not in site:
                    raise ValueError("VPN sites are configured but missing " "the name parameter.")
                # Make sure VPN sites are resolvable before continuing
                sites = [
                    element_resolver(element, do_raise=True)
                    for element in site.get("site_element", [])
                ]
                site.update(site_element=sites)

        updated = False
        created = False
        try:
            extgw = ExternalGateway.get(name)
        except ElementNotFound:
            extgw = ExternalGateway.create(name, trust_all_cas)
            created = True

        if external_endpoint:
            for endpoint in external_endpoint:
                _, modified, was_created = ExternalEndpoint.update_or_create(
                    extgw, with_status=True, **endpoint
                )
                if was_created or modified:
                    updated = True

        if vpn_site:
            for site in vpn_site:
                _, modified, was_created = VPNSite.update_or_create(
                    extgw,
                    name=site["name"],
                    site_element=site.get("site_element"),
                    with_status=True,
                )
                if was_created or modified:
                    updated = True

        if with_status:
            return extgw, updated, created
        return extgw

    @property
    def vpn_site(self):
        """
        A VPN site defines a collection of IP's or networks that
        identify address space that is defined on the other end of
        the VPN tunnel.

        :rtype: CreateCollection(VPNSite)
        """
        return create_collection(self.get_relation("vpn_site"), VPNSite)

    @property
    def external_endpoint(self):
        """
        An External Endpoint is the IP based definition for the destination
        VPN peers. There may be multiple per External Gateway.  Add a new
        endpoint to an existing test_external gateway::

            >>> list(ExternalGateway.objects.all())
            [ExternalGateway(name=cisco-remote-side), ExternalGateway(name=remoteside)]
            >>> gateway.external_endpoint.create('someendpoint', '12.12.12.12')
            'http://1.1.1.1:8082/6.1/elements/external_gateway/22961/external_endpoint/27467'

        :rtype: CreateCollection(ExternalEndpoint)
        """
        return create_collection(self.get_relation("external_endpoint"), ExternalEndpoint)

    @property
    def trust_all_cas(self):
        """
        Gateway setting identifying whether all CA's specified in the
        profile are supported or only specific ones.

        :rtype: bool
        """
        return self.data.get("trust_all_cas")


class ElementContactAddress(SerializedIterable):
    """
    An ElementContactAddress is assigned to an element, such as ExternalGateway.
    These contact addresses can have multiple location and addresses per element
    but any single contact address can have only one address associated.
    """

    def __init__(self, smcresult, subelement):
        self._subelement = subelement  # Original element
        self._etag = smcresult.etag
        super(ElementContactAddress, self).__init__(
            smcresult.json.get("contact_addresses", []), ContactAddress
        )

    def create(self, location_ref, address, dynamic=False, overwrite_existing=False):
        """
        Create a contact address for the given element. Address is always
        a required field. If the contact address should be dynamic, then
        the value of the address field should be assigned by the DHCP
        interface name, i.e.::

            external_endpoint.contact_addresses.create(
                location=Location('foo'),
                address='First DHCP Interface ip', dynamic=True)

        If you set override_existing=True, any pre-existing contact addresses will
        be removed, otherwise this is an append operation.

        :param str,Location location_ref: href or Location element, location is created
            if provided as a string and it doesn't exist
        :param address: string repesenting address
        :param bool dynamic: whether address is dynamic or static
        :param bool overwrite_existing: whether to keep existing locations or
            to overwrite default: False
        :return: None
        :raises: ActionCommandFailed
        """
        json = [
            {"location_ref": location_helper(location_ref), "address": address, "dynamic": dynamic}
        ]

        if not overwrite_existing:
            json.extend(addr.data for addr in self.items)

        return self._subelement.make_request(
            resource="contact_addresses",
            method="update",
            etag=self._etag,
            json={"contact_addresses": json},
        )

    def delete(self, location_name=None):
        """
        Delete a contact address by it's location name. Every ElementContactAddress
        has a one to one relationship between a location and an address. If the
        location is not provided, then all contact addresses will be deleted.

        :param str location_name: name of the location to remove
        :raises ElementNotFound: location specified does not exist
        """
        json = {"contact_addresses": []}

        if location_name:
            location_ref = Location(location_name).href
            json.setdefault("contact_addresses", []).extend(
                [location.data for location in self if location.location_ref != location_ref]
            )

        return self._subelement.make_request(
            resource="contact_addresses", method="update", etag=self._etag, json=json
        )


class ExternalEndpoint(SubElement):
    """
    External Endpoint is used by the External Gateway and defines the IP
    and other VPN related settings to identify the VPN peer. This is created
    to define the details of the non-SMC managed gateway. This class is a property
    of :py:class:`smc.vpn.elements.ExternalGateway` and should not be called
    directly.
    Add an endpoint to existing External Gateway::

        gw = ExternalGateway('aws')
        gw.external_endpoint.create(name='aws01', address='2.2.2.2')

    .. versionchanged:: 0.7.0

        When using SMC >= 6.5, you can also provide a value for ConnectionType parameter
        when creating the element, for example::

            gw = ExternalGateway('aws')
            gw.external_endpoint.create(name='aws01', address='2.2.2.2',
                                        connection_type=ConnectionType('Active'))

    .. seealso:: :class:`~ConnectionType`
    """

    typeof = "external_endpoint"

    def create(
        self,
        name,
        address=None,
        enabled=True,
        ipsec_vpn=True,
        nat_t=False,
        force_nat_t=False,
        dynamic=False,
        ike_phase1_id_type=None,
        ike_phase1_id_value=None,
        connection_type_ref=None,
        **kw
    ):
        """
        Create an test_external endpoint. Define common settings for that
        specify the address, enabled, nat_t, name, etc. You can also omit
        the IP address if the endpoint is dynamic. In that case, you must
        also specify the ike_phase1 settings.

        :param str name: name of test_external endpoint
        :param str address: address of remote host
        :param bool enabled: True|False (default: True)
        :param bool ipsec_vpn: True|False (default: True)
        :param bool nat_t: True|False (default: False)
        :param bool force_nat_t: True|False (default: False)
        :param bool dynamic: is a dynamic VPN (default: False)
        :param int ike_phase1_id_type: If using a dynamic endpoint, you must
            set this value. Valid options: 0=DNS name, 1=Email, 2=DN, 3=IP Address
        :param str ike_phase1_id_value: value of ike_phase1_id. Required if
            ike_phase1_id_type and dynamic set.
        :param ConnectionType connection_type_ref: SMC>=6.5 setting. Specifies the
            mode for this endpoint; i.e. Active, Aggregate, Standby. (Default: Active)
        :raises CreateElementFailed: create element with reason
        :return: newly created element
        :rtype: ExternalEndpoint
        """
        json = {
            "name": name,
            "address": address,
            "dynamic": dynamic,
            "enabled": enabled,
            "nat_t": nat_t,
            "force_nat_t": force_nat_t,
            "ipsec_vpn": ipsec_vpn,
        }

        json.update(kw)
        if dynamic:
            json.pop("address", None)

        if ike_phase1_id_value:
            json.update(ike_phase1_id_value=ike_phase1_id_value)

        if ike_phase1_id_type is not None:
            json.update(ike_phase1_id_type=ike_phase1_id_type)

        json.update(
            connection_type_ref=element_resolver(connection_type_ref)
        ) if connection_type_ref else json.update(
            connection_type_ref=element_default(ConnectionType, "Active")
        )

        return ElementCreator(self.__class__, href=self.href, json=json)

    @classmethod
    def update_or_create(cls, external_gateway, name, with_status=False, **kw):
        """
        Update or create external endpoints for the specified external gateway.
        An ExternalEndpoint is considered unique based on the IP address for the
        endpoint (you cannot add two external endpoints with the same IP). If the
        external endpoint is dynamic, then the name is the unique identifier.

        :param ExternalGateway external_gateway: external gateway reference
        :param str name: name of the ExternalEndpoint. This is only used as
            a direct match if the endpoint is dynamic. Otherwise the address
            field in the keyword arguments will be used as you cannot add
            multiple external endpoints with the same IP address.
        :param bool with_status: If set to True, returns a 3-tuple of
            (ExternalEndpoint, modified, created), where modified and created
            is the boolean status for operations performed.
        :param dict kw: keyword arguments to satisfy ExternalEndpoint.create
            constructor
        :raises CreateElementFailed: Failed to create external endpoint with reason
        :raises ElementNotFound: If specified ExternalGateway is not valid
        :return: if with_status=True, return tuple(ExternalEndpoint, created). Otherwise
            return only ExternalEndpoint.
        """
        external_endpoint = None
        if "address" in kw:
            external_endpoint = external_gateway.external_endpoint.get_contains(
                "({})".format(kw["address"])
            )
        if external_endpoint is None:
            external_endpoint = external_gateway.external_endpoint.get_contains(name)

        updated = False
        created = False
        if external_endpoint:  # Check for changes
            if "connection_type_ref" in kw:  # 6.5 only
                kw.update(connection_type_ref=element_resolver(kw.pop("connection_type_ref")))

            for name, value in kw.items():  # Check for differences before updating
                if getattr(external_endpoint, name, None) != value:
                    external_endpoint.data[name] = value
                    updated = True
            if updated:
                external_endpoint.update()
        else:
            external_endpoint = external_gateway.external_endpoint.create(name, **kw)
            created = True

        if with_status:
            return external_endpoint, updated, created
        return external_endpoint

    @property
    def force_nat_t(self):
        """
        Whether force_nat_t is enabled on this endpoint.

        :rtype: bool
        """
        return self.data.get("force_nat_t")

    @property
    def enabled(self):
        """
        Whether this endpoint is enabled.

        :rtype: bool
        """
        return self.data.get("enabled")

    def enable_disable(self):
        """
        Enable or disable this endpoint. If enabled, it will be disabled
        and vice versa.

        :return: None
        """
        self.update(enabled=True) if not self.enabled else self.update(enabled=False)

    def enable_disable_force_nat_t(self):
        """
        Enable or disable NAT-T on this endpoint. If enabled, it will be
        disabled and vice versa.

        :return: None
        """
        self.update(force_nat_t=True) if not self.force_nat_t else self.update(force_nat_t=False)

    @property
    def contact_addresses(self):
        """
        Contact Addresses are a mutable collection of contact addresses
        assigned to a supported element.

        :rtype: ElementContactAddress
        """
        return ElementContactAddress(
            self.make_request(resource="contact_addresses", raw_result=True), self
        )

    @property
    def connection_type_ref(self):
        """
        The reference to the connection type for this external endpoint. A
        connection type specifies how the endpoint will behave in an active,
        standby or aggregate role.

        .. note:: This will return None on SMC versions < 6.5

        :rtype: ConnectionType
        """
        return Element.from_href(self.data.get("connection_type_ref"))


class VPNSite(SubElement):
    """
    VPN Site information for an internal or test_external gateway
    Sites are used to encapsulate hosts or networks as 'protected' for VPN
    policy configuration.

    Create a new vpn site for an engine::

        engine = Engine('myengine')
        network = Network('network-192.168.5.0/25') #get resource
        engine.vpn.sites.create('newsite', [network.href])

    Sites can also be added to ExternalGateway's as well::

        extgw = ExternalGateway('mygw')
        extgw.vpn_site.create('newsite', [Network('foo')])

    This class is a property of :py:class:`smc.core.engine.InternalGateway`
    or :py:class:`smc.vpn.elements.ExternalGateway` and should not be accessed
    directly.

    :ivar InternalGateway,ExternalGateway gateway: gateway referenced
    """

    typeof = "vpn_site"
    gateway = ElementRef("gateway")

    def create(self, name, site_element, vpn_references=None):
        """
        Create a VPN site for an internal or external gateway

        :param str name: name of site
        :param list site_element: list of protected networks/hosts
        :type site_element: list[str,Element]
        :param list(dict) vpn_references: Set of associations Site-VPN.
        :raises CreateElementFailed: create element failed with reason
        :return: href of new element
        :rtype: str
        """
        site_element = element_resolver(site_element)
        json = {"name": name, "site_element": site_element}
        if vpn_references:
            json.update(vpn_references=vpn_references)

        return ElementCreator(self.__class__, href=self.href, json=json)

    @classmethod
    def update_or_create(cls, external_gateway, name, site_element=None, with_status=False,
                         vpn_references=None):
        """
        Update or create a VPN Site elements or modify an existing VPN
        site based on value of provided site_element list. The resultant
        VPN site end result will be what is provided in the site_element
        argument (can also be an empty list to clear existing).

        :param ExternalGateway external_gateway: The external gateway for
            this VPN site
        :param str name: name of the VPN site
        :param list(str,Element) site_element: list of resolved Elements to
            add to the VPN site
        :param bool with_status: If set to True, returns a 3-tuple of
            (VPNSite, modified, created), where modified and created
            is the boolean status for operations performed.
        :param lidt(dict) vpn_references: Set of associations Site-VPN.
        :raises ElementNotFound: ExternalGateway or unresolved site_element
        """
        site_element = [] if not site_element else site_element
        site_elements = [element_resolver(element) for element in site_element]
        vpn_references = vpn_references if vpn_references else []
        vpn_site = external_gateway.vpn_site.get_exact(name)
        updated = False
        created = False
        if vpn_site:  # If difference, reset
            if set(site_elements) != set(vpn_site.data.get("site_element", [])) and site_element:
                vpn_site.data["site_element"] = site_elements
            vpn_site.update(vpn_references=vpn_references)
            updated = True

        else:
            vpn_site = external_gateway.vpn_site.create(name=name, site_element=site_elements,
                                                        vpn_references=vpn_references)
            created = True

        if with_status:
            return vpn_site, updated, created
        return vpn_site

    @property
    def name(self):
        name = super(VPNSite, self).name
        if not name:
            return self.data.get("name")
        return name

    @property
    def site_element(self):
        """
        Site elements for this VPN Site.

        :return: Elements used in this VPN site
        :rtype: list(Element)
        """
        return [Element.from_href(element) for element in self.data.get("site_element")]

    @property
    def vpn_references(self):
        """
        Set of associations Site-VPN
        :rtype: list
        """
        return self.data.get("vpn_references", [])

    def add_site_element(self, element):
        """
        Add a site element or list of elements to this VPN.

        :param list element: list of Elements or href's of vpn site
            elements
        :type element: list(str,Network)
        :raises UpdateElementFailed: fails due to reason
        :return: None
        """
        element = element_resolver(element)
        self.data["site_element"].extend(element)
        self.update()


class VPNProfile(Element):
    """
    A VPN Profile is used to specify cryptography and other Policy VPN specific
    features. Every PolicyVPN requires a VPNProfile. The system will provide
    common profiles labeled as System Element that can be used without
    modification.
    """

    typeof = "vpn_profile"

    @classmethod
    def create(cls, name, capabilities=None, cn_authentication_for_mobile_vpn=False,
               disable_anti_replay=False, disable_path_discovery=False,
               hybrid_authentication_for_mobile_vpn=False, keep_alive=False,
               preshared_key_for_mobile_vpn=False, sa_life_time=86400,
               sa_to_any_network_allowed=False, trust_all_cas=True,
               trusted_certificate_authority=[], tunnel_life_time_kbytes=0,
               tunnel_life_time_seconds=28800, comment=None, **kw):
        """
        Create a VPN Profile. There are a variety of kwargs that can
        be and also retrieved about a VPN Profile. Keyword parameters
        are specified below. To access a valid keyword, use the standard
        dot notation.

        To validate supported keyword attributes for a VPN Profile, consult
        the native SMC API docs for your version of SMC. You can also optionally
        print the element contents after retrieving the element and use
        `update` to modify the element.

        For example::

            vpn = VPNProfile.create(name='mySecureVPN', comment='test comment')
            pprint(vars(vpn.data))

        Then once identifying the attribute, update the relevant top level
        attribute values::

            vpn.update(sa_life_time=128000, tunnel_life_time_seconds=57600)

        :param str name: Name of profile
        :param dict capabilities: Capabilities are all boolean values that specify features or
            cryptography features to enable or disable on this VPN profile.
            To update or change these values, you can use the built in `update`
            with a key of 'capabilities' and dict value of attributes
        :param bool cn_authentication_for_mobile_vpn: Indicates whether CN authentification is
            allowed or not, for a client using a certificate authentication.
        :param bool disable_anti_replay: IPSEC_DISABLE_ANTI_REPLAY flag value
        :param bool disable_path_discovery: NO_PATH_MTU_DISCOVERY flag value.
        :param bool hybrid_authentication_for_mobile_vpn: Indicates whether Hybrid authentification
            is allowed or not, for a client using a certificate authentication.
        :param bool keep_alive: Keep-alive option
        :param bool preshared_key_for_mobile_vpn: Indicates whether preshared key authentification
            is allowed or not,together with a client certificate authentication.,
        :param int sa_life_time: IKE Lifetime in seconds
        :param bool sa_to_any_network_allowed: IPSEC_SA_To_ANY flag value.
        :param bool trust_all_cas: Whether to trust all certificate authorities or not
        :param list trusted_certificate_authority: List of trusted certificate authorities for this
            profile (if the trust all CAs attribute has been set to false)
        :param int tunnel_life_time_kbytes: IPsec Lifetime in KBytes.
        :param int tunnel_life_time_seconds: IPsec Lifetime in seconds.
        :param str comment: optional comment
        :raises CreateElementFailed: failed creating element with reason
        :rtype: VPNProfile
        """
        kw.update(name=name, capabilities=capabilities,
                  cn_authentication_for_mobile_vpn=cn_authentication_for_mobile_vpn,
                  disable_anti_replay=disable_anti_replay,
                  disable_path_discovery=disable_path_discovery,
                  hybrid_authentication_for_mobile_vpn=hybrid_authentication_for_mobile_vpn,
                  keep_alive=keep_alive,
                  preshared_key_authentication_for_mobile_vpn=preshared_key_for_mobile_vpn,
                  sa_life_time=sa_life_time,
                  sa_to_any_network_allowed=sa_to_any_network_allowed,
                  trust_all_cas=trust_all_cas,
                  tunnel_life_time_kbytes=tunnel_life_time_kbytes,
                  tunnel_life_time_seconds=tunnel_life_time_seconds, comment=comment)

        if trusted_certificate_authority:
            kw.update(trusted_certificate_authority=trusted_certificate_authority)
        return ElementCreator(cls, json=kw)

    @property
    def capabilities(self):
        """
        Capabilities are all boolean values that specify features or
        cryptography features to enable or disable on this VPN profile.
        To update or change these values, you can use the built in `update`
        with a key of 'capabilities' and dict value of attributes, i.e::

            vpn = VPNProfile('mySecureVPN')
            pprint(vpn.capabilities) # <-- show all options
            vpn.update(capabilities={'sha2_for_ipsec': True, 'sha2_for_ike': True})

        :rtype: dict
        """
        return self.data.get("capabilities", {})

    @property
    def cn_authentication_for_mobile_vpn(self):
        return self.data.get("cn_authentication_for_mobile_vpn")

    @property
    def disable_anti_replay(self):
        return self.data.get("disable_anti_replay")

    @property
    def disable_path_discovery(self):
        return self.data.get("disable_path_discovery")

    @property
    def hybrid_authentication_for_mobile_vpn(self):
        return self.data.get("hybrid_authentication_for_mobile_vpn")

    @property
    def keep_alive(self):
        return self.data.get("keep_alive")

    @property
    def preshared_key_authentication_for_mobile_vpn(self):
        return self.data.get("preshared_key_authentication_for_mobile_vpn")

    @property
    def sa_life_time(self):
        return self.data.get("sa_life_time")

    @property
    def sa_to_any_network_allowed(self):
        return self.data.get("sa_to_any_network_allowed")

    @property
    def trust_all_cas(self):
        return self.data.get("trust_all_cas", [])

    @property
    def tunnel_life_time_kbytes(self):
        return self.data.get("tunnel_life_time_kbytes")

    @property
    def tunnel_life_time_seconds(self):
        return self.data.get("tunnel_life_time_seconds")

    @property
    def trusted_certificate_authority(self):
        return self.data.get("trusted_certificate_authority")


class VPNBrokerDomain(Element):
    """VPN Broker Domain element defines the virtual network that
    contains the VPN Broker gateway and the VPN Broker members.
    """

    typeof = "vpn_broker_domain"

    @classmethod
    def create(cls, name, mac_address_prefix, file_ref, comment=None, **kw):
        """Create a VPN broker domain.

            VPNBrokerDomain.create(
                 name="vpn1", mac_address_prefix="06:02:02", file_ref=myfile.href
            )

        :param str name: name of vpn broker domain
        :param str mac_address_prefix: unique identifier for the VPN
                   Broker Domain in MAC address format. The length
                   must be three octets.  The first octet must be
                   even.  The address must be a unique unicast MAC
                   address.
        :param file_ref href or VPNBrokerConfigFile element

        :raises CreateElementFailed: reason for failure
        :rtype: VPNBrokerDomain

        """
        kw.update(
            name=name, comment=comment, mac_address_prefix=mac_address_prefix, file_ref=file_ref
        )
        return ElementCreator(cls, json=kw)


class VPNBrokerConfigFile(Element):
    """
    exported VPN Broker Domain element from the NGFW Manager
    """

    typeof = "broker_config_file"

    @classmethod
    def create(cls, name, comment=None, **kw):
        """
        Create a VPN broker config file

            VPNBrokerConfigFile.create(name="myfile")

        :param str name: name of config file
        :raises CreateElementFailed: reason for failure
        :rtype: VPNBrokerConfigFile
        """
        kw.update(name=name, comment=comment)
        return ElementCreator(cls, json=kw)


class ConnectionType(Element):
    """
    .. versionadded:: 0.7.0
        Introduced in SMC >= 6.5 to provide a way to group VPN element types

    ConnectionTypes are used in various VPN configurations such as an
    ExternalGateway endpoint element to define how the endpoint should
    be treated, i.e. active, aggregate or standby.

    :ivar int connectivity_group: connectivity group for this connection type
    :ivar str mode: mode, valid options: 'active', 'aggregate', 'standby'
    """

    typeof = "connection_type"

    @classmethod
    def create(cls, name, mode="active", connectivity_group=1, link_type_ref=None, comment=None):
        """
        Create a connection type for an VPN endpoint.
        ::

            ConnectionType.create(name='mygroup', mode='standby')

        :param str name: name of connection type
        :param str mode: mode of connection type, valid options active, standby,
            aggregate
        :param int connectivity_group: integer used to group multiple connection types
            into a single monitoring group (default: 1)
        :param str link_type_ref: Indicates link type for the connections. Not Required.
        :param str comment: optional comment
        :raises CreateElementFailed: reason for failure
        :rtype: ConnectionType
        """
        json = {
            "name": name,
            "mode": mode,
            "comment": comment,
            "connectivity_group": connectivity_group,
        }
        if link_type_ref:
            json.update(link_type_ref=element_resolver(link_type_ref))
        return ElementCreator(
            cls,
            json=json,
        )

    def mode(self):
        return self.data.get("mode")

    def connectivity_group(self):
        return self.data.get("connectivity_group")

    def link_type_ref(self):
        return self.data.get("link_type_ref", None)


class LinkUsagePreference(object):
    def __init__(self, preference, qos_class):
        self.preference = preference
        self.qos_class = qos_class.href


class LinkUsageFEC(object):
    """
    Create a LinkUsageFEC object.
    :param int link_fec_threshold: Packet drop threshold that will start Forward Erasure Correction
    :param int link_fec_percent: FEC percentage indicating the ratio of correction packets
     to data packets
    :param list link_fec_qos: QoS Classes where Forward Erasure Correction will be applied
    :param list link_fec_type: Link Types where Forward Erasure Correction will be applied.
    :rtype: LinkUsageFEC
    """

    def __init__(self, link_fec_threshold, link_fec_percent, link_fec_qos, link_fec_type):
        self.link_fec_threshold = link_fec_threshold
        self.link_fec_percent = link_fec_percent
        self.link_fec_qos = link_fec_qos
        self.link_fec_type = link_fec_type

    def link_fec_threshold(self):
        return self.link_fec_threshold

    def link_fec_percent(self):
        return self.link_fec_percent

    def link_fec_qos(self):
        return self.link_fec_qos

    def link_fec_type(self):
        return self.link_fec_type


class LinkUsageDUP(object):
    """
    Create a LinkUsageDUP object.
    :param list link_dup_qos: QoS Classes where Packet Duplication will be applied
    :param list link_dup_type: Link Types where Packet Duplication will be applied.
    :rtype: LinkUsageDUP
    """

    def __init__(self, link_dup_qos, link_dup_type):
        self.link_dup_qos = link_dup_qos
        self.link_dup_type = link_dup_type

    def link_dup_qos(self):
        return self.link_dup_qos

    def link_dup_type(self):
        return self.link_dup_type


class LinkUsageException(object):
    def __init__(self, link_type, link_usage_preference):
        self.data = {"link_type": link_type.href, "link_usage_preference": link_usage_preference}
        link_usage_preferences_json = []
        for lup in link_usage_preference:
            link_usage_preferences_json.append({
                    "preference": lup.preference,
                    "qos_class": lup.qos_class
                })
        self.data["link_usage_preference"] = link_usage_preferences_json

    def link_type(self):
        return self.data.link_type

    def link_usage_preference(self):
        return self.data.link_usage_preference


class LinkUsageProfile(Element):
    typeof = "link_usage_profile"

    @classmethod
    def create(cls, name, default_link_balancing_preference=0, link_usage_exception=None,
               link_usage_fec=None, link_usage_dup=None):
        """
        Create a LinkUsageProfile.
        :param str name: name of Link usage profile
        :param int default_link_balancing_preference: The link balancing preference
        from 0 equal balancing to 4 best link
        :param list link_usage_exception: list of link_usage_exception
        :param obj link_usage_fec: LinkUsageFEC object for FEC configuration (optional)
        :param obj link_usage_dup: LinkUsageDUP object for Packet Duplication configuration
        (optional)
        :raises CreateElementFailed: failed to create element with reason
        :raises ElementNotFound: specified element reference was not found
        :rtype: LinkUsageProfile
        """
        link_usage_profile_json = {}
        link_usage_profile_json.update(name=name)
        link_usage_profile_json.update(
            default_link_balancing_preference=default_link_balancing_preference)
        link_usage_exception_json = []
        link_usage_exception = [] if not link_usage_exception else link_usage_exception
        for lue in link_usage_exception:
            link_usage_exception_temp_json = {"link_type": lue.data['link_type'],
                                              "link_usage_preference":
                                                  lue.data['link_usage_preference']}
            link_usage_exception_json.append(link_usage_exception_temp_json)
        link_usage_profile_json.update(link_usage_exception=link_usage_exception_json)

        if link_usage_fec:
            link_fec_qos_json = [link_fec_qos.href for link_fec_qos in link_usage_fec.link_fec_qos]
            link_usage_profile_json.update(link_fec_qos_ref=link_fec_qos_json)

            link_fec_type_json = \
                [link_fec_type.href for link_fec_type in link_usage_fec.link_fec_type]
            link_usage_profile_json.update(link_fec_type_ref=link_fec_type_json)

            link_usage_profile_json.update(link_fec_threshold=link_usage_fec.link_fec_threshold)
            link_usage_profile_json.update(link_fec_percentage=link_usage_fec.link_fec_percent)

        if link_usage_dup:
            link_dup_qos_json = [link_dup_qos.href for link_dup_qos in link_usage_dup.link_dup_qos]
            link_usage_profile_json.update(link_duplicate_qos_ref=link_dup_qos_json)

            link_dup_type_json = \
                [link_dup_type.href for link_dup_type in link_usage_dup.link_dup_type]
            link_usage_profile_json.update(link_dont_duplicate_link_type_ref=link_dup_type_json)

        return ElementCreator(cls, link_usage_profile_json)

    @property
    def default_link_balancing_preference(self):
        """
        default link balancing preference 0 to 4
        equal balancing to best link
        """
        return self.data.get("default_link_balancing_preference")

    @property
    def link_usage_exception(self):
        """
        List of exceptions
        """
        return self.link_usage_exception.get("link_usage_exception")
