from smc.base.model import Element, ElementCreator, lookup_class
from smc.base.structs import NestedDict
from smc.base.util import element_resolver
from smc.api.exceptions import PolicyCommandFailed, CreateRuleFailed
from smc.base.decorators import cacheable_resource
from smc.base.collection import rule_collection
from smc.core.resource import History
from smc.policy.rule import RuleCommon, Rule, SubElement


class SSLVPNPortal(Element):
    """
    An SSL VPN Portal.
    """
    typeof = "ssl_vpn_portal"

    @classmethod
    def create(cls, name, admin_domain=None, allow_empty_referrer=None, brand_color=None,
               log_access=None, look_and_feel=None, persistent_session=None,
               portal_session_timeout=None, portal_theme=None, portal_timeout=None,
               self_signed_certificate=False, server_credentials=None,
               session_timeout_unit=None, ssl_vpn_hostnames=None,
               ssl_vpn_policy=None, timeout_unit=None, title=None):
        """
        An SSL VPN Portal.
        :param name: str, name of the portal
        :param admin_domain: Admin domain Element.
        :param allow_empty_referrer: bool, allow empty referrer
        :param brand_color: str, brand color
        :param log_access: bool, log access
        :param look_and_feel: str, look and feel
        :param persistent_session: bool, persistent session
        :param portal_session_timeout: int, portal session timeout
        :param portal_theme: str, portal theme
        :param portal_timeout: int, portal timeout
        :param self_signed_certificate: bool, self signed certificate
        :param session_timeout_unit: str, session timeout unit
        :param ssl_vpn_hostnames: list of SSL VPN Hostnames
        :param ssl_vpn_policy: SSL VPN Policy Element
        :param timeout_unit: str, timeout unit
        :param title: str, title of the portal
        :return: SSLVPNPortal
        """
        json = {
            "name": name,
            "admin_domain": element_resolver(admin_domain) if admin_domain else None,
            "allow_empty_referrer": allow_empty_referrer if allow_empty_referrer else None,
            "brand_color": brand_color if brand_color else None,
            "log_access": log_access if log_access else None,
            "look_and_feel": look_and_feel if look_and_feel else None,
            "persistent_session": persistent_session if persistent_session else None,
            "portal_session_timeout": portal_session_timeout if portal_session_timeout else None,
            "portal_theme": portal_theme if portal_theme else None,
            "portal_timeout": portal_timeout if portal_timeout else None,
            "self_signed_certificate": self_signed_certificate if self_signed_certificate else None,
            "session_timeout_unit": session_timeout_unit if session_timeout_unit else None,
            "ssl_vpn_policy": element_resolver(ssl_vpn_policy),
            "timeout_unit": timeout_unit if timeout_unit else None,
            "title": title if title else None
        }
        if ssl_vpn_hostnames:
            sslvpn_hostname_list = []
            for host in ssl_vpn_hostnames:
                sslvpn_hostname_list.append({"ssl_vpn_hostname": host})
            json.update({"ssl_vpn_hostname": sslvpn_hostname_list})
        if server_credentials:
            tls_credentials_list = []
            for server_credential in server_credentials:
                tls_credentials_list.append(element_resolver(server_credential))
            json.update({"server_credential": tls_credentials_list})

        return ElementCreator(cls, json)

    @property
    def ssl_vpn_hostnames(self):
        """
        SSL VPN Hostnames.
        :rtype: list
        """
        return self.data.get("ssl_vpn_hostname")

    @ssl_vpn_hostnames.setter
    def ssl_vpn_hostnames(self, value):
        self.data.update({"ssl_vpn_hostnames": value})

    @property
    def allow_empty_referrer(self):
        """
        Allow empty referrer.
        :rtype: bool
        """
        return self.data.get("allow_empty_referrer")

    @allow_empty_referrer.setter
    def allow_empty_referrer(self, value):
        self.data.update({"allow_empty_referrer": value})

    @property
    def brand_color(self):
        """
        Brand color.
        :rtype: str
        """
        return self.data.get("brand_color")

    @brand_color.setter
    def brand_color(self, value):
        self.data.update({"brand_color": value})

    @property
    def log_access(self):
        """
        Log access.
        :rtype: str
        """
        return self.data.get("log_access")

    @log_access.setter
    def log_access(self, value):
        self.data.update({"log_access": value})

    @property
    def look_and_feel(self):
        """
        Look and feel.
        :rtype: str
        """
        return self.data.get("look_and_feel")

    @look_and_feel.setter
    def look_and_feel(self, value):
        self.data.update({"look_and_feel": value})

    @property
    def persistent_session(self):
        """
        Persistent session.
        :rtype: bool
        """
        return self.data.get("persistent_session")

    @persistent_session.setter
    def persistent_session(self, value):
        self.data.update({"persistent_session": value})

    @property
    def portal_session_timeout(self):
        """
        Portal session timeout.
        :rtype: int
        """
        return self.data.get("portal_session_timeout")

    @portal_session_timeout.setter
    def portal_session_timeout(self, value):
        self.data.update({"portal_session_timeout": value})

    @property
    def portal_theme(self):
        """
        Portal theme.
        :rtype: str
        """
        return self.data.get("portal_theme")

    @portal_theme.setter
    def portal_theme(self, value):
        self.data.update({"portal_theme": value})

    @property
    def portal_timeout(self):
        """
        Portal timeout.
        :rtype: int
        """
        return self.data.get("portal_timeout")

    @portal_timeout.setter
    def portal_timeout(self, value):
        self.data.update({"portal_timeout": value})

    @property
    def self_signed_certificate(self):
        """
        Self signed certificate.
        :rtype: bool
        """
        return self.data.get("self_signed_certificate")

    @self_signed_certificate.setter
    def self_signed_certificate(self, value):
        self.data.update({"self_signed_certificate": value})

    @property
    def session_timeout_unit(self):
        """
        Session timeout unit.
        :rtype: str
        """
        return self.data.get("session_timeout_unit")

    @session_timeout_unit.setter
    def session_timeout_unit(self, value):
        self.data.update({"session_timeout_unit": value})

    @property
    def ssl_vpn_policy(self):
        """
        SSL VPN Policy.
        :rtype: str
        """
        return self.data.get("ssl_vpn_policy")

    @ssl_vpn_policy.setter
    def ssl_vpn_policy(self, value):
        self.data.update({"ssl_vpn_policy": value})

    @property
    def timeout_unit(self):
        """
        Timeout unit.
        :rtype: str
        """
        return self.data.get("timeout_unit")

    @timeout_unit.setter
    def timeout_unit(self, value):
        self.data.update({"timeout_unit": value})

    @property
    def title(self):
        """
        Title.
        :rtype: str
        """
        return self.data.get("title")

    @title.setter
    def title(self, value):
        self.data.update({"title": value})

    @property
    def server_credentials(self):
        """
        Server credentials.
        :rtype: list
        """
        return self.data.get("server_credentials")

    @server_credentials.setter
    def server_credentials(self, value):
        self.data.update({"server_credentials": value})

    @property
    def admin_domain(self):
        """
        Admin domain.
        :rtype: str
        """
        return self.data.get("admin_domain")

    @admin_domain.setter
    def admin_domain(self, value):
        self.data.update({"admin_domain": value})


class SSLVPNHttpField(NestedDict):
    """
    An HTTP field to be used in an SSL VPN
    """

    def __init__(self, http_field_name=None, http_field_value=None):
        data = {"http_field_name": http_field_name, "http_field_value": http_field_value}
        super(SSLVPNHttpField, self).__init__(data=data)


class SSLVPNHostname(NestedDict):
    """
    An SSL VPN name which can be an IP Address or FQDN.
    """

    def __init__(self, ssl_vpn_hostname):
        data = {"ssl_vpn_hostname": ssl_vpn_hostname}
        super(SSLVPNHostname, self).__init__(data=data)


class SSLVPNAllowedURL(NestedDict):
    """
    An SSL VPN allowed URL dict for Free Form URL SSLVPN Web Service
    """

    def __init__(self, protocol="HTTP", url_host=None, port=None):
        data = {"protocol": protocol, "url_host": url_host, "port": port}
        super(SSLVPNAllowedURL, self).__init__(data=data)


class SSLVPNSSODomain(Element):
    """
    An SSL VPN Single Sign On Domain.
    """
    typeof = "ssl_vpn_sso_domain"

    @classmethod
    def create(cls, name, sso_mode="session_based", timeout=30):
        """
        An SSL VPN Single Sign On Domain.
        :param str name: Name of the ssl vpn sso domain.
        :param str sso_mode: Name of sso mode like persistent/session_based.
        :param int timeout: sso timeout in days when sso mode is persistent.
        :rtype: SSLVPNSSODomain
        """
        json = {
            "name": name,
            "sso_mode": sso_mode,
            "timeout": timeout
        }
        return ElementCreator(cls, json)

    @property
    def sso_mode(self):
        return self.data.get("sso_mode")

    @sso_mode.setter
    def sso_mode(self, value):
        self.data.update({"sso_mode": value})

    @property
    def timeout(self):
        return self.data.get("timeout")

    @timeout.setter
    def timeout(self, value):
        self.data.update({"timeout": value})


class SSLVPNServiceProfile(Element):
    """
    An SSL VPN Service Profile.
    """

    typeof = "ssl_vpn_service_profile"

    @classmethod
    def create(cls, name, cookie_hiding="no_encryption", ssl_vpn_profile_exception=None,
               authentication_type="none", login_page_url=None, ntlm_support=False,
               password_input_name=None, post_request_url=None, ssl_vpn_http_field=None,
               user_input_custom_format=None, user_input_format="user", user_input_name=None):
        """
        An SSL VPN Service Profile.
        :param str name: Name of SSL VPN Service Profile.
        :param str cookie_hiding: Cookie hiding configuration.
        :param List<SSLVPNHostname> ssl_vpn_profile_exception: An SSL VPN name which can be an IP
            Address or FQDN.
        :param str authentication_type: Type of authentication for ssl VPN.
          None : Single Sign-On is Not Used
          http : HTTP Authentication methods Basic/Digest/NTLM are used
          form : Form Authentication with a custom login url, request url,...
        :param str login_page_url: Login Page URL.
        :param bool ntlm_support: Is support NTLMV2?
        :param str password_input_name: Password input name.
        :param str post_request_url: Post request URL.
        :param List<SSLVPNHttpField> ssl_vpn_http_field: An HTTP field to be used in an SSL VPN.
        :param user_input_custom_format: Custom format of user input like domain/user.
        :param str user_input_format: Domain and User format.
        :param str user_input_name: User input field name.
        :rtype: SSLVPNServiceProfile
        """
        ssl_vpn_http_field = ssl_vpn_http_field if ssl_vpn_http_field else []
        ssl_vpn_profile_exception = ssl_vpn_profile_exception if ssl_vpn_profile_exception else []

        json = {
            "name": name,
            "cookie_hiding": cookie_hiding,
            "ssl_vpn_profile_exception": [exception.data for exception in
                                          ssl_vpn_profile_exception],
            "authentication_type": authentication_type,
            "login_page_url": login_page_url,
            "ntlm_support": ntlm_support,
            "password_input_name": password_input_name,
            "post_request_url": post_request_url,
            "ssl_vpn_http_field": [http_field.data for http_field in ssl_vpn_http_field],
            "user_input_custom_format": user_input_custom_format,
            "user_input_format": user_input_format,
            "user_input_name": user_input_name

        }
        return ElementCreator(cls, json)

    @property
    def cookie_hiding(self):
        return self.data.get("cookie_hiding")

    @cookie_hiding.setter
    def cookie_hiding(self, value):
        self.data.update({"cookie_hiding": value})

    @property
    def ssl_vpn_profile_exception(self):
        return self.data.get("ssl_vpn_profile_exception")

    @ssl_vpn_profile_exception.setter
    def ssl_vpn_profile_exception(self, value):
        self.data.update({"ssl_vpn_profile_exception": value})

    @property
    def authentication_type(self):
        return self.data.get("authentication_type")

    @authentication_type.setter
    def authentication_type(self, value):
        self.data.update({"authentication_type": value})

    @property
    def login_page_url(self):
        return self.data.get("login_page_url")

    @login_page_url.setter
    def login_page_url(self, value):
        self.data.update({"login_page_url": value})

    @property
    def ntlm_support(self):
        return self.data.get("ntlm_support")

    @ntlm_support.setter
    def ntlm_support(self, value):
        self.data.update({"ntlm_support": value})

    @property
    def password_input_name(self):
        return self.data.get("password_input_name")

    @password_input_name.setter
    def password_input_name(self, value):
        self.data.update({"password_input_name": value})

    @property
    def post_request_url(self):
        return self.data.get("post_request_url")

    @post_request_url.setter
    def post_request_url(self, value):
        self.data.update({"post_request_url": value})

    @property
    def ssl_vpn_http_field(self):
        return self.data.get("ssl_vpn_http_field")

    @ssl_vpn_http_field.setter
    def ssl_vpn_http_field(self, value):
        self.data.update({"ssl_vpn_http_field": value})

    @property
    def user_input_custom_format(self):
        return self.data.get("user_input_custom_format")

    @user_input_custom_format.setter
    def user_input_custom_format(self, value):
        self.data.update({"user_input_custom_format": value})

    @property
    def user_input_format(self):
        return self.data.get("user_input_format")

    @user_input_format.setter
    def user_input_format(self, value):
        self.data.update({"user_input_format": value})

    @property
    def user_input_name(self):
        return self.data.get("user_input_name")

    @user_input_name.setter
    def user_input_name(self, value):
        self.data.update({"user_input_name": value})


class SSLVPNWebService(Element):
    """
    An SSL VPN Web Service.
    """

    typeof = "ssl_vpn_web_service"

    @classmethod
    def create(cls, name, admin_domain=None, cookie_protection=None, description=None,
               disable_rewrite=None, external_url=None, internal_url=None, rewrite_html=None,
               routing_method=None, self_signed_certificate=None, server_credential=None,
               ssl_vpn_allowed_url=None, ssl_vpn_althost=None, ssl_vpn_service_profile=None,
               start_page=None, title=None, trusted_ca=None, url_prefix=None,
               visible_in_portal=None, ssl_vpn_sso_domain=None):
        """
        Create an SSL VPN Web Service.
        :param str ssl_vpn_sso_domain: ssl_vpn_sso_domain obj or href
        :param str name: Name of the SSL VPN Web Service.
        :param str admin_domain: Admin domain URL.
        :param bool cookie_protection: Cookie protection flag.
        :param str description: Description of the service.
        :param bool disable_rewrite: Disable rewrite flag.
        :param str external_url: External URL.
        :param str internal_url: Internal URL. (if missing will be completed with a / at the end
        :param bool rewrite_html: Rewrite HTML flag.
        :param str routing_method: Routing method. (can be dns_mapping/url_rewrite or free_url)
        :param bool self_signed_certificate: Self-signed certificate flag.
        :param str server_credential: Server credential URL.
        :param list <SSLVPNAllowedURL> : List of allowed URLs dict (protocol, url_host, port).
        :param list ssl_vpn_althost: List of alternative hosts.
        :param obj/str ssl_vpn_service_profile: SSL VPN Service Profile
        :param str start_page: Start page URL.
        :param str title: Title of the service.
        :param list trusted_ca: List of trusted CAs.
        :param str url_prefix: URL prefix.
        :param bool visible_in_portal: Visible in portal flag.
        :return: Created SSLVPNWebService object.
        """
        ssl_vpn_allowed_url_entries = ssl_vpn_allowed_url if ssl_vpn_allowed_url else []
        json = {
            "name": name,
            "admin_domain": admin_domain,
            "cookie_protection": cookie_protection,
            "description": description,
            "disable_rewrite": disable_rewrite,
            "external_url": external_url,
            "internal_url": internal_url,
            "rewrite_html": rewrite_html,
            "routing_method": routing_method,
            "self_signed_certificate": self_signed_certificate,
            "server_credential": server_credential,
            "ssl_vpn_allowed_url": [entry for entry in ssl_vpn_allowed_url_entries],
            "ssl_vpn_althost": ssl_vpn_althost,
            "ssl_vpn_service_profile": element_resolver(ssl_vpn_service_profile),
            "start_page": start_page,
            "title": title,
            "trusted_ca": trusted_ca,
            "url_prefix": url_prefix,
            "visible_in_portal": visible_in_portal
        }
        if ssl_vpn_sso_domain:
            ssl_vpn_sso_domain = element_resolver(ssl_vpn_sso_domain)
            json.update(ssl_vpn_sso_domain=ssl_vpn_sso_domain)
        return ElementCreator(cls, json)

    @property
    def external_url(self):
        return self.data.get("external_url")

    @external_url.setter
    def external_url(self, value):
        self.data.update({"external_url": value})

    @property
    def server_credential(self):
        return self.data.get("server_credential")

    @server_credential.setter
    def server_credential(self, value):
        self.data.update({"server_credential": value})

    @property
    def admin_domain(self):
        return self.data.get("admin_domain")

    @admin_domain.setter
    def admin_domain(self, value):
        self.data.update({"admin_domain": value})

    @property
    def cookie_protection(self):
        return self.data.get("cookie_protection")

    @cookie_protection.setter
    def cookie_protection(self, value):
        self.data.update({"cookie_protection": value})

    @property
    def description(self):
        return self.data.get("description")

    @description.setter
    def description(self, value):
        self.data.update({"description": value})

    @property
    def disable_rewrite(self):
        return self.data.get("disable_rewrite")

    @disable_rewrite.setter
    def disable_rewrite(self, value):
        self.data.update({"disable_rewrite": value})

    @property
    def internal_url(self):
        return self.data.get("internal_url")

    @internal_url.setter
    def internal_url(self, value):
        self.data.update({"internal_url": value})

    @property
    def rewrite_html(self):
        return self.data.get("rewrite_html")

    @rewrite_html.setter
    def rewrite_html(self, value):
        self.data.update({"rewrite_html": value})

    @property
    def routing_method(self):
        return self.data.get("routing_method")

    @routing_method.setter
    def routing_method(self, value):
        self.data.update({"routing_method": value})

    @property
    def self_signed_certificate(self):
        return self.data.get("self_signed_certificate")

    @self_signed_certificate.setter
    def self_signed_certificate(self, value):
        self.data.update({"self_signed_certificate": value})

    @property
    def ssl_vpn_allowed_url(self):
        return self.data.get("ssl_vpn_allowed_url")

    @ssl_vpn_allowed_url.setter
    def ssl_vpn_allowed_url(self, value):
        self.data.update({"ssl_vpn_allowed_url": value})

    @property
    def ssl_vpn_althost(self):
        return self.data.get("ssl_vpn_althost")

    @ssl_vpn_althost.setter
    def ssl_vpn_althost(self, value):
        self.data.update({"ssl_vpn_althost": value})

    @property
    def ssl_vpn_service_profile(self):
        return self.data.get("ssl_vpn_service_profile")

    @ssl_vpn_service_profile.setter
    def ssl_vpn_service_profile(self, value):
        self.data.update({"ssl_vpn_service_profile": value})

    @property
    def ssl_vpn_sso_domain(self):
        return self.data.get("ssl_vpn_sso_domain")

    @ssl_vpn_sso_domain.setter
    def ssl_vpn_sso_domain(self, value):
        self.data.update({"ssl_vpn_sso_domain": value})

    @property
    def start_page(self):
        return self.data.get("start_page")

    @start_page.setter
    def start_page(self, value):
        self.data.update({"start_page": value})

    @property
    def title(self):
        return self.data.get("title")

    @title.setter
    def title(self, value):
        self.data.update({"title": value})

    @property
    def trusted_ca(self):
        return self.data.get("trusted_ca")

    @trusted_ca.setter
    def trusted_ca(self, value):
        self.data.update({"trusted_ca": value})

    @property
    def url_prefix(self):
        return self.data.get("url_prefix")

    @url_prefix.setter
    def url_prefix(self, value):
        self.data.update({"url_prefix": value})

    @property
    def visible_in_portal(self):
        return self.data.get("visible_in_portal")

    @visible_in_portal.setter
    def visible_in_portal(self, value):
        self.data.update({"visible_in_portal": value})


class SSLVPNRule(RuleCommon, Rule, SubElement):
    """
    An SSL VPN Policy Rule
    """

    typeof = "sslvpn_rule"

    def create(self,
               name=None,
               ssl_vpn_web_service=None,
               authentication=None,
               comment=None,
               rank=None,
               **kw):
        """
        An SSL VPN Policy Rule
        :param str name: Name of the SSL VPN Policy Rule.
        :param list ssl_vpn_web_service: SSL VPN Portal Service.
        :param obj authentication: Authentication Method.
        :param str comment: Comment.
        :param int rank: Rank of the rule.
        :rtype: SSLVPNRule
        """
        authentication = (
            Authentication() if not authentication else authentication
        )

        href = self.href
        json = {
            "Authentication": authentication,
            "comment": comment,
            "rank": rank
        }
        if ssl_vpn_web_service:
            ssl_vpn_web_service_list = []
            for ws in ssl_vpn_web_service:
                ssl_vpn_web_service_list.append(element_resolver(ws))
            json.update(ssl_vpn_web_service=ssl_vpn_web_service_list)
        if name:
            json["name"] = name
        json.update(**kw)
        return ElementCreator(self.__class__, exception=CreateRuleFailed, href=href, json=json)

    @property
    def name(self):
        """
        Name attribute of rule element
        """
        return self._meta.name if self._meta.name else "Rule @%s" % self.tag

    @property
    def history(self):
        """
        .. versionadded:: 0.6.3
            Requires SMC version >= 6.5

        Obtain the history of this element. This will not chronicle every
        modification made over time, but instead a current snapshot with
        historical information such as when the element was created, by
        whom, when it was last modified and it's current state.

        :raises ResourceNotFound:
        :rtype: History
        """
        return History(**self.make_request(resource="history"))

    @cacheable_resource
    def authentication(self):
        """
        Read only authentication field

        :rtype: Authentication
        """
        return Authentication(self)

    @property
    def comment(self):
        """
        Optional comment for this rule.

        :param str value: string comment
        :rtype: str
        """
        return self.data.get("comment")

    @comment.setter
    def comment(self, value):
        self.data["comment"] = value

    @property
    def is_disabled(self):
        """
        Whether the rule is enabled or disabled

        :param bool value: True, False
        :rtype: bool
        """
        return self.data.get("is_disabled")

    def disable(self):
        """
        Disable this rule
        """
        self.data["is_disabled"] = True

    def enable(self):
        """
        Enable this rule
        """
        self.data["is_disabled"] = False

    @cacheable_resource
    def ssl_vpn_web_service(self):
        """
        Services assigned to this rule

        :rtype: ssl_vpn_portal_service
        """
        return SSLVPNWebService(self)

    @property
    def parent_policy(self):
        """
        Read-only name of the parent policy

        :return: :class:`smc.base.model.Element` of type policy
        """
        return Element.from_href(self.data.get("parent_policy"))

    def save(self):
        """
        After making changes to a rule element, you must call save
        to apply the changes. Rule changes are made to cache before
        sending to SMC.

        :raises PolicyCommandFailed: failed to save with reason
        :return: href of this rule
        :rtype: str
        """
        return self.update()


class Authentication(NestedDict):
    """
    Authentication is set on a per rule basis and dictate
    whether a user requires identification to match.
    """

    def __init__(self, rule=None):
        if rule is None:
            auth = dict(methods=[], require_auth=False, users=[])
        else:
            auth = rule.data.data.get("Authentication", {})
        super(Authentication, self).__init__(data=auth)

    def __eq__(self, other):
        if isinstance(other, Authentication):
            if self.require_auth != other.require_auth:
                return False
            for values in ("users", "methods"):
                if set(self.data.get(values, [])) != set(other.data.get(values, [])):
                    return False
            return True
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __repr__(self):
        return (f"<Authentication(methods={self.methods},"
                f" require_auth={self.require_auth}, users={self.users})>")


class SSLVPNPolicyRule(object):
    """
    An SSL VPN Policy Rule collector.
    """
    @property
    def sslvpn_rules(self):
        return rule_collection(self.get_relation("sslvpn_rules"), SSLVPNRule)


class SSLVPNPolicy(SSLVPNPolicyRule, Element):
    """
    An SSL VPN Policy.
    """

    typeof = "ssl_vpn_policy"

    @classmethod
    def create(cls, name):
        """
        An SSL VPN Policy.
        :param str name: Name of the SSL VPN Policy.
        :rtype: SSLVPNPolicy
        """
        json = {
            "name": name
        }
        return ElementCreator(cls, json)

    def force_unlock(self):
        """
        Forcibly unlock a locked policy
        :return: None
        """
        self.make_request(PolicyCommandFailed, method="create", resource="force_unlock")

    def save_as(self, new_name: str):
        """
        Save as the current policy with a new name
        :return: the duplicated policy
        """
        return Element.from_href(self.make_request(PolicyCommandFailed,
                                                   method="create",
                                                   resource="save_as",
                                                   params={"name": new_name},
                                                   raw_result=True).href)

    def search_rule(self, search):
        """
        Search a rule for a rule tag or name value
        Result will be the meta data for rule (name, href, type)

        Searching for a rule in specific policy::

            f = SSLVPNPolicy(policy)
            search = f.search_rule(searchable)

        :param str search: search string
        :return: rule elements matching criteria
        :rtype: list(Element)
        """
        result = self.make_request(resource="search_rule", params={"filter": search})
        if result:
            results = []
            for data in result:
                typeof = data.get("type")
                klazz = lookup_class(typeof)
                results.append(klazz(**data))
            return results
        return []
