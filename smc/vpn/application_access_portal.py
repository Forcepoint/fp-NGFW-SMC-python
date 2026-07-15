from __future__ import annotations

from typing import Any, Optional, Union, Iterator

from smc.base.model import Element, ElementCreator, lookup_class
from smc.base.structs import NestedDict
from smc.base.util import element_resolver
from smc.api.exceptions import PolicyCommandFailed, CreateRuleFailed
from smc.base.decorators import cacheable_resource
from smc.base.collection import rule_collection
from smc.core.resource import History
from smc.policy.rule import RuleCommon, Rule, SubElement


class ApplicationAccessPortal(Element):
    """
    An Application Access Portal.
    """
    typeof = "application_access_portal"

    @classmethod
    def create(cls, name: str, admin_domain: Any = None,
               allow_empty_referrer: Optional[bool] = None, brand_color: Optional[str] = None,
               log_access: Optional[bool] = None, look_and_feel: Optional[str] = None,
               persistent_session: Optional[bool] = None,
               portal_session_timeout: Optional[int] = None, portal_theme: Optional[str] = None,
               portal_timeout: Optional[int] = None,
               self_signed_certificate: bool = False,
               server_credentials: Optional[list[Any]] = None,
               session_timeout_unit: Optional[str] = None,
               application_access_hostnames: Optional[list[Any]] = None,
               application_access_policy: Any = None, timeout_unit: Optional[str] = None,
               title: Optional[str] = None) -> ApplicationAccessPortal:
        """
        An Application Access Portal.
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
        :param application_access_hostnames: list of Application Access Hostnames
        :param application_access_policy: Application Access Policy Element
        :param timeout_unit: str, timeout unit
        :param title: str, title of the portal
        :return: ApplicationAccessPortal
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
            "application_access_policy": element_resolver(application_access_policy),
            "timeout_unit": timeout_unit if timeout_unit else None,
            "title": title if title else None
        }
        if application_access_hostnames:
            application_access_hostname_list = []
            for host in application_access_hostnames:
                application_access_hostname_list.append({"application_access_hostname": host})
            json.update({"application_access_hostname": application_access_hostname_list})
        if server_credentials:
            tls_credentials_list = []
            for server_credential in server_credentials:
                tls_credentials_list.append(element_resolver(server_credential))
            json.update({"server_credential": tls_credentials_list})

        return ElementCreator(cls, json)

    @property
    def application_access_hostnames(self) -> Optional[list[Any]]:
        """
        Application Access Hostnames.
        :rtype: list
        """
        return self.data.get("application_access_hostname")

    @application_access_hostnames.setter
    def application_access_hostnames(self, value: Any) -> None:
        self.data.update({"application_access_hostnames": value})

    @property
    def allow_empty_referrer(self) -> Optional[bool]:
        """
        Allow empty referrer.
        :rtype: bool
        """
        return self.data.get("allow_empty_referrer")

    @allow_empty_referrer.setter
    def allow_empty_referrer(self, value: Any) -> None:
        self.data.update({"allow_empty_referrer": value})

    @property
    def brand_color(self) -> Optional[str]:
        """
        Brand color.
        :rtype: str
        """
        return self.data.get("brand_color")

    @brand_color.setter
    def brand_color(self, value: Any) -> None:
        self.data.update({"brand_color": value})

    @property
    def log_access(self) -> Optional[str]:
        """
        Log access.
        :rtype: str
        """
        return self.data.get("log_access")

    @log_access.setter
    def log_access(self, value: Any) -> None:
        self.data.update({"log_access": value})

    @property
    def look_and_feel(self) -> Optional[str]:
        """
        Look and feel.
        :rtype: str
        """
        return self.data.get("look_and_feel")

    @look_and_feel.setter
    def look_and_feel(self, value: Any) -> None:
        self.data.update({"look_and_feel": value})

    @property
    def persistent_session(self) -> Optional[bool]:
        """
        Persistent session.
        :rtype: bool
        """
        return self.data.get("persistent_session")

    @persistent_session.setter
    def persistent_session(self, value: Any) -> None:
        self.data.update({"persistent_session": value})

    @property
    def portal_session_timeout(self) -> Optional[int]:
        """
        Portal session timeout.
        :rtype: int
        """
        return self.data.get("portal_session_timeout")

    @portal_session_timeout.setter
    def portal_session_timeout(self, value: Any) -> None:
        self.data.update({"portal_session_timeout": value})

    @property
    def portal_theme(self) -> Optional[str]:
        """
        Portal theme.
        :rtype: str
        """
        return self.data.get("portal_theme")

    @portal_theme.setter
    def portal_theme(self, value: Any) -> None:
        self.data.update({"portal_theme": value})

    @property
    def portal_timeout(self) -> Optional[int]:
        """
        Portal timeout.
        :rtype: int
        """
        return self.data.get("portal_timeout")

    @portal_timeout.setter
    def portal_timeout(self, value: Any) -> None:
        self.data.update({"portal_timeout": value})

    @property
    def self_signed_certificate(self) -> Optional[bool]:
        """
        Self signed certificate.
        :rtype: bool
        """
        return self.data.get("self_signed_certificate")

    @self_signed_certificate.setter
    def self_signed_certificate(self, value: Any) -> None:
        self.data.update({"self_signed_certificate": value})

    @property
    def session_timeout_unit(self) -> Optional[str]:
        """
        Session timeout unit.
        :rtype: str
        """
        return self.data.get("session_timeout_unit")

    @session_timeout_unit.setter
    def session_timeout_unit(self, value: Any) -> None:
        self.data.update({"session_timeout_unit": value})

    @property
    def application_access_policy(self) -> Optional[str]:
        """
        Application Access Policy.
        :rtype: str
        """
        return self.data.get("application_access_policy")

    @application_access_policy.setter
    def application_access_policy(self, value: Any) -> None:
        self.data.update({"application_access_policy": value})

    @property
    def timeout_unit(self) -> Optional[str]:
        """
        Timeout unit.
        :rtype: str
        """
        return self.data.get("timeout_unit")

    @timeout_unit.setter
    def timeout_unit(self, value: Any) -> None:
        self.data.update({"timeout_unit": value})

    @property
    def title(self) -> Optional[str]:
        """
        Title.
        :rtype: str
        """
        return self.data.get("title")

    @title.setter
    def title(self, value: Any) -> None:
        self.data.update({"title": value})

    @property
    def server_credentials(self) -> Optional[list[Any]]:
        """
        Server credentials.
        :rtype: list
        """
        return self.data.get("server_credentials")

    @server_credentials.setter
    def server_credentials(self, value: Any) -> None:
        self.data.update({"server_credentials": value})

    @property
    def admin_domain(self) -> Optional[str]:
        """
        Admin domain.
        :rtype: str
        """
        return self.data.get("admin_domain")

    @admin_domain.setter
    def admin_domain(self, value: Any) -> None:
        self.data.update({"admin_domain": value})


class ApplicationAccessHttpField(NestedDict):
    """
    An HTTP field to be used in an Application Access
    """

    def __init__(self, http_field_name: Optional[str] = None,
                 http_field_value: Optional[str] = None) -> None:
        data = {"http_field_name": http_field_name, "http_field_value": http_field_value}
        super(ApplicationAccessHttpField, self).__init__(data=data)


class ApplicationAccessHostname(NestedDict):
    """
    An Application Access name which can be an IP Address or FQDN.
    """

    def __init__(self, application_access_hostname: Any) -> None:
        data = {"application_access_hostname": application_access_hostname}
        super(ApplicationAccessHostname, self).__init__(data=data)


class ApplicationAccessAllowedURL(NestedDict):
    """
    An Application Access allowed URL dict for Free Form URL Application Access Web Service
    """

    def __init__(self, protocol: str = "HTTP", url_host: Optional[str] = None,
                 port: Optional[int] = None) -> None:
        data = {"protocol": protocol, "url_host": url_host, "port": port}
        super(ApplicationAccessAllowedURL, self).__init__(data=data)


class ApplicationAccessSSODomain(Element):
    """
    An Application Access Single Sign On Domain.
    """
    typeof = "application_access_sso_domain"

    @classmethod
    def create(cls, name: str, sso_mode: str = "session_based",
               timeout: int = 30) -> ApplicationAccessSSODomain:
        """
        An Application Access Single Sign On Domain.
        :param str name: Name of the ssl vpn sso domain.
        :param str sso_mode: Name of sso mode like persistent/session_based.
        :param int timeout: sso timeout in days when sso mode is persistent.
        :rtype: ApplicationAccessSSODomain
        """
        json = {
            "name": name,
            "sso_mode": sso_mode,
            "timeout": timeout
        }
        return ElementCreator(cls, json)

    @property
    def sso_mode(self) -> Optional[str]:
        return self.data.get("sso_mode")

    @sso_mode.setter
    def sso_mode(self, value: Any) -> None:
        self.data.update({"sso_mode": value})

    @property
    def timeout(self) -> Optional[int]:
        return self.data.get("timeout")

    @timeout.setter
    def timeout(self, value: Any) -> None:
        self.data.update({"timeout": value})


class ApplicationAccessServiceProfile(Element):
    """
    An Application Access Service Profile.
    """

    typeof = "application_access_service_profile"

    @classmethod
    def create(cls, name: str, cookie_hiding: str = "no_encryption",
               application_access_profile_exception: Optional[list[Any]] = None,
               authentication_type: str = "none", login_page_url: Optional[str] = None,
               ntlm_support: bool = False,
               password_input_name: Optional[str] = None,
               post_request_url: Optional[str] = None,
               application_access_http_field: Optional[list[Any]] = None,
               user_input_custom_format: Optional[str] = None, user_input_format: str = "user",
               user_input_name: Optional[str] = None) -> ApplicationAccessServiceProfile:
        """
        An Application Access Service Profile.
        :param str name: Name of Application Access Service Profile.
        :param str cookie_hiding: Cookie hiding configuration.
        :param List<ApplicationAccessHostname> application_access_profile_exception: An Application Access name which can be an IP
            Address or FQDN.
        :param str authentication_type: Type of authentication for ssl VPN.
          None : Single Sign-On is Not Used
          http : HTTP Authentication methods Basic/Digest/NTLM are used
          form : Form Authentication with a custom login url, request url,...
        :param str login_page_url: Login Page URL.
        :param bool ntlm_support: Is support NTLMV2?
        :param str password_input_name: Password input name.
        :param str post_request_url: Post request URL.
        :param List<ApplicationAccessHttpField> application_access_http_field: An HTTP field to be used in an Application Access.
        :param user_input_custom_format: Custom format of user input like domain/user.
        :param str user_input_format: Domain and User format.
        :param str user_input_name: User input field name.
        :rtype: ApplicationAccessServiceProfile
        """
        application_access_http_field = application_access_http_field if application_access_http_field else []
        application_access_profile_exception = application_access_profile_exception if application_access_profile_exception else []

        json = {
            "name": name,
            "cookie_hiding": cookie_hiding,
            "application_access_profile_exception": [exception.data for exception in
                                          application_access_profile_exception],
            "authentication_type": authentication_type,
            "login_page_url": login_page_url,
            "ntlm_support": ntlm_support,
            "password_input_name": password_input_name,
            "post_request_url": post_request_url,
            "application_access_http_field": [http_field.data for http_field in application_access_http_field],
            "user_input_custom_format": user_input_custom_format,
            "user_input_format": user_input_format,
            "user_input_name": user_input_name

        }
        return ElementCreator(cls, json)

    @property
    def cookie_hiding(self) -> Optional[str]:
        return self.data.get("cookie_hiding")

    @cookie_hiding.setter
    def cookie_hiding(self, value: Any) -> None:
        self.data.update({"cookie_hiding": value})

    @property
    def application_access_profile_exception(self) -> Optional[list[Any]]:
        return self.data.get("application_access_profile_exception")

    @application_access_profile_exception.setter
    def application_access_profile_exception(self, value: Any) -> None:
        self.data.update({"application_access_profile_exception": value})

    @property
    def authentication_type(self) -> Optional[str]:
        return self.data.get("authentication_type")

    @authentication_type.setter
    def authentication_type(self, value: Any) -> None:
        self.data.update({"authentication_type": value})

    @property
    def login_page_url(self) -> Optional[str]:
        return self.data.get("login_page_url")

    @login_page_url.setter
    def login_page_url(self, value: Any) -> None:
        self.data.update({"login_page_url": value})

    @property
    def ntlm_support(self) -> Optional[bool]:
        return self.data.get("ntlm_support")

    @ntlm_support.setter
    def ntlm_support(self, value: Any) -> None:
        self.data.update({"ntlm_support": value})

    @property
    def password_input_name(self) -> Optional[str]:
        return self.data.get("password_input_name")

    @password_input_name.setter
    def password_input_name(self, value: Any) -> None:
        self.data.update({"password_input_name": value})

    @property
    def post_request_url(self) -> Optional[str]:
        return self.data.get("post_request_url")

    @post_request_url.setter
    def post_request_url(self, value: Any) -> None:
        self.data.update({"post_request_url": value})

    @property
    def application_access_http_field(self) -> Optional[list[Any]]:
        return self.data.get("application_access_http_field")

    @application_access_http_field.setter
    def application_access_http_field(self, value: Any) -> None:
        self.data.update({"application_access_http_field": value})

    @property
    def user_input_custom_format(self) -> Optional[str]:
        return self.data.get("user_input_custom_format")

    @user_input_custom_format.setter
    def user_input_custom_format(self, value: Any) -> None:
        self.data.update({"user_input_custom_format": value})

    @property
    def user_input_format(self) -> Optional[str]:
        return self.data.get("user_input_format")

    @user_input_format.setter
    def user_input_format(self, value: Any) -> None:
        self.data.update({"user_input_format": value})

    @property
    def user_input_name(self) -> Optional[str]:
        return self.data.get("user_input_name")

    @user_input_name.setter
    def user_input_name(self, value: Any) -> None:
        self.data.update({"user_input_name": value})


class ApplicationAccessWebService(Element):
    """
    An Application Access Web Service.
    """

    typeof = "application_access_web_service"

    @classmethod
    def create(cls, name: str, admin_domain: Any = None,
               cookie_protection: Optional[bool] = None, description: Optional[str] = None,
               disable_rewrite: Optional[bool] = None, external_url: Optional[str] = None,
               internal_url: Optional[str] = None, rewrite_html: Optional[bool] = None,
               routing_method: Optional[str] = None,
               self_signed_certificate: Optional[bool] = None,
               server_credential: Any = None,
               application_access_allowed_url: Optional[list[Any]] = None,
               application_access_althost: Optional[list[Any]] = None,
               application_access_service_profile: Any = None,
               start_page: Optional[str] = None, title: Optional[str] = None,
               trusted_ca: Optional[list[Any]] = None, url_prefix: Optional[str] = None,
               visible_in_portal: Optional[bool] = None,
               application_access_sso_domain: Any = None) -> ApplicationAccessWebService:
        """
        Create an Application Access Web Service.
        :param str application_access_sso_domain: application_access_sso_domain obj or href
        :param str name: Name of the Application Access Web Service.
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
        :param list <ApplicationAccessAllowedURL> : List of allowed URLs dict (protocol, url_host, port).
        :param list application_access_althost: List of alternative hosts.
        :param obj/str application_access_service_profile: Application Access Service Profile
        :param str start_page: Start page URL.
        :param str title: Title of the service.
        :param list trusted_ca: List of trusted CAs.
        :param str url_prefix: URL prefix.
        :param bool visible_in_portal: Visible in portal flag.
        :return: Created ApplicationAccessWebService object.
        """
        application_access_allowed_url_entries = application_access_allowed_url if application_access_allowed_url else []
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
            "application_access_allowed_url": [entry for entry in application_access_allowed_url_entries],
            "application_access_althost": application_access_althost,
            "application_access_service_profile": element_resolver(application_access_service_profile),
            "start_page": start_page,
            "title": title,
            "trusted_ca": trusted_ca,
            "url_prefix": url_prefix,
            "visible_in_portal": visible_in_portal
        }
        if application_access_sso_domain:
            application_access_sso_domain = element_resolver(application_access_sso_domain)
            json.update(application_access_sso_domain=application_access_sso_domain)
        return ElementCreator(cls, json)

    @property
    def external_url(self) -> Optional[str]:
        return self.data.get("external_url")

    @external_url.setter
    def external_url(self, value: Any) -> None:
        self.data.update({"external_url": value})

    @property
    def server_credential(self) -> Any:
        return self.data.get("server_credential")

    @server_credential.setter
    def server_credential(self, value: Any) -> None:
        self.data.update({"server_credential": value})

    @property
    def admin_domain(self) -> Any:
        return self.data.get("admin_domain")

    @admin_domain.setter
    def admin_domain(self, value: Any) -> None:
        self.data.update({"admin_domain": value})

    @property
    def cookie_protection(self) -> Optional[bool]:
        return self.data.get("cookie_protection")

    @cookie_protection.setter
    def cookie_protection(self, value: Any) -> None:
        self.data.update({"cookie_protection": value})

    @property
    def description(self) -> Optional[str]:
        return self.data.get("description")

    @description.setter
    def description(self, value: Any) -> None:
        self.data.update({"description": value})

    @property
    def disable_rewrite(self) -> Optional[bool]:
        return self.data.get("disable_rewrite")

    @disable_rewrite.setter
    def disable_rewrite(self, value: Any) -> None:
        self.data.update({"disable_rewrite": value})

    @property
    def internal_url(self) -> Optional[str]:
        return self.data.get("internal_url")

    @internal_url.setter
    def internal_url(self, value: Any) -> None:
        self.data.update({"internal_url": value})

    @property
    def rewrite_html(self) -> Optional[bool]:
        return self.data.get("rewrite_html")

    @rewrite_html.setter
    def rewrite_html(self, value: Any) -> None:
        self.data.update({"rewrite_html": value})

    @property
    def routing_method(self) -> Optional[str]:
        return self.data.get("routing_method")

    @routing_method.setter
    def routing_method(self, value: Any) -> None:
        self.data.update({"routing_method": value})

    @property
    def self_signed_certificate(self) -> Optional[bool]:
        return self.data.get("self_signed_certificate")

    @self_signed_certificate.setter
    def self_signed_certificate(self, value: Any) -> None:
        self.data.update({"self_signed_certificate": value})

    @property
    def application_access_allowed_url(self) -> Optional[list[Any]]:
        return self.data.get("application_access_allowed_url")

    @application_access_allowed_url.setter
    def application_access_allowed_url(self, value: Any) -> None:
        self.data.update({"application_access_allowed_url": value})

    @property
    def application_access_althost(self) -> Optional[list[Any]]:
        return self.data.get("application_access_althost")

    @application_access_althost.setter
    def application_access_althost(self, value: Any) -> None:
        self.data.update({"application_access_althost": value})

    @property
    def application_access_service_profile(self) -> Any:
        return self.data.get("application_access_service_profile")

    @application_access_service_profile.setter
    def application_access_service_profile(self, value: Any) -> None:
        self.data.update({"application_access_service_profile": value})

    @property
    def application_access_sso_domain(self) -> Any:
        return self.data.get("application_access_sso_domain")

    @application_access_sso_domain.setter
    def application_access_sso_domain(self, value: Any) -> None:
        self.data.update({"application_access_sso_domain": value})

    @property
    def start_page(self) -> Optional[str]:
        return self.data.get("start_page")

    @start_page.setter
    def start_page(self, value: Any) -> None:
        self.data.update({"start_page": value})

    @property
    def title(self) -> Optional[str]:
        return self.data.get("title")

    @title.setter
    def title(self, value: Any) -> None:
        self.data.update({"title": value})

    @property
    def trusted_ca(self) -> Optional[list[Any]]:
        return self.data.get("trusted_ca")

    @trusted_ca.setter
    def trusted_ca(self, value: Any) -> None:
        self.data.update({"trusted_ca": value})

    @property
    def url_prefix(self) -> Optional[str]:
        return self.data.get("url_prefix")

    @url_prefix.setter
    def url_prefix(self, value: Any) -> None:
        self.data.update({"url_prefix": value})

    @property
    def visible_in_portal(self) -> Optional[bool]:
        return self.data.get("visible_in_portal")

    @visible_in_portal.setter
    def visible_in_portal(self, value: Any) -> None:
        self.data.update({"visible_in_portal": value})


class ApplicationAccessRule(RuleCommon, Rule, SubElement):
    """
    An Application Access Policy Rule
    """

    typeof = "application_access_rule"

    def create(self,
               name: Optional[str] = None,
               application_access_web_service: Optional[list[Any]] = None,
               authentication: Any = None,
               comment: Optional[str] = None,
               rank: Optional[int] = None,
               **kw: Any) -> ApplicationAccessRule:
        """
        An Application Access Policy Rule
        :param str name: Name of the Application Access Policy Rule.
        :param list application_access_web_service: Application Access Portal Service.
        :param obj authentication: Authentication Method.
        :param str comment: Comment.
        :param int rank: Rank of the rule.
        :rtype: ApplicationAccessRule
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
        if application_access_web_service:
            application_access_web_service_list = []
            for ws in application_access_web_service:
                application_access_web_service_list.append(element_resolver(ws))
            json.update(application_access_web_service=application_access_web_service_list)
        if name:
            json["name"] = name
        json.update(**kw)
        return ElementCreator(self.__class__, exception=CreateRuleFailed, href=href, json=json)

    @property
    def name(self) -> str:
        """
        Name attribute of rule element
        """
        return self._meta.name if self._meta.name else "Rule @%s" % self.tag

    @property
    def history(self) -> History:
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
    def authentication(self) -> Authentication:
        """
        Read only authentication field

        :rtype: Authentication
        """
        return Authentication(self)

    @property
    def comment(self) -> Optional[str]:
        """
        Optional comment for this rule.

        :param str value: string comment
        :rtype: str
        """
        return self.data.get("comment")

    @comment.setter
    def comment(self, value: Any) -> None:
        self.data["comment"] = value

    @property
    def is_disabled(self) -> Optional[bool]:
        """
        Whether the rule is enabled or disabled

        :param bool value: True, False
        :rtype: bool
        """
        return self.data.get("is_disabled")

    def disable(self) -> None:
        """
        Disable this rule
        """
        self.data["is_disabled"] = True

    def enable(self) -> None:
        """
        Enable this rule
        """
        self.data["is_disabled"] = False

    @cacheable_resource
    def application_access_web_service(self) -> ApplicationAccessWebService:
        """
        Services assigned to this rule

        :rtype: application_access_portal_service
        """
        return ApplicationAccessWebService(self)

    @property
    def parent_policy(self) -> Any:
        """
        Read-only name of the parent policy

        :return: :class:`smc.base.model.Element` of type policy
        """
        return Element.from_href(self.data.get("parent_policy"))

    def save(self) -> str:
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

    def __init__(self, rule: Any = None) -> None:
        if rule is None:
            auth = dict(methods=[], require_auth=False, users=[])
        else:
            auth = rule.data.data.get("Authentication", {})
        super(Authentication, self).__init__(data=auth)

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, Authentication):
            if self.require_auth != other.require_auth:
                return False
            for values in ("users", "methods"):
                if set(self.data.get(values, [])) != set(other.data.get(values, [])):
                    return False
            return True
        return False

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def __repr__(self) -> str:
        return (f"<Authentication(methods={self.methods},"
                f" require_auth={self.require_auth}, users={self.users})>")


class ApplicationAccessPolicyRule(object):
    """
    An Application Access Policy Rule collector.
    """
    @property
    def application_access_rules(self) -> Any:
        return rule_collection(self.get_relation("application_access_rules"), ApplicationAccessRule)


class ApplicationAccessPolicy(ApplicationAccessPolicyRule, Element):
    """
    An Application Access Policy.
    """

    typeof = "application_access_policy"

    @classmethod
    def create(cls, name: str) -> ApplicationAccessPolicy:
        """
        An Application Access Policy.
        :param str name: Name of the Application Access Policy.
        :rtype: ApplicationAccessPolicy
        """
        json = {
            "name": name
        }
        return ElementCreator(cls, json)

    def force_unlock(self) -> None:
        """
        Forcibly unlock a locked policy
        :return: None
        """
        self.make_request(PolicyCommandFailed, method="create", resource="force_unlock")

    def save_as(self, new_name: str) -> Any:
        """
        Save as the current policy with a new name
        :return: the duplicated policy
        """
        return Element.from_href(self.make_request(PolicyCommandFailed,
                                                   method="create",
                                                   resource="save_as",
                                                   params={"name": new_name},
                                                   raw_result=True).href)

    def search_rule(self, search: str) -> list[Any]:
        """
        Search a rule for a rule tag or name value
        Result will be the meta data for rule (name, href, type)

        Searching for a rule in specific policy::

            f = ApplicationAccessPolicy(policy)
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
