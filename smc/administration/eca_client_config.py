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
ECA Client configuration and ECA Endpoint Settings are used to configure endpoint integration
"""

from smc.base.model import Element, ElementCreator
from smc.base.structs import NestedDict
from smc.base.util import element_resolver, save_to_file
from smc.api.exceptions import EcaClientConfigExportError, ElementNotFound
from smc.administration.system import AdminDomain
from smc.elements.situations import EcaOperatingSystemSituation, InspectionSituationContext


class EcaClientConfig(Element):
    """
    ECA Client Configuration elements contain
    the Trusted Certificate Authority element used to secure communication
    between the NGFW Engine and the endpoint clients
    """

    typeof = "eca_client_config"

    @classmethod
    def create(cls, name=None, eca_ca_ref=None, auto_discovery=True, admin_domain=None):
        """
        Create an eca client config
        :param str, name: Name of ECA client configuration
        :param list, eca_ca_ref: Eca TLS Certificate Authority Reference
        :param bool, auto_discovery: if True advertise engine contact address to ECA client
        :param str admin_domain: domain to apply (default: Shared Domain)
        :rtype: eca_client_config
        """
        if not admin_domain:
            admin_domain = AdminDomain("Shared Domain")
        eca_ca_ref = element_resolver(eca_ca_ref)
        json = {
            "name": name,
            "admin_domain": element_resolver(admin_domain),
            "auto_discovery": auto_discovery
        }
        eca_ca_ref_list = []
        for cert in eca_ca_ref:
            eca_ca_ref_list.append(element_resolver(cert))
        json.update(eca_ca_ref=eca_ca_ref_list)
        return ElementCreator(cls, json)

    def export_client_config(self, filename=None):
        """
        Export the ECA client config .
        :raises CertificateExportError: error exporting certificate
        :rtype: str
        """
        result = self.make_request(
            EcaClientConfigExportError, raw_result=True, resource="configuration_export"
        )

        if filename is not None:
            save_to_file(filename, result.content)
            return

        return result.content

    def __getattr__(self, attr):
        return None

    def __repr__(self):
        return f"eca_client_config(name={self.name}," \
               f" eca_ca_ref={self.eca_ca_ref}," \
               f" admin_domain={self.admin_domain}," \
               f" auto_discovery={self.auto_discovery})"


def create_eca_os_situation_dict():
    """
        This method gather all ECA OS situation from system update package
        and create a dict with it : Like checkbox page in GUI
        By default all OS are set with False value. All OS that needs to be put
        in the ECA Endpoint settings needs to be set to True.
        :rtype: dict
    """
    eca_os_situation_dict = {}
    eos_list = EcaOperatingSystemSituation.objects.all()
    for eos in eos_list:
        eca_os_situation_dict[f'{eos.name}'] = False
    return eca_os_situation_dict


class EcaEndpointSettings(Element):
    """
        ECA Endpoint Settings elements contain
        All the properties to check and Configure endpoint
    """

    typeof = "eca_endpoint_settings"

    @classmethod
    def create(cls, name=None, admin_domain=None, client_av_disabled=False,
               client_av_enabled=False, client_av_unknown=None, eca_os_dict={},
               local_firewall_disabled=False, local_firewall_enabled=False,
               local_firewall_unknown=False, os_update_time_days=0,
               os_update_time_enabled=False, os_update_time_operator="less_than",
               os_update_unknown=False):
        """
        Create an eca endpoint setting
        :param str name: Name of ECA Endpoint Settings.
        :param str admin_domain: domain to apply (default: Shared Domain)
        :param dict, eca_os_dict: dict of all system
         eca operating system endpoint situation, value must be set to True to add ECA OS
         Situation to eca_os list json parameter
        :param bool local_firewall_disabled: Set endpoint local engine status to disable
        :param bool local_firewall_enabled: Set endpoint local engine status to enable.
        :param bool local_firewall_unknown: Set endpoint local engine status to can not be
            identified.
        :param list(ECAOperatingSystemSituation) eca_os: ECA OS situation.
        :param bool client_av_enabled: This attributes sets Client Anti-Virus enabled status.
        :param bool client_av_disabled: This attributes sets Client Anti-Virus disabled status.
        :param bool client_av_unknown: This attributes sets Client Anti-Virus unknown status.
        :param int os_update_time_days: This attribute defines status of system update installed
            less than or more than days ago.
        :param bool os_update_time_enabled: This attribute defines if os update time enable.
        :param str os_update_time_operator: It will decide less than 'os_update_time_days' or more
            than 'os_update_time_days' the updates were installed.
        :param bool os_update_unknown: Set this parameter if status cannot be identified.
        :rtype: eca_endpoint_settings
        """
        if not admin_domain:
            admin_domain = AdminDomain("Shared Domain")
        json = {
            "name": name,
            "admin_domain": element_resolver(admin_domain),
            "client_av_disabled": client_av_disabled,
            "client_av_enabled": client_av_enabled,
            "client_av_unknown": client_av_unknown,
            "local_firewall_disabled": local_firewall_disabled,
            "local_firewall_enabled": local_firewall_enabled,
            "local_firewall_unknown": local_firewall_unknown,
            "os_update_time_enabled": os_update_time_enabled,
            "os_update_unknown": os_update_unknown,
            "os_update_time_days": os_update_time_days,
            "os_update_time_operator": os_update_time_operator
        }
        eca_os_situation_list = []
        for eca_situation_os_key in eca_os_dict.keys():
            if eca_os_dict[eca_situation_os_key] is True:
                eca_os_href = EcaOperatingSystemSituation(eca_situation_os_key).href
                eca_os_situation_list.append(eca_os_href)
        json.update(eca_os=eca_os_situation_list)
        return ElementCreator(cls, json)

    def client_av_disabled(self):
        """
        Client Anti-Virus disabled status
        :rtype: bool
        """
        return self.data.get("client_av_disabled")

    def client_av_enabled(self):
        """
        Client Anti-Virus enabled status.
        :rtype: bool
        """
        return self.data.get("client_av_enabled")

    def client_av_unknown(self):
        """
        Client Anti-Virus unknown status.
        :rtype: bool
        """
        return self.data.get("os_update_time_operator")

    def local_firewall_disabled(self):
        """
        Endpoint local engine disable status..
        :rtype: bool
        """
        return self.data.get("local_firewall_disabled")

    def local_firewall_enabled(self):
        """
        Endpoint local engine enable status.
        :rtype: bool
        """
        return self.data.get("local_firewall_enabled")

    def local_firewall_unknown(self):
        """
        Endpoint local engine unknown status.
        :rtype: bool
        """
        return self.data.get("local_firewall_unknown")

    def eca_os(self):
        """
        ECA OS situation.
        :rtype: list(ECAOperatingSystemSituation)
        """
        return [EcaOperatingSystemSituation.from_href(os) for os in self.data.get("eca_os")]

    def os_update_time_days(self):
        """
        Status of system update installed.
        :rtype: int
        """
        return self.data.get("os_update_time_days")

    def os_update_time_enabled(self):
        """
         Os update time enable.
        :rtype: bool
        """
        return self.data.get("os_update_time_enabled")

    def os_update_time_operator(self):
        """
        Os update time operator like 'less than or more than'.
        :rtype: str
        """
        return self.data.get("os_update_time_operator")

    def os_update_unknown(self):
        """
         Os update unknown.
        :rtype: bool
        """
        return self.data.get("os_update_unknown")


class ECAExecutable(NestedDict):
    """
    ECA Executable object used by ECA Custom situations.
    """

    def __init__(self, data):
        super(ECAExecutable, self).__init__(data=data)

    @classmethod
    def create(cls, file_name=None, md5_hash=None, product_name=None, sha256_hash=None,
               version_number=None):
        """
        :param str file_name: Executable file name.
        :param str md5_hash: Executable's md5 hash.
        :param str product_name: Name of product.
        :param str sha256_hash: Executable's sha256 hash.
        :param str version_number: Product version number.
        """
        json = {
            "file_name": file_name,
            "md5_hash": md5_hash,
            "product_name": product_name,
            "sha256_hash": sha256_hash,
            "version_number": version_number
        }
        return cls(json)


class EndpointApplication(Element):
    """
    ECA Endpoint Application Identify an ECA Endpoint application
    """
    typeof = "ei_application_situation"
    situation_context_name = "EI Correlation"

    @classmethod
    def create(cls, name=None, version_number=None, product_name=None,
               signer_name=None, eca_custom_situation_type="signer_information", file_name=None,
               eca_executable=None,
               comment=None):
        """
        Create an eca endpoint setting
        :param str name: Name of ECA Endpoint Application.
        :param str version_number: Product version number.
        :param str product_name: Name of the product.
        :param str signer_name: Name of the signer.
        :param str eca_custom_situation_type: One of eca custom situation type.
            1. product_information
            2. signer_information
            3. executable_list
        :param str file_name: Product file name.
        :param list(ECAExecutable) eca_executable: Eca executables.
        :param str comment: Optional comment.

        :rtype: EndpointApplication
        """
        try:
            situation_context_ref = InspectionSituationContext(
                EndpointApplication.situation_context_name).href
        except ElementNotFound as ex:
            raise ex
        eca_executable = eca_executable if eca_executable else []

        json = {
            "name": name,
            "version_number": version_number,
            "product_name": product_name,
            "eca_custom_situation_type": eca_custom_situation_type,
            "file_name": file_name,
            "situation_context_ref": situation_context_ref,
            "comment": comment,
        }
        if eca_custom_situation_type == "signer_information":
            json.update(signer_name=signer_name)
        elif eca_custom_situation_type == "executable_list":
            json.update(eca_executable=[executable.data for executable in eca_executable])
        return ElementCreator(cls, json)

    @property
    def eca_executable(self):
        """
        ECA Executable object used by ECA Custom situations.
        :rtype: list(ECAExecutable)
        """

        return [ECAExecutable(executable) for executable in self.data.get("eca_executable", [])]
