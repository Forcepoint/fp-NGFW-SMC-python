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
Tag elements like 'ip_country_group' or 'ip_list_group'.
"""
from smc.base.model import Element


class IPListGroupTag(Element):
    """
    IP List group tag elements cannot be created, only viewed.
    """

    typeof = "ip_list_group"


class SpecificSoftwareTag(Element):
    """
    Specific Software Tag elements cannot be created, only viewed.
    """

    typeof = "application_specific_tag"


class NotSpecificSoftwareTag(Element):
    """
    Not Specific Software Tag elements cannot be created, only viewed.
    """

    typeof = "application_not_specific_tag"


class HardwareTag(Element):
    """
    Hardware Tag elements cannot be created, only viewed.
    """

    typeof = "hardware_tag"


class SpecificPlatformTag(Element):
    """
    Specific Platform Tag elements cannot be created, only viewed.
    """

    typeof = "os_specific_tag"


class NotSpecificPlatformTag(Element):
    """
    Not Specific Platform Tag elements cannot be created, only viewed.
    """

    typeof = "os_not_specific_tag"


class ApplicationGroupTag(Element):
    """
    Application Group Tag elements cannot be created, only viewed.
    """

    typeof = "application_group_tag"


class ApplicationRiskTag(Element):
    """
    Application Risk Tag elements cannot be created, only viewed.
    """

    typeof = "application_risk_tag"


class ApplicationTag(Element):
    """
    Application Tag elements cannot be created, only viewed.
    """

    typeof = "application_tag"


class ApplicationUsageGroupTag(Element):
    """
    Application Usage Group Tag elements cannot be created, only viewed.
    """

    typeof = "application_usage_group_tag"


class ApplicationUsageTag(Element):
    """
    Application Usage Tag elements cannot be created, only viewed.
    """

    typeof = "application_usage_tag"


class ECAApplicationCategoryTag(Element):
    """
    ECA Application Category Tag elements cannot be created, only viewed.
    """

    typeof = "eia_application_category_tag"


class ECAApplicationUsageGroupCategoryTag(Element):
    """
    ECA Application Category Tag elements cannot be created, only viewed.
    """

    typeof = "eia_application_usage_group_tag"


class FileFilteringCompatibilityTag(Element):
    """
    File Filtering Compatibility Tag elements cannot be created, only viewed.
    """

    typeof = "file_filtering_compatibility_tag"


class FilterExpressionTag(Element):
    """
    Filter Expression Tag elements cannot be created, only viewed.
    """

    typeof = "filter_expression_tag"


class SidewinderTag(Element):
    """
    Sidewinder Tag elements cannot be created, only viewed.
    """

    typeof = "sidewinder_tag"


class SituationGroupTag(Element):
    """
    Situation Group Tag elements cannot be created, only viewed.
    """

    typeof = "situation_group_tag"


class TrustedCATag(Element):
    """
    Trusted CA Tag elements cannot be created, only viewed.
    """

    typeof = "trusted_ca_tag"


class URLCategoryRiskTag(Element):
    """
    URL Category Risk Tag elements cannot be created, only viewed.
    """

    typeof = "url_category_risk_tag"


class VulnerabilityImpactTag(Element):
    """
    Vulnerability Impact Tag elements cannot be created, only viewed.
    """

    typeof = "vulnerability_impact_tag"


class VulnerabilityTypeTag(Element):
    """
    Vulnerability Impact Tag elements cannot be created, only viewed.
    """

    typeof = "vulnerability_tag"
