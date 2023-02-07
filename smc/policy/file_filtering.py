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

from smc.policy.policy import Policy
from smc.base.model import SubElement
from smc.base.collection import rule_collection
from smc.policy.rule import RuleCommon


class FileFilteringRule(RuleCommon, SubElement):
    """
    Represents a file filtering rule
    """

    typeof = "file_filtering_rule"

    def create(self):
        pass

    def add_after(self):
        pass

    def add_before(self):
        pass


class FileFilteringPolicy(Policy):
    """
    The File Filtering Policy references a specific file based policy for
    doing additional inspection based on file types. Use the policy
    parameters to specify how certain files are treated by either threat
    intelligence feeds,sandbox or by local AV scanning. You can also use
    this policy to disable threat prevention based on specific files.
    """

    typeof = "file_filtering_policy"

    @classmethod
    def create(cls):
        pass

    @property
    def file_filtering_rules(self):
        """
        File filtering rules for this policy.

        :rtype: rule_collection(FileFilteringRule)
        """
        return rule_collection(self.get_relation("file_filtering_rules"), FileFilteringRule)

    def export(self):
        pass  # Not valid on file filtering policy
