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
Example script to show how to use DomainName.
"""

from smc import session
from smc.compat import is_smc_version_less_than_or_equal
from smc.elements.network import DomainName
from smc_info import SMC_URL, API_KEY, API_VERSION

NOT_CREATED_MSG = "Fail to create domain name."
NOT_UPDATE_ERROR = "Fail to update an domain name."
DOMAIN_NAME = 'test_domain_name'
COMMENT = "This is testing of DomainName."
if __name__ == "__main__":
    try:
        session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120,
                      api_version=API_VERSION)
        print("session OK")
        if is_smc_version_less_than_or_equal("6.10"):
            domain_name = DomainName.create(DOMAIN_NAME,
                                            comment=COMMENT)
            print("Successfully created DomainName")
        else:
            domain_name = DomainName.create(DOMAIN_NAME, domain_name_entry=["test1", "test2"],
                                            comment=COMMENT)
            assert "test1" in domain_name.domain_name_entry, NOT_CREATED_MSG
            print("Successfully created DomainName")
            domain_name.update(domain_name_entry=["test1", "test2", "test3"])
            domain_name = DomainName(DOMAIN_NAME)
            assert "test3" in domain_name.domain_name_entry, NOT_UPDATE_ERROR
            print("Successfully updated DomainName")
    except BaseException as e:
        print("Exception:{}".format(e))
        exit(-1)
    finally:
        DomainName(DOMAIN_NAME).delete()
        print("Successfully deleted DomainName")
