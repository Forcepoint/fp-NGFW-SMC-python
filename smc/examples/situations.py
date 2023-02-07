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
Example to show how to use situations:
1-create Validation Succeed TLS Match situation with domain list
2-create No Validation TLS Match situation
3-create Validation Failed TLS Match situation
4-retrieve TLSMatchSituation information
"""
import smc.examples

from smc import session
from smc.base.model import Element
from smc.elements.situations import TLSMatchSituation, InspectionSituation, SubTLSMatchSituation
from smc_info import SMC_URL, API_KEY, API_VERSION

if __name__ == "__main__":
    session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120, api_version=API_VERSION)
    print("session OK")

try:
    SUCCEED_TLS_MATCH: str = "myTestTLSMatch_succeed"
    NO_VALIDATION_TLS_MATCH: str = "myTestTLSMatch_no_validation"
    VALIDATION_FAILED_TLS_MATCH: str = "myTestTLSMatch_validation_failed"

    # create TLSMatchSituation validation succeed
    TLSMatchSituation.create(name=SUCCEED_TLS_MATCH,
                             match_certificate_validation="succeed_tls_validation",
                             matching_domains=["bar.com", "foo.com"],
                             deny_decrypting=False)

    # create TLSMatchSituation no validation
    TLSMatchSituation.create(name=NO_VALIDATION_TLS_MATCH,
                             match_certificate_validation="no_validation",
                             deny_decrypting=True)

    # create TLSMatchSituation validation_failed
    TLSMatchSituation.create(name=VALIDATION_FAILED_TLS_MATCH,
                             match_certificate_validation="validation_failed",
                             validation_failed_matches=["match_self_signed_certificates",
                                                        "match_non_trusted_CAs"],
                             deny_decrypting=True)

    # check domain list created
    myTls = TLSMatchSituation(SUCCEED_TLS_MATCH)
    for parameter in myTls.parameter_values:
        print("parameter={}".format(parameter))
        lst_sub_situations = parameter.data.data.get("sub_situations")
        if lst_sub_situations is not None:
            for sub_situation_href in lst_sub_situations:
                sub_situation = Element.from_href(sub_situation_href)
                print("sub_situation={}".format(sub_situation))
                for sub_parameter in sub_situation.parameter_values:
                    print("parameter={}".format(sub_parameter))
                    domain_list = sub_parameter.data.data.get("string_values")
                    if domain_list is not None:
                        for domain in domain_list:
                            print("domain={}".format(domain))
                    assert domain_list is not None, "Domain list not created !!"


except BaseException as e:
    print("ex={}".format(e))
    exit(-1)
finally:
    TLSMatchSituation(SUCCEED_TLS_MATCH).delete()
    TLSMatchSituation(NO_VALIDATION_TLS_MATCH).delete()
    TLSMatchSituation(VALIDATION_FAILED_TLS_MATCH).delete()
    session.logout()
