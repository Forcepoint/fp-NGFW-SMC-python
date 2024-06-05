#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
import argparse
import logging
import sys

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.base.model import Element  # noqa
from smc.elements.situations import TLSMatchSituation, InspectionSituationContext, \
    InspectionSituation, _severity_by_name  # noqa

SUCCEED_TLS_MATCH: str = "myTestTLSMatch_succeed"
NO_VALIDATION_TLS_MATCH: str = "myTestTLSMatch_no_validation"
VALIDATION_FAILED_TLS_MATCH: str = "myTestTLSMatch_validation_failed"
SITUATION_NAME = "test_inspection_situation"
CREATE_SITUATION_ERROR = "Fail to create inspection situation."
UPDATE_SITUATION_ERROR = "Fail to update inspection situation."


logging.getLogger()
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - '
                                                '%(name)s - [%(levelname)s] : %(message)s')


def main():
    return_code = 0
    try:
        arguments = parse_command_line_arguments()
        session.login(url=arguments.api_url, api_key=arguments.api_key,
                      login=arguments.smc_user,
                      pwd=arguments.smc_pwd, api_version=arguments.api_version)
        logging.info("session OK")

        situation_context = InspectionSituationContext("Executable File Stream")
        logging.info("Creation of {} situation.".format(SITUATION_NAME))
        is_situation = InspectionSituation.create(name=SITUATION_NAME,
                                                  situation_context=situation_context,
                                                  severity='critical')
        is_situation.create_regular_expression("situation_regexp_content")
        is_situation = InspectionSituation(SITUATION_NAME)
        is_valid_pa = False
        for parameter_value in is_situation.parameter_values:
            if parameter_value.reg_exp == "situation_regexp_content":
                is_valid_pa = True
                break
        assert is_situation.severity == "critical" and \
               is_situation.situation_context.href == situation_context.href and \
               is_valid_pa, CREATE_SITUATION_ERROR
        logging.error(f"Successfully created InspectionSituation.")

        is_situation = InspectionSituation(SITUATION_NAME)
        situation_context = InspectionSituationContext("File Stream Redirection").href
        is_situation.update(severity=_severity_by_name('information'),
                            situation_context_ref=situation_context)
        is_situation = InspectionSituation(SITUATION_NAME)
        assert is_situation.severity == "information" and \
               is_situation.situation_context.href == situation_context, UPDATE_SITUATION_ERROR
        logging.error(f"Successfully updated InspectionSituation.")

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
            logging.info(f"parameter={parameter}")
            lst_sub_situations = parameter.data.data.get("sub_situations")
            if lst_sub_situations is not None:
                for sub_situation_href in lst_sub_situations:
                    sub_situation = Element.from_href(sub_situation_href)
                    logging.info(f"sub_situation={sub_situation}")
                    for sub_parameter in sub_situation.parameter_values:
                        logging.info(f"parameter={sub_parameter}")
                        domain_list = sub_parameter.data.data.get("string_values")
                        if domain_list is not None:
                            for domain in domain_list:
                                logging.info(f"domain={domain}")
                        assert domain_list is not None, "Domain list not created !!"
    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        InspectionSituation(SITUATION_NAME).delete()
        logging.error(f"Successfully deleted InspectionSituation.")
        TLSMatchSituation(SUCCEED_TLS_MATCH).delete()
        TLSMatchSituation(NO_VALIDATION_TLS_MATCH).delete()
        TLSMatchSituation(VALIDATION_FAILED_TLS_MATCH).delete()
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to use situations',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        add_help=False)
    parser.add_argument(
        '-h', '--help',
        action='store_true',
        help='show this help message and exit')

    parser.add_argument(
        '--api-url',
        type=str,
        help='SMC API url like https://192.168.1.1:8082')
    parser.add_argument(
        '--api-version',
        type=str,
        help='The API version to use for run the script'
    )
    parser.add_argument(
        '--smc-user',
        type=str,
        help='SMC API user')
    parser.add_argument(
        '--smc-pwd',
        type=str,
        help='SMC API password')
    parser.add_argument(
        '--api-key',
        type=str, default=None,
        help='SMC API api key (Default: None)')

    arguments = parser.parse_args()

    if arguments.help:
        parser.print_help()
        sys.exit(1)
    if arguments.api_url is None:
        parser.print_help()
        sys.exit(1)

    return arguments


if __name__ == "__main__":
    sys.exit(main())
