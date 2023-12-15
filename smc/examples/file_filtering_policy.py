#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import logging
import sys

# Python Base Import
# Python SMC Import
sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.compat import is_api_version_less_than_or_equal  # noqa
from smc.elements.alerts import CustomAlert  # noqa
from smc.elements.network import Zone, AddressRange, DomainName  # noqa
from smc.elements.tags import SituationGroupTag, FileFilteringCompatibilityTag  # noqa
from smc.policy.file_filtering import FileFilteringPolicy  # noqa
from smc.policy.rule_elements import FileFilteringRuleAction, Destination, MatchExpression, \
    Source, SituationMatchPart, LogOptions  # noqa

POLICY_CREATE_ERROR = "Fail to create file filtering policy."
CREATE_RULE_ERROR = "Fail to create file filtering policy rule."
UPDATE_RULE_ERROR = "Fail to update file filtering policy rule."
POLICY_NAME = 'test_file_filtering_policy'
COMMENT = "This is to test file filtering policy."
RULE1 = "ffp_rule_1"
RULE2 = "ffp_rule_2"

logging.getLogger()
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - '
                                                '%(name)s - [%(levelname)s] : %(message)s')


def action_settings(action, sandbox=True, icap_dlp_file_size_exceeded_action="ALLOW",
                    icap_dlp_max_file_size=50, icap_dlp_scan_enabled=True,
                    icap_dlp_service_fail_action="DISCARD",
                    rematch_archive_content=True, sandbox_allow_level="unknown",
                    sandbox_delay_file_transfer=True, scan_detection="undefined"):
    rule_action = FileFilteringRuleAction()
    if is_api_version_less_than_or_equal("6.5"):
        rule_action.action = action
    else:
        rule_action.action = [action]
    rule_action.sandbox = sandbox
    rule_action.icap_dlp_file_size_exceeded_action = icap_dlp_file_size_exceeded_action
    rule_action.icap_dlp_max_file_size = icap_dlp_max_file_size
    rule_action.icap_dlp_scan_enabled = icap_dlp_scan_enabled
    rule_action.icap_dlp_service_fail_action = icap_dlp_service_fail_action
    rule_action.rematch_archive_content = rematch_archive_content
    rule_action.sandbox_allow_level = sandbox_allow_level
    rule_action.sandbox_delay_file_transfer = sandbox_delay_file_transfer
    rule_action.scan_detection = scan_detection

    return rule_action


def main():

    return_code = 0
    try:
        arguments = parse_command_line_arguments()
        session.login(url=arguments.api_url, api_key=arguments.api_key,
                      login=arguments.smc_user,
                      pwd=arguments.smc_pwd, api_version=arguments.api_version)

        # delete if FileFilteringPolicy present
        logging.info("delete if file filtering policy present")
        if FileFilteringPolicy.objects.filter(POLICY_NAME, exact_match=True):
            if FileFilteringPolicy(POLICY_NAME).is_locked():
                FileFilteringPolicy(POLICY_NAME).unlock()
                logging.info("File filtering policy is locked, unlocked it")

            FileFilteringPolicy(POLICY_NAME).delete()
            logging.info("Deleted File filtering policy as it was already exist")

        # create File Filtering Policy
        policy = FileFilteringPolicy.create(POLICY_NAME, COMMENT)
        assert policy.name == POLICY_NAME and isinstance(policy,
                                                         FileFilteringPolicy), POLICY_CREATE_ERROR
        logging.info(f"File filtering policy is created successfully with name: {POLICY_NAME}")

        # adding first rule with any and action allow
        situations = {"any": True}
        action = action_settings('allow')
        connection_tracking_options = {'mss_enforced': True, 'mss_enforced_max': 10,
                                       'mss_enforced_min': 0, 'timeout': -1, 'state': None,
                                       'sync_connections': None}
        # add file filtering rule
        policy.file_filtering_rules.create(
            name=RULE1,
            sources="any",
            destinations="any",
            situations="any",
            connection_tracking=connection_tracking_options,
            action=action,
        )
        added_rule = list(policy.file_filtering_rules)[0]

        assert added_rule.sources.is_any and added_rule.destinations.is_any and \
               added_rule.situations.is_any and "allow" in added_rule.action.action and \
               added_rule.action.sandbox, CREATE_RULE_ERROR
        added_rule.action.update(action=['discard'], sandbox=False)
        added_rule.update()
        policy = FileFilteringPolicy(POLICY_NAME)
        added_rule = list(policy.file_filtering_rules)[0]
        assert "discard" in added_rule.action.action and \
               not added_rule.action.sandbox, UPDATE_RULE_ERROR

        # adding second rule with action allow_after

        interface_zone1 = list(Zone.objects.all())[0]
        address_range1 = list(AddressRange.objects.all())[0]
        domain_name1 = list(DomainName.objects.all())[0]
        # create Expression1
        match_expression1 = MatchExpression.create(name="expression1", zone=interface_zone1,
                                                   network_element=address_range1,
                                                   domain_name=domain_name1)
        interface_zone2 = list(Zone.objects.all())[1]
        address_range2 = list(AddressRange.objects.all())[1]
        domain_name2 = list(DomainName.objects.all())[1]

        # create Expression2
        match_expression2 = MatchExpression.create(name="expression2", zone=interface_zone2,
                                                   network_element=address_range2,
                                                   domain_name=domain_name2)

        source = Source()
        source.add_many([match_expression1])
        destinations = Destination()
        destinations.add_many([match_expression2, match_expression1])

        situation_tag = list(SituationGroupTag.objects.all())[0]
        file_filtering_tag = list(FileFilteringCompatibilityTag.objects.all())[0]

        situation_match_part = SituationMatchPart()
        situation_match_part.add_many([situation_tag, file_filtering_tag])
        option = LogOptions()
        option.log_accounting_info_mode = True
        option.log_severity = 10
        option.log_level = "alert"
        option.log_alert = list(CustomAlert.objects.all())[0]

        # add file filtering rule2
        policy.file_filtering_rules.create(
            name=RULE2,
            sources=source,
            destinations=destinations,
            situations=situation_match_part,
            connection_tracking=connection_tracking_options,
            action=action,
            log_options=option
        )
        added_rule = \
            list(filter(lambda rule: rule.name == RULE2, list(policy.file_filtering_rules)))[0]
        source_flag = False
        for element in added_rule.sources.all()[0].values():
            if (isinstance(element, Zone) and element.href == interface_zone1.href) or (
                    isinstance(element, AddressRange) and element.href == address_range1.href) or (
                    isinstance(element, DomainName) and element.href == domain_name1.href):
                source_flag = True
            else:
                source_flag = False
                break

        assert source_flag and "allow" in added_rule.action.action and \
               added_rule.action.sandbox, CREATE_RULE_ERROR
        added_rule.action.update(action=['allow_after'], sandbox=False)
        added_rule.update()
        policy = FileFilteringPolicy(POLICY_NAME)
        added_rule = \
            list(filter(lambda rule: rule.name == RULE2, list(policy.file_filtering_rules)))[0]
        assert "allow_after" in added_rule.action.action and \
               not added_rule.action.sandbox, UPDATE_RULE_ERROR
    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        # delete FileFilteringPolicy
        FileFilteringPolicy(POLICY_NAME).delete()
        logging.info("FileFilteringPolicy Deleted successfully")
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show the File Filtering Policy',
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


if __name__ == '__main__':
    sys.exit(main())
