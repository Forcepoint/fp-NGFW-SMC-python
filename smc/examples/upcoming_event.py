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
Example script to show upcoming event usage.
- retrieve upcoming event
- get and update global policy
- get and update filtered situations
"""

# Python SMC Import
import argparse
import logging
import sys

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.administration.system import System  # noqa
from smc.elements.situations import Situation  # noqa

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

        # get upcoming event
        system = System()
        events = system.upcoming_event()

        for event in events:
            logging.info(f"event={event}")

        # get upcoming event policy
        system = System()
        policy = system.upcoming_event_policy()

        logging.info("")

        # read and disable all situations with severity=low
        for policy_entry in policy:
            logging.info(f"Policy entry={policy_entry}")
            if policy_entry.situation.severity == "low":
                logging.info(f"disable situation:{policy_entry.situation}")
                policy_entry.enabled = False

        # update the policy
        system.update_upcoming_event_policy(policy)

        # filter situation for current administrator
        situations = [Situation("MLC Certificate expires soon")]
        logging.info(f"Ignore situations={situations}")
        system.update_upcoming_event_ignore_settings(situations)

        # get filtered situations for the administrator
        filtered_situations = system.upcoming_event_ignore_settings().entries
        for situation in filtered_situations:
            logging.info(f"filtered situation={situation}")
    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show upcoming event usage.',
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
