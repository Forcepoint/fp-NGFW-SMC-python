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
Example of how to use asynchronous tasks
(Need to run using demo mode)

-Update a policy
-check pending changes
-run refresh task
-wait for task to be completed
-check pending changes
"""
import argparse
import logging
import sys
import time

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.administration.system import System  # noqa
from smc.core.engines import Layer3Firewall  # noqa
from smc.elements.service import TCPService  # noqa
from smc.policy.layer3 import FirewallPolicy  # noqa

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

        system = System()
        # activate system property: enforce_change_management, self_approve_changes
        # pending changes must be approved (@see approve_all()) before being refreshed
        system.update_system_property(system_key=50, new_value="true")
        system.update_system_property(system_key=51, new_value="true")

        plano = Layer3Firewall("Plano")

        # check for pending changes
        logging.info("check for pending changes..")
        nb_changes_before = 0
        for changes in plano.pending_changes.all():
            logging.info(changes, changes.resolve_element)
            nb_changes_before += 1
        logging.info(f"changes found:{nb_changes_before}")

        # update policy used by plano
        logging.info("Update policy..")
        policy = FirewallPolicy(plano.installed_policy)
        new_rule = policy.fw_ipv4_access_rules.create(
                    name="newrule",
                    sources="any",
                    destinations="any",
                    services=[TCPService("SSH")],
                    action="discard",
                    )

        # check again for pending changes
        # wait for pending changes update
        time.sleep(1)
        logging.info("check for pending changes..")
        nb_changes_after = 0
        for changes in plano.pending_changes.all():
            logging.info(changes, changes.resolve_element)
            nb_changes_after += 1
        logging.info(f"changes found:{nb_changes_after}")

        # validate number of changes
        assert nb_changes_after == nb_changes_before + 1, "Pending changes are not consistent!"

        # accept all pending changes if needed by configuration
        # (@see Global System Properties dialog:
        # Require approval for Changes in NGFW Engine Configuration)
        logging.info("accept all pending changes..")
        plano.pending_changes.approve_all()
        # check for approver atttribute
        for changes in plano.pending_changes.all():
            logging.info(changes, changes.approver)

        logging.info("check for pending changes after approve..")
        for changes in plano.pending_changes.all():
            logging.info(changes, changes.resolve_element)

        # launch asynchronous refresh task
        logging.info("run refresh policy task..")
        # generate_snapshot parameter is True by default
        task_follower = plano.refresh(wait_for_finish=True)
        while not task_follower.done():
            logging.info("wait for task to be completed..")
            task_follower.wait(3)
        logging.info(f"task success:{task_follower.task.success}, "
                     f"progress:{task_follower.task.progress}, "
                     f"last message:{task_follower.task.last_message}")

        # validate refresh successful
        assert task_follower.task.success, "Refresh failed!"

        # wait for pending changes to be deleted on mgt server
        logging.info("wait 5s..")
        time.sleep(5)

        nb_changes_after_refresh = 0
        for changes in plano.pending_changes.all():
            logging.info(changes, changes.resolve_element)
            nb_changes_after_refresh += 1
        logging.info(f"changes found:{nb_changes_after_refresh}")

        # validate number of changes
        assert nb_changes_after_refresh == 0, "Pending changes are not consistent after refresh!"

    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        new_rule.delete()
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to use asynchronous tasks',
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
