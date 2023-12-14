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
Example script to show how to use Engine Node health
-get virtual engine or Layer3 firewall
-get health data for each node
-retrieve master engine from virtual engine health
"""

# Python Base Import
import argparse
import logging
import sys

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.core.engines import Layer3VirtualEngine, Layer3Firewall  # noqa
from smc.core.waiters import NodeStatusWaiter  # noqa

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

        virtual_engine = Layer3VirtualEngine("Dubai Virtual 1")
        logging.info(f"Check nodes status for {virtual_engine}...")

        for node in virtual_engine.nodes:

            # Wait for node to be Online
            waiter = NodeStatusWaiter(node, "Online", max_wait=3)
            while not waiter.done():
                status = waiter.result(5)
                logging.info(f"Status after 5 sec wait: {status}")
            logging.info(f"Node:{node} is {status}")

            assert status is not None, f"Node {node} can't be contacted"

            for stats in node.hardware_status.filesystem:
                logging.info(f"hardware status.filesystem={stats}")
            for stats in node.hardware_status.logging_subsystem:
                logging.info(f"hardware status.logging_subsystem={stats}")
            for stats in node.hardware_status.sandbox_subsystem:
                logging.info(f"hardware status.sandbox_subsystem={stats}")
            for stats in node.interface_status:
                logging.info(f"interface status={stats}")
            logging.info(f"health=>Master Node={node.health.master_node}")
            logging.info(f"health=>Node status={node.health.engine_node_status}")
            logging.info(f"health=>dyn up={node.health.dyn_up}")
            # print all attributes
            logging.info(f"health=>{node.health}")

        single_fw = Layer3Firewall("Plano")
        logging.info(f"Check nodes status for {single_fw}...")

        for node in single_fw.nodes:

            # Wait for node to be Online
            waiter = NodeStatusWaiter(node, 'Online', max_wait=3)
            while not waiter.done():
                status = waiter.result(5)
                logging.info(f"Status after 5 sec wait: {status}")
            logging.info(f"Node:{node} is {status}")

            assert status is not None, f"Node {node} can't be contacted"

            # should be None
            logging.info(f"health=>Master Node={node.health.master_node}")
            logging.info(f"health=>Node status={node.health.engine_node_status}")
            logging.info(f"health=>dyn up={node.health.dyn_up}")
            # print all attributes
            logging.info(f"health=>{node.health}")
    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to use Engine Node Health',
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
