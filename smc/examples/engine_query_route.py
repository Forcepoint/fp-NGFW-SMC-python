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
Allows querying a route for the specific supported engine {cluster_type} with key
{element_key} Options:
A. Using Query Parameters:
    source: the IP Address A.B.C.D corresponding to the source query ip address.
    destination: the IP Address A.B.C.D corresponding to the destination query ip address.
B. Using payload to be able to specify source network element uri
    and/or destination network element uri.
"""
import argparse
import logging
import sys

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.core.engine import Engine  # noqa
from smc.elements.network import Host  # noqa

ROUTE_ERROR = "Error to get list of route"
engine_name = 'Plano'

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

        engine = Engine(engine_name)
        # Find route for source to destination using ip address
        list_of_route = engine.query_route(source_ip='0.0.0.0', destination_ip='0.0.0.0')
        assert list_of_route, ROUTE_ERROR
        # Find the route using query route with ref
        list_of_routing = list(Host.objects.all())
        if list_of_routing:
            host1 = list_of_routing[0]
            host2 = list_of_routing[1]
            list_of_route = engine.query_route(source_ref=host1.href, destination_ref=host2.href)
            assert list_of_route, ROUTE_ERROR
            list_of_route = engine.query_route(source_ip='0.0.0.0', destination_ref=host2.href)
            list_of_route = engine.query_route(source_ref=host1.href, destination_ip='0.0.0.0')
    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to allow querying a route for '
                    'the specific supported engine',
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
