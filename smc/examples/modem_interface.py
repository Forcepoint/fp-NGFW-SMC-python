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
Example script to show how to use Modem interfaces (LTE/4G)
- create a Layer3Firewall
- create a modem interface with an APN
- iterate engine.modem_interface and verify href is valid
- delete the modem interface and the firewall
"""

import argparse
import logging
import sys

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.core.engines import Layer3Firewall  # noqa

logging.getLogger()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - '
                                               '%(name)s - [%(levelname)s] : %(message)s')

ENGINE_NAME = "myModemFw"
MODEM_INTERFACE_ID = "5"
APN_NAME = "internet"


def main():
    return_code = 0
    arguments = parse_command_line_arguments()
    try:
        session.login(url=arguments.api_url, api_key=arguments.api_key,
                      login=arguments.smc_user,
                      pwd=arguments.smc_pwd, api_version=arguments.api_version,
                      verify=False)
        logging.info("session OK")

        # Create a minimal Layer3Firewall for testing
        logging.info("Creating engine %s", ENGINE_NAME)
        engine = Layer3Firewall.create(
            name=ENGINE_NAME,
            mgmt_ip="192.168.100.1",
            mgmt_network="192.168.100.0/24",
        )
        logging.info("Engine created successfully")

        # Create a modem interface with an APN
        logging.info("Creating modem interface %s with APN '%s'", MODEM_INTERFACE_ID, APN_NAME)
        engine.modem_interface.add_layer3_interface(
            interface_id=MODEM_INTERFACE_ID,
            apn=APN_NAME,
            interfaces=[{"dynamic_index": 1, "automatic_default_route": True}],
        )
        logging.info("Modem interface created successfully")

        # Invalidate engine cache so physicalInterfaces is re-fetched
        engine._del_cache()

        # Iterate modem_interface and verify href
        logging.info("Iterating engine.modem_interface to check href...")
        modem_ifaces = list(engine.modem_interface)
        assert len(modem_ifaces) > 0, "No modem interfaces found after creation"

        for iface in modem_ifaces:
            logging.info("  interface=%s  href=%s", iface.name, iface.href)
            assert iface.href is not None, (
                "ModemInterface href is None for '%s'" % iface.name
            )

        logging.info("All modem interfaces have a valid href: OK")

        # Delete the modem interface
        if arguments.clean_created_resources:
            for iface in engine.modem_interface:
                if iface.interface_id == MODEM_INTERFACE_ID:
                    logging.info("Deleting modem interface %s", iface.name)
                    iface.delete()
                    logging.info("Modem interface deleted successfully")
                    break

    except AssertionError as e:
        logging.error("Assertion failed: %s", e)
        return_code = 1
    except Exception as e:
        logging.error("Unexpected error: %s", e, exc_info=True)
        return_code = 1
    finally:
        try:
            if arguments.clean_created_resources:
                Layer3Firewall(ENGINE_NAME).delete()
                logging.info("Engine %s deleted", ENGINE_NAME)
        except Exception:
            pass
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to use modem interfaces (SMC-65692)',
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
        help='The API version to use for run the script')
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
    parser.add_argument(
        '--clean-created-resources',
        action=argparse.BooleanOptionalAction, default=True,
        help='Delete created elements at the end (Default: True)')

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
