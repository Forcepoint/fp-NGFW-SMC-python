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
Example script to show how to subscribe to BLACKLIST notifications using websocket library
or smc_monitoring extension
Since SMC>=7.0 BLACKLIST is renamed BLOCK_LIST
"""

import argparse
import datetime
# Python Base Import
import json
import logging
import math
import ssl
import sys
import threading
import time

sys.path.append('../../../')  # smc-python
sys.path.append('../../../smc-monitoring')  # smc-python-monitoring
from smc import session  # noqa
from websocket import create_connection, WebSocketTimeoutException  # noqa
from smc_monitoring.monitors.blacklist import BlacklistQuery  # noqa
from smc.administration.system import System  # noqa
from smc.compat import is_smc_version_less_than  # noqa
from smc.core.engines import Layer3Firewall  # noqa
from smc.elements.other import Blacklist  # noqa
from smc.policy.layer3 import FirewallPolicy  # noqa

WRONG_ENTRIES_SIZE = "Couldn't retrieve the expected number of entries!"
NOT_ONLINE = "Node is not online!"

ENGINENAME = "myFw"
RETRY_ONLINE = 30

# Try with large number of blacklist entries
NUMBER_BLACKLIST_ENTRIES = 300

#     """ Define logger used in python file. """
formatter = logging.Formatter('%(asctime)s:%(name)s.%(funcName)s:%(levelname)s: %(message)s')
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(formatter)
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(console_handler)
logger.propagate = False

logging.getLogger()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - '
                                               '%(name)s - [%(levelname)s] : %(message)s')


# create a blacklist entry each 5 second
def add_blacklist_entry(idx, engine, nb_to_add=1):
    logging.info(" ")
    logging.info("Thread started: add new entries...")
    for i in range(nb_to_add):
        # Add blacklist entry
        time.sleep(5)
        ip_src = "{}.{}.0.1/32".format(idx, i + 1)
        logging.info(f"Thread: add new entry:src={ip_src}")
        engine.blacklist(src=ip_src, dst="10.0.0.2/32")
    logging.info("Thread terminated")


def main():
    return_code = 0
    try:
        arguments = parse_command_line_arguments()
        session.login(url=arguments.api_url, api_key=arguments.api_key,
                      login=arguments.smc_user,
                      pwd=arguments.smc_pwd, api_version=arguments.api_version,
                      verify=False)
        logging.info("session OK")

        logging.info(f'{datetime.datetime.now().strftime("%H:%M:%S")} => '
                     f'Create Engine:{ENGINENAME}..')
        engine = Layer3Firewall.create(name=ENGINENAME,
                                       mgmt_ip="192.168.10.1",
                                       mgmt_network="192.168.10.0/24")
        logging.info("initial contact and license..")
        for node in engine.nodes:
            node.initial_contact()
            node.bind_license()

        # wait time for engine to be online
        online = False
        retry = 0
        while not online and retry < RETRY_ONLINE:
            status = engine.nodes[0].status().monitoring_state
            online = status == "READY"
            logging.info(f"{datetime.datetime.now().strftime('%H:%M:%S')} =>state={status}")
            time.sleep(5)
            retry += 1

        logging.info(f"{datetime.datetime.now().strftime('%H:%M:%S')} =>create and upload policy..")
        policy = FirewallPolicy().create("myPolicy1")

        poller = engine.upload(policy="myPolicy1", wait_for_finish=True)
        while not poller.done():
            poller.wait(5)
            logging.info(f"Task Progress {poller.task.progress}%")
        logging.info(poller.last_message())

        # wait time for engine to be online
        online = False
        retry = 0
        while not online and retry < RETRY_ONLINE:
            status = engine.nodes[0].status().monitoring_state
            online = status == "READY"
            logging.info(f"{datetime.datetime.now().strftime('%H:%M:%S')} =>state={status}")
            time.sleep(5)
            retry += 1

        assert online, NOT_ONLINE

        # git cito.
        logging.info(f"{datetime.datetime.now().strftime('%H:%M:%S')} => Add blacklist to all "
                     f"defined engines..")
        System().blacklist("11.11.0.1/32", "11.11.0.2/32")

        engine = Layer3Firewall(ENGINENAME)

        # create 10 entries
        logging.info(f'{datetime.datetime.now().strftime("%H:%M:%S")} => '
                     f'Add 10 blacklist entries to engine..')
        bl = Blacklist()
        for i in range(10):
            ip_src = "11.0.0.{}/32".format(i)
            logging.info(f"{datetime.datetime.now().strftime('%H:%M:%S')} => "
                         f"add entry:src={ip_src}")
            bl.add_entry(src=ip_src, dst="10.0.0.2/32")
        engine.blacklist_bulk(bl)

        # wait time for entries to be added
        time.sleep(5)

        logging.info(" ")
        logging.info(f'{datetime.datetime.now().strftime("%H:%M:%S")} => '
                     f'Retrieve Blacklist using websocket library')
        ws = create_connection(
            f"{arguments.ws_url}/{str(arguments.api_version)}/monitoring/session/socket",
            cookie=session.session_id,
            timeout=10,
            subprotocols={"access_token", session._token} if session._token else None,
            sslopt={"cert_reqs": ssl.CERT_NONE}
        )
        if is_smc_version_less_than("7.0"):
            definition = "BLACKLIST"
        else:
            definition = "BLOCK_LIST"
        query = {
            "query": {"definition": definition, "target": ENGINENAME},
            "fetch": {},
            "format": {"type": "texts"},
        }

        try:
            ws.send(json.dumps(query))
            result = ws.recv()
            logging.info(f"Received '{result}'")
            fetch_id = json.loads(result)['fetch']

            retry = 0
            entry_added = False
            while not entry_added:
                try:
                    result = ws.recv()
                    logging.info(f"Received '{result}'")
                    added = json.loads(result).get("records").get("added")
                    entry_added = len(added) >= 1
                except WebSocketTimeoutException as e:
                    # No entry has been received within 10s
                    logging.error(e)
                    logging.info(f"{datetime.datetime.now().strftime('%H:%M:%S')} => "
                                 f"add entry:src={'1.1.1.1/32'}")
                    engine.blacklist(src="1.1.1.1/32", dst="100.0.0.1/32")
                finally:
                    assert retry < 10, WRONG_ENTRIES_SIZE
                    retry += 1

        except BaseException as e:
            logging.error(f"{datetime.datetime.now().strftime('%H:%M:%S')} => "
                          f"Failed to retrieve entries:{e} !")
            exit(-1)
        finally:
            ses_mon_abort_query = {"abort": fetch_id}
            ws.send(json.dumps(ses_mon_abort_query))
            ws.close()
        logging.info(f"{datetime.datetime.now().strftime('%H:%M:%S')} => Retrieved:{len(added)} !")

        # create 10 entries
        logging.info(f"{datetime.datetime.now().strftime('%H:%M:%S')} => "
                     f"Add 10 blacklist entries to engine..")
        bl = Blacklist()
        for i in range(10):
            ip_src = "10.0.0.{}/32".format(i)
            logging.info(f"{datetime.datetime.now().strftime('%H:%M:%S')} => "
                         f"add entry:src={ip_src}")
            bl.add_entry(src=ip_src, dst="100.0.0.2/32")
        engine.blacklist_bulk(bl)

        # wait time for entries to be added
        time.sleep(5)

        # create thread to simulate adding 10 new entries every five seconds
        t1 = threading.Thread(target=add_blacklist_entry, args=(1, engine, 10))
        t1.start()

        logging.info(" ")
        logging.info(f"{datetime.datetime.now().strftime('%H:%M:%S')} => "
                     f"Retrieve Blacklist Data using smc_monitoring fetch_batch while new entries "
                     f"are received within inactivity delay (in this case all the entries since "
                     f"they are generated every 5 seconds)")
        query = BlacklistQuery(ENGINENAME)
        for record in query.fetch_batch(max_recv=0, query_timeout=120, inactivity_timeout=20):
            logging.info(f"{datetime.datetime.now().strftime('%H:%M:%S')} => {record}")
        logging.info(f"{datetime.datetime.now().strftime('%H:%M:%S')} => Retrieved !")

        #
        # create a large number of entries
        #
        logging.info(f"{datetime.datetime.now().strftime('%H:%M:%S')} => "
                     f"Add {NUMBER_BLACKLIST_ENTRIES} blacklist entries to engine..")
        bl = Blacklist()
        nb_block = math.floor(NUMBER_BLACKLIST_ENTRIES / 250)
        for k in range(nb_block):
            logging.info(f"{datetime.datetime.now().strftime('%H:%M:%S')} => "
                         f"add 250 entries block {k}...")
            for i in range(250):
                ip_src = "{}.0.0.{}/32".format(30 + k, i)
                bl.add_entry(src=ip_src, dst="10.0.0.2/32")
        nb_entries = NUMBER_BLACKLIST_ENTRIES - nb_block * 250
        logging.info(f"{datetime.datetime.now().strftime('%H:%M:%S')} => "
                     f"add {nb_entries} entries block {k + 1}...")
        for i in range(nb_entries):
            ip_src = "{}.0.0.{}/32".format(30 + k + 1, i)
            bl.add_entry(src=ip_src, dst="10.0.0.2/32")
        engine.blacklist_bulk(bl)

        #
        # Retrieve all entries:
        # use max_recv=0, inactivity_timeout=20
        logging.info(f"{datetime.datetime.now().strftime('%H:%M:%S')} => "
                     f"Retrieve all BlacklistEntry elements using smc_monitoring fetch_as_element")
        query = BlacklistQuery(ENGINENAME)
        count = 0
        for element in query.fetch_as_element(max_recv=0, inactivity_timeout=20):
            logging.info(f"{datetime.datetime.now().strftime('%H:%M:%S')} => "
                         f"{element.first_fetch} "
                         f"{element.blacklist_id} "
                         f"{element.blacklist_entry_key} "
                         f"{element.engine} "
                         f"{element.href} "
                         f"{element.source}"
                         f"{element.destination} "
                         f"{element.protocol} "
                         f"{element.duration}"
                         )
            count += 1
        logging.info(f"{datetime.datetime.now().strftime('%H:%M:%S')} => {count} entries retrieved")
        logging.info(f"{datetime.datetime.now().strftime('%H:%M:%S')} => fetch ended, join..")
        t1.join()
        logging.info(f"{datetime.datetime.now().strftime('%H:%M:%S')} => join ended")

    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1

    finally:
        # remove blacklist entries
        logging.info("Remove blacklist entries..")
        query = BlacklistQuery(ENGINENAME)
        for element in query.fetch_as_element(max_recv=0, query_timeout=5):
            logging.info(f"Remove {element.blacklist_entry_key}")
            element.delete()
        engine = Layer3Firewall(ENGINENAME)
        engine.blacklist_flush()
        engine.delete()
        FirewallPolicy("myPolicy1").delete()

        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to subscribe to BLACKLIST notifications using '
                    'websocket library or smc_monitoring extension',
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
        '--ws-url',
        type=str,
        help='SMC WS url like https://192.168.1.1:8082')
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
