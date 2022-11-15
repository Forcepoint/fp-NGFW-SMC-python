"""
Example script to show how to subscribe to BLACKLIST notifications using websocket library
or smc_monitoring extension
Since SMC>=7.0 BLACKLIST is renamed BLOCK_LIST
"""


# Python Base Import
import json
import logging
import math
import ssl
import sys
import threading
import time
import datetime
import smc.examples


from websocket import create_connection, WebSocketTimeoutException

from smc import session
from smc_monitoring.monitors.blacklist import BlacklistQuery

from smc.administration.system import System
from smc.compat import is_smc_version_less_than
from smc.core.engines import Layer3Firewall
from smc.elements.other import Blacklist
from smc.policy.layer3 import FirewallPolicy
from smc_info import SMC_URL, API_KEY, API_VERSION, WS_URL

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


# create a blacklist entry each 5 second
def add_blacklist_entry(idx, engine, nb_to_add=1):
    print()
    print("Thread started: add new entries...")
    for i in range(nb_to_add):
        # Add blacklist entry
        time.sleep(5)
        ip_src = "{}.{}.0.1/32".format(idx, i+1)
        print("Thread: add new entry:src={}".format(ip_src))
        engine.blacklist(src=ip_src, dst="10.0.0.2/32")
    print("Thread terminated")


if __name__ == '__main__':
    session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120, api_version=API_VERSION)
    print("session OK")

try:
    print("{} => Create Engine:{}..".format(datetime.datetime.now().strftime("%H:%M:%S"),
                                            ENGINENAME))
    engine = Layer3Firewall.create(name=ENGINENAME,
                                   mgmt_ip="192.168.10.1",
                                   mgmt_network="192.168.10.0/24")
    print("initial contact and license..")
    for node in engine.nodes:
        node.initial_contact()
        node.bind_license()

    # wait time for engine to be online
    online = False
    retry = 0
    while not online and retry < RETRY_ONLINE:
        status = engine.nodes[0].status().monitoring_state
        online = status == "READY"
        print("{} =>state={}".format(datetime.datetime.now().strftime("%H:%M:%S"), status))
        time.sleep(5)
        retry += 1

    print("{} =>create and upload policy..".format(datetime.datetime.now().strftime("%H:%M:%S")))
    policy = FirewallPolicy().create("myPolicy1")

    poller = engine.upload(policy="myPolicy1", wait_for_finish=True)
    while not poller.done():
        poller.wait(5)
        print("Task Progress {}%".format(poller.task.progress))
    print(poller.last_message())

    # wait time for engine to be online
    online = False
    retry = 0
    while not online and retry < RETRY_ONLINE:
        status = engine.nodes[0].status().monitoring_state
        online = status == "READY"
        print("{} =>state={}".format(datetime.datetime.now().strftime("%H:%M:%S"), status))
        time.sleep(5)
        retry += 1

    assert online, NOT_ONLINE

    # Add blacklist to all defined engines.
    print("{} => Add blacklist to all defined engines.."
          .format(datetime.datetime.now().strftime("%H:%M:%S")))
    System().blacklist("11.11.0.1/32", "11.11.0.2/32")

    engine = Layer3Firewall(ENGINENAME)

    # create 10 entries
    print("{} => Add 10 blacklist entries to engine.."
          .format(datetime.datetime.now().strftime("%H:%M:%S")))
    bl = Blacklist()
    for i in range(10):
        ip_src = "11.0.0.{}/32".format(i)
        print("{} => add entry:src={}".format(datetime.datetime.now().strftime("%H:%M:%S"), ip_src))
        bl.add_entry(src=ip_src, dst="10.0.0.2/32")
    engine.blacklist_bulk(bl)

    # wait time for entries to be added
    time.sleep(5)

    print()
    print("{} => Retrieve Blacklist using websocket library"
          .format(datetime.datetime.now().strftime("%H:%M:%S")))
    ws = create_connection(
        "{}/{}/monitoring/session/socket".format(WS_URL, str(API_VERSION)),
        cookie=session.session_id,
        timeout=10,
        socket=session.sock,
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
        print("Received '{}'".format(result))
        fetch_id = json.loads(result)['fetch']

        retry = 0
        entry_added = False
        while not entry_added:
            try:
                result = ws.recv()
                print("Received '{}'".format(result))
                added = json.loads(result).get("records").get("added")
                entry_added = len(added) >= 1
            except WebSocketTimeoutException as e:
                # No entry has been received within 10s
                print(e)
                print("{} => add entry:src={}"
                      .format(datetime.datetime.now().strftime("%H:%M:%S"), "1.1.1.1/32"))
                engine.blacklist(src="1.1.1.1/32", dst="100.0.0.1/32")
            finally:
                assert retry < 10, WRONG_ENTRIES_SIZE
                retry += 1

    except BaseException as e:
        print("{} => Failed to retrieve entries:{} !"
              .format(datetime.datetime.now().strftime("%H:%M:%S"), e))
        exit(-1)
    finally:
        ses_mon_abort_query = {"abort": fetch_id}
        ws.send(json.dumps(ses_mon_abort_query))
        ws.close()
    print("{} => Retrieved:{} !".format(datetime.datetime.now().strftime("%H:%M:%S"), len(added)))

    # create 10 entries
    print("{} => Add 10 blacklist entries to engine.."
          .format(datetime.datetime.now().strftime("%H:%M:%S")))
    bl = Blacklist()
    for i in range(10):
        ip_src = "10.0.0.{}/32".format(i)
        print("{} => add entry:src={}".format(datetime.datetime.now().strftime("%H:%M:%S"), ip_src))
        bl.add_entry(src=ip_src, dst="100.0.0.2/32")
    engine.blacklist_bulk(bl)

    # wait time for entries to be added
    time.sleep(5)

    # create thread to simulate adding 10 new entries every five seconds
    t1 = threading.Thread(target=add_blacklist_entry, args=(1, engine, 10))
    t1.start()

    print()
    print("{} => Retrieve Blacklist Data using smc_monitoring fetch_batch while new entries"
          " are received within inactivity delay (in this case all the entries since they are"
          " generated every 5 seconds)"
          .format(datetime.datetime.now().strftime("%H:%M:%S")))
    query = BlacklistQuery(ENGINENAME)
    for record in query.fetch_batch(max_recv=0, query_timeout=120, inactivity_timeout=20):
        print("{} => {}".format(datetime.datetime.now().strftime("%H:%M:%S"), record))
    print("{} => Retrieved !".format(datetime.datetime.now().strftime("%H:%M:%S")))

    #
    # create a large number of entries
    #
    print("{} => Add {} blacklist entries to engine.."
          .format(datetime.datetime.now().strftime("%H:%M:%S"), NUMBER_BLACKLIST_ENTRIES))
    bl = Blacklist()
    nb_block = math.floor(NUMBER_BLACKLIST_ENTRIES / 250)
    for k in range(nb_block):
        print("{} => add 250 entries block {}..."
              .format(datetime.datetime.now().strftime("%H:%M:%S"), k))
        for i in range(250):
            ip_src = "{}.0.0.{}/32".format(30+k, i)
            bl.add_entry(src=ip_src, dst="10.0.0.2/32")
    nb_entries = NUMBER_BLACKLIST_ENTRIES - nb_block * 250
    print("{} => add {} entries block {}..."
          .format(datetime.datetime.now().strftime("%H:%M:%S"), nb_entries, k+1))
    for i in range(nb_entries):
        ip_src = "{}.0.0.{}/32".format(30+k+1, i)
        bl.add_entry(src=ip_src, dst="10.0.0.2/32")
    engine.blacklist_bulk(bl)

    #
    # Retrieve all entries:
    # use max_recv=0, inactivity_timeout=20
    print("{} => Retrieve all BlacklistEntry elements using smc_monitoring fetch_as_element"
          .format(datetime.datetime.now().strftime("%H:%M:%S")))
    query = BlacklistQuery(ENGINENAME)
    count = 0
    for element in query.fetch_as_element(max_recv=0, inactivity_timeout=20):
        print("{} => {} {} {} {} {} {}".format(datetime.datetime.now().strftime("%H:%M:%S"),
                                               element.first_fetch,
                                               element.blacklist_id,
                                               element.blacklist_entry_key,
                                               element.engine,
                                               element.href,
                                               element.source,
                                               element.destination,
                                               element.protocol,
                                               element.duration))
        count += 1
    print("{} => {} entries retrieved"
          .format(datetime.datetime.now().strftime("%H:%M:%S"), count))
    print("{} => fetch ended, join..".format(datetime.datetime.now().strftime("%H:%M:%S")))
    t1.join()
    print("{} => join ended".format(datetime.datetime.now().strftime("%H:%M:%S")))

except BaseException as e:
    print(e)
    exit(-1)

finally:
    # remove blacklist entries
    print("Remove blacklist entries..")
    query = BlacklistQuery(ENGINENAME)
    for element in query.fetch_as_element(max_recv=0, query_timeout=5):
        print("Remove {}".format(element.blacklist_entry_key))
        element.delete()
    engine = Layer3Firewall(ENGINENAME)
    engine.blacklist_flush()
    engine.delete()
    FirewallPolicy("myPolicy1").delete()

    session.logout()
