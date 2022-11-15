"""
Example script to show how to use EngineUpgrade object.
-get all upgrade package
-import engine upgrade
    Example : python import_engine_upgrade.py /tmp/engine_remote_upgrade.zip
    where:
        /tmp/engine_remote_upgrade.zip : The complete path to the engine upgrade file
         to be imported
"""

# Python Base Import
import logging
import sys
import re
import smc.examples

# Python SMC Import
from os.path import exists
from smc import session
from smc.administration.system import System
from smc.api.exceptions import ActionCommandFailed

from smc_info import SMC_URL, API_KEY, API_VERSION

FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
NOT_IMPORTED_ERR = "The upgrade package is not imported!."
ALREADY_IMPORTED_ERR = "The upgrade package has already been imported and downloaded. " \
                       "First delete the upgrade and then try again."
FORCE_IMPORT_FLAG = True

if __name__ == "__main__":

    logging.getLogger()
    logging.basicConfig(level=logging.INFO, format=FORMAT, datefmt="%H:%M:%S")
    session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120, api_version=API_VERSION)

    print("session OK")

    try:
        if len(sys.argv) >= 2:
            IMPORT_UPGRADE_FILE = sys.argv[1]
            UPGRADE_VERSION = re.search(r'\d+.\d+.\d+',
                                        IMPORT_UPGRADE_FILE).group(0)
        else:
            logging.error("Engine upgrade zip file path is missing "
                          "from command line.")
            exit(-1)
        system = System()
        logging.info("retrieve all engine upgrade in desc order")
        upgrades = system.engine_upgrade()
        upgrade = upgrades.get_contains(UPGRADE_VERSION)
        logging.info("Engine upgrade version {} is available ".format(UPGRADE_VERSION))
        logging.info("Import Engine Upgrade from a file : {}".format(IMPORT_UPGRADE_FILE))
        # To test this condition we need import available in local directory
        if exists(IMPORT_UPGRADE_FILE):
            imported_packages = system.engine_upgrade_import(IMPORT_UPGRADE_FILE, FORCE_IMPORT_FLAG)
            upgrades = system.engine_upgrade()
            upgrade = upgrades.get_contains(UPGRADE_VERSION)
            assert ".zip" in upgrade.name, NOT_IMPORTED_ERR

    except ActionCommandFailed as exception:
        logging.error("Task failed: {}".format(str(exception)))
        exit(-1)
    except BaseException as e:
        print("ex={}".format(e))
        exit(-1)

    finally:
        session.logout()
