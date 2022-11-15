"""
Example script to show how to use UpdatePackage object.
-get all update package
-import update package
-activate imported update package
"""

# Python Base Import
import logging
import smc.examples

# Python SMC Import
import time
from os.path import exists

from smc import session
from smc.administration.system import System
from smc.api.exceptions import ActionCommandFailed
from smc.base.model import LoadElement
from smc_info import SMC_URL, API_KEY, API_VERSION

FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
UPDATE_PACKAGE_FILE = "/tmp/sgpkg-ips-2711t-5242.jar"
NOT_IMPORTED_ERR = "Update package is not correctly imported!"
NOT_ACTIVATED_ERR = "Update package is not correctly activated!"


def refresh_update_package(update_package_to_refresh, state):
    nb_iter = 0
    while nb_iter < 5 and update_package_to_refresh.state.lower() != state:
        logging.info('state {}'.format(update_package_to_refresh.state))
        time.sleep(5)
        update_package_to_refresh.data = LoadElement(update_package_to_refresh.href)
        nb_iter += 1


if __name__ == "__main__":

    session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120, api_version=API_VERSION)

    print("session OK")

    try:

        system = System()

        logging.info("retrieve all update packages in desc order")
        for update in system.update_package():
            logging.info(update)
            if update.state.lower() == "available":
                next_update = update

        # download and import next available update package received
        if next_update is not None:
            logging.info("download update package {}..".format(next_update))
            poller = next_update.download(wait_for_finish=True)
            while not poller.done():
                poller.wait(5)
                logging.info('Percentage complete {}%'.format(poller.task.progress))

            # refresh next_update after download ( needed to refresh "state" attribute)
            refresh_update_package(next_update, "imported")
            assert next_update.state.lower() == "imported", NOT_IMPORTED_ERR

            logging.info("activate update package:{}".format(next_update))
            poller = next_update.activate(wait_for_finish=True)
            while not poller.done():
                poller.wait(10)
                logging.info('Percentage complete {}%'.format(poller.task.progress))

            # refresh next_update after activation ( needed to refresh "state" attribute)
            refresh_update_package(next_update, "active")
            assert next_update.state.lower() == "active", NOT_ACTIVATED_ERR

        # this part is not run in robot tests
        logging.info("Import update package from file")
        if exists(UPDATE_PACKAGE_FILE):
            imported_packages = system.update_package_import(UPDATE_PACKAGE_FILE)
            for update_package in imported_packages:
                logging.info("imported update package update package:{}".format(update_package))

    except ActionCommandFailed as exception:
        logging.error("Task failed: " + str(exception))
        exit(-1)
    except BaseException as e:
        print("ex={}".format(e))
        exit(-1)

    finally:
        session.logout()
