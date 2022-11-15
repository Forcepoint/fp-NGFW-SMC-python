"""
Example script to export all elements.
-follow the result and check result is valid zip file
-use exclude_trashed option
-import inconsistent import file. check exception
"""

# Python Base Import
import logging
import zipfile
import smc.examples

# Python SMC Import
from smc import session
from smc.administration.system import System
from smc.api.exceptions import ActionCommandFailed
from smc.core.engines import Layer2Firewall
from smc_info import *

if __name__ == "__main__":

    session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120, api_version=API_VERSION)

    print("session OK")

    # try export all
    system = System()
    export_zip = "/tmp/export_test.zip"

    # check trashed host is in export (default case)
    # using the SMC Client need first to create a testHostTrashed Host and trash it
    system.export_elements(export_zip, timeout=5, max_tries=50)
    the_zip_file = zipfile.ZipFile(export_zip)
    data_xml = the_zip_file.open('exported_data.xml').read()
    assert data_xml.find('testHostTrashed'.encode()) > -1,\
        "Host testHostTrashed not found in export"

    # use exclude_trashed=true parameter and check trashed host NOT in export
    system.export_elements(export_zip, timeout=5, max_tries=50, exclude_trashed=True)
    the_zip_file = zipfile.ZipFile(export_zip)
    data_xml = the_zip_file.open('exported_data.xml').read()
    assert data_xml.find('testHostTrashed'.encode()) == -1, "Host testHostTrashed found in export"

    valid_zip = the_zip_file.testzip()

    # check export all is valid
    if valid_zip is not None:
        logging.warning("Invalid zip file")
    else:
        logging.info("Zip file is valid")

    logging.info("Export firewall")
    # try export firewall
    l2FW = Layer2Firewall("Atlanta L2 FW")
    for interface in l2FW.interface:
        logging.info("interface=" + str(interface))
    l2FW.export("/tmp/Atlantal2FW.zip")

    # try import corrupted file
    logging.info("Import Corrupted file")
    try:
        system.import_elements("/tmp/WRONG_Atlantal2FW.zip")
    except ActionCommandFailed as exception:
        logging.warning("Import result: " + str(exception))

    except BaseException as e:
        print("ex={}".format(e))
        exit(-1)
    finally:
        session.logout()
