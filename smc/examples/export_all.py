"""
Example script to export all elements.
follow the result and check result is valid zip file

then import element
"""

# Python Base Import
import logging
import zipfile
import sys

# Python SMC Import
from smc import session
from smc.administration.system import System
from smc.api.exceptions import ActionCommandFailed
from smc.core.engines import Layer2Firewall

FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
logging.getLogger()
logging.basicConfig(level=logging.INFO, format=FORMAT, datefmt="%H:%M:%S")

if __name__ == "__main__":
    URLSMC = "http://localhost:8082"
    APIKEYSMC = "HuphG4Uwg4dN6TyvorTR0001"
    try:
        session.login(url=URLSMC, api_key=APIKEYSMC, verify=False, timeout=120)
    except BaseException as exception_retournee:
        sys.exit(-1)

    logging.info("session OK")

# try export all
system = System()
export_zip = "/tmp/export_test.zip"
system.export_elements(export_zip, timeout=5, max_tries=50)
the_zip_file = zipfile.ZipFile(export_zip)
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
