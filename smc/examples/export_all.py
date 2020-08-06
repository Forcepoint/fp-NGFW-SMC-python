"""
Example script to export all elements.
follow the result and check result is valid zip file

"""

# Python Base Import
import zipfile
import sys
# Python SMC Import
from smc import session
from smc.administration.system import System

if __name__ == '__main__':
    URLSMC='http://localhost:8082'
    APIKEYSMC='HuphG4Uwg4dN6TyvorTR0001'
    try:
        session.login(url=URLSMC, api_key=APIKEYSMC, verify=False, timeout=120)
    except BaseException as exception_retournee:
        sys.exit(-1)

    print("session OK")

system = System()
export_zip = "/tmp/export_test.zip"
system.export_elements(export_zip, timeout=5, max_tries=50)
the_zip_file = zipfile.ZipFile(export_zip)
valid_zip = the_zip_file.testzip()

if valid_zip is not None:
    print("Invalid zip file")
    sys.exit(1)
else:
    print("Zip file is valid")
    sys.exit(0)
