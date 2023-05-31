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
Example script to show how to use UpdateServerProfile
"""
from smc import session
from smc.administration.certificates.tls import TLSProfile
from smc.elements.other import UpdateServerProfile
from smc_info import *

name = "test_update_server_profile"
message = "Testing of update server profile."
creation_error = "Failed to create update server profile with attribute."
update_error = "Failed to update server profile with retry attribute."
RETRY = 4
TIMEOUT = 30
URL = "https://autoupdate.ngfw.forcepoint.com/dynup.rss"

if __name__ == '__main__':
    session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120, api_version=API_VERSION)
    print("session OK")

try:
    print("Check and delete if UpdateServerProfile is present.")
    if UpdateServerProfile.objects.filter(name=name, exact_match=True):
        UpdateServerProfile(name).delete()
        print("Successfully deleted UpdateServerProfile.")
    tls_profile = list(TLSProfile.objects.all())[0]
    # create update server profile
    update_server_profile = UpdateServerProfile.create(name, retry=RETRY, timeout=TIMEOUT,
                                                       urls=[URL], tls_profile_ref=tls_profile,
                                                       comment=message)
    assert update_server_profile.retry == RETRY and update_server_profile.timeout == TIMEOUT,\
        creation_error
    print("Successfully created UpdateServerProfile.")
    update_server_profile.update(retry=RETRY + 1)
    assert update_server_profile.retry == RETRY + 1, update_error
    print("Successfully updated UpdateServerProfile.")

except Exception as e:
    print("Exception is: {}".format(str(e)))
    exit(1)
finally:
    UpdateServerProfile(name).delete()
    print("Deleted UpdateServerProfile successfully.")
    session.logout()
