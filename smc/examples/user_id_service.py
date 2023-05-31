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
Example script to show how to use UserIDService.
"""

from smc import session
from smc.administration.certificates.tls import TLSProfile
from smc.elements.profiles import UserIDService
from smc.elements.servers import LogServer
from smc.elements.ssm import LoggingProfile, ProbingProfile
from smc_info import SMC_URL, API_KEY, API_VERSION

CREATE_FAILED = "Failed to create UserIDService"
UPDATE_FAILED = "Failed to update UserIDService"
ADDRESS = "127.0.0.1"
PORT = 5000
NAME = 'user_id_service_test'
MSG = "testing of user id service"
EXPIRE = 500
TIMEOUT = 20
if __name__ == "__main__":
    try:
        session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120,
                      api_version=API_VERSION)
        print("session OK")
        tls = list(TLSProfile.objects.all())[0]
        logging_profile = list(LoggingProfile.objects.all())[0]
        log_server = list(LogServer.objects.all())[0]
        probing_profile = list(ProbingProfile.objects.all())[0]
        user_id_service = UserIDService.create(NAME,
                                               address="127.0.0.1",
                                               monitored_user_domains=None,
                                               netflow=True,
                                               snmp_trap=True,
                                               tls_field="DNSName",
                                               tls_value="10",
                                               tls_profile=tls,
                                               port=PORT,
                                               address_list=None,
                                               encoding="UTF-8",
                                               logging_profile=logging_profile,
                                               monitoring_log_server=log_server,
                                               probing_profile=probing_profile,
                                               time_zone="Europe/Paris",
                                               comment=MSG)
        assert user_id_service.address == ADDRESS and user_id_service.port == PORT, CREATE_FAILED
        print("UserIDService successfully created.")
        user_id_service.update(cache_expiration=EXPIRE, connect_timeout=TIMEOUT)
        user_id_service = UserIDService(NAME)
        assert user_id_service.cache_expiration == EXPIRE and user_id_service.connect_timeout == \
               TIMEOUT, UPDATE_FAILED
        print("UserIDService successfully updated.")

    except BaseException as e:
        print("Exception:{}".format(e))
        exit(-1)
    finally:
        UserIDService(NAME).delete()
        print("Deleted UserIDService successfully.")
