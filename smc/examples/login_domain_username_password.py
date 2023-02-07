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
Example script to show how to use Administration Domains and Administrators.
"""

import logging
import time
import traceback
import smc.examples

from smc import session
from smc.elements.servers import LogServer
from smc.api.exceptions import UpdateElementFailed
from smc.administration.system import AdminDomain
from smc.elements.user import AdminUser, ApiClient
from smc_info import *

logging.getLogger()
logging.basicConfig(level=logging.INFO)

error_update = "Element reference breaks domain boundary restriction"
domain_name = "domain_test"
admin_name = "admin_test"
admin_password = "MySuperPassword2021!"
admin_user_lock_error = "Failed to Lock Admin User"
admin_user_unlock_error = "Failed to Unlock Admin User"
announcement_message = "Test Message"
access_attribute_error = "Failed to access AdminDomain's attribute"

if __name__ == "__main__":

    try:
        session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120,
                      api_version=API_VERSION)

        # Create SMC Domain
        if AdminDomain.objects.filter(domain_name, exact_match=True):
            AdminDomain(domain_name).delete()
            logging.info("Domain [%s] has been deleted", domain_name)

        domain_obj = AdminDomain.create(name=domain_name, announcement_enabled=False,
                                        announcement_message=announcement_message,
                                        contact_email='test@forcepoint.com',
                                        category_filter_system=True,
                                        show_not_categorized=True,
                                        comment='test creation')
        assert domain_obj.announcement_message == announcement_message, "{} {}".format(
            access_attribute_error, 'announcement_message')
        assert domain_obj.show_not_categorized, "{} {}".format(access_attribute_error,
                                                               'show_not_categorized')
        assert domain_obj.category_filter_system, "{} {}".format(access_attribute_error,
                                                                 'category_filter_system')
        domain_obj.update(announcement_enabled=True)
        assert domain_obj.announcement_enabled, "Failed to update AdminDomain"
        # Create new SMC Admin
        if AdminUser.objects.filter(name=admin_name):
            AdminUser(admin_name).enable_disable()
            time.sleep(1)
            AdminUser(admin_name).delete()
            logging.info("AdminUser [%s] has been deleted", admin_name)

        admin = AdminUser.create(admin_name, superuser=True)
        admin.change_password(admin_password)
        # Lock Admin User
        AdminUser(admin_name).lock()
        assert AdminUser(admin_name).is_locked(), admin_user_lock_error
        # Unlock Admin User
        AdminUser(admin_name).unlock()
        assert not AdminUser(admin_name).is_locked(), admin_user_unlock_error
        session.logout()

        # small delay before connect with newly created user
        time.sleep(1)

        session.login(url=SMC_URL, api_version=API_VERSION, login=admin_name, pwd=admin_password,
                      domain=domain_name)

        try:
            LogServer("Log Server").update(comment='updated in sub domain')
        except UpdateElementFailed as error:
            logging.info("Update of log server failed but is is expected")
            assert str(error).__contains__(error_update), \
                logging.error("Expecting to have [%s] but got [%s]", error_update, error)

        session.logout()

    except BaseException as e:
        print("ex={}".format(e))
        print(traceback.format_exc())
        exit(-1)

    finally:
        # Cleanup env
        session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120,
                      api_version=API_VERSION)

        # Delete SMC Domain
        AdminDomain(domain_name).delete()
        logging.info("Domain [%s] has been deleted", domain_name)

        # Delete new SMC Admin
        AdminUser(admin_name).enable_disable()
        time.sleep(1)
        AdminUser(admin_name).delete()
        logging.info("AdminUser [%s] has been deleted", admin_name)

        session.logout()
