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
Example script to show how to use Administration Domains, Administrators and WebPortalAdminUser.
"""

import logging
import time
import traceback
from smc import session
from smc.administration.reports import ReportDesign
from smc.core.engines import IPS
from smc.elements.servers import LogServer
from smc.api.exceptions import UpdateElementFailed
from smc.administration.system import AdminDomain
from smc.elements.tags import FilterExpressionTag
from smc.elements.user import AdminUser, ApiClient, WebPortalAdminUser
from smc.policy.layer3 import FirewallSubPolicy, FirewallTemplatePolicy
from smc_info import *

logging.getLogger()
logging.basicConfig(level=logging.INFO)

error_update = "Element reference breaks domain boundary restriction"
domain_name = "domain_test"
admin_name = "admin_test"
web_admin_test = "web_admin_test"
admin_password = "MySuperPassword2021!"
admin_user_lock_error = "Failed to Lock Admin User"
admin_user_unlock_error = "Failed to Unlock Admin User"
announcement_message = "Test Message"
access_attribute_error = "Failed to access AdminDomain's attribute"
failed_update_web_user = "Failed to update web portal admin user"
receive_error_value = "Receive incorrect values"
access_attribute_error = "Failed to access AdminDomain's attribute."
pwd_meta_data_error = "Failed to get password meta data error."
RETRY = 3
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

        # WebPortalAdminUser
        if WebPortalAdminUser.objects.filter(web_admin_test, exact_match=True):
            WebPortalAdminUser(web_admin_test).delete()
        # create web portal admin user
        sub_policy = list(FirewallSubPolicy.objects.all())[0]
        print("Accessing sub policy : {}".format(sub_policy))
        filter_tag = list(FilterExpressionTag.objects.all())[0]
        print("Accessing filter tag : {}".format(filter_tag))
        report_design = list(ReportDesign.objects.all())[0]
        print("Accessing report design : {}".format(report_design))
        template_policy = list(FirewallTemplatePolicy.objects.all())[0]
        print("Accessing template policy : {}".format(template_policy))
        engine = list(IPS.objects.all())[0]
        admin = WebPortalAdminUser.create(web_admin_test, log_service_enabled=True,
                                          policy_service_enabled=True, report_service_enabled=True,
                                          granted_template_policy=[template_policy],
                                          granted_report_design=[report_design],
                                          granted_sub_policy=[sub_policy],
                                          filter_tag=[filter_tag.href], show_inspection_policy=True,
                                          show_main_policy=True, show_only_ip_addresses=True,
                                          show_sub_policy=True, show_template_policy=True,
                                          show_upload_comment=True, show_upload_history=True)
        print("WebPortalAdminUser created successfully.")
        assert admin.log_service_enabled and admin.policy_service_enabled and admin. \
            report_service_enabled, receive_error_value
        # update some attributes
        admin.update(log_service_enabled=False, policy_service_enabled=False,
                     report_service_enabled=False)
        assert not admin.log_service_enabled and not admin.policy_service_enabled and not \
            admin.report_service_enabled, failed_update_web_user
        admin.update(granted_engine=[engine.href])
        assert admin.granted_engine, "Failed to update granted engine."
        print("Updated WebPortalAdminUser successfully.")
        # change password
        admin.change_password(admin_password)
        # check enable disable is working for web admin user.
        # disable web admin user
        admin.enable_disable()
        is_user_enable = True
        retry = 0
        while is_user_enable and retry < RETRY:
            admin = WebPortalAdminUser(web_admin_test)
            is_user_enable = admin.enabled
            time.sleep(2)
            retry += 1
        # check web admin  user is disabled
        assert not admin.enabled, failed_update_web_user
        # enable web admin user
        admin.enable_disable()
        retry = 0
        while not is_user_enable and retry < RETRY:
            admin = WebPortalAdminUser(web_admin_test)
            is_user_enable = admin.enabled
            time.sleep(2)
            retry += 1
        # check web admin user is enable
        assert admin.enabled, failed_update_web_user
        print("Check enable disable request")
        # Create new SMC Admin
        if AdminUser.objects.filter(name=admin_name):
            AdminUser(admin_name).enable_disable()
            time.sleep(1)
            AdminUser(admin_name).delete()
            logging.info("AdminUser [%s] has been deleted", admin_name)

        admin = AdminUser.create(admin_name, superuser=True)
        admin.change_password(admin_password)
        # check password meta data
        assert admin.password_meta_data.creation_date, pwd_meta_data_error
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

        # Delete Web Admin User
        WebPortalAdminUser(web_admin_test).delete()
        logging.info("WebPortalAdminUser [%s] has been deleted", web_admin_test)

        session.logout()
