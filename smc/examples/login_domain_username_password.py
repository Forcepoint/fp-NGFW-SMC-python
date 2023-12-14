#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
import argparse
import logging
import sys
import time

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.administration.reports import ReportDesign  # noqa
from smc.core.engines import IPS  # noqa
from smc.elements.servers import LogServer  # noqa
from smc.api.exceptions import UpdateElementFailed  # noqa
from smc.administration.system import AdminDomain  # noqa
from smc.administration.access_rights import Permission, AccessControlList  # noqa
from smc.administration.role import Role  # noqa
from smc.elements.tags import FilterExpressionTag  # noqa
from smc.elements.user import AdminUser, ApiClient, WebPortalAdminUser  # noqa
from smc.policy.layer3 import FirewallSubPolicy, FirewallTemplatePolicy  # noqa

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

logging.getLogger()
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - '
                                                '%(name)s - [%(levelname)s] : %(message)s')


def main():
    return_code = 0
    try:
        arguments = parse_command_line_arguments()
        session.login(url=arguments.api_url, api_key=arguments.api_key,
                      login=arguments.smc_user,
                      pwd=arguments.smc_pwd, api_version=arguments.api_version)

        # Create SMC Domain
        if AdminDomain.objects.filter(domain_name, exact_match=True):
            AdminDomain(domain_name).delete()
            logging.info(f"Domain [{domain_name}] has been deleted")

        domain_obj = AdminDomain.create(name=domain_name, announcement_enabled=False,
                                        announcement_message=announcement_message,
                                        contact_email='test@forcepoint.com',
                                        category_filter_system=True,
                                        show_not_categorized=True,
                                        comment='test creation')
        assert domain_obj.announcement_message == announcement_message, "{} {}".format(
            access_attribute_error, 'announcement_message')
        assert domain_obj.show_not_categorized, (f"{access_attribute_error} "
                                                 f"{'show_not_categorized'}")
        assert domain_obj.category_filter_system, (f"{access_attribute_error} "
                                                   f"{'category_filter_system'}")
        domain_obj.update(announcement_enabled=True)
        assert domain_obj.announcement_enabled, "Failed to update AdminDomain"

        # WebPortalAdminUser
        if WebPortalAdminUser.objects.filter(web_admin_test, exact_match=True):
            WebPortalAdminUser(web_admin_test).delete()
        # create web portal admin user
        sub_policy = list(FirewallSubPolicy.objects.all())[0]
        logging.info(f"Accessing sub policy : {sub_policy}")
        filter_tag = list(FilterExpressionTag.objects.all())[0]
        logging.info(f"Accessing filter tag : {filter_tag}")
        report_design = list(ReportDesign.objects.all())[0]
        logging.info(f"Accessing report design : {report_design}")
        template_policy = list(FirewallTemplatePolicy.objects.all())[0]
        logging.info(f"Accessing template policy : {template_policy}")
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
        logging.info("WebPortalAdminUser created successfully.")
        assert admin.log_service_enabled and admin.policy_service_enabled and admin. \
            report_service_enabled, receive_error_value
        # update some attributes
        admin.update(log_service_enabled=False, policy_service_enabled=False,
                     report_service_enabled=False)
        assert not admin.log_service_enabled and not admin.policy_service_enabled and not \
            admin.report_service_enabled, failed_update_web_user
        admin.update(granted_engine=[engine.href])
        assert admin.granted_engine, "Failed to update granted engine."
        logging.info("Updated WebPortalAdminUser successfully.")
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
        logging.info("Check enable disable request")
        # Create new SMC Admin
        if AdminUser.objects.filter(name=admin_name):
            AdminUser(admin_name).enable_disable()
            time.sleep(1)
            AdminUser(admin_name).delete()
            logging.info(f"AdminUser [{admin_name}] has been deleted", )

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

        session.login(url=arguments.api_url,
                      login=admin_name, domain=domain_name,
                      pwd=admin_password, api_version=arguments.api_version)

        try:
            LogServer("Log Server").update(comment='updated in sub domain')
        except UpdateElementFailed as error:
            logging.error("Update of log server failed but is is expected")
            assert str(error).__contains__(error_update), \
                logging.error(f"Expecting to have [{error_update}] but got [{error}]")

        # Create SMC Admin in sub domain
        permissions = Permission.create([AccessControlList('ALL Elements')],
                                        Role("Operator"),
                                        domain=AdminDomain(domain_name))
        admin = AdminUser.create(name=f"smc_user_{domain_name}", permissions=[permissions])
        admin.change_password(password="MyComplexPassword00!")

        session.logout()

    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1

    finally:
        # Cleanup env
        session.login(url=arguments.api_url, api_key=arguments.api_key,
                      login=arguments.smc_user,
                      pwd=arguments.smc_pwd, api_version=arguments.api_version)

        # Delete SMC Domain
        AdminDomain(domain_name).delete()
        logging.info(f"Domain [{domain_name}] has been deleted")

        # Delete new SMC Admin
        AdminUser(admin_name).enable_disable()
        time.sleep(1)
        AdminUser(admin_name).delete()
        logging.info(f"AdminUser [{admin_name}] has been deleted")

        # Delete Web Admin User
        WebPortalAdminUser(web_admin_test).delete()
        logging.info(f"WebPortalAdminUser [{web_admin_test}] has been deleted")

        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to use Administration Domains, Administrators and '
                    'WebPortalAdminUser',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        add_help=False)
    parser.add_argument(
        '-h', '--help',
        action='store_true',
        help='show this help message and exit')

    parser.add_argument(
        '--api-url',
        type=str,
        help='SMC API url like https://192.168.1.1:8082')
    parser.add_argument(
        '--api-version',
        type=str,
        help='The API version to use for run the script'
    )
    parser.add_argument(
        '--smc-user',
        type=str,
        help='SMC API user')
    parser.add_argument(
        '--smc-pwd',
        type=str,
        help='SMC API password')
    parser.add_argument(
        '--api-key',
        type=str, default=None,
        help='SMC API api key (Default: None)')

    arguments = parser.parse_args()

    if arguments.help:
        parser.print_help()
        sys.exit(1)
    if arguments.api_url is None:
        parser.print_help()
        sys.exit(1)

    return arguments


if __name__ == '__main__':
    sys.exit(main())
