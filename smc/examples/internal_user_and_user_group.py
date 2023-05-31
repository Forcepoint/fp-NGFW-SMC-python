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
Example of creating and accessing internal user and internal user group.
"""

from smc import session
from smc.administration.user_auth.servers import AuthenticationMethod
from smc.administration.user_auth.users import InternalUserGroup, InternalUser
from smc.base.util import element_resolver
from smc.core.engines import Layer3Firewall
from smc_info import API_VERSION, SMC_URL, API_KEY

INTERNAL_USER_GROUP_CREATE_ERROR = "Failed to create internal user group."
FAILED_TO_CREATE_USER = "Failed to create internal user."
UPDATE_ERROR = "Failed to update internal user."
UPDATE_AUTH_METHOD_ERROR = "Failed to update method to internal user."
group_name = "test_internal_user_group"
user_name1 = "test_internal_user1"
user_name2 = "test_internal_user2"
user_password = "test_internal_user1"
pre_shared_key = "XYXPQRABCD"
method1 = AuthenticationMethod(name="User password")
method2 = AuthenticationMethod(name="Pre-Shared Key Method")


def check_if_user_present(user_name):
    """
    check if the user is present or not.
    """
    is_user_created = InternalUser.objects.filter(name=user_name)
    assert is_user_created, FAILED_TO_CREATE_USER


def delete_if_user_present(user_name):
    """
    check and delete if the user is present.
    """
    if InternalUser.objects.filter(name=user_name, exact_match=True):
        InternalUser(user_name).delete()


def create_user_group_and_verify():
    """
    If an internal user group is present, delete it, then add it again and validate that it was
    created.
    """
    if InternalUserGroup.objects.filter(name=group_name, exact_match=True):
        InternalUserGroup(group_name).delete()
    internal_user_group = InternalUserGroup.create(group_name)
    is_group_created = InternalUserGroup.objects.filter(name=group_name)
    assert is_group_created, INTERNAL_USER_GROUP_CREATE_ERROR
    print("successfully created an internal user group : {}".format(group_name))
    return internal_user_group


if __name__ == "__main__":
    try:
        session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120,
                      api_version=API_VERSION)
        print("session OK")
        # get list of all internal user group
        all_internal_user_group = list(InternalUserGroup.objects.all())
        print("Accessing the list of internal user groups: {}".format(len(all_internal_user_group)))
        internal_user_group_object = create_user_group_and_verify()
        delete_if_user_present(user_name1)
        authentication_methods = [method1.href]
        internal_user_object1 = InternalUser.create(user_name1, password=user_password,
                                                    authentication_method=authentication_methods,
                                                    comment="testing of internal user")
        check_if_user_present(user_name1)
        print("internal user successfully created: {}".format(user_name1))
        internal_user_object1.update(password=user_password,
                                     user_group=element_resolver([internal_user_group_object]))
        assert [group for group in internal_user_object1.user_group if
                group.name == internal_user_group_object.name], UPDATE_ERROR
        print("Member of internal user group added to internal user")
        authentication_methods = [method.href for method in
                                  list(AuthenticationMethod.objects.all()) if
                                  method.name in [method1.name, method2.name]]

        internal_user_object1.update(pre_shared_key="XYXPQRABCD",
                                     authentication_method=authentication_methods,
                                     password=user_password)
        print("Added two authentication method to internal user")
        assert [method for method in internal_user_object1.authentication_method if
                method.name == method2.name], UPDATE_AUTH_METHOD_ERROR
        delete_if_user_present(user_name2)
        internal_user_object2 = InternalUser.create(user_name2, pre_shared_key=pre_shared_key,
                                                    authentication_method=[method2.href],
                                                    comment="testing of internal user")
        check_if_user_present(user_name2)
    except BaseException as e:
        print("Exception:{}".format(e))
        exit(-1)
    finally:
        InternalUserGroup(group_name).delete()
        print("Internal user group {} successfully deleted".format(group_name))
        InternalUser(user_name1).delete()
        print("Internal user {} successfully deleted".format(user_name1))
        InternalUser(user_name2).delete()
        print("Internal user {} successfully deleted.".format(user_name2))
