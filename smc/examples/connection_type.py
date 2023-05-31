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
Example script to show how to use Connection Type
"""
from smc import session
from smc.elements.netlink import LinkType
from smc.vpn.elements import ConnectionType
from smc_info import *

connection_type_name = "test_connection_type"
message = "Testing of connection link."
mode = 'active'
if __name__ == '__main__':
    session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120, api_version=API_VERSION)
    print("session OK")

try:
    link_type = list(LinkType.objects.all())[0]
    print("Accessing first link type element.")
    # create connection type
    connection_type = ConnectionType.create(name=connection_type_name, mode=mode,
                                            connectivity_group=1, link_type_ref=link_type,
                                            comment=message)
    assert connection_type.mode() == mode, "Failed to create connection type with mode attribute."
    assert connection_type.link_type_ref() == link_type.href, "Failed to create connection type " \
                                                              "with link_type_ref attribute"
    print("Connection Type {} created successfully.".format(connection_type.name))
    connection_type.update(link_type_ref=None)
    assert connection_type.link_type_ref() is None, "Failed to update connection type."
except Exception as e:
    print("Exception is: {}".format(str(e)))
    exit(1)
finally:
    ConnectionType(connection_type_name).delete()
    print("Deleted Connection Type Successfully.")
    session.logout()
