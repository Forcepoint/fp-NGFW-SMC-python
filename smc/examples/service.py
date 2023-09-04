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
Example script to show how to use EthernetService.
"""

from smc import session
from smc.elements.group import EthernetServiceGroup
from smc.elements.protocols import ProtocolAgent
from smc.elements.service import EthernetService
from smc_info import SMC_URL, API_KEY, API_VERSION

ETHERNET_SERVICE_CREATE_ERROR = "Fail to create an EthernetService."
ETHERNET_SERVICE_UPDATE_ERROR = "Fail to update an EthernetService."
ETHERNET_SERVICE_NAME = 'test_ethernet_service'
COMMENT1 = "This is testing of EthernetService."
ETHERNET_SERVICE_GROUP_CREATE_ERROR = "Fail to create an EthernetServiceGroup."
ETHERNET_SERVICE_GROUP_UPDATE_ERROR = "Fail to update an EthernetServiceGroup."
ETHERNET_SERVICE_GROUP_NAME = 'test_ethernet_service_group'
COMMENT2 = "This is testing of EthernetServiceGroup."
if __name__ == "__main__":
    try:
        session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120,
                      api_version=API_VERSION)
        print("session OK")
        protocol = list(ProtocolAgent.objects.all())[0]
        ethernet_service = EthernetService.create(ETHERNET_SERVICE_NAME, frame_type="eth2",
                                                  protocol_agent_ref=protocol, value1='1',
                                                  value2='2', comment=COMMENT1)
        assert ethernet_service.value1 == '0x1' and ethernet_service.value2 == '0x2' and \
               ethernet_service.protocol_agent_ref.href == \
               protocol.href, ETHERNET_SERVICE_CREATE_ERROR
        print("Successfully created EthernetService.")
        ethernet_service.update(value1=int('3', 16), value2=int('4', 16))
        ethernet_service = EthernetService(ETHERNET_SERVICE_NAME)
        assert ethernet_service.value1 == '0x3' and ethernet_service.value2 == \
               '0x4', ETHERNET_SERVICE_UPDATE_ERROR
        print("Successfully updated EthernetService.")
        ethernet_service_group = EthernetServiceGroup.create(ETHERNET_SERVICE_GROUP_NAME,
                                                             members=[ethernet_service],
                                                             comment=COMMENT2)
        assert ethernet_service_group.members[
                   0] == ethernet_service.href, ETHERNET_SERVICE_GROUP_CREATE_ERROR
        print("Successfully created EthernetServiceGroup.")
        ethernet_service_group.empty_members()
        ethernet_service_group = EthernetServiceGroup(ETHERNET_SERVICE_GROUP_NAME)
        assert not ethernet_service_group.members, ETHERNET_SERVICE_GROUP_UPDATE_ERROR
        print("Successfully updated EthernetServiceGroup.")
    except BaseException as e:
        print("Exception:{}".format(e))
        exit(-1)
    finally:
        EthernetServiceGroup(ETHERNET_SERVICE_GROUP_NAME).delete()
        print("Successfully deleted EthernetServiceGroup")
        EthernetService(ETHERNET_SERVICE_NAME).delete()
        print("Successfully deleted EthernetService")
