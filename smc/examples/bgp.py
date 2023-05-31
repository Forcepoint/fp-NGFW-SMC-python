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
Example script to show how to use BGP stuff like BGPProfile.
"""

from smc import session
from smc.elements.network import Network
from smc.routing.bgp import BGPProfile, BGPAggregationEntry, RedistributionEntry
from smc_info import SMC_URL, API_KEY, API_VERSION

NOT_CREATED_MSG = "Failed to create BGPProfile."
UPDATE_ERROR = "Failed to update an BGPProfile."
NAME = 'BGP_Profile'
INTERNAL_DISTANCE = 100
EXTERNAL_DISTANCE = 200
LOCAL_DISTANCE = 50
ENABLED = True
REDISTRIBUTION_TYPE = "kernel"
if __name__ == "__main__":
    try:
        session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120,
                      api_version=API_VERSION)
        network = list(Network.objects.all())[0]
        aggregation_entry = BGPAggregationEntry.create("aggregate_as_set", network)
        bgp_profile = BGPProfile.create(
            name=NAME,
            internal_distance=INTERNAL_DISTANCE,
            external_distance=EXTERNAL_DISTANCE,
            local_distance=LOCAL_DISTANCE,
            subnet_distance=[(network, INTERNAL_DISTANCE)],
            aggregation_entry=[
                aggregation_entry.data],
            redistribution_entry=[
                RedistributionEntry.create("kernel", enabled=ENABLED, filter_type=None).data,
                RedistributionEntry.create("static", enabled=ENABLED, filter_type=None).data])
        aggregation_entry = bgp_profile.aggregation_entry[0]
        for entry in bgp_profile.redistribution_entry:
            if entry.data["type"] == REDISTRIBUTION_TYPE:
                assert entry.data["enabled"] == ENABLED, NOT_CREATED_MSG
                break
        assert bgp_profile.internal_distance == INTERNAL_DISTANCE and bgp_profile.external_distance\
               == EXTERNAL_DISTANCE and aggregation_entry.data.get("subnet") == \
               aggregation_entry.data["subnet"], NOT_CREATED_MSG
        print("BGPProfile is successfully created.")
        bgp_profile = BGPProfile(NAME)
        bgp_profile.update(internal=EXTERNAL_DISTANCE, external=INTERNAL_DISTANCE,
                           local=INTERNAL_DISTANCE)
        assert bgp_profile.internal_distance == EXTERNAL_DISTANCE and \
               bgp_profile.external_distance == INTERNAL_DISTANCE and \
               bgp_profile.local_distance == INTERNAL_DISTANCE, UPDATE_ERROR
        print("BGPProfile is successfully updated.")
    except BaseException as e:
        print("Exception:{}".format(e))
        exit(-1)
    finally:
        print("BGPProfile is successfully deleted.")
        BGPProfile(NAME).delete()
