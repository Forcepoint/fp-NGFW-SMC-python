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
Example script to show upcoming event usage.
- retrieve upcoming event
- get and update global policy
- get and update filtered situations
"""

# Python Base Import

# Python SMC Import
import smc.examples

from smc import session
from smc.administration.system import System
from smc.elements.situations import Situation
from smc_info import *

if __name__ == "__main__":

    session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120, api_version=API_VERSION)

    print("session OK")

    try:
        # get upcoming event
        system = System()
        events = system.upcoming_event()

        for event in events:
            print("event={}".format(event))

        # get upcoming event policy
        system = System()
        policy = system.upcoming_event_policy()

        print("")

        # read and disable all situations with severity=low
        for policy_entry in policy:
            print("Policy entry={}".format(policy_entry))
            if policy_entry.situation.severity == "low":
                print("disable situation:{}".format(policy_entry.situation))
                policy_entry.enabled = False

        # update the policy
        system.update_upcoming_event_policy(policy)

        # filter situation for current administrator
        situations = [Situation("MLC Certificate expires soon")]
        print("Ignore situations={}".format(situations))
        system.update_upcoming_event_ignore_settings(situations)

        # get filtered situations for the administrator
        filtered_situations = system.upcoming_event_ignore_settings().entries
        for situation in filtered_situations:
            print("filtered situation={}".format(situation))

    except Exception as e:
        print("Error:{}".format(e))
        exit(-1)
    finally:
        session.logout()
