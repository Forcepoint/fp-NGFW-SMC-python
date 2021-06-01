"""
Example of how to use asynchronous tasks
(Need to run using demo mode)

-Update a policy
-check pending changes
-run refresh task
-wait for task to be completed
-check pending changes
"""
import time

from smc import session
import logging

from smc.core.engines import Layer3Firewall
from smc.elements.service import TCPService
from smc.policy.layer3 import FirewallPolicy
from smc_info import *

logging.getLogger()

if __name__ == "__main__":
    session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120, api_version=API_VERSION)
    print("session OK")

try:
    plano = Layer3Firewall("Plano")

    # check for pending changes
    print("check for pending changes..")
    nb_changes_before = 0
    for changes in plano.pending_changes.all():
        print(changes, changes.resolve_element)
        nb_changes_before += 1
    print("changes found:{}".format(nb_changes_before))

    # update policy used by plano
    print("Update policy..")
    policy = FirewallPolicy(plano.installed_policy)
    new_rule = policy.fw_ipv4_access_rules.create(
                name="newrule",
                sources="any",
                destinations="any",
                services=[TCPService("SSH")],
                action="discard",
                )

    # check again for pending changes
    # wait for pending changes update
    time.sleep(1)
    print("check for pending changes..")
    nb_changes_after = 0
    for changes in plano.pending_changes.all():
        print(changes, changes.resolve_element)
        nb_changes_after += 1
    print("changes found:{}".format(nb_changes_after))

    # validate number of changes
    assert nb_changes_after == nb_changes_before + 1, "Pending changes are not consistent!"

    # accept all pending changes if needed by configuration
    # (@see Require approval for Changes in NGFW Engine Configuration)
#    print("accept all pending changes..")
#    plano.pending_changes.approve_all()

    # launch asynchronous refresh task
    print("run refresh policy task..")
    # generate_snapshot parameter is True by default
    task_follower = plano.refresh(wait_for_finish=True)
    while not task_follower.done():
        print("wait for task to be completed..")
        task_follower.wait(3)
    print("task success:{}, progress:{}, last message:{}".format(task_follower.task.success,
                                                                 task_follower.task.progress,
                                                                 task_follower.task.last_message))

    nb_changes_after_refresh = 0
    for changes in plano.pending_changes.all():
        print(changes, changes.resolve_element)
        nb_changes_after_refresh += 1
    print("changes found:{}".format(nb_changes_after_refresh))

    # validate number of changes
    assert nb_changes_after_refresh == 0, "Pending changes are not consistent after refresh!"

except BaseException as e:
    print(e)
    exit(-1)
finally:
    new_rule.delete()
    session.logout()
