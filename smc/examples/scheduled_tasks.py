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
Example of how to use scheduled tasks

1- create refresh/delete/export/archive task
2- start task manually
3- create a schedule

"""
import sys
import time

import smc.examples

from smc import session
from smc.administration.scheduled_tasks import RefreshPolicyTask, ExportLogTask, DeleteLogTask, \
    server_directory, ArchiveLogTask, RemoteUpgradeTask, ServerBackupTask
from smc.core.engine import Engine
from smc.core.engines import Layer3Firewall
from smc.elements.servers import ManagementServer, LogServer
from smc_info import SMC_URL, API_KEY, API_VERSION
RETRY_ONLINE = 30
ENGINE_NAME = 'test_engine'
NOT_CREATED_MSG = "Fail to create server backup task"
TASK_NAME = 'backup_task_test'

if __name__ == "__main__":
    session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120, api_version=API_VERSION)
    print("session OK")

try:
    execute_remote_upgrade = False

    # Create a refresh policy task
    task = RefreshPolicyTask.create(
        name='myrefreshpolicytask',
        engines=[Engine("Plano"), Engine("Paris")],
        comment='some comment')

    # Get all refresh tasks
    for task in RefreshPolicyTask.objects.all():
        print(task, task.task_schedule)

    # Create delete log task
    mgt_server = ManagementServer("Management Server")
    DeleteLogTask.create(
        name='mydeletelogtask',
        servers=[mgt_server],
        for_fw_log=True,
        comment='delete log task comment')

    # Get all delete log tasks
    for task in DeleteLogTask.objects.all():
        print(task, task.task_schedule)

    # check task created
    task = DeleteLogTask("mydeletelogtask")
    assert task.for_fw_log is True, "delete task is not consistent!"

    # start task manually
    task_to_follow = task.start()
    while not task_to_follow.get_task_poller().done():
        task_to_follow = task_to_follow.update_status()
        print("wait for delete log task to be completed..")
        time.sleep(3)
    print("task success:{}, progress:{}, last message:{}".format(task_to_follow.success,
                                                                 task_to_follow.progress,
                                                                 task_to_follow.last_message))

    # add a schedule for the task
    task.add_schedule(name="delete_log_task_schedule", activation_date=time.time()*1000)

    # check schedule
    task_schedule = task.task_schedule
    for schedule in task_schedule:
        assert schedule.activated is True, "delete task schedule is not consistent!"

    # Create a export log task
    ExportLogTask.create(
        name='myexportlogtask',
        servers=[mgt_server],
        file_name="c:/tmp/export.csv",
        file_format="csv",
        for_fw_log=True,
        server_directory_lst=[server_directory(server=mgt_server)],
        comment='export log task comment')

    # get all export log tasks
    for task in ExportLogTask.objects.all():
        print(task, task.task_schedule)

    # Create a archive log task
    ArchiveLogTask.create(
        name='myarchivelogtask',
        servers=[mgt_server],
        time_range="last_full_week_sun_sat",
        all_logs=True,
        server_directory_lst=[server_directory(server=mgt_server)],
        comment='export log task comment')

    # get all archive log tasks
    for task in ArchiveLogTask.objects.all():
        print(task, task.task_schedule)

    """
    This below script is for testing of RemoteUpgradeTask which can be manually tested by passing
    engine file path as command line parameter.
    """
    if len(sys.argv) >= 2:
        execute_remote_upgrade = True

    if execute_remote_upgrade:
        IMPORT_UPGRADE_FILE = RT_UPGRADE_FILE = sys.argv[1]  # sys.argv[1]
        engine = Layer3Firewall.create(name=ENGINE_NAME,
                                       mgmt_ip="192.168.10.1",
                                       mgmt_network="192.168.10.0/24",
                                       extra_opts={"is_cert_auto_renewal": True}
                                       )
        for node in engine.nodes:
            node.initial_contact()
            node.bind_license()
            # wait time for engine to be online
        online = False
        retry = 0
        while not online and retry < RETRY_ONLINE:
            status = engine.nodes[0].status().monitoring_state
            online = status == "READY"
            time.sleep(5)
            retry += 1
        engine = Engine(ENGINE_NAME)
        upgrade_task = RemoteUpgradeTask.create('remote_upgrade_test', [engine],
                                                IMPORT_UPGRADE_FILE)
        upgrade_task.task_schedule
    else:
        print("Engine upgrade zip file path is missing from command line.")

    backup_task = ServerBackupTask.create(name=TASK_NAME,
                                          servers=[ManagementServer(name='Management Server')])
    assert backup_task.name == TASK_NAME and backup_task.servers, NOT_CREATED_MSG
    print("ServerBackupTask '{}' created successfully.".format(TASK_NAME))
    backup_task.update(
        resources=[ManagementServer(name='Management Server').href, LogServer("Log Server").href])
    print("ServerBackupTask '{}' updated successfully with LogServer.".format(TASK_NAME))
except BaseException as e:
    print(e)
    exit(-1)
finally:
    RefreshPolicyTask("myrefreshpolicytask").delete()
    DeleteLogTask("mydeletelogtask").delete()
    ExportLogTask("myexportlogtask").delete()
    ArchiveLogTask("myarchivelogtask").delete()
    if execute_remote_upgrade:
        RemoteUpgradeTask("remote_upgrade_test").delete()
    ServerBackupTask(TASK_NAME).delete()
    print("ServerBackupTask '{}' deleted successfully.".format(TASK_NAME))
    session.logout()
