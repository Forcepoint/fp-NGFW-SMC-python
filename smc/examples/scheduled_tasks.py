"""
Example of how to use scheduled tasks

1- create refresh/delete/export/archive task
2- start task manually
3- create a schedule

"""
import time

import smc.examples

from smc import session
from smc.administration.scheduled_tasks import RefreshPolicyTask, ExportLogTask, DeleteLogTask, \
    server_directory, ArchiveLogTask
from smc.core.engine import Engine
from smc.elements.servers import ManagementServer
from smc_info import SMC_URL, API_KEY, API_VERSION


if __name__ == "__main__":
    session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120, api_version=API_VERSION)
    print("session OK")

try:
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
    while not task_to_follow.success:
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

except BaseException as e:
    print(e)
    exit(-1)
finally:
    RefreshPolicyTask("myrefreshpolicytask").delete()
    DeleteLogTask("mydeletelogtask").delete()
    ExportLogTask("myexportlogtask").delete()
    ArchiveLogTask("myarchivelogtask").delete()
    session.logout()
