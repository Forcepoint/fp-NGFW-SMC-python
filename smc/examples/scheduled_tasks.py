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
Example of how to use scheduled tasks

1- create refresh/delete/export/archive task
2- start task manually
3- create a schedule

"""
import argparse
import logging
import os
import sys
import time
sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.compat import is_api_version_less_than  # noqa
from smc.core.engine import Engine  # noqa
from smc.core.engines import Layer3Firewall  # noqa
from smc.elements.servers import ManagementServer, LogServer  # noqa
from smc.administration.scheduled_tasks import RefreshPolicyTask, DeleteLogTask, ExportLogTask, \
    server_directory, ArchiveLogTask, RemoteUpgradeTask, ServerBackupTask, \
    TrafficCaptureInterfaceSettings, TrafficCaptureTask  # noqa

RETRY_ONLINE = 30
ENGINE_NAME = 'test_engine'
NOT_CREATED_MSG = "Fail to create server backup task"
TASK_NAME = 'backup_task_test'
TRAFFIC_CAPTURE_TASK = 'traffic_capture_test'
CREATE_TRAFFIC_CAPTURE_ERROR = "Failed to create traffic capture task."
UPDATE_TRAFFIC_CAPTURE_ERROR = "Failed to update traffic capture task."
ERROR_TO_START_TASK_AND_GET_RESULT = "Failed to executed traffic capture task."
RETRY_FINISH = 4

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
        logging.info("session OK")

        execute_remote_upgrade = False

        # Create a refresh policy task
        task = RefreshPolicyTask.create(
            name='myrefreshpolicytask',
            engines=[Engine("Plano"), Engine("Paris")],
            comment='some comment')

        # Get all refresh tasks
        for task in RefreshPolicyTask.objects.all():
            logging.info(task, task.task_schedule)

        # Create delete log task
        mgt_server = ManagementServer("Management Server")
        DeleteLogTask.create(
            name='mydeletelogtask',
            servers=[mgt_server],
            for_fw_log=True,
            comment='delete log task comment')

        # Get all delete log tasks
        for task in DeleteLogTask.objects.all():
            logging.info(task, task.task_schedule)

        # check task created
        task = DeleteLogTask("mydeletelogtask")
        assert task.for_fw_log is True, "delete task is not consistent!"

        # start task manually
        task_to_follow = task.start()
        while not task_to_follow.get_task_poller().done():
            task_to_follow = task_to_follow.update_status()
            logging.info("wait for delete log task to be completed..")
            time.sleep(3)
        logging.info(f"task success:{task_to_follow.success}, progress:{task_to_follow.progress}, "
                     f"last message:{task_to_follow.last_message}")

        # add a schedule for the task
        task.add_schedule(name="delete_log_task_schedule", activation_date=time.time() * 1000)

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
            logging.info(task, task.task_schedule)

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
            logging.info(task, task.task_schedule)

        if arguments.remote_upgrade_file:
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
                                                    arguments.remote_upgrade_file)
            upgrade_task.task_schedule
        else:
            logging.info("Engine upgrade zip file path is missing from command line.")

        backup_task = ServerBackupTask.create(name=TASK_NAME,
                                              servers=[ManagementServer(name='Management Server')])
        assert backup_task.name == TASK_NAME and backup_task.servers, NOT_CREATED_MSG
        logging.info(f"ServerBackupTask '{TASK_NAME}' created successfully.")
        backup_task.update(resources=[ManagementServer(name='Management Server').href,
                                      LogServer("Log Server").href])
        logging.info(f"ServerBackupTask '{TASK_NAME}' updated successfully with LogServer.")

        # TrafficCapture Task
        engine_hki = Engine("Helsinki")
        physical_interfaces_hki = list(engine_hki.physical_interface)
        # create interface settings for all nodes of the engine with same filter.
        list_of_interface = TrafficCaptureInterfaceSettings.create_interface_setting_for_all_node(
            engine_hki, pint_ref=physical_interfaces_hki[0], filter="10.42.9.22")
        engine_plano = Engine("Plano")
        engine_nodes_plano = list(engine_plano.nodes)
        physical_interfaces_plano = list(engine_plano.physical_interface)
        # create interface setting with specific engine node and interface with filter.
        interface_setting_plano = TrafficCaptureInterfaceSettings.create(
            node_ref=engine_nodes_plano[0], pint_ref=physical_interfaces_plano[0],
            filter="10.42.9.22")
        list_of_interface.append(interface_setting_plano)
        if not is_api_version_less_than("6.10"):
            traffic_capture_task = TrafficCaptureTask.create(
                TRAFFIC_CAPTURE_TASK,
                interface_settings=list_of_interface,
                max_file_size_in_mb=500,
                capture_headers_only=False,
                description="This is is to test traffic capture task.",
                duration_in_sec=10,
                sg_info_option=True,
                comment="Testing of traffic capture task.",
            )
            assert traffic_capture_task.max_file_size == 500 and \
                   not traffic_capture_task.capture_headers_only and \
                   traffic_capture_task.duration == 10, CREATE_TRAFFIC_CAPTURE_ERROR
            # update is getting failed since there is issue from SMC Api side. we can verify later
            traffic_capture_task.update(capture_headers_only=True, max_file_size=300)
            traffic_capture_task = TrafficCaptureTask(TRAFFIC_CAPTURE_TASK)
            assert (traffic_capture_task.capture_headers_only and
                    traffic_capture_task.max_file_size == 300), UPDATE_TRAFFIC_CAPTURE_ERROR
            started_task = traffic_capture_task.start()
            download_task = started_task.download_only(filename="test.tar.gz", timeout=10)
            started_task = started_task.update_status()
            is_file_present = False
            file_size = 0
            if download_task.filename:
                file_name = download_task.filename
                if os.path.isfile(file_name):
                    is_file_present = True
                    file_size = os.path.getsize(file_name)
            assert started_task.success and is_file_present and \
                   file_size > 0, ERROR_TO_START_TASK_AND_GET_RESULT
            logging.info("Successfully executed traffic capture task.")
    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1
    finally:
        RefreshPolicyTask("myrefreshpolicytask").delete()
        DeleteLogTask("mydeletelogtask").delete()
        ExportLogTask("myexportlogtask").delete()
        ArchiveLogTask("myarchivelogtask").delete()
        if execute_remote_upgrade:
            RemoteUpgradeTask("remote_upgrade_test").delete()
            Layer3Firewall(ENGINE_NAME).delete()
        ServerBackupTask(TASK_NAME).delete()
        logging.info(f"ServerBackupTask '{TASK_NAME}' deleted successfully.")
        if not is_api_version_less_than("6.10"):
            TrafficCaptureTask(TRAFFIC_CAPTURE_TASK).delete()
            logging.info("TrafficCaptureTask deleted successfully.")
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script to show how to use scheduled tasks',
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
    parser.add_argument(
        '--remote-upgrade-file',
        type=str, default=None,
        help='Path to remote upgrade zip file.'
    )

    arguments = parser.parse_args()

    if arguments.help:
        parser.print_help()
        sys.exit(1)
    if arguments.api_url is None:
        parser.print_help()
        sys.exit(1)

    return arguments


if __name__ == "__main__":
    sys.exit(main())
