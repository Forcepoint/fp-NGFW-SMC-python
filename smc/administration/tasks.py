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
Tasks will be fired when executing specific actions such as a policy
upload, refresh, or making backups.

This module provides that ability to access task specific attributes
and optionally poll for status of an operation.

An example of using a task poller when uploading an engine policy
(use `wait_for_finish=True`)::

    engine = Engine('myfirewall')
    poller = engine.upload(policy=fwpolicy, wait_for_finish=True)
    while not poller.done():
        poller.wait(5)
        print("Task Progress {}%".format(poller.task.progress))
    print(poller.last_message())
    assert poller.is_success(), logging.error("Timeout error during policy upload")

"""
import re
import time
import threading
import zipfile
import datetime
import os
from smc.base.model import ElementCache, Element, SubElement
from smc.api.exceptions import TaskRunFailed, ActionCommandFailed, ResourceNotFound
from smc.base.collection import Search
from smc.base.util import millis_to_utc
from smc.compat import PYTHON_v3_9, is_smc_version_less_than

clean_html = re.compile(r"<.*?>")


def TaskHistory():
    """
    Task history retrieves a list of tasks in an event queue.

    :return: list of task events
    :rtype: list(TaskProgress)
    """
    events = Search.objects.entry_point("task_progress")
    return [event for event in events]


class TaskProgress(Element):
    """
    Task Progress represents a task event queue. These
    tasks may be completed or still running. The task event
    queue events can be retrieved by calling :func:`~TaskHistory`.
    """

    typeof = "task_progress"

    @property
    def task(self):
        """
        Return the task associated with this event

        :rtype: Task
        """
        return Task(self.data)


class Task(SubElement):
    """
    Task representation. This is generic and the format is used for
    any calls to SMC that return an asynchronous follower link to
    check the status of the task.

    :param str last_message: Last message received on this task
    :param bool in_progress: Whether the task is in progress or finished
    :param bool success: Whether the task succeeded or not
    :param str follower: Fully qualified path to the follower link to track
        this task.
    """

    def __init__(self, task):
        super(Task, self).__init__(href=task.get("follower", None), name=task.get("type", None))
        self.data = ElementCache(task)

    @property
    def parent(self):
        """
        The possible parent task

        :rtype: Task or None
        """
        if not is_smc_version_less_than("7.1.6"):
            if "parent" in self.data:
                return Task(self.make_request(method="read", href=self.data.get("parent")))
        # by default No parent task
        return None

    @property
    def children(self):
        """
        The possible children tasks

        :rtype: list(Task) or None
        """
        if not is_smc_version_less_than("7.1.6"):
            if "children" in self.data:
                return [Task(self.make_request(method="read", href=child)) for child in self.data.get("children", [])]
        # by default No children task
        return None

    @property
    def resource(self):
        """
        The resource/s associated with this task

        :rtype: list(Element)
        """
        return [Element.from_href(resource) for resource in self.data.get("resource", [])]

    @property
    def progress(self):
        """
        Percentage of completion

        :rtype: int
        """
        return self.data.get("progress", 0)

    @property
    def waiting_inputs(self):
        """
        the task is waiting for inputs

        :rtype: boolean
        """
        return self.data.get("waiting_inputs", 0)

    def get_waiting_input_link(self):
        links = self.data.get("link", [])
        waiting_input_link = None
        for link in links:
            if link["rel"] == "waiting_input":
                waiting_input_link = link["href"]
        return waiting_input_link

    @property
    def success(self):
        """
        the task has succeed

        :rtype: boolean
        """
        return self.data.get("success", 0)

    @property
    def last_message(self):
        """
        the last message returned by the task

        :rtype: string
        """
        return self.data.get("last_message", 0)

    @property
    def start_time(self):
        """
        Task start time in UTC datetime format

        :rtype: datetime
        """
        start_time = self.data.get("start_time")
        if start_time:
            return millis_to_utc(start_time)

    @property
    def end_time(self):
        """
        Task end time in UTC datetime format

        :rtype: datetime
        """
        end_time = self.data.get("end_time")
        if end_time:
            return millis_to_utc(end_time)

    def abort(self):
        """
        Abort existing task.

        :raises ActionCommandFailed: aborting task failed with reason
        :return: None
        """
        try:
            self.make_request(method="delete", resource="abort")

        except ResourceNotFound:
            pass
        except ActionCommandFailed:
            pass

    @property
    def result_url(self):
        """
        Link to result (this task)

        :rtype: str
        """
        if self.in_progress:
            raise IOError("Task is not finished!")
        return self.get_relation("result")

    def get_result(self):
        """
        Get result of task.
        :rtype SMCResult.
        """
        return self.make_request(TaskRunFailed, href=self.result_url, raw_result=True).content

    def get_progress_report(self):
        """
        Get progress report if applicable

        :raises BaseException if not applicable
        :str[] array of progress report lines
        """
        path = os.getcwd()
        extract_path = f"{path}/progress_report_{datetime.datetime.now().timestamp()}_result"
        saved_path = f"{extract_path}.zip"

        self.make_request(TaskRunFailed, href=self.result_url, filename=saved_path)

        with zipfile.ZipFile(saved_path, "r") as zip_ref:
            zip_ref.extractall(extract_path)

        if "display_conf_report.txt" in os.listdir(extract_path):
            with open(os.path.join(extract_path, "display_conf_report.txt")) as progress_report_file:
                return progress_report_file.readlines()
        else:
            raise BaseException("No progress report available!")

    def update_status(self):
        """
        Gets the current status of this task and returns a
        new task object.

        :raises TaskRunFailed: fail to update task status
        """
        task = self.make_request(TaskRunFailed, href=self.href)

        return Task(task)

    def __getattr__(self, key):
        return self.data.get(key)

    @staticmethod
    def execute(self, resource, **kw):
        """
        Execute the task and return a TaskOperationPoller.

        :rtype: TaskOperationPoller
        """
        params = kw.pop("params", {})
        json = kw.pop("json", None)
        task = self.make_request(
            TaskRunFailed, method="create", params=params, json=json, resource=resource
        )

        timeout = kw.pop("timeout", 5)
        wait_for_finish = kw.pop("wait_for_finish", True)

        return TaskOperationPoller(
            task=task, timeout=timeout, wait_for_finish=wait_for_finish, **kw
        )

    def get_task_poller(self, **kw):
        """
        return a TaskOperationPoller for the Task.

        :rtype: TaskOperationPoller
        """
        timeout = kw.pop('timeout', 5)
        wait_for_finish = kw.pop('wait_for_finish', True)

        return TaskOperationPoller(
            task=self.data, timeout=timeout,
            wait_for_finish=wait_for_finish,
            **kw)

    @staticmethod
    def download(self, resource, filename, timeout=5, max_tries=36, **kw):
        """
        Start and return a Download Task

        :rtype: DownloadTask(TaskOperationPoller)
        """
        params = kw.pop("params", {})
        task = self.make_request(TaskRunFailed, method="create", resource=resource, params=params)

        return DownloadTask(timeout=timeout, max_tries=max_tries, filename=filename, task=task)

    def download_only(self, filename, timeout=5, max_tries=36):
        """
        This does not start task only return a Download Task.
        :rtype: DownloadTask(TaskOperationPoller)
        """
        return DownloadTask(timeout=timeout, max_tries=max_tries, filename=filename, task=self.data)


class TaskOperationPoller(object):
    """
    Task Operation Poller provides a way to poll the SMC
    for the status of the task operation. This is returned
    by functions that return a task. Typically these will be
    operations like refreshing policy, uploading policy, etc.
    """

    def __init__(self, task, timeout=5, max_tries=36, wait_for_finish=False):
        self._task = Task(task)
        self._thread = None
        self._done = None
        self._exception = None
        self.callbacks = []  # Call after operation completes
        if wait_for_finish:
            self._max_tries = max_tries
            self._timeout = timeout
            self._done = threading.Event()
            self._thread = threading.Thread(target=self._start)
            self._thread.daemon = True
            self._thread.start()

    def _start(self):
        while not self.finished():
            try:
                time.sleep(self._timeout)
                self._task = self._task.update_status()
                self._max_tries -= 1
            except Exception as e:
                self._exception = e
                break

        self._done.set()
        for call in self.callbacks:
            call(self.task)

    def finished(self):
        return self._done.is_set() or not self._task.in_progress or self._max_tries == 0

    def add_done_callback(self, callback):
        """
        Add a callback to run after the task completes.
        The callable must take 1 argument which will be
        the completed Task.

        :param callback: a callable that takes a single argument which
            will be the completed Task.
        """
        if self._done is None or self._done.is_set():
            raise ValueError("Task has already finished")
        if callable(callback):
            self.callbacks.append(callback)

    def result(self, timeout=None):
        """
        Return the current Task after waiting for timeout

        :rtype: Task
        """
        self.wait(timeout)
        return self._task

    def wait(self, timeout=None):
        """
        Blocking wait for task status.
        """
        if self._thread is None:
            return
        self._thread.join(timeout=timeout)

    def last_message(self, timeout=5):
        """
        Wait a specified amount of time and return
        the last message from the task

        :rtype: str
        """
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        return self._task.last_message

    def done(self):
        """
        Is the task done yet

        :rtype: bool
        """
        # isAlive() is removed since python3.9
        return self._thread is None or \
            (not PYTHON_v3_9 and not self._thread.isAlive()) or \
            (PYTHON_v3_9 and not self._thread.is_alive())

    @property
    def task(self):
        """
        Access to task

        :rtype: Task
        """
        return self._task

    def stop(self):
        """
        Stop the running task
        """
        if self._thread is not None and self._thread.isAlive():
            self._done.set()

    def is_success(self):
        """
        Check if the task was successful and not in progress.
        complete done method since we can be in timeout

        :rtype: bool
        """""
        return not self._task.data.data['in_progress'] and self._task.success


class DownloadTask(TaskOperationPoller):
    """
    A download task handles tasks that have files associated, for example
    exporting an element to a specified file.
    """

    def __init__(self, filename, task, timeout=5, max_tries=36, **kw):
        super(DownloadTask, self).__init__(
            task, timeout=timeout, max_tries=max_tries, wait_for_finish=True, **kw
        )
        self.type = "download_task"
        self.filename = filename

        self.download(None)

    def download(self, timeout):
        self.wait(timeout)
        if not self.task.in_progress and not self.task.success:
            raise TaskRunFailed(self.task.last_message)
        try:
            result = self.task.make_request(
                TaskRunFailed, raw_result=True, href=self.task.result_url, filename=self.filename
            )

            self.filename = result.content

        except IOError as io:
            raise TaskRunFailed("Export task failed with message: {}".format(io))
