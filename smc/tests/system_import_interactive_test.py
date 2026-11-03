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
System.import_elements_interactive_mode must report how the import ended, not how the wait for the
conflicts ended. The SMC is simulated: the import task is waiting for inputs until the import is
continued, then it follows the statuses given by the test.
"""
import unittest
from types import SimpleNamespace
from typing import Any, Callable, Dict, Optional
from unittest import mock

from smc.administration.system import System
from smc.api.exceptions import ActionCommandFailed

CONTINUE_HREF = "http://smc/import/continue"
UNRESOLVED_REFERENCES = "Import failed because of unresolved references"


def _status(in_progress: bool, success: bool, last_message: str, waiting_inputs: bool = False) -> Any:
    return SimpleNamespace(data=SimpleNamespace(in_progress=in_progress), progress=0, success=success,
                           last_message=last_message, waiting_inputs=waiting_inputs,
                           get_waiting_input_link=lambda: "http://smc/import/waiting_input")


def _import(status_after_continue: Callable[[], Any], continue_answer: Optional[Dict[str, Any]] = None) -> None:
    """Run the import against a simulated SMC, the task returns status_after_continue() once continued."""
    state = {"continued": False}
    # The task claims success while it waits for the conflicts to be resolved
    waiting = _status(in_progress=True, success=True, last_message="", waiting_inputs=True)
    task = mock.Mock()
    task.data = SimpleNamespace(in_progress=True)
    task.progress = 0
    task.update_status.side_effect = lambda: status_after_continue() if state["continued"] else waiting

    conflicts = {"inputs": [{"import_conflict": {}}], "link": [{"rel": "continue", "href": CONTINUE_HREF}]}
    answer = {"in_progress": False, "follower": "http://smc/task/1"}
    answer.update(continue_answer or {})

    def create() -> Any:
        state["continued"] = True
        return SimpleNamespace(json=answer)

    request = mock.Mock()
    request.return_value.read.return_value = SimpleNamespace(json=conflicts)
    request.return_value.create.side_effect = create

    with mock.patch.object(System, "make_request", return_value={}), \
            mock.patch("smc.administration.system.Task", return_value=task), \
            mock.patch("smc.administration.system.SMCRequest", request), \
            mock.patch("smc.administration.system.time.sleep"), \
            mock.patch("builtins.open", mock.mock_open()):
        System.__new__(System).import_elements_interactive_mode("import.zip")


class SystemImportInteractiveTest(unittest.TestCase):

    def test_failed_import_raises_the_message_of_the_end_of_the_import(self) -> None:
        failed = _status(in_progress=False, success=False, last_message=UNRESOLVED_REFERENCES)
        with self.assertRaises(ActionCommandFailed) as ctx:
            _import(lambda: failed)
        self.assertIn(UNRESOLVED_REFERENCES, str(ctx.exception))

    def test_successful_import_does_not_raise(self) -> None:
        succeeded = _status(in_progress=False, success=True, last_message="done")
        _import(lambda: succeeded)

    def test_import_still_running_after_continue_is_waited_for(self) -> None:
        statuses = iter([_status(True, False, ""), _status(True, False, "")])
        failed = _status(in_progress=False, success=False, last_message=UNRESOLVED_REFERENCES)
        reads = []

        def next_status() -> Any:
            reads.append(1)
            return next(statuses, failed)

        with self.assertRaises(ActionCommandFailed):
            _import(next_status)
        self.assertGreater(len(reads), 2)

    def test_continue_answer_reporting_a_failure_raises(self) -> None:
        succeeded = _status(in_progress=False, success=True, last_message="")
        with self.assertRaises(ActionCommandFailed) as ctx:
            _import(lambda: succeeded, {"success": False, "last_message": UNRESOLVED_REFERENCES})
        self.assertIn(UNRESOLVED_REFERENCES, str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
