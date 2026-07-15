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
Module that controls aspects of the HA System, such as getting info or diagnostics, set active or
set standby, etc.

To get the HA Diagnostics, do::

    >>> from smc.core.ha_management import HAManagement
    >>>     diag = ha.diagnostic()
    >>>    print("diagnostic messages:")
    >>>    for infob in diag.message:
    >>>        print("title:{}".format(infob.title))
    >>>        for msg in infob.message:
    >>>            print("msg:{}".format(msg))
    diagnostic messages:
    title:Management Server
    msg:    Primary IP address:127.0.0.1 / IP address in configuration: 127.0.0.1
            / IP address detected by Java runtime: 172.16.42.199
    msg:    Secondary IP addresses:
    msg:    Contact IP addresses: LocationHQ:127.0.0.1 HQ:127.0.0.1 Default:127.0.0.1
    ...
    title:Log Server
    msg:    Primary IP address:127.0.0.1 / IP address in configuration: ?
            / IP address detected by Java runtime: ?
    msg:    Secondary IP addresses:
    msg:    Contact IP addresses: LocationHQ:127.0.0.1 HQ:127.0.0.1 Default:127.0.0.1
    ...
"""
from __future__ import annotations

from typing import Any, Optional, Union, Iterator
import time

from smc.api.common import fetch_entry_point, SMCRequest, _get_session
from smc.api.exceptions import HaCommandException, HaRequestException
from smc.base.model import Element
from smc.base.structs import NestedDict
from smc.compat import min_smc_version
from smc.elements.servers import ManagementServer


class HAInfo(NestedDict):
    """
    Represents HA Management information.
    """
    def __init__(self, data: Any) -> None:
        super(HAInfo, self).__init__(data=data)

    @property
    def connected_server(self) -> Any:
        """
        :return: Connected server
        :rtype: Server
        """
        return Element.from_href(self.data.get("connected_server"))

    @connected_server.setter
    def connected_server(self, value: Any) -> None:
        self.data.set("connected_server", value)

    @property
    def active_server(self) -> Any:
        """
        :return: Active server
        :rtype: Server
        """
        return Element.from_href(self.data.get("active_server"))

    @active_server.setter
    def active_server(self, value: Any) -> None:
        self.data.set("active_server", value)

    @property
    def standby_servers(self) -> list[Any]:
        """
        :return: list of Standby servers
        :rtype: list(Server)
        """
        if self.data.get("standby_servers"):
            return [Element.from_href(server) for server in self.data.get("standby_servers")]
        return []

    @standby_servers.setter
    def standby_servers(self, values: Any) -> None:
        self.data.set("standby_servers", values)

    def __str__(self) -> str:
        lst_stdby = ""
        if self.standby_servers is not None:
            for stdby in self.standby_servers:
                lst_stdby += ", {}".format(stdby)

        return "Active: {} Standby: {}".format(self.active_server, lst_stdby)


class InfoBlock(NestedDict):
    """
    Represents diagnostic messages.
    """
    def __init__(self, data: Any) -> None:
        super(InfoBlock, self).__init__(data=data)

    @property
    def title(self) -> Optional[str]:
        """
        :return: title for the block
        :rtype: str
        """
        return self.data.get("title")

    @title.setter
    def title(self, value: Any) -> None:
        self.data.set("title", value)

    @property
    def message(self) -> Optional[Any]:
        """
        :return: messages for the block
        :rtype: list(str)
        """
        return self.data.get("message")

    @message.setter
    def message(self, value: Any) -> None:
        self.data.set("message", value)


class HADiagnostic(NestedDict):
    """
    HA Availability diagnostic result.
    """
    def __init__(self, data: Any) -> None:
        super(HADiagnostic, self).__init__(data=data)

    @property
    def status(self) -> Optional[str]:
        """
        :return: status
        :rtype: str
        """
        return self.data.get("status")

    @status.setter
    def status(self, value: Any) -> None:
        self.data.set("status", value)

    @property
    def execution_message(self) -> Optional[Any]:
        """
        :return: execution messages
        :rtype: list(str)
        """
        return self.data.get("execution_message")

    @execution_message.setter
    def execution_message(self, value: Any) -> None:
        self.data.set("execution_message", value)

    @property
    def errors_warnings(self) -> InfoBlock:
        """
        :return: error and warning messages
        :rtype: list(str)
        """
        return InfoBlock(self.data.get("errors_warnings"))

    @errors_warnings.setter
    def errors_warnings(self, value: Any) -> None:
        self.data.set("errors_warnings", InfoBlock(value))

    @property
    def durations(self) -> InfoBlock:
        """
        :return: diagnostic messages
        :rtype: InfoBlock
        """
        return InfoBlock(self.data.get("durations"))

    @durations.setter
    def durations(self, value: Any) -> None:
        self.data.set("durations", InfoBlock(value))

    @property
    def message(self) -> list[Any]:
        """
        :return: messages
        :rtype: list(InfoBlock)
        """
        return [InfoBlock(message) for message in self.data.get("message")]

    @message.setter
    def message(self, value: Any) -> None:
        self.data.set("message", [InfoBlock(message) for message in value])


class HAManagement(object):
    """
    High level Class to administrate Management Server High availability.
    """

    def __init__(self) -> None:
        self.entry = fetch_entry_point("ha")

    @staticmethod
    def check_status(response: Any, valid_status_codes: Any = (200,)) -> None:
        """
        Check the response status code and raise HaCommandException.
        :param Response response: API Response
        :param valid_status_codes: status codes considered successful (default: 200 only).
        :raise: HaCommandException: if status code is not one of valid_status_codes
        """
        if response.status_code not in valid_status_codes:
            raise HaCommandException(response)

    @staticmethod
    def check_result(smc_result: Any) -> None:
        """
        Check the smc_result content and raise HaRequestException if there is no JSON content.
        :param SMCResult raw result of the SMC API request
        :raise: HaRequestException: if there is no JSON payload in the result
        """
        if smc_result.json is None :
            raise HaRequestException(smc_result.msg)

    def get_ha(self) -> HAInfo:
        """
        :return: HA Information
        :rtype: HAInfo
        """
        return HAInfo(SMCRequest(href=self.entry).read().json)

    def set_activation(self, timeout: int = 600, verbose: bool = False) -> dict[str, Any]:
        """
        Launches the activation of the connected Management Server.

        <b>Warning:</b> This method does not tolerate the presence of a Standby Management Server
        with existing replication issues.
        If such a server is present, it must be excluded before using this method.

        Therefore, this method must be called on the Standby Management Server to activate.
        This method is available only for SMC ≥ 7.3.0.

        If the system state is considered suspicious, the activation request is rejected.
        In such cases, you must run database_replication_diagnostic on each server and act according to the reported state.

        This method waits until the timeout expires for the activation to be fully applied on all servers.

        :param int timeout: Maximum time to wait for stabilization, default 600s ( 10 minutes ).
        :param bool verbose: Prints the current replication state every 10 seconds, default False.
        :return: The replication state at the end of the activation procedure.
        :rtype: JSON payload with the following structure:
        {
            "success": boolean that indicates whether the activation was successful,
            "state": string that describes the final replication state or an error message if the activation failed or timed out
        }
        """
        try:
            success = False
            response = self.set_active()
            if min_smc_version("7.3"):
                if response.status_code == 200:
                    start_time = time.time()
                    time.sleep(10)  # time.sleep parameter is in seconds.
                    while True:
                        try:
                            # this entry point does not exist in old SMC version (introduction in
                            # 7.3.4, 7.4.2 and 7.5.0)
                            state = self.database_replication_diagnostic()["state"]
                        except Exception:
                            response_message = ("This version of SMC does not support the required"
                                                "API entry point 'database_replication_diagnostic'."
                                                "Please check the replication state manually."
                                                "Standby server initialization against the new server will continue in the background.")
                            success = True
                            break
                        if state.startswith("[ACT_REP]"):
                            response_message = state
                            success = True
                            break
                        if time.time() - start_time > timeout:
                            response_message = (f"Timeout reached ({timeout} seconds), final replication "
                                                f"state is {state}")
                            break
                        if verbose:
                            print(f"Current replication state: {state}, in progress since {int(time.time() - start_time)} seconds")
                        time.sleep(10)  # time.sleep parameter is in seconds.
                else:
                    response_message = f"Activation request failed: {response}"
            else:
                response_message = (f"Activation request done, but replication state cannot be "
                                    f"monitored for SMC versions prior to 7.3. Please check the replication state manually.")
                success = True

        except HaCommandException as e:
            response_message = f"Activation request failed: {e}"
        return {
            "success": success,
            "state": response_message
        }

    def init_standby(self, server: Any, timeout: int = 600, verbose: bool = False) -> dict[str, Any]:
        """
        Launches the initialization of the incremental replication for the standby server provided as a parameter.

        <b>Warning:</b> This method does not tolerate the presence of a Standby Management Server
        with existing replication issues.
        If such a server is present, it must be excluded before using this method.

        Therefore, this method must be called on the Standby Management Server to activate.
        This method is available only for SMC ≥ 7.3.0.

        If the system state is considered suspicious, the initialization request is rejected.
        In such cases, you must run database_replication_diagnostic on each server and act according to the reported state.

        This method waits until the timeout expires for the initialization to be fully applied on all servers.

        :param ManagementServer server: Management Server to initialize.
        :param int timeout: Maximum time to wait for stabilization, default 600s ( 10 minutes ).
        :param bool verbose: Prints the current replication state every 10 seconds, default False.
        :return: The replication state at the end of the initialization procedure.
        :rtype: JSON payload with the following structure:
        {
            "success": boolean that indicates whether the activation was successful,
            "state": string that describes the final replication state or an error message if the activation failed or timed out
        }
        """
        try:
            success = False
            response = self.full_replication(server)
            if min_smc_version("7.3"):
                if response.status_code == 200:
                    start_time = time.time()
                    time.sleep(10)  # time.sleep parameter is in seconds.
                    while True:
                        # this entry point does not exist in old SMC version (introduction in
                        # 7.3.4, 7.4.2 and 7.5.0)
                        try:
                            diagnostic_result = self.all_servers_replication_diagnostic()
                        except Exception:
                            response_message = ("This version of SMC does not support"
                                                "the required API entry point 'all_servers_replication_states'."
                                                "Please check the replication state manually."
                                                "Standby server initialization has been requested successfully")
                            success = True
                            break
                        state = None
                        if diagnostic_result is None:
                            state = f"{server.name} replication state not available"
                        else:
                            for standby_server in diagnostic_result["standby_server_states"]:
                                if standby_server.get("server_name") == server.name:
                                    state = standby_server.get("state")
                                    break
                        if state is None:
                            state = f"{server.name} replication state not available"
                        if state.startswith("[STB_REP]"):
                            response_message = state
                            success = True
                            break
                        if time.time() - start_time > timeout:
                            response_message = (f"Timeout reached ({timeout} seconds), final replication "
                                                f"state is {state}")
                            break
                        if verbose:
                            print(f"Current replication state {server.name}: {state}, in progress "
                                  f"since"
                                  f" {int(time.time() - start_time)} seconds")
                        time.sleep(10)  # time.sleep parameter is in seconds.
                else:
                    response_message = f"Init standby request failed: {response}"
            else:
                response_message = (f"Init standby request done, but replication state cannot be "
                                    f"monitored for SMC versions prior to 7.3. Please check the replication state manually.")
                success = True

        except HaCommandException as e:
            response_message = f"Init standby request failed: {e}"
        return {
            "success": success,
            "state": response_message
        }

    def set_active(self, server: Optional[Any] = None, force: bool = False) -> Any:
        """
        Launch activation of the specified management server or the connected management server
        if not specified. ( Since SMC 7.3, activation should be requested on target server to
        activate, before SMC 7.3, activation was managed by the current active server unless
        PostgreSQL native replication has been enabled ).

        If system state is suspicious, activation will be rejected **unless force mode** is used.
        **For example:**
            -if current primary management server is stopped (or unresponsive)
            -if standby server is known to have a replication issue

        (Note: If SMC API is not enabled on standby server,then it has to be activated.
               When HA Management Server is administrated through SMC API, activation of SMC API
               on Active Server is mandatory.).

        Activation will be refuse if SMC API is not setup on specified management server.
           (and also, if specified server is not accessible).

        WARNING: if force mode is used, system integrity is not guarantee.
        :param Server server: the specified management server ( optional since SMC 7.3 or if
        PostgreSQL native replication has been enabled ).
        :param bool force: force mode, default False
        :return: the return data.
        :rtype: requests.Response
        """
        session = _get_session(SMCRequest._session_manager)
        params = {"force": force}
        if server:
            params.update(server_name=server.name)

        response = session.session.post(
            url=self.entry+"/set_active",
            headers={"Content-Type": "application/json"},
            params=params,
        )
        # set_active may answer 202 with an operation id (async wizard) or a standard 200.
        self.check_status(response, valid_status_codes=(200, 202))
        return response

    def set_standby(self, server: Optional[Any] = None, force: bool = False) -> Any:
        """
        Launch deactivation of the specified management server or the connected management server
        if not specified
        (Note: the system may have no Active management server once applied.
         If SMC API is not enabled on standby server, SMC API may be not more available at all).

        Deactivation may be rejected if applied on active server and if it will stop the SMC API
        (API disabled on standby management server).
        In this case, you'll have to use the force parameter to true and assume that to be able
        to activate a server,
        a connection with the SMC Client will have to be done.
        :param Server server: the specified management server
        :param bool force: force mode, default False
        :return: the confirmation message.
        :rtype: requests.Response
        """
        session = _get_session(SMCRequest._session_manager)
        params = {"force": force}
        if server:
            params.update(server_name=server.name)

        response = session.session.post(
            url=self.entry+"/set_standby",
            headers={"Content-Type": "application/json"},
            params=params,
        )
        self.check_status(response)
        return response

    def full_replication(self, server: Any, force: bool = False) -> Any:
        """
        Launch full replication of the specified standby management server.

        Full replication will be rejected if applied on active server
        or not requested through Active Server.
        :param Server server: the specified management server
        :param bool force: force mode, default False
        :return: the confirmation message.
        :rtype: requests.Response
        """
        session = _get_session(SMCRequest._session_manager)
        params = {"force": force, "server_name": server.name}
        response = session.session.post(
            url=self.entry+"/full_replication",
            headers={"Content-Type": "application/json"},
            params=params,
        )
        self.check_status(response)
        return response

    def exclude(self, server: Any, force: bool = False) -> Any:
        """
        Exclude the specified management server from database replication (database scope only)

        Exclusion will be rejected if applied on active server
        or not requested through Active Server.
        :param Server server: the specified management server
        :param bool force: force mode, default False
        :return: the confirmation message.
        :rtype: requests.Response
        """
        session = _get_session(SMCRequest._session_manager)
        params = {"force": force, "server_name": server.name}
        response = session.session.post(
            url=self.entry+"/exclude",
            headers={"Content-Type": "application/json"},
            params=params,
        )
        self.check_status(response)
        return response

    def diagnostic(self, deep: bool = False, exclude_info: bool = False, global_timeout: int = 0, server_timeout: int = 0) -> HADiagnostic:
        """
        Returns a diagnostic for replication status over all SMC Servers.

        :param bool deep: when set, do a deep analysis on all pending messages instead of global
                          analysis on message count by channel.
                          (can be very long if there is some replication issues with many pending
                          messages).
                          Use parameter deep=true for activation.
        :param bool exclude_info: when set, information about SMC Servers are excluded
                                  (they are helpful for High Availability administration.)
                                  Use parameter exclude_info=true to disable message add focus on
                                  warning.
        :param int global_timeout: define a global timeout in seconds for execution.
                                   Execution time may be longer than the global timeout
                                   but best effort will be done the interrupt execution when
                                   timeout is reached.
                                   Default value is 3 minutes.
                                   There is no max value, service execution may be long but never
                                   infinite.
                                   In case of global timeout, partial result available will be
                                   provided.
                                   Use parameter global_timeout to set the value in seconds.
        :param int server_timeout: define a timeout in seconds to get the diagnostic by server.
                                   default value is 60s.
                                   Note that this value should be lesser than the global timeout to
                                   be coherent.
                                   Use parameter server_timeout to set the value in seconds.
        :return: all diagnostic messages grouped by server (for information messages) and
                 warnings list.
        :rtype: HADiagnostic
        """
        params = {"deep": deep, "exclude_info": exclude_info, "global_timeout": global_timeout,
                  "server_timeout": server_timeout}
        result = SMCRequest(href=self.entry+"/diagnostic", params=params).read();
        self.check_result(result)
        return HADiagnostic(result.json)

    def all_servers_replication_diagnostic(self) -> dict[str, Any]:
        """
        Returns a diagnostic for database replication status across all servers.

        Provides information about the active server state and all standby servers'
        replication states in the high availability management servers.

        SMC API entry point for this method is only available for SMC 7.3.4+, 7.4.2+ or higher.

        :return: Replication diagnostic information containing:
                 - active_server_state: Current state of the active server's database replication
                 - standby_server_states: List of standby servers with their replication states,
                   each containing:
                   - server_name: Name of the standby server
                   - state: Current replication state description
        :rtype: dict

        Example response::
        {
            "active_server_state": "[ACT_REP] Active database replication is enabled",
            "standby_server_states": [
                {
                    "server_name": "DK_MGT_2",
                    "state": "[STB_REP] Standby database replication is enabled"
                },
                {
                    "server_name": "HOST_MGT",
                    "state": "[STB_REP] Standby database replication is enabled"
                }
            ]
        }
        """
        if min_smc_version("7.3"):
            result = SMCRequest(href=self.entry + "/all_servers_replication_states").read()
            self.check_result(result)
            return result.json
        else:
            raise HaCommandException("This method is only available for SMC 7.3 or higher.")

    def database_replication_diagnostic(self) -> dict[str, Any]:
        """
        Returns a diagnostic for database replication status.

        Provides information about the database replication state including server details,
        license validity, replication configuration, and active connections.

        SMC API entry point for this method is only available for SMC 7.3 or higher.

        :return: Database replication diagnostic information containing:
                 - server_name: Name of the server
                 - valid_license: Whether the license is valid
                 - servers: List of servers with their IDs
                 - state: Current replication state description
                 - table_count: Number of tables being replicated
                 - element_count: Number of elements being replicated
                 - active_server_publication: Whether active server publication is enabled
                 - standby_server_registered: Number of registered standby servers
                 - active_replication_streaming: Number of active replication streams
                 - active_replication_to_standby_servers: List of active replication connections
                   to standby servers with connection details
                 - standby_replication_subscription: Number of standby replication subscriptions
        :rtype: dict

        Example response::

            {
              "server_name": "HOST_MGT",
              "valid_license": true,
              "servers": "[HOST_MGT (10), DK_MGT_2 (1296), DK_MGT_1 (1174)]",
              "state": "[ACT_REP] Active database replication is enabled",
              "table_count": "371",
              "element_count": "1428",
              "active_server_publication": true,
              "standby_server_registered": "2",
              "active_replication_streaming": "2",
              "active_replication_to_standby_servers": [
                "[PG-PUB|-->127.0.0.1  on port 44946|sub_smc1174|pid:16159|Since:2026-02-23 08:15:33+0100",
                "[PG-PUB|-->127.0.0.1  on port 46142|sub_smc1296|pid:16930|Since:2026-02-23 08:16:12+0100"
              ],
              "standby_replication_subscription": "0"
            }
        """
        if min_smc_version("7.3"):
            result = SMCRequest(href=self.entry+"/database_replication_diagnostic").read()
            self.check_result(result)
            return result.json
        else:
            raise HaCommandException("This method is only available for SMC 7.3 or higher.")

    def audit_replication_diagnostic(self) -> dict[str, Any]:
        """
        Returns a diagnostic for audit replication status.

        Provides information about the audit replication state including server details,
        replication status, and file counts.

        SMC API entry point for this method is only available for SMC 7.3 or higher.

        :return: Audit replication diagnostic information containing:
                 - server_name: Name of the server
                 - status: Whether audit replication is active
                 - last_error: Last error message or status description
                 - state: Current replication state (e.g., "Listening")
                 - last_update: Timestamp of last update in milliseconds
                 - info: Additional information about the server mode (mostly active mode or standby mode)
                 - input_files_count: Number of input files being processed
                 - output_files_count: Number of output files generated
        :rtype: dict

        Example response::

            {
              "server_name": "HOST_MGT",
              "status": true,
              "last_error": "Active server - listening",
              "state": "Listening",
              "last_update": 1771579987596,
              "info": "Active server mode has been enabled",
              "input_files_count": 3,
              "output_files_count": 25
            }
        """
        if min_smc_version("7.3"):
            result = SMCRequest(href=self.entry+"/audit_replication_diagnostic").read()
            self.check_result(result)
            return result.json
        else:
            raise HaCommandException("This method is only available for SMC 7.3 or higher.")

    def audit_scan(self) -> Any:
        """
        Launch an audit scan request on the standby management server.
        Active management server will reject the request.

        SMC API entry point for this method is only available for SMC 7.3 or higher.

        :return: the confirmation message.
        :rtype: requests.Response
        """
        if min_smc_version("7.3"):
            session = _get_session(SMCRequest._session_manager)
            response = session.session.post(
                url=self.entry+"/audit_scan_request"
            )
            self.check_status(response)
            return response
        else:
            raise HaCommandException("This method is only available for SMC 7.3 or higher.")

    def audit_full_scan(self, disable_delay: bool = False) -> Any:
        """
        Launch an audit full scan request on the standby management server.
        Active management server will reject the request.

        SMC API entry point for this method is only available for SMC 7.3 or higher.

        :param bool disable_delay: disable delay will start a full scan without moderation, default False

        :return: the confirmation message or error message.
        :rtype: requests.Response
        """
        if min_smc_version("7.3"):
            params = {"disable_delay": disable_delay}
            session = _get_session(SMCRequest._session_manager)
            response = session.session.post(
                url=self.entry+f"/audit_full_scan_request",
                params=params,
            )
            self.check_status(response)
            return response
        else:
            raise HaCommandException("This method is only available for SMC 7.3 or higher.")
