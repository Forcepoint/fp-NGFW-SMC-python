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
from smc.api.common import fetch_entry_point, SMCRequest, _get_session
from smc.api.exceptions import HaCommandException
from smc.base.model import Element


class HAInfo(object):
    """
    Represents HA Management information.
    """

    def __init__(self, **data):
        for d, v in data.items():
            setattr(self, d, v)

    @property
    def active_server(self):
        """
        :return: Active server
        :rtype: Server
        """
        return Element.from_href(self._active_server)\
            if hasattr(self, "_active_server") else None

    @active_server.setter
    def active_server(self, value):
        self._active_server = value

    @property
    def standby_servers(self):
        """
        :return: list of Standby servers
        :rtype: list(Server)
        """
        return [Element.from_href(server) for server in self._standby_servers]\
            if hasattr(self, "_standby_servers") else None

    @standby_servers.setter
    def standby_servers(self, values):
        self._standby_servers = values

    def __str__(self):
        lst_stdby = ""
        if self.standby_servers is not None:
            for stdby in self.standby_servers:
                lst_stdby += ", {}".format(stdby)

        return "Active: {} Standby: {}".format(self.active_server, lst_stdby)


class InfoBlock(object):
    """
    Represents diagnostic messages.
    """

    def __init__(self, **data):
        for d, v in data.items():
            setattr(self, d, v)

    @property
    def title(self):
        """
        :return: title for the block
        :rtype: str
        """
        return self._title

    @title.setter
    def title(self, value):
        self._title = value

    @property
    def message(self):
        """
        :return: messages for the block
        :rtype: list(str)
        """
        return self._message

    @message.setter
    def message(self, value):
        self._message = value


class HADiagnostic(object):
    """
    HA Availability diagnostic result.
    """

    def __init__(self, **data):
        for d, v in data.items():
            setattr(self, d, v)

    @property
    def status(self):
        """
        :return: status
        :rtype: str
        """
        return self._status

    @status.setter
    def status(self, value):
        self._status = value

    @property
    def execution_message(self):
        """
        :return: execution messages
        :rtype: list(str)
        """
        return self._execution_message

    @execution_message.setter
    def execution_message(self, value):
        self._execution_message = value

    @property
    def errors_warnings(self):
        """
        :return: error and warning messages
        :rtype: list(str)
        """
        return self._errors_warnings

    @errors_warnings.setter
    def errors_warnings(self, value):
        self._errors_warnings = InfoBlock(**value)

    @property
    def durations(self):
        """
        :return: diagnostic messages
        :rtype: InfoBlock
        """
        return self._durations

    @durations.setter
    def durations(self, value):
        self._durations = InfoBlock(**value)

    @property
    def message(self):
        """
        :return: messages
        :rtype: list(InfoBlock)
        """
        return self._message

    @message.setter
    def message(self, value):
        self._message = [InfoBlock(**message) for message in value]


class HAManagement(object):
    """
    High level Class to administrate Management Server High availability.
    """

    def __init__(self):
        self.entry = fetch_entry_point("ha")

    @staticmethod
    def check_status(response):
        """
        Check the response status code and raise HaCommandException.
        :param Response response: API Response
        :raise: HaCommandException: if status code is not 200
        """
        if response.status_code != 200:
            raise HaCommandException(response)

    def get_ha(self):
        """
        :return: HA Information
        :rtype: HAInfo
        """
        return HAInfo(**SMCRequest(href=self.entry).read().json)

    def set_active(self, server, force=False):
        """
        Launch activation of the specified management server.

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
        :param Server server: the specified management server
        :param bool force: force mode, default False
        :return: the return data.
        :rtype: requests.Response
        """
        session = _get_session(SMCRequest._session_manager)
        params = {"force": force, "server_name": ""+server.name}
        response = session.session.post(
            url=self.entry+"/set_active",
            headers={"Content-Type": "application/json"},
            params=params,
        )
        self.check_status(response)
        return response

    def set_standby(self, server, force=False):
        """
        Launch deactivation of the specified active management server.
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
        params = {"force": force, "server_name": ""+server.name}
        response = session.session.post(
            url=self.entry+"/set_standby",
            headers={"Content-Type": "application/json"},
            params=params,
        )
        self.check_status(response)
        return response

    def full_replication(self, server, force=False):
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
        params = {"force": force, "server_name": ""+server.name}
        response = session.session.post(
            url=self.entry+"/full_replication",
            headers={"Content-Type": "application/json"},
            params=params,
        )
        self.check_status(response)
        return response

    def exclude(self, server, force=False):
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
        params = {"force": force, "server_name": ""+server.name}
        response = session.session.post(
            url=self.entry+"/exclude",
            headers={"Content-Type": "application/json"},
            params=params,
        )
        self.check_status(response)
        return response

    def diagnostic(self, deep=False, exclude_info=False, global_timeout=0, server_timeout=0):
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
        return HADiagnostic(**SMCRequest(href=self.entry+"/diagnostic", params=params).read().json)
