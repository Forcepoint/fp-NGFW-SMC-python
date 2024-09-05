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

import os
import ssl
import json
import select
import logging
import threading
import time
from pprint import pformat
from smc import session
from smc.compat import PYTHON_v3_9
from smc_monitoring.models.formatters import TableFormat, ElementFormat

import websocket
from websocket import WebSocketApp, ABNF, WebSocketProtocolException

logger = logging.getLogger(__name__)

BUFFER_ERROR = b"The decoded text message was too big for the output buffer and " \
               b"the endpoint does not support partial messages"


def websocket_debug():
    websocket.enableTrace(True)


class FetchAborted(Exception):
    pass


class InvalidFetch(Exception):
    pass


class SessionNotFound(Exception):
    pass


def _get_ca_bundle():
    """
    If verify=True, then requests is using the built in
    certifi CA database. Attempt to get that path for
    the websocket.
    """
    try:
        import certifi

        return certifi.where()
    except ImportError:
        pass


def get_ssl_opt(**kw):
    sslopt = {}
    if session.is_ssl:
        # SSL verification is based on the session settings since the
        # session must be made before calling this class. If verify=True,
        # try to get the CA bundle from certifi if the package exists
        # Set check_hostname to False because python ssl doesn't appear
        # to validate the subjectAltName properly, however requests does
        # and would have already validated this when the session was set
        # up. This can still be overridden by setting check_hostname=True.
        sslopt.update(cert_reqs=ssl.CERT_NONE, check_hostname=False)

        certfile = session.session.verify
        if certfile:
            if isinstance(certfile, bool):  # verify=True
                certfile = _get_ca_bundle()
                if certfile is None:
                    certfile = ""

            sslopt.update(
                cert_reqs=kw.pop("cert_reqs", ssl.CERT_REQUIRED),
                check_hostname=kw.pop("check_hostname", False),
            )

            if sslopt.get("cert_reqs") != ssl.CERT_NONE:
                os.environ["WEBSOCKET_CLIENT_CA_BUNDLE"] = certfile

    return sslopt


def get_sock_from_session():
    sock = None
    if session.session_id is None:
        sock = session.sock
        if sock is None:
            # Need to refresh the session
            session.refresh()
            sock = session.sock
            logger.debug("WS: socket from new session:{} id:{}".format(sock,
                                                                       sock.session.id))
        else:
            logger.debug("WS: session still available socket:{} id:{}".format(sock,
                                                                              sock.session.id))
    return sock


class SMCSocketAsyncProtocol:
    """
    SMCSocketAsyncProtocol manages the web socket connection between this
    client and the SMC. It provides the interface to monitor the query
    results and call the callback_method provided on the fly when there is new data.
    It is possible to provide formatter like TableFormat, ElementFormat and the element name you
    want to retrieve

    Example of subscribing to log notifications using callback method::

        >>>     def callback_log_table_fct(wso, data):
        ...         print(data)

        >>>     query = LogQuery()
        >>>     query.add_or_filter([
        ...               InFilter(FieldValue(LogField.DPORT), [NumberValue(80)]),
        ...               InFilter(FieldValue(LogField.SERVICE), [ServiceValue('TCP/80')])])

        >>>    async_ws = SMCSocketAsyncProtocol(query=query,
        ...                              on_message_fct=callback_log_table_fct,
        ...                              formatter=TableFormat)
        >>>     async_ws.run(background=True)


    """

    def __init__(self, query, on_message_fct, formatter=TableFormat, element_name=None, **kw):
        """
        Initialize the web socket.

        :param Query query: Query type from `smc_monitoring.monitors`
        :param formatter: Custom formats used to return data in different formats.
        :param element_name: if formatter is ElementFormat give the name of the element to retrieve
            e.g. Neighbor, RoutingView, Alert..
        """

        self.query = query
        self.on_message_fct = on_message_fct
        self.formatter = formatter
        self.element_name = element_name
        self.thread = None
        self.fetch_id = None

        if formatter is ElementFormat:
            query.format.field_format("id")
            for custom_field in ["field_ids", "field_names"]:
                query.format.data.pop(custom_field, None)

        if not session.session:
            raise SessionNotFound(
                "No SMC session found. You must first "
                "obtain an SMC session through session.login before making "
                "a web socket connection."
            )

        # Case use ssl for session_id
        self.sock = get_sock_from_session()

        self.sslopt = get_ssl_opt(**kw)

        self.ws = WebSocketApp(session.web_socket_url + query.location,
                               on_open=self._on_open_ws,
                               on_message=self._on_message_ws,
                               on_close=self._on_close,
                               on_error=self._on_error,
                               cookie=session.session_id,
                               socket=self.sock)

    def run(self, background=False):
        """
        Start listening from the websocket on the callback method
        """
        if background:
            logger.debug("WS run in new thread...")
            # we disable Origin header because it conflicts with Tomcat Cors Filter
            # and in this context, we do not need to have cors filtering
            self.thread = threading.Thread(target=self.ws.run_forever,
                                           kwargs={"sslopt": self.sslopt, "suppress_origin": True})
            self.thread.start()
        else:
            logger.debug("WS run in main thread...")
            # we disable Origin header because it conflicts with Tomcat Cors Filter
            # and in this context, we do not need to have cors filtering
            self.ws.run_forever(sslopt=self.sslopt, suppress_origin=True)

    def _on_open_ws(self, ws):
        logger.debug("WS:{} open".format(ws))
        ws.send(json.dumps(self.query.request))

    def _on_message_ws(self, ws, message):
        data = json.loads(message)
        self.fetch_id = data.get("fetch")
        records = self.query.get_record(results=data)
        if records:
            if self.formatter is ElementFormat:
                for message in records:
                    self.on_message_fct(ws, self.element_name(**message))
            else:
                fmt = self.formatter(self.query)
                self.on_message_fct(ws, fmt.formatted(records))

    def _on_error(self, ws, err):
        ws.close()
        logger.error("WS:{} error: {}".format(ws, err))

    def _on_close(self, ws, close_status_code, close_msg):
        logger.debug("WS:{} closed status={} message={} ! ".format(ws,
                                                                   close_status_code,
                                                                   close_msg))

    def abort(self):
        """
        Abort
        End listening for new messages and let server close the websocket
        :return: True ws connection aborted
        """
        if self.fetch_id is None:
            logger.warning("WS fetch_id is None: can't abort !")
            return False
        if session.session_id is None and self.sock is None:
            self.sock = get_sock_from_session()

        self.ws.send("{{'abort': {}}}".format(self.fetch_id))
        logger.debug("WS connection aborted !")
        return True

    def close(self):
        """
        Close the websocket
        """
        logger.info("Close WS:{}".format(self))
        self.ws.close()


class SMCSocketProtocol(websocket.WebSocket):
    """
    SMCSocketProtocol manages the web socket connection between this
    client and the SMC. It provides the interface to monitor the query
    results and yield them back to the caller as a context manager.
    """

    def __init__(self, query, query_timeout=None, sock_timeout=3, inactivity_timeout=None, **kw):
        """
        Initialize the web socket.

        :param Query query: Query type from `smc_monitoring.monitors`
        :param int query_timeout: length of time to wait on recieving web
            socket results (total query time).
        :param int inactivity_timeout: length of time before exiting if no new entry.
        :param int sock_timeout: length of time to wait on a select call
            before trying to receive data. For LogQueries, this should be
            short, i.e. 1 second. For other queries the default is 3 sec.
        :param int max_recv: for queries that are not 'live', set
            this to supply a max number of receive iterations.
        :param kw: supported keyword args:
            cert_reqs: ssl.CERT_NONE|ssl.CERT_REQUIRED|ssl.CERT_OPTIONAL
            check_hostname: True|False
            enable_multithread: True|False (Default: True)

        .. note:: The keyword args are not required unless you want to override
            default settings. If SSL is used for the SMC session, the settings
            for verifying the server with the root CA is based on whether the
            'verify' setting has been provided with a path to the root CA file.
        """
        if not session.session:
            raise SessionNotFound(
                "No SMC session found. You must first "
                "obtain an SMC session through session.login before making "
                "a web socket connection."
            )

        sslopt = get_ssl_opt(**kw)

        # Enable multithread locking
        if "enable_multithread" not in kw:
            kw.update(enable_multithread=True)

        # Max number of receives, configurable for batching
        self.max_recv = kw.pop("max_recv", 0)

        super(SMCSocketProtocol, self).__init__(sslopt=sslopt, **kw)
        self.query_timeout = query_timeout
        self.inactivity_timeout = inactivity_timeout
        self.query = query
        self.fetch_id = None
        # Inner thread used to keep socket select alive
        self.thread = None
        self.event = threading.Event()
        self.sock_timeout = sock_timeout

    def __enter__(self):
        if session.session_id is None:
            sock = session.sock
            if sock is None:
                # Need to obtain new socket
                logger.debug("Refresh the login session..")
                session.refresh()
            # we disable Origin header because it conflicts with Tomcat Cors Filter
            # and in this context, we do not need to have cors filtering
            self.connect(
                url=session.web_socket_url + self.query.location,
                socket=session.sock,
                suppress_origin=True)
        else:
            # we disable Origin header because it conflicts with Tomcat Cors Filter
            # and in this context, we do not need to have cors filtering
            self.connect(
                url=session.web_socket_url + self.query.location,
                cookie=session.session_id,
                suppress_origin=True)

        if self.connected:
            self.settimeout(self.sock_timeout)
            self.on_open()
        return self

    def __exit__(self, exctype, value, traceback):
        if exctype in (SystemExit, GeneratorExit):
            return False
        elif exctype in (InvalidFetch, WebSocketProtocolException):
            raise FetchAborted(value)
        return True

    def on_open(self):
        """
        Once the connection is made, start the query off and
        start an event loop to wait for a signal to
        stop. Results are yielded within receive().
        """

        def event_loop():
            logger.debug(pformat(self.query.request))
            self.send(json.dumps(self.query.request))
            while not self.event.is_set():
                # print('Waiting around on the socket: %s' % self.gettimeout())
                self.event.wait(self.gettimeout())

            logger.debug("Event loop terminating.")

        self.thread = threading.Thread(target=event_loop)
        self.thread.setDaemon(True)
        self.thread.start()

    def send_message(self, message):
        """
        Send a message down the socket. The message is expected
        to have a `request` attribute that holds the message to
        be serialized and sent.
        """
        if self.connected:
            self.send(json.dumps(message.request))

    def abort(self):
        """
        Abort the connection
        """
        logger.info("Abort called, cleaning up.")
        raise FetchAborted

    def recv(self):
        """
        Receive string data(byte array) from the server.
        :rtype: string (byte array) value.
        """
        with self.readlock:
            opcode, data = self.recv_data()
        if opcode == ABNF.OPCODE_TEXT:
            return data.decode("utf-8")
        elif opcode == ABNF.OPCODE_BINARY:
            return data
        elif opcode == ABNF.OPCODE_CLOSE and BUFFER_ERROR in data:
            raise WebSocketProtocolException("Invalid close frame, {}".format(data))
        else:
            return ''

    def receive(self):
        """
        Generator yielding results from the web socket. Results
        will come as they are received. Even though socket select
        has a timeout, the SMC will not reply with a message more
        than every two minutes.
        """
        try:
            itr = 0
            if self.connected and self.query_timeout:
                start = time.time()
                inactivity_start = time.time()
            while self.connected:
                r, w, e = select.select((self.sock,), (), (), self.sock_timeout)

                if r:
                    if self.inactivity_timeout:
                        inactivity_start = time.time()
                    message = json.loads(self.recv())

                    if "fetch" in message:
                        self.fetch_id = message["fetch"]

                    if "failure" in message:
                        raise InvalidFetch(message["failure"])

                    if "records" in message:
                        if "added" in message["records"]:
                            num = len(message["records"]["added"])
                        else:
                            num = len(message["records"])

                        logger.info("Query returned %s records.", num)
                        if self.max_recv:
                            itr += 1

                    if "end" in message:
                        logger.debug(
                            "Received end message: %s" %
                            message["end"])
                        yield message
                        break

                    yield message
                    if self.max_recv and self.max_recv <= itr:
                        break

                if self.query_timeout:
                    progress = time.time()
                    if self.query_timeout < int(progress - start):
                        logger.info("Socket receive query timeout")
                        break

                if self.inactivity_timeout:
                    progress = time.time()
                    if self.inactivity_timeout < int(progress - inactivity_start):
                        logger.info("Socket receive inactivity timeout")
                        break

        except (Exception, KeyboardInterrupt, SystemExit, FetchAborted) as e:
            logger.info(
                "Caught exception in receive: %s -> %s",
                type(e),
                str(e))
            if isinstance(e, (SystemExit, InvalidFetch, WebSocketProtocolException)):
                # propagate SystemExit, InvalidFetch
                raise
        finally:
            if self.connected:
                if self.fetch_id:
                    self.send(json.dumps({"abort": self.fetch_id}))
                self.close()

            if self.thread:
                self.event.set()
                while (not PYTHON_v3_9 and self.thread.isAlive()) or \
                      (PYTHON_v3_9 and self.thread.is_alive()):
                    self.event.wait(1)

            logger.info("Closed web socket connection normally:{}.".format(self))
