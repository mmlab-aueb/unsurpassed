# -*- coding: utf-8 -*-
import zmq
from zmq.eventloop.zmqstream import ZMQStream
from zmq.eventloop.ioloop import IOLoop, PeriodicCallback, DelayedCallback
from util import split_address
from logging import getLogger

from config import *
from mn_obj import MN_object

__license__ = """
    This file is part of Dedalus.

    Dedalus is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Dedalus is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Dedalus.  If not, see <http://www.gnu.org/licenses/>.
"""

__author__ = 'Esmerald Aliaj'
__email__ = 'esmeraldaliai@yahoo.gr'

_LOG = getLogger(__name__)
_DLOG = getLogger('dedalus_logger')


class ConnectionNotReadyError(RuntimeError):
    """Exception raised when attempting to use the MNWorker before the handshake took place.
    """
    pass


class MissingHeartbeat(UserWarning):
    """Exception raised when a heartbeat was not received on time.
    """
    pass


class MNWorker(MN_object):
    """Class for the MN worker side.

    Thin encapsulation of a zmq.DEALER socket.
    Provides a send method with optional timeout parameter.

    Will use a timeout to indicate a broker failure.

    :param context:    the context to use for socket creation.
    :type context:     zmq.Context
    :param endpoint:   endpoint to connect to.
    :type endpoint:    str
    :param service:    the name of the service we support.
    :type service:     byte-string
    """

    _proto_version = b'MNPW01'  # worker protocol version

    def __init__(self, context, endpoint, service, worker_type, address, protocols):
        """Initialize the MNWorker.
        """
        self.context = context
        self.endpoint = endpoint
        self.service = service
        self.type = worker_type
        self.address = address
        self.protocols = protocols
        self.envelope = None
        self.HB_RETRIES = HB_RETRIES
        self.HB_INTERVAL = HB_INTERVAL
        self._data = {}
        self.stream = None
        self._tmo = None
        self.timed_out = False
        self.need_handshake = True
        self.connected = False
        self.ticker = None
        self._delayed_cb = None
        self._create_stream()
        _LOG.info("Worker initialized and can be found at '%s'" % endpoint)
        return

    def _create_stream(self):
        """Helper to create the socket and the stream.
        """
        socket = self.context.socket(zmq.DEALER)
        ioloop = IOLoop.instance()
        self.stream = ZMQStream(socket, ioloop)
        self.stream.on_recv(self._on_message)
        self.stream.socket.setsockopt(zmq.LINGER, 0)
        self.stream.connect(self.endpoint)
        self.ticker = PeriodicCallback(self._tick, self.HB_INTERVAL)
        self._send_ready()
        self.ticker.start()
        return

    def _send_ready(self):
        """Helper method to prepare and send the workers READY message.
        """
        _LOG.debug("Informing broker I am ready")
        ready_msg = [b'', WORKER_PROTO, MSG_READY, self.service, self.type, self.address, self.protocols]
        if self.stream.closed():
            self.shutdown()
        self.stream.send_multipart(ready_msg)
        self.curr_retries = self.HB_RETRIES
        return

    def _tick(self):
        """Method called every HB_INTERVAL milliseconds.
        """
        self.curr_retries -= 1
        self.send_hb()
        if self.curr_retries >= 0:
            return
        # connection seems to be dead
        self.shutdown()
        # try to recreate it
        # self._delayed_cb = IOLoop.call_later(self._create_stream, 5000)
        # self._delayed_cb = IOLoop.add_timeout(self._create_stream, 5000)
        self._delayed_cb = DelayedCallback(self._create_stream, self.HB_INTERVAL)
        self._delayed_cb.start()
        return

    def send_hb(self):
        """Construct and send HB message to broker.
        """
        _LOG.debug("Sending heartbeat")
        msg = [b'', WORKER_PROTO, MSG_HEARTBEAT]
        if self.stream.closed():
            self.shutdown()
        self.stream.send_multipart(msg)
        return

    def shutdown(self):
        """Method to deactivate the worker connection completely.

        Will delete the stream and the underlying socket.
        """
        if self.ticker:
            self.ticker.stop()
            self.ticker = None
        if not self.stream:
            return
        self.stream.socket.close()
        self.stream.close()
        self.stream = None
        self.timed_out = False
        self.need_handshake = True
        self.connected = False
        return

    def reply(self, msg):
        """Send the given message.

        :param msg:    full message to send.
        :type msg:     can either be a byte-string or a list of byte-strings
        """
        if self.need_handshake:
            raise ConnectionNotReadyError()
        to_send = self.envelope
        self.envelope = None
        if isinstance(msg, list):
            to_send.extend(msg)
        else:
            to_send.append(msg)
        if self.stream.closed():
            self.shutdown()
        self.stream.send_multipart(to_send)
        return

    def _on_message(self, msg):
        """Helper method called on message receive.

        :param msg:    a list w/ the message parts
        :type msg:     a list of byte-strings
        """
        _LOG.debug("Received: %s." % msg)
        # 1st part is empty
        msg.pop(0)
        # 2nd part is protocol version
        proto = msg.pop(0)
        if proto != WORKER_PROTO:
            # ignore message from not supported protocol
            pass
        # 3rd part is message type
        msg_type = msg.pop(0)
        # XXX: hardcoded message types!
        # any message resets the retries counter
        self.need_handshake = False
        self.curr_retries = self.HB_RETRIES
        if msg_type == MSG_DISCONNECT:  # disconnect
            _LOG.info("Broker wants us to disconnect.")
            self.curr_retries = 0  # reconnect will be triggered by hb timer
        elif msg_type == MSG_QUERY:  # request
            # remaining parts are the user message
            _LOG.debug("Received new request: %s." % msg)
            envelope, msg = split_address(msg)
            envelope.append(b'')
            envelope = [b'', WORKER_PROTO, MSG_REPLY] + envelope  # reply
            self.envelope = envelope
            self.on_request(msg)
        else:
            # invalid message
            # ignored
            _LOG.debug('ignoring message with invalid id')
            pass
        return

    def on_request(self, msg):
        """Public method called when a request arrived.

        :param msg:    a list w/ the message parts
        :type msg:     a list of byte-strings

        Must be overloaded to provide support for various services!
        """
        pass


class DataTracker(object):
    """Helper class to represent a cached data object in the worker.

    :param hid:      the worker id.
    :type hid:       str
    :param service:  service this data belongs to
    :type service:   str
    :param contents: contents of the hashed data
    :type contents:  bytearray
    """

    def __init__(self, hid, service, contents):
        self.hid = hid
        self.service = service
        self.contents = contents
        self.size = 0
        return

    def get_size(self):
        """Will return the size in bytes of the data held by this object.

        :rtype: int
        """
        return len(self.contents)
