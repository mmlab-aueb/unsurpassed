# -*- coding: utf-8 -*-
import zmq
from zmq.eventloop.ioloop import IOLoop
from zmq.eventloop.zmqstream import ZMQStream
from mnclient import MNClient, InvalidStateError
from unittest import TestCase

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

_do_print = True


class MyClient(MNClient):

    def on_message(self, msg):
        if _do_print:
            print('client received:', msg)
        self.last_msg = msg
        IOLoop.instance().stop()
        return

    def on_timeout(self):
        if _do_print:
            print('client timed out!')
        IOLoop.instance().stop()
        return


class TestMNClient(TestCase):

    endpoint = b'tcp://127.0.0.1:5555'
    service = b'test'

    def setUp(self):
        if _do_print:
            print('Setting up...')
        self.context = zmq.Context()
        self.broker = None
        self._msgs = []
        return

    def tearDown(self):
        if _do_print:
            print('Tearing down...')
        if self.broker:
            self._stop_broker()
        self.broker = None
        self._msgs = []
        self.context.term()
        self.context = None
        return

    def _on_msg(self, msg):
        self._msgs.append(msg)
        if _do_print:
            print('broker received:', msg)
        if self.broker.do_reply:
            new_msg = msg[:4]
            new_msg.append(b'REPLY')
            self.broker.send_multipart(new_msg)
        else:
            IOLoop.instance().stop()
        return

    def _start_broker(self, do_reply=False):
        """Helper activating a fake broker in the ioloop.
        """
        if _do_print:
            print('Starting broker at', self.endpoint)
        socket = self.context.socket(zmq.ROUTER)
        self.broker = ZMQStream(socket)
        self.broker.socket.setsockopt(zmq.LINGER, 0)
        self.broker.bind(self.endpoint)
        self.broker.on_recv(self._on_msg)
        self.broker.do_reply = do_reply
        return

    def _stop_broker(self):
        if _do_print:
            print('Stopping broker')
        if self.broker:
            self.broker.socket.close()
            self.broker.close()
            self.broker = None
        return

    # Tests from here
    
    def test_01_create_01(self):
        """Test MNClient simple create.
        """
        client = MNClient(self.context, self.endpoint, self.service)
        self.assertEqual(self.endpoint, client.endpoint)
        self.assertEqual(self.service, client.service)
        client.shutdown()
        return

    def test_02_send_01(self):
        """Test MNClient simple request.
        """
        self._start_broker()
        client = MNClient(self.context, self.endpoint, self.service)
        client.request(b'XXX')
        IOLoop.instance().start()
        client.shutdown()
        self.assertEqual(len(self._msgs), 1)
        rmsg = self._msgs[0]
        # msg[0] is identity of sender
        self.assertEqual(rmsg[1], b'')  # routing delimiter
        self.assertEqual(rmsg[2], client._proto_version)
        self.assertEqual(rmsg[3], self.service)
        self.assertEqual(rmsg[4], b'XXX')
        self._stop_broker()
        return

    def test_02_send_02(self):
        """Test MNClient multipart request.
        """
        mydata = [b'AAA', b'bbb']
        self._start_broker()
        client = MNClient(self.context, self.endpoint, self.service)
        client.request(mydata)
        IOLoop.instance().start()
        client.shutdown()
        self.assertEqual(len(self._msgs), 1)
        rmsg = self._msgs[0]
        # msg[0] is identity of sender
        self.assertEqual(rmsg[1], b'')  # routing delimiter
        self.assertEqual(rmsg[2], client._proto_version)
        self.assertEqual(rmsg[3], self.service)
        self.assertEqual(rmsg[4:], mydata)
        self._stop_broker()
        return

    def test_02_send_03(self):
        """Test MNClient request in invalid state.
        """
        client = MNClient(self.context, self.endpoint, self.service)
        client.request(b'XXX')  # ok
        self.assertRaises(InvalidStateError, client.request, b'AAA')
        client.shutdown()
        return

    def test_03_timeout_01(self):
        """Test MNClient request w/ timeout.
        """
        client = MyClient(self.context, self.endpoint, self.service)
        client.request(b'XXX', 20)  # 20 millisecs timeout
        IOLoop.instance().start()
        client.shutdown()
        self.assertEqual(client.timed_out, True)
        return

    def test_04_receive_01(self):
        """Test MNClient message receive.
        """
        self._start_broker(do_reply=True)
        client = MyClient(self.context, self.endpoint, self.service)
        client.request(b'XXX')
        IOLoop.instance().start()
        client.shutdown()
        self._stop_broker()
        self.assertEqual(True, hasattr(client, 'last_msg'))
        self.assertEqual(3, len(client.last_msg))
        self.assertEqual(b'REPLY', client.last_msg[-1])
        self.assertEqual(self.service, client.last_msg[-2])
        return
