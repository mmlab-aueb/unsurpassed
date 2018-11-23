# -*- coding: utf-8 -*-
import sys
import time
from unittest import TestCase

import zmq
from zmq.eventloop.zmqstream import ZMQStream
from zmq.eventloop.ioloop import IOLoop, DelayedCallback, PeriodicCallback

from mnworker import MNWorker, ConnectionNotReadyError, MissingHeartbeat

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


class WorkerRunner(MNWorker):
    HB_INTERVAL = 1000
    HB_RETRIES = 10

    def on_request(self, msg):
        if _do_print:
            print("New worker request, replying with:", msg)
        answer = [b'REPLY'] + msg
        self.reply(answer)
        return


class TestMNWorker(TestCase):

    endpoint = b'tcp://127.0.0.1:5555'
    service = b'test'

    def setUp(self):
        if _do_print:
            print('Setting up...')
        sys.stdout.flush()
        self.context = zmq.Context()
        self.broker = None
        self._msgs = []
        return

    def tearDown(self):
        if _do_print:
            print('Tearing down...')
        sys.stdout.flush()
        if self.broker:
            self._stop_broker()
        self.broker = None
        self.context = None
        return

    def _on_msg(self, msg):
        if _do_print:
            print('Broker received:', msg)
        self.target = msg.pop(0)
        marker_frame = msg.pop(0)
        if msg[1] == b'\x01':  # ready
            if _do_print:
                print('READY received')
            return
        if msg[1] == b'\x04':  # ready
            if _do_print:
                print('HB received')
            return
        if msg[1] == b'\x03':  # reply
            IOLoop.instance().stop()
            return
        return

    def _start_broker(self, do_reply=False):
        """Helper activating a fake broker in the ioloop.
        """
        socket = self.context.socket(zmq.ROUTER)
        self.broker = ZMQStream(socket)
        self.broker.socket.setsockopt(zmq.LINGER, 0)
        self.broker.bind(self.endpoint)
        self.broker.on_recv(self._on_msg)
        self.broker.do_reply = do_reply
        self.broker.ticker = PeriodicCallback(self._tick, WorkerRunner.HB_INTERVAL)
        self.broker.ticker.start()
        self.target = None
        if _do_print:
            print("Broker started")
        return

    def _stop_broker(self):
        if self.broker:
            self.broker.ticker.stop()
            self.broker.ticker = None
            self.broker.socket.close()
            self.broker.close()
            self.broker = None
        if _do_print:
            print("Broker stopped")
        return

    def _tick(self):
        if self.broker and self.target:
            msg = [self.target, b'', b'MNPW01', b'\x04']
            self.broker.send_multipart(msg)
            if _do_print:
                print("Tick sent:", msg)
        return

    def send_req(self):
        data = [b'AA', b'bb']
        msg = [self.target, b'', b'MNPW01', b'\x02', self.target, b''] + data
        self.broker.send_multipart(msg)
        if _do_print:
            print('broker sent:', msg)
        return

    @staticmethod
    def stop_loop():
        IOLoop.instance().stop()
        return

    # Tests follow

    def test_simple_worker(self):
        """Test MNWorker simple req/reply.
        """
        self._start_broker()
        time.sleep(0.2)
        worker = WorkerRunner(self.context, self.endpoint, self.service)
        sender = DelayedCallback(self.send_req, 500)
        stopper = DelayedCallback(self.stop_loop, 2500)
        sender.start()
        stopper.start()
        IOLoop.instance().start()
        worker.shutdown()
        self._stop_broker()
        return
