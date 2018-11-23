# -*- coding: utf-8 -*-
import doctest
from datetime import datetime
from logging import getLogger

import msgpack
import zmq
from zmq.eventloop.ioloop import IOLoop

from config import *
from mnworker import MNWorker
from scanner_hw import HWScanner, HWTraffic, NetworkManager
from util import get_current_ip

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

# TODO: At some point this must be set dynamically
WK_TYPE = WK_TYPE_PC
WK_SERVICE = SERVICE_ECHO


class WorkerRunner(MNWorker):
    def __init__(self, context, endpoint, service):
        self.scanner = HWScanner()
        self.traffic_generator = HWTraffic()
        self.network_manager = NetworkManager()
        # TODO: send all information as an object so we can pack and unpack it easily, would also help in the frontend
        MNWorker.__init__(self, context, endpoint, service, WK_TYPE, bytes(get_current_ip(DEFAULT_INTEFACE)),
                          bytes(' '.join(self.network_manager.available_routing_protocols)))
        # first two characters of any function id will identify its module
        self._module_code = {b'hs': self.scanner.run,
                             b'tg': self.traffic_generator.run,
                             b'nm': self.network_manager.run,
                             b'wr': self.local_commands}
        self._worker_funcs = {MSG_WDUMP: self.dump}

    def on_request(self, msg):
        cmd = msg.pop(0)
        if cmd[:2] in self._module_code:
            res = self._module_code[cmd[:2]](cmd, msg)
            if isinstance(res, dict):
                res['finished_at'] = datetime.now().strftime('%d-%M-%Y %I:%M:%S')
        else:
            self.reply('Requested operation not supported!')
            return
        _LOG.debug("Work done for operation: %s with output %s." % (cmd, res))
        self.reply([cmd, msgpack.packb(res)])
        return

    def local_commands(self, cmd, msg):
        if cmd in self._worker_funcs:
            fnc = self._worker_funcs[cmd]
            return fnc(msg)
        else:
            # ignore unknown command
            _LOG.info("I received an unknown command: %s." % cmd)
        return

    def dump(self, msg):
        """Return system info.
        """
        res = self.scanner.dump()
        res.update({'routing_dump': self.network_manager.get_routing_dump(),
                    'address': self.network_manager.current_ip_address,
                    'control-address': get_current_ip(CONTROL_INTERFACE),
                    'current_routing_protocol': self.network_manager.current_routing_protocol,
                    'current_dtn_protocol': self.network_manager.get_current_dtn_protocol(),
                    'dtn_dump': self.network_manager.get_dtn_dump(),
                    'ccn_dump': self.network_manager.get_ccn_dump()})
        return res

    def shutdown(self):
        # TODO: if these close on heartbeat loss, they will never open again
        # TODO: move the auto-open code here instead of mnworker
        # self.scanner.shutdown()
        # self.network_manager.shutdown()
        # self.traffic_generator.shutdown()
        super(WorkerRunner, self).shutdown()


def run(address):
    context = zmq.Context()
    worker = WorkerRunner(context, address, WK_SERVICE)
    try:
        IOLoop.instance().start()
        worker.shutdown()
    except KeyboardInterrupt:
        _LOG.info("Interrupt received, stopping!")
    finally:
        # clean up
        worker.shutdown()
        context.term()


if __name__ == '__main__':
    doctest.testmod()
