# -*- coding: utf-8 -*-
import zmq
import doctest
from zmq.eventloop.ioloop import IOLoop
from logging import getLogger
from mnbroker import MNBroker

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


class DedalusRunner(MNBroker):
    pass


def run(address, optional_address=None):
    context = zmq.Context()
    broker = DedalusRunner(context, address, optional_address)
    try:
        IOLoop.instance().start()
    except KeyboardInterrupt:
        _LOG.info("Interrupt received, stopping.")
    finally:
        # clean up
        broker.shutdown()
        context.term()


if __name__ == '__main__':
    doctest.testmod()
