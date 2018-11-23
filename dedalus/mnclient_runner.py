# -*- coding: utf-8 -*-
import zmq
import msgpack
from zmq.eventloop.ioloop import IOLoop
from mnclient import MNClient
from logging import getLogger
from config import *
import sys

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


class ClientRunner(MNClient):

    def __init__(self, context, endpoint, service):
        MNClient.__init__(self, context, endpoint, service)
        self.options = {'1': self.test_traffic}
        self.options_descr = {'1': "test traffic between two (random) nodes"}
        self.winfo = {}
        self.workers = [b'006b8b4568']

        self.req_list = [('workers\' info', [b'', self._proto_version, b'ho.stat', MSG_WINFO]),
                        ('cpu percent', [b'', self._proto_version, SERVICE_ECHO, self.workers[0], MSG_CPUPERCENT]),
                        ('cpu times', [b'', self._proto_version, SERVICE_ECHO, self.workers[0], MSG_CPUTIMES]),
                        ('cpu times percent', [b'', self._proto_version, SERVICE_ECHO, self.workers[0], MSG_CPUTIMESPERCENT]),
                        ('cpu count', [b'', self._proto_version, SERVICE_ECHO, self.workers[0], MSG_CPUCOUNT]),
                        ('cpu stats', [b'', self._proto_version, SERVICE_ECHO, self.workers[0], MSG_CPUSTATS]),
                        ('network io counters', [b'', self._proto_version, SERVICE_ECHO, self.workers[0], MSG_NETIOCOUNTERS]),
                        ('network connections', [b'', self._proto_version, SERVICE_ECHO, self.workers[0], MSG_NETCONNECTIONS]),
                        ('network interfaces addresed', [b'', self._proto_version, SERVICE_ECHO, self.workers[0], MSG_NETIFADDRS]),
                        ('network interfaces statistics', [b'', self._proto_version, SERVICE_ECHO, self.workers[0], MSG_NETIFSTATS]),
                        ('boot time', [b'', self._proto_version, SERVICE_ECHO, self.workers[0], MSG_BOOTTIME]),
                        ('memory info', [b'', self._proto_version, SERVICE_ECHO, self.workers[0], MSG_MEMORYINFO]),
                        ('memory precent', [b'', self._proto_version, SERVICE_ECHO, self.workers[0], MSG_MEMORYPERCENT]),
                        ('connections', [b'', self._proto_version, SERVICE_ECHO, self.workers[0], MSG_CONNECTIONS]),
                        ('dump', [b'', self._proto_version, SERVICE_ECHO, self.workers[0], MSG_DUMP]),
                        ('send traffic', [b'', self._proto_version, SERVICE_ECHO, self.workers[0], MSG_SENDTRAFFIC, msgpack.packb({b'interface' : b'lo', b'destination': b'localhost', b'waittime' : bytes(0)})]),
                        ('stop sending traffic', [b'', self._proto_version, SERVICE_ECHO, self.workers[0], MSG_STOPSENDINGTRAFFIC]),
                        ('babel dump', [b'', self._proto_version, SERVICE_ECHO, self.workers[0], MSG_DUMP_B])]

                        # TESTED SEPERATELY BECAUSE IT REQUIRES TWO REQUESTS!!!
                        # ('measure bandwith', [b'', self._proto_version,MSG_MEASUREBANDWIDTH])
                        # TODO ---> make it one request command

        self.current_req = -1

        # TODO check EOFError --> Occurs because of the ssh connection
        # self.run_dummy_interface()
        print("~~Testing commands used by dedalus~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        # TODO should be replaced from the dummy interface
        self.test_all_commands()

        return

    def on_message(self, msg):
        # [rp, ' ', CLIENT_PROTO, service, cmd, wid, reply_msg]

        _LOG.info("Received: %s" % repr(msg))
        # TODO see message parts

         # 1st part is empty
        msg.pop(0)

        # 2nd part is protocol version
        # TODO: version check
        proto = msg.pop(0)
        if proto != CLIENT_PROTO:
            pass
            # TODO raise exception. add this functionality to other classes too

        (service, cmd, wid_str, reply) = msg

        if cmd == MSG_WINFO:
            self.winfo = msgpack.unpackb(reply)# TODO check recieved messages.
            self.workers = [x["id"] for x in self.winfo if 'broker' not in x['service']]# get worker info
            print(self.workers)
            # self.measure_trafic_between(workers[0], workers[1])
        elif cmd == MSG_MEASUREBANDWIDTH:
            print('HEY YOU!') #DEBUG
            print(msgpack.unpackb(reply)) #DEBUG
        print("-------->Results are: ")#DEBUG
        if reply:
            print(msgpack.unpackb(reply)) #DEBUG
        else:
            print("No reply msg found")

        self.test_all_commands()
        # self.run_dummy_interface(self.winfo)

    def do(self, option):
        if option not in self.options.keys():
            print("Your option does not exist. To see options type 0")
            return
        return self.options[option]()

    def show_operations(self):
        for (key, value) in self.options_descr:
            print(key, value)

    def on_timeout(self):
        print('TIMEOUT!')
        _LOG.info("Timeout! No response from broker.")
        return

    def test_traffic(self):
        self.request([b'', self._proto_version, b'ho.stat', MSG_WINFO])
        print(self.winfo)
        #workers = [x["id"] for x in self.winfo if 'broker' not in self.winfo[x]['service']]# get worker info
        #print(workers)
	    # get worker info
        # request a server in one worker
        # request a client in other worker
        # measure the bandwith

    def measure_trafic_between(self, node1, node2):
        # OPEN IPERF3 SERVER
        port = '7777'
        addr1 = [x['ip'] for x in self.winfo if x['id'] == node1]
        addr1 = bytes(str(addr1[0])+":"+port)
        addr2 = [x['ip'] for x in self.winfo if x['id'] == node2]
        addr2 = bytes(str(addr2[0])+":"+port)
        self.request([b'', CLIENT_PROTO, SERVICE_ECHO, node2, MSG_MEASUREBANDWIDTH, msgpack.packb({b'bind_address': addr1, b'mode': b'server'})])
        # OPEN IPERF3 CLIENT
        self.can_send = True #DEBUG SHOULD NOT BE HERE!!!!
        self.request([b'', CLIENT_PROTO, SERVICE_ECHO, node1, MSG_MEASUREBANDWIDTH, msgpack.packb({b'bind_address': addr2, b'mode': b'client'})])

    # should be called after every on_message in order to work properly
    def run_dummy_interface(self, res = "NODATA"):

            if res == 'NODATA':
                print("HELLO TO DUMMY CLIENT INTERFACE!")
                print("To see options type 0. To exit type -1")
            else:
                print(res)

            try:
                opt = input('>>>')
            except EOFError:
                print('eRRoR')#DEBUG
                opt = '1'

            if opt == '-1':
                #close client or something
                return

            if opt == '0':
                self.show_operations()
            else:
                print("Running option %s" %opt)
                print(self.do(opt))

    def test_all_commands(self):

        self.prepare_next_req()

        (msg, req) = self.req_list[self.current_req]
        print("")
        print("")
        print("Testing command: %s" %msg)
        self.request(req)

    def prepare_next_req(self):
        self.current_req += 1
        if self.current_req == len(self.req_list):
            print("Testing finished")
            IOLoop.instance().stop()


def run(address):

    context = zmq.Context()
    client = ClientRunner(context, address, SERVICE_ECHO)
    try:
        IOLoop.instance().start()
        client.shutdown()
    except KeyboardInterrupt:
        _LOG.info("Interrupt received, stopping!")
    finally:
        # clean up
        client.shutdown()
        context.term()


if __name__ == '__main__':
    run("tcp://127.0.0.1:5555")
