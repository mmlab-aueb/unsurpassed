# -*- coding: utf-8 -*-
import codecs
import os
import sys
import threading
import time
from logging import getLogger
from os import path, makedirs

import ext.sh
from ext.sh import sudo, tail, pkill, SignalException_SIGKILL, ErrorReturnCode_1, echo, rm, ip

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

__author__ = 'Petros Gketsopoulos'
__email__ = 'pgetsopoulos@hotmail.com'

_LOG = getLogger(__name__)
_DLOG = getLogger('dedalus_logger')

# CCN constants

REFRESH_TIME = 30

NUM_OF_CONTENTS = 10  # number of contents to be created/looked up
RESTART_TIME = 0.1


# TODO: add get paths and get neighbors functionality
# TODO: add documentation (we should review the documentation of all methods)
# TODO: This file needs serious reformatting, or removal
class CCNNode(object):
    def __init__(self):
        """Init CCNNode instance.
        """
        self.proto_info = {}
        self.proto_state = {'stats_info': {},
                            'stats_bundles': {},
                            'stats_conv': {},
                            'neighbors': []}

    def info(self):
        # TODO what should we return? what information do we need from ccn?
        return self.proto_state


class Scanner(object):
    def __init__(self):
        """Init CCNScanner instance.
        """
        self.node = CCNNode()

        self.local_address = self.get_local_address()
        self.current_node = 'node' + self.local_address.split("168.1.")[1]
        self.process = None
        self.neighbours_callback = None
        self.faces_ids = {}
        self.download_thread = None
        self.thread_running = threading.Event()

        self.logs_path = path.abspath(path.join(path.dirname(__file__), '..', 'Log/CCN/'))

        if not path.exists(self.logs_path):
            makedirs(self.logs_path)

        self.ccn_path = '/home/pi/ccn-lite/build/bin/'
        self.ndntlv_path = "/home/pi/ccn-lite/test/ndntlv"
        self.relay_socket = "/tmp/mgmt-relay.sock"
        self.create_files()
        self.stop()

    def get_routing_info(self):
        return {'name': self.current_node}

    def create_files(self):
        # create NUM_OF_CONTENTS contents
        lower = 0
        for num in range(lower, NUM_OF_CONTENTS + 1):
            self.create_content("content_" + str(num), "test/test" + str(num), "This is content number " + str(num))

    def start(self):
        try:
            os.system('mkdir -p /home/pi/ccn-lite/test/ndntlv')
            os.system(
                '/home/pi/ccn-lite/build/bin/ccn-lite-relay -v trace -s ndn2013 -u 9998 -x /tmp/mgmt-relay.sock -d '
                '/home/pi/ccn-lite/test/ndntlv > ' + self.logs_path + '/ccn-start.log 2>&1 &')

            if self.download_thread is None:
                self.thread_running.clear()
                self.download_thread = threading.Thread(target=self.neighbours_background)
                self.download_thread.start()

            return {'success': True}
        except ErrorReturnCode_1:
            return {'success': True, 'info': 'a ccn instance was already running in this system'}

    def stop(self):
        self.delete_sockets()

        if self.download_thread is not None:
            self.thread_running.set()

        try:
            pkill('ccn')
        except SignalException_SIGKILL:
            return {'success': True, 'info': 'ccn relay killed!'}
        except ErrorReturnCode_1:
            return {'success': True, 'info': 'no running ccn instance found'}
        return {'success': True}

    def delete_sockets(self):
        # TODO Check exception codes
        try:
            # with mn_sudo:
            rm('/tmp/mgmt-relay*')
            rm('/tmp/.ccn-light-ctrl-*')
        except SignalException_SIGKILL:
            return 'ccn relay killed!'
        except ErrorReturnCode_1:
            return 'no running ccn instance found'

        return "ccn sockets deleted"

    def search_content(self, local, path):
        os.system(
            '/home/pi/ccn-lite/build/bin/ccn-lite-peek -s ndn2013 -u ' + local + '/9998 \"' + path + '" | /home/pi'
                                                                                                     '/ccn-lite/build/bin/ccn-lite-pktdump -f 2 >> ' + self.logs_path + '/ccn-search.log 2>&1 &')
        return "Search done check the log"

    def search(self, node="node1"):
        self.search_content(self.local_address,
                            "/" + node + "/test/test" + str(0))
        return {'success': True}

    def create_content(self, filename, path, content):
        data_creation_file = open(self.logs_path + '/datacreation.txt', "w")
        echo("From node" + self.current_node + ": " + content, _out=data_creation_file)
        actual_path = '/' + self.current_node + '/' + path
        os.system(
            '/home/pi/ccn-lite/build/bin/ccn-lite-mkC -s ndn2013 \"' + actual_path + '\" -i ' + self.logs_path + '/datacreation.txt -o /home/pi/ccn-lite/test/ndntlv/' + filename + '.ndntlv')
        return

    def restart_server(self):
        self.stop()
        time.sleep(RESTART_TIME)
        return self.start()

    def get_local_address(self):
        local = "192.168.1.1"
        interfaces_path = "/etc/network/interfaces"
        for line in tail("-n", "20", "-f", interfaces_path, _iter=True):
            if "address 192.168.1." in line:
                local = line.split("address ")[1].splitlines()[0]
                break
        return local

    def get_neighbours_route(self):
        result = ip("route")
        full = result.stdout.decode('utf-8')
        for line in full.splitlines():
            if "via" in line and line.startswith("192.168.1."):
                address = line.split(" ")[2].splitlines()[0]
                target = line.split(" ")[0].splitlines()[0]
                node = target.split("168.1.")[1]
                self.add_face(address, node)

    def neighbours_background(self):
        start_time = time.time()
        while not self.thread_running.is_set():
            self.get_neighbours_route()
            self.thread_running.wait(REFRESH_TIME - ((time.time() - start_time) % REFRESH_TIME))

    # Reads the FACEID from the dump xml of CCN-Lite
    def read_face(self):
        face_dump_file = self.logs_path + '/facedump.txt'
        with codecs.open(face_dump_file, "rb") as f:
            node = "none"
            for line in f:
                if "FACEID" in line:
                    node = line.split("FACEID>")[1].split("<")[0]
                if "PEER" in line:
                    if node != "none":
                        return node

    # Create face based on address
    def add_face(self, address, node):
        command1 = ext.sh.Command(self.ccn_path + "ccn-lite-ctrl")
        command2 = ext.sh.Command(self.ccn_path + "ccn-lite-ccnb2xml")
        command2(command1("-x", self.relay_socket, "newUDPface", "any", address, "9998", _piped=True), _piped=True)

        face_dump_file = open(self.logs_path + '/facedump.txt', "w")
        sudo(sudo(self.ccn_path + "ccn-lite-ctrl", "-x", self.relay_socket, "debug", "dump"),
             self.ccn_path + "ccn-lite-ccnb2xml", _out=face_dump_file)
        face_dump_file.close()
        time.sleep(0.1)
        face_id = self.read_face()
        if face_id is None:
            return
        self.delete_face(node)
        self.faces_ids[node] = face_id
        command2(command1("-x", self.relay_socket, "prefixreg", "/node" + node, face_id, "ndn2013", _piped=True),
                 _piped=True)
        return

    # Delete a face of a node -NOT address
    def delete_face(self, node):
        if node in self.faces_ids:
            face_to_delete = self.faces_ids[node]
        else:
            return
        command1 = ext.sh.Command(self.ccn_path + "ccn-lite-ctrl")
        command2 = ext.sh.Command(self.ccn_path + "ccn-lite-ccnb2xml")
        command2(command1("-x", self.relay_socket, "destroyface", face_to_delete, _piped=True), _piped=True)
        return


if __name__ == "__main__":
    icn_protocol = Scanner()

    # create NUM_OF_CONTENTS contents
    lower = 0
    for num in range(lower, NUM_OF_CONTENTS + 1):
        icn_protocol.create_content("content_" + str(num), "test/test" + str(num), "This is content number " + str(num))

    icn_protocol.start()

    if len(sys.argv) > 1:
        if sys.argv[1] == "search":
            time.sleep(3)
            lower = 0
            for num in range(lower, NUM_OF_CONTENTS + 1):
                icn_protocol.search_content(icn_protocol.local_address, "/" + sys.argv[2] + "/test/test" + str(num))
                time.sleep(1)
    try:
        while True:
            time.sleep(1)
    except (KeyboardInterrupt, Exception):
        icn_protocol.stop()
    finally:
        pass
