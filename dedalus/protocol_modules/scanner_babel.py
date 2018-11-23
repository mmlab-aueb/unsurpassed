# -*- coding: utf-8 -*-
import socket
from logging import getLogger, WARNING
from os import path, makedirs

from parse import *

from config import *
from ext.sh import babeld, killall, sudo, SignalException_SIGKILL, ErrorReturnCode_1

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

__author__ = 'Georgia Dimaki'
__email__ = 'ginadimaki@gmail.com'

_LOG = getLogger(__name__)
_DLOG = getLogger('dedalus_logger')
getLogger("parse").setLevel(WARNING)

mn_sudo = sudo.bake("-S", _in=S_SUDO)


class BabelNode(object):
    """Babel node class.

    Represents a node that runs the babel routing protocol.
    """

    def __init__(self):
        """Init BabelNode instance.
        """
        self.proto_info = {}
        self.proto_state = {'if_info': {},
                            'xroute': {},
                            'route': {},
                            'neighbour': {}}

    def routing_info(self):
        ri = {'if_info': {},
              'neighbour': {}}
        try:
            ri['if_info']['ipv4'] = self.proto_state['if_info']['ipv4']
            ri['if_info']['ipv6'] = self.proto_state['if_info']['ipv6']

            ri['if_info']['interface'] = self.proto_state['if_info']['interface']
            for neighbour in self.proto_state['neighbour'].values():
                key = neighbour['neighbour']
                ri['neighbour'][key] = {'neighbour': key,
                                        'address': neighbour['address'],
                                        'cost': neighbour['cost']}
        except KeyError:
            pass
        return ri

    def neighbors(self):
        """returns the neighbours list

        :rtype: list
        """
        return self.proto_state['neighbour']


class Scanner(object):
    """BabelScanner class.

    The module that scans the babel protocol to retrieve information about its state.

    :param ip:          the ip used to establish the TCP connection with babel daemon
    :type ip:           str
    :param port:        the port used to establish the TCP connection with babel daemon
    :type port:         int
    :param buffer_size: the buffer used to receive the babel reply
    :type buffer_size:  int
    """

    def __init__(self, ip='::1', port=33123, buffer_size=1024):
        self.ip = ip
        self.port = port
        self.buffer_size = buffer_size
        self.termination_chars = ['ok', 'no', 'bad']
        self.socket = None
        self.node = BabelNode()
        self.formats = {
            'BABEL': "BABEL {conf_version}\nversion {version}\nhost {host}\nmy-id {id}\nok\n",
            'xroute': "add xroute {xroute} prefix {prefix} from {from} metric {metric}",
            'interface': "add interface {interface} up {isUp} ipv6 {ipv6} ipv4 {ipv4}",
            'neighbour': "add neighbour {neighbour} address {address} if {interface} "
                         "reach {reach} rxcost {rxcost} txcost {txcost} cost {cost}",
            'route': "add route {route} prefix {prefix} from {from} installed {isInstalled} "
                     "id {id} metric {metric} refmetric {refmetric} via {via} if {interface}"
        }
        self._msgs_list = {MSG_FLUSH: {'msg': "flush interface\n", 'func': self._flush},
                           MSG_DUMP_B: {'msg': "dump\n", 'func': self._dump},
                           MSG_MONITOR: {'msg': "monitor\n", 'func': self._monitor},
                           MSG_UNMONITOR: {'msg': "unmonitor\n", 'func': self._unmonitor},
                           }
        self.process = None

        self.logs_path = path.abspath(path.join(path.dirname(__file__), '..', 'Log/Routing/'))
        if not path.exists(self.logs_path):
            makedirs(self.logs_path)
        self.stop()
        self.start()

    def start(self):
        try:
            log_file = open(self.logs_path + '/babeld.log', "a")
            with mn_sudo:
                self.process = babeld(DEFAULT_INTEFACE, '-g', '33123', '-d', '2', _out=log_file, _bg=True)
        except ErrorReturnCode_1:
            return 'a babel instance was already running in this system'

    @staticmethod
    def stop():
        try:
            with mn_sudo:
                killall('babeld')
        except SignalException_SIGKILL:
            return 'babeld daemon killed!'
        except ErrorReturnCode_1:
            return 'no running babel instance found'

    def _connect(self):
        """Method called to establish the TCP connection of the host and the babel configuration interface.

        When connection is established babel sends a message with information about the protocol version.

        :rtype: str
        """
        try:
            self.socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            self.socket.connect((self.ip, self.port))
            ans = self.recvall(self.socket, self.buffer_size, self.termination_chars)
            self.node.proto_info = parse(self.formats['BABEL'], ans).named
            return ans
        except socket.timeout:
            raise

    def _disconnect(self):
        """Method called to terminate the TCP connection.

        :rtype: None
        """
        self.socket.close()

    def get_routing_info(self):
        """Method that queries the babel configuration interface.
           All possible commands are in _msgs_list
        """
        self.run_cmd(MSG_DUMP_B)
        return self.node.routing_info()

    def get_current_interface(self):
        try:
            nint = self.get_routing_info()['if_info']['interface']
        except (TypeError, KeyError):
            nint = None
        return nint

    def run_cmd(self, msg_code):
        to_return = 'empty'
        if msg_code not in self._msgs_list:
            return None
        try:
            self._connect()
            self.socket.send(self._msgs_list[msg_code]['msg'])
            ans = self.recvall(self.socket, self.buffer_size, self.termination_chars)
            func = self._msgs_list[msg_code]['func']
            to_return = func(ans)
        except socket.error as err:
            return "error while querying babel: %s" % err
        finally:
            self._disconnect()
            return to_return

    def _dump(self, ans):
        """Method called on dump command

        :param ans: the answer to dump command
        :type ans: str

        :rtype: dict
        """
        if not ans:
            return None
        try:
            for line in ans.split('\n'):
                if line in self.termination_chars:
                    break
                elif 'interface' in line:
                    self.node.proto_state['if_info'] = parse(self.formats['interface'], line).named
                elif 'add' in line:  # TODO: more will be needed
                    format_kind = line.split(' ')[1]  # the token after 'add'
                    res = parse(self.formats[format_kind], line).named
                    key = res[format_kind]
                    self.node.proto_state[format_kind][key] = res
        except (AttributeError, KeyError, IndexError) as err:
            _LOG.debug("A line reported from Babel could not be parsed.")
            _LOG.debug(err)

        return self.node.proto_state

    def _monitor(self, ans):
        """Method called on monitor command. not used yet
        """
        pass

    def _unmonitor(self, ans):
        """Method called on unmonitor command. not used yet
        """
        pass

    def _flush(self, ans):
        """Method called on flush command. not used yet.
        """
        pass

    def get_node_info(self):
        """Method that returns the babel node.

        :rtype: BabelNode
        """
        return self.node

    @staticmethod
    def recvall(s, buffer_size, termination_chars=None):
        """Method called to receive babel's answer.

        .. note::

           if there are no termination characters then we read once and return,
           if there are we read until we stumble into one.


        :param s: the socket
        :type s:  Socket
        :param buffer_size:    the size of the buffer used
        :type buffer_size:     int
        :param termination_chars:   characters that indicate the termination of the answer
        :type termination_chars:    list of str

        :rtype: str
        """
        # TODO: this function makes me feel uncomfortable, keep an eye on it
        ans = ''
        while True:
            try:
                data = s.recv(buffer_size)
            except socket.error:
                return None
            if data:
                ans += data
            if termination_chars:
                for term in termination_chars:
                    if term in data:
                        return ans
            else:
                break
        return ans


if __name__ == "__main__":
    # doctest.testmod()
    pass
