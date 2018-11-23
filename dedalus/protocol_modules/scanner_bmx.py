# -*- coding: utf-8 -*-
import json
from logging import getLogger
from os import path, makedirs, listdir

from config import *
from ext.sh import bmx7, killall, sudo, SignalException_SIGKILL, ErrorReturnCode_1
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

__author__ = 'Georgia Dimaki'
__email__ = 'ginadimaki@gmail.com'

_LOG = getLogger(__name__)
_DLOG = getLogger('dedalus_logger')

mn_sudo = sudo.bake("-S", _in=S_SUDO)


# TODO: add get paths and get neighbors functionality
# TODO: add documentation (we should review the documentation of all methods)
class BMXNode(object):
    """BMX node class.

    Represents a node that runs the bmx7 routing protocol. Basically works as a structure
    that keeps track of bmx status and information.
    """

    def __init__(self):
        """Init BMXNode instance.
        """
        self.proto_info = {}  # bmx node status
        self.proto_state = {'interfaces': {},
                            'links': {},
                            'descriptions': {},
                            'originators': {},
                            'network-graph': {}}

    def routing_info(self):
        ps = self.proto_state
        ri = {'if_info': {},
              'neighbour': {}}
        try:
            if DEFAULT_INTEFACE in ps['interfaces']:
                ri['if_info']['interface'] = ps['interfaces'][DEFAULT_INTEFACE]['dev']
                ri['if_info']['ipv6'] = ps['interfaces'][DEFAULT_INTEFACE]['localIp'].split('/')[0]
                # TODO check local vs global
                ri['if_info']['ipv4'] = get_current_ip(DEFAULT_INTEFACE)  # TODO discuss this

            for key in ps['links']:
                # TODO: sometimes some of these might not exist
                nodeId = ps['links'][key]['nodeId']
                ri['neighbour'][key] = {'neighbour': key,
                                        'address': ps['links'][key]['nbLocalIp'],  # TODO nblocal vs local
                                        'cost': None}
                if nodeId in ps['originators']:
                    ri['neighbour'][key]['cost'] = ps['originators'][nodeId]['metric'] # TODO: fix this
        except KeyError as e:
                print(e.message)

        return ri

    def neighbors(self):
        """returns the neighbours list

        :rtype: list
        """
        return self.proto_state['links']


class Scanner(object):
    """BMXScanner class.

    The module that scans the bmx7 protocol to retrieve information about its state.
    """

    def __init__(self):
        """Init BabelScanner instance.
        """
        self.json_path = '/var/run/bmx7/json/'
        self.node = BMXNode()
        self.process = None

        self.logs_path = path.abspath(path.join(path.dirname(__file__), '..', 'Log/Routing/'))
        if not path.exists(self.logs_path):
            makedirs(self.logs_path)
        self.stop()
        self.start()

    def start(self):
        try:
            log_file = open(self.logs_path + '/bmx7.log', "a")
            with mn_sudo:
                # TODO: What if the json plugin is not there?
                self.process = bmx7('plugin=bmx7_json.so', 'dev=%s' % DEFAULT_INTEFACE, 'debug=0', _out=log_file,
                                    _bg=True)
        except ErrorReturnCode_1:
            return 'a bmx7 instance was already running in this system'

    @staticmethod
    def stop():
        try:
            with mn_sudo:
                killall('bmx7')
        except SignalException_SIGKILL:
            return 'bmx7 daemon killed!'
        except ErrorReturnCode_1:
            return 'no running bmx7 instance found'

    def get_routing_info(self):
        self._dump()
        return self.node.routing_info()

    def get_current_interface(self):
        try:
            nint = self.get_routing_info()['interfaces']
        except (TypeError, KeyError):
            nint = None

        return nint

    @staticmethod
    def _read_json(filename):

        if not path.isfile(filename) or not (path.getsize(filename) > 0):
            return None

        with open(filename) as json_file:
            json_item = json.load(json_file)
            return json_item

    def _dump(self):
        json_files = ['interfaces', 'links']
        dirs = ['netjson', 'originators', 'descriptions']

        # read status
        json_item = self._read_json(self.json_path + 'status')
        if json_item:
            self.node.proto_info = json_item['status']

        # read network graph
        json_item = self._read_json(self.json_path + 'netjson/network-graph.json')
        if json_item:
            self.node.proto_state['network-graph'] = json_item

        # read interfaces
        json_item = self._read_json(self.json_path + 'interfaces')
        if json_item:
            for iface in json_item['interfaces']:
                try:
                    self.node.proto_state['interfaces'][iface['dev']] = iface
                except KeyError:
                    continue

        # read links
        json_item = self._read_json(self.json_path + 'links')
        if json_item:
            for link in json_item['links']:
                try:
                    self.node.proto_state['links'][link['shortId']] = link
                except KeyError:
                    continue

        # read originators and descriptions
        for d in ['originators', 'descriptions']:
            d_path = self.json_path + d
            if path.exists(d_path):
                for f in listdir(d_path):
                    json_item = self._read_json(d_path + '/' + f)
                    if json_item:
                        self.node.proto_state[d][f] = json_item

        return self.node.proto_state


if __name__ == "__main__":
    # doctest.testmod()
    pass
