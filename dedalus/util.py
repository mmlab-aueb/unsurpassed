# -*- coding: utf-8 -*-
import base64
import json
import binascii
import socket
import psutil
import os
from parse import *
from hashlib import sha256
from contextlib import contextmanager
from netifaces import interfaces, ifaddresses, AF_INET
from ext.sh import ip

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


def socketid2hex(sid):
    """Returns printable hex representation of a socket id.
    """
    ret = ''.join("%02X" % ord(c) for c in sid)
    return ret


def split_address(msg):
    """Function to split return Id and message received by ROUTER socket.

    Returns 2-tuple with return Id and remaining message parts.
    Empty frames after the Id are stripped.
    """
    ret_ids = []
    for i, p in enumerate(msg):
        if p:
            ret_ids.append(p)
        else:
            break
    return ret_ids, msg[i + 1:]


def hash_b64(s):
    """
    Returns the base 64 hash of `s`
    """
    hasher = sha256(s)
    result = base64.b64encode(hasher.digest())[:-1]
    return result


def to_json(d):
    """
    Serializes an object into a json string
    """
    return json.dumps(d, sort_keys=True)


def from_json(json_str):
    """
    Returns an object from a json string
    """
    if not json_str: return None
    return json.loads(json_str)


def bytes_to_hexstring(raw_bytes):
    """
    Returns a hexadecimal representation of a bytearray
    """
    hex_data = binascii.hexlify(raw_bytes)
    text_string = hex_data.decode('utf-8')
    return text_string


# TODO move also to client side
def hexstring_to_bytes(hexstring):
    """
    Converts a hex encoded string to a bytearray
    """
    try:
        raw_bytes = binascii.unhexlify(hexstring.encode('utf-8'))
    except TypeError:
        return None
    return raw_bytes


def get_ip_addresses(family=socket.AF_INET):
    """
    Returns 2-tuple with interface address.
    """
    for interface, snics in psutil.net_if_addrs().items():
        for snic in snics:
            if snic.family == family:
                yield (interface, snic.address)


def get_current_ip(nint=None):
    """
    Will return the current ip address for the given interface.

    If no interface is given the wireless interface will be chosen.

    .. note::

           If the wireless interface name does not start with `w` and
           no explicit interface is given this function will return the
           ip of the first available interface.
    """
    try:
        if nint is None:
            nints = interfaces()
            for cur_nint in nints:
                if cur_nint.startswith('w'):
                    nint = cur_nint
                    break
                else:
                    nint = nints[-1]
        inet = ifaddresses(nint)[AF_INET]
        addr = inet[0]['addr']
        return addr
    except KeyError:
        return None


@contextmanager
def suppress_stdout():
    """ Use context management wherever you want to suppress output

    :Example:

    print("This message will get printed.")
    with suppress_stdout():
        print("This wont!")

    :return:
    """
    with open(os.devnull, "w") as devnull:
        old_stdout = sys.stdout
        sys.stdout = devnull
        try:
            yield
        finally:
            sys.stdout = old_stdout


def get_next_hops(interface='dev'):
    out = ip("neighbor")
    out_format = "{ip} dev {interface} lladdr {link_layer_addr} {state}"
    for line in out:
        if interface in line:
            yield parse(out_format, line).named
