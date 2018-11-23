# -*- coding: utf-8 -*-
from multiprocessing import Process
from socket import *
from collections import Counter
from logging import getLogger
from os import path, getpid

import msgpack
import psutil
from scapy.all import *
from scapy.layers.inet import IP

from config import *
from ext.sh import sudo, reboot, ErrorReturnCode_1, ErrorReturnCode_3
from ext.which import which as check_protocol
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

mn_sudo = sudo.bake("-S", _in=S_SUDO)


class NetworkManager(object):
    def __init__(self):
        self.current_routing_protocol = DEFAULT_ROUTING_PROTOCOL
        self.current_ip_address = get_current_ip(DEFAULT_INTEFACE)
        # TODO: this runs before the interface gets an ip
        self.control_ip_address = get_current_ip(CONTROL_INTERFACE)
        self.available_routing_protocols = []
        self.known_routing_protocols = ALL_PROTOCOLS
        self.current_scanner = None
        self.find_available_protocols()
        self.import_scanner_module()
        self.funcs = {MSG_NETRESTART: self.restart_protocol,
                      MSG_SETPROTO: self.change_protocol,
                      MSG_ROUTINGINFO: self.get_routing_dump,
                      MSG_NETSTART: self.start_network,
                      MSG_NETSTOP: self.stop_network,
                      MSG_DTNSTART: self.start_dtn,
                      MSG_DTNRESTART: self.restart_dtn,
                      MSG_DTNSTOP: self.stop_dtn,
                      MSG_CURRENTRPROTO: self.get_current_routing_protocol,
                      MSG_CURRENTDPROTO: self.get_current_dtn_protocol,
                      MSG_SETDTNPROTO: self.change_dtn_protocol,
                      MSG_ICNSTART: self.start_icn,
                      MSG_ICNRESTART: self.restart_icn,
                      MSG_ICNSTOP: self.stop_icn}
        self.dtn_protocol = None
        self.icn_protocol = None

    def find_available_protocols(self):
        for protocol in self.known_routing_protocols:
            exec_path = check_protocol(protocol)
            if exec_path is None:
                continue
            self.available_routing_protocols.append(protocol)

    def import_scanner_module(self):
        if self.current_routing_protocol not in self.available_routing_protocols:
            _LOG.debug('Protocol [%s] does not seem to be installed on this system' % self.current_routing_protocol)
            if len(self.available_routing_protocols):
                self.current_routing_protocol = self.available_routing_protocols[0]
                _LOG.debug('Instead protocol [%s] will be used' % self.current_routing_protocol)
                self.import_scanner_module()
            else:
                _LOG.debug('No available routing protocols found!')
                return

        imported_scanner = getattr(
            __import__('protocol_modules.%s' % PROTOCOL_MODULES[self.current_routing_protocol], fromlist=['Scanner']),
            'Scanner')
        self.current_scanner = imported_scanner()

    def run(self, cmd, arg):
        # TODO: dynamically unpack arguments
        if cmd == MSG_NETRESTART:
            fnc = self.funcs[cmd]
            return fnc()
        elif cmd == MSG_SETPROTO or cmd == MSG_SETDTNPROTO:
            protocol = arg.pop(0)
            fnc = self.funcs[cmd]
            return fnc(protocol)
        elif cmd == MSG_DTNSTOP:
            fnc = self.funcs[cmd]
            return fnc()
        else:
            fnc = self.funcs[cmd]
            return fnc()

    def get_routing_dump(self):
        if self.current_scanner is None:
            return 'no available routing protocol found'
        return self.current_scanner.get_routing_info()

    def stop_network(self):
        if self.current_scanner is None:
            return 'no available routing protocol found'
        self.current_scanner.stop()
        return True

    def start_network(self):
        if self.current_scanner is None:
            return 'no available routing protocol found'
        self.current_scanner.start()
        return True

    def restart_protocol(self):
        if self.current_scanner is None:
            return 'no available routing protocol found'
        self.current_scanner.stop()
        self.current_scanner.start()
        return {'success': True}

    def change_protocol(self, protocol):
        if self.current_scanner is None:
            return {'success': False, 'error': 'no available routing protocol found'}
        if protocol == self.current_routing_protocol:
            return {'success': True}
        self.current_routing_protocol = protocol
        self.current_scanner.stop()
        self.import_scanner_module()
        return {'success': True}

    def get_current_routing_protocol(self):
        return self.current_routing_protocol

    def change_dtn_protocol(self, protocol):
        if self.dtn_protocol is None:
            self.start_dtn()
            return {'success': True}
        if protocol == self.dtn_protocol.protocol:
            return {'success': True}
        # TODO: set correct protocol
        self.restart_dtn()
        return {'success': True}

    def load_dtn_module(self):
        if check_protocol(N_IBR) is not None:
            from protocol_modules.scanner_ibr import Scanner as dtn_scanner
            self.dtn_protocol = dtn_scanner()

    def start_dtn(self):
        self.load_dtn_module()
        if self.dtn_protocol is not None:
            self.dtn_protocol.start()
            return {'success': True}
        return {'success': False}

    def stop_dtn(self):
        if self.dtn_protocol is not None:
            self.dtn_protocol.stop()
            self.dtn_protocol = None
        return {'success': True}

    def restart_dtn(self):
        if self.dtn_protocol is not None:
            self.stop_dtn()
            self.start_dtn()
            return {'success': True}
        else:
            self.start_dtn()
            return {'success': True}

    def get_current_dtn_protocol(self):
        if self.dtn_protocol is not None:
            return self.dtn_protocol.get_routing()
        else:
            return 'off'

    def get_dtn_dump(self):
        if self.dtn_protocol is not None:
            return self.dtn_protocol.get_routing_info()
        else:
            return None

    # Start of icn code
    def load_icn_module(self):
        # if check_protocol(N_CCN) is not None:
        from protocol_modules.scanner_ccn import Scanner as icn_scanner
        self.icn_protocol = icn_scanner()
        return {'success': True}

    def start_icn(self):
        self.load_icn_module()
        if self.icn_protocol:
            return self.icn_protocol.start()
        else:
            return {'success': False}

    def stop_icn(self):
        if self.icn_protocol is not None:
            res = self.icn_protocol.stop()
            self.icn_protocol = None
        return {'success': True}

    def restart_icn(self):
        if self.icn_protocol is not None:
            return self.icn_protocol.restart_server()

    def get_ccn_dump(self):
        if self.icn_protocol is not None:
            return self.icn_protocol.get_routing_info()
        else:
            return None

    # End of icn code

    def shutdown(self):
        _LOG.debug('Closing all routing protocols!')
        if self.current_scanner is None:
            return
        self.current_scanner.stop()


class HWTraffic(object):
    # TODO: document this class
    # TODO: automatically unpack arguments
    # TODO: execute long running functions on a different process
    def __init__(self):
        self.iperf_server = None
        self.iperf_client = None
        self.client_result = ''
        self.server_result = ''
        self._worker_funcs = {MSG_MEASUREBANDWIDTH: self.measure_throughput,
                              MSG_TXPOWER: self.change_txpower,
                              MSG_DTNFILE: self.send_dtn_file,
                              MSG_PINGTEST: self.ping_test,
                              MSG_ICNFILE: self.search_icn_file}
        self.logs_path = path.abspath(path.join(path.dirname(__file__), 'Log/Routing/'))
        self.throughput_server = None
        self.open_throughput_server()
        self.dtn_protocol = None
        self.load_dtn_module()
        self.icn_protocol = None

    # TODO: review and improve this
    def run(self, cmd, arg):
        ret = None
        if cmd == MSG_MEASUREBANDWIDTH or cmd == MSG_PINGTEST:
            bind_address = '127.0.0.1'
            try:
                data = msgpack.unpackb(arg.pop(0))
                bind_address = data['destination']
            except KeyError:
                pass
            finally:
                fnc = self._worker_funcs[cmd]
                return fnc(bind_address)
        elif cmd == MSG_TXPOWER:
            txpower = arg
            fnc = self._worker_funcs[cmd]
            ret = fnc(txpower)
        elif cmd == MSG_DTNFILE:
            data = msgpack.unpackb(arg.pop(0))
            fnc = self._worker_funcs[cmd]
            ret = fnc(data['destination'])
        elif cmd == MSG_ICNFILE:
            data = msgpack.unpackb(arg.pop(0), encoding='utf-8')
            fnc = self._worker_funcs[cmd]
            ret = fnc(data['destination'])

        return ret

    def measure_throughput(self, host, port=50042, period=10):
        def throughput_format(num):
            for x in ['', 'k', 'M', 'G', 'T']:
                if num < 1024.:
                    return "%3.1f %sbps" % (num, x)
                num /= 1024.
            return "%3.1f Pbps" % num
        out = {}
        count = 0
        testdata = 'x' * (THROUGHPUT_BUFSIZE - 1) + '\n'
        t1 = time.time()
        s = socket.socket(AF_INET, SOCK_STREAM)
        t2 = time.time()
        try:
            s.settimeout(1)
            s.connect((host, port))
            s.settimeout(None)
            t3 = time.time()
            while True:
                s.send(testdata)
                count = count + 1
                if time.time() > t1 + period:
                    break
            s.shutdown(1)  # Send EOF
            t4 = time.time()
            data = s.recv(THROUGHPUT_BUFSIZE)
            t5 = time.time()
            out = {b'from': bytes(get_current_ip(DEFAULT_INTEFACE)),
                    b'to': bytes(host),
                    'route': self.traceroute_test(host),
                    b'throughput': bytes(throughput_format(round((THROUGHPUT_BUFSIZE * count * 8) / (t5 - t1), 3)))}
        except socket.error as err:
            out[b'error'] = bytes(err)
        return out

    @staticmethod
    def throughput_listener(port=50042):
        s = socket.socket(AF_INET, SOCK_STREAM)
        s.bind(('', port))
        s.listen(1)
        _LOG.debug('Throughput server ready, pid: %s' % getpid())
        while 1:
            conn, (host, remoteport) = s.accept()
            while 1:
                data = conn.recv(THROUGHPUT_BUFSIZE)
                if not data:
                    break
                del data
            conn.send('OK\n')
            conn.close()
            _LOG.debug('Done with %s port %s' % (host, remoteport))

    def open_throughput_server(self):
        # log_file = open(self.logs_path + '/iperf.log', "a")
        self.throughput_server = Process(target=self.throughput_listener,
                                         name="dedalus_throughput_server")
        self.throughput_server.start()

    def kill_throughput_server(self):
        try:
            self.throughput_server.terminate()
        except AttributeError:
            return

    # TODO: use format instead of % everywhere
    # TODO: add a command for this
    @staticmethod
    def ping_test(self, addr, n=10):
        _LOG.debug('Testing {0} pings to address {1}.\n'.format(n, addr))
        minimum = float('Inf')
        maximum = float('Inf')
        average = float('Inf')
        lost = float('Inf')

        count_flag = '-c'
        if 'win' in sys.platform:
            count_flag = '-n'

        try:
            ping = subprocess.Popen(['ping', addr, count_flag, str(n)],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    shell=False)
            (out, err) = ping.communicate()
            out = out.decode('utf-8')
            if out and ('win' in sys.platform):
                try:
                    # Windows-specific output parsing
                    minimum = int(re.findall(r'Minimum = (\d+)', out)[0])
                    maximum = int(re.findall(r'Maximum = (\d+)', out)[0])
                    average = int(re.findall(r'Average = (\d+)', out)[0])
                    lost = int(re.findall(r'Lost = (\d+)', out)[0])
                # TODO: what could go wrong here
                except IndexError:
                    return 'No data could be extracted'
            elif out:
                try:
                    # Linux-specific output parsing
                    summary = re.findall(r'rtt min/avg/max/mdev = (\S+)', out)[0]
                    (minimum, average, maximum, mdev) = (float(x) for x in summary.split('/'))
                    lost = int(re.findall(r'(\d+)% packet loss', out)[0])
                except IndexError:
                    return 'No data could be extracted'
            else:
                return 'No ping supported by the system'

        except subprocess.CalledProcessError:
            return 'No ping supported by the system'

        return {'from': get_current_ip(DEFAULT_INTEFACE),
                'to': addr,
                'minimum': minimum,
                'maximum': maximum,
                'average': average,
                'lost': lost}

    @staticmethod
    def traceroute_test(addr):
        _LOG.debug('Testing traceroute to address {0}.\n'.format(addr))
        udp_flag = '-U'
        no_domain_name_flag = '-n'
        probes_flag = '-q 1'

        try:
            traceroute = subprocess.Popen(['traceroute', addr, udp_flag, no_domain_name_flag, probes_flag],
                                          stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE,
                                          shell=False)
            # TODO: Add timeout
            (out, err) = traceroute.communicate()
            if out:
                out = out.splitlines()
                del out[0]
        except (subprocess.CalledProcessError, OSError):
            return 'No traceroute supported by the system'
        return out

    @staticmethod
    def change_txpower(txpower="31", iface=DEFAULT_INTEFACE):
        # TODO: maybe return the current txpower level
        try:
            mn_sudo.iwconfig(iface, "txpower", txpower)
            return {'success': True}
        except (ErrorReturnCode_1, ErrorReturnCode_3):
            return {'success': False}

    # TODO: dtn should load once
    def load_dtn_module(self):
        if check_protocol(N_IBR) is not None:
            from protocol_modules.scanner_ibr import Scanner as dtn_scanner
            self.dtn_protocol = dtn_scanner()

    # TODO: dtn should load once
    def load_icn_module(self):
        from protocol_modules.scanner_ccn import Scanner as icn_scanner
        self.icn_protocol = icn_scanner()

    def send_dtn_file(self, destination):
        # TODO: this return value should be a dict
        res = 'dtn functionality is not available'
        if self.dtn_protocol is not None:
            res = self.dtn_protocol.send_files(destination)
        return res

    # icn code
    def search_icn_file(self, node):
        self.load_icn_module()
        self.icn_protocol.start()
        res = 'icn functionality is not available'
        if self.icn_protocol is not None:
            res = self.icn_protocol.search(node)
        return res

    def shutdown(self):
        self.kill_throughput_server()
        return


class HWScanner(object):
    def __init__(self):
        self._worker_funcs = {MSG_ECHO: self.echo,
                              MSG_CPUPERCENT: self.cpu_percent,
                              MSG_CPUTIMES: self.cpu_times,
                              MSG_CPUTIMESPERCENT: self.cpu_times_percent,
                              MSG_CPUCOUNT: self.cpu_count,
                              MSG_CPUSTATS: self.cpu_stats,
                              MSG_NETIOCOUNTERS: self.net_io_counters,
                              MSG_NETCONNECTIONS: self.net_connections,
                              MSG_NETIFADDRS: self.net_if_addrs,
                              MSG_NETIFSTATS: self.net_if_stats,
                              MSG_BOOTTIME: self.boot_time,
                              MSG_MEMORYINFO: self.memory_info,
                              MSG_MEMORYPERCENT: self.memory_percent,
                              MSG_CONNECTIONS: self.connections,
                              MSG_DUMP: self.dump,
                              MSG_REBOOT_HOST: self.restart_host
                              }

    def run(self, cmd, args):
        data = None
        if args:
            data = msgpack.unpackb(args)
        if cmd in self._worker_funcs:
            fnc = self._worker_funcs[cmd]
            if data:
                return fnc(*data)
            return fnc()
        return None

    def get_interface(self):
        """Returns the current interface used by the routing protocol.
        """
        return DEFAULT_INTEFACE

    @staticmethod
    def cpu_percent(interval=1, percpu=True):
        """Return a float representing the current system-wide CPU utilization as a percentage. When interval is > 0.0 
        compares system CPU times elapsed before and after the interval (blocking). When interval is 0.0 or None 
        compares system CPU times elapsed since last call or module import, returning immediately. That means the first 
        time this is called it will return a meaningless 0.0 value which you are supposed to ignore. In this case it is 
        recommended for accuracy that this function be called with at least 0.1 seconds between calls. When percpu is 
        True returns a list of floats representing the utilization as a percentage for each CPU. First element of the 
        list refers to first CPU, second element to second CPU and so on. The order of the list is consistent across 
        calls.
        """
        return psutil.cpu_percent(interval=interval, percpu=percpu)

    @staticmethod
    def cpu_times():
        """Return system CPU times as a named tuple. Every attribute represents the seconds the CPU has spent in the 
        given mode. The attributes availability varies depending on the platform.
        """
        return psutil.cpu_times()

    @staticmethod
    def cpu_times_percent(interval=1, percpu=False):
        """Same as cpu_percent() but provides utilization percentages for each specific CPU time as is returned by 
        psutil.cpu_times(percpu=True). interval and percpu arguments have the same meaning as in cpu_percent().
        """
        return psutil.cpu_times_percent(interval=interval, percpu=percpu)

    @staticmethod
    def cpu_count(logical=False):
        """Return the number of logical CPUs in the system (same as os.cpu_count() in Python 3.4). If logical is False 
        return the number of physical cores only (hyper thread CPUs are excluded). Return None if undetermined.
        """
        return psutil.cpu_count(logical=logical)

    @staticmethod
    def cpu_stats():
        """Return various CPU statistics as a named tuple
        """
        return psutil.cpu_stats()

    @staticmethod
    def cpu_freq():
        """Return CPU frequency as a nameduple including current, min and max frequencies expressed in Mhz. On Linux 
        current frequency reports the real-time value, on all other platforms it represents the nominal “fixed” value. 
        If percpu is True and the system supports per-cpu frequency retrieval (Linux only) a list of frequencies is 
        returned for each CPU, if not, a list with a single element is returned. If min and max cannot be determined 
        they are set to 0.
        """
        return psutil.cpu_freq()

    @staticmethod
    def virtual_memory():
        """Return statistics about system memory usage as a named tuple including the following fields, expressed in bytes.
        """
        return psutil.virtual_memory()

    @staticmethod
    def swap_memory():
        """Return system swap memory statistics as a named tuple
        """
        return psutil.swap_memory()

    @staticmethod
    def disk_partitions():
        """Return all mounted disk partitions as a list of named tuples including device, mount point and filesystem 
        type, similarly to “df” command on UNIX. If all parameter is False it tries to distinguish and return physical 
        devices only (e.g. hard disks, cd-rom drives, USB keys) and ignore all others (e.g. memory partitions such as 
        /dev/shm). Note that this may not be fully reliable on all systems (e.g. on BSD this parameter is ignored). 
        Named tuple’s fstype field is a string which varies depending on the platform. On Linux it can be one of the 
        values found in /proc/filesystems (e.g. 'ext3' for an ext3 hard drive o 'iso9660' for the CD-ROM drive). On 
        Windows it is determined via GetDriveType and can be either "removable", "fixed", "remote", "cdrom", "unmounted" 
        or "ramdisk". On OSX and BSD it is retrieved via getfsstat(2).
        """
        return psutil.disk_partitions()

    @staticmethod
    def disk_usage(directory='/'):
        """Return disk usage statistics about the given path as a named tuple including total, used and free space 
        expressed in bytes, plus the percentage usage. OSError is raised if path does not exist. 
        """
        return psutil.disk_usage(directory)

    @staticmethod
    def disk_io_counters(perdisk=True):
        """Return system-wide disk I/O statistics as a named tuple
        """
        return psutil.disk_io_counters(perdisk=perdisk)

    @staticmethod
    def net_io_counters(pernic=True):
        """Return system-wide network I/O statistics as a named tuple
        """
        return psutil.net_io_counters(pernic=pernic)

    @staticmethod
    def net_connections():
        """Return system-wide socket connections as a list of named tuples.
        """
        return psutil.net_connections()

    @staticmethod
    def net_if_addrs():
        """Return the addresses associated to each NIC (network interface card) installed on the system as a dictionary 
        whose keys are the NIC names and value is a list of named tuples for each address assigned to the NIC.
        """
        return psutil.net_if_addrs()

    @staticmethod
    def net_if_stats():
        """Return information about each NIC (network interface card) installed on the system as a dictionary whose keys 
        are the NIC names and value is a named tuple.
        """
        return psutil.net_if_stats()

    @staticmethod
    def sensors_temperatures(fahrenheit=False):
        """Return hardware temperatures. Each entry is a named tuple representing a certain hardware temperature sensor 
        (it may be a CPU, an hard disk or something else, depending on the OS and its configuration). All temperatures 
        are expressed in celsius unless fahrenheit is set to True. If sensors are not supported by the OS an empty dict 
        is returned.
        """
        return psutil.sensors_temperatures(fahrenheit=fahrenheit)

    @staticmethod
    def sensors_fans():
        """Return hardware fans speed. Each entry is a named tuple representing a certain hardware sensor fan. Fan speed 
        is expressed in RPM (rounds per minute). If sensors are not supported by the OS an empty dict is returned.
        """
        return psutil.sensors_fans()

    @staticmethod
    def sensors_battery():
        """Return battery status information as a named tuple including the following values. If no battery is installed 
        or metrics can’t be determined None is returned.
        """
        return psutil.sensors_battery()

    @staticmethod
    def users():
        """Return users currently connected on the system as a list of named tuples.
        """
        return psutil.users()

    @staticmethod
    def boot_time():
        """Return the system boot time expressed in seconds since the epoch.
        """
        return psutil.boot_time()

    @staticmethod
    def pids():
        """Return a list of current running PIDs. To iterate over all processes and avoid race conditions process_iter() 
        should be preferred.
        """
        return psutil.pids()

    @staticmethod
    def pid_exists(pid):
        """Check whether the given PID exists in the current process list. This is faster than doing pid in 
        psutil.pids() and should be preferred.
        """
        return psutil.pid_exists(pid)

    @staticmethod
    def pid():
        """The process PID. This is the only (read-only) attribute of the class.
        """
        return psutil.Process().pid()

    @staticmethod
    def ppid():
        """The process parent PID. On Windows the return value is cached after first call. Not on POSIX because ppid may 
        change if process becomes a zombie.
        """
        return psutil.Process().ppid()

    @staticmethod
    def name():
        """The process name. On Windows the return value is cached after first call. Not on POSIX because the process 
        name may change.
        """
        return psutil.Process().name()

    @staticmethod
    def exe():
        """The process executable as an absolute path. On some systems this may also be an empty string. The return 
        value is cached after first call.
        """
        return psutil.Process().exe()

    @staticmethod
    def cmdline():
        """The command line this process has been called with as a list of strings. The return value is not cached 
        because the cmdline of a process may change.
        """
        return psutil.Process().cmdline()

    @staticmethod
    def environ():
        """The environment variables of the process as a dict. Note: this might not reflect changes made after the 
        process started.
        """
        return psutil.Process().environ()

    @staticmethod
    def create_time():
        """The process creation time as a floating point number expressed in seconds since the epoch, in UTC. The return 
        value is cached after first call.
        """
        return psutil.Process().create_time()

    @staticmethod
    def status():
        """The current process status as a string.
        """
        return psutil.Process().status()

    @staticmethod
    def cwd():
        """The process current working directory as an absolute path.
        """
        return psutil.Process().cwd()

    @staticmethod
    def username():
        """The name of the user that owns the process. On UNIX this is calculated by using real process uid.
        """
        return psutil.Process().username()

    @staticmethod
    def uids():
        """The real, effective and saved user ids of this process as a named tuple. This is the same as os.getresuid() 
        but can be used for any process PID.
        """
        return psutil.Process().uids()

    @staticmethod
    def gids():
        """The real, effective and saved group ids of this process as a named tuple. This is the same as os.getresgid() 
        but can be used for any process PID.
        """
        return psutil.Process().gids()

    @staticmethod
    def terminal():
        """The terminal associated with this process, if any, else None. This is similar to “tty” command but can be 
        used for any process PID.
        """
        return psutil.Process().terminal()

    @staticmethod
    def nice(value=None):
        """Get or set process niceness (priority). On UNIX this is a number which usually goes from -20 to 20. The 
        higher the nice value, the lower the priority of the process.
        """
        return psutil.Process().nice(value)

    @staticmethod
    def io_counters():
        """Return process I/O statistics as a named tuple.
        """
        return psutil.Process().io_counters()

    @staticmethod
    def num_ctx_switches():
        """The number voluntary and involuntary context switches performed by this process (cumulative).
        """
        return psutil.Process().num_ctx_switches()

    @staticmethod
    def num_fds():
        """The number of file descriptors currently opened by this process (non cumulative).
        """
        return psutil.Process().num_fds()

    @staticmethod
    def num_handles():
        """The number of handles currently used by this process (non cumulative).
        """
        return psutil.Process().num_handles()

    @staticmethod
    def num_threads():
        """The number of threads currently used by this process (non cumulative).
        """
        return psutil.Process().num_threads()

    @staticmethod
    def threads():
        """Return threads opened by process as a list of named tuples including thread id and thread CPU times (user/system).
        """
        return psutil.Process().threads()

    @staticmethod
    def process_cpu_times(pid):
        """Return a (user, system, children_user, children_system) named tuple representing the accumulated process 
        time, in seconds (see explanation). On Windows and OSX only user and system are filled, the others are set to 0. 
        This is similar to os.times() but can be used for any process PID.
        """
        return psutil.Process(pid).cpu_times

    @staticmethod
    def process_cpu_percent(pid, interval=None):
        """Return a float representing the process CPU utilization as a percentage which can also be > 100.0 in case of 
        a process running multiple threads on different CPUs. When interval is > 0.0 compares process times to system 
        CPU times elapsed before and after the interval (blocking). When interval is 0.0 or None compares process times 
        to system CPU times elapsed since last call, returning immediately. That means the first time this is called it 
        will return a meaningless 0.0 value which you are supposed to ignore. In this case is recommended for accuracy 
        that this function be called a second time with at least 0.1 seconds between calls.
        """
        return psutil.Process(pid).cpu_percent(interval=interval)

    @staticmethod
    def process_cpu_num(pid):
        """Return what CPU this process is currently running on. The returned number should be <= psutil.cpu_count(). It 
        may be used in conjunction with psutil.cpu_percent(percpu=True) to observe the system workload distributed 
        across multiple CPUs.
        """
        return psutil.Process(pid).cpu_num()

    @staticmethod
    def memory_info():
        """Return a named tuple with variable fields depending on the platform representing memory information about the 
        process. The “portable” fields available on all platforms are rss and vms. All numbers are expressed in bytes.
        """
        return psutil.Process().memory_info()

    @staticmethod
    def memory_percent(memtype="rss"):
        """Compare process memory to total physical system memory and calculate process memory utilization as a 
        percentage. memtype argument is a string that dictates what type of process memory you want to compare against.
        """
        return psutil.Process().memory_percent(memtype=memtype)

    @staticmethod
    def memory_maps(grouped=True):
        """Return process’s mapped memory regions as a list of named tuples whose fields are variable depending on the 
        platform. This method is useful to obtain a detailed representation of process memory usage as explained here 
        (the most important value is “private” memory). If grouped is True the mapped regions with the same path are 
        grouped together and the different memory fields are summed. If grouped is False each mapped region is shown as 
        a single entity and the named tuple will also include the mapped region’s address space (addr) and permission 
        set (perms).
        """
        return psutil.Process().memory_maps(grouped=grouped)

    @staticmethod
    def children(recursive=False):
        """Return the children of this process as a list of Process objects, preemptively checking whether PID has been 
        reused. If recursive is True return all the parent descendants.
        """
        return psutil.Process().children(recursive=recursive)

    @staticmethod
    def open_files():
        """Return regular files opened by process as a list of named tuples.
        """
        return psutil.Process().open_files()

    @staticmethod
    def connections(kind="inet"):
        """Return socket connections opened by process as a list of named tuples.
        """
        return psutil.Process().connections(kind=kind)

    @staticmethod
    def is_running(pid):
        """Return whether the current process is running in the current process list. This is reliable also in case the 
        process is gone and its PID reused by another process.
        """
        return psutil.Process(pid).is_running()

    @staticmethod
    def terminate_process(pid):
        """Terminate the process with SIGTERM signal preemptively checking whether PID has been reused.
        """
        return psutil.Process(pid).terminate()

    @staticmethod
    def wait_process(pid, timeout=None):
        """Wait for process termination and if the process is a children of the current one also return the exit code, 
        else None. On Windows there’s no such limitation (exit code is always returned). If the process is already 
        terminated immediately return None instead of raising NoSuchProcess. If timeout is specified and process is 
        still alive raise TimeoutExpired exception. It can also be used in a non-blocking fashion by specifying 
        timeout=0 in which case it will either return immediately or raise TimeoutExpired.
        """
        return psutil.Process(pid).wait(timeout=timeout)

    @staticmethod
    def kill_process(pid):
        """Kill the current process by using SIGKILL signal preemptively checking whether PID has been reused.
        """
        return psutil.Process(pid).kill()

    @staticmethod
    def resume_process(pid):
        """Resume process execution with SIGCONT signal preemptively checking whether PID has been reused.
        """
        return psutil.Process(pid).resume()

    @staticmethod
    def suspend_process(pid):
        """Suspend process execution with SIGSTOP signal preemptively checking whether PID has been reused.
        """
        return psutil.Process(pid).suspend()

    @staticmethod
    def echo(echo_message):
        """Return echo message
        """
        return echo_message

    def dump(self):
        """Return system info in bulk.
        """
        return {'net_io_counters': self.net_io_counters(),
                'memory_percent': self.memory_percent(),
                'temperatures': self.sensors_temperatures(),
                'battery': self.sensors_battery(),
                'cpu_percent': self.cpu_percent(),
                'boot_time': self.boot_time()}

    @staticmethod
    def traffic_per_connection(sample_interval=1, hosts_limit=10):
        try:
            traffic = Counter()
            hosts = {}
            interface = DEFAULT_INTEFACE

            def bandwidth_format(num):
                for x in ['', 'k', 'M', 'G', 'T']:
                    if num < 1024.:
                        return "%3.1f %sB" % (num, x)
                    num /= 1024.
                return "%3.1f PB" % num

            def traffic_monitor_callback(pkt):
                if IP in pkt:
                    pkt = pkt[IP]
                    traffic.update({tuple(sorted(map(atol, (pkt.src, pkt.dst)))): pkt.len})

            sniff(iface=interface, prn=traffic_monitor_callback, store=False,
                  timeout=sample_interval)

            for (h1, h2), total in traffic.most_common(hosts_limit):
                h1, h2 = map(ltoa, (h1, h2))
                for host in (h1, h2):
                    if host not in hosts:
                        try:
                            rhost = socket.gethostbyaddr(host)
                            hosts[host] = rhost[0]
                        except IndexError:
                            hosts[host] = None
                        except socket.herror:
                            hosts[host] = None

                h1 = "%s (%s)" % (hosts[h1], h1) if hosts[h1] is not None else h1
                h2 = "%s (%s)" % (hosts[h2], h2) if hosts[h2] is not None else h2
                yield {'bandwidth': bandwidth_format(float(total) / sample_interval), 'from': h1, 'to': h2}
        except socket.error:
            yield "Traffic information gathering not permitted by host!"

    @staticmethod
    def restart_host():
        # TODO: this does not restart a node
        with mn_sudo:
            reboot('now')

    @staticmethod
    def shutdown():
        _LOG.debug('Closing all hardware scanners!')
