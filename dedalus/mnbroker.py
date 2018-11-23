# -*- coding: utf-8 -*-
from logging import getLogger

import msgpack
import zmq
from zmq.eventloop.ioloop import PeriodicCallback
from zmq.eventloop.zmqstream import ZMQStream

from config import *
from mn_obj import MN_object
from util import split_address, bytes_to_hexstring, hexstring_to_bytes, get_current_ip

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


# TODO: Exception management is needed for all functions, especially the 'socket closed' issue
# TODO: Have a way to contact all workers


class MNBroker(MN_object):
    """The Dedalus broker class.

    The broker routes messages from clients to appropriate nodes/workers based
    on the requested data. It will also allow workers to register to different
    services as well as files.

    This base class defines the overall functionality and the API. Subclasses are
    meant to implement additional features (like logging).

    .. note::

      The workers will *always* be served by the `main_ep` endpoint.

      In a two-endpoint setup clients will be handled via the `opt_ep`
      endpoint.

    :param context:    the context to use for socket creation.
    :type context:     zmq.Context
    :param main_ep:    the primary endpoint for workers and clients.
    :type main_ep:     str
    :param opt_ep:     is an optional 2nd endpoint.
    :type opt_ep:      str
    :param service_q:  the class to be used for the service worker-queue.
    :type service_q:   class
    :param data_q:     the class to be used for the data-queue.
    :type data_q:      class

     :Example:

     context = zmq.Context()
     broker = MNBrokerRunner(context, "tcp://127.0.0.1:5555")
     IOLoop.instance().start()
     broker.shutdown()!

     .. seealso:: :class:`MNWorker`
     .. warnings also:: the broker is expected to be able to serve a few thousand clients, no guarantees yet though
     .. note:: this is by far not a ready product
    """

    # TODO: if a worker is doing a long running task we probably shouldn't keep it in the heartbeat timer list
    # TODO: add two brokers using b-star
    # TODO: implement the titanic scheme for added reliability in case of disjoint req/rep

    def __init__(self, context, main_ep, opt_ep=None, service_q=None, data_q=None):
        """Init MNBroker instance.
        """
        if service_q is None:
            self.service_q = ServiceQueue
        else:
            self.service_q = service_q
        if data_q is None:
            self.data_q = ServiceQueue
        else:
            self.data_q = data_q
        socket = context.socket(zmq.ROUTER)
        socket.bind(main_ep)
        socket.setsockopt(zmq.IDENTITY, b'BROKER')
        self.main_stream = ZMQStream(socket)
        self.main_stream.on_recv(self.on_message)
        if opt_ep:
            socket = context.socket(zmq.ROUTER)
            socket.bind(opt_ep)
            self.client_stream = ZMQStream(socket)
            self.client_stream.on_recv(self.on_message)
        else:
            self.client_stream = self.main_stream
        # TODO: merge worker_tracker and info
        self._workers = {}
        self._workers_info = {}
        self._services = {}  # TODO: each worker must have his own request queue
        self._worker_cmds = {MSG_READY: self.on_ready,
                             MSG_REPLY: self.on_reply,
                             MSG_HEARTBEAT: self.on_heartbeat,
                             MSG_DISCONNECT: self.on_disconnect,
                             }
        self._local_cmds = {MSG_WINFO: self.get_workers_info,
                            }
        self.hb_check_timer = PeriodicCallback(self.on_timer, HB_INTERVAL)
        self.hb_check_timer.start()

        self.hb_get_winfo = PeriodicCallback(self.collect_workers_info, HB_INTERVAL)
        self.hb_get_winfo.start()

        self.register_worker_info(self.main_stream.getsockopt(zmq.IDENTITY))  # register this instance
        _LOG.info("Broker initialized and can be found at '%s'" % main_ep)
        return

    def register_worker(self, wid, service, worker_type, address, protocols):
        """Register the worker id and add it to the given service.

        Does nothing if worker is already known.

        :param wid:         the worker id.
        :type wid:          str
        :param service:     the service name.
        :type service:      str
        :param worker_type: the type of the worker.
        :type worker_type:  str
        :param address:     the ipv4 or upv6 address of the worker.
        :type address:      str
        :param protocols:   the routing protocols reported by the worker.
        :type protocols:    str

        :rtype: None
        """
        if wid in self._workers:
            return
        self._workers[wid] = WorkerTracker(WORKER_PROTO, wid, service, self.main_stream)
        # If service exists then add this worker to its workers queue, if not create it.
        if service in self._services:
            wq, wr = self._services[service]
            wq.put(wid)
        else:
            q = self.service_q()
            q.put(wid)
            self._services[service] = (q, [])
        self.register_worker_info(wid, service, WORKER_ONLINE_STATUS, worker_type, address, protocols)
        _LOG.info("New worker of type: '%s' registered with id: '%s', for service: '%s' and can be found at '%s'." % (
            worker_type, bytes_to_hexstring(wid), service, address))
        return

    def unregister_worker(self, wid):
        """Unregister the worker with the given id and stop all timers for the worker.

        If the worker id is not registered, nothing happens.

        :param wid:    the worker id.
        :type wid:     str

        :rtype: None
        """
        try:
            wtracker = self._workers[wid]
        except KeyError:
            # not registered, ignore
            return
        # remove this workers' data from the map
        wtracker.shutdown()
        service = wtracker.service
        if service in self._services:
            wq, wr = self._services[service]
            wq.remove(wid)
        del self._workers[wid]
        self.reset_node_info(wid)
        _LOG.info("Worker with id: '%s' was removed from the pool." % bytes_to_hexstring(wid))
        return

    def disconnect(self, wid):
        """Send disconnect command and unregister worker.

        If the worker id is not registered, nothing happens.

        :param wid:    the worker id.
        :type wid:     str

        :rtype: None
        """
        try:
            wtracker = self._workers[wid]
        except KeyError:
            # not registered, ignore
            return
        _LOG.info("Requesting from worker with id: '%s' to disconnect." % bytes_to_hexstring(wid))
        to_send = [wid, b'', WORKER_PROTO, MSG_DISCONNECT]
        if self.main_stream.closed():
            self.shutdown()
        self.main_stream.send_multipart(to_send)
        self.unregister_worker(wid)
        return

    def client_response(self, rp, service, cmd, wid, msg):
        """Package and send reply to client.

        The message will contain the protocol used to serve this update,
        the service used, as well as echo back the requested command id and worker id.

        :param rp:       return address stack
        :type rp:        list of str
        :param service:  name of service
        :type service:   str
        :param cmd:      id of the operation requested by the client
        :type cmd:       str
        :param wid:      id of the worker that is replying
        :type wid:       str
        :param msg:      message parts
        :type msg:       list of str

        :rtype: None
        """
        _LOG.debug("Replying to client %s regarding request [%s]." % (rp, cmd))
        to_send = rp[:]
        to_send.extend([b'', CLIENT_PROTO, service, cmd, str(wid)])
        to_send.extend(msg)
        if self.client_stream.closed():
            self.shutdown()
        self.client_stream.send_multipart(to_send)
        return

    def shutdown(self):
        """Shutdown broker.

        Will unregister all workers, stop all timers and ignore all further
        messages.

        .. warning:: The instance MUST not be used after :func:`shutdown` has been called.

        :rtype: None
        """
        if self.client_stream == self.main_stream:
            self.client_stream = None
        self.main_stream.on_recv(None)
        self.main_stream.socket.setsockopt(zmq.LINGER, 0)
        self.main_stream.socket.close()
        self.main_stream.close()
        self.main_stream = None
        if self.client_stream:
            self.client_stream.on_recv(None)
            self.client_stream.socket.setsockopt(zmq.LINGER, 0)
            self.client_stream.socket.close()
            self.client_stream.close()
            self.client_stream = None
        self._workers = {}
        self._services = {}
        _LOG.info("Shutting down! All workers unregistered, will not process more messages.")
        return

    def on_timer(self):
        """Method called on timer expiry.

        Checks which workers are dead and unregisters them.

        :rtype: None
        """
        # use list to avoid size change during iteration error
        for wtracker in list(self._workers.values()):
            if not wtracker.is_alive():
                _LOG.debug("Worker with id: '%s' timed out." % bytes_to_hexstring(wtracker.id))
                self.unregister_worker(wtracker.id)
        return

    def on_ready(self, rp, msg):
        """Process worker READY command.

        Registers the worker for a service.

        :param rp:  return address stack
        :type rp:   list of str
        :param msg: message parts
        :type msg:  list of str

        :rtype: None
        """
        try:
            ret_id = rp[0]
            service = msg.pop(0)
            worker_type = msg.pop(0)
            address = msg.pop(0)
            protocols = msg.pop(0)
            self.register_worker(ret_id, service, worker_type, address, protocols)
        except IndexError:
            _LOG.debug("Error while registering worker %s: %s" % (rp, msg))
        return

    def on_reply(self, rp, msg):
        """Process worker REPLY command.

        Route the `msg` to the client given by the address(es) in front of `msg`.

        :param rp:  return address stack
        :type rp:   list of str
        :param msg: message parts
        :type msg:  list of str

        :rtype: None
        """
        ret_id = rp[0]
        wtracker = self._workers.get(ret_id)
        if not wtracker:
            # worker not found, ignore message
            return
        service = wtracker.service
        # make worker available again
        try:
            wq, wr = self._services[service]
            cp, msg = split_address(msg)
            if cp[0] == 'BROKER':
                self.update_worker_info(ret_id, msg)
                return
            cmd = msg.pop(0)
            self.client_response(cp, service, cmd, bytes_to_hexstring(wtracker.id), msg)
            wq.put(wtracker.id)
            self.change_worker_status(rp[0], WORKER_ONLINE_STATUS)
            if wr:
                proto, rp, msg = wr.pop(0)
                self.on_client(proto, rp, msg)
        except KeyError:
            # unknown service
            _LOG.info("Worker with id: '%s' reports an unknown service." % bytes_to_hexstring(ret_id))
            self.disconnect(ret_id)
        return

    def on_heartbeat(self, rp, msg):
        """Process worker HEARTBEAT command.

        :param rp:  return address stack
        :type rp:   list of str
        :param msg: message parts
        :type msg:  list of str

        :rtype: None
        """
        ret_id = rp[0]
        try:
            worker = self._workers[ret_id]
            if worker.is_alive():
                worker.on_heartbeat()
        except KeyError:
            # ignore HB for unknown worker
            pass
        return

    def on_disconnect(self, rp, msg):
        """Process worker DISCONNECT command.

        Unregisters the worker who sent this message.

        :param rp:  return address stack
        :type rp:   list of str
        :param msg: message parts
        :type msg:  list of str

        :rtype: None
        """
        wid = rp[0]
        _LOG.debug("Worker with id: '%s' wants to disconnect." % bytes_to_hexstring(wid))
        self.change_worker_status(wid, WORKER_INACTIVE_STATUS)
        self.unregister_worker(wid)
        return

    def on_ho(self, rp, service, msg):
        """Process HO request.

        For now only ho.service is handled.

        :param rp:      return address stack
        :type rp:       list of str
        :param service: the protocol id sent
        :type service:  str
        :param msg:     message parts
        :type msg:      list of str

        :rtype: None
        """
        _LOG.debug("New HO request received for service [%s] and code [%s]." % (service, msg))
        if service == b'ho.service':
            s = msg[0]
            ret = b'404'
            # TODO: review this
            for wr in self._workers.values():
                if s == wr.service:
                    ret = b'200'
                    break
            self.client_response(rp, service, '', '', [ret])
        elif service == b'ho.stat':
            cmd = msg[0]
            if cmd in self._local_cmds:
                fnc = self._local_cmds[cmd]
                ret = msgpack.packb(fnc())
            else:
                ret = 'Command not supported'
            _LOG.debug("Replying with: [%s]." % ret)
            self.client_response(rp, service, cmd, '', [ret])
        else:
            self.client_response(rp, service, '', '', [b'501'])
        return

    def on_client(self, proto, rp, msg):
        """Method called on client message.

        Frame 0 of msg is the requested service.
        The remaining frames are the request to forward to the worker.

        .. note::

           If the service is unknown to the broker the message is
           ignored.

        .. note::

           If currently no worker is available for a known service,
           the message is queued for later delivery.

        If a worker is available for the requested service, the
        message is repackaged and sent to the worker. The worker in
        question is removed from the pool of available workers.

        If the service name starts with `ho.`, the message is passed to
        the internal HO_ handler.

        :param proto: the protocol id sent
        :type proto:  str
        :param rp:    return address stack
        :type rp:     list of str
        :param msg:   message parts
        :type msg:    list of str

        :rtype: None
        """
        _LOG.debug("Received a new request from client: %s regarding %s." % (rp, msg[0]))
        service = msg.pop(0)
        if service.startswith(b'ho.'):
            self.on_ho(rp, service, msg)
            return
        try:
            if len(msg) != 2 and len(msg) != 3:
                _LOG.debug("Request was not formed correctly, ignoring")
                return
            wq, wr = self._services[service]
            cwid = msg.pop(0)
            wid = self.find_worker(hexstring_to_bytes(cwid), service)
            if not wid:
                # no worker ready
                # queue message
                msg.insert(0, cwid)
                msg.insert(0, service)
                wr.append((proto, rp, msg))
                return
            wtracker = self._workers[wid]
            to_send = [wtracker.id, b'', WORKER_PROTO, MSG_QUERY]
            to_send.extend(rp)
            to_send.append(b'')
            to_send.extend(msg)
            self.change_worker_status(wtracker.id, WORKER_BUSY_STATUS)
            if self.main_stream.closed():
                self.shutdown()
            self.main_stream.send_multipart(to_send)
        except KeyError:
            # unknwon service
            # ignore request
            _LOG.debug('Broker has no service "%s"' % service)
        return

    def on_worker(self, proto, rp, msg):
        """Method called on worker message.

        Frame 0 of msg is the command id.
        The remaining frames depend on the command.

        This method determines the command sent by the worker and
        calls the appropriate method. If the command is unknown the
        message is ignored and a DISCONNECT is sent.

        :param proto: the protocol id sent
        :type proto:  str
        :param rp:  return address stack
        :type rp:   list of str
        :param msg: message parts
        :type msg:  list of str

        :rtype: None
        """
        _LOG.debug("Received a new reply from worker: %s." % rp)
        cmd = msg.pop(0)
        if cmd in self._worker_cmds:
            fnc = self._worker_cmds[cmd]
            fnc(rp, msg)
        else:
            # ignore unknown command
            # DISCONNECT worker
            _LOG.info("Worker with id: '%s' is trying to use an unknown command." % bytes_to_hexstring(rp[0]))
            self.disconnect(rp[0])
        return

    def on_message(self, msg):
        """Processes given message.

        Decides what kind of message it is -- client or worker -- and
        calls the appropriate method. If unknown, the message is
        ignored.

        :param msg: message parts
        :type msg:  list of str

        :rtype: None
        """
        _LOG.debug("Received: %s" % msg)
        rp, msg = split_address(msg)
        # TODO: this condition should be changed to something better
        if len(msg) < 2:
            _LOG.debug("Unrecognized message.")
            return
        # dispatch on first frame after path
        t = msg.pop(0)
        if t.startswith(b'MNPW'):
            self.on_worker(t, rp, msg)
        elif t.startswith(b'MNPC'):
            self.on_client(t, rp, msg)
        else:
            _LOG.debug('Broker unknown Protocol: "%s"' % t)
        return

    def find_worker(self, wid, service):
        """Find a worker with the given id.

        :param wid: data id
        :type wid:  str
        :param service: service the worker supports
        :type service:  str

        :rtype: str
        """
        wq, wr = self._services[service]
        if wq.__contains__(wid):
            wq.remove(wid)
            _LOG.debug("Worker with id: %s selected and removed from the pool." % wid)
            return wid
        else:
            return None

    def register_worker_info(self, wid, service=SERVICE_BROKER, status=WORKER_ONLINE_STATUS, worker_type=WK_TYPE_BROKER,
                             address=get_current_ip(DEFAULT_INTEFACE), protocols=None):
        """Update the worker info list.

        :param wid:         the worker id.
        :type wid:          str
        :param service:     the service name.
        :type service:      str
        :param status:      the current network status of the worker.
        :type status:       str
        :param worker_type: the specific worker type.
        :type worker_type:  str
        :param address:     the ipv4 or ipv6 of this worker.
        :type address:      str
        :param protocols:   the routing protocols reported by the worker.
        :type protocols:    str

        :rtype: None
        """
        service_list = set([])
        service_list.add(service)
        existing_worker = next((x for x in self._workers_info if
                                self._workers_info[x]['ip'] == address), None)
        if existing_worker:
            service_list.update(self._workers_info[existing_worker]['service'])
            del self._workers_info[existing_worker]

        if isinstance(protocols, str):
            protocols = protocols.split(' ')
        worker_info = {'id': bytes_to_hexstring(wid), 'status': status, 'ip': address,
                       'type': worker_type, 'service': list(service_list), 'protocols': protocols}
        self._workers_info[wid] = worker_info

        # broker will store a list of protocols supported by all clients
        if wid != self.main_stream.getsockopt(zmq.IDENTITY):
            if self._workers_info[self.main_stream.getsockopt(zmq.IDENTITY)]['protocols'] is None:
                self._workers_info[self.main_stream.getsockopt(zmq.IDENTITY)]['protocols'] = protocols
            else:
                self._workers_info[self.main_stream.getsockopt(zmq.IDENTITY)]['protocols'] = \
                    list(set(self._workers_info[self.main_stream.getsockopt(zmq.IDENTITY)]['protocols']).intersection(
                        set(protocols)))
        return

    def reset_node_info(self, wid, status=WORKER_OFFLINE_STATUS):
        worker_info = {'id': bytes_to_hexstring(wid), 'status': status, 'ip': self._workers_info[wid]['ip'],
                       'type': self._workers_info[wid]['type'], 'service': self._workers_info[wid]['service'],
                       'protocols': self._workers_info[wid]['protocols']}
        try:
            self._workers_info[wid] = worker_info
        except KeyError:
            pass

    def change_worker_status(self, wid, status):
        """Change the status of the worker with the given id.

        :param wid:     data id
        :type wid:      str
        :param status:  service the worker supports
        :type status:   str

        :rtype: str
        """
        try:
            self._workers_info[wid]['status'] = status
        except KeyError:
            pass

    def get_workers_info(self):
        """Return a list with the information of all current workers.

        :rtype: dict
        """
        return self._workers_info.values()

    def update_worker_info(self, wid, data):
        # for now there is only one possible command
        cmd = data.pop(0)
        wdata = msgpack.unpackb(data.pop(0))
        self._workers_info[wid].update(wdata)

    def collect_workers_info(self):
        # A return address pointing to 'BROKER' will be interpreted as belonging to an internal 'ho' request
        self.send_to_all_workers(b'BROKER')

    def send_to_all_workers(self, rp, msg_type=MSG_WDUMP):
        for wid in self._workers:
            to_send = [wid, b'', WORKER_PROTO, MSG_QUERY, rp, b'', msg_type]
            # self.change_worker_status(wid, WORKER_BUSY_STATUS)
            if self.main_stream.closed():
                self.shutdown()
            self.main_stream.send_multipart(to_send)


class WorkerTracker(object):
    """Helper class to represent a worker in the broker.

    Instances of this class are used to track the state of the attached worker
    and carry the timers for incoming and outgoing heartbeats.

    :param proto:    the worker protocol id.
    :type proto:     str
    :param wid:      the worker id.
    :type wid:       str
    :param service:  service this worker serves
    :type service:   str
    :param stream:   the ZMQStream used to send messages
    :type stream:    ZMQStream
    """

    def __init__(self, proto, wid, service, stream):
        self.proto = proto
        self.id = wid
        self.service = service
        self.curr_retries = HB_RETRIES
        self.stream = stream
        self.last_hb = 0
        self.free_space = 0
        self.data = []
        self.hb_out_timer = PeriodicCallback(self.send_hb, HB_INTERVAL)
        self.hb_out_timer.start()
        return

    def send_hb(self):
        """Called on every HB_INTERVAL.

        Decrements the current retries count by one.

        Sends heartbeat to worker.
        """
        self.curr_retries -= 1
        msg = [self.id, b'', self.proto, MSG_HEARTBEAT]
        if self.stream.closed():
            pass
        self.stream.send_multipart(msg)
        return

    def set_stream(self, stream):
        self.stream = stream

    def on_heartbeat(self):
        """Called when a heartbeat message from the worker was received.

        Sets current retries to HB_RETRIES.
        """
        self.curr_retries = HB_RETRIES
        return

    def is_alive(self):
        """Returns True when the worker is considered alive.
        """
        return self.curr_retries > 0

    def shutdown(self):
        """Cleanup worker.

        Stops timer.
        """
        self.hb_out_timer.stop()
        self.hb_out_timer = None
        self.stream = None
        return


class ServiceQueue(object):
    """Class defining the Queue interface for workers for a service.

    The methods on this class are the only ones used by the broker.
    """

    def __init__(self):
        """Initialize queue instance.
        """
        self.q = []
        return

    def __contains__(self, wid):
        """Check if given worker id is already in queue.

        :param wid:    the workers id
        :type wid:     str
        :rtype:        bool
        """
        return wid in self.q

    def __len__(self):
        """Return the length of the queue.

        :rtype:        int
        """
        return len(self.q)

    def remove(self, wid):
        """Remove a worker from the queue.

        :param wid:    the workers id
        :type wid:     str
        """
        try:
            self.q.remove(wid)
        except ValueError:
            pass
        return

    def put(self, wid):
        """Put a worker in the queue.

        Nothing will happen if the worker is already in queue.

        :param wid:    the workers id
        :type wid:     str
        """
        if wid not in self.q:
            self.q.append(wid)
        return

    def get(self):
        """Get the next worker from the queue.
        """
        if not self.q:
            return None
        return self.q.pop(0)
