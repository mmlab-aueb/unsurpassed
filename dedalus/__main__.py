#! /usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import yaml
import zmq
from argparse import ArgumentParser
from logging import config, basicConfig, captureWarnings, getLogger, CRITICAL, ERROR, WARNING, INFO, DEBUG, \
    StreamHandler
from logging.handlers import TimedRotatingFileHandler, RotatingFileHandler
import socket
from zmq.log.handlers import PUBHandler
from util import get_current_ip
from mnbroker_runner import run as br
from mnclient_runner import run as cr
from mnworker_runner import run as wr
from _version import __version__
import time

time.sleep(5)


# TODO: Fix name format
def dedalus_handler():
    path = os.path.dirname(os.path.realpath(__file__))
    path = os.path.join(path, 'Log/dedalus.log')
    return TimedRotatingFileHandler(path, when="midnight", interval=1, backupCount=20, encoding="utf8")


# TODO: Fix name format
def error_handler():
    path = os.path.dirname(os.path.realpath(__file__))
    path = os.path.join(path, 'Log/errors.log')
    return RotatingFileHandler(path, maxBytes=10485760, backupCount=20, encoding="utf8")


# TODO: review this, does the idea make sense
# TODO: blocks messages if started in multiple processes
def network_handler(protocol='tcp', endpoint='*', port='4547'):
    ctx = zmq.Context()
    pub = ctx.socket(zmq.PUB)
    try:
        pub.bind('%s://%s:%s' % (protocol, endpoint, port))
    except zmq.error.ZMQError:
        print("Logger::Network logger endpoint is already in use!")
    handler = PUBHandler(pub)
    return handler


# TODO: if the logging directory does not exist create it
def setup_logging(default_path='logging.yaml', default_level='INFO', env_key='DEDALUS_LOG_CFG'):
    path = default_path
    value = os.getenv(env_key, None)
    if value:
        path = value
    path = '{0}/{1}'.format(os.path.dirname(os.path.realpath(__file__)), path)
    if os.path.exists(path):
        with open(path, 'rt') as f:
            configset = yaml.safe_load(f.read())
        config.dictConfig(configset)
    else:
        log_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'Log/dedalus.log')
        basicConfig(format='%(asctime)s: %(name)s: %(levelname)s: %(message)s', filename=log_path,
                    level=default_level)
        captureWarnings(True)


if __name__ == "__main__":
    parser = ArgumentParser(description='Dedalus v%s' % __version__)
    parser.add_argument("m", help="running mode", default='broker', choices=['broker', 'client', 'worker'])

    parser.add_argument("-t", "--transport", help="protocol to be used for transport", type=str, default='tcp',
                        choices=['tcp', 'udp', 'inproc'], required=False)
    parser.add_argument("-p", "--port", type=int, default=5555, help="port address for the main endpoint")
    parser.add_argument("-l", "--optport", type=int, default=5555, help="port address for the optional endpoint")
    parser.add_argument("-a", "--address", type=str, default=get_current_ip(),
                        help="main broker endpoint")
    parser.add_argument("-o", "--optional", type=str, default=None, help="optional broker endpoint")

    parser.add_argument("-v", "--verbose", help="increase output verbosity", default=0, action="count")
    parser.add_argument("-q", "--quiet", help="suppress all messages to the console", default=False,
                        action="store_true")
    args = parser.parse_args()

    setup_logging()
    _LOG = getLogger(__name__)
    _DLOG = getLogger('dedalus_logger')

    try:
        print("-Dedalus v%s-" % __version__)

        if args.quiet:
            # remove the stream handler
            for h in getLogger().handlers:
                if isinstance(h, StreamHandler):
                    getLogger().removeHandler(h)

        # set logging level
        raw_log_level = args.verbose
        if raw_log_level <= 0:  # default
            log_level = CRITICAL
        elif raw_log_level == 1:
            log_level = ERROR
        elif raw_log_level == 2:
            log_level = WARNING
        elif raw_log_level == 3:
            log_level = INFO
        else:
            log_level = DEBUG
        getLogger().setLevel(log_level)

        socket.inet_aton(args.address)
        main_endpoint = '%s://%s:%s' % (args.transport, args.address, args.port)

        optional_endpoint = None
        if args.optional:
            socket.inet_aton(args.optional)
            optional_endpoint = '%s://%s:%s' % (args.transport, args.optional, args.port)

        if args.port > 65535 or args.port < 4000:
            parser.error("--port should be a valid port number in the range (4000, 65535)")

        print("Services to run: %s" % args.m)

        print("main endpoint [%s], optional endpoint [%s]" % (main_endpoint, optional_endpoint))

        if args.m == 'broker':
            br(main_endpoint, optional_endpoint)
        elif args.m == 'worker':
            wr(main_endpoint)
        else:
            cr(main_endpoint)
    except KeyboardInterrupt:
        pass
    except socket.error:
        parser.error("--address should be a valid IPv4 or IPv6 address")
        pass
