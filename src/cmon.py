#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    Monitor (and log) a network connection
"""
import enum
import sys
import os
import argparse
import logging
import time
from typing import List, Union

__version__ = '1.0.4'
__author__ = 'David Nugent <davidn@uniquode.io>'


class ConnectionState(enum.Enum):
    DOWN = 0
    UP = 1


def prog_name(prog: str) -> str:
    return os.path.basename(prog)


def parse_args(prog: str, args: List[str],
               namespace: Union[None, argparse.Namespace, None] = None) -> argparse.Namespace:
    prog = prog_name(prog)
    parser = argparse.ArgumentParser(prog=prog, description=__doc__)
    parser.add_argument('-H', '--host', action='store', default='8.8.8.8',
                        help='host name or ip to test against')
    parser.add_argument('-i', '--interval', action='store', type=float, default=1.0,
                        help='interval between tests (default 1.0 secs)')
    parser.add_argument('-e', '--errors', action='store', type=int, default=4,
                        help='number of errors (lost packets) before connection is considered dead')
    parser.add_argument('-t', '--times', default=None,
                        help='maximum number of times to try (default not set = forever)')
    parser.add_argument('-l', '--logfile', action='store',
                        help='create or append log to a file (default none = no log file)')
    parser.add_argument('-v', '--verbose', action='count', default=0,
                        help='increase logging verbosity')
    parser.add_argument('-V', '--version', action='version', version=f'{prog} v{__version__} by {__author__}',
                        help='print version and exit')
    namespace = namespace or argparse.Namespace(prog=prog, parser=parser)
    return parser.parse_args(args, namespace)


def setup_logging(logfile: str, verbosity: int) -> logging.Logger:
    logging.getLogger().handlers = []   # reset
    formatter = logging.Formatter('%(asctime)s  %(name)s %(message)s')
    logger = logging.getLogger('cmon')
    # root logger level
    logger.setLevel(logging.WARNING if verbosity == 0 else logging.INFO if verbosity == 1 else logging.DEBUG)
    if logfile:
        # file logger
        fh = logging.FileHandler(logfile)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    return logger


def monitor(logger: logging.Logger, host: str, interval: float, errors: int, times: int):
    from scapy.layers.inet import ICMP, IP
    from scapy.sendrecv import sr1

    def diagnostic(sent, rcvd, e):
        if rcvd is None:
            logger.debug(f'icmp {host}: timeout')
        elif e:
            logger.debug(f'icmp {host} error {e}: {e.args}')
        elif rcvd.src != sent.dst:  # assume response from intermediary
            logger.debug(f'icmp {host}: not reachable {rcvd.src} type={rcvd.type}')
        else:
            logger.debug(f'icmp {host}: success')
            return ConnectionState.UP
        return ConnectionState.DOWN

    state = None
    count = errors
    errcount = 0
    while not times or count < times:
        icmp = IP(dst=host)/ICMP()
        mark = time.time()
        endat = mark + interval
        count += 1
        exc = rsp = None
        try:
            rsp = sr1(icmp, timeout=interval, verbose=False)
        except OSError as ex:
            exc = ex
        newstate = diagnostic(icmp, rsp, exc)
        if state is not ConnectionState.DOWN:
            if newstate is ConnectionState.DOWN:    # UP failure case
                errcount += 1
                if errcount >= errors:
                    logger.warning(f'DOWN {host}')
                    state = newstate
            elif state is not ConnectionState.UP:   # found UP
                state = newstate
                logger.warning(f'UP {host}')
        else:
            if newstate is ConnectionState.UP:
                errcount = 0
                state = newstate
                logger.warning(f'UP {host}')
        mark = time.time()
        if mark < endat:
            time.sleep(endat - mark)
    return 0 if state is ConnectionState.UP else 1


def run(argv: argparse.Namespace) -> int:
    logger = setup_logging(argv.logfile, argv.verbose)
    message = f'Start host={argv.host} interval={argv.interval} maxerr={argv.errors}; v{__version__}'
    if argv.times:
        message += " times={argv.times}"
    logger.info(message)
    started = time.time()
    try:
        if os.geteuid() != 0:
            raise PermissionError('this script requires elevated (root) priviledges')
        monitor(logger, argv.host, argv.interval, argv.errors, argv.times)
    except (KeyboardInterrupt, PermissionError, ImportError) as exc:
        logger.critical(f'Terminated: {exc}')
    logger.info(f'Elapsed: {time.time() - started}')
    return 0


def main(prog: str, args: List[str]):
    return run(parse_args(prog, args))


if __name__ == '__main__':
    exit(main(sys.argv[0], sys.argv[1:]))
