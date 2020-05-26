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
from datetime import timedelta
from typing import List, Union

__version__ = '1.1.1'
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
    parser.add_argument('-l', '--logfile', action='store', default=None,
                        help='create or append log to a file (default none = no log file)')
    parser.add_argument('-c', '--csv', action='store', default=None,
                        help='create or append RTT data to CSV file (default none = no RTT data logged)')
    parser.add_argument('-v', '--verbose', action='count', default=0,
                        help='increase logging verbosity')
    parser.add_argument('-V', '--version', action='version', version=f'{prog} v{__version__} by {__author__}',
                        help='print version and exit')
    namespace = namespace or argparse.Namespace(prog=prog, parser=parser, rdd=None)
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


class CSVLog:
    HEADERS = 'timestamp,host,state,status,rtt\n'

    def __init__(self, filename):
        self._filename = filename
        self._fd = None

    @property
    def filename(self):
        return self._filename

    def open(self):
        if self._filename:
            try:
                self._fd = open(self._filename, mode='a+', encoding='utf-8')
                # write headers if beginning of file
                if self._fd.seek(os.SEEK_CUR, 0) == 0:
                    self._fd.write(self.HEADERS)
            except EnvironmentError:
                raise
            except (TypeError, AttributeError):
                pass
            return True
        return False

    def close(self):
        if self._fd is not None:
            self._fd.close()

    @staticmethod
    def esc(string):
        if not string:
            string = ''
        elif '"' in string:
            string = '"' + ''.join([f"\\{x}" if x == '"' else x for x in string]) + '"'
        return string

    def add(self, timestamp: float, host: str, state: str, status: str, rtt: float):
        if self._fd is not None:
            self._fd.write(f"{timestamp},{self.esc(host)},{state},{self.esc(status)},{0.0 if not rtt else rtt}\n")
            self._fd.flush()


def monitor(logger: logging.Logger, csv: CSVLog, host: str, interval: float, errors: int, times: int):
    from scapy.layers.inet import ICMP, IP
    from scapy.sendrecv import sr1

    currentstate = None
    uptime = downtime = None
    pingcount = errcount = 0

    def in_milliseconds(value: float):
        return int(value * 1000000) / 1000

    def getstate(c: ConnectionState) -> str:
        return 'U' if c == ConnectionState.UP else 'D' if c == ConnectionState.DOWN else 'U'

    def diagnostic(sent, rcvd, e):
        new_state = ConnectionState.DOWN
        rtt = None
        if rcvd is None:
            result = 'timeout'
        elif e:
            result = f'error {e}: {e.args}'
        elif rcvd.src != sent.dst:  # assume response from intermediary
            result = f'not reachable {rcvd.src} type={rcvd.type}'
        else:
            result = 'success'
            new_state = ConnectionState.UP
            rtt = in_milliseconds(rcvd.time - sent.sent_time)
        csv.add(sent.sent_time, host, getstate(new_state), result, rtt)
        logger.debug(f'{host} icmp {result}{" " + str(rtt) + " ms" if rtt else ""}')
        return new_state

    def lost(up_time):
        nonlocal downtime
        up_for = ""
        if up_time is not None and downtime is not None:
            duration = downtime - up_time
            up_for = f" uptime {timedelta(seconds=duration)}"
        logger.warning(f'{host} DOWN{up_for}')

    def recovered(current):
        nonlocal downtime, uptime, errcount
        uptime = current
        down_for = ""
        if downtime is not None:
            duration = current - downtime
            down_for = f" dowmtime {timedelta(seconds=duration)}"
        logger.warning(f'{host} UP{down_for}')
        errcount = 0
        downtime = None

    if os.geteuid() != 0:
        raise PermissionError('this script requires elevated (root) priviledges')

    while not times or pingcount < times:
        icmp = IP(dst=host)/ICMP()
        pingcount += 1
        endat = time.time() + interval
        exc = rsp = None
        starttime = time.time()
        try:
            rsp = sr1(icmp, timeout=interval, verbose=False)
        except OSError as ex:
            exc = ex
        newstate = diagnostic(icmp, rsp, exc)
        if currentstate is not ConnectionState.DOWN:
            if newstate is ConnectionState.DOWN:    # UP failure case
                if downtime is None:
                    downtime = starttime
                errcount += 1
                if errcount >= errors:
                    lost(uptime)
                    currentstate = newstate
            elif currentstate is not ConnectionState.UP:   # found UP
                recovered(starttime)
                currentstate = newstate
        elif newstate is ConnectionState.UP:
            recovered(starttime)
            currentstate = newstate
        if starttime < endat:
            time.sleep(endat - starttime)
    return 0 if currentstate is ConnectionState.UP else 1


def run(argv: argparse.Namespace) -> int:
    logger = setup_logging(argv.logfile, argv.verbose)
    csv = CSVLog(argv.csv)
    message = f'Start host={argv.host} interval={argv.interval} maxerr={argv.errors}'
    if argv.times:
        message += f" times={argv.times}"
    if csv:
        message += f" csv={csv.filename}"
    message += f"; v{__version__}"
    logger.info(message)
    started = time.time()
    try:
        csv.open()
        monitor(logger, csv, argv.host, argv.interval, argv.errors, argv.times)
    except (KeyboardInterrupt, PermissionError, ImportError) as exc:
        logger.critical(f'Terminated: {exc.__class__.__name__}')
    csv.close()
    logger.info(f'Elapsed: {time.time() - started}')
    return 0


def main(prog: str, args: List[str]):
    return run(parse_args(prog, args))


if __name__ == '__main__':
    exit(main(sys.argv[0], sys.argv[1:]))
