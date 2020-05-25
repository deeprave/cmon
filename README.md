# cmon
Small python utility to monitor and optionally log connection state.

## Requirements
- scapy is required for low level ICMP packet handling

## Usage
```.bash
usage: cmon.py [-h] [-H HOST] [-i INTERVAL] [-e ERRORS] [-t TIMES] [-l LOGFILE] [-c CSV] [-v] [-V]

Monitor (and log) a network connection

optional arguments:
  -h, --help            show this help message and exit
  -H HOST, --host HOST  host name or ip to test against
  -i INTERVAL, --interval INTERVAL
                        interval between tests (default 1.0 secs)
  -e ERRORS, --errors ERRORS
                        number of errors (lost packets) before connection is considered dead
  -t TIMES, --times TIMES
                        maximum number of times to try (default not set = forever)
  -l LOGFILE, --logfile LOGFILE
                        create or append log to a file (default none = no log file)
  -c CSV, --csv CSV     create or append RTT data to CSV file (default none = no RTT data logged)
  -v, --verbose         increase logging verbosity
  -V, --version         print version and exit
```