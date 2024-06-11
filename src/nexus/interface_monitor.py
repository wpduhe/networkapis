from nexus.utils import NXOSLite
from tabulate import tabulate
import argparse
import re
import time
import math


parser = argparse.ArgumentParser(description='Interface monitor utility for NXOS devices',
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)

parser.add_argument('--host-interfaces', '-H',
                    help='Hosts and interfaces you want to monitor. Formatted as host:int:int,host:int:int',
                    required=True)
parser.add_argument('--interval', '-I', help='Interval for how often statistics are retrieved', default=15)


def readable_speed(n) -> str:
    speeds = [' bps', ' Kbps', ' Mbps', ' Gbps', ' Tbps']

    n = float(n)
    speeddx = max(0, min(len(speeds)-1, math.floor(0 if n == 0 else math.log10(abs(n))/3)))

    return '{}{}'.format(n / 10**(3 * speeddx), speeds[speeddx])


def main():
    hosts = args['host-interfaces'].split(',')
    hosts = {NXOSLite(host.split(':')[0]): host.split(':')[1:] for host in hosts}

    while True:
        for host, interfaces in hosts.items():
            output = host.exec_command(f'show interface {",".join(interfaces)}')

            intfs = re.finditer(rf'')

    pass


if __name__ == '__main__':
    args = vars(parser.parse_args())
    main()
