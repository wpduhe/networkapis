from iosxr.utils import IOSXR
from tabulate import tabulate
import math
import time
import re


HOSTS = ['10.192.23.16', '10.192.23.17']
INTERFACE1 = 'te0/0/0/2'
INTERFACE2 = 'te0/0/0/2'

# HOSTS = ['10.192.208.4', '10.192.208.5']
COMMAND1 = f"show int {INTERFACE1} | utility egrep '(rate|put drop)'"
COMMAND2 = f"show int {INTERFACE2} | utility egrep '(rate|put drop)'"
TIMER = 15


def readable_speed(n) -> str:
    speeds = [' bps', ' Kbps', ' Mbps', ' Gbps', 'Tbps']

    n = float(n)
    speeddx = max(0, min(len(speeds)-1, math.floor(0 if n == 0 else math.log10(abs(n))/3)))

    return '{}{}'.format(n / 10**(3 * speeddx), speeds[speeddx])


def main():
    h1, h2 = [IOSXR(h) for h in HOSTS]
    i1, o1, i2, o2 = 0, 0, 0, 0

    with open('monitor_log.txt', 'a') as log_file:
        while True:
            info1 = h1.session.send_command(COMMAND1)
            info2 = h2.session.send_command(COMMAND2)

            log_file.write(f'\n\n\n\n{h1.hostname}\n{info1}\n\n{h2.hostname}\n{info2}')

            rates1 = re.finditer(r'put rate\s+(\d+)', info1)
            rates2 = re.finditer(r'put rate\s+(\d+)', info2)

            drops1 = re.finditer(r'(\d+) total', info1)
            drops2 = re.finditer(r'(\d+) total', info2)

            ni1, no1 = [int(_.group(1)) for _ in drops1]
            ni2, no2 = [int(_.group(1)) for _ in drops2]

            i1 = round((ni1 - i1) / TIMER)
            o1 = round((no1 - o1) / TIMER)
            i2 = round((ni2 - i2) / TIMER)
            o2 = round((no2 - o2) / TIMER)

            rates1 = [readable_speed(int(_.group(1))) for _ in rates1]
            rates2 = [readable_speed(int(_.group(1))) for _ in rates2]

            print(tabulate([[h1.hostname, INTERFACE1, *rates1, i1, o1], [h2.hostname, INTERFACE2, *rates2, i2, o2]],
                           headers=['Device', 'Interface', 'Input', 'Output', 'Input Drops /sec', 'Output Drops /sec']),
                  end='\n\n')

            time.sleep(TIMER)


if __name__ == '__main__':
    main()
