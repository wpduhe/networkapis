#! python3

import requests
import time
import sys


def main():
    p_start_time = time.perf_counter()

    results = {
        'successful': 0,
        'min': 10,
        'max': 0
    }

    proxies = {
        'http': f'http://{sys.argv[1]}:80'
    }

    try:
        print(f'{"Successful Attempts":<25}{"Minimum":<20}{"Maximum":<20}')
        while results['successful'] < 100:
            start = time.perf_counter()
            _ = requests.get('http://ipchicken.com', proxies=proxies)
            elap = time.perf_counter() - start

            results['successful'] += 1
            results['min'] = round((elap if elap < results['min'] else results['min']), ndigits=3)
            results['max'] = round((elap if elap > results['max'] else results['max']), ndigits=3)

            print(f'Request completed in {elap} seconds', end='\r')
            print(f'{results["successful"]:<25}{results["min"]:<20}{results["max"]:<20}', end='\r')
            time.sleep(0.2)
        raise KeyboardInterrupt

    except KeyboardInterrupt:
        p_end_time = time.perf_counter() - p_start_time
        print(f'{results["successful"]:<25}{results["min"]:<20}{results["max"]:<20}')
        print(f'\nProcess ran for {round(p_end_time)} seconds')
        sys.exit(0)
    except requests.exceptions.ProxyError as e:
        p_end_time = time.perf_counter() - p_start_time
        print(f'{results["successful"]:<25}{results["min"]:<20}{results["max"]:<20}')
        print('The proxy server encountered an error', '\n', e.args)
        print(f'\nProcess ran for {round(p_end_time)} seconds')
        sys.exit(1)


if __name__ == '__main__':
    try:
        print(f'Starting test with proxy server {sys.argv[1]}')
        main()
    except IndexError:
        print('Please provide a proxy IP\n')
        sys.exit(1)
