from githubapi.utils import GithubAPI
from nexus.utils import NXOS
import logging
import json
import sys
import re


formatter = logging.Formatter(fmt='%(asctime)s.%(msecs)03dZ - %(name)s - %(levelname)s - %(message)s',
                              datefmt='%Y-%m-%dT%H:%M:%S')

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
handler.setFormatter(formatter)

logging.basicConfig(level=logging.DEBUG, handlers=[handler])
logger = logging.getLogger(__name__)

logging.getLogger('urllib3').setLevel(logging.WARNING)
logging.getLogger('github').setLevel(logging.WARNING)
logging.getLogger('netmiko').setLevel(logging.WARNING)
logging.getLogger('paramiko').setLevel(logging.WARNING)


def main():
    logger.debug(f'Updating prefix cache')

    xr = NXOS('10.0.255.19')  # XRDC Core-1
    fw = NXOS('10.64.255.72')  # FWDC Core-1

    # Get only routes that have AS paths
    xr_bgp_output = xr.exec_command('show ip bgp regexp "[0-9]$" | include / | exclude 0.0.0.0/0 | no-more')
    fw_bgp_output = fw.exec_command('show ip bgp regexp "[0-9]$" | include / | exclude 0.0.0.0/0 | no-more')

    xr_bgp_output = xr_bgp_output.split('\n')
    fw_bgp_output = fw_bgp_output.split('\n')

    xr_bgp_output.remove('')
    fw_bgp_output.remove('')

    xr_bgp_routes = set(re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}).*?(\d+)\D+$', line).groups()
                        for line in xr_bgp_output)
    fw_bgp_routes = set(re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}).*?(\d+)\D+$', line).groups()
                        for line in fw_bgp_output)

    prefixes = xr_bgp_routes.union(fw_bgp_routes)

    gh.update_file('datacenter/prefix_cache.json', message='prefix_cache_update',
                   content=json.dumps(list(x for x in prefixes), indent=2))
    logger.debug('Prefix cache updated')


if __name__ == '__main__':
    gh = GithubAPI()
    main()
