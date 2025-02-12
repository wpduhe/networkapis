import re
import requests
import os
import urllib3
import logging
import sys
import hashlib
from lxml import etree
from bs4 import BeautifulSoup
from ipaddress import IPv4Network



formatter = logging.Formatter(fmt='%(asctime)s.%(msecs)03dZ - %(name)s - %(levelname)s - %(message)s',
                              datefmt='%Y-%m-%dT%H:%M:%S')

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
handler.setFormatter(formatter)

logging.basicConfig(level=logging.DEBUG, handlers=[handler])
logger = logging.getLogger(__name__)

logging.getLogger('urllib3').setLevel(logging.WARNING)
logging.getLogger('asyncio').setLevel(logging.WARNING)


urllib3.disable_warnings()


# Template host data
TEMP_FQDN = 'xrdcupprx01a.mgmt.medcity.net'
TEMP_MGMT_IP = '10.27.31.101'
TEMP_HOST = 'XRDCUPPRX01A'


def xmlprint(element):
    print(etree.tostring(element, encoding='utf8').decode('utf8'))


def download_config(host: str=None) -> etree.ElementTree:
    # Login to WSA management interface and download XML configuration file wsa_config_gen.xml
    if not host:
        host = TEMP_FQDN

    session = requests.session()
    session.verify = False
    resp = session.get(f'https://{host}:8443')

    soup = BeautifulSoup(resp.text, features='lxml')

    form = soup.form
    form = etree.fromstring(str(form))
    referrer = form.find('input/[@name="referrer"]')
    screen = form.find('input/[@name="screen"]')
    csrf_key = form.find('input/[@name="CSRFKey"]')

    login_data = {
        'action': 'Login',
        'username': os.getenv('netmgmtuser'),
        'password': os.getenv('netmgmtpass'),
        'action_type': 'ajax_validation',
        'referrer': referrer.attrib['value'],
        'screen': screen.attrib['value'],
        'CSRFKey': csrf_key.attrib['value']
    }

    session.headers['X-Requested-With'] = 'XMLHttpRequest'
    resp = session.post(f'https://{host}:8443/login', data=login_data)
    del login_data['action_type']
    resp = session.post(f'https://{host}:8443/login', data=login_data)

    if 'logged in as' not in resp.text.lower():
        raise Exception(f'Login to {host} failed...')

    resp = session.get(f'https://{host}:8443/system_administration/configuration/configuration_file')
    csrf_key = re.search(r'CSRFKey=[a-z0-9-]+', resp.text).group()[8:]

    #
    #
    # Submit form to download data
    session.headers['Referer'] = f'https://{host}:8443/system_administration/configuration/configuration_file'
    session.headers['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/' \
                                'apng,*/*;q=0.8,application/signed-exchange;v=b3'
    session.headers['Origin'] = f'https://{host}:8443'
    session.headers['Upgrade-Insecure-Requests'] = '1'

    download_form = {
        'action': (None, 'Save'),
        'operation': (None, 'download'),
        'password_config': (None, 'plain_passwords'),
        'filename': (None, 'user'),
        'filename_name': (None, 'wsa_gold_image'),  # Was from_buffer
        'load_from': (None, 'from_appliance'),
        'appliance_filename': (None, 'EUN_DEFAULT.tar.gz'),
        'CSRFKey': (None, csrf_key)
    }

    resp = session.post(f'https://{host}:8443/system_administration/configuration/configuration_file',
                        files=download_form)

    configuration = etree.fromstring(resp.content)
    configuration = etree.ElementTree(element=configuration)

    #
    #
    # Log out and return the configuration
    session.get(f'https://{host}:8443/login?action=Logout&CSRFKey={csrf_key}')
    session.close()

    return configuration



def main():
    logger.debug(f'Downloading live WSA route table from {TEMP_FQDN} to compare for consistency with administratively '
                 f'defined routes.')
    tree = download_config()

    admin_routes = requests.get('https://pyapis.ocp.app.medcity.net/apis/wsa/routes', verify=False).text.strip()
    admin_routes = re.split(r'\n', admin_routes)
    admin_routes = [IPv4Network(re.search(r'\S+\s+(\S+)\s+\S+', _).group(1)) for _ in admin_routes]
    admin_routes.sort(key=lambda x: int(x.network_address))

    admin_routes_hash = hashlib.md5(str(admin_routes).encode())
    logger.debug(f'Administratively defined routes MD5 hash: {admin_routes_hash.hexdigest()}')

    config = tree.getroot()
    routes = config.find('routing_tables/routing_table/[routing_table_interface="Data"]/routes')
    appliance_routes = [IPv4Network(route.find('destination').text) for route in routes]
    appliance_routes.sort(key=lambda x: int(x.network_address))

    appliance_routes_hash = hashlib.md5(str(appliance_routes).encode())
    logger.debug(f'Routing table from live WSA MD5 hash: {appliance_routes_hash.hexdigest()}')

    # Check to see if appliance routes conform to the administratively defined routes
    if admin_routes != appliance_routes:
        # If they do not match, update routes
        logger.debug('WSA appliance routes differ from administratively defined routes.')
        logger.debug('Starting route deployment for all sites. ')
        import wsa.deploy_routes
    else:
        logger.debug('WSA appliance routes match administratively defined routes. No action required.')


if __name__ == '__main__':
    main()
