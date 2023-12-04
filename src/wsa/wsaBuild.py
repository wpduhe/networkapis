import sys
sys.path.extend(['C:\\Users\\JXU8356\\PycharmProjects\\Network_APIs'])

from lxml.etree import Element
from lxml import etree
from bs4 import BeautifulSoup
from githubapi.utils import GithubAPI
from ipaddress import IPv4Network
from getpass import getpass
import urllib3
import requests
import json
import os
import re


# Template host data
TEMP_FQDN = 'xrdcupprx01a.mgmt.medcity.net'
TEMP_MGMT_IP = '10.27.31.103'
TEMP_HOST = 'XRDCUPPRX01A'


def xmlprint(element):
    print(etree.tostring(element, encoding='utf8').decode('utf8'))


def download_config(host: str=None):
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


def buildWSA(mgmtIP: str, ntp: list, dns: list, auth_servers: list, hostname: str, p1: str, p2: str, snmpLocation: str,
             intGateway: str, extGateway: str, mgmtGateway: str, frdcRadius: bool = False, **kwargs):

    irrelevant_tags = [
        'ports',
        'ip_groups',
        'ethernet_settings',
        'carp_preemptive',
        'WSA_Version',
        'config_rollback',
        'fips_mode',
        'config_encryption',
        'certificate_pairs',
        'gui_loginhistory',
        'gui_max_sessions',
        'external_group_mappings',
        'ocsp_enabled',
        'cli_external_group_mappings',
        'cli_ocsp_enabled',
        'second_factor_service_profiles',
        'second_factor_auth_mechanism',
        'second_factor_role_privileges',
        'second_factor_custom_info',
        'account_policies',
        'password_policies',
        'users',
        'entropy_settings',
        'core_watch_enabled',
        'admin_access',
        'proxy_server',
        'https_proxy_server',
        'ise_service'
    ]

    p1 = {
        'ip': p1.split('/')[0],
        'netmask': p1.split('/')[1]
    }

    p2 = {
        'ip': p2.split('/')[0],
        'netmask': p2.split('/')[1]
    }

    mgmtIP = {
        'ip': mgmtIP.split('/')[0],
        'netmask': mgmtIP.split('/')[1]
    }

    # Open base configuration file
    # tree = ElementTree(file='../wsa/wsa.xml')
    tree = download_config()

    config = tree.getroot()

    # Certain XML elements may need to be removed
    for tag in irrelevant_tags:
        elem = config.find(tag)
        config.remove(elem)

    # Set WSA hostname
    hostname_elem = tree.find('hostname')
    hostname_elem.text = f'{hostname}.mgmt.medcity.net'

    #
    #
    # Set P1 Interface Settings
    p1_elem = tree.find('interfaces/interface/[phys_interface="P1"]')
    p1_ip_elem = p1_elem.find('ip')
    p1_mask_elem = p1_elem.find('netmask')
    p1_host_elem = p1_elem.find('interface_hostname')
    p1_ip_elem.text = p1['ip']
    p1_mask_elem.text = p1['netmask']
    p1_host_elem.text = f'{hostname}-P1.mgmt.medcity.net'

    # Set P2 Interface Settings
    p2_elem = tree.find('interfaces/interface/[phys_interface="P2"]')
    p2_ip_elem = p2_elem.find('ip')
    p2_mask_elem = p2_elem.find('netmask')
    p2_host_elem = p2_elem.find('interface_hostname')
    p2_ip_elem.text = p2['ip']
    p2_mask_elem.text = p2['netmask']
    p2_host_elem.text = f'{hostname}-P2.mgmt.medcity.net'

    # Set Management Interface Settings
    mgmt_intf_elem = tree.find('interfaces/interface/[phys_interface="Management"]')
    mgmt_ip_elem = mgmt_intf_elem.find('ip')
    mgmt_mask_elem = mgmt_intf_elem.find('netmask')
    mgmt_host_elem = mgmt_intf_elem.find('interface_hostname')
    mgmt_ip_elem.text = mgmtIP['ip']
    mgmt_mask_elem.text = mgmtIP['netmask']
    mgmt_host_elem.text = f'{hostname}.mgmt.medcity.net'

    #
    #
    # Set DNS servers
    local_dns_elem = tree.find('dns/local_dns')
    # Reset DNS config
    for elem in local_dns_elem:
        local_dns_elem.remove(elem)
    # Set current environment DNS config
    for dns_server in dns:
        dns_server_host = Element('dns_ip', priority=str(dns.index(dns_server)))
        dns_server_host.text = dns_server
        local_dns_elem.append(dns_server_host)

    #
    #
    # Configure NTP servers
    ntp_elem = tree.find('ntp')
    # Reset NTP element
    for elem in ntp_elem:
        ntp_elem.remove(elem)
    # Set current environment NTP config
    for ntp_server in ntp:
        ntp_server_host = Element('ntp_server')
        ntp_server_host.text = ntp_server
        ntp_elem.append(ntp_server_host)

    ntp_query_interval = Element('ntp_query_interval')
    ntp_syncup_min_delay = Element('ntp_syncup_min_delay')
    ntp_routing_table = Element('ntp_routing_table')
    ntp_use_auth = Element('ntp_use_auth')

    ntp_query_interval.text = '86400'
    ntp_syncup_min_delay.text = '500'
    ntp_routing_table.text = '0'
    ntp_use_auth.text = '0'

    ntp_elem.append(ntp_query_interval)
    ntp_elem.append(ntp_syncup_min_delay)
    ntp_elem.append(ntp_routing_table)
    ntp_elem.append(ntp_use_auth)

    timezone = tree.find('timezone')
    timezone.text = kwargs['timezone']

    #
    #
    # Set Authentication Realm Servers
    servers_elem = tree.find('wga_config/prox_config_auth_realms/prox_config_auth_realm/prox_config_auth_realm_ad/'
                             'prox_config_auth_realm_ad_servers')
    # Reset Auth Realm Servers
    for elem in servers_elem:
        servers_elem.remove(elem)
    # Set current environment Auth Servers
    for server in auth_servers:
        ad_server = Element('prox_config_auth_realm_ad_server')
        ad_server_host = Element('prox_config_auth_realm_ad_server_host')
        ad_server_host.text = server
        ad_server.append(ad_server_host)
        servers_elem.append(ad_server)

    #
    #
    # Get routing XML file and set gateways
    api = GithubAPI()
    route_content = api.get_file_content(file_path='wsa/wsa_routes.xml')

    routes = etree.fromstring(route_content)

    # Set external gateway on external routes
    external_gateways = routes.findall('routing_table/[routing_table_interface="Data"]/routes/'
                                       'route/[gateway="external_gateway"]/gateway')
    for elem in external_gateways:
        elem.text = extGateway

    # Set internal gateway on internal routes
    internal_gateways = routes.findall('routing_table/[routing_table_interface="Data"]/routes/'
                                       'route/[gateway="internal_gateway"]/gateway')
    for elem in internal_gateways:
        elem.text = intGateway

    # Set default gateway on data routing table
    default_router_elem = routes.find('routing_table/[routing_table_defaultrouter="external_gateway"]/'
                                      'routing_table_defaultrouter')
    default_router_elem.text = extGateway

    #  Set mgmt gateway on management routing table
    mgmt_gateway_elem = routes.find('routing_table/[routing_table_defaultrouter="mgmt_gateway"]/'
                                    'routing_table_defaultrouter')
    mgmt_gateway_elem.text = mgmtGateway

    routing_tables = tree.find('routing_tables')
    for elem in routing_tables:
        routing_tables.remove(elem)

    for elem in routes:
        routing_tables.append(elem)

    #
    #
    # Configure Radius Service
    radius_hosts = tree.find('service_profiles/service_profile/[service_name="radius"]/service_settings/'
                             'radius_service_hosts')
    # Reset Radius Services
    for elem in radius_hosts:
        radius_hosts.remove(elem)
    # Configure Radius Services
    p_radius_hostname = Element('radius_hostname')
    p_radius_hostname.text = ('10.90.42.49' if frdcRadius else '10.27.21.99')
    s_radius_hostname = Element('radius_hostname')
    s_radius_hostname.text = ('10.27.21.99' if frdcRadius else '10.90.42.49')
    p_radius_port = Element('radius_port')
    p_radius_port.text = '1812'
    s_radius_port = Element('radius_port')
    s_radius_port.text = '1812'
    p_radius_shared_secret = Element('radius_shared_secret')
    p_radius_shared_secret.text = 'fYiqjiaw'
    s_radius_shared_secret = Element('radius_shared_secret')
    s_radius_shared_secret.text = 'fYiqjiaw'
    p_radius_timeout = Element('radius_timeout')
    p_radius_timeout.text = '5'
    s_radius_timeout = Element('radius_timeout')
    s_radius_timeout.text = '5'

    p_radius_auth_type = Element('radius_auth_type')
    p_radius_auth_type.text = 'pap'
    p_radius_cert_type = Element('radius_cert_type')
    p_radius_cert_type.text = 'None'
    s_radius_auth_type = Element('radius_auth_type')
    s_radius_auth_type.text = 'pap'
    s_radius_cert_type = Element('radius_cert_type')
    s_radius_cert_type.text = 'None'

    primary_radius = Element('radius_service_host')
    primary_radius.append(p_radius_hostname)
    primary_radius.append(p_radius_port)
    primary_radius.append(p_radius_shared_secret)
    primary_radius.append(p_radius_timeout)
    primary_radius.append(p_radius_auth_type)
    primary_radius.append(p_radius_cert_type)

    radius_hosts.append(primary_radius)

    secondary_radius = Element('radius_service_host')
    secondary_radius.append(s_radius_hostname)
    secondary_radius.append(s_radius_port)
    secondary_radius.append(s_radius_shared_secret)
    secondary_radius.append(s_radius_timeout)
    secondary_radius.append(s_radius_auth_type)
    secondary_radius.append(s_radius_cert_type)

    radius_hosts.append(secondary_radius)

    #
    #
    # Configure CLI Service Profile
    cli_radius_hosts = tree.find('cli_service_profiles/cli_service_profile/[cli_service_name="radius"]/'
                                 'cli_service_settings/cli_radius_service_hosts')
    # Reset CLI Service Profiles
    for elem in cli_radius_hosts:
        cli_radius_hosts.remove(elem)
    # Configure CLI Service Profiles
    p_cli_radius_hostname = Element('cli_radius_hostname')
    p_cli_radius_hostname.text = ('10.90.42.49' if frdcRadius else '10.27.21.99')
    s_cli_radius_hostname = Element('cli_radius_hostname')
    s_cli_radius_hostname.text = ('10.27.21.99' if frdcRadius else '10.90.42.49')
    p_cli_radius_port = Element('cli_radius_port')
    p_cli_radius_port.text = '1812'
    p_cli_radius_shared_secret = Element('cli_radius_shared_secret')
    p_cli_radius_shared_secret.text = 'fYiqjiaw'
    p_cli_radius_timeout = Element('cli_radius_timeout')
    p_cli_radius_timeout.text = '5'
    p_cli_radius_auth_type = Element('cli_radius_auth_type')
    p_cli_radius_auth_type.text = 'pap'
    p_cli_radius_cert_type = Element('cli_radius_cert_type')
    p_cli_radius_cert_type.text = 'None'
    s_cli_radius_port = Element('cli_radius_port')
    s_cli_radius_port.text = '1812'
    s_cli_radius_shared_secret = Element('cli_radius_shared_secret')
    s_cli_radius_shared_secret.text = 'fYiqjiaw'
    s_cli_radius_timeout = Element('cli_radius_timeout')
    s_cli_radius_timeout.text = '5'
    s_cli_radius_auth_type = Element('cli_radius_auth_type')
    s_cli_radius_auth_type.text = 'pap'
    s_cli_radius_cert_type = Element('cli_radius_cert_type')
    s_cli_radius_cert_type.text = 'None'

    primary_cli_radius = Element('cli_radius_service_host')
    primary_cli_radius.append(p_cli_radius_hostname)
    primary_cli_radius.append(p_cli_radius_port)
    primary_cli_radius.append(p_cli_radius_shared_secret)
    primary_cli_radius.append(p_cli_radius_timeout)
    primary_cli_radius.append(p_cli_radius_auth_type)
    primary_cli_radius.append(p_cli_radius_cert_type)

    cli_radius_hosts.append(primary_cli_radius)

    secondary_cli_radius = Element('cli_radius_service_host')
    secondary_cli_radius.append(s_cli_radius_hostname)
    secondary_cli_radius.append(s_cli_radius_port)
    secondary_cli_radius.append(s_cli_radius_shared_secret)
    secondary_cli_radius.append(s_cli_radius_timeout)
    secondary_cli_radius.append(s_cli_radius_auth_type)
    secondary_cli_radius.append(s_cli_radius_cert_type)

    cli_radius_hosts.append(secondary_cli_radius)

    #
    #
    # Configure SNMP settings
    snmp_sys_location = tree.find('snmp/syslocation')
    snmp_sys_location.text = snmpLocation

    snmp_community_elem = tree.find('snmp/community')
    snmp_trap_comm_elem = tree.find('snmp/trapcommunity')
    snmp_auth_elem = tree.find('snmp/authpassphrase')
    snmp_priv_elem = tree.find('snmp/privpassphrase')
    snmp_community = requests.post('https://pyapis.ocp.app.medcity.net/apis/admin/get_current_snmp_strings',
                                   json={'APIKey': os.getenv('localapikey'), 'Trusted': True},
                                   verify=False).json()['rw']
    snmp_community_elem.text = snmp_community
    snmp_trap_comm_elem.text = snmp_community
    snmp_auth_elem.text = snmp_community
    snmp_priv_elem.text = snmp_community

    #
    #
    # Configure log settings
    log_name_elem = tree.find(f'log_subscriptions/log_w3c_accesslog/[name="{TEMP_MGMT_IP}"]/name')
    log_dest_elem = tree.find(f'log_subscriptions/log_w3c_accesslog/[name="{TEMP_MGMT_IP}"]/retrieval/'
                              f'syslog_push/hostname')

    log_name_elem.text = mgmtIP['ip']
    log_dest_elem.text = kwargs['logging']

    #
    #
    # Configure wga_config (auth realms)
    wga_config = tree.find('wga_config')
    auth_realm_username = tree.find(f'wga_config/prox_config_auth_realms/prox_config_auth_realm/'
                                    f'prox_config_auth_realm_ad/[prox_config_auth_realm_ad_username="{TEMP_HOST}$"]/'
                                    f'prox_config_auth_realm_ad_username')

    for elem in list(wga_config):
        if elem.tag == 'prox_etc_continue_custom_text':
            elem.text = f"""You can read the IT&S Electronic Communications policy here: <a href="http://connect.medcity.net/c/document_library/get_file?uuid=93d46e19-3e82-478d-9b49-1d6829182d4c&groupId=42069440"> IP.SEC.002</a>. <b> {hostname} </b>"""
        if elem.tag == 'prox_etc_error_page_custom_text':
            elem.text = f"""You can read the IT&S Electronic Communications policy here: <a href="http://connect.medcity.net/c/document_library/get_file?uuid=93d46e19-3e82-478d-9b49-1d6829182d4c&groupId=42069440"> IP.SEC.002</a>. <b> {hostname} </b>"""
        if elem.tag == 'prox_etc_ftp_eun_message':
            elem.text = f"""You can read the IT&S Electronic Communications policy here: <a href="http://connect.medcity.net/c/document_library/get_file?uuid=93d46e19-3e82-478d-9b49-1d6829182d4c&groupId=42069440"> IP.SEC.002</a>. <b> {hostname} </b>"""
        if elem.tag == 'prox_etc_transparent_auth_server':
            elem.text = f'{hostname}-P1.mgmt'

    auth_realm_username.text = f'{hostname}$'

    tree.write('../wsa/wsa_config_gen.xml', doctype='<!DOCTYPE config SYSTEM "config.dtd">', xml_declaration=True)
    # Configuration generated per appliance and uploaded
    #
    #
    #
    #
    #
    # Login to WSA management interface and upload XML configuration file wsa_config_gen.xml
    host = mgmtIP['ip']

    session = requests.session()
    session.verify = False
    resp = session.get(f'https://{host}:8443')

    soup = BeautifulSoup(resp.text, features='lxml')

    form = soup.form
    form = etree.fromstring(str(form))
    referrer = form.find('input/[@name="referrer"]')
    screen = form.find('input/[@name="screen"]')
    csrfKey = form.find('input/[@name="CSRFKey"]')
    # print(csrfKey.attrib['value'])

    loginData = {
        'action': 'Login',
        'username': kwargs['username'],
        'password': kwargs['password'],
        'action_type': 'ajax_validation',
        'referrer': referrer.attrib['value'],
        'screen': screen.attrib['value'],
        'CSRFKey': csrfKey.attrib['value']
    }

    session.headers['X-Requested-With'] = 'XMLHttpRequest'
    resp = session.post(f'https://{host}:8443/login', data=loginData)
    del loginData['action_type']
    resp = session.post(f'https://{host}:8443/login', data=loginData)

    if 'logged in as' not in resp.text.lower():
        failed_attempts.append([wsa['hostname'], 'Failed Login'])
        return None

    resp = session.get(f'https://{host}:8443/system_administration/configuration/configuration_file')
    csrfKey = re.search('CSRFKey=[a-z0-9-]+', resp.text).group()[8:]

    session.headers['Referer'] = f'https://{host}:8443/system_administration/configuration/configuration_file'
    session.headers['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/' \
                                'apng,*/*;q=0.8,application/signed-exchange;v=b3'
    session.headers['Origin'] = f'https://{host}:8443'
    session.headers['Upgrade-Insecure-Requests'] = '1'

    files = {
        'action': (None, 'Load'),
        'operation': (None, 'download'),
        'password_config': (None, 'plain_passwords'),
        'filename': (None, 'system'),
        'load_from': (None, 'from_local'),  # Was from_buffer
        'local_file': ('wsa.xml', open('../wsa/wsa_config_gen.xml', 'r').read(), 'text/xml'),
        'load_nw_settings': (None, '1'),
        'CSRFKey': (None, csrfKey)
    }

    resp = session.post(f'https://{host}:8443/system_administration/configuration/configuration_file',
                        files=files)

    if "success" not in resp.text.lower():
        # print(f'{wsa["hostname"]} Configuration Upload failed')
        failed_attempts.append([wsa['hostname'], 'Configuration Upload Failure'])
        return None

    file1 = {
        'action': (None, 'ImportRootCACertificate'),
        'certificate': ('HCA Internal Root CA.crt', open('../wsa/HCA Internal Root CA.crt', 'r').read(),
                        'application/x-x509-ca-cert'),
        'CSRFKey': (None, csrfKey)
    }

    file2 = {
        'action': (None, 'ImportRootCACertificate'),
        'certificate': (
            'HCA Internal Issuing CA 03.crt', open('../wsa/HCA Internal Issuing CA 03.crt', 'r').read(),
            'application/x-x509-ca-cert'),
        'CSRFKey': (None, csrfKey)
    }

    session.get(f'https://{host}:8443/network/cert/cert_management')

    session.post(f'https://{host}:8443/network/cert/cert_management', files=file1)
    session.post(f'https://{host}:8443/network/cert/cert_management', files=file2)

    commitPost = {
        'action': 'Commit',
        'screen': 'commit',
        'logout': '',
        'comment': '',
        'CSRFKey': csrfKey
    }

    resp = session.post(f'https://{host}:8443/commit', data=commitPost)

    upload_payload = {
        'action': 'UploadCertificate',
        'freshGeneratedCert': None,
        'was_enabled': 0,
        'fresh_uploaded_cert': None,
        'enabled': 1,
        'httpsPorts': 443,
        'generatedCertPresence': False,
        'uploadedCertPresence': False,
        'certType': 'Uploaded',
        'uploadCertName': 'C:\\fakepath\\star.mgmt.medcity.net.crt',
        'uploadKeyName': 'C:\\fakepath\\star.mgmt.medcity.net.key',
        'encrypted_key_password': 'yfHSkz5HirQ5ERnjAFvz',
        'decrypt_https_for_auth': 1,
        'decrypt_for_eun': 1,
        'decrypt_for_eua': 0,
        'invalidGroup[0]': 'scan',
        'invalidGroup[1]': 'scan',
        'invalidGroup[2]': 'scan',
        'invalidGroup[3]': 'scan',
        'invalidGroup[4]': 'scan',
        'invalidGroup[5]': 'scan',
        'ocsp_enabled': 0,
        'ocspGroup[0]': 'drop',
        'ocspGroup[1]': 'scan',
        'ocspGroup[2]': 'scan',
        'ocsp_valid_response_cache_ttl': '1h',
        'ocsp_invalid_response_cache_ttl': '2m',
        'ocsp_network_error_cache_timeout': '1m',
        'ocsp_clock_skew': '5m',
        'ocsp_network_error_timeout': '10s',
        'actionName': None,
        'genCertCommonName': None,
        'genCertOrganization': None,
        'genCertOrganizationUnit': None,
        'genCertCountry': None,
        'genCertExpiration': None,
        'genCertIsCritical': None,
        'CSRFKey': csrfKey
    }

    files = {
        'uploadCertificate': ('star.mgmt.medcity.net.crt', open('../wsa/star.mgmt.medcity.net.crt', 'r').read(),
                              'application/x-x509-ca-cert'),
        'uploadKey': ('star.mgmt.medcity.net.key', open('../wsa/star.mgmt.medcity.net.key', 'r').read(),
                      'application/octet-stream')
    }

    session.get(f'https://{host}:8443/security_services/web_proxy/https_proxy')
    session.headers['Content-Type'] = 'application/x-www-form-urlencoded'
    session.post(f'https://{host}:8443/security_services/web_proxy/https_proxy',
                 data=f'action=FormEditHTTPSProxy&CSRFKey={csrfKey}')
    session.post(f'https://{host}:8443/security_services/web_proxy/https_proxy',
                 data=f'action=&action:AcceptLicense=Accept&CSRFKey={csrfKey}')
    del session.headers['Content-Type']
    upload_r = session.post(f'https://{host}:8443/security_services/web_proxy/https_proxy', files=files,
                            data=upload_payload)
    # print('Upload Response:\n\n')

    soup = BeautifulSoup(upload_r.text, features='lxml')
    form = soup.find(id='form')
    submit_payload = {}
    for t in form.find_all('input'):
        if t.get('name') is not None and t.get('name') in upload_payload.keys():
            submit_payload[t.get('name')] = (None, t.get('value'))
    submit_payload['action'] = (None, 'EditHTTPSProxy')
    submit_payload['CSRFKey'] = (None, csrfKey)
    submit_payload['certType'] = (None, 'Uploaded')
    submit_payload['decrypt_for_eua'] = (None, 0)
    submit_payload['ocsp_enabled'] = (None, 0)

    submit_r = session.post(f'https://{host}:8443/security_services/web_proxy/https_proxy', files=submit_payload)

    session.post(f'https://{host}:8443/commit', data=commitPost)

    # Enable ISE, Configure ISE, and Upload Certificates

    # ise_primary = 'fwdclpidmise01a.hca.corpad.net'
    # ise_secondary = 'xrdclpidmise01a.hca.corpad.net'
    #
    # ise_payload = f'action=FormEdit&CSRFKey={csrfKey}'
    #
    # session.get(f'https://{host}:8443/network/identity_services/ise')
    # enable_r = session.post(f'https://{host}:8443/network/identity_services/ise', data=ise_payload,
    #                         headers={'Content-Type': 'application/x-www-form-urlencoded'})
    #
    # p_upload_p = {'action': 'UploadPxGridCertificate',
    #               'ise_server': ise_primary,
    #               'CSRFKey': csrfKey}
    # p_upload_f = {
    #     'uploadPxGridCertificate': ('HCAPrimarypxGridCert.pem', open('../wsa/HCAPrimarypxGridCert.pem', 'r').read(),
    #                                 'application/octet-stream')}
    #
    # p_upload_r = session.post(f'https://{host}:8443/network/identity_services/ise', data=p_upload_p, files=p_upload_f)
    #
    # soup = BeautifulSoup(p_upload_r.text, features='lxml')
    # p_upload_v = soup.find('input', {'name': 'freshPxGridCert'}).get('value')
    #
    # s_upload_p = {
    #     'action': 'UploadSecondaryPxGridCertificate',
    #     'uploadedPxGridCertPresence': True,
    #     'freshPxGridCert': p_upload_v,
    #     'ise_server': ise_primary,
    #     'ise_server_secondary': ise_secondary,
    #     'CSRFKey': csrfKey
    # }
    # s_upload_f = {
    #     'uploadSecondaryPxGridCertificate': ('HCASecondarypxGridCert.pem',
    #                                          open('../wsa/HCASecondarypxGridCert.pem', 'r').read(),
    #                                          'application/octet-stream')}
    #
    # s_upload_r = session.post(f'https://{host}:8443/network/identity_services/ise', data=s_upload_p, files=s_upload_f)
    #
    # soup = BeautifulSoup(s_upload_r.text, features='lxml')
    # s_upload_v = soup.find('input', {'name': 'freshSecondaryPxGridCert'}).get('value')
    #
    # w_upload_p = {
    #     'action': 'UploadCertificate',
    #     'certType': 'Uploaded',
    #     'uploadCertName': 'C:\\fakepath\\hcaisepxgridbmultisan.pem',
    #     'uploadKeyName': 'C:\\fakepath\\hcaisepxgridbmultisan.pvk',
    #     'ise_server': ise_primary,
    #     'uploadedPxGridCertPresence': True,
    #     'freshPxGridCert': p_upload_v,
    #     'ise_server_secondary': ise_secondary,
    #     'uploadedSecondaryPxGridCertPresence': True,
    #     'freshSecondaryPxGridCert': s_upload_v,
    #     'encrypted_key': 1,
    #     'encrypted_key_password': 'ytiruces',
    #     'CSRFKey': csrfKey
    # }
    #
    # w_upload_f = {
    #     'uploadCertificate': ('hcaisepxgridbmultisan.pem', open('../wsa/hcaisepxgridbmultisan.pem', 'r').read(),
    #                           'application/octet-stream'),
    #     'uploadKey': ('hcaisepxgridbmultisan.pvk', open('../wsa/hcaisepxgridbmultisan.pvk', 'r').read(),
    #                   'application/octet-stream')}
    #
    # w_upload_r = session.post(f'https://{host}:8443/network/identity_services/ise', data=w_upload_p, files=w_upload_f)
    #
    # soup = BeautifulSoup(w_upload_r.text, features='lxml')
    # w_upload_c_v = soup.find('input', {'name': 'freshUploadedCert'}).get('value')
    #
    # edit_payload = {
    #     'action': 'Edit',
    #     'freshUploadedCert': w_upload_c_v,
    #     'freshPxGridCert': p_upload_v,
    #     'freshSecondaryPxGridCert': s_upload_v,
    #     'enabled': 1,
    #     'ise_server': ise_primary,
    #     'uploadedPxGridCertPresence': True,
    #     'ise_server_secondary': ise_secondary,
    #     'uploadedSecondaryPxGridCertPresence': True,
    #     'uploadedCertPresence': True,
    #     'certType': 'Uploaded',
    #     'encrypted_key': 1,
    #     'CSRFKey': csrfKey
    # }
    #
    # edit_r = session.post(f'https://{host}:8443/network/identity_services/ise', data=edit_payload)

    # session.post(f'https://{host}:8443/commit', data=commitPost)

    # Logout and Close WSA Session
    session.get(f'https://{host}:8443/login?action=Logout&CSRFKey={csrfKey}')
    session.close()

    os.remove('wsa_config_gen.xml')

    return True


def build_wsa_api(wsa_env: str, wsa_list: str, username: str, password: str):
    if wsa_env.upper() not in ['FRDC', 'SEDC', 'SLDC', 'TPDC', 'XRDC']:
        return 400, {'message': f'Invalid Environment provided: {wsa_env}'}
    else:
        wsa_env = f'{wsa_env.upper()}-WSA'

    wsa_data = json.load(open('data/wsa.json'))

    wsa_env = wsa_data[wsa_env]

    if wsa_list.upper() == 'ALL':
        wsa_list = [re.search(r'\D+$', wsa['hostname']).group() for environment in wsa_env['environments']
                    for wsa in wsa_env['environments'][environment]['wsaList']]
    else:
        wsa_list = re.split(r'[,\s]+', wsa_list)

    wsa_list.sort()

    wsa_credentials = {
        'username': username,
        'password': password
    }

    urllib3.disable_warnings()

    for environment in wsa_env['environments']:
        for wsa in wsa_env['environments'][environment]['wsaList']:
            if re.search(r'\D+$', wsa['hostname']).group() in wsa_list:
                print(wsa['hostname'], wsa['mgmtIP'])
                wsa_mgmt_network = IPv4Network(wsa['mgmtIP'], strict=False)
                wsa_mgmt_gateway = str(wsa_mgmt_network.network_address + 1)
                buildWSA(intGateway=wsa_env['environments'][environment]['internal_gateway'],
                         extGateway=wsa_env['environments'][environment]['external_gateway'],
                         mgmtGateway=wsa_mgmt_gateway, **wsa, **wsa_env, **wsa_credentials)

    return 200, {'message': 'I did my best!  You should definitely go check on them!'}


if __name__ == '__main__':
    failed_attempts = []

    site = input('\nFRDC\nSEDC\nSLDC\nTPDC\nXRDC\n\n'
                 'Enter the environment you would like to build or type \'cancel\' to abort: ').upper()

    if site.lower() == 'cancel':
        print('   Exiting...')
        exit()
    elif site not in ['FRDC', 'SEDC', 'SLDC', 'TPDC', 'XRDC']:
        print(f'Invalid Environment provided: {site}')
        exit()
    else:
        site += '-WSA'

    data = json.load(open('../data/wsa.json'))

    site = data[site]

    subset = input("Provide a comma separated list of the WSAs letters you wish to configure or type 'all' "
                   "(ie 'A, B, C, AA' or 'a,B, aa'): ").upper()

    if subset == 'ALL':
        subset = [re.search(r'\D+$', wsa['hostname']).group() for environment in site['environments']
                  for wsa in site['environments'][environment]['wsaList']]
    else:
        subset = re.split(r'[,\s]+', subset)

    subset.sort()
    print('\n\nThese WSAs will be configured:', subset)
    proceed = input('\nDo you wish to continue (y/n)? ').upper()

    if proceed.startswith('N'):
        print('Aborting')
        sys.exit(0)

    credentials = {
        'username': input('Enter the username to be used for all logins: '),
        'password': getpass('Enter the password: ')
        # 'password': 'ironport'
    }

    urllib3.disable_warnings()

    for environment in site['environments']:
        for wsa in site['environments'][environment]['wsaList']:
            if re.search(r'\D+$', wsa['hostname']).group() in subset:
                print(wsa['hostname'], wsa['mgmtIP'])
                mgmt_network = IPv4Network(wsa['mgmtIP'], strict=False)
                mgmt_gateway = str(mgmt_network.network_address + 1)
                if not buildWSA(intGateway=site['environments'][environment]['internal_gateway'],
                                extGateway=site['environments'][environment]['external_gateway'],
                                mgmtGateway=mgmt_gateway, **wsa, **site, **credentials):
                    print(wsa['hostname'], 'failed')

    if failed_attempts:
        for _ in failed_attempts:
            print(_)
