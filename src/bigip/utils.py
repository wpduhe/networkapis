from f5.bigip import ManagementRoot
from socket import gethostbyname, gethostbyaddr, herror, gaierror
from ipaddress import IPv4Address, IPv4Network
from data.environments import F5Environment
from ipam.utils import NetworkAPIIPAM
from typing import List
from io import BytesIO
from githubapi.utils import GithubAPI
from types import SimpleNamespace
import requests
import json
import re
import time
import paramiko
import os


def jsonload(response: requests.Response) -> SimpleNamespace:
    if response.ok:
        return json.loads(response.text, object_hook=lambda x: SimpleNamespace(**x))


def tonamespace(d: dict) -> SimpleNamespace:
    return json.loads(json.dumps(d), object_hook=lambda x: SimpleNamespace(**x))


class BaseLTMObject:
    deletable_attributes = ['selfLink', 'generation', 'fullPath', 'membersReference', 'creationTime',
                            'fallbackPersistenceReference', 'lastModifiedTime', 'poolReference', 'vsIndex',
                            'rulesReference', 'ruleReference', 'policiesReference', 'profilesReference', 'profiles_s',
                            'members_s', 'certReference', 'chainReference', 'defaultsFromReference', 'keyReference',
                            'securityLogProfiles', 'securityLogProfilesReference', 'requestChunking',
                            'responseChunking']

    kind: str

    def dict(self):
        json_data = {}
        for attr in self.__dict__:
            if self.__getattribute__(attr) is not None:
                json_data[attr] = self.__getattribute__(attr)
        return json_data

    def object_uri(self):
        uri = str(self.kind)
        uri = uri.split(':')
        uri = f'/{"/".join(uri[:-1])}'
        return uri

    @classmethod
    def load(cls, **kwargs):
        _obj = cls()
        for arg in kwargs:
            _obj.__setattr__(arg, kwargs[arg])

        return _obj

    @staticmethod
    def remove_deletable_attrs(_obj):
        for _ in _obj.attrs.keys():
            if _ in BaseLTMObject.deletable_attributes:
                _obj.__delattr__(_)


class VIP(BaseLTMObject):
    def __init__(self):
        self.name = None
        self.partition = '/Common/'
        self.addressStatus = 'yes'
        self.ipProtocol = None
        self.destination = None
        self.enabled = True
        self.mask = '255.255.255.255'
        self.profiles = [{'name': 'http', 'context': 'all'}]
        self.pool = None
        self.sourceAddressTranslation = {'type': 'automap'}
        self.sourcePort = 'preserve'
        self.translateAddress = 'enabled'
        self.persist = []
        self.rules = []
        self.kind = 'tm:ltm:virtual:virtualstate'


class Pool(BaseLTMObject):
    def __init__(self):
        self.name = None
        self.partition = 'Common'
        self.loadBalancingMode = 'observed-member'
        self.monitor = None
        self.members = []
        self.kind = 'tm:ltm:pool:poolstate'
        self.serviceDownAction = 'reset'


class Monitor(BaseLTMObject):
    def __init__(self, _type: str):
        self.name: None
        self.partition = 'Common'
        self.kind = f'tm:ltm:monitor:{_type}:{_type}state'


class Rule(BaseLTMObject):
    def __init__(self):
        self.name = None
        self.apiAnonymous = None
        self.partition = 'Common'
        self.kind = 'tm:ltm:rule:rulestate'


class SSLCert(BaseLTMObject):
    def __init__(self):
        self.name = None
        self.kind = 'tm:sys:file:ssl-cert:ssl-certstate'


class SSLKey(BaseLTMObject):
    def __init__(self):
        self.name = None
        self.kind = 'tm:sys:file:ssl-key:ssl-keystate'


class LTM:
    env = None

    default_monitors = ['diameter', 'dns', 'external', 'firepass', 'ftp', 'gateway-icmp', 'http', 'https', 'icmp',
                        'imap', 'inband', 'ldap', 'module-score', 'mqtt', 'mssql', 'mysql', 'nntp', 'none', 'oracle',
                        'pop3', 'postgresql', 'radius', 'radius-accounting', 'real-server', 'rpc', 'sasp', 'scripted',
                        'sip', 'smb', 'smtp', 'snmp-dca', 'snmp-dca-base', 'soap', 'tcp', 'tcp-echo', 'tcp-half-open',
                        'udp', 'virtual-location', 'wap', 'wmi']
    default_profiles = ['analytics', 'certificate-authority', 'client-ldap', 'client-ssl', 'connector', 'dhcpv4',
                        'dhcpv6', 'diameter', 'dns', 'dns-logging', 'fasthttp', 'fastl4', 'fix', 'ftp', 'gtp', 'html',
                        'http', 'http-compression', 'http-proxy-connect', 'http2', 'httprouter', 'icap', 'ilx', 'imap',
                        'ipother', 'ipsecalg', 'mblb', 'mqtt', 'netflow', 'ntlm', 'ocsp-stapling-params', 'one-connect',
                        'pop3', 'pptp', 'qoe', 'radius', 'request-adapt', 'request-log', 'response-adapt', 'rewrite',
                        'rtsp', 'sctp', 'server-ldap', 'server-ssl', 'service', 'sip', 'smtps', 'socks',
                        'splitsessionclient', 'splitsessionserver', 'statistics', 'stream', 'tcp', 'tcp-analytics',
                        'tftp', 'udp', 'web-acceleration', 'websocket', 'xml', 'serverssl']
    default_persistence = ['cookie', 'dest-addr', 'global-settings', 'hash', 'host', 'msrdp', 'sip', 'source-addr',
                           'ssl', 'universal', ]

    def __init__(self, host, username: str=None, password: str=None):
        self.host = host
        if username and password:
            self.mgmt = ManagementRoot(host, username=username, password=password)
        else:
            self.mgmt = ManagementRoot(host, username=os.getenv('netmgmtuser'), password=os.getenv('netmgmtpass'))
        self.ssl_profile_list = self.mgmt.tm.ltm.profile.client_ssls.get_collection()
        self.wildcard_certs = list((profile.name for profile in self.ssl_profile_list
                                    if profile.name.lower().startswith('star.')))
        self.destination_list = list(set((re.search(r'[.:\d]+', vip.destination).group()
                                          for vip in self.mgmt.tm.ltm.virtuals.get_collection())))
        self.destination_list.sort()
        self.vip_address_list = list(set((re.search(r'[.\d]+', vip.destination).group()
                                          for vip in self.mgmt.tm.ltm.virtuals.get_collection())))
        self.vip_address_list.sort()
        self.self_ips = self.mgmt.tm.net.selfips.get_collection()
        self.self_ips = list((ip.name for ip in self.self_ips))

    def ssh_command(self, command: str=None, commands: list=None):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(self.host, username=os.getenv('netmgmtuser'), password=os.getenv('netmgmtpass'))

        if command:
            stdin, stdout, stderr = ssh.exec_command(command)
            output = stdout.readlines()

        elif commands:
            output = []
            for command in commands:
                stdin, stdout, stderr = ssh.exec_command(command)
                output += stdout.readlines()

        else:
            output = []

        ssh.close()

        return ''.join(output)

    @staticmethod
    def ip_is_vip(ip: str):
        """Returns True or False based on whether an IP address falls in a defined VIP range"""
        envs = json.load(open('data/F5Environments.json', 'r'))
        address = IPv4Address(ip)
        for env in envs:
            for pool in env['iPPoolsField']:
                network = IPv4Network(pool)
                if address in list(network.hosts()):
                    return True
        return False

    @classmethod
    def login_to_pair(cls, device_pair: list, username: str=None, password: str=None):
        """Given a pair of LTM management addresses, login to the active unit."""
        assert len(device_pair) <= 2, 'device_pair cannot exceed 2 devices'
        if username and password:
            ltm = cls(device_pair[0], username=username, password=password)
        else:
            ltm = cls(device_pair[0])
        failover = ltm.mgmt.tm.sys.failover.load()
        if 'active' in failover.apiRawValues['apiAnonymous']:
            return ltm
        else:
            if username and password:
                ltm = cls(device_pair[1], username=username, password=password)
            else:
                ltm = cls(device_pair[1])
            return ltm

    @classmethod
    def login_to_environment(cls, env, username: str=None, password: str=None):
        env = F5Environment(env)
        if username and password:
            ltm = cls.login_to_pair(env.devicesField, username=username, password=password)
        else:
            ltm = cls.login_to_pair(env.devicesField)

        ltm.env = env

        return ltm

    def sync_environment(self):
        failover = self.mgmt.tm.sys.failover.load()

        if self.env:
            if 'active' in failover.apiRawValues['apiAnonymous']:
                self.mgmt.tm.cm.exec_cmd('run', utilCmdArgs=f'config-sync to-group {self.env.deviceGroupNameField}')
            else:
                raise Exception(['Device is not active unit'])
        else:
            groups = self.mgmt.tm.cm.device_groups.get_collection()
            group = next(group for group in groups if group.type == 'sync-failover')

            if 'active' in failover.apiRawValues['apiAnonymous']:
                self.mgmt.tm.cm.exec_cmd('run', utilCmdArgs=f'config-sync to-group {group.name}')

            pass

    def get_pool(self, pool_name):
        pool = self.mgmt.tm.ltm.pools.pool.load(name=pool_name)
        return pool

    def get_pool_members(self, pool_name):
        pool = self.get_pool(pool_name)
        members_collection = pool.members_s.get_collection()
        members = list(({'name': member.name, 'address': member.address} for member in members_collection))
        for member, member_c in zip(members, members_collection):
            member['status'] = member_c.stats.raw['_meta_data']['container'].state
            try:
                member['fqdn'] = gethostbyaddr(member['address'])[0]
            except herror:
                pass
        return members

    def get_vip_by_address(self, vip_address):
        vips = self.mgmt.tm.ltm.virtuals.get_collection()
        vip = next(vip for vip in vips if f'/{vip_address}:' in vip.destination and 'pool' in vip.attrs)
        return vip

    def get_vip_by_destination(self, vip_address: str, vip_port: str or int):
        vips = self.mgmt.tm.ltm.virtuals.get_collection()
        # Removed search for pool as sometimes there are redirect VIPs that do not have a pool defined
        vip = next(vip for vip in vips if f'/{vip_address}:{vip_port}' in vip.destination)  # and 'pool' in vip.attrs)
        return vip

    @staticmethod
    def get_vip_data(env: str):
        ltm = LTM.login_to_environment(env)
        vip_data = list((vip for vip in ltm.mgmt.tm.ltm.virtuals.get_collection()))
        vip_list = {}
        for vip in vip_data:
            address = re.search(r'[.\d]+', vip.destination).group()
            if address not in vip_list.keys():
                vip_list[address] = []
            name = vip.name
            vip_list[address].append(name)

        if '0.0.0.0' in vip_list.keys():
            del vip_list['0.0.0.0']
        return vip_list

    @classmethod
    def get_ltm_by(cls, fqdn: str=None, vip_address: str=None):
        envs = json.load(open('data/F5Environments.json', 'r'))

        if fqdn:
            address = IPv4Address(gethostbyname(fqdn))
        elif vip_address:
            address = IPv4Address(vip_address)
        else:
            raise ValueError('fqdn or address ')

        for env in envs:
            for pool in env['iPPoolsField']:
                network = IPv4Network(pool)
                if address in list(network.hosts()):
                    ltm = cls(env['devicesField'][0])
                    failover = ltm.mgmt.tm.sys.failover.load()
                    if 'active' in failover.apiRawValues['apiAnonymous']:
                        ltm.env = F5Environment(env['nameField'])
                        return ltm
                    else:
                        ltm = cls(env['devicesField'][1])
                        ltm.env = F5Environment(env['nameField'])
                        return ltm

    @staticmethod
    def get_pool_members_by_fqdn(fqdn):
        address = IPv4Address(gethostbyname(fqdn))
        ltm = LTM.get_ltm_by(fqdn=fqdn)
        vip = ltm.get_vip_by_address(str(address))
        members = ltm.get_pool_members(vip.pool.replace('/Common/', ''))
        return members

    @staticmethod
    def get_pool_members_by_address(address):
        ltm = LTM.get_ltm_by(vip_address=address)
        vip = ltm.get_vip_by_address(str(address))
        members = ltm.get_pool_members(vip.pool.replace('/Common/', ''))
        return members

    @staticmethod
    def get_vip_info_by_fqdn(fqdn):
        address = IPv4Address(gethostbyname(fqdn))
        ltm = LTM.get_ltm_by(fqdn=fqdn)
        vip = ltm.get_vip_by_address(str(address))
        pool = ltm.get_pool(vip.pool.replace('/Common/', ''))
        members = ltm.get_pool_members(vip.pool.replace('/Common/', ''))
        try:
            rules = vip.rules
        except AttributeError:
            rules = None
        return {
            'vip_name': vip.name,
            'address': vip.destination.replace('/Common/', ''),
            'pool': vip.pool.replace('/Common/', ''),
            'pool_monitor': pool.monitor,
            'members': members,
            'iRules': rules,
            'profiles': list((profile.name for profile in vip.profiles_s.get_collection())),
            'ltm_info': ltm.env.devicesField,
            'ltm_active': ltm.host,
            'ltm_env_name': ltm.env.nameField
        }

    def get_vip_info_by_destination(self, vip_address: str, vip_port: int or str):
        vip = self.get_vip_by_destination(vip_address, vip_port)
        members = self.get_pool_members(vip.pool.replace('/Common/', ''))
        return {
            'vip_name': vip.name,
            'address': vip.destination.replace('/Common/', ''),
            'pool': vip.pool.replace('/Common/', ''),
            'members': members,
            'iRules': vip.rules,
            'profiles': list((profile.name for profile in vip.profiles_s.get_collection()))
        }

    def create_pool(self, configuration: dict):
        return self.mgmt.tm.ltm.pools.pool.create(**configuration)

    def create_vip(self, configuration: dict):
        return self.mgmt.tm.ltm.virtuals.virtual.create(**configuration)

    def create_monitor(self, configuration: dict):
        if configuration['kind'].split(':')[3] == 'http':
            return self.mgmt.tm.ltm.monitor.https.http.create(**configuration)
        elif configuration['kind'].split(':')[3] == 'https':
            return self.mgmt.tm.ltm.monitor.https_s.https.create(**configuration)
        elif configuration['kind'].split(':')[3] == 'tcp':
            return self.mgmt.tm.ltm.monitor.tcps.tcp.create(**configuration)
        elif configuration['kind'].split(':')[3] == 'udp':
            return self.mgmt.tm.ltm.monitor.udps.udp.create(**configuration)
        else:
            return None

    def create_app_lb(self, name: str, protocol: str, port: int or str, members: List[dict], address: str=None,
                      skip_dns=False, custom_monitor=None):
        gtm_zones = [
            'app.parallon.com',
            'app.medcity.net',
            's3.medcity.net'
        ]

        if not isinstance(port, int):
            port = int(port)

        vip_name = f'{name}-{protocol}{port}'
        pool_name = f'{vip_name}_Pool'
        wide_name = name
        suffix = name[name.index('.') + 1:]
        backside_ssl = False

        # VIP address processing
        # big = BIG()
        ipam = NetworkAPIIPAM()

        if address is None:
            # address = big.assign_next_ip_from_list(network_list=self.env.iPPoolsField, name=name)
            address = ipam.assign_next_ip_from_list(networks=self.env.iPPoolsField, name=name)
            if not address.ok:
                raise Exception(['No VIP addresses are available.  Add new VIP Pool to F5 Environment'])
            address = jsonload(ipam.get_address(address.json()['address']))
        else:
            # Check to make sure VIP destination does not already exist
            if f'{address}:{port}' in self.destination_list:
                raise Exception([f'{address}:{port} already exists as a destination in the requested F5 environment'])

            address = IPv4Address(address)

            # Validate that the manually requested address is a member of the defined VIP pools
            for index, network in zip(range(len(list((x for x in self.env.iPPoolsField)))),
                                      list((x for x in self.env.iPPoolsField))):
                network = IPv4Network(network, strict=False)
                if address in network.hosts():
                    break
                elif index == len(list((x for x in self.env.iPPoolsField))) - 1:
                    raise Exception([f'{address} is not a part of the documented VIP Pool ranges '
                                     f'for {self.env.nameField}'])
                else:
                    continue

            # Check address assignment status
            check_address = jsonload(ipam.get_address(address.exploded))

            if check_address.id == 0:
                # address = big.assign_ip(ipaddress=address.exploded, name=name)
                address = ipam.bulk_reserve([dict(name=name, address=address.exploded)])
            else:
                address = check_address

        # Determine which pool monitor to use
        member_port = int(members[0]['port'])

        # Custom monitor process to create it if it doesn't exist and to set the monitor path
        if custom_monitor and custom_monitor['type'].lower() in ['http', 'https', 'tcp', 'udp']:
            if custom_monitor['type'].lower() == 'http':
                if self.mgmt.tm.ltm.monitor.https.http.exists(name=custom_monitor['name']):
                    monitor = f'/Common/{custom_monitor["name"]}'
                else:
                    mon = Monitor(_type='http')
                    mon.name = custom_monitor['name']
                    mon = self.create_monitor(mon.dict())
                    monitor = mon.fullPath
            elif custom_monitor['type'].lower() == 'https':
                if self.mgmt.tm.ltm.monitor.https_s.https.exists(custom_monitor['name']):
                    monitor = f'/Common/{custom_monitor["name"]}'
                else:
                    mon = Monitor(_type='https')
                    mon.name = custom_monitor['name']
                    mon = self.create_monitor(mon.dict())
                    monitor = mon.fullPath
            elif custom_monitor['type'].lower() == 'tcp':
                if self.mgmt.tm.ltm.monitor.tcps.tcp.exists(custom_monitor['name']):
                    monitor = f'/Common/{custom_monitor["name"]}'
                else:
                    mon = Monitor(_type='tcp')
                    mon.name = custom_monitor['name']
                    mon = self.create_monitor(mon.dict())
                    monitor = mon.fullPath
            elif custom_monitor['type'].lower() == 'udp':
                if self.mgmt.tm.ltm.monitor.udps.udp.exists(custom_monitor['name']):
                    monitor = f'/Common/{custom_monitor["name"]}'
                else:
                    mon = Monitor(_type='udp')
                    mon.name = custom_monitor['name']
                    mon = self.create_monitor(mon.dict())
                    monitor = mon.fullPath
            else:
                monitor = None
        else:
            monitor = None

        # Default monitor selection if custom_monitor creation failed or was not provided
        if not monitor:
            if protocol.lower() == 'tcp':
                if member_port == 80 or member_port == 8080:
                    monitor = '/Common/http'
                elif member_port == 443 or member_port == 8443 or member_port == 9443:
                    monitor = '/Common/https'
                    backside_ssl = True
                else:
                    monitor = '/Common/tcp'
            elif protocol == 'udp':
                monitor = '/Common/udp'
            else:
                monitor = '/Common/icmp'

        pool_config = Pool()
        pool_config.name = pool_name
        pool_config.monitor = monitor
        pool = self.create_pool(pool_config.dict())

        for member in members:
            if re.match(r'[.\d]+', member['server_name']):
                try:
                    lookup = gethostbyaddr(member['server_name'])
                    member['server_name'] = lookup[0]
                except herror:
                    pass

            member_config = {
                'name': f'{member["server_name"]}:{member["port"]}',
                'address': f'{member["address"]}',
                'partition': 'Common'
            }

            pool.members_s.members.create(**member_config)

        vip_config = VIP()
        vip_config.name = vip_name
        vip_config.ipProtocol = protocol.lower()
        vip_config.destination = f'/Common/{address.properties["address"]}:{port}'
        vip_config.profiles.append({'name': ('tcp' if protocol.lower() == 'tcp' else 'udp'),
                                    'context': 'all'})
        vip_config.pool = f'/Common/{pool.name}'
        vip_config.persist.append(
            {
                'name': ('cookie' if port == 80 or port == 443 else 'source_addr'),
                'partition': 'Common',
                'tmDefault': 'yes'
            }
        )

        if backside_ssl is True:
            vip_config.profiles.append({
                'name': 'serverssl',
                'context': 'serverside'
            })

        if port == 443:
            for profile in self.wildcard_certs:
                if f'star.{suffix}' == profile:
                    vip_config.profiles.append({
                        'name': profile,
                        'context': 'clientside'
                    })
            redirect_config = VIP()
            redirect_config.name = f'{vip_name}_HTTP_TO_HTTPS'
            redirect_config.ipProtocol = 'tcp'
            redirect_config.destination = f'/Common/{address.properties["address"]}:80'
            redirect_config.profiles = [
                {'name': 'tcp', 'context': 'all'},
                {'name': 'http', 'context': 'all'}
            ]
            redirect_config.rules = ['/Common/_sys_https_redirect']

            self.create_vip(redirect_config.dict())

        vip = self.create_vip(vip_config.dict())

        # self.sync_environment()

        if skip_dns:
            wide = None
        else:
            # Add Wide IP creation if GTMs are authoritative for the DNS suffix
            time.sleep(15)  # Sleep to allow VIP discovery by GTM
            wide, wide_pool = None, None
            if 'XRDC Dev' not in self.env.nameField and 'QOL-Nexus' not in self.env.nameField:
                if suffix in gtm_zones:
                    gtm = GTM.login()
                    wide, wide_pool = gtm.create_wide_ip_for_vip(wide_name, vip.name, vip.fullPath,
                                                                 address.properties['address'], self.self_ips)

        vip = self.get_vip_by_address(address.properties['address'])
        pool = self.get_pool(vip.pool.replace('/Common/', ''))
        members = self.get_pool_members(vip.pool.replace('/Common/', ''))

        response = {
            'vip_name': vip.name,
            'address': vip.destination.replace('/Common/', ''),
            'pool': vip.pool.replace('/Common/', ''),
            'pool_monitor': pool.monitor,
            'members': members,
            'profiles': list((profile.name for profile in vip.profiles_s.get_collection())),
            'wide_ip': (wide.name if wide else None)
        }

        # return vip, pool, wide, wide_pool
        return 200, response

    @classmethod
    def add_member_to_pool(cls, vip_address: str, vip_port: int or str, member: dict=None):
        ltm = cls.get_ltm_by(vip_address=vip_address)

        vip = ltm.get_vip_by_destination(str(vip_address), vip_port)
        pool = ltm.get_pool(vip.pool.replace('/Common/', ''))

        if re.match(r'[.\d]+', member['server_name']):
            try:
                lookup = gethostbyaddr(member['server_name'])
                member['server_name'] = lookup[0]
            except herror:
                pass

        member_config = {
            'name': f'{member["server_name"]}:{member["port"]}',
            'address': f'{member["address"]}',
            'partition': 'Common'
        }

        pool.members_s.members.create(**member_config)

        ltm.sync_environment()

        return 200, {
            'message': 'Pool Member Added',
            'updated_config': {
                'vip_name': vip.name.replace('/Common/', ''),
                'address': vip.destination.replace('/Common/', ''),
                'pool': pool.name.replace('/Common/', ''),
                'members': ltm.get_pool_members(pool.name)
            }
        }

    @classmethod
    def remove_member_from_pool(cls, vip_address: str, vip_port: int, member_address: str):
        ltm = cls.get_ltm_by(vip_address=vip_address)

        vip = ltm.get_vip_by_destination(vip_address, vip_port)
        pool = ltm.get_pool(vip.pool.replace('/Common/', ''))
        members = pool.members_s.get_collection()
        try:
            member = next(member for member in members if member.address == member_address)
            member.delete()
        except StopIteration:
            return 400, {
                'message': 'Pool Member was not found',
                'existing_config': {
                    'vip_name': vip.name,
                    'address': vip.destination.replace('/Common/', ''),
                    'pool': pool.name.replace('/Common/', ''),
                    'members': ltm.get_pool_members(pool.name)
                }
            }

        ltm.sync_environment()

        return 200, {
            'message': 'Pool Member Removed',
            'updated_config': {
                'vip_name': vip.name.strip('/Common/'),
                'address': vip.destination.strip('/Common/'),
                'pool': pool.name.strip('/Common/'),
                'members': ltm.get_pool_members(pool.name)
            }
        }

    @classmethod
    def vip_clone(cls, vip_address: str, ltm_env: str=None, ltm_pair: list=None):
        def default_rule(irule):
            """Returns True if an iRule is F5 verified, suggesting that it is a system default iRule"""
            if 'apiRawValues' in irule.__dict__.keys():
                if 'verificationStatus' in irule.apiRawValues.keys():
                    if irule.apiRawValues['verificationStatus'] == 'signature-verified':
                        return True
            else:
                return False

        monitor_list = []
        profile_list = []

        pool_monitors = []

        pool_config = []
        monitor_config = []
        persist_config = []
        rule_config = []
        vip_config = []
        profile_config = []

        configs = {'PoolConfigs': pool_config, 'MonitorConfigs': monitor_config, 'PersistenceProfiles': persist_config,
                   'RuleConfig': rule_config, 'VIPConfig': vip_config, 'ProfileConfig': profile_config}

        if ltm_env:
            ltm = cls.login_to_environment(ltm_env)
        elif ltm_pair:
            ltm = cls.login_to_pair(ltm_pair)
        else:
            ltm = cls.get_ltm_by(vip_address)

        # Get HTTP Monitors and append to monitor list
        monitor_list += ltm.mgmt.tm.ltm.monitor.https.get_collection()
        # Get HTTPS Monitors
        monitor_list += ltm.mgmt.tm.ltm.monitor.https_s.get_collection()
        # Get TCP Monitors
        monitor_list += ltm.mgmt.tm.ltm.monitor.tcps.get_collection()
        # Get UDP Monitors
        monitor_list += ltm.mgmt.tm.ltm.monitor.udps.get_collection()

        # Get TCP Profiles
        profile_list += ltm.mgmt.tm.ltm.profile.tcps.get_collection()
        # Get UDP Profiles
        profile_list += ltm.mgmt.tm.ltm.profile.udps.get_collection()
        # Get HTTP Profiles
        profile_list += ltm.mgmt.tm.ltm.profile.https.get_collection()
        # Get Server SSL Profiles
        profile_list += ltm.mgmt.tm.ltm.profile.server_ssls.get_collection()
        # Get Client SSL Profiles
        profile_list += ltm.mgmt.tm.ltm.profile.client_ssls.get_collection()
        # Get OneConnect Profiles
        profile_list += ltm.mgmt.tm.ltm.profile.one_connects.get_collection()
        # Get HTTP Compression Profiles
        profile_list += ltm.mgmt.tm.ltm.profile.http_compressions.get_collection()

        vips = list(dest for dest in ltm.destination_list if vip_address == dest[:dest.index(':')])

        for v in vips:
            vip_address, vip_port = v.split(':')

            vip = ltm.get_vip_by_destination(vip_address, vip_port)

            try:
                vip.__delattr__('fallbaackPersistence')
            except AttributeError:
                pass

            # Append pool name from VIP to pool_list
            try:
                pool = ltm.mgmt.tm.ltm.pools.pool.load(name=vip.pool.replace('/Common/', ''))
                pool_monitors += list(res.group().replace('/Common/', '') for res in re.finditer(r'/Common/\S+',
                                                                                                 pool.monitor))
                members = pool.members_s.get_collection()
                pool.members = []
                for member in members:
                    try:
                        member_name = gethostbyaddr(member.address)[0]
                        member_port = re.search(r'\d+$', member.name).group()
                        member_name += f':{member_port}'
                    except herror:
                        member_name = member.name

                    pool.members.append(dict(name=member_name, address=member.address, partition=member.partition))

                BaseLTMObject.remove_deletable_attrs(pool)
                if pool not in pool_config:
                    pool_config.append(pool)
            except AttributeError:
                pool_monitors = []

            try:
                for persist in vip.persist:
                    link = str(persist['nameReference'])
                    if 'persistence/cookie' in link:
                        persist = ltm.mgmt.tm.ltm.persistence.cookies.cookie.load(name=persist['name'])
                        BaseLTMObject.remove_deletable_attrs(persist)
                        if persist.name not in ltm.default_persistence:
                            persist_config.append(persist)
                    elif 'persistence/source-addr' in link:
                        persist = ltm.mgmt.tm.ltm.persistence.source_addrs.source_addr.load(name=persist['name'])
                        BaseLTMObject.remove_deletable_attrs(persist)
                        if persist.name not in ltm.default_persistence:
                            persist_config.append(persist)
                    elif 'persistence/universal' in link:
                        persist = ltm.mgmt.tm.ltm.persistence.universals.universal.load(name=persist['name'])
                        BaseLTMObject.remove_deletable_attrs(persist)
                        if persist.name not in ltm.default_persistence:
                            persist_config.append(persist)
                        if persist.rule != 'none':
                            rule = ltm.mgmt.tm.ltm.rules.rule.load(name=persist.rule.replace('/Common/', ''))
                            BaseLTMObject.remove_deletable_attrs(rule)
                            if not default_rule(rule):
                                rule_config.append(rule)
                    else:
                        pass
                    for _ in vip.persist:
                        del _['nameReference']
            except AttributeError:
                pass

            # Append iRules on VIP to rule_config
            try:
                for rule in vip.rules:
                    rule = ltm.mgmt.tm.ltm.rules.rule.load(name=rule.replace('/Common/', ''))
                    BaseLTMObject.remove_deletable_attrs(rule)
                    if not default_rule(rule):
                        rule_config.append(rule)
            except AttributeError:
                pass

            # Analyze iRules for pool selectors
            pools_in_rules = []
            for rule in rule_config:
                pools_in_rules += list(res[1] for res in list(re.finditer('pool +{(.*)}', rule.apiAnonymous)))
                pools_in_rules += list(res[1] for res in list(re.finditer(r'pool +([A-z0-9-]+)', rule.apiAnonymous)))

            for rule_pool in pools_in_rules:
                rule_pool = ltm.mgmt.tm.ltm.pools.pool.load(name=rule_pool.replace('/Common/', ''))

                pool_monitors += list(
                    res.group().replace('/Common/', '') for res in re.finditer(r'/Common/\S+', rule_pool.monitor))
                members = rule_pool.members_s.get_collection()
                rule_pool.members = [dict(name=member.name, address=member.address, partition=member.partition)
                                     for member in members]
                BaseLTMObject.remove_deletable_attrs(rule_pool)
                if rule_pool.name not in list(pool.name for pool in pool_config):
                    pool_config.append(rule_pool)

            # Iterate over monitors and append
            for monitor in monitor_list:
                if monitor.name in pool_monitors and BaseLTMObject.remove_deletable_attrs(monitor) not in \
                        monitor_config and monitor.name not in ltm.default_monitors:
                    monitor_config.append(monitor)

            # Collect profiles found on VIP for extraction to JSON
            vip.profiles = []
            profiles = vip.profiles_s.get_collection()
            for profile in profiles:
                BaseLTMObject.remove_deletable_attrs(profile)
                vip.profiles.append(profile.attrs)
            BaseLTMObject.remove_deletable_attrs(vip)
            vip_config.append(vip)

            for profile in profile_list:
                if profile.name in list(profile['name'] for profile in vip.profiles) and \
                        BaseLTMObject.remove_deletable_attrs(
                            profile) not in profile_config and profile.name not in ltm.default_profiles:
                    profile_config.append(profile)
            # Transform classes into JSON

            for profile in profile_config:
                if 'sslstate' in profile.kind:
                    chain = profile.__dict__.get('certKeyChain')
                    if chain:
                        for _dict in profile.certKeyChain:
                            for key in list(_dict.keys()):
                                if 'Reference' in key:
                                    del _dict[key]

        for key in configs:
            for ltm_object in configs[key]:
                ltm_object.partition = 'Common'
                # commands += [
                #     f'show running-config '
                #     f'{" ".join(ltm_object.kind.split(":")[ltm_object.kind.split(":").index("ltm"): -1])} '
                #     f'{ltm_object.name}']
            configs[key] = list(obj.attrs for obj in configs[key])

        # commands = list(set(commands))
        # ucs_content = ltm.ssh_command(commands=commands)

        # Configuration order is Monitors, Pools, Rules, Persistence, Profiles, VIPs

        # Remove duplicate configurations
        for key in configs:
            configs[key] = list(json.dumps(o, sort_keys=True) for o in configs[key])
            configs[key] = list(set(configs[key]))
            configs[key] = list(json.loads(o) for o in configs[key])

        return_data = {
            'source_environment': (None if ltm_pair else ltm.env.nameField),
            'source_devices': (ltm_pair if ltm_pair else ltm.env.devicesField),
            'configurations': configs
        }

        return 200, return_data

    def deploy_configurations(self, data: dict):
        """Accepts resulting data from LTM.vip_clone() and deploys those configurations"""
        # Monitor Configs
        for monitor in data['MonitorConfigs']:
            kind = monitor['kind'].split(':')[-2]
            if kind == 'http':
                if self.mgmt.tm.ltm.monitor.https.http.exists(name=monitor['name']):
                    # self.mgmt.tm.ltm.monitor.https.http.modify(**monitor)
                    pass
                else:
                    self.mgmt.tm.ltm.monitor.https.http.create(**monitor)
            elif kind == 'https':
                if self.mgmt.tm.ltm.monitor.https_s.https.exists(name=monitor['name']):
                    # self.mgmt.tm.ltm.monitor.https_s.https.modify(**monitor)
                    pass
                else:
                    self.mgmt.tm.ltm.monitor.https_s.https.create(**monitor)
            elif kind == 'tcp':
                if self.mgmt.tm.ltm.monitor.tcps.tcp.exists(name=monitor['name']):
                    # self.mgmt.tm.ltm.monitor.tcps.tcp.modify(**monitor)
                    pass
                else:
                    self.mgmt.tm.ltm.monitor.tcps.tcp.create(**monitor)
            elif kind == 'udp':
                if self.mgmt.tm.ltm.monitor.udps.udp.exists(name=monitor['name']):
                    # self.mgmt.tm.ltm.monitor.udps.udp.modify(**monitor)
                    pass
                else:
                    self.mgmt.tm.ltm.monitor.udps.udp.create(**monitor)
        # Pools
        for pool in data['PoolConfigs']:
            if self.mgmt.tm.ltm.pools.pool.exists(name=pool['name']):
                # self.mgmt.tm.ltm.pools.pool.modify(**pool)
                pass
            else:
                self.mgmt.tm.ltm.pools.pool.create(**pool)
        # Rules
        for rule in data['RuleConfig']:
            if self.mgmt.tm.ltm.rules.rule.exists(name=rule['name']):
                # self.mgmt.tm.ltm.rules.rule.modify(**rule)
                pass
            else:
                self.mgmt.tm.ltm.rules.rule.create(**rule)
        # Persistence
        for persist in data['PersistenceProfiles']:
            kind = persist['kind'].split(':')[-2]
            if kind == 'universal':
                if self.mgmt.tm.ltm.persistence.universals.universal.exists(name=persist['name']):
                    # self.mgmt.tm.ltm.persistence.universals.universal.modify(**persist)
                    pass
                else:
                    self.mgmt.tm.ltm.persistence.universals.universal.create(**persist)
            elif kind == 'cookie':
                if self.mgmt.tm.ltm.persistence.cookies.cookie.exists(name=persist['name']):
                    # self.mgmt.tm.ltm.persistence.cookies.cookie.modify(**persist)
                    pass
                else:
                    self.mgmt.tm.ltm.persistence.cookies.cookie.create(**persist)
            elif kind == 'source-addr':
                if self.mgmt.tm.ltm.persistence.source_addrs.source_addr.exists(name=persist['name']):
                    # self.mgmt.tm.ltm.persistence.source_addrs.source_addr.modify(**persist)
                    pass
                else:
                    self.mgmt.tm.ltm.persistence.source_addrs.source_addr.create(**persist)
        # Profiles
        for profile in data['ProfileConfig']:
            kind = profile['kind'].split(':')[-2]
            if kind == 'http':
                if self.mgmt.tm.ltm.profile.https.http.exists(name=profile['name']):
                    # self.mgmt.tm.ltm.profile.https.http.modify(**profile)
                    pass
                else:
                    self.mgmt.tm.ltm.profile.https.http.create(**profile)
            elif kind == 'http-compression':
                if self.mgmt.tm.ltm.profile.http_compressions.http_compression.exists(name=profile['name']):
                    # self.mgmt.tm.ltm.profile.http_compressions.http_compression.modify(**profile)
                    pass
                else:
                    self.mgmt.tm.ltm.profile.http_compressions.http_compression.create(**profile)
            elif kind == 'tcp':
                if self.mgmt.tm.ltm.profile.tcps.tcp.exists(name=profile['name']):
                    # self.mgmt.tm.ltm.profile.tcps.tcp.modify(**profile)
                    pass
                else:
                    self.mgmt.tm.ltm.profile.tcps.tcp.create(**profile)
            elif kind == 'udp':
                if self.mgmt.tm.ltm.profile.udps.udp.exists(name=profile['name']):
                    # self.mgmt.tm.ltm.profile.udps.udp.modify(**profile)
                    pass
                else:
                    self.mgmt.tm.ltm.profile.udps.udp.create(**profile)
            elif kind == 'one-connect':
                if self.mgmt.tm.ltm.profile.one_connects.one_connect.exists(name=profile['name']):
                    # self.mgmt.tm.ltm.profile.one_connects.one_connect.modify(**profile)
                    pass
                else:
                    self.mgmt.tm.ltm.profile.one_connects.one_connect.create(**profile)
            elif kind == 'analytics':
                if self.mgmt.tm.ltm.profile.analytics_s.analytics.exists(name=profile['name']):
                    # self.mgmt.tm.ltm.profile.analytics_s.analytics.modify(**profile)
                    pass
                else:
                    self.mgmt.tm.ltm.profile.analytics_s.analytics.create(**profile)
            elif kind == 'client_ssl':
                pass
            elif kind == 'server_ssl':
                pass
        # VIPs
        for vip in data['VIPConfig']:
            if self.mgmt.tm.ltm.virtuals.virtual.exists(name=vip['name']):
                # self.mgmt.tm.ltm.virtuals.virtual.modify(**vip)
                pass
            else:
                self.mgmt.tm.ltm.virtuals.virtual.create(**vip)

        self.sync_environment()

    def advertise_vip(self, virtual_address: str):
        """Creates an OSPF route for a virtual address that would not typically be found on the subject LTM"""
        vas = self.mgmt.tm.ltm.virtual_address_s.get_collection()

        try:
            va = next(va for va in vas if va.address == virtual_address)
        except StopIteration:
            raise Exception('Virtual Address not found on this LTM')

        va.routeAdvertisement = 'enabled'
        va.update()
        return None

    @staticmethod
    def store_vip_config(app_code: str, inst_name: str, fqdn: str=None, vip_address: str=None):

        if fqdn:
            address = IPv4Address(gethostbyname(fqdn)).__str__()
        elif vip_address:
            address = IPv4Address(vip_address).__str__()
        else:
            raise Exception('FQDN or IP Address must be supplied')

        x, configs = LTM.vip_clone(vip_address=address)

        configs['source_fqdn'] = (fqdn if fqdn else vip_address)
        configs['source_address'] = address

        file_path = f'f5caas/{app_code.lower()}/{inst_name.lower()}/{address.replace(".", "_")}.json'

        api = GithubAPI()
        if api.file_exists(file_path=file_path):
            api.update_file(file_path=file_path, message=f'Automated retrieval of {address} configurations - Updated',
                            content=json.dumps(configs, indent=4, sort_keys=True))
        else:
            api.add_file(file_path=file_path, message=f'Automated retrieval of {address} configurations',
                         content=json.dumps(configs, indent=4, sort_keys=True))

        return 200, {'message': 'Configuration has been stored/updated', 'Configurations': configs}

    @staticmethod
    def as3_converter(ltm_config: str):
        files = [('conf', BytesIO(ltm_config.encode()))]

        response = requests.post('http://localhost:8080/as3converter', files=files)

        return response.json()


class GTM:
    env = None
    internal_gtms = ['10.27.71.91', '10.90.8.91']
    external_gtms = ['10.27.132.91', '10.90.9.91']

    def __init__(self, host):
        self.host = host
        self.mgmt = ManagementRoot(host, username=os.getenv('netmgmtuser'), password=os.getenv('netmgmtpass'))
        self.servers = self.mgmt.tm.gtm.servers.get_collection()

    @classmethod
    def login(cls, external=False):
        if external is True:
            gtm = cls(cls.external_gtms[1])
        else:
            gtm = cls(cls.internal_gtms[1])
        return gtm

    def get_a_pool(self, name: str):
        return self.mgmt.tm.gtm.pools.a_s.a.load(name=name)

    def create_a_pool(self, configuration: dict):
        return self.mgmt.tm.gtm.pools.a_s.a.create(**configuration)

    def get_a_wideip(self, name: str):
        return self.mgmt.tm.gtm.wideips.a_s.a.load(name=name)

    def create_a_wideip(self, configuration: dict):
        return self.mgmt.tm.gtm.wideips.a_s.a.create(**configuration)

    @staticmethod
    def reverse_lookup(vip_address: str):
        start_time = time.perf_counter()
        ltm = LTM.get_ltm_by(vip_address=vip_address)
        target_vips = {re.search(r'[-.\w]+$', vip.name).group() for vip in ltm.mgmt.tm.ltm.virtuals.get_collection()
                       if vip.destination[:vip.destination.index(':')].replace('/Common/', '') == vip_address}

        # Set external to True if the supplied address is not a private address
        external = IPv4Address(vip_address).is_global

        gtm = GTM.login(external=external)

        # Don't process anything more if nothing was found
        if len(target_vips) == 0:
            return 200, {
                'Elapsed Time': round(time.perf_counter() - start_time),
                'IP': vip_address,
                'Result': f'No VIP names found using {vip_address}',
                'LTM Environment': ltm.env.nameField,
                'LTM Devices': ltm.env.devicesField
            }

        target_pools = {pool.name for pool in gtm.mgmt.tm.gtm.pools.a_s.get_collection()
                        for member in pool.members_s.get_collection()
                        if member.name in target_vips}
        wide_ips = list({wide.name for wide in gtm.mgmt.tm.gtm.wideips.a_s.get_collection()
                         if 'pools' in wide.attrs.keys()
                         for pool in wide.pools
                         if pool['name'] in target_pools})

        del gtm

        response = {
            'Elapsed Time': round(time.perf_counter() - start_time),
            'IP': vip_address,
            'Results': wide_ips,
            'LTM Environment': ltm.env.nameField,
            'LTM Devices': ltm.env.devicesField
        }

        return 200, response

    def create_wide_ip_for_vip(self, hostname: str, vip_name: str, vip_fullpath: str, vip_address: str,
                               ltm_selfips: list):
        try:
            resolution = gethostbyname(hostname)
            return hostname, resolution
        except gaierror:
            pass

        server = next(server for server in self.servers for address in server.addresses
                      if address['name'] in ltm_selfips)

        pool_config = {
            'name': f'{vip_name}-POOL',
            'loadBalancingMode': 'global-availability',
            'fallbackIp': vip_address,
            'fallbackMode': 'fallback-ip',
            'members': [
                {
                    'name': f'{server.name}:{vip_fullpath}',
                    'fullPath': f'{server.fullPath}:{vip_fullpath}'
                }
            ]
        }

        pool = self.create_a_pool(pool_config)

        wide_config = {
            'name': hostname,
            'poolLbMode': 'global-availability',
            'pools': [
                {
                    'name': pool.name,
                    'partition': 'Common',
                    'order': 0,
                    'ratio': 1
                }
            ]
        }

        wideip = self.create_a_wideip(wide_config)

        return wideip, pool


class BigIQ:
    def __init__(self, username: str=None, password: str=None):
        self.__ADDRESS = '10.27.71.20'
        self.__AUTH_PROVIDER = 'ACS-RADIUS-admin-auth'
        self.__URL_BASE = 'https://%s' % self.__ADDRESS
        self.session = requests.session()
        self.session.verify = False
        self.login(username=username, password=password)

    def login(self, username: str=None, password: str=None) -> None:
        path = '/mgmt/shared/authn/login'
        js = dict(username=(username if username else os.getenv('netmgmtuser')),
                  password=(password if password else os.getenv('netmgmtpass')),
                  loginProviderName=self.__AUTH_PROVIDER)

        response = jsonload(self.post(path, data=js))

        self.session.headers['X-F5-Auth-Token'] = response.token.token

    def get(self, path, **kwargs) -> requests.Response:
        headers = {'Accept': 'application/json'}
        # Update Headers with any provided header values
        for kwarg, arg in kwargs.items():
            if kwarg.lower() == 'headers' and isinstance(arg, dict):
                headers.update(arg)
        return self.session.get('%s%s' % (self.__URL_BASE, path), headers=headers)

    def post(self, path, data: dict) -> requests.Response:
        return self.session.post('%s%s' % (self.__URL_BASE, path), json=data)

    def get_devices(self) -> List[SimpleNamespace]:
        path = '/mgmt/shared/resolver/device-groups/cm-adccore-allbigipDevices/devices'
        devices = [tonamespace(_) for _ in self.get(path=path).json()['items']]
        return devices

    def get_device_groups(self) -> List[SimpleNamespace]:
        path = '/mgmt/shared/resolver/device-groups'
        subject = [tonamespace(_) for _ in self.get(path=path).json()['items']]
        return subject

    def get_device_group(self, name: str) -> List[SimpleNamespace]:
        path = '/mgmt/shared/resolver/device-groups/%s/devices' % name
        subject = [tonamespace(_) for _ in self.get(path=path).json()['items']]
        subject = [_ for _ in subject if _.managementAddress != self.__ADDRESS]
        return subject
