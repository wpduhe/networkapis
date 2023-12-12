from typing import Any
from ipaddress import IPv4Network
import re


class Container:
    def __init__(self, name, object_type: Any):
        self.__setattr__(name, name)
        self.__type = object_type

    def add(self, name, class_object):
        assert type(class_object) == self.__type
        self.__setattr__(name, class_object)

    def get(self, key, value):
        for interface in list(self):
            if interface.__getattribute__(key) == value:
                return interface

        return None

    def __iter__(self):
        for attr_name in dir(self):
            if isinstance(self.__getattribute__(attr_name), self.__type):
                yield self.__getattribute__(attr_name)

    def __len__(self):
        return len(list(self.__iter__()))

    def __json__(self):
        if self.__type == CDPNeighbor:
            data = [x.__dict__ for x in self]
            data.sort(key=lambda x: x['platform'])
        elif self.__type == Interface:
            data = [x.__dict__ for x in self]
            data.sort(key=lambda x: x['name'])
        else:
            data = [x.__dict__ for x in self]

        return data


class Interface:
    name = None
    description = None
    type = None
    mode = None
    members = None
    member_of = None
    vpc_id = None
    allowed_vlans = None
    access_vlan = None
    config = ''
    is_enabled = None
    is_up = None
    vrf = None
    cdp_neighbor = None

    def __init__(self, config: list):
        self.name = re.search(r'\S+$', config[0]).group()
        if 'port-channel' in config[0].lower():
            self.type = 'port-channel'
            self.abbr = 'Po{}'.format(re.search(r"[.\d]+", config[0]).group())
            self.members = []
        elif 'vlan' in config[0].lower():
            self.type = 'vlan'
            self.mode = 'routed'
            self.abbr = self.name
        elif re.search(r'Bun\D*E\D*[^\n]+', config[0]):
            # Finds Bundle-Ether
            intf_type, intf = re.search(r'(Bun\D*E\D*)([^\n]+)', config[0]).groups()
            self.type = 'port-channel'
            self.abbr = f'BE{intf}'
        elif re.search(r'Fa\D*E\D*[^\n]+', config[0]):
            # Finds FastEthernet
            intf_type, intf = re.search(r'(Fa\D*E\D*)([^\n]+)', config[0]).groups()
            self.type = 'physical'
            self.abbr = f'Fa{intf}'
        elif re.search(r'Te\D*G\D*E\D*[^\n]+', config[0]):
            # Finds TenGigabitEthernet or TenGigE interfaces
            intf_type, intf = re.search(r'(Te\D*G\D*E\D*)([^\n]+)', config[0]).groups()
            self.type = 'physical'
            self.abbr = f'Te{intf}'
        elif re.search(r'TwentyFiveG\D*E\D*[^\n]+', config[0]):
            # Finds TwentyFiveGigE interfaces
            intf_type, intf = re.search(r'(TwentyFiveG\D*E\D*)([^\n]+)', config[0]).groups()
            self.type = 'physical'
            self.abbr = f'TF{intf}'
        elif re.search(r'For\D*G\D*E\D*[^\n]+', config[0]):
            # Finds FortyGigE interfaces
            intf_type, intf = re.search(r'(For\D*G\D*E\D*)([^\n]+)', config[0]).groups()
            self.type = 'physical'
            self.abbr = f'Fo{intf}'
        elif re.search(r'Hun\D*G\D*E\D*[^\n]+', config[0]):
            # Finds HundredGigE interfaces
            intf_type, intf = re.search(r'(Hun\D*G\D*E\D*)([^\n]+)', config[0]).groups()
            self.type = 'physical'
            self.abbr = f'Hu{intf}'
        elif re.search(r'G\D*E\D*[^\n]+', config[0]):
            # Finds GigabitEthernet interfaces
            intf_type, intf = re.search(r'(Gi\D*E\D*)([^\n]+)', config[0]).groups()
            self.type = 'physical'
            self.abbr = f'Gi{intf}'
        elif 'ethernet' in config[0].lower():
            self.type = 'physical'
            self.abbr = self.name.replace('Ethernet', 'Eth')
        elif 'loopback' in config[0].lower():
            self.type = 'loopback'
            self.abbr = self.name.replace('loopback', 'Lo')
            self.mode = 'routed'
        elif 'mgmt0' in config[0].lower():
            self.type = 'management'
            self.abbr = 'mgmt0'
            self.mode = 'routed'
        else:
            self.type = 'unknown'
            self.abbr = 'unknown'
        self.config = '\n'.join(config)
        self.hsrp_groups = []

        for line in config:
            if 'description' in line:
                self.description = re.sub(' +description ', '', line)

            if 'switchport mode' in line:
                self.mode = re.search(r'\S+$', line).group()
                self.allowed_vlans = '1-4094'

            if 'switchport access vlan' in line:
                self.access_vlan = int(re.search(r'\d+', line).group())

            if 'switchport trunk allowed vlan' in line:
                try:
                    self.allowed_vlans = re.search(r'[\d+,-]+$', line).group()
                except AttributeError:
                    pass

            if 'channel-group' in line:
                self.member_of = 'Po{}'.format(re.search(r'\d+', line).group())

            if re.match(r'^ +vpc \d+$', line):
                self.vpc_id = re.search(r'\d+', line).group()

            if 'vrf' in line:
                self.vrf = re.search(r'\S+$', line).group()

            if re.search(r'hsrp \d+', line):
                self.hsrp_groups.append(int(re.search(r'\d+', line).group()))

        if self.hsrp_groups:
            self.hsrp_groups.sort()
        else:
            self.hsrp_groups = []

    def __repr__(self):
        return self.name


class CDPNeighbor:
    device_id = None
    platform = None
    local_interfaces = None
    remote_interfaces = None
    ip_addresses = None

    def __init__(self, data: str):
        assert data.lower().startswith(' id')

        self.ip_addresses = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', data)

        self.device_id = re.search(r':\s*([^(\s,.]+)', data).group(1).strip()
        self.platform = re.search(r'Platform:\s*([^,]+)', data).group(1)
        self.local_interfaces = [re.search(r'Interface:\s*([^\n,]+)', data).group(1)]
        self.remote_interfaces = [re.search(r'\(outgoing port\):\s*([^\n,]+)', data).group(1)]

    def __add__(self, x):
        self.local_interfaces += x.local_interfaces
        self.remote_interfaces += x.remote_interfaces

        return self

    def __repr__(self):
        return self.device_id


class Subnet:
    network = None
    description = None
    interface = None
    vlan = None

    def __init__(self, prefix: str):
        self.address = prefix[:prefix.index('/')]

        if IPv4Network(prefix, strict=False):
            self.network = IPv4Network(prefix, strict=False)

    def __repr__(self):
        return self.network.with_prefixlen

    @staticmethod
    def convert_to_cidr(address):
        ip, mask = re.findall(r'\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}', address)
        if mask == '255.255.255.255':
            return f'{ip}/32'
        elif mask == '255.255.255.254':
            return f'{ip}/31'
        elif mask == '255.255.255.252':
            return f'{ip}/30'
        elif mask == '255.255.255.248':
            return f'{ip}/29'
        elif mask == '255.255.255.240':
            return f'{ip}/28'
        elif mask == '255.255.255.224':
            return f'{ip}/27'
        elif mask == '255.255.255.192':
            return f'{ip}/26'
        elif mask == '255.255.255.128':
            return f'{ip}/25'
        elif mask == '255.255.255.0':
            return f'{ip}/24'
        elif mask == '255.255.254.0':
            return f'{ip}/23'
        elif mask == '255.255.252.0':
            return f'{ip}/22'
        elif mask == '255.255.248.0':
            return f'{ip}/21'
        elif mask == '255.255.240.0':
            return f'{ip}/20'
        elif mask == '255.255.224.0':
            return f'{ip}/19'
        elif mask == '255.255.192.0':
            return f'{ip}/18'
        elif mask == '255.255.128.0':
            return f'{ip}/17'
        elif mask == '255.255.0.0':
            return f'{ip}/16'
        elif mask == '255.254.0.0':
            return f'{ip}/15'
        elif mask == '255.252.0.0':
            return f'{ip}/14'
        elif mask == '255.248.0.0':
            return f'{ip}/13'
        elif mask == '255.240.0.0':
            return f'{ip}/12'
        elif mask == '255.224.0.0':
            return f'{ip}/11'
        elif mask == '255.192.0.0':
            return f'{ip}/10'
        elif mask == '255.128.0.0':
            return f'{ip}/9'
        elif mask == '255.0.0.0':
            return f'{ip}/8'
        elif mask == '254.0.0.0':
            return f'{ip}/7'
        elif mask == '252.0.0.0':
            return f'{ip}/6'
        elif mask == '248.0.0.0':
            return f'{ip}/5'
        elif mask == '240.0.0.0':
            return f'{ip}/4'
        elif mask == '224.0.0.0':
            return f'{ip}/3'
        elif mask == '192.0.0.0':
            return f'{ip}/2'
        elif mask == '128.0.0.0':
            return f'{ip}/1'
        elif mask == '0.0.0.0':
            return f'{ip}/0'


class VLAN:
    id = None
    name = None

    def __init__(self, vlan_id, name):
        self.id = int(vlan_id)
        self.name = name

    def __repr__(self):
        return self.id


class VPC:
    domain = None
    self = None
    peer = None
    peer_link = None

    def __init__(self, domain, vpc_self, peer):
        self.domain = domain
        self.self = vpc_self
        self.peer = peer


class VRF:
    name = None
    rd = None

    def __init__(self, config: str):
        self.name = re.search(r'vrf .*?(\S+)\n', config).group(1)
        self.config = config

    def __repr__(self):
        return self.name


class StaticRoute:
    prefix = None
    network = None
    next_hop = None
    id = None
    name = None
    metric = 1

    def __init__(self, route: str):
        if re.match(r'ip route (\d{1,3}\.){3}\d{1,3}/\d+', route):
            # This route is using CIDR
            self.prefix, self.next_hop, metric = re.search(r'ip route (\S+) (\S+)\s*(\d*)', route).groups()
            self.network = IPv4Network(self.prefix, strict=False)
            name = re.search(r'name (\S+)', route)
            if name:
                self.name = name
            if metric:
                self.metric = int(metric)
            self.id = f'{self.prefix}_{self.next_hop}'
        elif re.match(r'ip route (\d{1,3}\.){3}\d{1,3} (\d{1,3}\.){3}\d{1,3} (\d{1,3}\.){3}\d{1,3}', route):
            # This route is using netmask
            net, mask, hop, metric = re.search(r'ip route (\S+) (\S+) (\S+)\s*(\d*)', route).groups()
            self.prefix = Subnet.convert_to_cidr(f'{net} {mask}')
            self.network = IPv4Network(self.prefix, strict=False)
            name = re.search(r'name (\S+)', route).group(1)
            if name:
                self.name = name
            if metric:
                self.metric = int(metric)
            self.id = f'{self.prefix}_{self.next_hop}'
        else:
            raise Exception('Something went wrong with static route processing')
