from netmiko import Netmiko
from cisco.classes import *
import re
import os


class Route:
    origin_as = None
    communities = None

    def __init__(self, route: str):
        self.network = IPv4Network(re.search(r'Routing entry for ([^\n]+)', route).group(1))
        self.distance = int(re.search(r'distance (\d+)', route).group(1))
        self.metric = int(re.search(r'metric (\d+)', route).group(1))

        if self.distance == 20:
            self.protocol = 'ebgp'
        elif self.distance == 200:
            self.protocol = 'ibgp'
        elif self.distance == 110:
            self.protocol = 'ospf'
        elif self.distance == 90:
            self.protocol = 'eigrp'
        elif self.distance == 0:
            self.protocol = 'connected'
        else:
            # Accounts for any other administrative distance
            self.protocol = 'static'


class IOSXE:
    def __init__(self, ip):
        device = {
            'host': ip,
            'device_type': 'cisco_xe',
            'banner_timeout': 8,
            'username': os.getenv('netmgmtuser'),
            'password': os.getenv('netmgmtpass')
        }

        self.session = Netmiko(**device)
        self.running_config = self.session.send_command('show run')

        self.interface = Container('interface', Interface)
        self.vlans = Container('vlans', VLAN)
        self.subnets = Container('subnets', Subnet)
        self.cdp_neighbor = Container('cdp_neighbor', CDPNeighbor)

        self.hostname = re.search(r'hostname ([^\n]+)', self.running_config).group(1)

        # Process interface configs
        self.interface_configs = re.findall(r'(?m)^interface[^!]+', self.running_config)

        for index, interface in enumerate([c.split('\n') for c in self.interface_configs]):
            attribute_name = re.search(r'\S+$', interface[0]).group()
            attribute_name = re.sub(r'[-./]', '_', attribute_name)
            interface = Interface(self.interface_configs[index].split('\n'))
            self.interface.add(attribute_name, interface)

        # Get directly connected networks from interfaces
        for interface in self.interface:
            # Get networks found on interfaces with IPs and load into subnets
            if re.search(r'ip address \d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}', interface.config):
                subnets = re.findall(r'\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3} \d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}',
                                     interface.config)
                for subnet in subnets:
                    cidr = Subnet.convert_to_cidr(subnet)
                    csubnet = Subnet(cidr)
                    csubnet.description = interface.description
                    if interface.name.lower().startswith('vlan'):
                        csubnet.vlan = int(re.search(r'\d+', interface.name).group())
                    csubnet.interface = interface
                    self.subnets.add('net_%s' % re.sub(r'[./]', '_', csubnet.network.with_prefixlen), csubnet)

        # Populate Port Channel member information
        for intf in self.interface:
            if intf.type == 'physical':
                if intf.member_of is not None:
                    # po = 'port_channel{}'.format(re.search(r'\d+', intf.member_of).group())
                    po = self.interface.get('abbr', intf.member_of)
                    po.members.append(intf.abbr)

        # Process CDP Neighbors
        output = self.session.send_command('show cdp neighbor detail')
        output = re.split('Device', output)
        for n in output:
            if re.search(r'ID: ', n):
                neighbor = CDPNeighbor(n)
                attribute_name = re.sub(r'[-.]', '_', neighbor.device_id)

                search = self.cdp_neighbor.get('device_id', neighbor.device_id)

                if search is not None:
                    search += neighbor
                else:
                    self.cdp_neighbor.add(attribute_name, neighbor)

        # Collect VLAN Information
        vlans = self.session.send_command('show vlan brief | inc active')
        vlans = vlans.split('\n')
        for vlan in vlans:
            try:
                vlan_id, vlan_name = re.search(r'^(\S+)\s+(\S+)', vlan).groups()
            except AttributeError:
                continue
            self.vlans.add(f'vlan{vlan_id}', VLAN(int(vlan_id), vlan_name))

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.disconnect()

    def ip_lookup(self, ip: str) -> str or None:
        output = self.session.send_command(f'show ip route {ip}')
        prefix = re.search(r'Routing entry for ([^\n]+)', output)

        if prefix:
            return prefix.group(1)
        else:
            return None

    def prefix_lookup(self, cidr: str) -> IPv4Network or None:
        """Finds specific prefix only"""
        network = IPv4Network(cidr, strict=False)

        output = self.session.send_command(f'show ip route {network}')
        prefixes = set(_ for _ in re.findall(r'Routing entry for ([^\n]+)', output))

        if prefixes:
            return network
        else:
            return None

    def route_lookup(self, ip: str) -> Route:
        output = self.session.send_command(f'show ip route {ip}')
        route = Route(route=output)
        return route
