from cisco.classes import *
from netmiko.cisco.cisco_xr import CiscoXrSSH
from ipaddress import IPv4Network
from typing import List
import re
import os
import json
import pyperclip
import sys


class Route:
    origin_as = None
    communities = None

    def __init__(self, route: str, vrf: str):
        self.network = IPv4Network(re.search(r'Routing entry for ([^\n]+)', route).group(1))
        self.distance = int(re.search(r'distance (\d+)', route).group(1))
        self.metric = int(re.search(r'metric (\d+)', route).group(1))
        self.vrf = vrf

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


class IOSXR:
    routes = None

    def __init__(self, hostname: str, username: str=None, password: str=None):
        device = {
            'host': hostname,
            'username': (username if username else os.getenv('netmgmtuser')),
            'password': (password if password else os.getenv('netmgmtpass')),
            'device_type': 'cisco_xr',
            'banner_timeout': 8
        }
        self.session = CiscoXrSSH(**device)
        self.vrf = Container('vrf', VRF)
        self.interface = Container('interface', Interface)
        self.cdp_neighbor = Container('cdp_neighbor', CDPNeighbor)
        self.subnets = Container('subnets', Subnet)

        self.running_config = self.session.send_command('show run')
        self.hostname = re.search(r'hostname ([^\n]+)', self.running_config).group(1)
        self.vrf_configs = [x.group() for x in re.finditer(r'(?m)^vrf [^\n]+\n( +[^\n]+\n)+', self.running_config)]
        self.interface_configs = [x.group() for x in re.finditer(r'(?m)^interface [^\n]+\n( +[^\n]+\n)+',
                                                                 self.running_config)]

        # Process VRFs
        for v in self.vrf_configs:
            vrf = VRF(v)
            self.vrf.add(vrf.name, vrf)

        # Process Interface Configs
        for intf in self.interface_configs:
            intf = Interface(intf.split('\n'))
            attribute_name = re.sub('[-./]', '_', intf.abbr)
            intf.vrf = self.vrf.get('name', intf.vrf)
            self.interface.add(attribute_name, intf)

        # Process Networks
        for intf in self.interface:
            ips = re.findall(r'ip.*? address (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
                             intf.config)
            for ip in ips:
                prefix = Subnet.convert_to_cidr(ip)
                subnet = Subnet(prefix=prefix)
                subnet.interface = intf
                subnet.description = intf.description
                subnet.vrf = intf.vrf
                vlan = re.search(r'dot1q (\d+)', intf.config)
                if vlan:
                    subnet.vlan = int(vlan.group(1))
                self.subnets.add('net_%s' % re.sub(r'[./]', '_', subnet.network.with_prefixlen), subnet)

        # Process CDP neighbors
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

    def __enter__(self):
        return self

    def __exit__(self, x, y, z):
        self.session.disconnect()

    def get_routes(self):
        routing_table = self.session.send_command('show route vrf hca', read_timeout=60)
        routes = re.finditer(r'(\d+\.){3}\d+/\d+', routing_table)
        routes = list((IPv4Network(route.group()) for route in list(routes)))
        self.routes = list(set(routes))
        self.routes.remove(IPv4Network('0.0.0.0/0'))
        self.routes.sort()

    def ip_lookup(self, ip: str, vrf: str=None) -> str or None:
        """Returns the most specific prefix for a given IP address"""
        vrf = (vrf if vrf else 'hca')
        output = self.session.send_command(f'show route vrf {vrf} {ip}')
        prefixes = set(_ for _ in re.findall(r'Routing entry for ([^\n]+)', output))
        prefixes = [IPv4Network(_) for _ in prefixes]
        prefixes.sort(key=lambda x: x.prefixlen)

        if prefixes[-1].with_prefixlen == '0.0.0.0/0':
            return None
        else:
            return prefixes[-1].with_prefixlen

    def prefix_lookup(self, cidr: str) -> IPv4Network or None:
        """Finds specific prefix only"""
        network = IPv4Network(cidr, strict=False)

        output = self.session.send_command(f'show route vrf all {network}')
        prefixes = set(_ for _ in re.findall(r'Routing entry for ([^\n]+)', output))

        if prefixes:
            return network
        else:
            return None

    def route_lookup(self, ip: str, vrf: str=None) -> Route:
        vrf = (vrf if vrf else "hca")
        output = self.session.send_command(f'show route vrf {vrf} {ip}')
        route = Route(route=output, vrf=vrf)
        return route

    def find_a_slash_16(self) -> List[IPv4Network]:
        base = [IPv4Network(f'10.{i}.0.0/16') for i in range(256)]
        networks = []
        for i in base:
            output = self.session.send_command(f'show route vrf hca longer-prefixes {i}')
            if 'No matching routes found' in output:
                networks.append(i)

        return networks

    def bgp_lookup(self, route: Route):
        if route.protocol not in ['ibgp', 'ebgp']:
            route.communities = None
            route.origin_as = None
            return None

        # TODO: Find more attributes that could be added from BGP output
        output = self.session.send_command(f'show bgp vrf {route.vrf} {route.network}')
        communities = re.findall(r'Community: ([^,\n]+)', output)
        route.communities = set(community for c in communities for community in re.split(r'\s+', c))
        as_list = re.findall(r'(\d{5})[,\n]', output)
        route.origin_as = max(set(as_list), key=as_list.count)

    @classmethod
    def get_wan_bgp_peer_configs(cls, router_ip: str, parent_interface: str, vrf: str):
        # TODO: This method needs to be fixed to use netmiko
        host = cls(router_ip)
        interfaces = host.session.get_interfaces_ip()
        bgp_config = host.session.get_bgp_neighbors()
        bgp_config_vrf = bgp_config[vrf]
        local_as = re.search(r'"local_as": (\d+)', json.dumps(bgp_config))[1]
        neighbor_groups = set()
        prefix_sets = set()
        neighbors = ''
        network_list = []
        for interface in interfaces:
            if parent_interface in interface:
                ip = list(interfaces[interface]['ipv4'].keys())[0]
                cidr = interfaces[interface]['ipv4'][ip]['prefix_length']
                network_list.append(IPv4Network(f'{ip}/{cidr}', strict=False))

        for peer in bgp_config_vrf['peers']:
            peer_ip = IPv4Network(peer)
            for network in network_list:
                if network.overlaps(peer_ip):
                    r = host.session.cli([f'show run router bgp {local_as} vrf {vrf} neighbor {peer_ip.network_address}'])
                    output = list(r.values())[0]
                    neighbor_group = re.search(r'neighbor-group (\S+)', output)
                    if neighbor_group:
                        neighbor_groups.add(neighbor_group[1])
                    neighbors += output[output.index('neighbor'):].replace('!', '')

        neighbor_group_config = ''
        if neighbor_groups:
            for neighbor_group in neighbor_groups:
                r = host.session.cli([f'show run router bgp {local_as} neighbor-group {neighbor_group}'])
                output = list(r.values())[0]
                neighbor_group_config += output[output.index('neighbor'):].replace('!', '')

        r_bgp_config = f'router bgp {local_as}\n\n' + neighbor_group_config + f'\nvrf {vrf}\n\n' + neighbors

        route_policies = set(re.search(r'\S+$', a).group() for a in re.findall(r'route-policy \S+', r_bgp_config))
        route_policy_config = ''

        for route_policy in route_policies:
            output = host.session.cli([f'show rpl route-policy {route_policy}'])
            output = list(output.values())[0]
            route_policy_config += '\n' + output.replace('!', '')

        community_sets = set(re.search(r'\S+$', a).group()
                             for a in re.findall(r'community matches-any [-\w]+', route_policy_config))
        prefix_sets = set(re.search(r'\S+$', a).group()
                          for a in re.findall(r'destination in [-\w]+', route_policy_config))

        community_set_config = ''
        prefix_set_config = ''

        for community_set in community_sets:
            output = host.session.cli([f'show rpl community-set {community_set}'])
            output = list(output.values())[0]
            community_set_config += '\n' + output.replace('!', '')

        for prefix_set in prefix_sets:
            output = host.session.cli([f'show rpl prefix-set {prefix_set}'])
            output = list(output.values())[0]
            prefix_set_config += '\n' + output.replace('!', '')

        complete_config = '\n\n'.join([prefix_set_config, community_set_config, route_policy_config, r_bgp_config])

        # pyperclip.copy(complete_config)
        # print('The configuration has been copied to your clipboard.  Paste the configuration into a text document.')

        return complete_config


def subnet_exists(cidr: str):
    cidr = IPv4Network(cidr, strict=False)

    host = IOSXR('10.0.255.45')

    ip_lookup = host.ip_lookup(str(cidr.network_address), vrf='hca')
    prefix_lookup = host.prefix_lookup(cidr.with_prefixlen)

    if ip_lookup == cidr.with_prefixlen or prefix_lookup == cidr.with_prefixlen:
        return 200, {'exists': True, 'subnet': cidr.with_prefixlen}
    if not isinstance(ip_lookup, list) and IPv4Network(ip_lookup):
        network = IPv4Network(ip_lookup)
        if network.overlaps(cidr):
            return 200, {'exists': True, 'subnet': network.with_prefixlen}
    if not isinstance(prefix_lookup, list) and IPv4Network(prefix_lookup):
        network = IPv4Network(prefix_lookup)
        if network.overlaps(cidr):
            return 200, {'exists': True, 'subnet': network.with_prefixlen}
    else:
        return 200, {'exists': False, 'subnet': None}
