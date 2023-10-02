from cisco.classes import *
from ipaddress import IPv4Address, IPv4Network, AddressValueError
from nexus import nexus_tools
from data.information import getNexusEnvironments
from data.environments import NexusEnvironment
from netmiko.cisco import CiscoNxosSSH
from ipam.utils import BIG
from typing import List
import pyperclip
import re
import os
import json
import ftplib
from io import BytesIO
from concurrent.futures.thread import ThreadPoolExecutor
import concurrent


class TraceData:
    via = None
    trace_data = None

    def __init__(self, interface: dict = None, trace_content: dict = None, **kwargs):
        for arg in kwargs:
            self.__setattr__(arg, kwargs[arg])

        if trace_content is not None:
            self.trace_data = trace_content

        if interface is not None:
            self.via = interface


class NXOS:
    def __init__(self, host: str, username: str=None, password: str=None):
        if IPv4Address(host):
            self.host = host

            if username and password:
                self.session = CiscoNxosSSH(ip=host, username=username, password=password)
            else:
                self.session = CiscoNxosSSH(ip=host, username=os.getenv('netmgmtuser'),
                                            password=os.getenv('netmgmtpass'))

            self.interface = Container('interface', Interface)
            self.vlans = Container('vlans', VLAN)
            self.subnets = Container('subnets', Subnet)
            self.cdp_neighbors = Container('cdp_neighbor', CDPNeighbor)
            self.vrf = Container('vrf', VRF)
            self.env = None
            self.running_config = self.exec_command('show run')
            self.config_list = nexus_tools.nx_string_split(self.running_config)
            self.hostname = re.search(r'\S+$', re.search(r'[hostwic]+name \S+', self.running_config).group()).group()
            self.version = re.search(r'\S+$', re.search(r'version \S+', self.running_config).group()).group()
            self.__port_modes = False  # Tracks whether NXOS.get_interface_port_modes has been invoked

            # Populate Local VPC Information
            if 'vpc domain' in self.running_config:
                domain = re.search(r'vpc domain (\d+)', self.running_config)[1]
                peer, vpc_self = re.search(r'peer-keepalive.*destination ([.\d+]+).*source ([.\d+]+)',
                                           self.running_config).groups()
                self.vpc = VPC(domain, vpc_self, peer)

            self.vrf_configs = list(x.group()
                                    for x in re.finditer(r'(?m)^vrf context [^\n]+\n( +[^\n]+\n)+',
                                                         self.running_config))

            default_statics = re.findall(r'(?m)^ip route [^\n]+', self.running_config)
            def_vrf = VRF('vrf context default\n' + '\n  '.join(default_statics))
            def_vrf.staticroute = Container('staticroute', StaticRoute)
            self.vrf.add(def_vrf.name, def_vrf)

            for v in self.vrf_configs:
                vrf = VRF(v)
                vrf.staticroute = Container('staticroute', StaticRoute)
                self.vrf.add(vrf.name, vrf)

            # Process static routes
            for vrf in self.vrf:
                static_routes = re.findall(r'ip route [^\n]+', vrf.config)
                for static_route in static_routes:
                    route = StaticRoute(route=static_route)
                    attribute_name = re.sub(r'[./]', '_', f'net_{route.prefix}_{route.next_hop}')
                    vrf.staticroute.add(attribute_name, route)

            # Load interface information into Container class
            self.interface_configs = list(x.group()
                                          for x in re.finditer(r'(?m)^interface[^\n]+\n( +[^\n]+\n)+',
                                                               self.running_config))
            # self.interface_status = self.session.get_interfaces()  # This method does not work on some Nexus platforms

            for interface in self.interface_configs:
                attribute_name = re.search(r'interface ([^\n]+)', interface).group(1)
                attribute_name = re.sub(r'[-./]', '_', attribute_name)
                interface = Interface(interface.split('\n'))
                if 'vpc peer-link' in interface.config:
                    self.vpc.peer_link = interface
                vrf = re.search(r'vrf member (\S+)', interface.config)
                interface.vrf = (self.vrf.get('name', vrf.group(1)) if vrf else self.vrf.get('name', 'default'))
                self.interface.add(attribute_name, interface)

            for interface in self.interface:
                # Get networks found on interfaces with IPs and load into subnets
                if re.search(r'ip address \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}', interface.config):
                    subnets = re.findall(r'ip address (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})', interface.config)
                    for subnet in subnets:
                        csubnet = Subnet(subnet)
                        csubnet.description = interface.description
                        if interface.name.lower().startswith('vlan'):
                            csubnet.vlan = int(re.search(r'\d+', interface.name).group())
                        csubnet.interface = interface
                        self.subnets.add('net_%s' % re.sub(r'[./]', '_', csubnet.network.with_prefixlen), csubnet)

            # Populate Port Channel member information
            for intf in self.interface:
                if intf.type == 'physical':
                    if intf.member_of is not None:
                        po = self.interface.get('abbr', intf.member_of)
                        po.members.append(intf.abbr)

            # Process CDP Neighbors
            output = self.session.send_command('show cdp neighbor detail')
            output = re.split('Device', output)
            for n in output:
                if re.search(r'ID:\s*', n):
                    neighbor = CDPNeighbor(n)
                    attribute_name = re.sub(r'[-.]', '_', neighbor.device_id)

                    search = self.cdp_neighbors.get('device_id', neighbor.device_id)

                    if search is not None:
                        search += neighbor
                    else:
                        self.cdp_neighbors.add(attribute_name, neighbor)

            for neighbor in self.cdp_neighbors:
                for interface in neighbor.local_interfaces:
                    intf = self.interface.get('name', interface)
                    intf.cdp_neighbor = neighbor

            # Collect VLAN Information
            vlans = self.exec_command('show vlan brief | inc active')
            vlans = nexus_tools.nx_string_split(vlans)
            for vlan in vlans:
                try:
                    vlan_id, vlan_name = re.search(r'^(\S+)\s+(\S+)', vlan).groups()
                except AttributeError:
                    continue
                self.vlans.add(f'vlan{vlan_id}', VLAN(int(vlan_id), vlan_name))

            self.neighbor_check = []
            self.neighbor_check += [x.local_interfaces for x in self.cdp_neighbors]

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logout()

    def login(self):
        if self.session.is_alive():
            pass
        else:
            self.session.establish_connection()

    def logout(self):
        self.session.disconnect()

    @classmethod
    def login_to_environment(cls, env):
        env = NexusEnvironment(env)
        host = cls(env.l3switch1)
        host.env = env
        return host

    def exec_command(self, command: str, read_timeout: int=60) -> str:
        """
        Returns string output of the executed command
        """
        output = self.session.send_command(command, read_timeout=read_timeout)
        return output

    def configure(self, commands: list):
        self.session.send_config_set(commands)
        self.exec_command('copy run start')

    @staticmethod
    def store_file(filename: str, content):
        file = BytesIO(content.encode())
        conn = ftplib.FTP()
        conn.connect(host='corpsupdsk137.hca.corpad.net', port=ftplib.FTP_PORT)
        conn.login(user='anonymous')
        conn.storbinary('STOR %s' % filename, file)
        conn.close()

    def copy_to_ftp(self, filename: str):
        self.session.send_command(
            'copy %s ftp://anonymous@10.249.8.18/%s vrf management\r\r' % (filename, filename),
            expect_string='Password: ',
        )
        self.session.send_command(' ', expect_string='Copy complete')

    def copy_from_ftp(self, filename: str,):
        self.session.send_command(
            'copy ftp://anonymous@10.249.8.18/%s napis_%s vrf management\r\r' % (filename, filename),
            expect_string='Password: ',
        )
        self.session.send_command(' ', expect_string='Copy complete')

    def cleanup_file_system(self):
        """Deletes all files copied to device by automation processes"""
        self.session.send_command('del napis_* no-prompt')

    def get_next_vlan(self, env: str=None, offset: int=0) -> int:
        if self.__getattribute__('env'):
            low, high = self.env.vlanRange.split('-')
        else:
            env = NexusEnvironment(env.upper())
            low, high = env.vlanRange.split('-')

        vlan_range = set(range(int(low), int(high) + 1))

        existing_vlans = list((self.vlans.__getattribute__(attr).id
                               for attr in dir(self.vlans)
                               if isinstance(self.vlans.__getattribute__(attr), VLAN)))
        existing_vlans = [_ for _ in existing_vlans if int(low) <= _ <= int(high)]

        existing_vlans.sort()

        unused_vlans = vlan_range.symmetric_difference(set(existing_vlans))

        return list(unused_vlans)[offset]

    def mac_lookup(self, mac):
        valid_neighbor = [
            'N5K-C5548P',
            'N9K-C93180YC-EX',
            'N7K-C7004',
            'N5K-C5548UP',
            'N5K-C5596UP',
            'WS-C3750X-48P',
            'N9K-C93180YC-',
            'N7K-C7010',
            'cisco WS-C3750X-48P',
            'N9K-C9396PX'
        ]

        mac = re.sub(r'[.:-]', '', mac)
        mac = mac.lower()
        mac = mac[:4] + '.' + mac[4:8] + '.' + mac[8:]

        if not re.match(r'^[a-f\d]{4}\.[a-f\d]{4}\.[a-f\d]{4}$', mac):
            return 'Invalid MAC address supplied'

        command = f'show mac address-table dynamic address {mac} | include dynamic'
        output = self.exec_command(command)

        if len(output) == 0:
            return False, None, None

        interface = re.search(r'\S+$', output).group()
        if interface.lower() == 'peer-link':
            interface = self.vpc.peer_link
            interface.__delattr__('config')
        else:
            interface = next(self.interface.__getattribute__(attr)
                             for attr in dir(self.interface)
                             if isinstance(self.interface.__getattribute__(attr), Interface)
                             if self.interface.__getattribute__(attr).abbr == interface)
            # interface = self.interface.__getattribute__(interface.replace('Po', 'port_channel'))
            interface.__delattr__('config')

        if interface.type == 'port-channel':
            for member in interface.members:
                if member in self.neighbor_check:
                    neighbor = next(x for x in self.cdp_neighbors if x.local_interface in interface.members)
                    if neighbor.platform in valid_neighbor:
                        return True, neighbor, interface
                    else:
                        return False, None, interface
            return False, None, interface
        else:
            if interface.abbr in self.neighbor_check:
                neighbor = next(x for x in self.cdp_neighbors if x.local_interface == interface.abbr)
                if neighbor.platform in valid_neighbor:
                    return True, neighbor, interface
                else:
                    return False, None, interface
            else:
                # print('Return 5')
                # print(interface)
                return False, None, interface

    def vlan_lookup(self, vlan=None):
        if vlan is None:
            active_vlans = {self.vlans.__getattribute__(attr).id: []
                            for attr in dir(self.vlans) if isinstance(self.vlans.__getattribute__(attr), VLAN)}
            output = self.exec_command('show mac address-table dynamic | inc dynamic')
            output = output.split('\n')

            for line in output:
                if re.match(r'^.*\d+.*\S+$', line):
                    active_vlans[int(re.search(r'\d+', line).group())].append(re.search(r'\S+$', line).group())

            for key in active_vlans.keys():
                active_vlans[key] = list(set(active_vlans[key]))

            return active_vlans

        elif isinstance(vlan, int):
            output = self.exec_command(fr'show mac address-table dynamic vlan {vlan} | include ^[\*,\+]')
            output = output.split('\n')
            interface_list = []

            for line in output:
                try:
                    interface_list.append(re.search(r'\S+$', line).group())
                except AttributeError:
                    continue

            interface_list = list(set(interface_list))

            return interface_list

    def get_empty_vlans(self) -> List[int]:
        existing_vlans = list((self.vlans.__getattribute__(attr).id
                               for attr in dir(self.vlans)
                               if isinstance(self.vlans.__getattribute__(attr), VLAN)))

        empty_vlans = []

        for v in existing_vlans:
            output = self.exec_command(f'show mac address count vlan {v}')
            mac_address_count = re.findall(r'\d+', output)
            mac_address_count = sum(int(x) for x in mac_address_count)

            if mac_address_count == 0:
                empty_vlans.append(v)

        empty_vlans.sort()

        return empty_vlans

    @classmethod
    def create_new_svi(cls, env: str, no_of_ips: int, name: str, description: str=None, vrf: str=None, dhcp: bool=False,
                       **kwargs):
        env = NexusEnvironment(env)

        switch_1 = cls(env.l3switch1)
        switch_2 = cls(env.l3switch2)

        # env.name is being used because there is some dependency on an old process getNexusEnvironments()
        vlan = switch_1.get_next_vlan(env.name)

        big = BIG()

        subnet = big.assign_next_network_from_list(block_list=env.Subnets, name='', no_of_ips=no_of_ips,
                                                   coid=int(env.COID), asn=int(env.ASN))

        if not subnet:
            big.logout()
            return 400, [f'{env.name} has no available network for the required number of IPs.']

        big.logout()

        subnet = IPv4Network(subnet.properties['CIDR'])

        hsrp_ip = subnet.network_address + 1
        switch_1_ip = subnet.network_address + 2
        switch_2_ip = subnet.network_address + 3

        commands_1 = [
            f'vlan {vlan}',
            f'name {name.replace(" ", "_")}',
            f'interface Vlan{vlan}',
            (f'vrf member {vrf}' if vrf in env.vrfs else ''),
            f'ip address {switch_1_ip}/{subnet.prefixlen}',
            'hsrp 1',
            f'ip {hsrp_ip}',
            'timers 1 3',
            'priority 105',
            'preempt delay minimum 300',
            f'ip router ospf {env.ospfID} area {env.ospfArea}',
            'no shutdown',
            (f'description {description}' if description is not None else f'description {name}')
        ]

        commands_2 = [
            f'vlan {vlan}',
            f'name {name.replace(" ", "_")}',
            f'interface Vlan{vlan}',
            (f'vrf member {vrf}' if vrf in env.vrfs else ''),
            f'ip address {switch_2_ip}/{subnet.prefixlen}',
            'hsrp 1',
            f'ip {hsrp_ip}',
            'timers 1 3',
            'preempt delay minimum 300',
            f'ip router ospf {env.ospfID} area {env.ospfArea}',
            'no shutdown',
            (f'description {description}' if description is not None else f'description {name}')
        ]

        if dhcp is True:
            for command_set in [commands_1, commands_2]:
                for relay in env.dhcpRelay:
                    command_set.append(f'ip dhcp relay address {relay}')

        switch_1.configure(commands_1)
        switch_2.configure(commands_2)

        return 200, {'VLAN': vlan, 'Subnet': subnet.with_prefixlen, 'Name': name}

    def self_data(self):
        if self.vpc is not None:
            return {
                'VPC Domain': self.vpc.domain,
                'Self': self.vpc.self,
                'Peer': self.vpc.peer,
                'Hostname': self.hostname
            }
        else:
            return {
                'VPC Domain': None,
                'Self': self.host,
                'Peer': None,
                'Hostname': self.hostname
            }

    @classmethod
    def get_vlan_information(cls, env, vlan: str or int):
        vlan = str(vlan)
        host = cls.login_to_environment(env)
        subnets = [subnet.network.with_prefixlen for subnet in host.subnets if vlan == subnet.vlan]
        try:
            vlan = host.vlans.__getattribute__(f'vlan{vlan}')
        except AttributeError:
            return 404, {'message': 'VLAN was not found'}

        response = {
            'vlan_id': vlan.id,
            'vlan_name': vlan.name,
            'subnets': subnets
        }

        return 200, response

    def get_subnet(self, ip_address: str):
        for subnet in self.subnets:
            if IPv4Network(ip_address, strict=False).overlaps(subnet.network):
                return subnet

    @classmethod
    def trace_ip(cls, environment: str, ip_address):
        host = cls.login_to_environment(environment)
        subnet = host.get_subnet(ip_address)
        ip_address = IPv4Network(ip_address)

        output = host.exec_command(f'show ip arp vrf all | inc {str(ip_address.network_address)}')
        if not output:
            return 404, {'message': 'No ARP entry exists for the IP addresses that was provided'}

        mac_address = re.split(r'\s+', output)[2]

        trace_data = mac_lookup(host.host, mac_address)

        return_data = {
            'IPAddress': str(ip_address.network_address),
            'MACAddress': mac_address,
            'Subnet': subnet.network.with_prefixlen,
            'VLAN': int(subnet.vlan),
            'TraceData': trace_data
        }

        return 200, return_data

    @classmethod
    def shutdown_network(cls, environment: str, subnet: str):
        """Removes a subnet from an interface if found in the target environment"""
        env = NexusEnvironment(environment)

        host_1 = NXOS(env.l3switch1)
        subnet_1 = host_1.get_subnet(subnet)

        host_2 = NXOS(env.l3switch2)
        subnet_2 = host_2.get_subnet(subnet)

        if subnet_1:
            commands_1 = [
                f'interface {subnet_1.interface.abbr}',
                f'no ip address {subnet_1.address}/{subnet_1.network.prefixlen}'
            ]
            host_1.configure(commands_1)

        if subnet_2:
            commands_2 = [
                f'interface {subnet_2.interface.abbr}',
                f'no ip address {subnet_2.address}/{subnet_2.network.prefixlen}'
            ]
            host_2.configure(commands_2)

        return 200, {'message': 'Subnet has been removed', 'Switch1Interface': subnet_1.interface.name,
                     'Switch2Interface': subnet_2.interface.name, 'Subnet': subnet_1.network.with_prefixlen}

    @classmethod
    def create_custom_svi(cls, environment: str, subnet: str, description: str, vlan: int=None, vrf: str=None):
        """Build a customized network with specific subnet, VLAN ID, and VRF assignment.  Primarily for DR recovery."""
        # Verify validity of specified subnet
        try:
            subnet = IPv4Network(subnet, strict=False)
        except AddressValueError:
            return 400, {'message': 'Subnet Provided is invalid'}

        host = cls.login_to_environment(env=environment)
        env = NexusEnvironment(environment)

        commands_1 = []
        commands_2 = []

        if vlan is None:
            vlan = host.get_next_vlan(env.name)

        vlan_info = host.vlans.__dict__.get(f'vlan{vlan}')

        if vlan_info is None:
            vlan_info = VLAN(vlan_id=vlan, name=description.replace(' ', '_'))

            commands_1.append(f'vlan {vlan_info.id}')
            commands_1.append(f'name {vlan_info.name}')

            commands_2.append(f'vlan {vlan_info.id}')
            commands_2.append(f'name {vlan_info.name}')

        vlan_interface = host.interface.__dict__.get(f'Vlan{vlan_info.id}')

        vrf = (vrf.lower() if vrf in env.vrfs else env.defaultVRF)

        if vlan_interface:
            commands_1.append(f'interface vlan{vlan_info.id}')
            commands_1.append(f'ip address {subnet.network_address + 2}/{subnet.prefixlen} secondary')
            commands_1.append(f'hsrp {vlan_interface.hsrp_groups[-1] + 1}')
            commands_1.append(f'ip {subnet.network_address + 1}')
            commands_1.append('priority 105')
            commands_1.append('preempt delay minimum 300')
            commands_1.append('timers 1 3')

            commands_2.append(f'interface vlan{vlan_info.id}')
            commands_2.append(f'ip address {subnet.network_address + 3}/{subnet.prefixlen} secondary')
            commands_2.append(f'hsrp {vlan_interface.hsrp_groups[-1] + 1}')
            commands_2.append(f'ip {subnet.network_address + 1}')
            commands_2.append('preempt delay minimum 300')
            commands_2.append('timers 1 3')
        else:
            commands_1.append(f'interface vlan{vlan_info.id}')
            commands_1.append((f'vrf member {vrf}' if vrf else '!'))
            commands_1.append(f'description {description}')
            commands_1.append(f'ip address {subnet.network_address + 2}/{subnet.prefixlen}')
            commands_1.append(f'ip router ospf 1 area {env.ospfArea}')
            commands_1.append(f'hsrp 1')
            commands_1.append(f'ip {subnet.network_address + 1}')
            commands_1.append('priority 105')
            commands_1.append('preempt delay minimum 300')
            commands_1.append('timers 1 3')
            commands_1.append('no shutdown')

            commands_2.append(f'interface vlan{vlan_info.id}')
            commands_2.append((f'vrf member {vrf}' if vrf else '!'))
            commands_2.append(f'description {description}')
            commands_2.append(f'ip address {subnet.network_address + 3}/{subnet.prefixlen}')
            commands_2.append(f'ip router ospf 1 area {env.ospfArea}')
            commands_2.append(f'hsrp 1')
            commands_2.append(f'ip {subnet.network_address + 1}')
            commands_2.append('preempt delay minimum 300')
            commands_2.append('timers 1 3')
            commands_2.append('no shutdown')

        host_1 = cls(env.l3switch1)
        host_2 = cls(env.l3switch2)

        host_1.configure(commands_1)
        host_2.configure(commands_2)

        result_1 = host_1.exec_command(f'show run interface vlan{vlan}')
        result_2 = host_2.exec_command(f'show run interface vlan{vlan}')

        if 'Invalid range at' in result_1 or 'Invalid range at' in result_2:
            return 400, {'message': 'Partial or Complete Failure', 'Switch1': result_1, 'Switch2': result_2}
        elif f'{subnet.network_address + 1}' not in result_1 or f'{subnet.network_address + 1}' not in result_2:
            return 400, {'message': 'Partial or Complete Failure', 'Switch1': result_1, 'Switch2': result_2}
        else:
            return 200, {'message': 'Configuration Succeeded', 'Switch1': result_1, 'Switch2': result_2}

    def get_interface_port_modes(self, update: bool=False):
        if update:
            pass
        elif self.__port_modes:
            # Method has already been run
            return None

        for interface in self.interface:
            if interface.type == 'vlan':
                output = self.exec_command('show int %s | inc ^V' % interface.name)

                admin_state = re.search('administratively down', output, flags=re.IGNORECASE)
                state = re.search(r'protocol is (\w+)', output, flags=re.IGNORECASE).group(1)

                interface.is_enabled = (False if admin_state else True)
                interface.is_up = (False if state.lower() == 'down' else True)
                interface.mode = 'routed'
                continue

            output = self.exec_command('show int %s | egrep "[0-9] is|state is|rt mode is"' % interface.name)

            state, admin_state, mode = re.search(r'\d is ([-\w]+)[\s\S]+state is ([-\w]+)[\s\S]+mode is ([-\w]+)',
                                                 output).groups()

            interface.is_up = (True if state == 'up' else False)
            interface.is_enabled = (False if admin_state == 'admin-down' else True)
            interface.mode = mode

        self.__port_modes = True

    def shutdown_interface(self, intf: Interface) -> None:
        config = [
            f'interface {intf.name}',
            f' shutdown'
        ]

        _ = self.session.send_config_set(config)

    def enable_interface(self, intf: Interface) -> None:
        config = [
            f'interface {intf.name}',
            f' no shutdown'
        ]

        _ = self.session.send_config_set(config)

    def generate_l2_uplink_data(self) -> List[dict]:
        self.get_interface_port_modes()
        neighbor_data = {}

        for neighbor in self.cdp_neighbors:
            if '-LF-' in neighbor.device_id or '-BLF-' in neighbor.device_id:
                continue  # This is because it is a leaf switch

            interface = self.interface.get('abbr', neighbor.local_interface)

            if interface.member_of == self.vpc.peer_link.abbr:
                continue  # Do not process the VPC links

            if neighbor.local_interface.lower() == 'mgmt0' or neighbor.remote_interface.lower() == 'mgmt0':
                continue  # No need to process management interface connections

            if neighbor.device_id not in neighbor_data.keys():
                if interface.mode in ['trunk', 'access']:
                    neighbor_data[neighbor.device_id] = {
                        'remote_interfaces': [neighbor.remote_interface],
                        'local_interfaces': [neighbor.local_interface],
                        'platform': neighbor.platform,
                        'name': neighbor.device_id,
                        'ip': neighbor.ip_addresses[-1]  # Last IP usually is Management
                    }
            else:
                neighbor_data[neighbor.device_id]['remote_interfaces'].append(neighbor.remote_interface)
                neighbor_data[neighbor.device_id]['local_interfaces'].append(neighbor.local_interface)

        neigh_list = [neighbor_data[kw] for kw in neighbor_data.keys()]
        neigh_list.sort(key=lambda x: x['name'])

        pyperclip.copy(json.dumps(neigh_list, indent=2))
        print('Data has been copied to your clipboard')

        return neigh_list

    def generate_l3_link_data(self) -> list:
        self.get_interface_port_modes()

        l3_interfaces = set()  # This will be a set of interface names

        static_next_hops = set(re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
                                          self.exec_command('show ip route static vrf all | grep static')))
        for hop in static_next_hops:
            subnet = self.get_subnet(ip_address=hop)
            l3_interfaces.add(subnet.interface.name)

        routed_interfaces = [_.name for _ in self.interface if _.type != 'vlan'
                             if _.mode == 'routed' and _.is_enabled and _.is_up]

        l3_interfaces = l3_interfaces.union(set(routed_interfaces))

        return list(l3_interfaces)

    def generate_svi_recovery_script(self) -> str:
        output = self.exec_command('show ip int brief vrf all | inc "^Vl"').strip('\n')
        script = ''
        for line in output.split('\n'):
            intf, state = re.search(r'^(\S+).*?([-\w]+)$', line.strip()).groups()
            if state == 'admin-down':
                continue
            else:
                script += 'interface %s\n  no shutdown\n\n' % intf

        pyperclip.copy(script)
        filename = '%s_svi_recovery.txt' % self.hostname
        self.store_file(filename=filename, content=script)
        self.copy_from_ftp(filename=filename)
        print('Script has been copied to your clipboard and to the device')
        return script

    def generate_svi_shutdown_script(self) -> str:
        script = ''

        for interface in self.interface:
            if interface.type == 'vlan':
                script += 'interface %s\n shutdown\n\n' % interface.name

        pyperclip.copy(script)
        filename = '%s_svi_shutdown.txt' % self.hostname
        self.store_file(filename=filename, content=script)
        self.copy_from_ftp(filename=filename)
        print('Script has been copied to your clipboard and to the device')
        return script

    def generate_hsrp_script(self, active: bool, priority: int=100) -> str:
        script = ''

        for interface in self.interface:
            if interface.hsrp_groups:
                script += 'interface %s\n ' % interface.name
                for group in interface.hsrp_groups:
                    script += 'hsrp %d\n  priority %d\n  exit\n ' % (group, (250 if active else priority))
                script += 'exit\n\n'

        filename = '%s_hsrp_%s.txt' % (self.hostname, ('active' if active else 'recovery'))
        self.store_file(filename=filename, content=script)
        self.copy_from_ftp(filename=filename)
        pyperclip.copy(script)
        print('Script has been copied to your Clipboard and to the device')
        return script

    def generate_hsrp_restore(self) -> str:
        script = ''

        output = self.exec_command('show hsrp brief | egrep "[0-9]{1,3}\\."')
        groups = output.strip('\n').split('\n')

        for group in groups:
            group = group.strip()
            vlan, group_id, priority = re.split(r'\s+', group)[:3]

            script += 'interface %s\n hsrp %s\n  priority %s\n\n' % (vlan, group_id, priority)

        filename = '%s_hsrp_recovery.txt' % self.hostname

        self.store_file(filename=filename, content=script)
        self.copy_from_ftp(filename=filename)
        pyperclip.copy(script)

        print('Script has been copied to you clipboard and to the device')
        return script


def find_ospf_advertisement_difference(a: NXOS, b: NXOS):
    status_search = re.compile(r'ip router ospf \d+ area (\d{1,3}\.){3}\d{1,3}')

    inconsistent_configurations = set()

    a.get_interface_port_modes()
    b.get_interface_port_modes()

    def compare(x, y):
        for a_interface in x.interface:
            if a_interface.mode == 'routed':
                b_interface = y.interface.get('name', a_interface.name)

                if not b_interface:
                    inconsistent_configurations.add(a_interface.name)
                    continue

                # Search configuration for OSPF advertisement expression
                a_status = status_search.search(a_interface.config)
                b_status = status_search.search(b_interface.config)

                if a_status is None and b_status is None:
                    continue
                elif a_status is None or b_status is None:
                    inconsistent_configurations.add(a_interface.name)
                    continue

                if a_status.group() != b_status.group():
                    inconsistent_configurations.add(a_interface.name)

    # Compare backwards and forwards
    compare(a, b)
    compare(b, a)

    return inconsistent_configurations


def find_hsrp_difference(a: NXOS, b: NXOS):
    """Finds differences in interfaces participating in HSRP as well as group numbers and IPs per interface"""
    search = re.compile(r'(\S+)\s+(\d+)\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\S+)')

    inconsistent_configurations = set()
    output1 = a.session.send_command('show hsrp brief')
    output2 = b.session.send_command('show hsrp brief')

    groups1 = re.findall(search, output1)
    groups2 = re.findall(search, output2)

    for g1, g2 in zip(groups1, groups2):
        if g1 == g2:
            continue
        else:
            inconsistent_configurations.add(g1[0])

    return inconsistent_configurations


def compare_static_routes(a: NXOS, b: NXOS):
    """Finds differences in static routes per VRF"""
    inconsistencies = []
    a_vrf_list = [vrf.name for vrf in a.vrf]
    b_vrf_list = [vrf.name for vrf in b.vrf]

    a_vrf_list.sort()
    b_vrf_list.sort()

    same_vrfs = a_vrf_list == b_vrf_list
    print('VRFs are the same:', same_vrfs)

    for vrf in a.vrf:
        b_vrf = b.vrf.get('name', vrf.name)

        a_set = {r.id for r in vrf.staticroute}
        b_set = {r.id for r in b_vrf.staticroute}

        print(f'Static route difference for vrf {vrf.name}: ', a_set.symmetric_difference(b_set))


def compare_route_policy(a: NXOS, b: NXOS):
    """Compares prefix-lists, community-lists, and route-maps to check for routing consistency for dynamic protocols
    between a pair of chassis"""
    a_prefix_lists = {_ for _ in re.findall(r'(?m)^ip prefix-list (\S+)', a.running_config)}
    b_prefix_lists = {_ for _ in re.findall(r'(?m)^ip prefix-list (\S+)', b.running_config)}
    a_route_maps = {_ for _ in re.findall(r'(?m)^route-map (\S+)', a.running_config)}
    b_route_maps = {_ for _ in re.findall(r'(?m)^route-map (\S+)', a.running_config)}
    a_community_lists = {_ for _ in re.findall(r'(?m)^ip community-list \S+ (\S+)', a.running_config)}
    b_community_lists = {_ for _ in re.findall(r'(?m)^ip community-list \S+ (\S+)', b.running_config)}

    print('Both devices have same prefix-lists:', a_prefix_lists == b_prefix_lists)
    print('Both devices have same route-maps:', a_route_maps == b_route_maps)
    print('Both devices have same community-lists:', a_community_lists == b_community_lists)

    print('\nPrefix Lists:')
    """ Sample: ip prefix-list connected-interfaces seq 435 permit 10.95.92.0/23 le 32 """
    for prefix_list in a_prefix_lists:
        a_prefixes = {_ for _ in re.findall(
            r'(?m)^ip prefix-list %s \S+ \S+ \S+ (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})\s*([lge]*)\s*(\d*)' %
            prefix_list, a.running_config)}
        b_prefixes = {_ for _ in re.findall(
            r'(?m)^ip prefix-list %s \S+ \S+ \S+ (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})\s*([lge]*)\s*(\d*)' %
            prefix_list, b.running_config)}

        print(f'Results for {prefix_list}: {a_prefixes.symmetric_difference(b_prefixes)}')

    print('\nCommunity Lists:')
    """ Sample: ip community-list expanded COLO-MPLS-VPN permit "269:6550[8-9]" """
    for community_list in a_community_lists:
        a_communities = {_ for _ in re.findall(r'(?m)^ip community-list \S+ %s \S+ \S+' % community_list,
                                               a.running_config)}
        b_communities = {_ for _ in re.findall(r'(?m)^ip community-list \S+ %s \S+ \S+' % community_list,
                                               b.running_config)}

        print(f'Results for {community_list}: {a_communities.symmetric_difference(b_communities)}')

    print('\nRoute Maps:')
    """ Sample: 
        route-map static-drtest permit 10
          match ip address prefix-list static-routes-drtest 
          set metric-type type-1
    """
    for route_map in a_route_maps:
        a_maps = {_.group() for _ in re.finditer(r'(?m)^route-map %s [^\n]+\n( +[^\n]+\n)+' % route_map,
                                                 a.running_config)}
        b_maps = {_.group() for _ in re.finditer(r'(?m)^route-map %s [^\n]+\n( +[^\n]+\n)+' % route_map,
                                                 b.running_config)}

        print(f'Results for {route_map}: {a_maps.symmetric_difference(b_maps)}')

    return None


class NXOSLite:
    def __init__(self, host: str, username: str = None, password: str = None):
        if IPv4Address(host):
            self.host = host

            if username and password:
                self.session = CiscoNxosSSH(ip=host, username=username, password=password)
            else:
                self.session = CiscoNxosSSH(ip=host, username=os.getenv('netmgmtuser'),
                                            password=os.getenv('netmgmtpass'))

            self.login()
            self.hostname = self.session.base_prompt

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logout()

    def login(self):
        if self.session.is_alive():
            pass
        else:
            self.session.establish_connection()

    def logout(self):
        self.session.disconnect()

    def exec_command(self, command: str):
        return self.session.send_command(command)

    def configure(self, config_list: list):
        self.session.send_config_set(config_list)
        return None

    def configure_and_save(self, config_list: list):
        self.session.send_config_set(config_list)
        self.session.save_config()
        return None

    def write(self):
        self.session.save_config()

    @classmethod
    def manage_uplinks(cls, data: list, enabled: bool):
        """Shuts down links of all devices in data.  Input data is output from NXOS.generate_l2_uplink_data()"""
        for device in data:
            config = []
            for interface in device['remote_interfaces']:
                config += ['interface %s' % interface, ('no shutdown' if enabled else 'shutdown')]

            print(device['name'], device['ip'], config)

            host = cls(host=device['ip'])
            host.configure(config_list=config)
            host.session.save_config()

    @classmethod
    def manage_uplinks_v2(cls, data: List[dict], enabled: bool):
        """Shutdown or enable links of all devices in data.  Input data is output from NXOS.cdp_neighbor.__json__()"""
        for device in data:
            config = []
            for interface in device['remote_interfaces']:
                config += ['interface %s' % interface, ('no shutdown' if enabled else 'shutdown')]
            device['config'] = config

            # Display the configs to be sent to devices
            print(device['device_id'], device['ip_addresses'][0], device['config'])

        hosts = [(cls(d['ip_addresses'][0]), d['config']) for d in data]

        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_result = {executor.submit(h.configure_and_save, c): h.hostname for h, c in hosts}

            for future in concurrent.futures.as_completed(future_to_result):
                host = future_to_result[future]
                try:
                    data = future.result()
                except Exception as exc:
                    print('%r generated an exception: %s' % (host.hostname, exc))
                else:
                    print('%s - %s:  \n%s' % (host.hostname, host.host, data))

    @classmethod
    def recursive_commands(cls, data: List[dict], command: str='show cdp neighbor interface mgmt0'):
        with ThreadPoolExecutor(max_workers=5) as executor:
            # Start the load operations and mark each future with its URL
            hosts = [(cls(_['ip_addresses'][0]), command) for _ in data]
            future_to_result = {executor.submit(h.exec_command, c): h for h, c in hosts}

            for future in concurrent.futures.as_completed(future_to_result):
                host = future_to_result[future]
                try:
                    data = future.result()
                except Exception as exc:
                    print('%r generated an exception: %s' % (host.hostname, exc))
                else:
                    print('%s - %s:  \n%s' % (host.hostname, host.host, data))


def get_subnet_information(env: str, ip: str):
    if IPv4Address(ip):
        env = getNexusEnvironments(env)

        host1 = NXOS(env['l3switch1'])

        try:
            subnet = next(subnet for subnet in host1.subnets if IPv4Address(ip) in subnet.network.hosts())
        except StopIteration:
            return 404, [f'Network does not exist in {env["name"]}']

        response = {
            'Subnet': subnet.network.with_prefixlen,
            'Description': subnet.description,
            'Interface': subnet.interface.name,
            'VLAN': subnet.vlan
        }

        return 200, response


def mac_lookup(host, mac):
    host = NXOS(host)
    repeat, neighbor, interface = host.mac_lookup(mac)
    if interface is None:
        return ['MAC Address not found']
    trace_data = TraceData(interface=interface.__dict__, **host.self_data())
    del host
    attempts = 1

    while repeat and isinstance(neighbor, CDPNeighbor):
        host = NXOS(neighbor.ip_addresses[0])
        repeat, neighbor, interface = host.mac_lookup(mac)

        trace_data = TraceData(interface=interface.__dict__, trace_content=trace_data.__dict__, **host.self_data())

        del host

        attempts += 1
        if attempts > 5:
            break

    return trace_data.__dict__
