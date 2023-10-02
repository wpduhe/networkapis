from nexus.runSSHCommands import sshSession
from data.information import getNexusEnvironments
from nexus import nexus_tools
from creds import creds
from napalm import get_network_driver
import ipaddress
import re
import os


class nexusHost:

    def __init__(self, host):
        if bool(ipaddress.IPv4Address(host)) is True:
            print('Please wait while information is being retrieved...')
            self.host = host
            self.run = list(nexus_tools.nx_split_switchport(self.runCommand('show run')))
            self.interfaces = list(config for config in self.run if 'interface' in config[0]
                                   if re.search('^interface', config[0]) is not None)
            self.hostname = next(re.search(r'\S+$', line).group() for config in self.run for line in config
                                 if 'hostname' in line)
            self.poData = self.parsePortChannel()
            self.vpcData = self.getVpcData()
            self.cdpNeigh = self.getCdpNeighbors()
            self.vlanInfo = self.getVlanInfo()
            self.checkNeigh = list(x['Local Interface'] for x in self.cdpNeigh)
            self.json = {}

    def generate_json(self):
        self.json = {
            'hostname': self.hostname,
            'softwareVersion': next(config[0] for config in self.run if 'hostname' in config[1]),
            'mgmt0': next(re.search(r'[0-9\.]+', line).group()
                          for config in self.run if str('interface mgmt0').lower() in config
                          for line in config if 'ip address' in line),
            'NexusEnvironment': 'Gotta figure this one out'
        }

    def get_next_vlan(self, env):
        if not isinstance(env, dict):
            env = getNexusEnvironments(env)

        existing_vlans = list((int(x) for x in self.vlanInfo.keys()))

        for vlan in env['vlanRange']:
            if vlan not in existing_vlans:
                return vlan

    def runCommand(self, command):
        cr = {'username': os.getenv('netmgmtuser'), 'password': os.getenv('netmgmtpass')}
        ssh = sshSession(self.host, cr['username'], cr['password'])
        output = ssh.executeCmd(command)
        ssh.ssh.close()
        return output

    def configure(self, commands):
        cr = {'username': os.getenv('netmgmtuser'), 'password': os.getenv('netmgmtpass')}
        ssh = sshSession(self.host, cr['username'], cr['password'])
        ssh.configure(commands)
        ssh.ssh.close()

    def getVpcData(self):
        vpc = next(config for config in self.run if 'vpc domain' in config[0])

        vpcData = {}

        for line in vpc:
            if 'vpc domain' in line:
                vpcData['Domain'] = re.search(r'\d+', line).group()

            if 'destination' in line:
                result = re.findall(r'[\d\.]+', line)
                vpcData['Peer'] = result[0]
                vpcData['Self'] = result[1]

        return vpcData

    def getCdpNeighbors(self):
        command = 'show cdp neigh detail'
        output = self.runCommand(command)

        if len(output) == 0:
            return 'No CDP neighbors found'

        neighbors = []

        output = ''.join(output)
        output = output.split('----------------------------------------\n')
        for section in output[:]:
            output[output.index(section)] = section.split('\n')
        for section in output[:]:
            neighbor = {'IP Addresses': []}
            for line in section:
                if 'Device ID' in line:
                    line = line.split(':')
                    neighbor['Device ID'] = line[1]

                if 'IPv4 Address' in line:
                    line = line.split(': ')
                    neighbor['IP Addresses'].append(line[1])

                if 'Platform' in line:
                    line = line.split(': ')
                    line = line[1][:line[1].index(',')]
                    neighbor['Platform'] = line

                if 'Interface: ' in line:
                    line = line.split(': ')
                    line[1] = line[1][:line[1].index(',')]
                    neighbor['Local Interface'] = line[1].replace('Ethernet', 'Eth')
                    neighbor['Remote Interface:'] = line[2].replace('Ethernet', 'Eth')

                neighbor['IP Addresses'] = list(set(neighbor['IP Addresses']))

            if 'Device ID' in neighbor.keys():
                neighbors.append(neighbor)
        return neighbors

    def getInterfaces(self):
        command = 'show interface'
        output = self.runCommand(command)
        interfaces = tuple(nexus_tools.nx_split_config(output))

        command = 'show interface switchport'
        output = self.runCommand(command)
        switchports = tuple(nexus_tools.nx_split_switchport(output))

        data = {'Interfaces': interfaces, 'Switchports': switchports}

        return data

    def parsePortChannel(self):
        pos = list(self.run)
        nexus_tools.nx_filter_po(pos)

        phys = list(self.run)
        nexus_tools.nx_filter_phys(phys)

        portChannels = []

        for config in pos:
            intf = {}
            for line in config:
                if 'port-channel' in line:
                    intf['interface'] = 'Po' + re.search(r'[\d+\.]+', line).group()

                if re.search('^description', line) is not None:
                    intf['Description'] = re.sub(' +description ', '', line)

                if 'switchport mode' in line:
                    intf['Mode'] = re.search(r'\S+$', line).group()
                    if intf['Mode'] == 'trunk':
                        intf['Allowed'] = '1-4094'

                if 'switchport access vlan' in line:
                    intf['Access'] = re.search(r'\d+', line).group()

                if 'switchport trunk allowed vlan' in line:
                    try:
                        intf['Allowed'] = re.search(r'[\d+,-]+$', line).group()
                    except AttributeError:
                        pass

                if 'description' in line:
                    intf['description'] = re.search('description.*', line).group().replace('description ', '')

                if re.search(r'vpc \d+', line) is not None:
                    intf['VPC'] = re.search(r'\d+', line).group()

            intf['Members'] = []
            portChannels.append(intf)

        member = ''
        for config in phys:
            for line in config:
                if bool(re.match('^interface', line)):
                    member = re.search(r'\S+$', line).group().replace('Ethernet', 'Eth')

                if 'channel-group' in line:
                    po = 'Po' + re.search(r'\d+', line).group()
                    portChannel = next(x for x in portChannels if x['interface'] == po)
                    portChannel['Members'].append(member)

        return portChannels

    def getVlanInfo(self):
        vlans = self.run[:]
        nexus_tools.nx_filter_vlan(vlans)

        data = {}

        for item in vlans[:]:
            try:
                data[re.search('[0-9]+', item[0]).group()] = re.search(r'\S+', item[1].replace('name', '')).group()
            except IndexError:
                data[re.search('[0-9]+', item[0]).group()] = None

        return data

    def mac_lookup(self, mac):
        macValidate = re.compile(r'^[a-f\d]{4}\.[a-f\d]{4}\.[a-f\d]{4}$')

        neighValidate = [
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

        mac = mac.replace(':', '')
        mac = mac.replace('.', '')
        mac = mac.lower()
        mac = mac[:4] + '.' + mac[4:8] + '.' + mac[8:]

        if bool(macValidate.match(mac)) is False:
            return 'Invalid MAC address supplied'

        command = 'show mac address-table dynamic address ' + mac + ' | include dynamic'
        output = self.runCommand(command)

        if len(output) == 0:
            return 'MAC address was not found on device'

        interface = re.split(' +', output[0])
        interface = interface[len(interface) - 1]
        interface = interface.replace('\n', '')

        if interface.startswith('Po'):
            poInterface = str(interface)
            po = next(x for x in self.poData if x['interface'] == poInterface)
            for interface in po['Members']:
                if interface in self.checkNeigh:
                    neigh = next(x for x in self.cdpNeigh if x['Local Interface'] == interface)
                    if neigh['Platform'] in neighValidate:
                        neigh['via'] = po
                        neigh['proceed'] = True
                        # print('Return 1')
                        # print(neigh)
                        return neigh
                    neigh['via'] = po
                    neigh['proceed'] = False
                    # print('Return 2')
                    # print(neigh)
                    return neigh
            po['proceed'] = False
            # print('Return 3')
            # print(po)
            return po

        else:
            if interface in self.checkNeigh:
                neigh = next(x for x in self.cdpNeigh if x['Local Interface'] == interface)
                neigh['via'] = interface
                # print('Return 4')
                # print(neigh)
                return neigh
            else:
                # print('Return 5')
                # print(interface)
                return interface

    def vlan_lookup(self, vlan):
        if vlan.lower() == 'all':
            active_vlans = {key: [] for key in self.vlanInfo}
            output = self.runCommand('show mac address-table dynamic | inc dynamic')

            for line in output:
                try:
                    active_vlans[re.search('\d+', line).group()].append(re.search('\S+$', line).group())
                except KeyError:
                    pass

            for key in active_vlans.keys():
                active_vlans[key] = list(set(active_vlans[key]))

            return active_vlans

        else:
            output = self.runCommand(f'show mac address-table dynamic vlan {vlan} | include ^[\*,\+]')
            interface_list = []

            for line in output:
                interface_list.append(re.search('\S+$', line).group())

            interface_list = list(set(interface_list))

            return interface_list


def mac_lookup(host, mac):
    host = nexusHost(host)
    switch_data = host.vpcData
    switch_data['Hostname'] = host.hostname

    result = host.mac_lookup(mac)
    attempts = 1

    while isinstance(result, dict) and result['proceed'] is True:
        host = nexusHost(result['IP Addresses'][0])
        host.vpcData['traceData'] = switch_data
        switch_data = host.vpcData
        switch_data['Hostname'] = host.hostname

        result = host.mac_lookup(mac)

        if attempts < 6:
            attempts += 1
            continue
        else:
            break

    if isinstance(result, dict):
        del result['proceed']
        # Check to see if return value is an interface
        if 'interface' and 'Description' and 'Mode' in result.keys():
            switch_data['via'] = result
            return 200, switch_data
        # Check to see if return data is still a CDP neighbor
        elif 'IP Addresses' and 'Device ID' in result.keys():
            for po in host.poData:
                if result['Local Interface'] in po['Members']:
                    switch_data['via'] = po
                    return 200, switch_data
    else:
        # This conditional is invoked when return data is string
        for po in host.poData:
            if result in po['Members']:
                switch_data['via'] = po
                return 200, switch_data
        switch_data['via'] = result
        return 200, switch_data


def trunk_vlan(req_data: dict):
    def add_vlan_to_trunk(switch_data, vlan: str, name: str):
        # This method should be passed return data from mac_lookup() or data resembling that structure.

        def configure(ip_address: str,  command_set: list):
            try:
                ipaddress.IPv4Address(ip_address)
            except ipaddress.AddressValueError:
                return [f'{ip_address} is not a valid IP address']

            driver = get_network_driver('nxos_ssh')
            cr = {'username': os.getenv('netmgmtuser'), 'password': os.getenv('netmgmtpass')}

            device = driver(ip_address, cr['username'], cr['password'])
            device.open()
            device.load_merge_candidate(config='\n'.join(command_set))
            device.commit_config()
            device.close()

        def generate_command_set(interface: str, omit_int_config=False):
            commands = [
                f'vlan {vlan}',
                ('#' if name == '' else f'name {name}'),
                (f'interface {interface}' if omit_int_config is False else '#'),
                (f'switchport trunk allowed vlan add {vlan}' if omit_int_config is False else '#')
            ]

            return commands

        if isinstance(switch_data['via'], dict):
            # host1 = nexusHost(switchData['Self'])

            if 'VPC' in switch_data['via'].keys():
                host2 = nexusHost(switch_data['Peer'])

                po2 = next(x for x in host2.poData if 'VPC' in x.keys() if x['VPC'] == switch_data['via']['VPC'])
                omit = False
            else:
                po2 = {'interface': 'not required'}
                omit = True

            commands1 = generate_command_set(switch_data['via']['interface'])
            commands2 = generate_command_set(po2['interface'], omit_int_config=omit)

        elif isinstance(switch_data['via'], str):
            commands1 = generate_command_set(switch_data['via']['interface'])
            commands2 = generate_command_set('not required', omit_int_config=True)

        else:
            return 'Interface information could not be interpreted'

        configure(switch_data['Self'], commands1)
        configure(switch_data['Peer'], commands2)

        return {'Configurations Applied': {switch_data['Self']: commands1, switch_data['Peer']: commands2}}

    # Main Entry Point of Function
    env = getNexusEnvironments(req_data['Environment'])

    host = nexusHost(env['l3switch1'])
    try:
        if not bool(re.fullmatch('^VLAN\d+', host.vlanInfo[req_data['vlan']])):
            vlan_name = host.vlanInfo[req_data['vlan']]
        else:
            vlan_name = req_data['vlanName']
    except KeyError:
        vlan_name = req_data['vlanName']

    responses = []

    for mac in req_data['MAC']:
        resp_data = {f'Lookup Result for {mac}': mac_lookup(env['l3switch1'], mac)}
        responses.append(resp_data)

        if resp_data[f'Lookup Result for {mac}'] == 'MAC address was not found on device':
            continue
        else:
            resp_data['Configuration Results'] = add_vlan_to_trunk(resp_data[f'Lookup Result for {mac}'],
                                                                   req_data['vlan'],
                                                                   vlan_name)

    return 200, responses
