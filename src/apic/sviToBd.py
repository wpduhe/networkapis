import json, re, ipaddress
from data.environments import ACIEnvironment, NexusEnvironment
import os


class sviToBd:

    def __init__(self, env, apicEnv, info, suppressL3=False):
        # self.env = information.getNexusEnvironments(env)
        self.env = NexusEnvironment(env)
        self.apicEnv = ACIEnvironment(apicEnv)
        # self.apicEnv = GetAvailabilityZones.GetAvailabilityZones(apicEnv)
        self.vlans = []
        self.bdConfigs = []
        self.apConfigs = []
        self.epgConfigs = []
        self.aepConfigs = []
        self.suppressL3config = suppressL3
        self.sviConfigs = []
        self.data = info

    def getSVIConfig(self):
        from nexus import runSSHCommands

        credentials = {'username': os.getenv('netmgmtuser'), 'password': os.getenv('netmgmtpass')}

        for vlan in self.data:
            self.vlans.append(vlan['VLAN'])
            command = 'show run interface vlan' + vlan['VLAN'] + ' | begin ^interface'
            ssh0 = runSSHCommands.sshSession(self.env.l3switch1, credentials['username'], credentials['password'])
            self.sviConfigs.append(ssh0.executeCmd(command))
            ssh0.ssh.close()

    def parseConfig(self):
        for config in self.sviConfigs:
            vlanRegex = re.compile(r'\d+')
            vlanResults = vlanRegex.search(config[0])

            info = next(x for x in self.data if x['VLAN'] == vlanResults.group())

            if 'uni/tn-' + info['tenant'] + '/ap-' + info['AP'] \
                    not in (x['fvAp']['attributes']['dn'] for x in self.apConfigs):
                self.apConfigs.append({
                    'fvAp': {
                        'attributes': {
                            'dn': 'uni/tn-' + info['tenant'] + '/ap-' + info['AP'],
                            'name': info['AP'],
                            'status': 'created,modified'
                        }
                    }
                })

            if info['EPG'] not in (x['fvAEPg']['attributes']['name'] for x in self.epgConfigs):
                epg = {
                    'fvAEPg': {
                        'attributes': {
                            'dn': 'uni/tn-' + info['tenant'] + '/ap-' + info['AP'] + '/epg-' + info['EPG'],
                            'name': info['EPG'],
                            'status': 'created,modified'
                        },
                        'children': [{
                            'fvRsBd': {
                                'attributes': {
                                    'tnFvBDName': info['BD']
                                }
                            }
                        }, {
                            'fvRsDomAtt': {
                                'attributes': {
                                    'tDn': 'uni/phys-' + self.apicEnv.PhysicalDomain
                                }
                            }
                        }]
                    }
                }
                self.epgConfigs.append(epg)
                self.aepConfigs.append({
                    'infraRsFuncToEpg': {
                        'attributes': {
                            'dn': 'uni/infra/attentp-' + self.env.aciAEP + '/gen-default/rsfuncToEpg-[' +
                                  epg['fvAEPg']['attributes']['dn'] + ']',
                            'tDn': epg['fvAEPg']['attributes']['dn'],
                            'mode': 'regular',
                            'encap': 'vlan-' + info['VLAN'],
                            'status': 'created, modified'
                        }
                    }
                })

            if info['BD'] not in (x['fvBD']['attributes']['name'] for x in self.bdConfigs):
                bd = {
                    'fvBD': {
                        'attributes': {
                            'dn': 'uni/tn-' + info['tenant'] + '/BD-' + info['BD'],
                            'name': info['BD'],
                            'limitIpLearnToSubnets': 'yes',
                            'unicastRoute': 'yes',
                            'status': 'created,modified'
                        },
                        'children': [{
                            'fvRsBDToOut': {
                                'attributes': {
                                    'tnL3extOutName': self.apicEnv.L3OutCore
                                }
                            }
                        }, {
                            'fvRsCtx': {
                                'attributes': {
                                    'tnFvCtxName': info['VRF']
                                }
                            }
                        }]
                    }
                }
                if self.suppressL3config is False:
                    for line in config:
                        subnetRegex = re.compile(r'ip add.*[0-9./]+')
                        subnetResults = subnetRegex.search(line)

                        if subnetResults is not None:
                            regex = re.compile(r'[0-9./]+')
                            results = regex.search(line)
                            intfIP = results.group()
                            prefix = ipaddress.IPv4Network(intfIP, strict=False)
                            network = str(prefix).split('/')
                            gatewayIP = str(ipaddress.ip_address(int(ipaddress.ip_address(network[0]) + 1))) + '/' + \
                                        network[1]
                            fvSubnet = {
                                'fvSubnet': {
                                    'attributes': {
                                        'ip': gatewayIP,
                                        'scope': 'public',
                                        'name': '',
                                        'status': 'created,modified'
                                    }
                                }
                            }
                            if self.suppressL3config is False:
                                bd['fvBD']['children'].append(fvSubnet)
                self.bdConfigs.append(bd)

            else:
                bdIndex = self.bdConfigs.index(next(x for x in self.bdConfigs \
                                               if x['fvBD']['attributes']['name'] == info['BD']))
                for line in config:
                    subnetRegex = re.compile(r'ip add.*[0-9./]+')
                    subnetResults = subnetRegex.search(line)

                    if subnetResults is not None:
                        regex = re.compile(r'[0-9./]+')
                        results = regex.search(line)
                        intfIP = results.group()
                        prefix = ipaddress.IPv4Network(intfIP, strict=False)
                        network = str(prefix).split('/')
                        gatewayIP = str(ipaddress.ip_address(int(ipaddress.ip_address(network[0]) + 1))) + '/' + network[1]
                        fvSubnet = {
                            'fvSubnet': {
                                'attributes': {
                                    'ip': gatewayIP,
                                    'scope': 'public',
                                    'name': '',
                                    'status': 'created,modified'
                                }
                            }
                        }
                        if self.suppressL3config is False:
                            self.bdConfigs[bdIndex]['fvBD']['children'].append(fvSubnet)

    def print_config(self):
        print(json.dumps(self.apConfigs))
        print(json.dumps(self.epgConfigs))
        print(json.dumps(self.bdConfigs))
        print(json.dumps(self.aepConfigs))

    def migrate(self, stage):
        import requests
        from apic.utils import APIC
        from napalm import get_network_driver

        rollback = APIC(env=self.apicEnv.Name).snapshot('Auto pre-sviToBd {} {}'.format(', '.join(self.vlans), stage))

        if rollback is False:
            return 'Automated Snapshot Failed.  Migration configuration aborted.'

        driver = get_network_driver('nxos_ssh')

        allconfigs = []

        session = requests.session()
        session.verify = False
        url = 'https://' + self.apicEnv.IPAddress
        login_uri = url + '/api/aaaLogin.json'
        creds = {
            "aaaUser": {
                "attributes": {
                    "name": os.getenv('netmgmtuser'),
                    "pwd": os.getenv('netmgmtpass')
                }
            }
        }
        session.post(login_uri, json=creds)
        resp = session.get(f'{url}/api/mo/uni/infra/attentp-{self.env.aciAEP}/gen-default.json')
        resp = json.loads(resp.text)
        if resp['totalCount'] == '0':
            allconfigs.append({
                'infraAttEntityP': {
                    'attributes': {
                        'dn': 'uni/infra/attentp-{}'.format(self.env.aciAEP),
                        'name': self.env.aciAEP,
                        'status': 'modified'
                    },
                    'children': [{
                        'infraGeneric': {
                            'attributes': {
                                'name': 'default',
                                'status': 'created,modified'
                            }
                        }
                    }]
                }
            })

        if stage == 'layer2':
            for bd in self.bdConfigs:
                bd['fvBD']['attributes']['unicastRoute'] = 'no'
                bd['fvBD']['attributes']['arpFlood'] = 'yes'
                bd['fvBD']['attributes']['unkMacUcastAct'] = 'flood'
                for child in bd['fvBD']['children'][:]:
                    if 'fvSubnet' in child.keys():
                        bd['fvBD']['children'].remove(child)
                allconfigs.append(bd)

            for ap in self.apConfigs:
                allconfigs.append(ap)

            for epg in self.epgConfigs:
                if not self.apicEnv.Name.upper() == 'SEDC':
                    epg['fvAEPg']['children'].append({
                        'fvRsDomAtt': {
                            'attributes': {
                                'tDn': 'uni/phys-' + self.env.aciPhysDomain
                            }
                        }
                    })
                allconfigs.append(epg)

            for aep in self.aepConfigs:
                allconfigs.append(aep)

            for x in allconfigs:
                resp = session.post(url=f'{url}/api/mo/uni.json', data=json.dumps(x))

            session.close()

            return rollback

        elif stage == 'complete' and self.suppressL3config is False:
            cr = {'username': os.getenv('netmgmtuser'), 'password': os.getenv('netmgmtpass')}

            commands = []
            for vlan in self.data:
                commands.append('interface Vlan' + vlan['VLAN'])
                commands.append('shutdown')
                commands.append('description DO NOT ENABLE - MOVED TO ACI')

            for bd in self.bdConfigs:
                bd['fvBD']['attributes']['unicastRoute'] = 'yes'
                bd['fvBD']['attributes']['arpFlood'] = 'no'
                bd['fvBD']['attributes']['unkMacUcastAct'] = 'proxy'
                allconfigs.append(bd)
            for ap in self.apConfigs:
                allconfigs.append(ap)
            for epg in self.epgConfigs:
                if not self.apicEnv.Name.upper() == 'SEDC':
                    epg['fvAEPg']['children'].append({
                        'fvRsDomAtt': {
                            'attributes': {
                                'tDn': 'uni/phys-' + self.env.aciPhysDomain
                            }
                        }
                    })
                allconfigs.append(epg)
            # for aep in self.aepConfigs:
            #     allconfigs.append(aep)

            # Enable ACI
            for x in allconfigs:
                resp = session.post(f'{url}/api/mo/uni.json', data=json.dumps(x))

            session.close()

            # Shutdown SVIs
            device1 = driver(self.env.l3switch1, cr['username'], cr['password'])
            device2 = driver(self.env.l3switch2, cr['username'], cr['password'])
            device1.open()
            device2.open()
            device1.load_merge_candidate(config='\n'.join(commands))
            device2.load_merge_candidate(config='\n'.join(commands))
            device1.commit_config()
            device2.commit_config()
            device1.close()
            device2.close()

            return rollback


def svi_to_bd(req_data):
    try:
        migrate = req_data['migrate']
    except KeyError:
        migrate = False

    configuration = sviToBd(req_data['NexusEnvironment'], req_data['ACIEnvironment'], req_data['vlanData'],
                            suppressL3=req_data['suppressL3'])
    configuration.getSVIConfig()
    configuration.parseConfig()

    response = {
        'BDs': configuration.bdConfigs,
        'EPGs': configuration.epgConfigs,
        'APs': configuration.apConfigs,
        'AEP': configuration.aepConfigs
    }

    if migrate is not False:
        if migrate not in ['layer2', 'complete']:
            return 'Invalid migration request.  Stages are: layer2, complete'

        response['Snapshot'] = configuration.migrate(migrate)

    return response
