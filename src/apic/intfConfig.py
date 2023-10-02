from apic.utils import APIC
from apic.apic_tools import intf_range
import re


class intfConfig:
    def __init__(self, name=''):
        self.name = name
        self.profile_name = ''
        self.policy_group = {}
        self.profile = {}
        self.sw_profile = {}

    def port_channel(self, lacp=True):
        self.policy_group = {
            'infraAccBndlGrp': {
                'attributes': {
                    'dn': 'uni/infra/funcprof/accbundle-{}'.format(self.name),
                    'name': self.name,
                    'descr': self.name[self.name.index('-') + 1:],
                    'lagT': ('node' if self.name.startswith('vpc') else 'link'),
                    'status': 'created'
                },
                'children': [{
                    'infraRsCdpIfPol': {
                        'attributes': {
                            'tnCdpIfPolName': 'CDP-Enable'
                        }
                    }
                }, {
                    'infraRsLldpIfPol': {
                        'attributes': {
                            'tnLldpIfPolName': 'LLDP-Enable'
                        }
                    }
                }, {
                    'infraRsLacpPol': {
                        'attributes': {
                            'tnLacpLagPolName': ('pc-LACP-Active' if lacp is True else 'pc-Static-ON')
                        }
                    }
                }]
            }
        }

    def standalone_ports(self):
        self.policy_group = {
            'infraAccPortGrp': {
                'attributes': {
                    'dn': 'uni/infra/funcprof/accportgrp-{}'.format(self.name),
                    'name': self.name,
                    'status': 'created'
                },
                'children': [{
                    'infraRsCdpIfPol': {
                        'attributes': {
                            'tnCdpIfPolName': 'CDP-Enable'
                        }
                    }
                }, {
                    'infraRsLldpIfPol': {
                        'attributes': {
                            'tnLldpIfPolName': 'LLDP-Enable'
                        }
                    }
                }]
            }
        }

    def use_aep(self, aep):
        self.policy_group[next(key for key in self.policy_group)]['children'].append({
            'infraRsAttEntP': {
                'attributes': {
                    'tDn': f'uni/infra/attentp-{aep}'
                }
            }
        })

    def use_interfaces(self, interfaces: list):
        if len(interfaces) == 0:
            return 'No Interfaces provided'

        if len(interfaces) == 1:
            profile_descr = self.name[:self.name.index('-') + 1] + str(interfaces[0])
            block_descr = self.name[self.name.index('-') + 1:]

            self.profile = {
                'infraAccPortP': {
                    'attributes': {
                        'dn': 'uni/infra/accportprof-{}'.format(self.profile_name),
                        'name': self.profile_name,
                        'status': 'created,modified'
                    },
                    'children': [{
                        'infraHPortS': {
                            'attributes': {
                                'name': self.name,
                                'descr': profile_descr,
                                'type': 'range',
                                'status': 'created,modified'
                            },
                            'children': [{
                                'infraPortBlk': {
                                    'attributes': {
                                        'name': 'block{}'.format(str(max(interfaces) + 1)),
                                        'fromPort': str(min(interfaces)),
                                        'toPort': str(max(interfaces)),
                                        'descr': block_descr
                                    }
                                }
                            }, {
                                'infraRsAccBaseGrp': {
                                    'attributes': {
                                        'tDn': self.policy_group[next(key for key in self.policy_group)]['attributes'][
                                            'dn']
                                    }
                                }
                            }]
                        }
                    }]
                }
            }
        elif sorted(interfaces) == list(range(min(interfaces), max(interfaces) + 1)):
            descr_intf = '{}--{}'.format(str(min(interfaces)), str(max(interfaces)))
            profile_descr = self.name[:self.name.index('-') + 1] + descr_intf
            block_descr = self.name[self.name.index('-') + 1:]

            self.profile = {
                'infraAccPortP': {
                    'attributes': {
                        'dn': 'uni/infra/accportprof-{}'.format(self.profile_name),
                        'name': self.profile_name,
                        'status': 'created,modified'
                    },
                    'children': [{
                        'infraHPortS': {
                            'attributes': {
                                'name': self.name,
                                'descr': profile_descr,
                                'type': 'range',
                                'status': 'created,modified'
                            },
                            'children': [{
                                'infraPortBlk': {
                                    'attributes': {
                                        'name': 'block{}'.format(str(max(interfaces) + 1)),
                                        'fromPort': str(min(interfaces)),
                                        'toPort': str(max(interfaces)),
                                        'descr': block_descr
                                    }
                                }
                            }, {
                                'infraRsAccBaseGrp': {
                                    'attributes': {
                                        'tDn': self.policy_group[next(key for key in self.policy_group)]['attributes'][
                                            'dn']
                                    }
                                }
                            }]
                        }
                    }]
                }
            }
        else:
            descr_intf = '-'.join(str(x) for x in interfaces)
            profile_descr = self.name[:self.name.index('-') + 1] + descr_intf
            block_descr = self.name[self.name.index('-') + 1:]

            self.profile = {
                'infraAccPortP': {
                    'attributes': {
                        'dn': 'uni/infra/accportprof-{}'.format(self.profile_name),
                        'name': self.profile_name,
                        'status': 'created,modified'
                    },
                    'children': [{
                        'infraHPortS': {
                            'attributes': {
                                'name': self.name,
                                'descr': profile_descr,
                                'type': 'range',
                                'status': 'created,modified'
                            },
                            'children': [{
                                'infraRsAccBaseGrp': {
                                    'attributes': {
                                        'tDn': self.policy_group[next(key for key in self.policy_group)]['attributes'][
                                            'dn']
                                    }
                                }
                            }]
                        }
                    }]
                }
            }

            for interface in interfaces:
                self.profile['infraAccPortP']['children'][0]['infraHPortS']['children'].append(
                    {
                        'infraPortBlk': {
                            'attributes': {
                                'name': 'block{}'.format(str(interface + 1)),
                                'fromPort': str(interface),
                                'toPort': str(interface),
                                'descr': block_descr
                            }
                        }
                    })

    def use_switches(self, sw_profile=''):
        self.sw_profile = {
            'infraNodeP': {
                'attributes': {
                    'name': sw_profile,
                    'status': 'modified'
                },
                'children': [{
                    'infraRsAccPortP': {
                        'attributes': {
                            'tDn': 'uni/infra/accportprof-{}'.format(
                                self.profile['infraAccPortP']['attributes']['name']),
                            'status': 'created,modified'
                        }
                    }
                }]
            }
        }

    def return_config(self, negate_policy_group=False):
        return {
            'polUni': {
                'attributes': {
                    'dn': 'uni',
                    'status': 'modified'
                },
                'children': [{
                    'infraInfra': {
                        'attributes': {
                            'dn': 'uni/infra'
                        },
                        'children': [{
                            'infraFuncP': {
                                'attributes': {
                                    'dn': 'uni/infra/funcprof'
                                },
                                'children': ([] if negate_policy_group is True else [self.policy_group])
                            }
                        }, self.profile, self.sw_profile]
                    }
                }]
            }
        }


def intf_profile(req_data: dict):
    with APIC(env=req_data['AvailabilityZone']) as apic:
        aep = req_data['AEP']
        if apic.exists(infraAttEntityP=aep) is False:
            return 404, ['The AEP requested does not exist.']
        server = req_data['Server_Name']
        lacp = req_data['LACP']
        port_channel = req_data['Port_Channel']
        interfaces = req_data['Interfaces']
        switch_profile = req_data['Switch_Profile']
        leafs = re.findall(r'\d\d\d', switch_profile)

        if isinstance(interfaces, str):
            interfaces = interfaces.split(',')
            interfaces = intf_range(interfaces)
        elif isinstance(interfaces, list):
            interfaces = intf_range(interfaces)

        rollback = apic.snapshot(f'pre-intf_profile {server}')

        if rollback is False:
            return 500, ['Your request was valid but aborted because the snapshot creation in {} failed.'.
                         format(apic.env['Name'])]

        if port_channel is True and len(leafs) == 2:
            if len(leafs) * len(interfaces) > 16:
                return 400, ['Too many interfaces provided for Port Channel']

            name = f'vpc-{server}'

            configuration = intfConfig(name)
            configuration.profile_name = 'vpc-{}_{}'.format(aep.replace('aep-', ''), '-'.join(leafs))
            configuration.port_channel(lacp=lacp)
            configuration.use_aep(aep=aep)
            configuration.use_interfaces(interfaces)
            configuration.use_switches(sw_profile=switch_profile)
            resp = apic.post(configuration=configuration.return_config())
            if resp.ok is False:
                return 500, {'APIC Resp': {resp.reason: resp.json()}, 'Configuration': configuration.return_config()}

            return 200, {'APIC Resp': {resp.reason: resp.json()}, 'Configuration': configuration.return_config()}

        elif port_channel is True and len(leafs) == 1:
            if len(leafs) * len(interfaces) > 16:
                return 500, ['Too many interfaces provided for Port Channel']

            name = f'pc-{server}'

            configuration = intfConfig(name)
            configuration.profile_name = 'pc-{}_{}'.format(aep.replace('aep-', ''), '-'.join(leafs))
            configuration.port_channel(lacp=lacp)
            configuration.use_aep(aep=aep)
            configuration.use_interfaces(interfaces=interfaces)
            configuration.use_switches(sw_profile=switch_profile)
            resp = apic.post(configuration=configuration.return_config())
            if resp.ok is False:
                return 500, {'APIC Resp': {resp.reason: resp.json()}, 'Configuration': configuration.return_config()}

            return 200, {'APIC Resp': {resp.reason: resp.json()}, 'Configuration': configuration.return_config()}

        elif port_channel is False:
            name = 'acc-{}'.format(aep.replace('aep-', ''))
            if apic.exists(infraAccPortGrp=name) is True:
                negate = True
            else:
                negate = False

            configuration = intfConfig(name)
            configuration.profile_name = '{}_{}'.format(name, '-'.join(leafs))
            configuration.standalone_ports()
            configuration.use_aep(aep=aep)
            configuration.use_interfaces(interfaces=interfaces)
            configuration.use_switches(sw_profile=switch_profile)
            resp = apic.post(configuration.return_config(negate_policy_group=negate))
            if resp.ok is False:
                return 400, {'APIC Resp': {resp.reason: resp.json()},
                             'Configuration': configuration.return_config(negate_policy_group=negate)}

            return 200, {'APIC Resp': {resp.reason: resp.json()},
                         'Configuration': configuration.return_config(negate_policy_group=negate)}

        else:
            return 500, ['Your request could not be processed.  Please contact Network Design and Delivery']
