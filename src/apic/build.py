from ipaddress import ip_network as network
from ipaddress import ip_address as address
from data.environments import ACIEnvironment
from apic.classes import *
import itertools
import requests
import json
import re
import os

env = ACIEnvironment('hodc')

# TODO: Remove TACACS or make it optional in some way

'''
Order of submission:

infra
fabric
uni
tn_mgmt
tn_hca
tn_hcadr
tn_admz
'''

data_center = re.search(r'\w+', env.Name).group()
CR = 'created,modified'
MOD = 'modified'

url = f'https://{env.IPAddress}'
loginURL = f'{url}/api/aaaLogin.json'
post_url = f'{url}/api/mo/uni.json'

session = requests.session()
session.verify = False

response = session.post(loginURL, json={'aaaUser': {'attributes': {'name': 'admin', 'pwd': 'C1sco123'}}})
assert response.ok

uni = {
    'polUni': {
        'attributes': {
            'dn': 'uni',
            'status': MOD
        },
        'children': []
    }
}
infra_funcp = {
    'infraFuncP': {
        'attributes': {
            'dn': 'uni/infra/funcprof',
            'status': MOD
        },
        'children': []
    }
}
infra = {
    'infraInfra': {
        'attributes': {
            'dn': 'uni/infra',
            'status': 'modified'
        },
        'children': []
    }
}
fabric_funcp = {
    'fabricFuncP': {
        'attributes': {
            'dn': 'uni/fabric/funcprof',
            'status': MOD
        },
        'children': []
    }
}
fabric = {
    'fabricInst': {
        'attributes': {
            'dn': 'uni/fabric',
            'status': MOD
        },
        'children': []
    }
}
tn_mgmt = {
    'fvTenant': {
        'attributes': {
            'name': 'mgmt',
            'status': MOD
        },
        'children': []
    }
}
tn_hca = {
    'fvTenant': {
        'attributes': {
            'dn': 'uni/tn-tn-HCA',
            'name': 'tn-HCA',
            'status': CR
        },
        'children': []
    }
}
tn_hcadr = {
    'fvTenant': {
        'attributes': {
            'dn': 'uni/tn-tn-HCADR',
            'name': 'tn-HCADR',
            'status': CR
        },
        'children': []
    }
}
tn_admz = {
    'fvTenant': {
        'attributes': {
            'dn': 'uni/tn-tn-ADMZ',
            'name': 'tn-ADMZ',
            'status': CR
        },
        'children': [{
                'fvCtx': {
                    'attributes': {
                        'bdEnforcedEnable': 'no',
                        'knwMcastAct': 'permit',
                        'name': 'vrf-admz',
                        'pcEnfDir': 'ingress',
                        'pcEnfPref': 'enforced',
                        'status': CR
                    }
                }
            }
        ]
    }
}


# fabricFuncP is a child object of fabricInst
fabric['fabricInst']['children'].append(fabric_funcp)

# infraFuncP is a child object of infraInfra
infra['infraInfra']['children'].append(infra_funcp)


# Create VLAN pool for fabric
vlan_pool = {
    'fvnsVlanInstP': {
        'attributes': {
            'allocMode': 'dynamic',
            'name': f'vlp-{data_center}',
            'status': CR
        },
        'children': [{
                'fvnsEncapBlk': {
                    'attributes': {
                        'allocMode': 'static',
                        'from': 'vlan-2',
                        'role': 'external',
                        'to': 'vlan-3966'
                    }
                }
            }, {
                'fvnsEncapBlk': {
                    'attributes': {
                        'allocMode': 'static',
                        'from': 'vlan-3968',
                        'role': 'external',
                        'to': 'vlan-4094'
                    }
                }
            }
        ]
    }
}
infra['infraInfra']['children'].append(vlan_pool)

# Fabric interface policies append to infra/
cdp_enable = {
    'cdpIfPol': {
        'attributes': {
            'adminSt': 'enabled',
            'name': 'CDP-Enable',
            'status': CR,
        }
    }
}
infra['infraInfra']['children'].append(cdp_enable)

lldp_enable = {
    'lldpIfPol': {
        'attributes': {
            'adminRxSt': 'enabled',
            'adminTxSt': 'enabled',
            'name': 'LLDP-Enable',
            'status': CR
        }
    }
}
infra['infraInfra']['children'].append(lldp_enable)

pc_lacp_active = {
    'lacpLagPol': {
        'attributes': {
            'ctrl': 'fast-sel-hot-stdby,graceful-conv,susp-individual',
            'maxLinks': '16',
            'minLinks': '1',
            'mode': 'active',
            'name': 'pc-LACP-Active',
            'status': CR
        }
    }
}
infra['infraInfra']['children'].append(pc_lacp_active)

pc_static_on = {
    'lacpLagPol': {
        'attributes': {
            'ctrl': 'fast-sel-hot-stdby,graceful-conv,susp-individual',
            'maxLinks': '16',
            'minLinks': '1',
            'mode': 'off',
            'name': 'pc-Static-ON',
            'status': CR
        }
    }
}
infra['infraInfra']['children'].append(pc_static_on)

fabric_settings = {
    'infraSetPol': {
        'attributes': {
            'dn': 'uni/infra/settings',
            'domainValidation': 'no',
            'enforceSubnetCheck': 'yes',
            'name': 'default',
            'opflexpAuthenticateClients': 'no',
            'opflexpUseSsl': 'yes',
            'reallocateGipo': 'no',
            'unicastXrEpLearnDisable': 'yes',
            'status': MOD
        }
    }
}
infra['infraInfra']['children'].append(fabric_settings)

# Create physical domains for fabric
physical_domain = {  # This goes under uni/
    'physDomP': {
        'attributes': {
            'annotation': '',
            'dn': f'uni/phys-phy-dom-{data_center}',
            'name': f'phy-dom-{data_center}',
            'status': CR
        },
        'children': [{
                'infraRsVlanNs': {
                    'attributes': {
                        'annotation': '',
                        'tDn': f'uni/infra/vlanns-[vlp-{data_center}]-dynamic'
                    }
                }
            }
        ]
    }
}
uni['polUni']['children'].append(physical_domain)

l3_domain = {
    'l3extDomP': {
        'attributes': {
            'dn': f'uni/l3dom-l3-dom-{data_center}',
            'name': f'l3-dom-{data_center}',
            'status': CR
        },
        'children': [{
                'infraRsVlanNs': {
                    'attributes': {
                        'tDn': f'uni/infra/vlanns-[vlp-{data_center}]-dynamic'
                    }
                }
            }
        ]
    }
}
uni['polUni']['children'].append(l3_domain)

aep_l3_ports = {
    'infraAttEntityP': {
        'attributes': {
            'dn': 'uni/infra/attentp-aep-L3-Ports',
            'name': 'aep-L3-Ports',
            'status': CR
        },
        'children': [{
                'infraRsDomP': {
                    'attributes': {
                        'tDn': f'uni/l3dom-l3-dom-{data_center}'
                    }
                }
            }
        ]
    }
}
infra['infraInfra']['children'].append(aep_l3_ports)

rt_core_policy_group = {
    'infraAccPortGrp': {
        'attributes': {
            'dn': f'uni/infra/funcprof/accportgrp-rt-{data_center}-Core',
            'name': f'rt-{data_center}-Core',
            'status': CR
        },
        'children': [{
                'infraRsAttEntP': {
                    'attributes': {
                        'annotation': '',
                        'tDn': 'uni/infra/attentp-aep-L3-Ports'
                    }
                }
            }, {
                'infraRsCdpIfPol': {
                    'attributes': {
                        'annotation': '',
                        'tnCdpIfPolName': 'CDP-Enable'
                    }
                }
            }, {
                'infraRsLldpIfPol': {
                    'attributes': {
                        'annotation': '',
                        'tnLldpIfPolName': 'LLDP-Enable'
                    }
                }
            }
        ]
    }
}
infra_funcp['infraFuncP']['children'].append(rt_core_policy_group)

rt_core_profile = {
    'infraAccPortP': {
        'attributes': {
            'descr': 'RT 45--48',
            'dn': f'uni/infra/accportprof-rt-{data_center}-Core',
            'name': f'rt-{data_center}-Core',
            'status': CR
        },
        'children': [{
                'infraHPortS': {
                    'attributes': {
                        'descr': 'Routed Links to Core',
                        'name': 'rt-45--48',
                        'type': 'range'
                    },
                    'children': [{
                            'infraRsAccBaseGrp': {
                                'attributes': {
                                    'tDn': f'uni/infra/funcprof/accportgrp-rt-{data_center}-Core'
                                }
                            }
                        }, {
                            'infraPortBlk': {
                                'attributes': {
                                    'descr': f'{data_center}-Core',
                                    'fromCard': '1',
                                    'fromPort': '45',
                                    'name': 'block2',
                                    'toCard': '1',
                                    'toPort': '48'
                                }
                            }
                        }
                    ]
                }
            }
        ]
    }
}
infra['infraInfra']['children'].append(rt_core_profile)


# Create vpc policy for border leafs
vpc_policy = {
    'fabricProtPol': {
        'attributes': {
            'dn': 'uni/fabric/protpol',
            'name': 'default',
            'pairT': 'explicit',
            'status': MOD
        },
        'children': [{
                'fabricExplicitGEp': {
                    'attributes': {
                        'id': '101',
                        'name': 'vpc-101-102'
                    },
                    'children': [{
                            'fabricRsVpcInstPol': {
                                'attributes': {
                                    'tnVpcInstPolName': 'default'
                                }
                            }
                        }, {
                            'fabricNodePEp': {
                                'attributes': {
                                    'id': '101',
                                    'podId': '1'
                                }
                            }
                        }, {
                            'fabricNodePEp': {
                                'attributes': {
                                    'id': '102',
                                    'podId': '1'
                                }
                            }
                        }
                    ]
                }
            }
        ]
    }
}
fabric['fabricInst']['children'].append(vpc_policy)


# Fabric Policies append to fabric/
fabric_policy_group = {
    'fabricPodPGrp': {
        'attributes': {
            'name': env.Name,
            'status': CR
        },
        'children': [{
                'fabricRsSnmpPol': {
                    'attributes': {
                        'annotation': '',
                        'tnSnmpPolName': 'default'
                    }
                }
            }, {
                'fabricRsPodPGrpIsisDomP': {
                    'attributes': {
                        'annotation': '',
                        'tnIsisDomPolName': ''
                    }
                }
            }, {
                'fabricRsPodPGrpCoopP': {
                    'attributes': {
                        'annotation': '',
                        'tnCoopPolName': ''
                    }
                }
            }, {
                'fabricRsPodPGrpBGPRRP': {
                    'attributes': {
                        'annotation': '',
                        'tnBgpInstPolName': 'default'
                    }
                }
            }, {
                'fabricRsTimePol': {
                    'attributes': {
                        'annotation': '',
                        'tnDatetimePolName': 'default'
                    }
                }
            }, {
                'fabricRsMacsecPol': {
                    'attributes': {
                        'annotation': '',
                        'tnMacsecFabIfPolName': ''
                    }
                }
            }, {
                'fabricRsCommPol': {
                    'attributes': {
                        'annotation': '',
                        'tnCommPolName': ''
                    }
                }
            }
        ]
    }
}
fabric_funcp['fabricFuncP']['children'].append(fabric_policy_group)  # Appends to fabric/funcp

pod_profile = {
    'fabricPodP': {
        'attributes': {
            'dn': 'uni/fabric/podprof-default',
            'name': 'default',
            'status': MOD
        },
        'children': [{
                'fabricPodS': {
                    'attributes': {
                        'annotation': '',
                        'name': 'default',
                        'type': 'ALL'
                    },
                    'children': [{
                            'fabricRsPodPGrp': {
                                'attributes': {
                                    'tDn': 'uni/fabric/funcprof/podpgrp-{}'.format(env.Name)
                                }
                            }
                        }
                    ]
                }
            }
        ]
    }
}
fabric['fabricInst']['children'].append(pod_profile)

dns_policy = {
    'dnsProfile': {
        'attributes': {
            'IPVerPreference': 'IPv4',
            'dn': 'uni/fabric/dnsp-default',
            'name': 'default',
            'status': MOD
        },
        'children': [{
                'dnsRsProfileToEpg': {
                    'attributes': {
                        'tDn': 'uni/tn-mgmt/mgmtp-default/oob-default'
                    }
                }
            }, {
                'dnsProv': {
                    'attributes': {
                        'addr': env.PrimaryDNS,
                        'preferred': 'yes'
                    }
                }
            }, {
                'dnsProv': {
                    'attributes': {
                        'addr': env.SecondaryDNS,
                        'preferred': 'no'
                    }
                }
            }, {
                'dnsProv': {
                    'attributes': {
                        'addr': env.TertiaryDNS,
                        'preferred': 'no'
                    }
                }
            }
        ]
    }
}
fabric['fabricInst']['children'].append(dns_policy)

snmp_strings = {'rw': 'impasse', 'ro': 'notpublic'}

snmp_clients = {
    'snmpPol': {
        'attributes': {
            'adminSt': 'disabled',  # Leave disabled until fabric is production
            'contact': 'HCA NOC',
            'dn': 'uni/fabric/snmppol-default',
            'loc': env.Name,
            'name': 'default',
            'status': MOD
        },
        'children': [{
                'snmpCommunityP': {
                    'attributes': {
                        'annotation': '',
                        'descr': 'RW',
                        'name': snmp_strings['rw'],
                        'nameAlias': ''
                    }
                }
            }, {
                'snmpCommunityP': {
                    'attributes': {
                        'annotation': '',
                        'descr': 'RO',
                        'name': snmp_strings['ro'],
                        'nameAlias': ''
                    }
                }
            }, {
                'snmpClientGrpP': {
                    'attributes': {
                        'annotation': '',
                        'descr': '',
                        'name': 'snmpClients',
                        'nameAlias': ''
                    },
                    'children': [{
                            'snmpRsEpg': {
                                'attributes': {
                                    'annotation': '',
                                    'tDn': 'uni/tn-mgmt/mgmtp-default/oob-default'
                                }
                            }
                        }, {
                            'snmpClientP': {
                                'attributes': {
                                    'addr': '10.26.33.131',
                                    'annotation': '',
                                    'name': 'Spec-10-Dist-03-xrdclpappspc06',
                                    'nameAlias': ''
                                }
                            }
                        }, {
                            'snmpClientP': {
                                'attributes': {
                                    'addr': '10.26.31.30',
                                    'annotation': '',
                                    'name': 'Cisco-Collector-Server-1',
                                    'nameAlias': ''
                                }
                            }
                        }, {
                            'snmpClientP': {
                                'attributes': {
                                    'addr': '10.26.32.65',
                                    'annotation': '',
                                    'name': 'Spectrum1',
                                    'nameAlias': ''
                                }
                            }
                        }, {
                            'snmpClientP': {
                                'attributes': {
                                    'addr': '10.26.32.67',
                                    'annotation': '',
                                    'name': 'Spec-9-Dist-02-naspcp06',
                                    'nameAlias': ''
                                }
                            }
                        }, {
                            'snmpClientP': {
                                'attributes': {
                                    'addr': '10.26.32.89',
                                    'annotation': '',
                                    'name': 'Spec-9-Dist-08-naspcp0C',
                                    'nameAlias': ''
                                }
                            }
                        }, {
                            'snmpClientP': {
                                'attributes': {
                                    'addr': '10.26.33.132',
                                    'annotation': '',
                                    'name': 'Spec-10-Dist-04-xrdclpappspc07',
                                    'nameAlias': ''
                                }
                            }
                        }, {
                            'snmpClientP': {
                                'attributes': {
                                    'addr': '10.26.32.75',
                                    'annotation': '',
                                    'name': 'Spec-9-Dist-05-naspcp09',
                                    'nameAlias': ''
                                }
                            }
                        }, {
                            'snmpClientP': {
                                'attributes': {
                                    'addr': '10.26.32.96',
                                    'annotation': '',
                                    'name': 'Spec-9-FT-Dist-02-naspcp0I',
                                    'nameAlias': ''
                                }
                            }
                        }, {
                            'snmpClientP': {
                                'attributes': {
                                    'addr': '10.26.32.109',
                                    'annotation': '',
                                    'name': 'Spec-9-FT-Dist-08-naspcp0O',
                                    'nameAlias': ''
                                }
                            }
                        }, {
                            'snmpClientP': {
                                'attributes': {
                                    'addr': '10.26.32.98',
                                    'annotation': '',
                                    'name': 'Spec-9-FT-Dist-04-naspcp0K',
                                    'nameAlias': ''
                                }
                            }
                        }, {
                            'snmpClientP': {
                                'attributes': {
                                    'addr': '10.26.32.108',
                                    'annotation': '',
                                    'name': 'Spec-9-FT-Dist-07-naspcp0N',
                                    'nameAlias': ''
                                }
                            }
                        }, {
                            'snmpClientP': {
                                'attributes': {
                                    'addr': '10.26.33.136',
                                    'annotation': '',
                                    'name': 'Spec-10-FT-Dist-01-xrdclpappspc11',
                                    'nameAlias': ''
                                }
                            }
                        }, {
                            'snmpClientP': {
                                'attributes': {
                                    'addr': '10.26.32.68',
                                    'annotation': '',
                                    'name': 'Spec-9-Dist-03-naspcp07',
                                    'nameAlias': ''
                                }
                            }
                        }, {
                            'snmpClientP': {
                                'attributes': {
                                    'addr': '10.26.32.107',
                                    'annotation': '',
                                    'name': 'Spec-9-FT-Dist-06-naspcp0M',
                                    'nameAlias': ''
                                }
                            }
                        }, {
                            'snmpClientP': {
                                'attributes': {
                                    'addr': '10.26.33.139',
                                    'annotation': '',
                                    'name': 'Spec-10-FT-Dist-04-xrdclpappspc14',
                                    'nameAlias': ''
                                }
                            }
                        }, {
                            'snmpClientP': {
                                'attributes': {
                                    'addr': '10.26.32.158',
                                    'annotation': '',
                                    'name': 'Spec-9-FT-Dist-10-naspcp0Q',
                                    'nameAlias': ''
                                }
                            }
                        }, {
                            'snmpClientP': {
                                'attributes': {
                                    'addr': '10.26.32.79',
                                    'annotation': '',
                                    'name': 'Spec-9-Dist-06-naspcp0A',
                                    'nameAlias': ''
                                }
                            }
                        }, {
                            'snmpClientP': {
                                'attributes': {
                                    'addr': '10.26.33.137',
                                    'annotation': '',
                                    'name': 'Spec-10-FT-Dist-02-xrdclpappspc12',
                                    'nameAlias': ''
                                }
                            }
                        }, {
                            'snmpClientP': {
                                'attributes': {
                                    'addr': '10.26.33.62',
                                    'annotation': '',
                                    'name': 'CAPM-Data-Collector1',
                                    'nameAlias': ''
                                }
                            }
                        }, {
                            'snmpClientP': {
                                'attributes': {
                                    'addr': '10.26.32.88',
                                    'annotation': '',
                                    'name': 'Spec-9-Dist-07-naspcp0B',
                                    'nameAlias': ''
                                }
                            }
                        }, {
                            'snmpClientP': {
                                'attributes': {
                                    'addr': '10.26.32.99',
                                    'annotation': '',
                                    'name': 'Spec-9-FT-Dist-05-naspcp0L',
                                    'nameAlias': ''
                                }
                            }
                        }, {
                            'snmpClientP': {
                                'attributes': {
                                    'addr': '10.26.32.69',
                                    'annotation': '',
                                    'name': 'Spec-9-Dist-04-naspcp08',
                                    'nameAlias': ''
                                }
                            }
                        }, {
                            'snmpClientP': {
                                'attributes': {
                                    'addr': '10.26.32.157',
                                    'annotation': '',
                                    'name': 'Spec-9-FT-Dist-09-naspcp0P',
                                    'nameAlias': ''
                                }
                            }
                        }, {
                            'snmpClientP': {
                                'attributes': {
                                    'addr': '10.26.32.97',
                                    'annotation': '',
                                    'name': 'Spec-9-FT-Dist-03-naspcp0J',
                                    'nameAlias': ''
                                }
                            }
                        }, {
                            'snmpClientP': {
                                'attributes': {
                                    'addr': '10.26.33.129',
                                    'annotation': '',
                                    'name': 'Spec-10-Dist-01-xrdclpappspc04',
                                    'nameAlias': ''
                                }
                            }
                        }, {
                            'snmpClientP': {
                                'attributes': {
                                    'addr': '10.26.32.91',
                                    'annotation': '',
                                    'name': 'Spec-9-Dist-09-naspcp0D',
                                    'nameAlias': ''
                                }
                            }
                        }, {
                            'snmpClientP': {
                                'attributes': {
                                    'addr': '10.26.32.66',
                                    'annotation': '',
                                    'name': 'Spec-9-Dist-01-naspcp05',
                                    'nameAlias': ''
                                }
                            }
                        }, {
                            'snmpClientP': {
                                'attributes': {
                                    'addr': '10.26.32.92',
                                    'annotation': '',
                                    'name': 'Spec-9-Dist-10-naspcp0E',
                                    'nameAlias': ''
                                }
                            }
                        }, {
                            'snmpClientP': {
                                'attributes': {
                                    'addr': '10.26.33.6',
                                    'annotation': '',
                                    'name': 'CAPM-Data-Collector2',
                                    'nameAlias': ''
                                }
                            }
                        }, {
                            'snmpClientP': {
                                'attributes': {
                                    'addr': '10.26.32.95',
                                    'annotation': '',
                                    'name': 'Spec-9-FT-Dist-01-naspcp0H',
                                    'nameAlias': ''
                                }
                            }
                        }, {
                            'snmpClientP': {
                                'attributes': {
                                    'addr': '10.26.33.138',
                                    'annotation': '',
                                    'name': 'Spec-10-FT-Dist-03-xrdclpappspc13',
                                    'nameAlias': ''
                                }
                            }
                        }, {
                            'snmpClientP': {
                                'attributes': {
                                    'addr': '10.26.33.130',
                                    'annotation': '',
                                    'name': 'Spec-10-Dist-02-xrdclpappspc05',
                                    'nameAlias': ''
                                }
                            }
                        }
                    ]
                }
            }
        ]
    }
}
fabric['fabricInst']['children'].append(snmp_clients)

snmp_dest_group = {
    'snmpGroup': {
        'attributes': {
            'annotation': '',
            'descr': '',
            'dn': 'uni/fabric/snmpgroup-SNMP_Dest',
            'name': 'SNMP_Dest',
            'status': CR
        },
        'children': [{
                'snmpTrapDest': {
                    'attributes': {
                        'host': '10.26.32.93',
                        'notifT': 'traps',
                        'port': '162',
                        'secName': 'notpublic',
                        'v3SecLvl': 'noauth',
                        'ver': 'v2c'
                    },
                    'children': [{
                            'fileRsARemoteHostToEpg': {
                                'attributes': {
                                    'annotation': '',
                                    'tDn': 'uni/tn-mgmt/mgmtp-default/oob-default'
                                }
                            }
                        }
                    ]
                }
            }
        ]
    }
}
fabric['fabricInst']['children'].append(snmp_dest_group)

syslog_dest_group = {
    'syslogGroup': {
        'attributes': {
            'annotation': '',
            'descr': '',
            'dn': 'uni/fabric/slgroup-Syslog-Destination',
            'format': 'aci',
            'name': 'Syslog-Destination',
            'status': CR
        },
        'children': [{
                'syslogRemoteDest': {
                    'attributes': {
                        'adminState': 'disabled',  # Leave disabled until fabric is production
                        'annotation': '',
                        'descr': '',
                        'format': 'aci',
                        'forwardingFacility': 'local7',
                        'host': env.SyslogDest,
                        'name': 'HCA-Syslog',
                        'nameAlias': '',
                        'port': '514',
                        'severity': 'information'
                    },
                    'children': [{
                            'fileRsARemoteHostToEpg': {
                                'attributes': {
                                    'annotation': '',
                                    'tDn': 'uni/tn-mgmt/mgmtp-default/oob-default'
                                }
                            }
                        }
                    ]
                }
            }, {
                'syslogProf': {
                    'attributes': {
                        'adminState': 'enabled',
                        'annotation': '',
                        'descr': '',
                        'name': 'syslog',
                        'nameAlias': ''
                    }
                }
            }, {
                'syslogFile': {
                    'attributes': {
                        'adminState': 'enabled',
                        'annotation': '',
                        'descr': '',
                        'format': 'aci',
                        'name': '',
                        'nameAlias': '',
                        'severity': 'information'
                    }
                }
            }, {
                'syslogConsole': {
                    'attributes': {
                        'adminState': 'enabled',
                        'annotation': '',
                        'descr': '',
                        'format': 'aci',
                        'name': '',
                        'nameAlias': '',
                        'severity': 'alerts'
                    }
                }
            }
        ]
    }
}
fabric['fabricInst']['children'].append(syslog_dest_group)

bgp_route_reflectors = {
    'bgpInstPol': {
        'attributes': {
            'dn': 'uni/fabric/bgpInstP-default',
            'name': 'default',
            'status': MOD
        },
        'children': [{
                'bgpRRP': {
                    'attributes': {
                        'annotation': '',
                        'descr': '',
                        'name': '',
                        'nameAlias': ''
                    },
                    'children': [{
                            'bgpRRNodePEp': {
                                'attributes': {
                                    'id': '202',
                                    'podId': '1'
                                }
                            }
                        }, {
                            'bgpRRNodePEp': {
                                'attributes': {
                                    'id': '201',
                                    'podId': '1'
                                }
                            }
                        }
                    ]
                }
            }, {
                'bgpAsP': {
                    'attributes': {
                        'asn': env.ASN
                    }
                }
            }
        ]
    }
}
fabric['fabricInst']['children'].append(bgp_route_reflectors)

monitoring_policy = {
    'monCommonPol': {
        'attributes': {
            'dn': 'uni/fabric/moncommon',
            'name': 'default',
            'status': MOD
        },
        'children': [{
                'syslogSrc': {
                    'attributes': {
                        'annotation': '',
                        'descr': '',
                        'incl': 'all,audit,events,faults,session',
                        'minSev': 'information',
                        'name': 'Syslog-Source',
                        'nameAlias': ''
                    },
                    'children': [{
                            'syslogRsDestGroup': {
                                'attributes': {
                                    'annotation': '',
                                    'tDn': 'uni/fabric/slgroup-Syslog-Destination'
                                }
                            }
                        }
                    ]
                }
            }, {
                'snmpSrc': {
                    'attributes': {
                        'annotation': '',
                        'descr': '',
                        'incl': 'events,faults',
                        'minSev': 'info',
                        'name': 'HCA-SNMP',
                        'nameAlias': ''
                    },
                    'children': [{
                            'snmpRsDestGroup': {
                                'attributes': {
                                    'annotation': '',
                                    'tDn': 'uni/fabric/snmpgroup-SNMP_Dest'
                                }
                            }
                        }
                    ]
                }
            }
        ]
    }
}
fabric['fabricInst']['children'].append(monitoring_policy)

ntp_policy = {
    'datetimePol': {
        'attributes': {
            'StratumValue': '8',
            'adminSt': 'enabled',
            'authSt': 'disabled',
            'dn': 'uni/fabric/time-default',
            'masterMode': 'disabled',
            'name': 'default',
            'serverState': 'disabled',
            'status': MOD
        },
        'children': [{
                'datetimeNtpProv': {
                    'attributes': {
                        'annotation': '',
                        'descr': '',
                        'keyId': '0',
                        'maxPoll': '6',
                        'minPoll': '4',
                        'name': '10.90.10.100',
                        'nameAlias': '',
                        'preferred': ('yes' if env.PreferredNTP == '10.90.10.100' else 'no')
                    },
                    'children': [{
                            'datetimeRsNtpProvToEpg': {
                                'attributes': {
                                    'annotation': '',
                                    'tDn': 'uni/tn-mgmt/mgmtp-default/oob-default'
                                }
                            }
                        }
                    ]
                }
            }, {
                'datetimeNtpProv': {
                    'attributes': {
                        'annotation': '',
                        'descr': '',
                        'keyId': '0',
                        'maxPoll': '6',
                        'minPoll': '4',
                        'name': '10.26.10.100',
                        'nameAlias': '',
                        'preferred': ('yes' if env.PreferredNTP == '10.26.10.100' else 'no')
                    },
                    'children': [{
                            'datetimeRsNtpProvToEpg': {
                                'attributes': {
                                    'annotation': '',
                                    'tDn': 'uni/tn-mgmt/mgmtp-default/oob-default'
                                }
                            }
                        }
                    ]
                }
            }, {
                'datetimeNtpProv': {
                    'attributes': {
                        'annotation': '',
                        'descr': '',
                        'keyId': '0',
                        'maxPoll': '6',
                        'minPoll': '4',
                        'name': '10.154.10.100',
                        'nameAlias': '',
                        'preferred': ('yes' if env.PreferredNTP == '10.154.10.100' else 'no')
                    },
                    'children': [{
                            'datetimeRsNtpProvToEpg': {
                                'attributes': {
                                    'annotation': '',
                                    'tDn': 'uni/tn-mgmt/mgmtp-default/oob-default'
                                }
                            }
                        }
                    ]
                }
            }
        ]
    }
}
fabric['fabricInst']['children'].append(ntp_policy)

time_zone = {
    'datetimeFormat': {
        'attributes': {
            'displayFormat': 'local',
            'dn': 'uni/fabric/format-default',
            'name': 'default',
            'showOffset': 'enabled',
            'tz': 'n300_America-Chicago',
            'status': MOD
        }
    }
}
fabric['fabricInst']['children'].append(time_zone)

maintenance_groups = [
    {
        'maintMaintGrp': {
            'attributes': {
                'dn': 'uni/fabric/maintgrp-Odds',
                'name': 'Odds',
                'status': CR,
                'type': 'range'
            },
            'children': []
        }
    }, {
        'maintMaintGrp': {
            'attributes': {
                'dn': 'uni/fabric/maintgrp-Evens',
                'name': 'Evens',
                'status': CR,
                'type': 'range'
            },
            'children': []
        }
    }, {
        'maintMaintGrp': {
            'attributes': {
                'dn': 'uni/fabric/maintgrp-OOB',
                'name': 'Evens',
                'status': CR,
                'type': 'range'
            }
        }
    }, {
        'maintMaintGrp': {
            'attributes': {
                'dn': 'uni/fabric/maintgrp-SP-201',
                'name': 'SP-201',
                'status': CR,
                'type': 'range'
            },
            'children': [{
                    'fabricNodeBlk': {
                        'attributes': {
                            'from_': '201',
                            'name': 'blk201-201',
                            'to_': '201'
                        }
                    }
                }
            ]
        }
    }, {
        'maintMaintGrp': {
            'attributes': {
                'dn': 'uni/fabric/maintgrp-SP-202',
                'name': 'SP-202',
                'status': CR,
                'type': 'range'
            },
            'children': [{
                    'fabricNodeBlk': {
                        'attributes': {
                            'from_': '202',
                            'name': 'blk202-202',
                            'to_': '202'
                        }
                    }
                }
            ]
        }
    }, {
        'maintMaintGrp': {
            'attributes': {
                'dn': 'uni/fabric/maintgrp-Staging',
                'name': 'Staging',
                'status': CR,
                'type': 'range'
            }
        }
    }
]
for group in maintenance_groups:
    fabric['fabricInst']['children'].append(group)

remote_path = {
    'fileRemotePath': {
        'attributes': {
            'dn': 'uni/fabric/path-Voyence',
            'remotePort': '22',
            'name': 'Voyence',
            'host': '10.26.31.85',
            'protocol': 'scp',
            'remotePath': f'/opt/Juniper_Backups/ACI_Fabric/{env.Name}',
            'userName': os.getenv('voyenceuser'),
            'userPasswd': os.getenv('voyencepass'),
            'status': CR
        },
        'children': [{
                'fileRsARemoteHostToEpg': {
                    'attributes': {
                        'tDn': 'uni/tn-mgmt/mgmtp-default/oob-default',
                        'status': 'created,modified'
                    }
                }
            }
        ]
    }
}
fabric['fabricInst']['children'].append(remote_path)

trigger_schedule = {
    'trigSchedP': {
        'attributes': {
            'name': 'Nightly-Backup',
            'status': CR
        },
        'children': [{
                'trigRecurrWindowP': {
                    'attributes': {
                        'concurCap': 'unlimited',
                        'day': 'every-day',
                        'hour': '2',
                        'minute': '0',
                        'name': 'Morning-2AM',
                        'procBreak': 'none',
                        'procCap': 'unlimited',
                        'timeCap': 'unlimited'
                    }
                }
            }
        ]
    }
}
fabric['fabricInst']['children'].append(trigger_schedule)

config_export_profile = {
    'configExportP': {
        'attributes': {
            'adminSt': 'untriggered',
            'format': 'json',
            'includeSecureFields': 'yes',
            'maxSnapshotCount': 'global-limit',
            'name': 'Nightly-Offsite-Config-Export',
            'snapshot': 'no',
            'status': CR
        },
        'children': [{
                'configRsRemotePath': {
                    'attributes': {
                        'tnFileRemotePathName': 'Voyence'
                    }
                }
            }, {
                'configRsExportScheduler': {
                    'attributes': {
                        'tnTrigSchedPName': 'Nightly-Backup'
                    }
                }
            }
        ]
    }
}
fabric['fabricInst']['children'].append(config_export_profile)


# TACACS configuration appends to uni/
# tacacs = {
#     'aaaUserEp': {
#         'attributes': {
#             'dn': 'uni/userext',
#             'status': MOD
#         },
#         'children': [{
#                 'aaaTacacsPlusEp': {
#                     'attributes': {
#                         'dn': 'uni/userext/tacacsext',
#                         'status': MOD
#                     },
#                     'children': [{
#                             'aaaTacacsPlusProvider': {
#                                 'attributes': {
#                                     'name': '10.27.21.99',
#                                     'key': 'fYiqjiaw',
#                                     'status': CREATE
#                                 },
#                                 'children': [{
#                                         'aaaRsSecProvToEpg': {
#                                             'attributes': {
#                                                 'tDn': 'uni/tn-mgmt/mgmtp-default/oob-default'
#                                             }
#                                         }
#                                     }
#                                 ]
#                             }
#                         }, {
#                             'aaaTacacsPlusProvider': {
#                                 'attributes': {
#                                     'name': '10.90.42.49',
#                                     'key': 'fYiqjiaw',
#                                     'status': CREATE
#                                 },
#                                 'children': [{
#                                         'aaaRsSecProvToEpg': {
#                                             'attributes': {
#                                                 'tDn': 'uni/tn-mgmt/mgmtp-default/oob-default'
#                                             }
#                                         }
#                                     }
#                                 ]
#                             }
#                         }, {
#                             'aaaTacacsPlusProviderGroup': {
#                                 'attributes': {
#                                     'name': 'TACACS-Group',
#                                     'status': CREATE
#                                 },
#                                 'children': [{
#                                         'aaaProviderRef': {
#                                             'attributes': {
#                                                 'name': '10.27.21.99',
#                                                 'order': '1'
#                                             }
#                                         }
#                                     }, {
#                                         'aaaProviderRef': {
#                                             'attributes': {
#                                                 'name': '10.90.42.49',
#                                                 'order': '2'
#                                             }
#                                         }
#                                     }
#                                 ]
#                             }
#                         }
#                     ]
#                 }
#             }, {
#                 'aaaAuthRealm': {
#                     'attributes': {
#                         'dn': 'uni/userext/authrealm',
#                         'status': MOD
#                     },
#                     'children': [{
#                             'aaaDefaultAuth': {
#                                 'attributes': {
#                                     'dn': 'uni/userext/authrealm/defaultauth',
#                                     'providerGroup': 'TACACS-Group',
#                                     'realm': 'tacacs',
#                                     'status': MOD
#                                 }
#                             }
#                         }
#                     ]
#                 }
#             }
#         ]
#     }
# }
# uni['polUni']['children'].append(tacacs)


# Management tenant append to tn-mgmt/
oob_contract = {
    'vzOOBBrCP': {
        'attributes': {
            'name': 'c-oob-default',
            'scope': 'context'
        },
        'children': [{
                'vzSubj': {
                    'attributes': {
                        'name': 's-oob-default'
                    },
                    'children': [{
                            'vzRsSubjFiltAtt': {
                                'attributes': {
                                    'tnVzFilterName': 'default'
                                }
                            }
                        }
                    ]
                }
            }
        ]
    }
}
tn_mgmt['fvTenant']['children'].append(oob_contract)

mgmt_profile = {
    'mgmtMgmtP': {
        'attributes': {
            'name': 'default',
            'status': MOD
        },
        'children': []
    }
}
tn_mgmt['fvTenant']['children'].append(mgmt_profile)

oob_epg = {
    'mgmtOoB': {
        'attributes': {
            'name': 'default'
        },
        'children': [{
                'mgmtRsOoBProv': {
                    'attributes': {
                        'tnVzOOBBrCPName': 'c-oob-default'
                    }
                }
            }
        ]
    }
}
mgmt_profile['mgmtMgmtP']['children'].append(oob_epg)

oob_external = {
    'mgmtExtMgmtEntity': {
        'attributes': {
            'name': 'default'
        },
        'children': [{
                'mgmtInstP': {
                    'attributes': {
                        'name': 'oob-mgmt-ext'
                    },
                    'children': [{
                            'mgmtRsOoBCons': {
                                'attributes': {
                                    'tnVzOOBBrCPName': 'c-oob-default'
                                }
                            }
                        }, {
                            'mgmtSubnet': {
                                'attributes': {
                                    'ip': '0.0.0.0/0'
                                }
                            }
                        }
                    ]
                }
            }
        ]
    }
}
tn_mgmt['fvTenant']['children'].append(oob_external)


# Generate management addresses for apics, leafs, and spines
net = network(env.OOBLeafIPRange)
base_address = address(net.network_address)

for node, num in zip(['1', '2', '3', '101', '102', '201', '202'], [11, 12, 13, 6, 7, 4, 5]):
    node_config = {
        'mgmtRsOoBStNode': {
            'attributes': {
                'addr': f'{base_address + num}/{net.prefixlen}',
                'dn': f'uni/tn-mgmt/mgmtp-default/oob-default/rsooBStNode-[topology/pod-1/node-{node}]',
                'gw': f'{base_address + 1}',
                'tDn': f'topology/pod-1/node-{node}'
            }
        }
    }
    oob_epg['mgmtOoB']['children'].append(node_config)


'''
Create HCA Tenant Base Configurations:
c-Any contract  √
HCA VRF with c-Any provided and consumed  √
Not-Routed VRF  √
L3Outs  √
OSPF Interface Policy  √
'''

f_any = {  # Removed dn to allow consumption by any tenant
    'vzFilter': {
        'attributes': {
            'name': 'f-any',
            'status': CR
        },
        'children': [{
                'vzEntry': {
                    'attributes': {
                        'applyToFrag': 'no',
                        'arpOpc': 'unspecified',
                        'dFromPort': 'unspecified',
                        'dToPort': 'unspecified',
                        'etherT': 'unspecified',
                        'icmpv4T': 'unspecified',
                        'icmpv6T': 'unspecified',
                        'matchDscp': 'unspecified',
                        'name': 'any',
                        'prot': 'unspecified',
                        'sFromPort': 'unspecified',
                        'sToPort': 'unspecified',
                        'stateful': 'no',
                        'tcpRules': ''
                    }
                }
            }
        ]
    }
}
tn_hca['fvTenant']['children'].append(f_any)
tn_hcadr['fvTenant']['children'].append(f_any)

c_any = {  # Remove dn to be consumable by multiple tenants
    'vzBrCP': {
        'attributes': {
            'name': 'c-Any',
            'prio': 'unspecified',
            'scope': 'context',
            'targetDscp': 'unspecified',
            'status': CR
        },
        'children': [{
                'vzSubj': {
                    'attributes': {
                        'consMatchT': 'AtleastOne',
                        'name': 's-Any',
                        'prio': 'unspecified',
                        'provMatchT': 'AtleastOne',
                        'revFltPorts': 'yes',
                        'targetDscp': 'unspecified'
                    },
                    'children': [{
                            'vzRsSubjFiltAtt': {
                                'attributes': {
                                    'action': 'permit',
                                    'directives': '',
                                    'priorityOverride': 'default',
                                    'tnVzFilterName': 'f-any'
                                }
                            }
                        }
                    ]
                }
            }
        ]
    }
}
tn_hca['fvTenant']['children'].append(c_any)
tn_hcadr['fvTenant']['children'].append(c_any)

vrf_hca = {
    'fvCtx': {
        'attributes': {
            'bdEnforcedEnable': 'no',
            'dn': 'uni/tn-tn-HCA/ctx-vrf-hca',
            'knwMcastAct': 'permit',
            'name': 'vrf-hca',
            'pcEnfDir': 'ingress',
            'pcEnfPref': 'enforced',
            'status': CR
        },
        'children': [{
                'fvRsVrfValidationPol': {
                    'attributes': {
                        'annotation': '',
                        'tnL3extVrfValidationPolName': ''
                    }
                }
            }, {
                'vzAny': {
                    'attributes': {
                        'matchT': 'AtleastOne',
                        'prefGrMemb': 'disabled'
                    },
                    'children': [{
                            'vzRsAnyToProv': {
                                'attributes': {
                                    'matchT': 'AtleastOne',
                                    'prio': 'unspecified',
                                    'tnVzBrCPName': 'c-Any'
                                }
                            }
                        }, {
                            'vzRsAnyToCons': {
                                'attributes': {
                                    'prio': 'unspecified',
                                    'tnVzBrCPName': 'c-Any'
                                }
                            }
                        }
                    ]
                }
            }
        ]
    }
}
tn_hca['fvTenant']['children'].append(vrf_hca)

vrf_not_routed = {
    'fvCtx': {
        'attributes': {
            'bdEnforcedEnable': 'no',
            'dn': 'uni/tn-tn-HCA/ctx-vrf-Not-Routed',
            'knwMcastAct': 'permit',
            'name': 'vrf-Not-Routed',
            'pcEnfDir': 'ingress',
            'pcEnfPref': 'enforced',
            'status': CR
        }
    }
}
tn_hca['fvTenant']['children'].append(vrf_not_routed)

ospf_core_if_policy = {
    'ospfIfPol': {
        'attributes': {
            'cost': 'unspecified',
            'ctrl': '',
            'deadIntvl': '40',
            'helloIntvl': '10',
            'name': 'OSPF-Core',
            'nwT': 'p2p',
            'pfxSuppress': 'inherit',
            'prio': '1',
            'rexmitIntvl': '5',
            'xmitDelay': '1',
            'status': CR
        }
    }
}
tn_hca['fvTenant']['children'].append(ospf_core_if_policy)  # Omitted dn so it could be used in both tenants
tn_hcadr['fvTenant']['children'].append(ospf_core_if_policy)

ospf_passive_if_policy = {
    'ospfIfPol': {
        'attributes': {
            'cost': 'unspecified',
            'ctrl': 'passive',
            'deadIntvl': '40',
            'helloIntvl': '10',
            'name': 'OSPF-Passive',
            'nwT': 'bcast',
            'pfxSuppress': 'inherit',
            'prio': '1',
            'rexmitIntvl': '5',
            'xmitDelay': '1',
            'status': CR
        }
    }
}
tn_hca['fvTenant']['children'].append(ospf_passive_if_policy)  # Omitted dn so it could be used in both tenants
# tn_hcadr['fvTenant']['children'].append(ospf_passive_if_policy)

ospf_area = network(env.IPSupernet)
location_1 = env.BLF101Location
location_2 = env.BLF102Location

hca_core_l3out = {
    'l3extOut': {
        'attributes': {
            'descr': 'Routed networks to Core',
            'enforceRtctrl': 'export',
            'name': 'L3Out-Core',
            'targetDscp': 'unspecified',
            'status': CR
        },
        'children': [{
                'ospfExtP': {
                    'attributes': {
                        'areaCost': '1',
                        'areaCtrl': 'redistribute',
                        'areaId': f'{ospf_area.network_address}',
                        'areaType': 'nssa',
                        'multipodInternal': 'no'
                    }
                }
            }, {
                'l3extRsL3DomAtt': {
                    'attributes': {
                        'tDn': f'uni/l3dom-l3-dom-{data_center}'
                    }
                }
            }, {
                'l3extRsEctx': {
                    'attributes': {
                        'tnFvCtxName': 'vrf-hca'
                    }
                }
            }, {
                'l3extLNodeP': {
                    'attributes': {
                        'name': f'{location_1}-101',
                        'targetDscp': 'unspecified'
                    },
                    'children': [{
                            'l3extRsNodeL3OutAtt': {
                                'attributes': {
                                    'rtrId': f'{ospf_area.network_address + 10}',
                                    'rtrIdLoopBack': 'yes',
                                    'tDn': 'topology/pod-1/node-101'
                                },
                                'children': []
                            }
                        }, {
                            'l3extLIfP': {
                                'attributes': {
                                    'name': f'{location_1}-101-47-48',
                                    'tag': 'yellow-green'
                                },
                                'children': [{
                                        'ospfIfP': {
                                            'attributes': {
                                                'annotation': '',
                                                'authKeyId': '1',
                                                'authType': 'none',
                                                'descr': '',
                                                'name': '',
                                                'nameAlias': ''
                                            },
                                            'children': [{
                                                    'ospfRsIfPol': {
                                                        'attributes': {
                                                            'tnOspfIfPolName': 'OSPF-Core'
                                                        }
                                                    }
                                                }
                                            ]
                                        }
                                    }
                                ]
                            }
                        }
                    ]
                }
            }, {
                'l3extLNodeP': {
                    'attributes': {
                        'name': f'{location_2}-102',
                        'tag': 'yellow-green',
                        'targetDscp': 'unspecified'
                    },
                    'children': [{
                            'l3extRsNodeL3OutAtt': {
                                'attributes': {
                                    'rtrId': f'{ospf_area.network_address + 11}',
                                    'rtrIdLoopBack': 'yes',
                                    'tDn': 'topology/pod-1/node-102'
                                },
                                'children': []
                            }
                        }, {
                            'l3extLIfP': {
                                'attributes': {
                                    'name': f'{location_2}-102-47-48',
                                    'tag': 'yellow-green'
                                },
                                'children': [{
                                        'ospfIfP': {
                                            'attributes': {
                                                'annotation': '',
                                                'authKeyId': '1',
                                                'authType': 'none',
                                                'descr': '',
                                                'name': '',
                                                'nameAlias': ''
                                            },
                                            'children': [{
                                                    'ospfRsIfPol': {
                                                        'attributes': {
                                                            'tnOspfIfPolName': 'OSPF-Core'
                                                        }
                                                    }
                                                }
                                            ]
                                        }
                                    }
                                ]
                            }
                        }
                    ]
                }
            }, {
                'l3extInstP': {
                    'attributes': {
                        'floodOnEncap': 'disabled',
                        'matchT': 'AtleastOne',
                        'name': 'epg-External-Networks',
                        'prefGrMemb': 'exclude',
                        'prio': 'unspecified',
                        'targetDscp': 'unspecified'
                    },
                    'children': [{
                            'l3extSubnet': {
                                'attributes': {
                                    'aggregate': '',
                                    'annotation': '',
                                    'descr': '',
                                    'ip': '0.0.0.0/0',
                                    'scope': 'export-rtctrl,import-security'
                                }
                            }
                        }
                    ]
                }
            }
        ]
    }
}
tn_hca['fvTenant']['children'].append(hca_core_l3out)

hca_admz_l3out = {
    'l3extOut': {
        'attributes': {
            'dn': 'uni/tn-tn-HCA/out-L3Out-ADMZ',
            'enforceRtctrl': 'export',
            'name': 'L3Out-ADMZ',
            'targetDscp': 'unspecified',
            'status': CR
        },
        'children': [{
                'l3extRsL3DomAtt': {
                    'attributes': {
                        'tDn': f'uni/l3dom-l3-dom-{data_center}'
                    }
                }
            }, {
                'l3extRsEctx': {
                    'attributes': {
                        'tnFvCtxName': 'vrf-hca'
                    }
                }
            }, {
                'l3extLNodeP': {
                    'attributes': {
                        'name': 'BLF-101-102-FW-ADMZ-Frontside',
                        'tag': 'yellow-green',
                        'targetDscp': 'unspecified'
                    },
                    'children': [{
                            'l3extRsNodeL3OutAtt': {
                                'attributes': {
                                    'rtrId': f'{ospf_area.network_address + 11}',
                                    'rtrIdLoopBack': 'no',
                                    'tDn': 'topology/pod-1/node-102'
                                },
                                'children': []
                            }
                        }, {
                            'l3extRsNodeL3OutAtt': {
                                'attributes': {
                                    'rtrId': f'{ospf_area.network_address + 10}',
                                    'rtrIdLoopBack': 'no',
                                    'tDn': 'topology/pod-1/node-101'
                                },
                                'children': []
                            }
                        }, {
                            'l3extLIfP': {
                                'attributes': {
                                    'name': f'BLF-101-102-FW-ADMZ-Uplinks',
                                    'tag': 'yellow-green'
                                },
                                'children': [{
                                        'ospfIfP': {
                                            'attributes': {
                                                'authKeyId': '1',
                                                'authType': 'none'
                                            },
                                            'children': [{
                                                    'ospfRsIfPol': {
                                                        'attributes': {
                                                            'tnOspfIfPolName': 'OSPF-Passive'
                                                        }
                                                    }
                                                }
                                            ]
                                        }
                                    }
                                ]
                            }
                        }
                    ]
                }
            }, {
                'l3extInstP': {
                    'attributes': {
                        'floodOnEncap': 'disabled',
                        'matchT': 'AtleastOne',
                        'name': 'epg-ADMZ-Networks',
                        'prefGrMemb': 'exclude',
                        'prio': 'unspecified',
                        'targetDscp': 'unspecified'
                    },
                    'children': []
                }
            }
        ]
    }
}
tn_hca['fvTenant']['children'].append(hca_admz_l3out)

hca_f5_l3out = {
    'l3extOut': {
        'attributes': {
            'dn': 'uni/tn-tn-HCA/out-L3Out-F5',
            'enforceRtctrl': 'export',
            'name': 'L3Out-F5',
            'targetDscp': 'unspecified',
            'status': CR
        },
        'children': [{
                'l3extRsL3DomAtt': {
                    'attributes': {
                        'tDn': f'uni/l3dom-l3-dom-{data_center}'
                    }
                }
            }, {
                'l3extRsEctx': {
                    'attributes': {
                        'tnFvCtxName': 'vrf-hca'
                    }
                }
            }, {
                'l3extLNodeP': {
                    'attributes': {
                        'name': f'BLF-101-102-F5-Frontside',
                        'tag': 'yellow-green',
                        'targetDscp': 'unspecified'
                    },
                    'children': [{
                            'l3extRsNodeL3OutAtt': {
                                'attributes': {
                                    'rtrId': f'{ospf_area.network_address + 10}',
                                    'rtrIdLoopBack': 'no',
                                    'tDn': 'topology/pod-1/node-101'
                                },
                                'children': []
                            }
                        }, {
                            'l3extRsNodeL3OutAtt': {
                                'attributes': {
                                    'rtrId': f'{ospf_area.network_address + 11}',
                                    'rtrIdLoopBack': 'no',
                                    'tDn': 'topology/pod-1/node-102'
                                },
                                'children': []
                            }
                        }, {
                            'l3extLIfP': {
                                'attributes': {
                                    'name': f'BLF-101-102-F5-Uplinks',
                                    'tag': 'yellow-green'
                                },
                                'children': [{
                                        'ospfIfP': {
                                            'attributes': {
                                                'authKeyId': '1',
                                                'authType': 'none'
                                            },
                                            'children': [{
                                                    'ospfRsIfPol': {
                                                        'attributes': {
                                                            'tnOspfIfPolName': 'OSPF-Passive'
                                                        }
                                                    }
                                                }
                                            ]
                                        }
                                    }
                                ]
                            }
                        }
                    ]
                }
            }, {
                'l3extInstP': {
                    'attributes': {
                        'floodOnEncap': 'disabled',
                        'matchT': 'AtleastOne',
                        'name': 'epg-F5-QA-VIPs',
                        'prefGrMemb': 'exclude',
                        'prio': 'unspecified',
                        'targetDscp': 'unspecified'
                    },
                    'children': []
                }
            }, {
                'l3extInstP': {
                    'attributes': {
                        'floodOnEncap': 'disabled',
                        'matchT': 'AtleastOne',
                        'name': 'epg-F5-Prod-VIPs',
                        'prefGrMemb': 'exclude',
                        'prio': 'unspecified',
                        'targetDscp': 'unspecified'
                    },
                    'children': []
                }
            }
        ]
    }
}
tn_hca['fvTenant']['children'].append(hca_f5_l3out)

'''
Create HCADR Tenant Base Configurations:
c-Any contract  √
HCADR VRF with c-Any provided and consumed  √
Data Replication BD (no subnet)  √
Data Replication AP and EPG  √
'''

vrf_hcadr = {
    'fvCtx': {
        'attributes': {
            'bdEnforcedEnable': 'no',
            'dn': 'uni/tn-tn-HCADR/ctx-vrf-hcadr',
            'knwMcastAct': 'permit',
            'name': 'vrf-hcadr',
            'pcEnfDir': 'ingress',
            'pcEnfPref': 'enforced',
            'status': CR
        },
        'children': [{
                'fvRsVrfValidationPol': {
                    'attributes': {
                        'annotation': '',
                        'tnL3extVrfValidationPolName': ''
                    }
                }
            }, {
                'vzAny': {
                    'attributes': {
                        'matchT': 'AtleastOne',
                        'prefGrMemb': 'disabled'
                    },
                    'children': [{
                            'vzRsAnyToProv': {
                                'attributes': {
                                    'matchT': 'AtleastOne',
                                    'prio': 'unspecified',
                                    'tnVzBrCPName': 'c-Any'
                                }
                            }
                        }, {
                            'vzRsAnyToCons': {
                                'attributes': {
                                    'prio': 'unspecified',
                                    'tnVzBrCPName': 'c-Any'
                                }
                            }
                        }
                    ]
                }
            }
        ]
    }
}
tn_hcadr['fvTenant']['children'].append(vrf_hcadr)

hcadr_bd = {
    'fvBD': {
        'attributes': {
            'OptimizeWanBandwidth': 'no',
            'arpFlood': 'no',
            'dn': 'uni/tn-tn-HCADR/BD-bd-Data-Replication',
            'epClear': 'no',
            'epMoveDetectMode': '',
            'ipLearning': 'yes',
            'limitIpLearnToSubnets': 'yes',
            'mcastAllow': 'no',
            'multiDstPktAct': 'bd-flood',
            'name': 'bd-Data-Replication',
            'type': 'regular',
            'unicastRoute': 'yes',
            'unkMacUcastAct': 'proxy',
            'unkMcastAct': 'flood',
            'status': CR
        },
        'children': [{
                'fvRsCtx': {
                    'attributes': {
                        'tnFvCtxName': 'vrf-hcadr'
                    }
                }
            }, {
                'fvRsBDToOut': {
                    'attributes': {
                        'tnL3extOutName': 'L3Out-Core-HCADR'
                    }
                }
            }
        ]
    }
}
tn_hcadr['fvTenant']['children'].append(hcadr_bd)

hcadr_epg = {
    'fvAp': {
        'attributes': {
            'dn': 'uni/tn-tn-HCADR/ap-ap-Data-Replication',
            'name': 'ap-Data-Replication',
            'status': CR
        },
        'children': [{
                'fvAEPg': {
                    'attributes': {
                        'name': 'epg-Data-Replication'
                    },
                    'children': [{
                            'fvRsDomAtt': {
                                'attributes': {
                                    'tDn': f'uni/phys-phy-dom-{data_center}'
                                }
                            }
                        }, {
                            'fvRsBd': {
                                'attributes': {
                                    'tnFvBDName': 'bd-Data-Replication'
                                }
                            }
                        }
                    ]
                }
            }
        ]
    }
}
tn_hcadr['fvTenant']['children'].append(hcadr_epg)

hcadr_core_l3out = {
    'l3extOut': {
        'attributes': {
            'descr': 'Routed networks to Core',
            'enforceRtctrl': 'export',
            'name': 'L3Out-Core-HCADR',
            'targetDscp': 'unspecified',
            'status': CR
        },
        'children': [{
                'ospfExtP': {
                    'attributes': {
                        'areaCost': '1',
                        'areaCtrl': 'redistribute',
                        'areaId': f'{ospf_area.network_address}',
                        'areaType': 'nssa',
                        'multipodInternal': 'no'
                    }
                }
            }, {
                'l3extRsL3DomAtt': {
                    'attributes': {
                        'tDn': f'uni/l3dom-l3-dom-{data_center}'
                    }
                }
            }, {
                'l3extRsEctx': {
                    'attributes': {
                        'tnFvCtxName': 'vrf-hcadr'
                    }
                }
            }, {
                'l3extLNodeP': {
                    'attributes': {
                        'name': f'{location_1}-101',
                        'targetDscp': 'unspecified'
                    },
                    'children': [{
                            'l3extRsNodeL3OutAtt': {
                                'attributes': {
                                    'rtrId': f'{ospf_area.network_address + 10}',
                                    'rtrIdLoopBack': 'yes',
                                    'tDn': 'topology/pod-1/node-101'
                                },
                                'children': []
                            }
                        }, {
                            'l3extLIfP': {
                                'attributes': {
                                    'name': f'{location_1}-101-45-46',
                                    'tag': 'yellow-green'
                                },
                                'children': [{
                                        'ospfIfP': {
                                            'attributes': {
                                                'annotation': '',
                                                'authKeyId': '1',
                                                'authType': 'none',
                                                'descr': '',
                                                'name': '',
                                                'nameAlias': ''
                                            },
                                            'children': [{
                                                    'ospfRsIfPol': {
                                                        'attributes': {
                                                            'tnOspfIfPolName': 'OSPF-Core'
                                                        }
                                                    }
                                                }
                                            ]
                                        }
                                    }
                                ]
                            }
                        }
                    ]
                }
            }, {
                'l3extLNodeP': {
                    'attributes': {
                        'name': f'{location_2}-102',
                        'tag': 'yellow-green',
                        'targetDscp': 'unspecified'
                    },
                    'children': [{
                            'l3extRsNodeL3OutAtt': {
                                'attributes': {
                                    'rtrId': f'{ospf_area.network_address + 11}',
                                    'rtrIdLoopBack': 'yes',
                                    'tDn': 'topology/pod-1/node-102'
                                },
                                'children': []
                            }
                        }, {
                            'l3extLIfP': {
                                'attributes': {
                                    'name': f'{location_2}-102-45-46',
                                    'tag': 'yellow-green'
                                },
                                'children': [{
                                        'ospfIfP': {
                                            'attributes': {
                                                'annotation': '',
                                                'authKeyId': '1',
                                                'authType': 'none',
                                                'descr': '',
                                                'name': '',
                                                'nameAlias': ''
                                            },
                                            'children': [{
                                                    'ospfRsIfPol': {
                                                        'attributes': {
                                                            'tnOspfIfPolName': 'OSPF-Core'
                                                        }
                                                    }
                                                }
                                            ]
                                        }
                                    }
                                ]
                            }
                        }
                    ]
                }
            }, {
                'l3extInstP': {
                    'attributes': {
                        'floodOnEncap': 'disabled',
                        'matchT': 'AtleastOne',
                        'name': 'epg-External-Networks',
                        'prefGrMemb': 'exclude',
                        'prio': 'unspecified',
                        'targetDscp': 'unspecified'
                    },
                    'children': [{
                            'l3extSubnet': {
                                'attributes': {
                                    'aggregate': '',
                                    'annotation': '',
                                    'descr': '',
                                    'ip': '0.0.0.0/0',
                                    'scope': 'export-rtctrl,import-security'
                                }
                            }
                        }
                    ]
                }
            }
        ]
    }
}
tn_hcadr['fvTenant']['children'].append(hcadr_core_l3out)

# Create any switch profiles that can logically be determined
nodes = session.get(f'{url}/api/mo/fabricNode.json').json()['imdata']
nodes = [FabricNode.load(n) for n in nodes]
blf_nodes = [n for n in nodes if n.attributes.id in ['101', '102']]
data_leaf_nodes = [n for n in nodes if 102 < int(n.attributes.id) < 200]
oob_leaf_nodes = [n for n in nodes if 300 < int(n.attributes.id) < 400]

# Create OOB Leaf Profile
oob_profile = SwitchProfile()
oob_profile.attributes.name = f'{env.Name}-OOB-Leafs'
for oob_leaf in oob_leaf_nodes:
    oob_profile.create_switch_profile(name=f'{env.Name}-OOB-Leafs', nodes=[int(oob_leaf.attributes.id)])

session.post(f'{url}/api/mo/uni/infra.json', oob_profile.json())

# Create Border Leaf Profile
rack = set([re.search(r'[A-Z]\d\d', n.attributes.name).group() for n in blf_nodes])

blf_sw_profile = SwitchProfile()
blf_sw_profile.create_switch_profile(name=f'{env.Name}-{"-".join(rack)}-BLF-101-102', nodes=[101, 102])

vpc_profile = FabricProtPol()
vpc_profile.add_new_vpc_pair([101, 102])

session.post(f'{url}{blf_sw_profile.post_uri}', vpc_profile.json())

# Create Data Leaf Profiles
data_leaf_nodes.sort(key=lambda z: z.attributes.id)
if data_leaf_nodes:
    for x in range(0, len(data_leaf_nodes), 2):
        leaf_1 = data_leaf_nodes[x]
        leaf_2 = data_leaf_nodes[x + 1]

        rack_set = {re.search(r'[A-Z]\d\d', leaf_1.attributes.name).group()}
        rack_set.add(re.search(r'[A-Z]\d\d', leaf_2.attributes.name).group())

        leaf_profile = SwitchProfile()
        leaf_profile.create_switch_profile(name=f'{env.Name}-{"-".join(rack_set)}-LF-{leaf_1.attributes.id}-'
                                                f'{leaf_2.attributes.id}',
                                           nodes=[leaf_1.attributes.id, leaf_2.attributes.id])

        session.post(f'{url}{leaf_profile.post_uri}', leaf_profile.json())

        vpc_profile = FabricProtPol()
        vpc_profile.add_new_vpc_pair([leaf_1.attributes.id, leaf_2.attributes.id])

        session.post(f'{url}{leaf_profile.post_uri}', vpc_profile.json())

# Add all leaf nodes to a maintenance group
for node in itertools.chain(blf_nodes, data_leaf_nodes, oob_leaf_nodes):
    if 300 < int(node.attributes.id) < 400:
        node_block = FabricNodeBlock(int(node.attributes.id))
        node_block.attributes.dn = f'uni/fabric/maintgrp-OOB/nodeblk-blk{node}-{node}'

        session.post(f'{url}/api/mo/uni.json', node_block.json())

    elif 100 < int(node.attributes.id) < 200:
        if int(node.attributes.id) % 2:
            node_block = FabricNodeBlock(int(node.attributes.id))
            node_block.attributes.dn = f'uni/fabric/maintgrp-Odds/nodeblk-blk{node}-{node}'
        else:
            node_block = FabricNodeBlock(int(node.attributes.id))
            node_block.attributes.dn = f'uni/fabric/maintgrp-Evens/nodeblk-blk{node}-{node}'

            session.post(f'{url}/api/mo/uni.json', node_block.json())

        session.post(f'{url}/api/mo/uni.json', node_block.json())

# Create Interface Profiles and Policy Groups for OOB Management

aep = AEP()
aep.attributes.name = 'aep-OOB-Management'
aep.attributes.__delattr__('dn')
aep.infra_generic = InfraGeneric()
aep.create()
response = session.post(f'{url}{aep.post_uri}', json=aep.json())
assert response.ok

oob_pg = InterfacePolicyGroup()
oob_pg.create()
oob_pg.attributes.name = 'acc-OOB-Management'
oob_pg.use_aep(aep_name='aep-OOB-Management')
response = session.post(f'{url}{oob_pg.post_uri}', json=oob_pg.json())
assert response.ok

attach_policy_group = GenericClass('infraRsAccBaseGrp')
attach_policy_group.attributes.tDn = f'uni/infra/funcprof/accportgrp-{oob_pg.attributes.name}'
attach_policy_group.create()

oob_block = InterfaceBlock()
oob_block.create()
oob_block.attributes.name = 'block2'
oob_block.attributes.fromPort = '1'
oob_block.attributes.toPort = '48'

oob_selector = InterfaceSelector()
oob_selector.create()
oob_selector.attributes.name = 'acc-1--48'
oob_selector.children = [attach_policy_group, oob_block]

oob_prof = InterfaceProfile()
oob_prof.create()
oob_prof.attributes.name = f'{env.Name}-OOB-Leafs'
oob_prof.children = [oob_selector]
response = session.post(f'{url}{oob_prof.post_uri}', json=oob_prof.json())
assert response.ok

attach_i_profile = GenericClass('infraRsAccPortP')
attach_i_profile.attributes.dn = f'uni/infra/nprof-{oob_profile.attributes.name}/' \
                                 f'rsaccPortP-[uni/infra/accportprof-{oob_prof.attributes.name}]'
attach_i_profile.create()
response = session.post(f'{url}/api/mo/uni.json', json=attach_i_profile.json())
assert response.ok

# Create aep-Placeholders
aep = AEP()
aep.attributes.__setattr__('name', 'aep-Placeholders')
aep.attributes.__delattr__('dn')
aep.infra_generic = InfraGeneric()
aep.create()
response = session.post(f'{url}{aep.post_uri}', json=aep.json())
assert response.ok

response = session.post(f'{url}/api/mo/uni.json', json=infra)
print(json.dumps(infra))
assert response.ok

response = session.post(f'{url}/api/mo/uni.json', json=fabric)
print(json.dumps(fabric))
assert response.ok

response = session.post(f'{url}/api/mo/uni.json', json=uni)
print(json.dumps(uni))
assert response.ok

response = session.post(f'{url}/api/mo/uni.json', json=tn_mgmt)
print(json.dumps(tn_mgmt))
assert response.ok

response = session.post(f'{url}/api/mo/uni.json', json=tn_hca)
print(json.dumps(tn_hca))
assert response.ok

response = session.post(f'{url}/api/mo/uni.json', json=tn_hcadr)
print(json.dumps(tn_hcadr))
assert response.ok

response = session.post(f'{url}/api/mo/uni.json', json=tn_admz)
print(json.dumps(tn_admz))
assert response.ok
