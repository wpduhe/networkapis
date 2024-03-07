from ipaddress import ip_network as network
from ipaddress import ip_address as address
from data.environments import ACIEnvironment
from apic.classes import *
# import itertools
import requests
import json
import re
import os

os.chdir('C:/Users/jxu8356/PycharmProjects/networkapis/src')

env = ACIEnvironment('hodc-az2')

CR = 'created,modified'
MOD = 'modified'
PASSWORD = ''

URL = f'https://{env.IPAddress}'
loginURL = f'{URL}/api/aaaLogin.json'
SNMP_TRAP_DEST = '10.26.32.93'
OOBPROFILENAME = 'OOB-Leafs'
SNMP_CLIENTS = [('Spec-10-Dist-03-xrdclpappspc06', '10.26.33.131'),
                ('Cisco-Collector-Server-1', '10.26.31.30'),
                ('Spectrum1', '10.26.32.65'),
                ('Spec-9-Dist-02-naspcp06', '10.26.32.67'),
                ('Spec-9-Dist-08-naspcp0C', '10.26.32.89'),
                ('Spec-10-Dist-04-xrdclpappspc07', '10.26.33.132'),
                ('Spec-9-Dist-05-naspcp09', '10.26.32.75'),
                ('Spec-9-FT-Dist-02-naspcp0I', '10.26.32.96'),
                ('Spec-9-FT-Dist-08-naspcp0O', '10.26.32.109'),
                ('Spec-9-FT-Dist-04-naspcp0K', '10.26.32.98'),
                ('Spec-9-FT-Dist-07-naspcp0N', '10.26.32.108'),
                ('Spec-10-FT-Dist-01-xrdclpappspc11', '10.26.33.136'),
                ('Spec-9-Dist-03-naspcp07', '10.26.32.68'),
                ('Spec-9-FT-Dist-06-naspcp0M', '10.26.32.107'),
                ('Spec-10-FT-Dist-04-xrdclpappspc14', '10.26.33.139'),
                ('Spec-9-FT-Dist-10-naspcp0Q', '10.26.32.158'),
                ('Spec-9-Dist-06-naspcp0A', '10.26.32.79'),
                ('Spec-10-FT-Dist-02-xrdclpappspc12', '10.26.33.137'),
                ('CAPM-Data-Collector1', '10.26.33.62'),
                ('Spec-9-Dist-07-naspcp0B', '10.26.32.88'),
                ('Spec-9-FT-Dist-05-naspcp0L', '10.26.32.99'),
                ('Spec-9-Dist-04-naspcp08', '10.26.32.69'),
                ('Spec-9-FT-Dist-09-naspcp0P', '10.26.32.157'),
                ('Spec-9-FT-Dist-03-naspcp0J', '10.26.32.97'),
                ('Spec-10-Dist-01-xrdclpappspc04', '10.26.33.129'),
                ('Spec-9-Dist-09-naspcp0D', '10.26.32.91'),
                ('Spec-9-Dist-01-naspcp05', '10.26.32.66'),
                ('Spec-9-Dist-10-naspcp0E', '10.26.32.92'),
                ('CAPM-Data-Collector2', '10.26.33.6'),
                ('Spec-9-FT-Dist-01-naspcp0H', '10.26.32.95'),
                ('Spec-10-FT-Dist-03-xrdclpappspc13', '10.26.33.138'),
                ('Spec-10-Dist-02-xrdclpappspc05', '10.26.33.130')]


session = requests.session()
session.verify = False


# Login to APIC
response = session.post(loginURL, json={'aaaUser': {'attributes': {'name': 'admin', 'pwd': PASSWORD}}})
assert response.ok


# Configure fabric-wide settings
settings = {
    'domainValidation': 'no',
    'enforceSubnetCheck': 'yes',
    'opflexpAuthenticateClients': 'no',
    'opflexpUseSsl': 'yes',
    'reallocateGipo': 'no',
    'unicastXrEpLearnDisable': 'yes',
}
fabric_settings = GenericClass(apic_class='infraSetPol', name='default', **settings)

resp = session.post(f'{URL}/api/mo/uni/infra.json', fabric_settings.json())
print(resp.json())
assert resp.ok


# Configure Standard interface policies  CDP / LLDP / Port Aggregation
cdp = GenericClass(apic_class='cdpIfPol', name='CDP-Enable', adminSt='enabled')
lldp = GenericClass(apic_class='lldpIfPol', name='LLDP-Enable', adminRxSt='enabled', adminTxSt='enabled')
pc_active = GenericClass(apic_class='lacpLagPol', name='pc-LACP-Active', mode='active', minLinks='1', maxLinks='16',
                         ctrl='fast-sel-hot-stdby,graceful-conv,susp-individual')
pc_on = GenericClass(apic_class='lacpLagPol', name='pc-Static-ON', mode='off', minLinks='1', maxLinks='16',
                     ctrl='fast-sel-hot-stdby,graceful-conv,susp-individual')

resp = session.post(f'{URL}/api/mo/uni/infra.json', cdp.json())
print(resp.json())
assert resp.ok

resp = session.post(f'{URL}/api/mo/uni/infra.json', lldp.json())
print(resp.json())
assert resp.ok

resp = session.post(f'{URL}/api/mo/uni/infra.json', pc_active.json())
print(resp.json())
assert resp.ok

resp = session.post(f'{URL}/api/mo/uni/infra.json', pc_on.json())
print(resp.json())
assert resp.ok


# Create VLAN pool for fabric
vlp = GenericClass(apic_class='fvnsVlanInstP', name=f'vlp-{env.DataCenter}', allocMode='dynamic')
block1 = GenericClass(apic_class='fvnsEncapBlk', allocMode='static', to='vlan-3966', role='external')
block2 = GenericClass(apic_class='fvnsEncapBlk', allocMode='static', to='vlan-4094', role='external')
block1.attributes.__setattr__('from', 'vlan-2')
block2.attributes.__setattr__('from', 'vlan-3968')

vlp.children = [block1, block2]

resp = session.post(f'{URL}/api/mo/uni/infra.json', vlp.json())
print(resp.json())
assert resp.ok


# Create physical and layer3 domains for fabric
vlp_rel = GenericClass(apic_class='infraRsVlanNs', tDn=f'uni/infra/vlanns-[vlp-{env.DataCenter}]-dynamic')

phy_dom = GenericClass(apic_class='physDomP', name=f'phy-dom-{env.DataCenter}')
l3_dom = GenericClass(apic_class='l3extDomP', name=f'l3-dom-{env.DataCenter}')

phy_dom.children = [vlp_rel]
l3_dom.children = [vlp_rel]

resp = session.post(f'{URL}/api/mo/uni.json', phy_dom.json())
print(resp.json())
assert resp.ok

resp = session.post(f'{URL}/api/mo/uni.json', l3_dom.json())
print(resp.json())
assert resp.ok


# Create Standard AEPs
aep_l3 = GenericClass(apic_class='infraAttEntityP', name='aep-L3-Ports')
l3_dom_rel = GenericClass(apic_class='infraRsDomP', tDn=f'uni/l3dom-{l3_dom.attributes.name}')

aep_place = GenericClass(apic_class='infraAttEntityP', name='aep-Placeholders')
place_dom_rel = GenericClass(apic_class='infraRsDomP', tDn=f'uni/phys-{phy_dom.attributes.name}')

aep_l3.children = [l3_dom_rel]
aep_place.children = [place_dom_rel]

resp = session.post(f'{URL}/api/mo/uni/infra.json', aep_l3.json())
print(resp.json())
assert resp.ok

resp = session.post(f'{URL}/api/mo/uni/infra.json', aep_place.json())
print(resp.json())
assert resp.ok


# Create RDC Core interface policy group
core_pol_grp = GenericClass(apic_class='infraAccPortGrp', name=f'rt-{env.DataCenter}-Core')
aep_rel = GenericClass(apic_class='infraRsAttEntP', tDn='uni/infra/attentp-aep-L3-Ports')
cdp_rel = GenericClass(apic_class='infraRsCdpIfPol', tnCdpIfPolName='CDP-Enable')
lldp_rel = GenericClass(apic_class='infraRsLldpIfPol', tnLldpIfPolName='LLDP-Enable')

core_pol_grp.children = [aep_rel, cdp_rel, lldp_rel]

resp = session.post(f'{URL}/api/mo/uni/infra/funcprof.json', core_pol_grp.json())
print(resp.json())
assert resp.ok


# Create the RDC Core interface profile using the policy group above
core_prof = GenericClass(apic_class='infraAccPortP', descr='Routed 49--52', name=f'rt-{env.DataCenter}-Core')
core_sel = GenericClass(apic_class='infraHPortS', name='rt-49--52', type='range')
base_grp = GenericClass(apic_class='infraRsAccBaseGrp',
                        tDn=f'uni/infra/funcprof/accportgrp-{core_pol_grp.attributes.name}')
core_block = GenericClass(apic_class='infraPortBlk', name='block49', fromCard='1', toCard='1', fromPort='49',
                          toPort='52', descr=f'{env.DataCenter}-Core')

core_sel.children = [base_grp, core_block]
core_prof.children = [core_sel]

resp = session.post(f'{URL}/api/mo/uni/infra.json', core_prof.json())
print(resp.json())
assert resp.ok


# Setup Pod Policy Group
pod_pgrp = GenericClass(apic_class='fabricPodPGrp', name=env.Name, status='created,modified')
snmp_pol = GenericClass(apic_class='fabricRsSnmpPol', tnSnmpPolName='default')
bgp_rr = GenericClass(apic_class='fabricRsPodPGrpBGPRRP', tnBgpInstPolName='default')
time_pol = GenericClass(apic_class='fabricRsTimePol', tnDatetimePolName='default')

pod_pgrp.children = [snmp_pol, bgp_rr, time_pol]

resp = session.post(f'{URL}/api/mo/uni/fabric/funcprof.json', pod_pgrp.json())
print(resp.json())
assert resp.ok


# Configure Pod Profile
pod_prof = GenericClass(apic_class='fabricPodP', name='default', status='modified')
pod_sel = GenericClass(apic_class='fabricPodS', name='default', type='ALL')
pod_pgrp = GenericClass(apic_class='fabricRsPodPGrp', tDn=f'uni/fabric/funcprof/podpgrp-{env.Name}')

pod_sel.children = [pod_pgrp]
pod_prof.children = [pod_sel]

resp = session.post(f'{URL}/api/mo/uni/fabric.json', pod_prof.json())
print(resp.json())
assert resp.ok


# Configure DNS policy
dns_pol = GenericClass(apic_class='dnsProfile', name='default', status='modified', IPVerPreference='IPv4')
dns_epg = GenericClass(apic_class='dnsRsProfileToEpg', tDn='uni/tn-mgmt/mgmtp-default/oob-default')
dns_prov1 = GenericClass(apic_class='dnsProv', addr=env.PrimaryDNS, preferred='yes')
dns_prov2 = GenericClass(apic_class='dnsProv', addr=env.SecondaryDNS, preferred='no')
dns_prov3 = GenericClass(apic_class='dnsProv', addr=env.TertiaryDNS, preferred='no')

dns_pol.children = [dns_epg, dns_prov1, dns_prov2, dns_prov3]

resp = session.post(f'{URL}/api/mo/uni/fabric.json', dns_pol.json())
print(resp.json())
assert resp.ok


# Configure BGP Route Reflectors
sp1 = GenericClass(apic_class='bgpRRNodePEp', id='201', podId='1')
sp2 = GenericClass(apic_class='bgpRRNodePEp', id='202', podId='1')
bgp_rrp = GenericClass(apic_class='bgpRRP', name='')
bgp_as = GenericClass(apic_class='bgpAsP', asn=env.ASN)
bgp_rr = GenericClass(apic_class='bgpInstPol', name='default', status='modified')
bgp_rrp.children = [sp1, sp2]
bgp_rr.children = [bgp_rrp, bgp_as]

resp = session.post(f'{URL}/api/mo/uni/fabric.json', bgp_rr.json(empty_fields=True))
print(resp.json())
assert resp.ok

snmp_strings = {'rw': 'impasse', 'ro': 'notpublic'}


# Configure SNMP Client sources
snmp_pol = GenericClass(apic_class='snmpPol', name='default', status='modified', contact='HCA NOC', loc=env.Name)
snmp_comm_ro = GenericClass(apic_class='snmpCommunityP', descr='RO', name=snmp_strings['ro'])
snmp_comm_rw = GenericClass(apic_class='snmpCommunityP', descr='RW', name=snmp_strings['rw'])
snmp_client_grp = GenericClass(apic_class='snmpClientGrpP', name='snmpClients')
snmp_client_epg = GenericClass(apic_class='snmpRsEpg', tDn='uni/tn-mgmt/mgmtp-default/oob-default')

snmp_pol.children = [snmp_comm_ro, snmp_comm_rw, snmp_client_grp]
snmp_client_grp.children = [snmp_client_epg]
for name, addr in SNMP_CLIENTS:
    client = GenericClass(apic_class='snmpClientP', name=name, addr=addr)
    snmp_client_grp.children += [client]

resp = session.post(f'{URL}/api/mo/uni/fabric.json', snmp_pol.json())
print(resp.json())
assert resp.ok


# Configure SNMP Trap Destination
snmp_epg = GenericClass(apic_class='fileRsARemoteHostToEpg', tDn='uni/tn-mgmt/mgmtp-default/oob-default')
snmp_trap_dest = GenericClass(apic_class='snmpTrapDest', host=SNMP_TRAP_DEST, notifT='traps', port='162',
                              secName='notpublic', v3SecLvl='noauth', ver='v2c')
snmp_grp = GenericClass(apic_class='snmpGroup', name='SNMP_Dest', status='created,modified')

snmp_trap_dest.children = [snmp_epg]
snmp_grp.children = [snmp_trap_dest]

resp = session.post(f'{URL}/api/mo/uni/fabric.json', snmp_grp.json())
print(resp.json())
assert resp.ok


# Configure Syslog Destinations and Policies
syslog_epg = GenericClass(apic_class='fileRsARemoteHostToEpg', tDn='uni/tn-mgmt/mgmtp-default/oob-default')
syslog_remote = GenericClass(apic_class='syslogRemoteDest', adminState='enabled', host=env.SyslogDest,
                             name='HCA-Syslog', port=514, severity='information')
syslog_prof = GenericClass(apic_class='syslogProf', adminState='disabled',  # Leave Disabled until production ready
                           name='syslog')
syslog_grp = GenericClass(apic_class='syslogGroup', name='Syslog-Destination', status='created,modified', format='aci')
syslog_remote.children = [syslog_epg]
syslog_grp.children = [syslog_remote, syslog_prof]

resp = session.post(f'{URL}/api/mo/uni/fabric.json', syslog_grp.json())
print(resp.json())
assert resp.ok


# Configure monitoring Policy
mon_snmp = GenericClass(apic_class='snmpSrc', name='HCA-SNMP')
mon_sysl = GenericClass(apic_class='syslogSrc', name='Syslog-Source')
mon_snmp_grp = GenericClass(apic_class='snmpRsDestGroup', tDn='uni/fabric/snmpgroup-SNMP_Dest')
mon_sysl_grp = GenericClass(apic_class='syslogRsDestGroup', tDn='uni/fabric/slgroup-Syslog-Destination')
mon_pol = GenericClass(apic_class='monCommonPol', name='default', status='modified')

mon_snmp.children = [mon_snmp_grp]
mon_sysl.children = [mon_sysl_grp]
mon_pol.children = [mon_snmp, mon_sysl]

resp = session.post(f'{URL}/api/mo/uni/fabric.json', mon_pol.json())
print(resp.json())
assert resp.ok


# NTP Configuration
oob_epg_rel = GenericClass(apic_class='datetimeRsNtpProvToEpg', tDn='uni/tn-mgmt/mgmtp-default/oob-default')
ntp_prov1 = GenericClass(apic_class='datetimeNtpProv', name='10.90.10.100',
                         preferred=('yes' if env.PreferredNTP == '10.90.10.100' else 'no'))
ntp_prov2 = GenericClass(apic_class='datetimeNtpProv', name='10.26.10.100',
                         preferred=('yes' if env.PreferredNTP == '10.26.10.100' else 'no'))
ntp_prov3 = GenericClass(apic_class='datetimeNtpProv', name='10.154.10.100',
                         preferred=('yes' if env.PreferredNTP == '10.154.10.100' else 'no'))
ntp_prov1.children = [oob_epg_rel]
ntp_prov2.children = [oob_epg_rel]
ntp_prov3.children = [oob_epg_rel]
ntp_pol = GenericClass(apic_class='datetimePol', adminSt='enabled', masterMode='disabled', name='default', status=MOD)
ntp_pol.children = [ntp_prov1, ntp_prov2, ntp_prov3]

resp = session.post(f'{URL}/api/mo/uni/fabric.json', ntp_pol.json())
print(resp.json())
assert resp.ok


# Set Time Zone
time_zone = GenericClass(apic_class='datetimeFormat', displayFormat='local', name='default', showOffset='enabled',
                         tz='n300_America-Chicago', status='modified')

resp = session.post(f'{URL}/api/mo/uni/fabric.json', time_zone.json())
print(resp.json())
assert resp.ok


# Configure Voyence remote path
remote_epg = GenericClass(apic_class='fileRsARemoteHostToEpg', tDn='uni/tn-mgmt/mgmtp-default/oob-default')
remote_path = GenericClass(apic_class='fileRemotePath', name='Voyence', host='10.26.31.85', protocol='scp',
                           remotePath=f'/opt/Juniper_Backups/ACI_Fabric/{env.Name}', userName=os.getenv('voyenceuser'),
                           userPasswd=os.getenv('voyencepass'), remotePort='22', status='created,modified')
remote_path.children = [remote_epg]

resp = session.post(f'{URL}/api/mo/uni/fabric.json', remote_path.json())
print(resp.json())
assert resp.ok


# Setup Nightly Backup Scheduler
trig_window = GenericClass(apic_class='trigRecurrWindowP', day='every-day', hour='2', minute='0', name='Morning-2AM',
                           procBreak='none', procCap='unlimited', timeCap='unlimited', concurCap='unlimited')
trig_schedule = GenericClass(apic_class='trigSchedP', name='Nightly-Backup')
trig_schedule.children = [trig_window]

resp = session.post(f'{URL}/api/mo/uni/fabric.json', trig_schedule.json())
print(resp.json())
assert resp.ok


# Configure Nightly Config Export
rp = GenericClass(apic_class='configRsRemotePath', tnFileRemotePathName=remote_path.attributes.name)
sched = GenericClass(apic_class='configRsExportScheduler', tnTrigSchedPName=trig_schedule.attributes.name)
config_export_prof = GenericClass(apic_class='configExportP', format='json', includeSecureFields='yes',
                                  maxSnapshotCount='global-limit', name='Nightly-Offsite-Config-Export', snapshot='no',
                                  status='created,modified')

resp = session.post(f'{URL}/api/mo/uni/fabric.json', config_export_prof.json())
print(resp.json())
assert resp.ok


# TACACS configuration appends to uni/  # Not setting to be default auth as part of this  # Enable manually
prov_epg = GenericClass(apic_class='aaaRsSecProvToEpg', tDn='uni/tn-mgmt/mgmtp-default/oob-default')
prov1 = GenericClass(apic_class='aaaTacacsPlusProvider', name='10.27.21.99', key='fYiqjiaw', status=CR)
prov2 = GenericClass(apic_class='aaaTacacsPlusProvider', name='10.90.42.49', key='fYiqjiaw', status=CR)
prov_grp = GenericClass(apic_class='aaaTacacsPlusProviderGroup', name='TACACS-Group', status=CR)
prov1_att = GenericClass(apic_class='aaaProviderRef', name=prov1.attributes.name, order='1')
prov2_att = GenericClass(apic_class='aaaProviderRef', name=prov2.attributes.name, order='2')
tacacs_ep = GenericClass(apic_class='aaaTacacsPlusEp', dn='uni/userext/tacacsext', status=MOD)
tacacs = GenericClass(apic_class='aaaUserEp', dn='uni/userext', status=MOD)
prov1.children = [prov_epg]
prov2.children = [prov_epg]
prov_grp.children = [prov1_att, prov2_att]
tacacs_ep.children = [prov1, prov2, prov_grp]
tacacs.children = [tacacs_ep]

resp = session.post(f'{URL}/api/mo/uni.json', tacacs.json())
print(resp.json())
assert resp.ok


# Create Out-of-Band contract
oob_contract = GenericClass(apic_class='vzOOBBrCP', name='c-oob-default', scope='context')
oob_subj = GenericClass(apic_class='vzSubj', name='s-oob-default')
oob_filter = GenericClass(apic_class='vzRsSubjFiltAtt', tnVzFilterName='default')

oob_subj.children = [oob_filter]
oob_contract.children = [oob_subj]

resp = session.post(f'{URL}/api/mo/uni/tn-mgmt.json', oob_contract.json())
print(resp.json())
assert resp.ok


# Apply OOB Contract to OOB EPG
oob_epg = GenericClass(apic_class='mgmtOoB', name='default')
oob_epg_prov = GenericClass(apic_class='mgmtRsOoBProv', tnVzOOBBrCPName='c-oob-default')

oob_epg.children = [oob_epg_prov]

resp = session.post(f'{URL}/api/mo/uni/tn-mgmt/mgmtp-default.json', oob_epg.json())
print(resp.json())
assert resp.ok


# Apply Contract to OOB External EPG and define OOB subnets as quad-0
oob_ext_epg = GenericClass(apic_class='mgmtExtMgmtEntity', name='default')
mgmt_inst_p = GenericClass(apic_class='mgmtInstP', name='oob-mgmt-ext')
oob_ext_cons = GenericClass(apic_class='mgmtRsOoBCons', tnVzOOBBrCPName='c-oob-default')
oob_subnet = GenericClass(apic_class='mgmtSubnet', ip='0.0.0.0/0')

mgmt_inst_p.children = [oob_ext_cons, oob_subnet]
oob_ext_epg.children = [mgmt_inst_p]

resp = session.post(f'{URL}/api/mo/uni/tn-mgmt.json', oob_ext_epg.json())
print(resp.json())
assert resp.ok


# Generate management addresses for apics, leafs, and spines; required for syslog and SNMP
net = network(env.OOBLeafIPRange)
base_address = address(net.network_address)

for node, num in zip(['1', '2', '3', '101', '102', '201', '202'], [11, 12, 13, 6, 7, 4, 5]):
    node_config = GenericClass(apic_class='mgmtRsOoBStNode', addr=f'{base_address + num}/{net.prefixlen}',
                               dn=f'uni/tn-mgmt/mgmtp-default/oob-default/rsooBStNode-[topology/pod-1/node-{node}]',
                               gw=f'{base_address + 1}')

    resp = session.post(f'{URL}/api/mo/uni.json', node_config.json())
    print(resp.json())
    assert resp.ok


# Create tenants
hca = Tenant(name=env.Tenant)
hcadr = Tenant(name='tn-HCADR')
admz = Tenant(name=env.ADMZTenant)

resp = session.post(f'{URL}/api/mo/uni.json', hca.json())
print(resp.json())
assert resp.ok

resp = session.post(f'{URL}/api/mo/uni.json', hcadr.json())
print(resp.json())
assert resp.ok

resp = session.post(f'{URL}/api/mo/uni.json', admz.json())
print(resp.json())
assert resp.ok


# Create universal filter
f_any = GenericClass(apic_class='vzFilter', name='f-any', status=CR)
f_entry = GenericClass(apic_class='vzEntry', name='any', stateful='no')
f_any.children = [f_entry]

resp = session.post(f'{URL}/api/mo/uni/tn-{env.Tenant}.json', f_any.json())
print(resp.json())
assert resp.ok

resp = session.post(f'{URL}/api/mo/uni/tn-HCADR.json', f_any.json())
print(resp.json())
assert resp.ok


# Create universal contract
c_any = GenericClass(apic_class='vzBrCP', name='c-Any', prio='unspecified', scope='context', targetDscp='unspecified')
c_subj = GenericClass(apic_class='vzSubj', name='s-Any', revFltPorts='yes', consMatchT='AtleastOne',
                      provMatchT='AtleastOne')
filter_rel = GenericClass(apic_class='vzRsSubjFiltAtt', action='permit', tnVzFilterName='f-any')

c_subj.children = [filter_rel]
c_any.children = [c_subj]

resp = session.post(f'{URL}/api/mo/uni/tn-{env.Tenant}.json', c_any.json())
print(resp.json())
assert resp.ok

resp = session.post(f'{URL}/api/mo/uni/tn-tn-HCADR.json', c_any.json())
print(resp.json())
assert resp.ok


# Universal VzAny
vz_prov = GenericClass(apic_class='vzBrCP', tnVzBrCPName='c-Any')
vz_cons = GenericClass(apic_class='vzSubj', tnVzBrCPName='c-Any')
vz_any = GenericClass(apic_class='vzAny', matchT='AtleastOne', prefGrMemb='disabled')

vz_any.children = [vz_prov, vz_cons]


# Create VRFs for tn-HCA, tn-HCADR, tn-ADMZ
vrf_hca = Context(name=env.VRF, annotation='primary_vrf:True')
vrf_hcadr = Context(name='vrf-hcadr', annotation='primary_vrf:True')
vrf_admz = Context(name=env.ADMZVRF, annotation='primary_vrf:True')
vrf_not_routed = Context(name='vrf-Not-Routed')

vrf_hca.children = [vz_any]
vrf_hcadr.children = [vz_any]

resp = session.post(f'{URL}/api/mo/uni/tn-{env.Tenant}.json', vrf_hca.json())
print(resp.json())
assert resp.ok

resp = session.post(f'{URL}/api/mo/uni/tn-{env.Tenant}.json', vrf_not_routed.json())
print(resp.json())
assert resp.ok

resp = session.post(f'{URL}/api/mo/uni/tn-tn-HCADR.json', vrf_hcadr.json())
print(resp.json())
assert resp.ok

resp = session.post(f'{URL}/api/mo/uni/tn-{env.ADMZTenant}.json', vrf_admz.json())
print(resp.json())
assert resp.ok


# Create OSPF Interface policies
ospf_if_pol = GenericClass(apic_class='ospfIfPol', name='OSPF-Core', nwT='p2p')
ospf_pif_pol = GenericClass(apic_class='ospfIfPol', name='OSPF-Passive', ctrl='passive', nwT='bcast')

resp = session.post(f'{URL}/api/mo/uni/tn-common.json', ospf_if_pol.json())
print(resp.json())
assert resp.ok

resp = session.post(f'{URL}/api/mo/uni/tn-common.json', ospf_pif_pol.json())
print(resp.json())
assert resp.ok


ospf_area = network(env.IPSupernet)
location_1 = env.BLF101Location
location_2 = env.BLF102Location


# Create any switch profiles that can logically be determined
nodes = session.get(f'{URL}/api/class/fabricNode.json').json()['imdata']
nodes = [FabricNode.load(n) for n in nodes]
blf_nodes = [n for n in nodes if n.attributes.id in ['101', '102']]
data_leaf_nodes = [n for n in nodes if 102 < int(n.attributes.id) < 200]
oob_leaf_nodes = [n for n in nodes if 300 < int(n.attributes.id) < 400]

blf_nodes.sort(key=lambda _: int(_.attributes.id))
data_leaf_nodes.sort(key=lambda _: int(_.attributes.id))
oob_leaf_nodes.sort(key=lambda _: int(_.attributes.id))


# Create OOB Leaf Profile
oob_profile = SwitchProfile()
oob_profile.attributes.name = OOBPROFILENAME
oob_profile.create_switch_profile(name=OOBPROFILENAME, nodes=[int(_.attributes.id) for _ in oob_leaf_nodes])

session.post(f'{URL}/api/mo/uni/infra.json', oob_profile.json())

# Create Border Leaf Profile
rack = set([re.search(r'[A-Z]\d\d', n.attributes.name).group() for n in blf_nodes])

blf_sw_profile = SwitchProfile()
blf_sw_profile.create_switch_profile(name=f'{env.Name}-{"-".join(rack)}-BLF-101-102', nodes=[101, 102])

print(json.dumps(blf_sw_profile.json()))
resp = session.post(f'{URL}/api/mo/uni/infra.json', blf_sw_profile.json())
print(resp.json())

# Create VPC for border leafs
vpc_profile = FabricProtPol()
vpc_profile.add_new_vpc_pair([101, 102])
session.post(f'{URL}{vpc_profile.post_uri}', vpc_profile.json())

# Create Data Leaf Profiles
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

        session.post(f'{URL}{leaf_profile.post_uri}', leaf_profile.json())

        vpc_profile = FabricProtPol()
        vpc_profile.add_new_vpc_pair([leaf_1.attributes.id, leaf_2.attributes.id])

        session.post(f'{URL}{vpc_profile.post_uri}', vpc_profile.json())

# Create Interface Profiles and Policy Groups for OOB Management

aep = AEP()
aep.attributes.name = 'aep-OOB-Management'
aep.attributes.__delattr__('dn')
aep.infra_generic = InfraGeneric()
aep.create_modify()
aep.use_domain(env.PhysicalDomain)
response = session.post(f'{URL}{aep.post_uri}', json=aep.json())
assert response.ok

oob_pg = InterfacePolicyGroup()
oob_pg.create()
oob_pg.attributes.name = 'acc-OOB-Management'
oob_pg.use_aep(aep_name='aep-OOB-Management')
response = session.post(f'{URL}{oob_pg.post_uri}', json=oob_pg.json())
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
oob_prof.attributes.name = OOBPROFILENAME
oob_prof.children = [oob_selector]
response = session.post(f'{URL}{oob_prof.post_uri}', json=oob_prof.json())
assert response.ok

attach_i_profile = GenericClass('infraRsAccPortP')
attach_i_profile.attributes.dn = f'uni/infra/nprof-{oob_profile.attributes.name}/' \
                                 f'rsaccPortP-[uni/infra/accportprof-{oob_prof.attributes.name}]'
attach_i_profile.create()
response = session.post(f'{URL}/api/mo/uni.json', json=attach_i_profile.json())
assert response.ok
print(response.json())
