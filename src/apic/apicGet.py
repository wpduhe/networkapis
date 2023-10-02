import json
import requests
import random
import os
from data.environments import ACIEnvironment

# One Change
#
#  def startSession(env):
#     import requests
#     from creds.creds import aciCreds
#     from networkapis.GetAvailabilityZones import GetAvailabilityZones
#
#     if not isinstance(env, dict):
#         env = GetAvailabilityZones(env)
#
#     session = requests.session()
#     session.verify = False
#
#     url = 'https://{}'.format(env['IPAddress'])
#
#     session.post(f'{url}/api/aaaLogin.json', data=aciCreds())
#     return session


# def collectBDs(env, tn='tn-HCA', bd=''):
#     if env.__class__ is not dict:
#         env = get_azs(env)
#
#     # Target environments.py variables
#     url = 'https://' + env['IPAddress']
#     login_url = f'{url}/api/aaaLogin.json'
#
#     # Get Bridge Domains from Target Environment
#     session = requests.session()
#     session.verify = False
#
#     session.post(login_url, data=creds.aciCreds())
#
#     resp = session.get(f'{url}/api/mo/uni/tn-{tn}.json?query-target=subtree&target-subtree-class='
#                        'fvBD&rsp-subtree=full&rsp-prop-include=config-only')
#     session.close()
#
#     resp = json.loads(resp.text)
#     bds = json.loads(json.dumps(resp['imdata']))
#
#     if bd is not '':
#         try:
#             bd = next(x for x in bds if x['fvBD']['attributes']['name'] == bd)
#         except StopIteration:
#             return 'Bridge Domain does not exist'
#         return bd
#
#     return bds


# def collectVRFs(env, tn='tn-HCA', vrf=''):
#     if env.__class__ is not dict:
#         env = get_azs(env)
#
#     # Target environments.py variables
#     url = 'https://' + env['IPAddress']
#     login_url = url + '/api/aaaLogin.json'
#
#     # Get VRFs from Target Environment
#     session = requests.session()
#     session.verify = False
#
#     session.post(login_url, data=creds.aciCreds())
#
#     resp = session.get(url + '/api/mo/uni/tn-' + tn + '.json?query-target=subtree&target-subtree-class=fvCtx&rsp-prop-include=config-only')
#     session.close()
#
#     resp = json.loads(resp.text)
#     vrfs = json.loads(json.dumps(resp['imdata']))
#
#     if vrf is not '':
#         try:
#             vrf = next(x for x in vrfs if x['fvCtx']['attributes']['name'] == vrf)
#         except StopIteration:
#             return 'VRF does not exist'
#         return vrf
#
#     return vrfs


# def collectAPs(env, tn='tn-HCA', ap=''):
#     if env.__class__ is not dict:
#         env = get_azs(env)
#
#     # Target environments.py variables
#     url = 'https://' + env['IPAddress']
#     login_url = url + '/api/aaaLogin.json'
#
#     # Get application profiles from Target Environment
#     session = requests.session()
#     session.verify = False
#
#     session.post(login_url, data=creds.aciCreds())
#
#     resp = session.get(f'{url}/api/mo/uni/tn-{tn}.json?query-target=subtree&target-subtree-class='
#                        'fvAp&rsp-prop-include=config-only&rsp-subtree=full')
#
#     session.close()
#
#     resp = json.loads(resp.text)
#     aps = json.loads(json.dumps(resp['imdata']))
#
#     if ap is not '':
#         try:
#             ap = next(x for x in aps if x['fvAp']['attributes']['name'] == ap)
#         except StopIteration:
#             return 'Application Profile does not exist'
#         return ap
#
#     return aps


# def collectTags(env, tag):
#     if env.__class__ is not dict:
#         env = get_azs(env)
#
#     # Target environments.py variables
#     url = 'https://' + env['IPAddress']
#     login_url = url + '/api/aaaLogin.json'
#
#     # Get Requested Tags from Target Environment
#     session = requests.session()
#     session.verify = False
#
#     session.post(login_url, data=creds.aciCreds())
#
#     resp = session.get(f'{url}/api/class/tagInst.json?query-target-filter=eq(tagInst.name,"{tag}")')
#     session.close()
#
#     resp = json.loads(resp.text)
#     tags = json.loads(json.dumps(resp['imdata']))
#
#     return tags


# def collectSubnets(env, ip=''):
#     if env.__class__ is not dict:
#         env = get_azs(env)
#
#     # Target environments.py variables
#     url = 'https://' + env['IPAddress']
#     login_url = url + '/api/aaaLogin.json'
#
#     # Get Subnets from Target Environment
#     session = requests.session()
#     session.verify = False
#
#     session.post(login_url, data=creds.aciCreds())
#
#     bd_subnets = session.get(url + '/api/class/fvSubnet.json?rsp-subtree=full&rsp-prop-include=config-only')
#     ext_subnets = session.get(f'{url}/api/class/l3extSubnet.json?rsp-prop-include=config-only&query-target-filter='
#                               'ne(l3extSubnet.ip,"0.0.0.0/0")')
#     session.close()
#
#     bd_subnets = json.loads(bd_subnets.text)
#     bd_subnets = json.loads(json.dumps(bd_subnets['imdata']))
#     ext_subnets = json.loads(ext_subnets.text)
#     ext_subnets = json.loads(json.dumps(ext_subnets['imdata']))
#     for subnet in ext_subnets:
#         if subnet['l3extSubnet']['attributes']['scope'].find('import-security') < 0:
#             ext_subnets.remove(subnet)
#
#     if ip is not '':
#         ip = ipaddress.IPv4Address(ip)
#         networks = []
#         for subnet in bd_subnets:
#             networks.append(ipaddress.IPv4Network(subnet['fvSubnet']['attributes']['ip'], strict=False))
#         for subnet in ext_subnets:
#             if subnet['l3extSubnet']['attributes']['scope'].find('import-security') > -1:
#                 networks.append(ipaddress.IPv4Network(subnet['l3extSubnet']['attributes']['ip'], strict=False))
#         for network in networks:
#             if ip in network.hosts():
#                 gateway = str(ipaddress.IPv4Address(int(network.network_address)+1)) + '/' + str(network.prefixlen)
#                 try:
#                     return next(x for x in bd_subnets if x['fvSubnet']['attributes']['ip'] == gateway)
#                 except StopIteration:
#                     pass
#                 try:
#                     return next(x for x in ext_subnets if x['l3extSubnet']['attributes']['ip'] == network.with_prefixlen)
#                 except StopIteration:
#                     pass
#         return 'IP is not a member of any subnet within any ACI fabric'
#
#     subnets = []
#     for subnet in bd_subnets:
#         subnets.append(subnet)
#     for subnet in ext_subnets:
#         if subnet['l3extSubnet']['attributes']['scope'].find('import-security') > -1:
#             subnets.append(subnet)
#
#     return subnets


# def collectEPGs(env, epg=''):
#     if env.__class__ is not dict:
#         env = get_azs(env)
#
#     # Target environments.py variables
#     url = 'https://' + env['IPAddress']
#     login_url = url + '/api/aaaLogin.json'
#
#     # Get AEPs from Target Environment
#     session = requests.session()
#     session.verify = False
#
#     session.post(login_url, data=creds.aciCreds())
#
#     resp = session.get(f'{url}/api/class/fvAEPg.json?rsp-subtree=full&rsp-prop-include=config-only')
#     session.close()
#
#     resp = json.loads(resp.text)
#     epgs = json.loads(json.dumps(resp['imdata']))
#
#     if epg is not '':
#         try:
#             epg = next(x for x in epgs if x['fvAEPg']['attributes']['name'] == epg)
#         except StopIteration:
#             return 'EPG does not exist'
#         return epg
#
#     return epgs


# def collectAEPs(env, aep=''):
#     if env.__class__ is not dict:
#         env = get_azs(env)
#
#     # Target environments.py variables
#     url = 'https://' + env['IPAddress']
#     login_url = url + '/api/aaaLogin.json'
#
#     # Get AEPs from Target Environment
#     session = requests.session()
#     session.verify = False
#
#     session.post(login_url, data=creds.aciCreds())
#
#     resp = session.get(f'{url}/api/class/infraAttEntityP.json?rsp-subtree=full&rsp-prop-include=config-only')
#     session.close()
#
#     resp = json.loads(resp.text)
#     aeps = json.loads(json.dumps(resp['imdata']))
#
#     if aep is not '':
#         try:
#             aep = next(x for x in aeps if x['infraAttEntityP']['attributes']['name'] == aep)
#         except StopIteration:
#             return 'VRF does not exist'
#         return aep
#
#     return aeps


# def collectEncap(env):
#     if env.__class__ is not dict:
#         env = get_azs(env)
#
#     # Target environments.py variables
#     url = 'https://' + env['IPAddress']
#     login_url = url + '/api/aaaLogin.json'
#
#     session = requests.session()
#     session.verify = False
#
#     session.post(login_url, data=creds.aciCreds())
#     resp = session.get(url + '/api/class/fvIfConn.json')
#     session.close()
#
#     resp = json.loads(resp.text)
#     resp = json.loads(json.dumps(resp['imdata']))
#
#     # Strip dn to EPG
#     for x in resp:
#         x['fvIfConn']['attributes']['dn'] = x['fvIfConn']['attributes']['dn'][
#             x['fvIfConn']['attributes']['dn'].index('-[')+2 : x['fvIfConn']['attributes']['dn'].index(']/node')]
#
#     # Create dictionary using EPGs as keys
#     data = {x['fvIfConn']['attributes']['dn']: [] for x in resp}
#
#     # Append encapsulations found to be associated with each EPG
#     for key in data:
#         for ep in resp:
#             if ep['fvIfConn']['attributes']['dn'] == key:
#                 if ep['fvIfConn']['attributes']['encap'] not in data[key]:
#                     data[key].append(ep['fvIfConn']['attributes']['encap'])
#
#     return data


# def collectStaticPaths(env, search=''):
#     if env.__class__ is not dict:
#         env = get_azs(env)
#
#     # Target environments.py variables
#     url = 'https://' + env['IPAddress']
#     login_url = url + '/api/aaaLogin.json'
#
#     session = requests.session()
#     session.verify = False
#
#     session.post(login_url, data=creds.aciCreds())
#     if search is '':
#         resp = session.get(url + '/api/class/fvRsPathAtt.json')
#         resp = json.loads(resp.text)
#         resp = json.loads(json.dumps(resp['imdata']))
#         session.close()
#         return resp
#     else:
#         resp = session.get(url + '/api/class/fvRsPathAtt.json?query-target-filter=wcard(fvRsPathAtt.tDn,"' +
#                            search + '")&rsp-prop-include=config-only')
#         resp = json.loads(resp.text)
#         resp = json.loads(json.dumps(resp['imdata']))
#         session.close()
#         return resp


# def collectTDn(env, **kwargs):
#     if env.__class__ is not dict:
#         env = get_azs(env)
#
#     url = 'https://' + env['IPAddress']
#     login_url = url + '/api/aaaLogin.json'
#
#     session = requests.session()
#     session.verify = False
#
#     session.post(login_url, data=creds.aciCreds())
#
#     if len(kwargs) == 1:
#         for arg in kwargs:
#             resp = session.get(url + '/api/class/' + arg + '.json?query-target-filter=wcard(' +
#                                arg + '.tDn,"' + kwargs[arg] + '")&rsp-prop-include=config-only')
#             session.close()
#             resp = json.loads(resp.text)
#             resp = json.loads(json.dumps(resp['imdata']))
#             if len(resp) > 0:
#                 return resp
#             else:
#                 return 'The requested object does not exist.  Check class name and attribute name and try again.'
#     else:
#         return 'This module only accepts one keyword argument'


# def collectInv(env):
#     if env.__class__ is not dict:
#         env = get_azs(env)
#
#     # Target environments.py variables
#     url = 'https://' + env['IPAddress']
#     login_url = url + '/api/aaaLogin.json'
#
#     # Get Requested Tags from Target Environment
#     session = requests.session()
#     session.verify = False
#
#     session.post(login_url, data=creds.aciCreds())
#     resp = session.get(url + '/api/class/topSystem.json')
#     session.close()
#
#     resp = json.loads(resp.text)
#     resp = json.loads(json.dumps(resp['imdata']))
#
#     for inv in resp:
#         for attribute in [
#                 'bootstrapState'
#                 'childAction'
#                 'configIssues'
#                 'currentTime'
#                 'etepAddr'
#                 'fabricMAC'
#                 'id'
#                 'inbMgmtAddr'
#                 'inbMgmtAddr6'
#                 'inbMgmtAddr6Mask'
#                 'inbMgmtAddrMask'
#                 'inbMgmtGateway'
#                 'inbMgmtGateway6'
#                 'lcOwn'
#                 'modTs'
#                 'mode'
#                 'monPolDn'
#                 'nameAlias'
#                 'nodeType'
#                 'oobMgmtAddr6'
#                 'oobMgmtAddr6Mask'
#                 'oobMgmtGateway6'
#                 'remoteNetworkId'
#                 'remoteNode'
#                 'siteId'
#                 'state'
#                 'status'
#                 'tepPool'
#                 'unicastXrEpLearnDisable']:
#             try:
#                 del inv['topSystem']['attributes'][attribute]
#             except KeyError:
#                 pass
#
#     return resp


# def collectName(env, **kwargs):
#     if env.__class__ is not dict:
#         env = get_azs(env)
#
#     url = 'https://' + env['IPAddress']
#     login_url = url + '/api/aaaLogin.json'
#
#     session = requests.session()
#     session.verify = False
#
#     session.post(login_url, data=creds.aciCreds())
#
#     if len(kwargs) == 1:
#         for arg in kwargs:
#             resp = session.get(url + '/api/class/' + arg + '.json?query-target-filter=eq(' +
#                                arg + '.name,"' + kwargs[arg] + '")')
#             session.close()
#             resp = json.loads(resp.text)
#             resp = json.loads(json.dumps(resp['imdata']))
#             if len(resp) > 0:
#                 return resp
#             else:
#                 return 'The requested object does not exist.  Check class name and attribute name and try again.'
#     else:
#         session.close()
#         return 'This module only accepts one keyword argument'


# def collectEndpoints(env, epg=''):
#     if not isinstance(env, dict):
#         env = get_azs(env)
#
#     url = 'https://{}'.format(env['IPAddress'])
#     login_url = f'{url}/api/aaaLogin.json'
#
#     session = requests.session()
#     session.verify = False
#
#     session.post(login_url, data=creds.aciCreds())
#
#     if epg == '':
#         data = session.get(f'{url}/api/class/fvCEp.json')
#         session.close()
#         data = json.loads(data.text)
#         data = json.loads(json.dumps(data['imdata']))
#         return data
#     else:
#         data = session.get(f'{url}/api/class/fvCEp.json?query-target-filter=wcard(fvCEp.dn,"{epg}")')
#         session.close()
#         data = json.loads(data.text)
#         data = json.loads(json.dumps(data['imdata']))
#         return data


# def classDnSearch(env, obj_class='', dn_filter='', config_only=True):
#     if not isinstance(env, dict):
#         env = get_azs(env)
#
#     url = 'https://{}'.format(env['IPAddress'])
#     login_url = f'{url}/api/aaaLogin.json'
#
#     session = requests.session()
#     session.verify = False
#
#     session.post(login_url, data=creds.aciCreds())
#
#     if config_only is True:
#         data = session.get(f'{url}/api/class/{obj_class}.json?query-target-filter=wcard({obj_class}.dn,"{dn_filter}")&'
#                            f'rsp-prop-include=config-only')
#         session.close()
#         data = json.loads(data.text)
#         data = json.loads(json.dumps(data['imdata']))
#         return data
#     else:
#         data = session.get(f'{url}/api/class/{obj_class}.json?query-target-filter=wcard({obj_class}.dn,"{dn_filter}")')
#         session.close()
#         data = json.loads(data.text)
#         data = json.loads(json.dumps(data['imdata']))
#         return data


def exists(env, **kwargs):
    if env.__class__ is dict:
        env = ACIEnvironment(env['Name'])
    elif env.__class__ is not ACIEnvironment:
        env = ACIEnvironment(env)

    url = f'https://{env.IPAddress}'
    login_url = url + '/api/aaaLogin.json'

    session = requests.session()
    session.verify = False

    if len(kwargs) == 1:
        for arg in kwargs:
            creds = {
                "aaaUser": {
                    "attributes": {
                        "name": os.getenv('netmgmtuser'),
                        "pwd": os.getenv('netmgmtpass')
                    }
                }
            }
            session.post(login_url, json=creds)
            resp = session.get(url + '/api/class/' + arg + '.json?query-target-filter=eq('+
                               arg + '.name,"' + kwargs[arg] + '")')
            session.close()
            resp = json.loads(resp.text)
            if int(resp['totalCount']) == 1:
                return True
            else:
                return False
    else:
        return 'This module only accepts one keyword argument'


def snapshot(env, descr):
    if env.__class__ is not dict:
        env = ACIEnvironment(env)

    url = f'https://{env.IPAddress}'
    login_url = url + '/api/aaaLogin.json'

    session = requests.session()
    session.verify = False
    creds = {
        "aaaUser": {
            "attributes": {
                "name": os.getenv('netmgmtuser'),
                "pwd": os.getenv('netmgmtpass')
            }
        }
    }
    session.post(login_url, json=creds)

    descr = descr.replace(' ', '-')
    descr = descr + '-' + str(random.randint(100000, 999999))

    snap = {
        'configExportP': {
            'attributes': {
                'dn': 'uni/fabric/configexp-defaultOneTime',
                'name': 'defaultOneTime',
                'snapshot': 'true',
                'targetDn': '',
                'adminSt': 'triggered',
                'rn': 'configexp-defaultOneTime',
                'status': 'created,modified',
                'descr': descr
            }
        }
    }

    session.post(url + '/api/mo/uni.json', data=json.dumps(snap))
    resp = session.get(url + '/api/class/configExportP?query-target-filter=eq(configExportP.descr,"' + descr + '")')
    session.close()
    resp = json.loads(resp.text)
    if resp['totalCount'] == '1':
        # req_logit('Automated Snapshot: ' + env['Name'] + ' - ' + descr)
        return descr
    else:
        return False


def postToApic(env, post, uri='/api/mo/uni.json'):
    if env.__class__ is not dict:
        env = ACIEnvironment(env)

    url = f'https://{env.IPAddress}'
    login_url = url + '/api/aaaLogin.json'

    session = requests.session()
    session.verify = False
    creds = {
        "aaaUser": {
            "attributes": {
                "name": os.getenv('netmgmtuser'),
                "pwd": os.getenv('netmgmtpass')
            }
        }
    }
    session.post(login_url, json=creds)

    resp = session.post(url + uri, json=post)
    session.close()

    if resp.ok is True:
        return resp
    else:
        return False
