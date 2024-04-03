from fastapi import FastAPI, Response, Request, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic, HTTPBasicCredentials, APIKeyHeader
from schemas import *
from task_handler import TaskHandler, Task
from concurrent.futures import ThreadPoolExecutor
from iosxr.utils import IOSXR
from iosxe.utils import IOSXE
from nexus.utils import NXOS, mac_lookup as n_mac_lookup
from data.environments import ACIEnvironment, NexusEnvironment, DataCenter
from ipam.utils import BIG, valid_ip
from job_handler import run_job_handler
from checkpoint.CheckpointUtilities import CheckpointAPI, generate_policy_list
from ipaddress import IPv4Address, IPv4Network, AddressValueError
from apic import utils as apic_utils
from apic.classes import EPG, AEP, InfraGeneric
from apic import sviToBd
from apic.intfConfig import intf_profile
from bigip.utils import LTM
from githubapi.utils import GithubAPI
from ncm.utils import NCMIntegration
from wsa.pac_gen_v2 import pac_gen
from wsa import wsaBuild
from datetime import datetime
import json
import time
import os
import re
import socket
import sys
import asyncio
import logging
import functools
import netmiko
import requests
import yaml


# Set Timezone for OpenShift environment
os.environ['TZ'] = 'America/Chicago'
time.tzset()

# Constants
UPDATE_SPREADSHEET_KEY = 'updatespreadsheetkey'
FABRIC_INVENTORY_STATUS = 'fabricinventorystatus'

# config logging with GMT time stamps and a stream handler.
logging.Formatter.converter = time.gmtime
formatter = logging.Formatter(fmt='%(asctime)s.%(msecs)03dZ - %(name)s - %(levelname)s - %(message)s',
                              datefmt='%Y-%m-%dT%H:%M:%S')
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
ch.setFormatter(formatter)
logging.basicConfig(level=logging.DEBUG, handlers=[ch])  # ensures root logger is set to DEBUG
LOGGER = logging.getLogger(__name__)
# Suppress annoying logging from libraries below
logging.getLogger('urllib3.connectionpool').setLevel(logging.WARNING)
logging.getLogger('flask_cors.core').setLevel(logging.WARNING)
logging.getLogger('flask_cors.extension').setLevel(logging.WARNING)
logging.getLogger('paramiko.transport').level = logging.WARNING
logging.getLogger('netmiko').level = logging.WARNING
logging.getLogger('icontrol').level = logging.WARNING
logging.getLogger('flask_cors').level = logging.DEBUG
logging.getLogger('botocore').level = logging.WARNING
logging.getLogger('boto3').level = logging.WARNING
logging.getLogger('github').level = logging.WARNING
logging.getLogger('zeep').level = logging.WARNING
LOGGER.debug('Logging initialized.')


def req_logit(func, web_request, req_data=None):
    try:
        client = web_request.headers['X-Forwarded-For']
    except KeyError:
        client = web_request.client.host

    t = datetime.now()

    f = f'{t.ctime()}:  {web_request.method} {web_request.url.path} : {func.__name__} : Received by ' \
        f'{socket.gethostname()} from {client}: {json.dumps(req_data)}'

    LOGGER.debug(f)


def res_logit(func, web_request, res_data=None):
    try:
        client = web_request.headers['X-Forwarded-For']
    except KeyError:
        client = web_request.client.host

    t = datetime.now()

    f = f'{t.ctime()}:  Returned from {socket.gethostname()} : {func.__name__} : to {client}: {json.dumps(res_data)}'

    LOGGER.debug(f)


def validate_api_key(key):
    if key == os.getenv('localapikey'):
        return True
    else:
        return False


def validate_api_key_onbase(key):
    if key in [os.getenv('localapikey'), 'onBase_founDation_uPgade']:
        return True
    else:
        return False


tags_metadata = [
    {
        'name': 'ACI',
        'description': 'Operations for ACI fabrics'
    }, {
        'name': 'AppInstance',
        'description': 'Application Instance Repository'
    }, {
        'name': 'Aruba',
        'description': 'Operations for Aruba'
    }, {
        'name': 'Checkpoint',
        'description': 'Operations for Checkpoint firewalls'
    }, {
        'name': 'F5',
        'description': 'Operations for F5'
    }, {
        'name': 'IPAM',
        'description': 'Operations that interface with Proteus and BIG'
    }, {
        'name': 'ISE',
        'description': 'Operations for ISE'
    }, {
        'name': 'Nexus',
        'description': 'Operations that interface with Cisco Nexus network equipment'
    }, {
        'name': 'PAC',
        'description': 'Operations for PAC file'
    }, {
        'name': 'WLC',
        'description': 'Operations for WLC'
    }, {
        'name': 'WSA',
        'description': 'Operations for WSA appliances'
    }, {
        'name': 'PyAPIs',
        'description': 'Operations for PyAPIs'
    }, {
        'name': 'IOS-XR',
        'description': 'Helpful IOS-XR Utilities'
    }
]

tags_metadata.sort(key=lambda x: x['name'])

# Instantiate Application
app = FastAPI(openapi_tags=tags_metadata, title='PyAPIs Network Services API',
              swagger_ui_parameters={'docExpansion': 'none'})

# Enable CORS
origins = [
    "*",
    "http://localhost",
    "http://localhost:8080",
    "https://localhost",
    "https://localhost:8080",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# Enable Basic HTTP security
http_basic_security = HTTPBasic()
# Enable Header-Based Security for Apigee
evolve_key_security = APIKeyHeader(name='Evolve_Key')
ne_key_security = APIKeyHeader(name='NE_Key')

# Create task handler thread pool for background tasks
task_handler = TaskHandler(name='pyapis')

# Start the Job Handler if instance is the production Openshift instance
if socket.gethostname().startswith('pyapis-prd'):
    executor = ThreadPoolExecutor(max_workers=2)
    executor.submit(run_job_handler)


def challenge_request(func):
    @functools.wraps(func)
    def decorate(**kwargs):
        print('Processing Decorator')
        request = kwargs['request']
        ne_key = request.headers.get('NE_Key')
        evolve_key = request.headers.get('Evolve_Key')

        if evolve_key:
            print('Evolve Key Provided')
            if evolve_key == os.getenv('evolvekey'):
                return func(**kwargs)
            else:
                print('Evolve Key did not pass')
        elif ne_key:
            print('NE Key Provided')
            if ne_key == os.getenv('nekey'):
                return func(**kwargs)
            else:
                print('NE Key did not pass')

        print('No Keys')
        raise HTTPException(status_code=403)

    return decorate


@app.get('/', tags=['PyAPIs'], include_in_schema=False)
def root():
    return Response(status_code=302, headers={'Location': '/docs'})


@app.get('/apis/get_tasks', tags=['PyAPIs'])
def get_tasks(request: Request):
    """Return the Task collection of completed and running tasks"""
    req_logit(get_tasks, request)

    task_handler.clean_up()

    tasks = list(({'ID': task.ident, 'Function': task.func.__name__,
                   'TaskStatus': task.future.__getattribute__('_state'),
                   'TaskURI': task.fetch_uri, 'CreationTime': task.creation_time.isoformat()}
                  for task in task_handler.task_collection))
    response = {'TaskCollection': tasks}
    return response


@app.get('/apis/get_task_status/{ident}', tags=['PyAPIs'])
def get_task_status(request: Request, ident: str):
    """Retrieve the status of a task ID"""
    req_logit(get_task_status, request)

    task_handler.clean_up()

    task = task_handler.get_task(ident=ident)

    headers = {'Location': request.url.path}

    if isinstance(task, tuple):
        status, response = task
        return Response(status_code=status, content=json.dumps(response), media_type='application/json')

    elif isinstance(task, Task) and task.future.done():
        status, response = task.future.result()

        res_logit(task.func, request, response)

        headers = {'Location': f'/apis/completed_task/{str(ident)}'}

        return Response(status_code=303, content=json.dumps({'message': 'Task Status: COMPLETE'}),
                        media_type='application/json', headers=headers)
    else:
        return Response(status_code=202, content=json.dumps({'message': 'Task Status: RUNNING'}),
                        media_type='application/json', headers=headers)


@app.get('/apis/completed_task/{ident}', tags=['PyAPIs'])
def task_complete(request: Request, ident: str):
    """Retrieve the results of a task ID"""
    req_logit(get_task_status, request)

    task_handler.clean_up()

    task = task_handler.get_task(ident=ident)

    headers = task_location(ident)

    if isinstance(task, tuple):
        status, response = task
        return Response(status_code=status, content=json.dumps(response), media_type='application/json')

    elif isinstance(task, Task) and task.future.done():
        status, response = task.future.result()

        res_logit(task.func, request, response)

        return Response(status_code=status, content=json.dumps(response), media_type='application/json')
    else:
        return Response(status_code=202, content=json.dumps({'message': 'Task Status: RUNNING'}),
                        media_type='application/json', headers=headers)


def task_location(ident):
    headers = {
        'Location': f'/apis/get_task_status/{str(ident)}'
    }
    return headers


@app.get('/apis/nexus/environments', tags=['Nexus'])
def get_nexus_environments(request: Request):
    """Returns JSON that represents all Nexus environments"""
    req_logit(get_nexus_environments, request)

    data = json.load(open('data/NexusEnvironments.json', 'r'))
    return data


@app.get('/apis/nexus/environment_list', tags=['Nexus'])
def get_nexus_environments_list(request: Request):
    """Returns a list of Nexus environment names"""
    req_logit(get_nexus_environments_list, request)

    data = json.load(open('data/NexusEnvironments.json', 'r'))
    data = list((x['name'] for x in data['Environments']))
    data.sort()
    return data


@app.get('/apis/aci/environments', tags=['ACI'])
def get_aci_environments(request: Request, environment: Optional[str]=None):
    """Returns JSON that represents all ACI environments"""
    req_logit(get_aci_environments, request)

    data = json.load(open('data/ACIEnvironments.json', 'r'))

    if environment:
        data = next(e for e in data['Environments'] if e['Name'].upper() == environment.upper())

        accept_header = request.headers.get('Accept')
        if accept_header:
            if 'yaml' in accept_header.lower():
                new_data = {}
                for key, value in data.items():
                    new_data[key.lower()] = value

                return Response(status_code=200, content=yaml.dump(new_data), media_type='application/yaml')

    return data


@app.get('/apis/aci/environment_list', tags=['ACI'])
def get_aci_env_names(request: Request):
    """Returns a list of ACI environment names"""
    req_logit(get_aci_env_names, request)
    data = json.load(open('data/ACIEnvironments.json', 'r'))
    data = list((env['Name'] for env in data['Environments']))
    data.sort()
    return data


@app.get('/apis/getACIEnvironmentNames', tags=['ACI'], include_in_schema=False)
def get_aci_env_names(request: Request):
    """Old API endpoint.  Added to fix Janus. Hope to deprecate.  
    Returns a list of ACI environment names"""
    req_logit(get_aci_env_names, request)
    data = json.load(open('data/ACIEnvironments.json', 'r'))
    data = list((env['Name'] for env in data['Environments']))
    data.sort()
    return data


@app.get('/apis/f5/environments', tags=['F5'])
def get_f5_environments(request: Request):
    """Returns JSON that represents all recorded F5 environments"""
    req_logit(get_f5_environments, request)

    data = json.load(open('data/F5Environments.json', 'r'))
    return data


@app.get('/apis/f5/environment_list', tags=['F5'])
def get_f5_environment_list(request: Request):
    req_logit(get_f5_environment_list, request)

    data = json.load(open('data/F5Environments.json', 'r'))
    data = list(env['nameField'] for env in data)
    data.sort()
    return data


@app.get('/apis/aci/{az}/tenants/', tags=['ACI'], include_in_schema=False)
@app.get('/apis/aci/{az}/tenants', tags=['ACI'])
def collect_tenants(request: Request, az: str):
    """Returns list of non-default tenants for the specified ACI environment"""
    req_logit(collect_tenants, request, az)

    with apic_utils.APIC(env=az) as apic_api:
        tenants = apic_api.get('/api/class/fvTenant.json').json()['imdata']
    tenants = list((tn['fvTenant']['attributes']['name'] for tn in tenants
                    if tn['fvTenant']['attributes']['name'] not in ['infra', 'mgmt', 'common']))
    tenants.sort()

    return tenants


@app.get('/apis/aci/{az}/{tenant}/aps', tags=['ACI'])
def collect_aps(request: Request, az: str, tenant: str):
    """Returns a list of application profiles found in the specified tenant of the specified environment"""
    req_logit(collect_aps, request, f'{az}/{tenant}')

    with apic_utils.APIC(env=az) as apic_api:
        aps = apic_api.collect_aps(tn=tenant)
    aps = list((ap['fvAp']['attributes']['name'] for ap in aps))

    aps.sort()

    return aps


@app.get('/apis/aci/{az}/terraform_aps', tags=['ACI'])
def collect_tf_aps(request: Request, az: str):
    """Returns a list of application profiles that are supported by Terraform for the specified environment"""
    req_logit(collect_tf_aps, request)

    with apic_utils.APIC(env=az) as apic_api:
        aps = apic_api.collect_tf_aps()

    return aps


@app.get('/apis/aci/{az}/{tenant}/{ap}/epgs', tags=['ACI'])
def collect_epgs(request: Request, az: str, tenant: str, ap: str):
    """Returns a list of EPGs found in the specified application profile in the specified tenant in the specified
    environment"""
    req_logit(collect_epgs, request, f'{az}/{tenant}/{ap}')

    with apic_utils.APIC(env=az) as apic_api:
        epgs = apic_api.collect_epgs(tn=tenant)

    epgs = list((epg['fvAEPg']['attributes']['name'] for epg in epgs
                 if f'{ap}/' in epg['fvAEPg']['attributes']['dn']))

    epgs.sort()

    return epgs


@app.get('/apis/aci/{az}/get_epg_data/{epg}', tags=['ACI'])
def get_epg_data(request: Request, az: str, epg: str):
    """Returns information discovered about the given EPG"""
    req_logit(get_epg_data, request)

    status, response = apic_utils.get_epg_data(az, epg)

    return Response(status_code=status, content=json.dumps(response), media_type='application/json')


@app.get('/apis/aci/{az}/get_aci_vlan/{vlan}', tags=['ACI'])
def get_aci_vlan_data(request: Request, az: str, vlan: str):
    """Returns information discovered about the given VLAN encapsulation"""
    req_logit(get_aci_vlan_data, request)

    status, response = apic_utils.get_aci_vlan_data(environment=az, encap=vlan)

    return Response(status_code=status, content=json.dumps(response), media_type='application/json')


@app.get('/apis/aci/{az}/get_aci_subnet/{ip}', tags=['ACI'])
def get_aci_subnet_data(request: Request, az: str, ip: str):
    """Returns data associated with an IP subnet from an ACI fabric"""
    req_logit(get_aci_subnet_data, request)

    status, response = apic_utils.get_aci_subnet_data(environment=az, ip=ip)

    return Response(status_code=status, content=json.dumps(response), media_type='application/json')


@app.get('/apis/aci/{az}/get_bd_by_ip/{ip}', tags=['ACI'])
def get_bd_by_ip(request: Request, az: str, ip: str):
    """Returns bridge domain where a subnet that matches the provided IP address exists."""
    req_logit(get_bd_by_ip, request)

    status, response = apic_utils.APIC.get_bd_by_ip(environment=az, ip=ip)

    return Response(status_code=status, content=json.dumps(response), media_type='application/json')


def collect_dr_epgs(az=None):
    with apic_utils.APIC(env=az) as apic_api:
        epgs = apic_api.collect_epgs()
        dr_tagged = apic_api.collect_tags('dr')

    dr_tagged = list((x['tagInst']['attributes']['dn'].replace('/tag-dr', '') for x in dr_tagged))

    return epgs, dr_tagged


@app.get('/apis/aci/{az}/get_dr_vlans', tags=['ACI'])
def get_dr_vlans(request: Request, az: str):
    """Returns JSON representing all DR EPGs in the specified environment"""
    req_logit(get_dr_vlans, request, az)

    try:
        with apic_utils.APIC(env=az) as apic_api:
            resp = apic_api.get_dr_vlans()
        return resp
    except ValueError:
        return Response(status_code=400, content=json.dumps({'message': 'Environment Does Not Exist'}),
                        media_type='application/json')


@app.get('/apis/aci/{az}/get_nondr_vlans', tags=['ACI'])
def get_nondr_vlans(request: Request, az: str):
    """Returns JSON representing all Production EPGs in the specified environment"""
    req_logit(get_nondr_vlans, request, az)

    try:
        with apic_utils.APIC(env=az) as apic_api:
            resp = apic_api.get_nondr_vlans()
        return resp
    except ValueError:
        return Response(status_code=400, content=json.dumps({'message': 'Environment Does Not Exist'}),
                        media_type='application/json')


@app.get('/apis/aci/{az}/nondr_epgs', tags=['ACI'])
def get_nondr_epgs(request: Request, az: str):
    """Returns list of production EPGs in the specified environment"""
    req_logit(get_nondr_epgs, request, az)

    epg_list = []
    epgs, dr_tagged = collect_dr_epgs(az)

    for epg in (EPG.load(epg) for epg in epgs):
        if epg.attributes.dn not in dr_tagged:
            epg_list.append(epg.attributes.dn.replace('uni/', ''))

    return epg_list


@app.get('/apis/aci/{az}/dr_epgs', tags=['ACI'])
def get_dr_epgs(request: Request, az: str):
    """Returns list of all DR EPGs found in the specified environment"""
    req_logit(get_dr_epgs, request, az)

    epg_list = []
    epgs, dr_tagged = collect_dr_epgs(az)

    for epg in (EPG.load(epg) for epg in epgs):
        if epg.attributes.dn in dr_tagged:
            epg_list.append(epg.attributes.dn.replace('uni/', ''))

    return epg_list


@app.get('/apis/aci/{az}/aeps', tags=['ACI'])
def collect_aeps(request: Request, az: str):
    """Returns a list of AEPs (aka Port Templates) found in the specified environment"""
    req_logit(collect_aeps, request, az)

    with apic_utils.APIC(env=az) as apic_api:
        aeps = apic_api.collect_aeps()
    aeps = list((aep['infraAttEntityP']['attributes']['name'] for aep in aeps))

    aeps.sort()

    return aeps


@app.get('/apis/aci/{az}/{aep}/usage', tags=['ACI'])
def get_aep_usage(request: Request, az: str, aep: str):
    """Returns a series of leaf switches and interfaces used by the specified AEP"""
    req_logit(collect_aeps, request, az)

    with apic_utils.APIC(env=az) as apic_api:
        usage = apic_api.get_aep_usage(aep_name=aep)

    return usage


@app.get('/apis/aci/{az}/switch_profiles', tags=['ACI'])
def collect_switch_profiles(request: Request, az: str):
    """Returns a list of switch profiles found in the specified environment"""
    req_logit(collect_switch_profiles, request, az)

    with apic_utils.APIC(env=az) as apic_api:
        profiles = apic_api.collect_switch_profiles()
    profiles = list((profile['infraNodeP']['attributes']['name'] for profile in profiles))

    profiles.sort()

    return profiles


@app.get('/apis/aci/{az}/pods', tags=['ACI'])
def collect_pods(request: Request, az: str):
    req_logit(collect_pods, request, az)

    with apic_utils.APIC(env=az) as apic_api:
        pods = apic_api.collect_pods()
    pods = list(pod['fabricPod']['attributes']['id'] for pod in pods)

    pods.sort()
    return pods


@app.get('/apis/aci/{az}/teps', tags=['ACI'])
def collect_teps(request: Request, az: str):
    req_logit(collect_teps, request, az)

    with apic_utils.APIC(env=az) as apic_api:
        data = apic_api.collect_teps()
    data = sorted(data, key=lambda x: x['address'])
    return data


@app.get('/apis/aci/{az}/find_lldp_neigh/{neigh}', tags=['ACI'])
def find_lldp_neigh(request: Request, az: str, neigh: str):
    """Query the fabric for information about a list of LLDP neighbors.  Supports comma separated list of MAC addresses
    """
    req_logit(find_lldp_neigh, request, (az, neigh))

    with apic_utils.APIC(env=az) as apic_api:
        _, data = apic_api.find_lldp_neighbors(neigh)
    data = sorted(data, key=lambda x: x['chassisID'])
    return data


@app.get('/apis/aci/{az}/get_unused_objects', tags=['ACI'])
def get_unused_objects(request: Request, az: str):
    """Get a list of unused EPGs, BDs, and Subnets from the target fabric
    """
    req_logit(find_lldp_neigh, request, az)

    data = apic_utils.APIC(env=az).remove_unused_epgs_bds_subnets()

    return data


@app.get('/apis/aci/snmp_clients', tags=['ACI'], include_in_schema=False)
def collect_snmp_clients(request: Request):
    req_logit(collect_snmp_clients, request, None)

    with apic_utils.APIC(env='xrdc-az1') as apic:
        status, clients = apic.w_collect_snmp_clients()

    clients.sort(key=lambda x: x[1])

    client_response = ''

    for name, addr in clients:
        client_response += f'{name:<40}{addr:<15}\n'

    return Response(status_code=status, content=client_response, media_type='text/plain')


@app.get('/apis/aci/{az}/get_mgmt_addresses', tags=['ACI'], include_in_schema=False)
def get_mgmt_addresses(request: Request, az: str):
    req_logit(get_mgmt_addresses, request, None)

    with apic_utils.APIC(env=az) as apic:
        status, data = apic.get_leaf_mgmt_addresses()

    return json.loads(json.dumps(data, sort_keys=True))


@app.post('/apis/aci/add_new_leaf_pair', tags=['ACI'])
def add_new_leaf_pair(request: Request, req_data: AddNewLeafPair):
    """Configures the specified switch serial numbers as a new VPC leaf pair in the specified environment"""
    req_data = req_data.dict()

    if not validate_api_key(req_data.pop('APIKey')):
        return Response(status_code=403, content=json.dumps(['Invalid API Key'], media_type='application/json'))

    req_logit(add_new_leaf_pair, request, req_data)

    status, response = apic_utils.add_new_leaf_pair(env=req_data['AvailabilityZone'], rack1=req_data['RackSwitch1'],
                                                    serial1=req_data['Switch1_SerialNumber'],
                                                    rack2=req_data['RackSwitch2'],
                                                    serial2=req_data['Switch2_SerialNumber'])

    return Response(status_code=status, content=json.dumps(response), media_type='application/json')


@app.post('/apis/aci/add_oob_leaf', tags=['ACI'])
def add_oob_leaf(request: Request, req_data: AddOOBLeaf):
    """Configures the specified switch serial number as a new out-of-band leaf in the specified environments"""
    req_data = req_data.dict()

    if not validate_api_key(req_data.pop('APIKey')):
        return Response(status_code=403, content=json.dumps(['Invalid API Key']), media_type='application/json')

    req_logit(add_oob_leaf, request, req_data)

    status, response = apic_utils.add_oob_leaf(env=req_data['AvailabilityZone'], rack=req_data['Rack'],
                                               serial=req_data['SerialNumber'])

    return Response(status_code=status, content=json.dumps(response), media_type='application/json')


@app.get('/apis/aci/{az}/status', tags=['ACI'])
def fabric_status(request: Request, az: str=None, credentials: HTTPBasicCredentials=Depends(http_basic_security)):
    """Generates a new status report for the specified fabric and compares it to the previous report.  Then
    delivers the comparison information"""
    req_logit(fabric_status, request)

    status, response = apic_utils.fabric_status(env=az, **credentials.dict())

    return Response(status_code=status, content=json.dumps(response), media_type='application/json')


@app.get('/apis/aci/update_snmp_strings', tags=['ACI'], include_in_schema=False)
def update_snmp_strings(request: Request):
    """Updates the SNMP strings for an ACI environment"""
    req_logit(update_snmp_strings, request)

    envs = json.load(open('data/ACIEnvironments.json'))

    for env in envs['Environments']:
        with apic_utils.APIC(env=env['Name']) as apic_api:
            apic_api.update_snmp_strings()

    return Response(status_code=200, content=json.dumps({'message': 'Update SNMP Strings Completed'}),
                    media_type='application/json')


@app.post('/apis/aci/{az}/rebrand_epg_bd', tags=['ACI'])
def rebrand_epg_bd(request: Request, az: str, req_data: RebrandEpgBd):
    """Renames an EPG.  Optionally renames the bridge domain if a value is provided for new_bd_name.  Updates
    encapsulation on all AEPs as well.  Requests to this API will delete the old EPG.  This API will not rename a BD if
    the BD is shared with multiple EPGs."""
    req_data = req_data.dict()

    if not validate_api_key(req_data.pop('APIKey')):
        return Response(status_code=403, content=json.dumps({'message': 'Not Authorized'}),
                        media_type='application/json')

    req_logit(rebrand_epg_bd, request, req_data)

    with apic_utils.APIC(env=az) as apic_api:
        result = apic_api.rebrand_epg_bd(**req_data)

    return Response(status_code=200, content=json.dumps(result), media_type='application/json')


@app.post('/apis/aci/{az}/clone_aep', tags=['ACI'])
def clone_aep(request: Request, az: str, req_data: CloneAEP):
    """Renames an AEP.  Can be used to merge one AEP into another when specifying an existing AEP as the new AEP name.
    Requests to this API will delete the old AEP.  This API will not proceed if there is a conflicting VLAN to EPG
    association amongst the two specified AEPs."""
    req_data = req_data.dict()

    if not validate_api_key(req_data.pop('APIKey')):
        return Response(status_code=403, content=json.dumps({'message': 'Not Authorized'}),
                        media_type='application/json')

    req_logit(clone_aep, request, req_data)

    with apic_utils.APIC(env=az) as apic_api:
        status, result = apic_api.clone_aep(**req_data)

    return Response(status_code=status, content=json.dumps(result), media_type='application/json')


@app.post('/apis/aci/{az}/rebrand_aep', tags=['ACI'])
def rebrand_aep(request: Request, az: str, req_data: RebrandAEP):
    """Renames an AEP.  Can be used to merge one AEP into another when specifying an existing AEP as the new AEP name.
    Requests to this API will delete the old AEP.  This API will not proceed if there is a conflicting VLAN to EPG
    association amongst the two specified AEPs."""
    req_data = req_data.dict()

    if not validate_api_key(req_data.pop('APIKey')):
        return Response(status_code=403, content=json.dumps({'message': 'Not Authorized'}),
                        media_type='application/json')

    req_logit(rebrand_aep, request, req_data)

    with apic_utils.APIC(env=az) as apic_api:
        status, result = apic_api.rebrand_aep(**req_data)

    return Response(status_code=status, content=json.dumps(result), media_type='application/json')


@app.post('/apis/aci/move_to_dr', tags=['ACI'])
def move_to_dr(request: Request, req_data: DRTestMove):
    """Environment is implied SEDC.  Makes a copy of an EPG and BD from the production VRF (tn-HCA) into tn-DRTEST and
    updates all encapsulations on AEPs to use the copied EPG."""
    req_data = req_data.dict()

    if not validate_api_key(req_data.pop('APIKey')):
        return Response(status_code=403, content=json.dumps({'message': 'Not Authorized'}),
                        media_type='application/json')

    req_logit(move_to_dr, request, req_data)

    results = apic_utils.APIC.move_to_dr(**req_data)

    return Response(status_code=200, content=json.dumps(results), media_type='application/json')


@app.post('/apis/aci/return_to_prod', tags=['ACI'])
def return_to_prod(request: Request, req_data: DRTestMove):
    """Environment is implied SEDC.  Reverts the changes of move_to_dr APIC call, placing the EPG back into the
    production environment."""

    req_data = req_data.dict()

    if not validate_api_key(req_data.pop('APIKey')):
        return Response(status_code=403, content=json.dumps({'message': 'Not Authorized'}),
                        media_type='application/json')

    req_logit(return_to_prod, request, req_data)

    results = apic_utils.APIC.return_to_prod(**req_data)

    return Response(status_code=200, content=json.dumps(results), media_type='application/json')


@app.get('/apis/getStatus', tags=['PyAPIs'])
def get_status(request: Request):
    """Returns status of the recipient PyAPIs server"""
    if ':' in request.headers['Host']:
        host = request.headers['Host'][:request.headers['Host'].index(':')]
    else:
        host = request.headers['Host']

    response = {
        'Current Host': {
            'hostname': socket.gethostname(),
            'ip_address': socket.gethostbyname(socket.gethostname()),
            'py_version': re.search(r'[\d.]+', sys.version).group()
        },
        'Current Request': {
            'Host': request.headers['Host'],
            'FQDN': socket.getfqdn(host),
            'ip_address': socket.gethostbyname(host)
        },
        'Current Directory': os.getcwd().replace('\\', '/')
    }

    return response


@app.get('/apis/aci/updateVlanSpreadsheets', tags=['ACI'])
def update_vlan_spreadsheet(request: Request):
    """Updates the VLAN spreadsheet found at this location:
    //corpdpt01/telshare/Network_Engineering/Network_Design_and_Delivery/Py_ACI_VLANs.xlsx"""
    req_logit(update_vlan_spreadsheet, request)
    status, response = apic_utils.update_vlan_spreadsheet()
    return Response(status_code=status, content=json.dumps(response, indent=2), media_type='application/json')


@app.get('/apis/aci/fabricInventory', tags=['ACI'])
def fabric_inventory(request: Request):
    """Updates the ACI serial numbers spreadsheet found at this location:
    //corpdpt01/telshare/Network_Engineering/ACI/ACI_Serial_Numbers/Py_ACI_Serials.xlsx"""
    req_logit(fabric_inventory, request)
    status, response = apic_utils.fabric_inventory()
    return Response(status_code=status, content=json.dumps(response, indent=2), media_type='application/json')


@app.get('/apis/aci/{az}/get_next_vlan', tags=['ACI'])
def get_next_vlan(request: Request, az: str):
    """Return the next available VLAN ID for the specified ACI environment"""
    req_logit(get_next_vlan, request, az)

    with apic_utils.APIC(env=az) as apic_api:
        content = apic_api.get_next_vlan()

    return Response(status_code=200, content=f'{content}', media_type='text/plain')


@app.get('/apis/aci/{az}/get_vlan_data', tags=['ACI'], include_in_schema=False)
def get_vlan_data(request: Request, az: str, vlan: Optional[str or int]=None, epg: Optional[str]=None,
                  aep: Optional[str]=None):
    """Returns VLAN information for specified environment.  Can be queried for specific information using documented
    parameters."""
    if vlan is not None:
        vlan = int(vlan)

    req_logit(get_vlan_data, request, az)

    with apic_utils.APIC(env=az) as apic_api:
        response = apic_api.get_vlan_data(vlan=vlan, epg=epg, aep=aep)

    return response


@app.get('/apis/v2/aci/{az}/get_vlan_data', tags=['ACI'])
def get_vlan_data_v2(request: Request, az: str, VLAN: Optional[str or int]=None, EPG: Optional[str]=None,
                     AEP: Optional[str]=None, DN: Optional[str]=None):
    """Returns VLAN information for specified environment.  Can be queried for specific information using documented
    parameters."""
    try:
        if VLAN is not None:
            VLAN = int(VLAN)

        req_logit(get_vlan_data, request, az)

        with apic_utils.APIC(env=az) as apic_api:
            response = apic_api.get_vlan_data(vlan=VLAN, epg=EPG, aep=AEP, dn=DN)

        new_response = []

        if isinstance(response, list):
            for vlan in response:
                for key in vlan.keys():
                    vlan[key]['VLAN'] = key

            for vlan in response:
                for key in vlan:
                    new_response.append(vlan[key])

        elif isinstance(response, dict):
            for key in response:
                response[key]['VLAN'] = key

            for key in response:
                new_response.append(response[key])

        new_response.sort(key=lambda x: x['VLAN'])

        return new_response
    except Exception as e:
        return Response(status_code=500, content=json.dumps({'message': f'{e}'}), media_type='application/json')


@app.get('/apis/aci/{az}/verify_leaf_uplinks', tags=['ACI'])
def verify_leaf_uplinks(request: Request, az: str):
    """Verifies that all fabric leafs have an uplink to multiple spines"""
    req_logit(verify_leaf_uplinks, request)

    compliance = apic_utils.APIC.verify_leaf_uplinks(env=az)

    response = {'environment': az.upper(),
                'status': compliance}

    return Response(status_code=200, content=json.dumps(response), media_type='application/json')


@app.post('/apis/aci/{az}/create_new_epg', tags=['ACI'])
def create_new_epg(request: Request, az: str, req_data: CreateNewEPG):
    """Configures a new EPG in the specified ACI environment.  Returns VLAN and subnet information that was
    selected."""
    req_data = req_data.dict()

    if not validate_api_key(req_data.pop('APIKey')):
        return Response(status_code=403, content=json.dumps(['Invalid API Key']), media_type='application/json')

    req_logit(create_new_epg, request, req_data)

    aeps = req_data.pop('AEPs')

    status, r = apic_utils.create_new_epg(env=az, req_data=req_data)

    if status == 200 and aeps:
        env = ACIEnvironment(az)

        for aep in aeps:
            mapping = {
                'AEP': aep,
                'Tenant': env.Tenant,
                'AP': req_data['AppProfileName'],
                'EPG': req_data['EPGName']
            }

            apic_utils.assign_epg_to_aep(az, mapping)

    res_logit(create_new_epg, request, r)

    return Response(status_code=status, content=json.dumps(r), media_type='application/json')


@app.post('/apis/aci/{az}/create_custom_epg', tags=['ACI'])
def create_custom_epg(request: Request, az: str, req_data: CreateCustomEPG):
    """Configures a new EPG in the specified ACI environment.  Returns VLAN and subnet information that was
    selected."""
    req_data = req_data.dict()

    if not validate_api_key(req_data.pop('APIKey')):
        return Response(status_code=403, content=json.dumps(['Invalid API Key']), media_type='application/json')

    req_logit(create_custom_epg, request, req_data)

    for network in req_data['Subnets']:
        try:
            assert '/' in network
            IPv4Network(network, strict=False)
        except AssertionError:
            return Response(status_code=400, content=json.dumps(
                {'error': 'SubnetError', 'message': 'Network and prefix must be supplied'}),
                            media_type='application/json')
        except AddressValueError as reason:
            return Response(status_code=400, content=json.dumps({'error': 'SubnetError', 'message': str(reason)}),
                            media_type='application/json')

    aeps = req_data.pop('AEPs')

    status, r = apic_utils.create_custom_epg(env=az, req_data=req_data)

    if status == 200 and aeps:
        env = ACIEnvironment(az)

        for aep in aeps:
            mapping = {
                'AEP': aep,
                'Tenant': env.Tenant,
                'AP': req_data['AppProfileName'],
                'EPG': req_data['EPGName']
            }

            apic_utils.assign_epg_to_aep(az, mapping)

    res_logit(create_custom_epg, request, r)

    return Response(status_code=status, content=json.dumps(r), media_type='application/json')


@app.post('/apis/v2/aci/{az}/create_custom_epg', tags=['ACI'])
def create_custom_epg_v2(request: Request, az: str, req_data: CreateCustomEPGv2):
    """Configures a new EPG in the specified ACI environment.  Returns VLAN and subnet information that was
    selected."""
    req_data = req_data.dict()

    if not validate_api_key(req_data.pop('APIKey')):
        return Response(status_code=403, content=json.dumps(['Invalid API Key']), media_type='application/json')

    req_logit(create_custom_epg_v2, request, req_data)

    for network in req_data['Subnets']:
        try:
            assert '/' in network
            IPv4Network(network, strict=False)
        except AssertionError:
            return Response(status_code=400, content=json.dumps(
                {'error': 'SubnetError', 'message': 'Network and prefix must be supplied'}),
                            media_type='application/json')
        except AddressValueError as reason:
            return Response(status_code=400, content=json.dumps({'error': 'SubnetError', 'message': str(reason)}),
                            media_type='application/json')

    aeps = req_data.pop('AEPs')

    status, r = apic_utils.create_custom_epg_v2(env=az, req_data=req_data)

    if status == 200 and aeps:
        for aep in aeps:
            mapping = {
                'AEP': aep,
                'Tenant': req_data['TenantName'],
                'AP': req_data['AppProfileName'],
                'EPG': req_data['EPGName']
            }

            apic_utils.assign_epg_to_aep(az, mapping)

    res_logit(create_custom_epg_v2, request, r)

    return Response(status_code=status, content=json.dumps(r), media_type='application/json')


@app.post('/apis/aci/{az}/standardize_maintenance_groups', tags=['ACI'])
def standardize_maintenance_groups(request: Request, az: str, req_data: MaintenanceGroups):
    """Creates standard maintenance groups for fabric nodes and assigns nodes to those groups"""
    req_data_dict = req_data.dict()

    if not validate_api_key(req_data_dict.pop('APIKey')):
        return Response(status_code=403, content=json.dumps(['Invalid API Key']), media_type='application/json')

    req_logit(standardize_maintenance_groups, request, req_data_dict)

    apic_utils.APIC(env=az).assign_nodes_to_maintenance_groups()

    return Response(status_code=200, content=json.dumps({'message': 'Maintenance policies have been updated '
                                                                    'and nodes assigned'}))


@app.post('/apis/aci/{az}/change_epg_encap', tags=['ACI'])
def change_epg_encap(request: Request, az: str, req_data: ChangeEPGEncap):
    """Changes the specified encapsulation to a new encapsulation.  For auto-selection of a new encap, leave value as
    0"""
    req_data_dict = req_data.dict()

    if not validate_api_key(req_data_dict.pop('APIKey')):
        return Response(status_code=403, content=json.dumps(['Invalid API Key']), media_type='application/json')

    req_logit(create_custom_epg_v2, request, req_data_dict)

    with apic_utils.APIC(env=az) as apic:
        r = apic.change_epg_encap(epg_dn=req_data.epg_dn, old_encap=req_data.old_encap, new_encap=req_data.new_encap)

    return Response(status_code=200, content=json.dumps(r), media_type='application/json')


@app.post('/apis/aci/assignEpgToAep', tags=['ACI'])
def assign_epg_to_aep(request: Request, req_data: AssignEPGToAEP):
    """Assigns (Trunks) EPG (VLAN) to the specified AEP (aka Port Template) in the specified ACI environment"""
    req_data = req_data.dict()

    if not validate_api_key(req_data.pop('APIKey')):
        return Response(status_code=403, content=json.dumps(['Invalid API Key']), media_type='application/json')

    req_logit(assign_epg_to_aep, request, req_data)

    responses = []

    for mapping in req_data['AEPMappings']:
        status, response = apic_utils.assign_epg_to_aep(req_data['AvailabilityZone'], mapping)
        if status == 500:
            responses.append({'Status': 'Failed', 'EPG': mapping['EPG'], 'VLAN': response})
        else:
            responses.append(dict(Status='Success', **response))

    results = {'Assignments': responses}

    res_logit(assign_epg_to_aep, request, results)

    return results


@app.post('/apis/aci/{az}/assign_vlan_to_aep', tags=['ACI'])
def assign_vlan_to_aep(az: str, request: Request, req_data: AssignVlanToAep):
    """Assigns the EPG associated to a VLAN ID to the requested AEP"""
    req_data = req_data.dict()

    if not validate_api_key(req_data.pop('APIKey')):
        return Response(status_code=403, content=json.dumps(['Invalid API Key']), media_type='application/json')

    req_logit(assign_epg_to_aep, request, req_data)

    apic = apic_utils.APIC(env=az)

    responses = []

    for aep in req_data['assignments']:
        for vlan in aep['vlan_ids']:
            status, response = apic.assign_vlan_to_aep(vlan=vlan, aep=aep['aep'])
            responses += [{'vlan_id': vlan, 'aep': aep['aep'], 'status': status, 'response': response}]

    return Response(status_code=200, content=json.dumps(responses), media_type='application/json')


@app.post('/apis/aci/{az}/update_static_route', tags=['ACI'])
def update_static_route(request: Request, az: str, req_data: UpdateStaticRoute):
    """Changes the next hop for a static route"""
    req_data = req_data.dict()

    if not validate_api_key(req_data.pop('APIKey')):
        return Response(status_code=403, content=json.dumps(['Invalid API Key']), media_type='application/json')

    req_logit(update_static_route, request, req_data)

    with apic_utils.APIC(env=az) as apic:
        status, response = apic.update_static_route(**req_data)

    res_logit(update_static_route, request, response)

    return Response(status_code=status, content=json.dumps(response), media_type='application/json')


@app.get('/apis/appinst/applications', tags=['AppInstance'])
def get_applications(request: Request):
    """Returns list of all documented application profiles"""
    req_logit(get_applications, request)

    gh = GithubAPI()

    apps = gh.list_dir('applications')
    apps.sort()

    return apps


@app.get('/apis/appinst/applications/{application}', tags=['AppInstance'])
def get_application_instances(request: Request, application: str):
    """Returns list of all documented application profiles"""
    req_logit(get_application_instances, request, application)

    gh = GithubAPI()

    apps = gh.list_dir(f'applications/{application}')
    apps.sort()

    return apps


@app.get('/apis/appinst/{application}/{instance}', tags=['AppInstance'])
def get_application_instance(request: Request, application: str, instance: str):
    """Returns list of instances found within the specified application"""
    req_logit(get_application_instance, request, application)

    gh = GithubAPI()

    content = json.loads(gh.get_file_content(f'applications/{application}/{instance}'))

    return content


@app.post('/apis/appinst/{application}/{instance}/create', tags=['AppInstance'])
def create_new_app_instance(request: Request, req_data: CreateNewAppInstance):
    """Creates disaster recovery testing instance of an AppInstance"""
    req_data_dict = req_data.dict()

    if not validate_api_key(req_data_dict.pop('APIKey')):
        return Response(status_code=403, content=json.dumps(['Invalid API Key']), media_type='application/json')

    req_logit(create_new_app_instance, request, req_data_dict)

    status, data = apic_utils.AppInstance.create_new_instance(az=req_data.az, application=req_data.application,
                                                              inst_name=req_data.instance_name,
                                                              no_of_ips=req_data.no_of_ips,
                                                              dmz=req_data.dmz)

    res_logit(create_new_app_instance, request)

    return Response(status_code=status, content=json.dumps(data), media_type='application/json')


@app.post('/apis/appinst/{application}/{instance}/create_drt', tags=['AppInstance'])
def create_drt_app_instance(request: Request, application: str, instance:str, req_data: CreateDRTAppInstance):
    """Creates disaster recovery testing instance of an AppInstance"""
    req_data_dict = req_data.dict()

    if not validate_api_key(req_data_dict.pop('APIKey')):
        return Response(status_code=403, content=json.dumps(['Invalid API Key']), media_type='application/json')

    req_logit(create_drt_app_instance, request)

    inst = apic_utils.AppInstance.load(f'{application}/{instance}')
    vlan_info = inst.create_drt_instance(drenv=inst.originAZ.env.DREnv)

    res_logit(create_drt_app_instance, request)

    response_data = {'app_instance': inst.json(), 'vlan_info': vlan_info, 'epg_dn': inst.epg_dn(drt=True)}

    return Response(status_code=200, content=json.dumps(response_data), media_type='application/json')


@app.get('/apis/f5/vip_clone', tags=['F5'])
def vip_clone(request: Request, vip_address: str, ltm_env: str=None):
    """Currently returns all configuration and configuration dependencies needed to rebuild a VIP.  This will be
    modified to include the rebuild action to a specified environment"""
    req_logit(vip_clone, request, dict(**request.query_params))

    status, response = LTM.vip_clone(vip_address=vip_address, ltm_env=ltm_env)

    res_logit(vip_clone, request, response)

    return Response(status_code=status, content=json.dumps(response), media_type='application/json')


@app.get('/apis/f5/document_vip', tags=['F5'])
def document_vip(request: Request, app_code: str, instance_name: str, vip_address: str=None, fqdn: str=None):
    req_logit(document_vip, request, dict(**request.query_params))

    status, response = LTM.store_vip_config(app_code=app_code, inst_name=instance_name, vip_address=vip_address,
                                            fqdn=fqdn)

    res_logit(document_vip, request, response)

    return Response(status_code=status, content=json.dumps(response), media_type='application/json')


@app.post('/apis/f5/drt_restore_app_instance', tags=['F5'])
def drt_restore_app_instance(request: Request, req_data: DRTRestoreAppInstance):
    req_data_dict = req_data.dict()

    if not validate_api_key(req_data_dict.pop('APIKey')):
        return Response(status_code=403, content=json.dumps(['Invalid API Key']), media_type='application/json')

    req_logit(drt_restore_app_instance, request, req_data_dict)
    path = f'f5caas/{req_data.app_code}/{req_data.instance_name}'

    # Get configuration given inputs
    api = GithubAPI()

    vips = api.list_dir(path)

    if not vips:
        return Response(status_code=404, content=json.dumps({'message': f'{path} was not found'}),
                        media_type='application/json')

    # Login to DR Testing LTMs
    ltm = LTM.login_to_environment(env='DRTest')

    # Configure VIP
    for vip in vips:
        file = api.get_file_content(f'{path}/{vip}')
        vip_data = json.loads(file)['configurations']

        ltm.deploy_configurations(data=vip_data)

    return {'message': 'All VIPs have been configured in DR test environment'}


@app.post('/apis/nexus/createSVI', tags=['Nexus'])
def create_svi(request: Request, req_data: CreateSVI):
    """Creates a new SVI (Switch Virtual Interface) in a Nexus Environment"""
    req_data = req_data.dict()

    if not validate_api_key(req_data.pop('APIKey')):
        return Response(status_code=403, content=json.dumps(['Invalid API Key']), media_type='application/json')

    req_logit(create_svi, request, req_data)

    req_data['env'] = req_data.pop('Environment')
    req_data['no_of_ips'] = req_data.pop('numberOfIPs')
    req_data['name'] = req_data.pop('vlanName')

    status, response = NXOS.create_new_svi(**req_data)

    return Response(status_code=status, content=json.dumps(response), media_type='application/json')


@app.post('/apis/nexus/{environment}/create_custom_svi', tags=['Nexus'])
def create_custom_svi(request: Request, environment: str, req_data: CreateCustomSVI):
    req_data = req_data.dict()

    if not validate_api_key(req_data.pop('APIKey')):
        return Response(status_code=403, content=json.dumps(['Invalid API Key']), media_type='application/json')

    req_logit(create_custom_svi, request, req_data)

    status, response = NXOS.create_custom_svi(environment, **req_data)

    res_logit(create_custom_svi, request, response)

    return Response(status_code=status, content=json.dumps(response), media_type='application/json')


@app.post('/apis/sviToBd', tags=['ACI', 'Nexus'])
def svi_to_bd(request: Request, req_data: SVIToBD):
    """
    'Description': 'This API will migrate a VLAN and all of its subnets to an ACI fabric.',
        'Instructions': {
            1: 'Ensure you know what you are doing. Consult with William Duhé, BT Peake, or John Feger if you are '
               'unsure.',
            2: 'It is preferred to only provide 1 VLAN per request.  Although, it supports multiple.',
            3: 'Function of suppressL3: Setting this to true instructs the automation to ignore L3 information on a '
               'VLAN.  This is primarily used for L2 extensions from Nexus into ACI.',
            4: 'Function of migrate: You can use layer2 OR complete as values here.  If you select complete, '
               'suppressL3 must be set to false, or subnet information will not be gathered for the migration.  '
               'Complete will shutdown the SVI in the Nexus environments.py.  layer2 is used to extend a VLAN into the '
               'ACI fabric.'
        }
    """
    req_data = req_data.dict()

    if not validate_api_key(req_data.pop('APIKey')):
        return Response(status_code=403, content=json.dumps(['Invalid API Key']), media_type='application/json')

    req_logit(svi_to_bd, request, req_data)

    response = sviToBd.svi_to_bd(req_data)

    res_logit(svi_to_bd, request, response)
    return response


@app.get('/apis/nexus/{environment}/macLookup/{mac}', tags=['Nexus'])
def mac_lookup(request: Request, environment: str, mac: str):
    """This API returns trace data for the given MAC address from the specified environment."""
    req_logit(mac_lookup, request, request.path_params)

    env = NexusEnvironment(environment)

    result = n_mac_lookup(host=env.l3switch1, mac=mac)

    return result


@app.get('/apis/nexus/{environment}/trace_ip/{ip_address}', tags=['Nexus'])
def trace_ip(request: Request, environment: str, ip_address: str):
    req_logit(trace_ip, request, request.path_params)

    status, response = NXOS.trace_ip(environment=environment, ip_address=ip_address)

    return Response(status_code=status, content=json.dumps(response), media_type='application/json')


@app.post('/apis/nexus/trunkVlan', tags=['Nexus'], include_in_schema=False)
def trunk_vlan(request: Request, req_data: TrunkVlan):
    """
    This API will trace a MAC address and add the specified VLAN to the trunk port on which
    that MAC address is found.

    1: 'MAC Addresses can be in almost any format',
    2: 'VLAN is currently required to be a string',
    3: 'If the VLAN exists, the name on the 7K will be used. In this case, you may leave this field empty. '
        'Otherwise, provide a name for the VLAN.  If you are unsure, provide a name for the VLAN.'
    """
    from nexus.nexusHost import trunk_vlan as f_trunk_vlan

    req_data = req_data.dict()

    if not validate_api_key(req_data.pop('APIKey')):
        return Response(status_code=403, content=json.dumps(['Invalid API Key']))

    req_logit(trunk_vlan, request, req_data)

    status, response = f_trunk_vlan(req_data=req_data)

    return Response(status_code=status, content=json.dumps(response), media_type='application/json')


@app.get('/apis/wsa/routes', tags=['WSA'])
def get_wsa_routes(request: Request, dst: Optional[str]=None):
    """Returns the route(s) that are/will be configured on WSAs.  If a route is seen in this data but not in the WSA
    routing table, a POST to /apis/wsa/deploy_routes needs to be made."""
    from wsa.wsa_routes import get_routes

    req_logit(get_wsa_routes, request, dst)
    status, response = get_routes(dst=dst)

    return Response(status_code=status, content=response, media_type='text/plain')


@app.post('/apis/wsa/routes', tags=['WSA'])
@app.delete('/apis/wsa/routes', tags=['WSA'])
def wsa_routes(request: Request, req_data: WSARoutes):
    """Add or Delete routes to/from the WSA appliances"""
    from wsa.wsa_routes import add_route, delete_route

    if request.method == 'POST':
        req_data = req_data.dict()

        if req_data.pop('APIKey') != 'eMkVRwtOdIrPE4YOmqGr':
            return Response(status_code=403, content=json.dumps(['Invalid API Key']), media_type='text/plain')

        req_logit(wsa_routes, request, req_data)

        prefix = req_data['prefix']
        gateway = req_data['location'].lower()
        requester = req_data['requester']

        status, response = add_route(prefix=prefix, gateway=gateway, requester=requester)
        res_logit(wsa_routes, request, response)

        return Response(status_code=status, content=response, media_type='text/plain')

    elif request.method == 'DELETE':
        req_data = req_data.dict()

        if req_data.pop('APIKey') != 'eMkVRwtOdIrPE4YOmqGr':
            return Response(status_code=403, content=json.dumps(['Invalid API Key']), media_type='application/json')

        req_logit(wsa_routes, request, req_data)

        prefix = req_data['prefix']
        gateway = req_data['location']
        requester = req_data['requester']

        status, response = delete_route(prefix=prefix, gateway=gateway, requester=requester)
        res_logit(wsa_routes, request, response)

        return Response(status_code=status, content=response, media_type='text/plain')


@app.post('/apis/wsa/deploy_routes', tags=['WSA'])
def wsa_deploy_routes(request: Request, req_data: WSADeployRoutes):
    """Deploys the routing table found at /apis/wsa/routes to all WSA environments or to the specified site."""
    req_data = req_data.dict()

    if req_data.pop('key') != 'gxoCQuv7X84ZlXiOL9FR':
        return Response(status_code=403, content=json.dumps(['You need a key to call this API']),
                        media_type='application/json')

    req_logit(wsa_routes, request, req_data)

    site = ('' if req_data['site'].lower() == 'all' else req_data['site'].upper())

    from wsa.deploy import deploy_wsa_routes

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    elapsed, response = deploy_wsa_routes(loop=loop, site=site)

    res_logit(wsa_deploy_routes, request, f'Elapsed time: {elapsed} seconds')

    if isinstance(response, list):
        return response
    else:
        return Response(content=f'{elapsed}: {response}', media_type='text/plain')


@app.post('/apis/wsa/{data_center}/build', tags=['WSA'])
def wsa_build_api(request: Request, data_center: str, req_data: WSABuild):
    """Builds the specified WSAs.  Provide a comma separated list of the WSAs letters you wish to configure or type
    'all' (ie 'A, B, C, AA' or 'a,B, aa)"""
    req_data = req_data.dict()

    if not validate_api_key(req_data.pop('APIKey')):
        return Response(status_code=403, content=json.dumps(['Invalid API Key']))

    req_logit(wsa_build_api, request, req_data)

    status, response = wsaBuild.build_wsa_api(wsa_env=data_center, **req_data)

    res_logit(wsa_build_api, request, response)

    return response


@app.get('/apis/pac_file', tags=['PAC'])
def get_pac_file(request: Request, search: Optional[str]=None, loc: Optional[str]=None, host: Optional[str]=None,
                 comment: Optional[str]=None, mobile: Optional[str]=None, pilot: Optional[str]=None,
                 deploy: Optional[str]=None):
    """Returns information from the pac file in different formats based on the query parameters.  Query parameters
    also facilitates the merge of the PAC JSON from pilot branch to master."""

    req_logit(get_pac_file, request, f'loc: {(loc if loc else None)}, pilot: {(pilot if pilot else None)}, '
                                     f'mobile: {(mobile if mobile else None)}')

    lookup = search
    location = loc
    expression = host
    description = comment
    mobile = mobile

    gh_api = GithubAPI()

    if deploy is not None and deploy.lower() == 'true':
        req_logit(pac_file, request, 'PAC file deployment')
        gh_api.merge()
        return {'message': 'Merge Succeeded'}

    if pilot is not None and pilot.lower() == 'true':
        pac = json.loads(gh_api.get_file_content(file_path='pac/pac.json', branch='pilot'))
    else:
        pac = json.loads(gh_api.get_file_content(file_path='pac/pac.json', branch='main'))

    if expression is not None:
        search = {}
        for section in pac:
            search[section] = {'rules': list(rule for rule in pac[section]['rules']
                                             if 'host_exp' in rule.keys()
                                             if expression.lower() in rule['host_exp'])}
        return search

    if description is not None:
        search = {}
        for section in pac:
            search[section] = {'rules': list(rule for rule in pac[section]['rules']
                                             if description.lower() in rule['comment'].lower())}
        return search

    if lookup is not None:
        search = {}
        for section in pac:
            search[section] = {'rules': list(rule for rule in pac[section]['rules']
                                             for value in rule.values()
                                             if lookup.lower() in value.lower())
                               }
            if len(search[section]['rules']) == 0:
                del search[section]

        return search

    if location is not None:
        # This process generates and returns the PAC file as it will be used by the clients
        if pilot is not None and pilot.lower() == 'true':
            ref = 'pilot'
        else:
            ref = 'main'

        if mobile is not None and mobile.lower() == 'true':
            mobile = True
        else:
            mobile = False

        pac_file_contents = pac_gen(loc=loc, ref=ref, mobile=mobile)

        return Response(status_code=200, content=pac_file_contents, media_type='text/plain')

    return pac


@app.post('/apis/pac_file', tags=['PAC'])
@app.delete('/apis/pac_file', tags=['PAC'])
def pac_file(request: Request, req_data: Optional[PACFile]=None):
    """Add/Delete host expressions to/from the Proxy PAC file."""

    # TODO: Review this function.  An API key may need to be added
    api = GithubAPI()
    pac = json.loads(api.get_file_content(file_path='pac/pac.json', branch='pilot'))

    if request.method == 'POST':
        req_data = req_data.dict()

        section = req_data['section']
        host_exp = req_data['host_exp']
        if section == 'Proxy Rules':
            directive = 'PROXY'
        else:
            directive = 'DIRECT'
        comment = req_data['comment']

        req_logit(pac_file, request, req_data)

        exists = None

        try:
            exists = next(rule for section in pac
                          for rule in pac[section]['rules']
                          if 'host_exp' in rule
                          if rule['host_exp'] == host_exp)
        except StopIteration:
            pass

        if exists:
            return Response(status_code=400, content=json.dumps(['Host expression already exists']),
                            media_type='application/json')

        pac[section]['rules'].append({
            'host_exp': host_exp.replace(' ', ''),
            'comment': f'  {comment}  ',
            'directive': directive
        })

        resp = {
            section: {
                'rules': [{
                    'host_exp': host_exp,
                    'comment': f'  {comment}  ',
                    'directive': directive
                }]
            }
        }

        api.update_file(file_path='pac/pac.json', message=f'{host_exp} via {directive} added to {section}',
                        content=json.dumps(pac, indent=4), branch='pilot')

        return Response(status_code=200,
                        content='The following has been added to pac.json\n\n{}'
                                '<meta http-equiv="Refresh" contents="5; '
                                'url=https://pyapis.app.medcity.net/apis/pac_portal">'.format(
                                                                                            json.dumps(resp, indent=4)))

    if request.method == 'DELETE':
        req_data = req_data.dict()

        req_logit(pac_file, request, req_data)

        section = req_data['section']
        host_exp = req_data['host_exp']

        try:
            delete = next(x for x in pac[section]['rules'] if 'host_exp' in x if x['host_exp'] == host_exp)
        except StopIteration:
            return Response(status_code=404, content=json.dumps(['The rule provided does not exist']),
                            media_type='application/json')

        pac[section]['rules'].remove(delete)

        resp = {
            section: {
                'rules': [delete]
            }
        }

        api.update_file(file_path='pac/pac.json', message=f'DELETE {host_exp} from {section}.  View Diff',
                        content=json.dumps(pac, indent=4), branch='pilot')

        return Response(content='The following rule has been removed:\n\n{}'.format(json.dumps(resp, indent=4)))


@app.post('/apis/aci/createNewAEP', tags=['ACI'])
def create_new_aep(request: Request, req_data: CreateNewAEP):
    """Creates a new AEP (aka Port Template) in the specified ACI environment"""
    env = ACIEnvironment(req_data.AvailabilityZone)
    name = req_data.AEP

    req_logit(create_new_aep, request, req_data.dict())

    aep = AEP()
    aep.attributes.name = (f'aep-{name}' if not name.startswith('aep-') else name)
    aep.children = [InfraGeneric()]
    aep.use_domain(env.PhysicalDomain)

    with apic_utils.APIC(env=env.Name) as apic_api:
        resp = apic_api.post(aep.json(), uri=aep.post_uri)

    return Response(status_code=resp.status_code, content=json.dumps(resp.json()), media_type='application/json')


@app.post('/apis/aci/intfProfile', tags=['ACI'], include_in_schema=False)
def interface_profile(request: Request, req_data: IntfProfile):
    """Creates a new ACI interface configuration given the supplied information."""
    req_data = req_data.dict()

    if not validate_api_key(req_data.pop('APIKey')):
        return Response(status_code=403, content=json.dumps(['Invalid APIKey']), media_type='application/json')

    req_logit(interface_profile, request, req_data)

    status, response = intf_profile(req_data)

    res_logit(interface_profile, request, response)

    return Response(status_code=status, content=json.dumps(response), media_type='application/json')


@app.post('/apis/aci/{az}/configure_interfaces', tags=['ACI'])
def aci_interface_configuration(request: Request, az: str, req_data: ACIInterfaceConfiguration):
    """Creates a new ACI interface configuration based on the supplied information"""
    req_data = req_data.dict()

    if not validate_api_key(req_data.pop('APIKey')):
        return Response(status_code=403, content=json.dumps(['Invalid API Key']), media_type='application/json')

    req_logit(aci_interface_configuration, request, req_data)

    status, response = apic_utils.configure_interfaces(env=az, req_data=req_data['Configurations'])

    res_logit(aci_interface_configuration, request, response)

    return Response(status_code=status, content=json.dumps(response), media_type='application/json')


@app.post('/apis/aci/{az}/reclaim_interfaces', tags=['ACI'])
def aci_reclaim_interfaces(request: Request, az: str, req_data: ACIReclaimInterfaces):
    """Sets interfaces within the ACI fabric to default settings based on the supplied information.  Before using this
    API, ensure that all interfaces are in a down state.  Validation checks must find these interfaces down, otherwise
    they are assumed to be in use and will not be modified."""
    req_data = req_data.dict()

    if not validate_api_key(req_data.pop('APIKey')):
        return Response(status_code=403, content=json.dumps(['Invalid API Key']), media_type='application/json')

    req_logit(aci_reclaim_interfaces, request, req_data)

    with apic_utils.APIC(env=az) as apic:
        status, response = apic.reclaim_interfaces(profile_name=req_data['profile_name'],
                                                   interfaces=req_data['interfaces'])

    res_logit(aci_reclaim_interfaces, request, response)

    return Response(status_code=status, content=json.dumps(response), media_type='application/json')


@app.post('/apis/aci/tagEPG', tags=['ACI'])
@app.post('/apis/v2/aci/tagEPG', tags=['ACI'])
def tag_epg(request: Request, req_data: TagEPG):
    """Assign a tag to the EPG in the specified environment"""
    req_data = req_data.dict()

    if not validate_api_key(req_data.pop('APIKey')):
        return Response(status_code=403, content=json.dumps(['Invalid APIKey']), media_type='application/json')

    req_logit(tag_epg, request, req_data)

    env = req_data['AvailabilityZone']
    epgs = req_data['EPGs']

    # status, response = tag_epgs_v2(env, epgs)
    status, response = apic_utils.APIC.tag_epgs(env, epgs)

    res_logit(tag_epg, request, response)

    return Response(status_code=status, content=json.dumps(response), media_type='application/json')


@app.post('/apis/manage_device', tags=['IPAM'])
def manage_device(request: Request, req_data: ManageDevice):
    """This API creates DNS records for the supplied IP address with the given information and queues them for
    management.  Used for network devices."""
    req_data = req_data.dict()

    req_logit(manage_device, request, req_data)

    results = []

    with BIG() as big:
        for ip in req_data['ips']:
            status, response = big.manage_device(dns_template=req_data['dns_template'], ip=ip,
                                                 ip_name='Name not provided--Update')
            results.append({'ip': ip, 'status': status, 'result': response})

    res_logit(manage_device, request, results)

    return Response(status_code=status, content=json.dumps(results), media_type='application/json')


@app.post('/apis/aci/create_dr_environment', tags=['ACI'])
def create_dr_environment(request: Request, req_data: CreateDREnvironment):
    """Runs the DR script for the specified ACI environment"""
    req_data = req_data.dict()

    if not validate_api_key(req_data.pop('APIKey')):
        return Response(status_code=403, content='Unauthorized')

    req_logit(create_dr_environment, request, req_data)

    env = ACIEnvironment(req_data['Environment'])

    status, response = apic_utils.create_dr_env(env.Name, env.DREnv)

    return Response(status_code=status, content=json.dumps(response), media_type='application/json')


@app.post('/apis/aci/migrate_to_admz', tags=['ACI'])
def migrate_to_admz(request: Request, req_data: MigrateToADMZ):
    """This API takes a target EPG and subnet and migrates it to the ADMZ Tenant in the specified environment."""
    disable = False

    if disable is True:
        return Response(status_code=200, content=json.dumps(['API Disabled']), media_type='application/json')

    env = req_data.AvailabilityZone
    epg = req_data.EPG
    tenant = req_data.Tenant
    subnet = req_data.Subnet
    next_hop = req_data.NextHopFirewall
    fw_vlan = req_data.FirewallVLAN

    req_data = req_data.dict()

    if not validate_api_key(req_data.pop('APIKey')):
        return Response(status_code=401, content=json.dumps(['Unauthorized']), media_type='application/json')

    req_logit(migrate_to_admz, request, req_data)

    status, response = apic_utils.migrate_to_admz(env=env, epg=epg, subnet=subnet, next_hop=next_hop, fw_vlan=fw_vlan,
                                                  tenant=tenant)

    return Response(status_code=status, content=json.dumps(response), media_type='application/json')


@app.get('/apis/nexus/get_subnet_information', tags=['Nexus'])
def get_subnet_information(request: Request, ip: str=None):
    """This API looks for the subnet of the queried IP and attempts to login to the gateway device.  If successful,
    information about the device and subnet is returned."""
    req_logit(get_subnet_information, request, ip)

    if ip is None:
        ip = request.query_params.get('ip')

    try:
        ip = IPv4Address(ip)
    except AddressValueError:
        return Response(status_code=400, content=json.dumps({'error': 'The supplied value is not a valid IP address'}),
                        media_type='application/json')

    status, response = subnet_info_lookup(ip=ip.exploded)

    return Response(status_code=status, content=json.dumps(response), media_type='application/json')


@app.get('/apis/nexus/resolve_ip_to_datacenter', tags=['Nexus'])
def resolve_ip_to_datacenter(request: Request, ip: str=None):
    """This API looks up the origin ASN of a comma separated list of IP addresses using a list of cached prefixes to
    determine the originating data center"""
    if ip is None:
        ip = request.query_params.get('ip')

    req_logit(resolve_ip_to_datacenter, request, ip)

    ips = ip.split(',')
    ips = [IPv4Network(ip) for ip in ips]

    gh = GithubAPI()
    data = json.loads(gh.get_file_content('datacenter/prefix_cache.json'))
    data = [(IPv4Network(prefix), int(asn)) for prefix, asn in data]

    results = {}

    for ip in ips:
        candidates = [x for x in data if x[0].overlaps(ip)]
        # Sort candidates by prefix length, closest match is in last position after sort
        candidates.sort(key=lambda x: x[0].prefixlen)

        if candidates:
            prefix, asn = candidates[-1]
            results.update(**dict(ip=ip.network_address.exploded, datacenter=DataCenter.get_dc_by_asn(asn).__dict__))
        else:
            results.update(**dict(ip=ip.network_address.exploded, datacenter=None))

    return results


@app.get('/apis/nexus/{env}/get_vlan_information/{vlan}', tags=['Nexus'])
def nexus_get_vlan_information(request: Request, env: str, vlan: str):
    """Get Information about a VLAN in a Nexus environment"""
    req_logit(nexus_get_vlan_information, request)

    status, response = NXOS.get_vlan_information(env=env, vlan=vlan)

    res_logit(nexus_get_vlan_information, request, response)

    return Response(status_code=status, content=json.dumps(response), media_type='application/json')


@app.get('/apis/f5/gtm_reverse_lookup/{vip}', tags=['F5'])
def gtm_reverse_lookup(request: Request, vip: str = None):
    """Lookup what Wide IPs resolve to the specified VIP"""
    from bigip.utils import GTM

    req_logit(gtm_reverse_lookup, request, vip)

    status, response = GTM.reverse_lookup(vip_address=vip)

    res_logit(gtm_reverse_lookup, request, response)

    return Response(status_code=status, content=json.dumps(response), media_type='application/json')


def subnet_info_lookup(ip: str):
    fabric = False

    with IOSXR('10.0.255.46') as xr, IOSXR('10.64.255.95') as fw:
        xr_prefix = xr.ip_lookup(ip)
        fw_prefix = fw.ip_lookup(ip)

        # Check to make sure a route was found before continuing
        if xr_prefix or fw_prefix:
            pass
        else:
            return 404, {'message': 'No specific route found for the given IP'}

        xr_route = (xr.route_lookup(xr_prefix) if xr_prefix else None)
        fw_route = (fw.route_lookup(fw_prefix) if fw_prefix else None)

        if xr_route:
            xr.bgp_lookup(xr_route)
        if fw_route:
            fw.bgp_lookup(fw_route)

    network = (xr_route.network if xr_route else fw_route.network)

    # Try to connect to the gateway device.  Assumption: First available IP is the gateway address (True 99.9%)
    device = {
        'host': f'{(network.network_address + 1 if network.prefixlen < 32 else network.network_address)}',
        'username': os.getenv('netmgmtuser'),
        'password': os.getenv('netmgmtpass'),
        'banner_timeout': 8,
        'device_type': 'generic'
    }

    try:
        with netmiko.ConnectHandler(**device) as host:
            output = host.send_command('show version | include Software', expect_string=r'#')

        nx = re.search('NX.OS', output, flags=re.IGNORECASE)
        xr = re.search('IOS.XR', output, flags=re.IGNORECASE)
    except netmiko.exceptions.NetmikoTimeoutException:
        fabric = True  # Not necessarily True, but likely.  If not fabric, it would be F5 or firewall.
        nx = False
    except netmiko.exceptions.AuthenticationException:
        return 500, {'error': 'Unexpected authentication error occurred.  Please try again.'}
    # except netmiko.exceptions.ReadTimeout:
    # TODO: I think I can get rid of this section now
    #     # TODO: For some reason Nexus 7010s are causing a ReadTimeout when using 'generic' as the device_type.  Need
    #        to figure that out.  Exception handling has been added in the meantime
    #     # This usually seems to mean NX-OS.  Set
    #     nx = True

    if fabric:
        # Determine Origin AS
        asn = {xr_route.origin_as, fw_route.origin_as}
        try:
            asn.remove(None)
        except KeyError:
            pass
        origin_as = list(asn)[0]

        envs = json.load(open('data/ACIEnvironments.json'))
        for env in envs['Environments']:
            if origin_as == env['ASN']:
                resp = requests.get(f'http://localhost:8080'
                                    f'/apis/aci/{env["Name"]}/get_aci_subnet/{network.network_address}')
                if not resp.ok:
                    return resp.status_code, resp.json()
                if resp.json()['bridge_domain']:
                    if not resp.json()['endpoint_count']:
                        continue
                elif resp.json()['l3out']:
                    pass
                else:
                    # We most likely never found anything that matched
                    return 404, {'error': 'Nothing found when searching ACI fabrics'}

                response = {
                    'ActiveGateway': env['Name'],
                    'Subnet': resp.json()['subnet'],
                    'Description': resp.json()['consumers'][0],
                    'Interface': (resp.json()['l3out'] if resp.json()['l3out'] else resp.json()['bridge_domain']),
                    'VLAN': (resp.json()['vlans'][0]
                             if resp.json()['vlans'].__len__() == 1 else resp.json()['vlans']),
                    'aci_fabric': fabric
                }
                return 200, response
        return 400, {'message': 'This network may be supported by a firewall or F5', 'network': network.with_prefixlen}
    elif nx:
        with NXOS(f'{(network.network_address + 1 if network.prefixlen < 32 else network.network_address)}') as host:
            try:
                subnet = next(s for s in host.subnets if s.network.overlaps(IPv4Network(ip)))
            except StopIteration:
                return 404, {'message': f'Network not found on {host.hostname}'}

            response = {
                'ActiveGateway': host.hostname,
                'Subnet': subnet.network.with_prefixlen,
                'Description': subnet.description,
                'Interface': subnet.interface.name,
                'VLAN': subnet.vlan,
                'aci_fabric': fabric
            }
    elif xr:
        with IOSXR(f'{(network.network_address + 1 if network.prefixlen < 32 else network.network_address)}') as host:
            try:
                subnet = next(s for s in host.subnets if s.network.overlaps(IPv4Network(ip)))
            except StopIteration:
                return 404, {'message': f'Network not found on {host.hostname}'}

            response = {
                'ActiveGateway': host.hostname,
                'Subnet': subnet.network.with_prefixlen,
                'Description': subnet.description,
                'Interface': subnet.interface.name,
                'VLAN': subnet.vlan,
                'aci_fabric': fabric
            }

    else:
        with IOSXE(f'{(network.network_address + 1 if network.prefixlen < 32 else network.network_address)}') as host:
            try:
                subnet = next(s for s in host.subnets if s.network.overlaps(IPv4Network(ip)))
            except StopIteration:
                return 404, {'message': f'Network not found on {host.hostname}'}

            response = {
                'ActiveGateway': host.hostname,
                'Subnet': subnet.network.with_prefixlen,
                'Description': subnet.description,
                'Interface': subnet.interface.name,
                'VLAN': subnet.vlan,
                'aci_fabric': fabric
            }

    return 200, response


@app.get('/apis/subnet_exists', tags=['IPAM', 'Nexus'])
def subnet_exists(request: Request, cidr: str):
    """Returns True if a network that matches or overlaps with the specified CIDR address is found in the enterprise
    routing table.  Returns False otherwise."""
    from iosxr.utils import subnet_exists as f_subnet_exists

    req_logit(subnet_exists, request)

    status, response = f_subnet_exists(cidr=cidr)

    return Response(status_code=status, content=json.dumps(response), media_type='application/json')


@app.get('/apis/f5/get_pool_members', tags=['F5'])
def get_pool_members(request: Request, fqdn: str):
    """Returns a list pool members of an F5 VIP.  Lookup is based on the supplied FQDN"""
    from bigip.utils import LTM

    req_logit(get_pool_members, request)

    response = LTM.get_pool_members_by_fqdn(fqdn)
    return response


@app.get('/apis/f5/get_vip_info_by_fqdn/{fqdn}', tags=['F5'])
def get_vip_info_by_fqdn(request: Request, fqdn: str):
    """Returns a JSON representation of the F5 hierarchical structure associated with the supplied FQDN"""
    from bigip.utils import LTM

    req_logit(get_vip_info_by_fqdn, request)

    response = LTM.get_vip_info_by_fqdn(fqdn)

    return response


@app.post('/apis/f5/add_member_to_vip', tags=['F5'])
def add_member_to_vip(request: Request, req_data: AddMemberToPool):
    """Add a member to an existing F5 VIP."""
    req_data = req_data.dict()

    if not validate_api_key_onbase(req_data.pop('APIKey')):
        return Response(status_code=401, content=json.dumps({'message': 'Invalid API Key'}))

    req_logit(add_member_to_vip, request, req_data)

    status, response = LTM.add_member_to_pool(**req_data)

    res_logit(add_member_to_vip, request, response)

    return Response(status_code=status, content=json.dumps(response), media_type='application/json')


@app.post('/apis/f5/remove_member_from_vip', tags=['F5'])
def remove_member_from_vip(request: Request, req_data: RemoveMemberFromPool):
    """Remove a member from an existing F5 VIP."""
    req_data = req_data.dict()

    if not validate_api_key_onbase(req_data.pop('APIKey')):
        return Response(status_code=401, content=json.dumps({'message': 'Invalid API Key'}))

    req_logit(add_member_to_vip, request, req_data)

    status, response = LTM.remove_member_from_pool(**req_data)

    res_logit(remove_member_from_vip, request, response)

    return Response(status_code=status, content=json.dumps(response), media_type='application/json')


@app.post('/apis/f5/{environment}/create_app_load_balancer', tags=['F5'])
def create_app_load_balancer(request: Request, environment: str, req_data: CreateAppLB):
    """Creates a new F5 Virtual Server.  This request will also create DNS records when the GTM environment is
    authoritative for the DNS suffix."""
    req_data = req_data.dict()

    if not validate_api_key(req_data.pop('APIKey')):
        return Response(status_code=401, content=json.dumps({'message': 'Invalid API Key'}))

    req_logit(create_app_load_balancer, request, req_data)

    ltm = LTM.login_to_environment(env=environment)
    status, response = ltm.create_app_lb(**req_data)

    res_logit(create_app_load_balancer, request, response)

    return Response(status_code=status, content=json.dumps(response), media_type='application/json')


@app.post('/apis/ipam/update_ips', tags=['IPAM'])
def update_ips(request: Request, req_data: UpdateIPs):
    """Updates the name(s) of assigned IP address(es) in Proteus.  If the IP is unassigned, no action is taken."""
    req_data = req_data.dict()

    if not validate_api_key(req_data.pop('APIKey')):
        return Response(status_code=401, content=json.dumps({'message': 'Not Authorized'}),
                        media_type='application/json')

    req_logit(update_ips, request, req_data)

    res_data = {'Assigned': [], 'Updated': []}

    big = BIG()

    for ip_address in req_data['Updates']:
        if not valid_ip(ip_address['ip']):
            continue

        _ = big.assign_ip(ipaddress=ip_address['ip'], name=ip_address['name'])
        res_data['Updated'].append(ip_address)

    big.logout()

    res_logit(update_ips, request, res_data)

    return res_data


@app.post('/apis/checkpoint/proxy_pac_exception', tags=['Checkpoint'])
def proxy_pac_exception(request: Request, req_data: ProxyPACException,
                        credentials: HTTPBasicCredentials=Depends(http_basic_security)):
    """Adds a domain object to a group object that permits direct outbound Internet connections to approved URLs."""
    from checkpoint.CheckpointUtilities import proxy_pac_exception

    log_data = req_data.dict()

    if not validate_api_key(log_data.pop('APIKey')):
        return Response(status_code=403, content=json.dumps({'message': 'Invalid APIKey provided'}),
                        media_type='application/json')

    req_logit(proxy_pac_exception, request, log_data)

    if req_data.Directive == 'proxy':
        return {'message': 'Rule not needed for proxy directive'}
    req_data.__delattr__('Directive')
    req_data.__delattr__('APIKey')

    status, response = proxy_pac_exception(**req_data.dict(), **credentials.dict())

    return Response(status_code=status, content=json.dumps(response), media_type='application/json')


@app.post('/apis/checkpoint/flexvpn/add_networks', tags=['Checkpoint'])
def add_flex_vpn_networks(request: Request, req_data: FlexVPNNetworksRequests):
    # disable = False
    from checkpoint.CheckpointUtilities import AddNetworksToFlexVPN

    req_data = req_data.dict()

    if not validate_api_key(req_data.pop('APIKey')):
        return Response(status_code=401, content=json.dumps({'message': 'Unauthorized'}), media_type='application/json')

    req_logit(add_flex_vpn_networks, request, req_data)

    # TODO: Add Authentication check here!!!!!

    AddNetworksToFlexVPN(**req_data)

    return Response(status_code=202, content=json.dumps({'message': 'Accepted'}),
                    headers={'Location': 'https://pyapis.app.medcity.net/apis/checkpoint/policy-progress/Colo_Aruba'})


@app.post('/apis/checkpoint/flexvpn/remove_networks', tags=['Checkpoint'])
def remove_flex_vpn_networks(request: Request, req_data: FlexVPNNetworksRequests):
    # disable = False
    from checkpoint.CheckpointUtilities import RemoveNetworksFromFlexVPN

    req_data = req_data.dict()

    if not validate_api_key(req_data.pop('APIKey')):
        return Response(status_code=401, content=json.dumps({'message': 'Unauthorized'}), media_type='application/json')

    req_logit(remove_flex_vpn_networks, request, req_data)

    RemoveNetworksFromFlexVPN(**req_data)

    return Response(status_code=202, content=json.dumps({'message': 'Accepted'}),
                    headers={'Location': 'https://pyapis.app.medcity.net/apis/checkpoint/policy-progress/Colo_Aruba'})


@app.post('/apis/checkpoint/parallon/add_lab_rule', tags=['Checkpoint'])
def parallon_dev_rule(request: Request, req_data: AddFirewallRule):
    """Adds a new rule to the Parallon-TestDev-Evnironment firewall policy.
    Type should be 'host' or 'network'.
    Services should be defined as Protocol-Port  (ex: TCP-443 : or for a range: TCP-5000-5003)"""
    from checkpoint.CheckpointUtilities import CheckpointAPI

    req_data = req_data.dict()

    if req_data.pop('APIKey') != os.getenv('parallonkey'):
        return Response(status_code=401, content=json.dumps({'message': 'Invalid API Key'}),
                        media_type='application/json')

    req_logit(parallon_dev_rule, request, req_data)

    status, response = CheckpointAPI.ParallonDevRule(**req_data)

    res_logit(parallon_dev_rule, request, response)

    return Response(status_code=status, content=json.dumps(response), media_type='application/json')


@app.post('/apis/checkpoint/add_firewall_rule', tags=['Checkpoint'])
def add_firewall_rule(request: Request, req_data: AddFirewallRule):
    """Adds a new firewall rule under the Automated Rules section in all relevant Security Policies"""
    req_data = req_data.dict()

    if not validate_api_key(req_data.pop('APIKey')):
        return Response(status_code=401, content=json.dumps({'message': 'Unauthorized'}), media_type='application/json')

    req_logit(add_firewall_rule, request, req_data)

    status, response = CheckpointAPI.CreateAccessRule(**req_data)

    res_logit(add_firewall_rule, request, response)

    return Response(status_code=status, content=json.dumps(response), media_type='application/json')


@app.get('/apis/checkpoint/generate_policy_list', tags=['Checkpoint'])
def generate_fw_policy_list(request: Request, ips: str):
    """Provides a list of firewall policies that need to be updated given a piped list of source and destination IP
    addresses.  This API accepts Piped list of IPs and CIDRs.  (ie  10.234.160.138|10.249.8.0/24)"""
    req_logit(generate_fw_policy_list, request, ips)

    ips = ips.split('|')

    status, response = generate_policy_list(ips=ips)

    return Response(status_code=status, content=json.dumps(response), media_type='application/json')


@app.get('/apis/checkpoint/policy-progress/{policy_name}', tags=['Checkpoint'])
def get_policy_push_progress(request: Request, policy_name: str=None):
    """Returns the policy push progress for the specified Checkpoint security policy."""
    from checkpoint.CheckpointUtilities import CheckpointAPI

    req_logit(get_policy_push_progress, request)

    progress = CheckpointAPI.GetPolicyPushProgress(policy_name)

    if progress == 'Completed':
        return Response(status_code=202, content='See Other',
                        headers={'Location': 'https://pyapis.app.medcity.net/apis/checkpoint/'
                                             'policy-progress/completed'})
    else:
        return Response(status_code=200, content=progress)


@app.get('/apis/checkpoint/policy-progress/completed', tags=['Checkpoint'],)
def return_completed_policy_push():
    return {'message': 'Policy Push Complete'}


@app.get('/apis/checkpoint/test-QOL', tags=['Checkpoint'])
def queue_qol_policy_push():
    """Queues the policy installation of the QOLab-Simplified Checkpoint security policy"""
    from checkpoint import CheckpointUtilities

    api = CheckpointUtilities.CheckpointAPI()
    api.Username = 'corpsvcfwlautomation'
    api.Domain = 'Lab'

    api.QueuePolicyPush('QO_Lab-Simplified')

    return Response(status_code=202, content='Accepted',
                    headers={'Location': 'https://pyapis.app.medcity.net/apis/'
                                         'checkpoint/policy-progress/QO_Lab-Simplified'})


@app.get('/apis/ise/ipsk/maclookup', tags=['ISE', 'WLC'])
def ipsk_mac_lookup(request: Request, mac: str):
    from ise.iseUtil import ipsk_maclookup

    req_logit(ipsk_mac_lookup, request, mac)

    status, results = ipsk_maclookup(mac)

    res_logit(ipsk_mac_lookup, request, results)

    return Response(status_code=status, media_type='text/plain', content=results)


@app.get('/apis/ise/ts_creds', tags=['ISE'])
def trustsec_lookup(request: Request, ip: str, userid: str = 'ibm6580'):
    from ise.iseUtil import tscreds_lookup

    req_logit(trustsec_lookup, request, ip)

    status, results = tscreds_lookup(ip, userid)

    res_logit(trustsec_lookup, request, results)

    return Response(status_code=status, media_type='text/plain', content=results)


@app.post('/apis/ise/ipsk/mac_add', tags=['ISE', 'WLC'])
def ipsk_mac_add(request: Request, req_data: iPSKMacAdd):
    from ise.iseUtil import ipsk_multi_add

    req_data = req_data.dict()

    if not validate_api_key(req_data.pop('APIKey')):
        return Response(status_code=401, content=json.dumps({'message': 'Unauthorized'}), media_type='application/json')

    req_logit(ipsk_mac_add, request, req_data)

    ident = task_handler.submit_task(func=ipsk_multi_add, **req_data)

    return Response(status_code=202, headers=task_location(ident))


@app.get('/apis/ise/ipsk/psklookup', tags=['ISE', 'WLC'])
@challenge_request
def ipsk_psk_lookup(request: Request, div: str, idg: str, userid: str):
    from ise.iseUtil import psk_lookup, psk_lookup_auth

    req_logit(ipsk_psk_lookup, request, request.path_params)

    status, auth = psk_lookup_auth(userid, div)

    if status == 403:
        return Response(status_code=status, content=auth, media_type='text/plain')

    status, results = psk_lookup(div=div, idg=idg)

    return Response(status_code=status, content=json.dumps(results), media_type='application/json')


@app.get('/apis/ise/wlcradss', tags=['ISE', 'WLC'])
def wlc_radius_ss_lookup(request: Request, ip: str, userid: str = 'ibm6580'):
    from ise.iseUtil import wlcss_lookup

    req_logit(wlc_radius_ss_lookup, request, ip)

    status, results = wlcss_lookup(ip, userid)

    res_logit(wlc_radius_ss_lookup, request, results)

    return Response(status_code=status, media_type='text/plain', content=results)


@app.get('/apis/ise/ipsk/ipskidglist', tags=['ISE'])
def ipsk_idglist(all: bool = False, vlan: bool = True):
    from ise.iseUtil import ipsk_idg_list

    status, results = ipsk_idg_list(all=all, vlan=vlan)

    return Response(status_code=status, content=json.dumps(results), media_type='application/json')


@app.get('/apis/ise/ipsk/ipskdivlist', tags=['ISE'])
def ipsk_divlist():
    from ise.iseUtil import ipsk_div_list

    status, results = ipsk_div_list()

    return Response(status_code=status, content=json.dumps(results), media_type='application/json')


@app.get('/apis/wlc/wlcpower', tags=['WLC'])
def wlcpower(request: Request, ip: str):
    from wlc.wlcUtil import wlc_power

    req_logit(wlcpower, request, ip)

    status, results = wlc_power(ip)

    if status == 404:
        return Response(status_code=status, media_type='text/plain', content=results)

    return Response(status_code=status, content=json.dumps(results), media_type='application/json')


@app.post('/apis/admin/get_current_snmp_strings', include_in_schema=False)
def get_current_snmp_strings(request: Request, req_data: GetCurrentSNMPStrings):
    req_data = req_data.dict()

    if not validate_api_key(req_data.pop('APIKey')):
        return Response(status_code=401)

    req_logit(get_current_snmp_strings, request)

    status, results = NCMIntegration.w_get_snmp_strings(trusted=req_data['Trusted'])

    return Response(status_code=status, content=json.dumps(results), media_type='application/json')


@app.get('/apis/aruba/rap_status', tags=['Aruba'])
def rap_status(request: Request, device: str):
    from aruba.ArubaUtil import get_rap_status

    req_logit(rap_status, request, device)

    status, results = get_rap_status(device)

    res_logit(rap_status, request, results)

    return Response(status_code=status, content=json.dumps(results), media_type='application/json')


@app.get('/apis/iosxr/get_wan_bgp_peer_configs', tags=['IOS-XR'])
def get_wan_bgp_peer_configs(request: Request, host: str, interface: str, vrf: str):
    req_logit(get_wan_bgp_peer_configs, request, [host, interface, vrf])

    result = IOSXR.get_wan_bgp_peer_configs(router_ip=host, parent_interface=interface, vrf=vrf)

    return Response(status_code=200, content=result, media_type='text/plain')
