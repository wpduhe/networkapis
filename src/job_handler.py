import json
import time
import os
import re
import socket
from typing import List
from datetime import datetime
from socket import gethostbyaddr, herror
from apic.utils import ACIJob, APIC
from apic.classes import GenericClass, FabricNode
from ipam.utils import ManagementJob, BIG
from githubapi.utils import GithubAPI
from checkpoint.CheckpointUtilities import CheckpointAPI
from comms import email_notification, DESIGN_AND_DELIVERY_DL, NETWORK_ADVANCED_SUPPORT_DL
from nexus.utils import NXOS
import logging
import sys


formatter = logging.Formatter(fmt='%(asctime)s.%(msecs)03dZ - %(name)s - %(levelname)s - %(message)s',
                              datefmt='%Y-%m-%dT%H:%M:%S')

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
handler.setFormatter(formatter)

logging.basicConfig(level=logging.DEBUG, handlers=[handler])
logger = logging.getLogger(__name__)

logging.getLogger('urllib3').setLevel(logging.WARNING)
logging.getLogger('github').setLevel(logging.WARNING)
logging.getLogger('netmiko').setLevel(logging.WARNING)
logging.getLogger('paramiko').setLevel(logging.WARNING)


class JobHandler:
    leaf_add_automations = ['add_oob_leaf', 'add_new_leaf_pair']

    @staticmethod
    def process_aci_jobs():
        # Check to ensure there are files
        if not g_gh.file_exists(ACIJob.queue_path):
            return None

        logger.debug(f'Processing ACI jobs on {socket.gethostname()}')

        def AND(bool_list: List[bool]):
            """Compares a list of Booleans and returns True if none are False.  Asserts that all values are True"""
            res = True
            for val in bool_list:
                res = val and res
            return res

        for file in g_gh.list_dir(ACIJob.queue_path):
            # filename = key.split('/')[-1]  -- No longer needed
            content = g_gh.get_file_content(f'{ACIJob.queue_path}/{file}')
            try:
                job = ACIJob.load(json.loads(content))
            except json.decoder.JSONDecodeError:
                g_gh.delete_file(file_path=f'{ACIJob.queue_path}/{file}', message='JSON Decode Error')
                g_gh.add_file(file_path=f'{ACIJob.bad_file_path}/{file}', message='JSON DecodeError', content=content)
                continue

            if job.func in JobHandler.leaf_add_automations:
                with APIC(env=job.environment) as apic:

                    # file = key.split('/')[-1]  -- No longer needed
                    nodes = re.findall(r'\d\d+', file)
                    nodes = [FabricNode.load(apic.collect_nodes(node_id=node)) for node in nodes]
                    upgrades_complete = AND([apic.version in node.attributes.version for node in nodes])

                    if upgrades_complete:
                        for config in job.configs:
                            result = apic.post(configuration=config['configuration'], uri=config['uri'])
                            config['result'] = {result.status_code: result.json()}
                            
                        g_gh.add_file(file_path=f'{ACIJob.completed_jobs}/{file}', message='Completed ACIJob',
                                      content=json.dumps(job.__dict__, indent=4))
                        g_gh.delete_file(file_path=f'{ACIJob.queue_path}/{file}', message='Completed ACIJob')
                    continue

            if time.time() >= job.run_time:
                with APIC(env=job.environment) as apic:
                    for config in job.configs:
                        result = apic.post(configuration=config['configuration'], uri=config['uri'])
                        config['result'] = {result.status_code: result.json()}
                        
                    g_gh.add_file(file_path=f'{ACIJob.completed_jobs}/{file}', message='Completed ACIJob',
                                  content=json.dumps(job.__dict__, indent=4))
                    g_gh.delete_file(file_path=f'{ACIJob.completed_jobs}/{file}', message='Completed ACIJob')

        logger.debug(f'ACI jobs completed by {socket.gethostname()}')

    @staticmethod
    def process_mgmt_jobs():
        # Check to ensure there are management jobs
        if not g_gh.file_exists(ManagementJob.queue_path):
            return None

        logger.debug(f'Processing Management Jobs on {socket.gethostname()}')

        def check_record(args: list):
            try:
                result = gethostbyaddr(job.ip)
                if re.match(rf'{args[0]}-{args[1]}-\d+-{args[3]}-{args[4]}.{args[5]}.{args[6]}.mgmt.medcity.net',
                            result[0]):
                    job.completion = list(result)
                    g_gh.add_file(file_path=f'{job.completed_jobs}/{file}', message='Completed ManageentJob',
                                  content=json.dumps(job.__dict__, indent=4))
                    g_gh.delete_file(file_path=f'{job.queue_path}/{file}', message='Completed ManagementJob')
                    return True
                else:
                    return False
            except (herror, IndexError):
                return False

        # Iterate over files in queue path
        for file in g_gh.list_dir(ManagementJob.queue_path):
            content = g_gh.get_file_content(file_path=f'{ManagementJob.queue_path}/{file}')
            try:
                job = ManagementJob.load(json.loads(content))
            except json.decoder.JSONDecodeError:
                g_gh.add_file(f'{ManagementJob.bad_file_path}/{file}', message='JSON Decode Error', content=content)
                g_gh.delete_file(file_path=f'{ManagementJob.queue_path}/{file}', message='JSON Decode Error')
                continue

            # file = key.split('/')[-1]  -- No longer needed
            env = file.split('_')[0]
            node = file.split('_')[1]

            with APIC(env=str(env)) as apic:
                node = FabricNode.load(apic.collect_nodes(node))

                parsed = re.split('[-.]', job.dns_template)

                # Check to see if a host record matching the DNS template has already been created for the given IP:
                #    Could have been by user or prior DNS creation delay caused checks to fail
                if check_record(parsed):
                    continue

                # Verify that the node firmware has been upgraded to match the APIC version, do not manage if not.
                if apic.version not in node.attributes.version:
                    continue

            # Validate SSH access to the requested IP address
            if APIC.check_ssh_to_oob(job.ip):
                with BIG() as big:
                    status, _ = big.manage_device(dns_template=job.dns_template, ip=job.ip, ip_name='Not Provided')

                if status == 200:
                    job.completion = f'{time.asctime()}: Request submitted by automation'
                    g_gh.add_file(file_path=f'{job.completed_jobs}/{file}', message='Completed ManagementJob',
                                  content=json.dumps(job.__dict__, indent=4))
                    g_gh.delete_file(file_path=f'{job.queue_path}/{file}', message='Completed ManagementJob')
                else:
                    continue

        logger.debug(f'Management jobs completed by {socket.gethostname()}')

    @staticmethod
    def process_fw_policy_push():
        # Check to ensure there are pending policy pushes
        if not g_gh.file_exists('pyapis/checkpoint/policy_push_queue'):
            return None
        files = g_gh.list_dir('pyapis/checkpoint/policy_push_queue')

        if files:
            for policy in files:
                # TODO: Add Checkpoint change freeze check
                # if change_freeze():
                #     continue
                api = CheckpointAPI()
                api.Domain = policy.split('/')[2].split('--')[1].split('.')[0]
                api.IPAddress = '10.26.1.96'
                api.SessionDescription = 'PolicyPushAutomation'
                api.SessionName = 'PolicyPushAutomation'
                api.Password = os.getenv('fwpassword')

                api.Login()

                uri = '/web_api/install-policy'

                policy_json = g_gh.get_file_content(f'pyapis/checkpoint/policy_push_queue/{policy}')
                policy_json = json.loads(policy_json)

                install_attempt = api.PostJSON(uri, policy_json)

                if 200 <= install_attempt.status_code < 300:
                    # Delete the file since the policy push was successful

                    g_gh.add_file(file_path=f'pyapis/checkpoint/policy_push_queue'
                                            f'/{policy.replace(".json", "_InProgress.json")}', message='Policy Push',
                                  content=json.dumps(policy_json, indent=4))
                    g_gh.delete_file(file_path=f'pyapis/checkpoint/policy_push_queue/{policy}', message='Policy Push')
                    policy = policy.replace('.json', '_InProgress.json')
                    policy_content = json.dumps(policy_json, indent=4)

                    task_id = install_attempt.json()['task-id']

                    # Report on Status
                    x = 0
                    while x < 300:
                        status = api.GetTaskStatus(task_id).json()
                        currentprogress = f"{status['tasks'][0]['status']} - " \
                                          f"{status['tasks'][0]['progress-percentage']}"
                        policy_status = f'{policy_content}\n{currentprogress}'
                        #                 path='checkpoint/policy_push_queue')
                        g_gh.update_file(f'pyapis/checkpoint/policy_push_queue/{policy}', message='Pushing Policy',
                                         content=policy_status)
                        if status['tasks'][0]['progress-percentage'] == 100:
                            g_gh.delete_file(f'pyapis/checkpoint/policy_push_queue/{policy}',
                                             message='Policy Push Completed')
                            break
                        x += 1
                        time.sleep(30)
                api.Logout()

    # @staticmethod
    # def completed_job_cleanup():
    #         current_time = datetime.datetime.now(tz=obj.LastModified.tzinfo)
    #         delta = current_time - obj.LastModified
    #         if delta.days > 90:

    @staticmethod
    def check_fabric_supervisor_lifetimes(run_now: bool=False, force: bool=False, score: int=90,
                                          recipients: List[str]=None):
        def check_fabrics():
            logger.debug('Checking Fabric Lifetimes')
            environments = json.load(open('data/ACIEnvironments.json'))

            d = ''

            for environment in environments['Environments']:
                if environment['Name'].lower() != 'parallon-dev':
                    apic = APIC(env=environment['Name'])

                    flashes = apic.get('/api/class/eqptFlash.json').json()['imdata']
                    flashes = [GenericClass.load(_) for _ in flashes]

                    for flash in flashes:
                        if int(flash.attributes.lifetime) >= score:
                            # Flash memory reaching critical limits get Leaf information to report on it
                            node_id = re.search(r'node-(\d+)', flash.attributes.dn).group(1)
                            node = FabricNode.load(apic.collect_nodes(node_id=node_id))

                            d += f'<table>' \
                                 f'<tr><td>{"Availability Zone:":<22}</td><td>{apic.env.Name}</td></tr>' \
                                 f'<tr><td>{"Node Name:":<22}</td><td>{node.attributes.name}</td></tr>' \
                                 f'<tr><td>{"Node Model:":<22}</td><td>{node.attributes.model}</td></tr>' \
                                 f'<tr><td>{"Node Serial:":<22}</td><td>{node.attributes.serial}</td></tr>' \
                                 f'<tr><td>{"Flash Lifetime:":<22}</td><td>{flash.attributes.lifetime}</td></tr>' \
                                 f'</table>\n'

                            logger.debug(f'Fabric flash lifetime reached: {apic.env.Name} {node.attributes.name} '
                                         f'{node.attributes.serial}')
            return d

        if force:
            pass
        elif not socket.gethostname().lower().startswith('pyapis-prd'):
            return None

        now = datetime.now()

        if now.isoweekday() == 1 and now.hour == 6 and 0 <= now.minute <= 5:
            data = check_fabrics()
        elif run_now:
            data = check_fabrics()
        else:
            return None

        if data:
            if recipients:
                email_notification(receivers=recipients,
                                   subject='Fabric Node Flash Lifetime Warnings', msg_text=data)
            else:
                recipients = [DESIGN_AND_DELIVERY_DL, NETWORK_ADVANCED_SUPPORT_DL]
                email_notification(receivers=recipients,
                                   subject='Fabric Node Flash Lifetime Warnings', msg_text=data)

    @staticmethod
    def prefix_cache(force: bool=False):
        dt = datetime.now()
        if 0 <= dt.minute <= 5 or force:
            logger.debug(f'Updating prefix cache')

            xr = NXOS('10.0.255.19')  # XRDC Core-1
            fw = NXOS('10.64.255.72')  # FWDC Core-1

            # Get only routes that have AS paths
            xr_bgp_output = xr.exec_command('show ip bgp regexp "[0-9]$" | include / | exclude 0.0.0.0/0 | no-more')
            fw_bgp_output = fw.exec_command('show ip bgp regexp "[0-9]$" | include / | exclude 0.0.0.0/0 | no-more')

            xr_bgp_output = xr_bgp_output.split('\n')
            fw_bgp_output = fw_bgp_output.split('\n')

            xr_bgp_output.remove('')
            fw_bgp_output.remove('')

            xr_bgp_routes = set(re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}).*?(\d+)\D+$', line).groups()
                                for line in xr_bgp_output)
            fw_bgp_routes = set(re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}).*?(\d+)\D+$', line).groups()
                                for line in fw_bgp_output)

            prefixes = xr_bgp_routes.union(fw_bgp_routes)

            g_gh.update_file('datacenter/prefix_cache.json', message='prefix_cache_update',
                             content=json.dumps(list(x for x in prefixes), indent=2))
            logger.debug('Prefix cache updated')

        return


if __name__ == '__main__':
    g_gh = GithubAPI()
    JobHandler.process_aci_jobs()
    JobHandler.process_mgmt_jobs()
    JobHandler.process_fw_policy_push()
    JobHandler.prefix_cache()
    # JobHandler.completed_job_cleanup()
    JobHandler.check_fabric_supervisor_lifetimes()


def run_job_handler():
    """Function called upon the instantiation of the application server which recalls itself at completion."""
    # Added while statement so that this function is started in a separate thread that never stops.
    while True:
        logger.debug('JobHandler sleeping...')
        time.sleep(300)
        logger.debug('JobHandler waking up...')
        global g_gh
        g_gh = GithubAPI()
        JobHandler.process_aci_jobs()
        JobHandler.process_mgmt_jobs()
        JobHandler.process_fw_policy_push()
        JobHandler.prefix_cache()
        # JobHandler.completed_job_cleanup()
        JobHandler.check_fabric_supervisor_lifetimes()
