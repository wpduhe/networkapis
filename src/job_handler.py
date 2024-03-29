import json
import time
import os
import re
# import requests
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


class JobHandler:
    leaf_add_automations = ['add_oob_leaf', 'add_new_leaf_pair']

    @staticmethod
    def process_aci_jobs():
        # Check to ensure there are files
        if not g_gh.file_exists(ACIJob.queue_path):
            print('No ACI jobs are queued')
            return None

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

    @staticmethod
    def process_mgmt_jobs():
        # Check to ensure there are management jobs
        if not g_gh.file_exists(ManagementJob.queue_path):
            print('No management jobs are queued')
            return None

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

    @staticmethod
    def process_fw_policy_push():
        # Check to ensure there are pending policy pushes
        if not g_gh.file_exists('pyapis/checkpoint/policy_push_queue'):
            print('No Checkpoint policy pushes are queued')
            return None
        files = g_gh.list_dir('pyapis/checkpoint/policy_push_queue')

        if files:

            print(f'Checking for pending policy installs.')

            for policy in files:
                print(f'Found {policy}')
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
            return d

        if force:
            pass
        elif not socket.gethostname().lower().startswith('pyapis01'):
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


if __name__ == '__main__':
    g_gh = GithubAPI()
    JobHandler.process_aci_jobs()
    JobHandler.process_mgmt_jobs()
    JobHandler.process_fw_policy_push()
    # JobHandler.completed_job_cleanup()
    JobHandler.check_fabric_supervisor_lifetimes()


def run_job_handler():
    """Function called upon the instantiation of the application server which recalls itself at completion."""
    # Added while statement so that this function is started in a separate thread that never stops.
    while True:
        time.sleep(300)
        global g_gh
        g_gh = GithubAPI()
        print('JobHandler Starting...')
        JobHandler.process_aci_jobs()
        JobHandler.process_mgmt_jobs()
        JobHandler.process_fw_policy_push()
        # JobHandler.completed_job_cleanup()
        JobHandler.check_fabric_supervisor_lifetimes()
        print('JobHandler Finished.')
