from githubapi.utils import GithubAPI
from job_handler import ManagementJob
from apic.classes import FabricNode
from apic.utils import APIC
from ipam.utils import NetworkAPIIPAM
import logging
import socket
import json
import time
import sys
import re


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


def main():
    logger.debug('Checking to see if management jobs are present')
    if not gh.file_exists(ManagementJob.queue_path):
        logger.debug('No management jobs were present')

        return None

    logger.debug(f'Processing Management Jobs on {socket.gethostname()}')

    def check_record(args: list):
        try:
            result = socket.gethostbyaddr(job.ip)
            if re.match(rf'{args[0]}-{args[1]}-\d+-{args[3]}-{args[4]}.{args[5]}.{args[6]}.mgmt.medcity.net',
                        result[0]):
                job.completion = list(result)
                gh.add_file(file_path=f'{job.completed_jobs}/{file}', message='Completed ManagementJob',
                            content=json.dumps(job.__dict__, indent=4))
                gh.delete_file(file_path=f'{job.queue_path}/{file}', message='Completed ManagementJob')
                return True
            else:
                return False
        except (socket.herror, IndexError):
            return False

    # Iterate over files in queue path
    for file in gh.list_dir(ManagementJob.queue_path):
        content = gh.get_file_content(file_path=f'{ManagementJob.queue_path}/{file}')
        try:
            job = ManagementJob.load(json.loads(content))
        except json.decoder.JSONDecodeError:
            gh.add_file(f'{ManagementJob.bad_file_path}/{file}', message='JSON Decode Error', content=content)
            gh.delete_file(file_path=f'{ManagementJob.queue_path}/{file}', message='JSON Decode Error')
            continue

        env, node = re.search(r'([^_]+)_(\d+)', file).groups()

        # env = file.split('_')[0]
        # node = file.split('_')[1]

        apic = APIC(env=str(env))

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
            # with BIG() as big:
            #     status, _ = big.manage_device(dns_template=job.dns_template, ip=job.ip, ip_name='Not Provided')
            ipam = NetworkAPIIPAM()

            r = ipam.manage_device(address=job.ip, dns_template=job.dns_template)

            if r.ok:
                job.completion = f'{time.asctime()}: Request submitted by automation'
                gh.add_file(file_path=f'{job.completed_jobs}/{file}', message='Completed ManagementJob',
                            content=json.dumps(job.__dict__, indent=4))
                gh.delete_file(file_path=f'{job.queue_path}/{file}', message='Completed ManagementJob')
            else:
                continue

    logger.debug(f'Management jobs completed by {socket.gethostname()}')


if __name__ == '__main__':
    gh = GithubAPI()
    main()
