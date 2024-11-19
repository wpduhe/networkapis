from typing import List
from githubapi.utils import GithubAPI
from apic.utils import APIC, ACIJob
from apic.classes import FabricNode
import logging
import socket
import sys
import json
import re
import time


LEAF_ADD_AUTOMATIONS = ['add_oob_leaf', 'add_new_leaf_pair']


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
    logger.debug('Checking to see if ACI jobs are present')
    if not gh.file_exists(ACIJob.queue_path):
        logger.debug('No ACI jobs were present')
        return None

    logger.debug(f'Processing ACI jobs on {socket.gethostname()}')

    def AND(bool_list: List[bool]):
        """Compares a list of Booleans and returns True if none are False.  Asserts that all values are True"""
        res = True
        for val in bool_list:
            res = val and res
        return res

    for file in gh.list_dir(ACIJob.queue_path):
        content = gh.get_file_content(f'{ACIJob.queue_path}/{file}')
        try:
            job = ACIJob.load(json.loads(content))
        except json.decoder.JSONDecodeError:
            gh.delete_file(file_path=f'{ACIJob.queue_path}/{file}', message='JSON Decode Error')
            gh.add_file(file_path=f'{ACIJob.bad_file_path}/{file}', message='JSON DecodeError', content=content)
            continue

        if job.func in LEAF_ADD_AUTOMATIONS:
            with APIC(env=job.environment) as apic:

                nodes = re.findall(r'\d\d+', file)
                nodes = [FabricNode.load(apic.collect_nodes(node_id=node)) for node in nodes]
                upgrades_complete = AND([apic.version in node.attributes.version for node in nodes])

                # Create temporary exception for 9300-FX3 leafs in APIC 4.2 environments
                if nodes[0].attributes.model.endswith('-FX3') and int(apic.version[0]) < 5:
                    # Override previous upgrade completion logic to bypass upgrade process for FX3 leafs
                    # This allows the new leaf node(s) to be moved to its appropriate maintenance group even though it
                    # has not been code leveled
                    upgrades_complete = True
                    logger.debug(f'Overriding leaf upgrade check for {" and ".join([n.attributes.id for n in nodes])} '
                                 f'because leaf model does not support APIC version {apic.version}')

                if upgrades_complete:
                    for config in job.configs:
                        result = apic.post(configuration=config['configuration'], uri=config['uri'])
                        config['result'] = {result.status_code: result.json()}

                    gh.add_file(file_path=f'{ACIJob.completed_jobs}/{file}', message='Completed ACIJob',
                                content=json.dumps(job.__dict__, indent=4))
                    gh.delete_file(file_path=f'{ACIJob.queue_path}/{file}', message='Completed ACIJob')
                continue

        if time.time() >= job.run_time:
            with APIC(env=job.environment) as apic:
                for config in job.configs:
                    result = apic.post(configuration=config['configuration'], uri=config['uri'])
                    config['result'] = {result.status_code: result.json()}

                gh.add_file(file_path=f'{ACIJob.completed_jobs}/{file}', message='Completed ACIJob',
                            content=json.dumps(job.__dict__, indent=4))
                gh.delete_file(file_path=f'{ACIJob.completed_jobs}/{file}', message='Completed ACIJob')

    logger.debug(f'ACI jobs completed by {socket.gethostname()}')


if __name__ == '__main__':
    gh = GithubAPI()
    main()
