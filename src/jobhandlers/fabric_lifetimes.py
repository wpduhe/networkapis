from comms import email_notification, DESIGN_AND_DELIVERY_DL, NETWORK_ADVANCED_SUPPORT_DL
from apic.classes import APICObject, FabricNode
from apic.utils import APIC
from typing import List
import logging
import socket
import json
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


def main(score: int = 90, recipients: List[str] = None):
    def check_fabrics():
        logger.debug('Checking Fabric Lifetimes')
        environments = json.load(open('data/ACIEnvironments.json'))

        d = ''

        for environment in environments['Environments']:
            if environment['Name'].lower() != 'parallon-dev':
                apic = APIC(env=environment['Name'])

                logger.debug(f'Logged into {apic.env.Name}. Checking lifetimes...')

                flashes = apic.get('/api/class/eqptFlash.json').json()['imdata']
                flashes = [APICObject.load(_) for _ in flashes]

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

    data = check_fabrics()

    if data:
        if recipients:
            email_notification(receivers=recipients,
                               subject='Fabric Node Flash Lifetime Warnings', msg_text=data)
        else:
            recipients = [DESIGN_AND_DELIVERY_DL, NETWORK_ADVANCED_SUPPORT_DL]
            email_notification(receivers=recipients,
                               subject='Fabric Node Flash Lifetime Warnings', msg_text=data)


if __name__ == '__main__':
    logger.debug('Checking fabric lifetimes')
    if socket.gethostname().lower().startswith('networkapis'):
        logger.debug('Host check passed... proceeding')
        main()
