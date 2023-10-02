from apic.utils import APIC
from apic.classes import EncapBlock
import sys


def main():
    blocks = []
    with APIC(env=sys.argv[1]) as apic:
        encap_blocks = apic.get(f'/api/class/{EncapBlock.class_}.json?rsp-prop-include=config-only').json()['imdata']
        for block in encap_blocks:
            if block[EncapBlock.class_]['attributes']['role'] == 'internal':
                blocks.append(block[EncapBlock.class_]['attributes']['dn'])
                block[EncapBlock.class_]['attributes']['role'] = 'external'
                block[EncapBlock.class_]['attributes']['status'] = 'modified'
                r = apic.post(configuration=block)
                if not r.ok:
                    print(f'{r.status_code} {r.reason} {r.json()}')
                else:
                    print(f'VLAN block has been updated from "internal" to "external"\n'
                          f'{block[EncapBlock.class_]["attributes"]["role"]}')
    for b in blocks:
        print(b)


if __name__ == '__main__':
    try:
        print(f'Processing VLAN blocks for {sys.argv[1].upper()}\n')
    except IndexError:
        print('Syntax Error: Environment name expected\n\nExample:  encap_block_corrections.py <environment>')
        sys.exit(1)
    main()
