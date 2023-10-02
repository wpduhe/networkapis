#! python3

from data.environments import ACIEnvironment
import argparse
import requests


parser = argparse.ArgumentParser(description='Automated copy of an entire application profile and its EPGs and Bridge '
                                             'Domains to the DR Testing environment.  Optionally assigns VLANs and '
                                             'attaches the EPGs to AEP(s)',
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('-E', '--environment', help='Specifies the source environment of the AP',
                    required=True)
parser.add_argument('-T', '--tenant',  help='Specifies the tenant of the AP', required=True)
parser.add_argument('-A', '--app-profile', help='Specifies the AP to be copied', required=True)
parser.add_argument('--aeps', help='Comma separated -no spaces- list of AEPs to where the EPGs should '
                                   'be attached')
parser.add_argument('--include-epgs', help='Comma separated -no spaces- list of specific EPGs that should be copied')
parser.add_argument('--exclude-epgs', help='Comma separated -no spaces- list of specific EPGs not to copy')
parser.add_argument('--preview-mode', action='store_true', help='Previews what will be copied to DRDC environment')


def display_configs(b, a):
    print('Bridge Domains:')
    for bd in b:
        print(f'  {bd.attributes.name}\n      Subnets:')
        for child in bd.children:
            if child.class_ == 'fvSubnet':
                print(f'{" " * 10}{child.attributes.ip}')
    print(f'\nApplication Profile: {a.attributes.name}\n  EPGs:')
    for child in a.children:
        print(f'      {child.attributes.name}')
    if config['aeps']:
        print(f'\nAttach EPGs to these AEPs:')
        for aep in config['aeps'].split(','):
            print(f'  {aep}')
    return None


def main():
    from apic.utils import APIC
    from apic.classes import AP, BD, InfraRsFuncToEpg

    sedc = ACIEnvironment('sedc')

    bds_to_copy = set()
    bds_to_post = list()

    # Retrieve application profile and associated EPGs and Bridge Domains
    with APIC(env=config['environment']) as apic:
        app_profile = AP.load(apic.collect_aps(tn=config['tenant'], ap=config['app_profile']))

        for epg in app_profile.children[:]:
            # include / exclude logic
            if config['exclude_epgs']:
                if epg.attributes.name in config['exclude_epgs'].split(','):
                    app_profile.children.remove(epg)
                    continue
            elif config['include_epgs']:
                if epg.attributes.name not in config['include_epgs'].split(','):
                    app_profile.children.remove(epg)
                    continue
                else:
                    pass

            # include / exclude logic
            for child in epg.children[:]:
                if child.class_ != 'fvRsBd':
                    epg.children.remove(child)
                else:
                    bds_to_copy.add(child.attributes.tnFvBDName)

            epg.domain(sedc.PhysicalDomain)

        for bd in bds_to_copy:
            bd = BD.load(apic.collect_bds(tn=config['tenant'], bd=bd))
            bd.attributes.__delattr__('dn')
            for child in bd.children[:]:
                if child.class_ == 'fvRsCtx':
                    child.attributes.tnFvCtxName = 'vrf-drtest'
                elif child.class_ == 'fvRsBDToOut':
                    child.attributes.tnL3extOutName = 'L3Out-Core-DRTEST'
                elif child.class_ == 'fvSubnet':
                    pass
                else:
                    bd.children.remove(child)

            bds_to_post.append(bd)

    app_profile.attributes.status = 'created,modified'
    app_profile.attributes.__delattr__('dn')

    display_configs(bds_to_post, app_profile)

    # Preview Mode process
    if config['preview_mode']:
        return None
    else:
        # Verify intent to copy these configurations
        a = ''
        while not a or (a.lower()[0] != 'y' and a.lower()[0] != 'n'):
            a = input('Are you sure you wish to POST these configurations to DRDC? (y/n): ')

        if a.lower().startswith('n'):
            print('Aborting...')
            return None

        # POST Bridge Domain, Application profile, and EPG configurations to SEDC DR fabric
        with APIC(env='sedc') as apic:
            for bd in bds_to_post:
                apic.post(bd.json(), uri='/api/mo/uni/tn-tn-DRTEST.json')

            apic.post(app_profile.json(), uri='/api/mo/uni/tn-tn-DRTEST.json')

            # Assign VLANs for the EPGs that were created
            if config['aeps']:
                config['aeps'] = config['aeps'].split(',')

                for aep in config['aeps']:
                    for epg in app_profile.children:
                        response = requests.get(f'https://pyapis.ocp.app.medcity.net/apis/v2/aci/SEDC/get_vlan_data?'
                                                f'EPG={epg.attributes.name}',
                                                verify=False).json()
                        attach = InfraRsFuncToEpg()
                        attach.attributes.dn = f'uni/infra/attentp-{aep}/gen-default/rsfuncToEpg-[uni/tn-tn-DRTEST/' \
                                               f'ap-{app_profile.attributes.name}/epg-{epg.attributes.name}]'
                        attach.attributes.mode = 'regular'
                        attach.attributes.encap = f'vlan-{response[0]["VLAN"] if response else apic.get_next_vlan()}'
                        attach.attributes.status = 'created'
                        apic.post(attach.json())


if __name__ == '__main__':
    args = parser.parse_args()
    config = vars(args)

    if config['environment'] and config['tenant'] and config['app_profile']:
        main()
