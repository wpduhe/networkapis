import json
import requests
import re
import os
from data.environments import ACIEnvironment
from apic.apicGet import snapshot, exists, postToApic


def copy_vmm_pgs(env, vmm_domain, aep):
    env = ACIEnvironment(env)

    url = f'https://{env.IPAddress}'
    login_url = f'{url}/api/aaaLogin.json'

    session = requests.Session()
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

    # Take a snapshot of the fabric.  Includes verification
    # if snapshot(env, f'Testing copyVMMPGs {vmmD} to {aep} ') is False:
    #     return 'Automated Snapshot failed.  Task Aborted.'

    # Collect Port Groups from VMM Domain
    vmm_epg_resp = session.get(f'{url}/api/class/vmmEpPD.json?query-target-filter='
                               f'wcard(vmmEpPD.idConsumerDn,"{vmm_domain}")')
    if vmm_epg_resp.ok is False:
        return 'Cannot find VMM Domain, check name and try again'

    vmm_epg_json = json.loads(vmm_epg_resp.text)
    vmm_epg_json = json.loads(json.dumps(vmm_epg_json['imdata']))

    vmm_epg_list = list((re.sub('^.*epg-', 'epg-', x['vmmEpPD']['attributes']['epgPKey']) for x in vmm_epg_json))
    print(vmm_epg_list)

    # Verify whether or not the specified AEP exists
    if exists(env, infraAttEntityP=aep) is True:
        # Since the AEP exists, collect EPGs already assigned to it in order to compare them to the EPGs assigned to the
        # VMM domain
        resp = session.get(f'{url}/api/mo/uni/infra/attentp-{aep}.json?'
                           f'query-target=subtree&target-subtree-class=infraRsFuncToEpg')
        resp = json.loads(resp.text)
        resp = json.loads(json.dumps(resp['imdata']))

        aep_search = list((x['infraRsFuncToEpg']['attributes']['tDn'] for x in resp))

        # Compare list of EPGs from VMM domain to EPGs from AEP and flag any that exist in both.
        for epg in vmm_epg_json:
            if epg['vmmEpPD']['attributes']['epgPKey'] in aep_search:
                epg['vmmEpPD']['attributes']['conflict'] = True
            else:
                epg['vmmEpPD']['attributes']['conflict'] = False

    func_to_epg = []
    proceed_with = []
    manually_figure = []  # Thinking that we will be able to change the encap from vCenter to encap on the AEP

    # Create AEP attachments for each EPG
    for epg in vmm_epg_json:
        # Check conflict flag.  If True then analyze known endpoints and compare their encapsulations to the VMM domain
        if epg['vmmEpPD']['attributes']['conflict'] is True:
            # Set query to EPG name
            query = epg['vmmEpPD']['attributes']['epgPKey'].split('/')[3]
            vmm_encap = epg['vmmEpPD']['attributes']['encap']

            # Query Fabric for EPG endpoints
            resp = session.get(f'{url}/api/class/fvCEp.json?query-target-filter=wcard(fvCEp.dn,"{query}")')
            resp = json.loads(resp.text)
            resp = json.loads(json.dumps(resp['imdata']))

            # Immediately add the VMM encapsulation to the list of encapsulations used for the EPG
            encaps = {vmm_encap}
            # This counter is used to count the number of instances where an endpoint uses the VMM encapsulation
            counter = 0
            for ep in resp:
                for key in ep:
                    # Compare endpoint encapsulation to the VMM encapsulation.  Increment counter if they match.
                    if ep[key]['attributes']['encap'] == vmm_encap:
                        counter += 1
                    # Add the endpoint encapsulation to the set.
                    encaps.add(ep[key]['attributes']['encap'])

            if counter == 0:
                # No endpoints are using the VMM encapsulation.  Therefore, we can change the encapsulation on the VMM
                # port group to be that of the first known encapsulation used by the endpoints and remove the VMM
                # encapsulation from the list of encapsulations.  This practically overwrites the VMM encapsulation
                # with the VLAN used by the endpoints
                encaps.remove(vmm_encap)
                print(query, str(encaps))
                print('No endpoints were known by the VMM encapsulation.  Overwriting the VMM encapsulation')

                # This assigns the non-VMM encapsulation only if there is one known encapsulation for the endpoints.
                # An empty set means that no endpoints were found for the EPG at all.  More than one encap means that
                # overwriting the encapsulation is dangerous.  This exception is accounted for at line 97.
                epg['vmmEpPD']['attributes']['encap'] = (list(encaps)[0] if len(encaps) == 1 else vmm_encap)

            elif len(resp) == counter:
                print(f'All known endpoints in {query} are using the VMM encapsulation.  AEP encapsulation will be '
                      f'overwritten.')
            else:
                print(f'Mutliple encapsulations are in use in {query}.  Manual process will need to be used.')

            if len(encaps) > 1:
                # More than one encapsulation is being used by the endpoints.  So the EPG is added to a list that
                # excludes it from any encapsulation changes.
                print(f'This EPG has more than one known encapsulation: {query}')
                manually_figure.append(epg['vmmEpPD']['attributes']['epgPKey'])
            else:
                # Only one encapsulation is being used by all known endpoints.  Create a AEP to EPG binding that uses
                # that one known encapsulation and add it to the printed configuration.
                print(f'This EPG is okay to have its encapsulation overwritten on {aep}: {query}')
                proceed_with.append(epg['vmmEpPD']['attributes']['epgPKey'])
                func_to_epg.append({
                    'infraRsFuncToEpg': {
                        'attributes': {
                            'tDn': epg['vmmEpPD']['attributes']['epgPKey'],
                            'mode': 'regular',
                            'encap': epg['vmmEpPD']['attributes']['encap'],
                            'status': 'created,modified'
                        }
                    }
                })
        # No conflict exists between the AEP and VMM domain, so the encapsulation from the VMM domain will be used on
        # the AEP.
        else:
            print('No conflict found. {} will be added to AEP with VMM encapsulation'.format(
                epg['vmmEpPD']['attributes']['epgPKey'].split('/')[3]))
            proceed_with.append(epg['vmmEpPD']['attributes']['epgPKey'])
            func_to_epg.append({
                'infraRsFuncToEpg': {
                    'attributes': {
                        'tDn': epg['vmmEpPD']['attributes']['epgPKey'],
                        'mode': 'regular',
                        'encap': epg['vmmEpPD']['attributes']['encap'],
                        'status': 'created,modified'
                    }
                }
            })

    print('\n\n\nProceeding With: ' + str(proceed_with))
    print('Manually Figure: ' + str(manually_figure))
    print(f'These bindings will be added to {aep}:')
    print(func_to_epg)
    input('Review the bindings and ensure you wish to proceed.')

    if len(func_to_epg) > 0:
        aep_config = {
            'infraAttEntityP': {
                'attributes': {
                    'name': aep,
                    'status': 'created,modified'
                },
                'children': [{
                    'infraRsDomP': {
                        'attributes': {
                            'tDn': 'uni/phys-' + env.PhysicalDomain,
                            'status': 'created,modified'
                        }
                    }
                }, {
                    'infraGeneric': {
                        'attributes': {
                            'name': 'default'
                        },
                        'children': func_to_epg
                    }
                }]
            }
        }
    else:
        return 'All port groups already exist on the destination AEP'

    print(aep_config)
    # exit()
    # Post configuration to APIC, then return status and reason
    # resp = postToApic(env, aepConfig, uri='/api/mo/uni/infra.json')
    # return {'Response': '{}: {}'.format(resp.status_code, resp.reason), 'APIC Configuration': aepConfig}

    return aep_config

    # return resp
