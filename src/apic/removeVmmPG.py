import os


def removeVmmPG(env, epg, vmmD, execute=False) :
    import json, requests
    from networkapis import GetAvailabilityZones
    from creds import creds

    env = GetAvailabilityZones.GetAvailabilityZones(env=env)

    url = 'https://' + env['IPAddress'] + '/'
    loginURL = url + 'api/aaaLogin.json'

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
    loginResp = session.post(loginURL, json=creds)
    if loginResp.ok is False:
        return print('Login Failed')

    epgResp = session.get(url + '/api/class/fvAEPg.json?query-target-filter=wcard(fvAEPg.name,"'+epg+'")')
    epgJSON = json.loads(epgResp.text)
    epgJSON = json.loads(json.dumps(epgJSON['imdata']))
    print(epgJSON)

    # dn = epgJSON['fvAEPg']['attributes']['dn'] + '/rsdomAtt-[uni/vmmp-VMware/dom-'+vmmD+']'

    delData = json.loads('{\
                            "fvRsDomAtt": {\
                                "attributes": {\
                                    "dn": "",\
                                    "status": "deleted"\
                                }\
                            }\
                        }')

    delData['fvRsDomAtt']['attributes']['dn'] = epgJSON[0]['fvAEPg']['attributes']['dn'] + '/rsdomAtt-[uni/vmmp-VMware/dom-'+vmmD+']'

    if execute is True:
        resp = session.post(url + 'api/mo/uni.json', data=json.dumps(delData,sort_keys=True))
        session.close()
        return resp
    else:
        session.close()
        return url + 'api/mo/uni.json\n' + json.dumps(delData,sort_keys=True)
