import json
from bigip.ltmClass import vipCopy


def vip_copy(request_data: dict):

    src_ltms = request_data['sourceLTMs']
    vips = request_data['vips']
    modify = request_data['modify']
    modify_data = request_data['modifyData']
    collection = request_data['collectionName']
    new_ltm = request_data['newLTM']

    vip_class = vipCopy()
    vip_class.login(ltms=src_ltms)
    if len(vips) > 0:
        for vip in vips:
            vip_class.collect(vip=vip)
    else:
        vip_class.collect(vip='')

    vip_class.generateData()

    if modify is True:
        vip_class.modifyConfigs(data=modify_data)

    response = {
        'modifyData': vip_class.data,
        'Configuration': ({
            'VIPs': vip_class.vipConfig,
            'Pools': vip_class.poolConfig,
            'Profiles': vip_class.profileConfig,
            'iRules': vip_class.ruleConfig,
            'Persist': vip_class.persistConfig,
            'Monitors': vip_class.monitorConfig
        } if collection == '' else 'Omitted because Postman Collection was Requested.'
                                   '  Location: file://corpdpt01/telshare/network_engineering/PyAPIs_Outputs')
    }

    if collection is not '':
        f5_auth_json = {
            'username': '{{3-4ID}}',
            'password': '{{3-4Password}}',
            'loginProviderName': 'tmos'
        }
        auth_event = [
                {
                    "listen": "test",
                    "script": {
                        "exec": [
                            "var jsonData = JSON.parse(responseBody);",
                            "pm.globals.set(\"F5AuthToken\", jsonData.token.token);"
                        ],
                        "type": "text/javascript"
                    }
                }
            ]
        post = {
            'info': {
                'name': collection,
                'schema': 'https://schema.getpostman.com/json/collection/v2.0.0/collection.json'
            },
            'item': [{
                    'name': 'Get F5 Token',
                    'event': auth_event,
                    'request': {
                        'method': 'POST',
                        'header': [{
                            'key': 'Content-Type',
                            'value': 'application/json'
                        }],
                        'body': {
                            'mode': 'raw',
                            'raw': json.dumps(f5_auth_json)
                        },
                        'url': 'https://{}/mgmt/shared/authn/login'.format(new_ltm[0])
                    }
                }]
        }

        allconfigs = [vip_class.monitorConfig, vip_class.poolConfig, vip_class.ruleConfig, vip_class.persistConfig,
                      vip_class.profileConfig, vip_class.vipConfig]

        for items in allconfigs:
            for x in items:
                path = x['kind']
                path = path.split(':')
                del path[-1]
                path = '/'.join(path)
                attach = {
                    'name': x['name'],
                    'request': {
                        'method': 'POST',
                        'header': [{
                            'key': 'Content-Type',
                            'value': 'application/json'
                        }, {
                            'key': 'X-F5-Auth-Token',
                            'value': '{{F5AuthToken}}'
                        }],
                        'body': {
                            'mode': 'raw',
                            'raw': json.dumps(x, indent=4)  # Indentation was added.  If issues arise start here.
                        },
                        'url': 'https://{}/mgmt/{}'.format(new_ltm[0], path)
                    }
                }
                post['item'].append(attach)

        with open(f'//CorpDpt01/TELShare/Network_Engineering/PyAPIs_Outputs/{collection}.json', 'w') as file:
            file.write(json.dumps(post, indent=4))

    return response
