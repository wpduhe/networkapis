import requests, json, re
import os


class vipCopy:
    def __init__(self, vip=''):
        self.vip = vip
        self.oldLTMs = []
        self.newLTMs = []
        self.vipsNotFound = []
        self.data = {'VIPs': [], 'Pools': [], 'memberUpdates': [], 'vipList': [], 'sslProfiles': []}

        self.poolList = []
        self.profileList = []
        self.monitorList = []
        self.sslProfileList = []

        self.vipConfig = []
        self.poolConfig = []
        self.profileConfig = []
        self.ruleConfig = []
        self.persistConfig = []
        self.monitorConfig = []

    def login(self, ltms):
            from creds import creds

            for ltm in ltms:
                self.session = requests.session()
                self.session.verify = False
                self.session.url = 'https://' + ltm

                print('Logging In')
                creds = {
                    "username": os.getenv('netmgmtuser'),
                    "password": os.getenv('netmgmtpass'),
                    "loginProviderName": "tmos"
                }
                self.resp = self.session.post(self.session.url + '/mgmt/shared/authn/login', json=creds)
                resp = json.loads(self.resp.text)
                self.session.headers['X-F5-Auth-Token'] = resp['token']['token']

                print('Checking failover state')
                self.resp = self.session.get(self.session.url + '/mgmt/tm/sys/failover')
                if self.resp.text.find('active') > -1:
                    break

    def collect(self, vip=''):
        poolSearch = re.compile('pool {.*}')
        poolSearch2 = re.compile('pool [A-z0-9-]+')

        if vip is not '':
            self.vip = vip

        # Collect all VIP names and destinations
        self.resp = self.session.get(self.session.url + '/mgmt/tm/ltm/virtual?$select=name,destination,fullPath')
        vips = json.loads(self.resp.text)
        vips = vips['items']
        for vip in vips:
            vip['destination'] = re.search(r'[.\d]+', vip['destination'])

        # Create iterator for VIPs
        vipGen = (x for x in vips)

        # If statement to extract specific VIPs if a destination address is provided
        # Otherwise all VIPs will be processed
        if self.vip is not '':
            for item in vipGen:
                if item['destination'] == self.vip:
                    resp = self.session.get(self.session.url + '/mgmt/tm/ltm/virtual/' + item['fullPath'].replace('/', '~') + '?expandSubcollections=true')
                    item = json.loads(resp.text)
                    # May need to go back and add the deletion of generation key
                    try:
                        del item['selfLink']
                    except KeyError:
                        pass
                    self.vipConfig.append(item)
        else:
            resp = self.session.get(self.session.url + '/mgmt/tm/ltm/virtual?expandSubcollections=true')
            resp = json.loads(resp.text)
            vips = resp['items']
            for item in vips:
                self.vipConfig.append(item)

        # Find custom persistence profiles and iRules used by the VIPs and append them to ruleConfig
        for obj in self.vipConfig:
            try:
                for persist in obj['persist']:
                    persist = self.session.get(self.session.url + persist['nameReference']['link'][
                        persist['nameReference']['link'].index('/mgmt'):])
                    persist = json.loads(persist.text)
                    try:
                        rule = self.session.get(self.session.url + persist['ruleReference']['link'][
                            persist['ruleReference']['link'].index('/mgmt'):])
                        rule = json.loads(rule.text)
                        rule = {
                            'kind': rule['kind'],
                            'name': rule['name'],
                            'partition': rule['partition'],
                            'apiAnonymous': rule['apiAnonymous']
                        }
                        self.ruleConfig.append(rule)
                    except KeyError:
                        pass
                    del persist['selfLink'], persist['generation'], persist['defaultsFromReference'], \
                        persist['ruleReference']
                    self.persistConfig.append(persist)
            except KeyError:
                pass
            try:
                for rule in obj['rulesReference']:
                    resp = self.session.get(self.session.url + rule['link'][rule['link'].find('/mgmt'):])
                    resp = json.loads(resp.text)
                    del resp['selfLink'], resp['generation']
                    try:
                        del resp['apiRawValues']
                    except KeyError:
                        pass
                    self.ruleConfig.append(resp)
            except KeyError:
                pass

            # Find Pools used by the VIPs and append them to poolList
            try:
                self.poolList.append(obj['pool'].replace('/Common/', ''))
            except KeyError:
                pass

            # Find Profiles used by the VIPs and append them to profileList
            try:
                obj['profiles'] = obj['profilesReference']['items']
                for profile in obj['profiles']:
                    if profile['nameReference']['link'] not in self.profileList:
                        self.profileList.append(profile['nameReference']['link'].replace('https://localhost', self.session.url))
                    del profile['selfLink'], profile['generation'], profile['nameReference'], profile['fullPath']
            except KeyError:
                pass

            # Delete resource references
            try:
                del obj['rulesReference']
            except KeyError:
                pass
            try:
                del obj['policiesReference']
            except KeyError:
                pass
            try:
                del obj['profilesReference']
            except KeyError:
                pass
            try:
                del obj['poolReference']
            except KeyError:
                pass
            try:
                for persist in obj['persist']:
                    del persist['nameReference']
            except KeyError:
                pass

        # Search iRules for Pool references and add any pools to poolList
        for rule in self.ruleConfig:
            results = poolSearch.findall(rule['apiAnonymous'])
            results2 = poolSearch2.findall(rule['apiAnonymous'])
            for result in results:
                self.poolList.append(result[result.index('{')+1:result.index('}')])
            for result in results2:
                self.poolList.append(result[5:])

        # Purge pool list of duplicate entries
        self.poolList = list(set(self.poolList))
        # Collect pool configurations based on poolList
        for pool in self.poolList:
            pool = self.session.get(self.session.url + '/mgmt/tm/ltm/pool/' + pool + '?expandSubcollections=true')
            pool = json.loads(pool.text)
            # Extract monitor from pool configuration and append to monitorList
            pool['monitor'] = pool['monitor'].replace('/Common/', '')
            pool['monitor'] = pool['monitor'].replace(' ', '')
            self.monitorList.append(pool['monitor'])
            members = []
            for member in pool['membersReference']['items']:
                members.append( {'name': member['name'], 'address': member['address']})
            pool = {
                'kind': pool['kind'],
                'name': pool['name'],
                'partition': 'Common',
                'allowNat': pool['allowNat'],
                'allowSnat': pool['allowSnat'],
                'loadBalancingMode': pool['loadBalancingMode'],
                'queueDepthLimit': pool['queueDepthLimit'],
                'queueOnConnectionLimit': pool['queueOnConnectionLimit'],
                'queueTimeLimit': pool['queueTimeLimit'],
                'reselectTries': pool['reselectTries'],
                'serviceDownAction': pool['serviceDownAction'],
                'slowRampTime': pool['slowRampTime'],
                'monitor': pool['monitor'],
                'members': members
            }
            if pool not in self.poolConfig:
                self.poolConfig.append(pool)

        # Remove duplicates from lists
        self.monitorList = list(set(self.monitorList))

        # Collect all monitors from LTM
        self.resp = self.session.get(self.session.url + '/mgmt/tm/ltm/monitor/http')
        httpMonitors = json.loads(self.resp.text)
        httpMonitors = json.loads(json.dumps(httpMonitors['items']))

        self.resp = self.session.get(self.session.url + '/mgmt/tm/ltm/monitor/https')
        httpsMonitors = json.loads(self.resp.text)
        httpsMonitors = json.loads(json.dumps(httpsMonitors['items']))

        self.resp = self.session.get(self.session.url + '/mgmt/tm/ltm/monitor/tcp')
        tcpMonitors = json.loads(self.resp.text)
        tcpMonitors = json.loads(json.dumps(tcpMonitors['items']))

        self.resp = self.session.get(self.session.url + '/mgmt/tm/ltm/monitor/udp')
        udpMonitors = json.loads(self.resp.text)
        udpMonitors = json.loads(json.dumps(udpMonitors['items']))

        monitors = []
        for monitor in httpMonitors:
            monitors.append(monitor)
        for monitor in httpsMonitors:
            monitors.append(monitor)
        for monitor in tcpMonitors:
            monitors.append(monitor)
        for monitor in udpMonitors:
            monitors.append(monitor)

        for monitor in monitors:
            if monitor['name'] in self.monitorList:
                del monitor['selfLink'], monitor['generation']
                if monitor not in self.monitorConfig:
                    self.monitorConfig.append(monitor)

        # Purge profileList of duplicates
        self.profileList = list(set(self.profileList))
        # Collect profile configuration based on profileList
        # sslProfiles = self.session.get(self.session.url + '/mgmt/tm/ltm/profile/client-ssl')
        # sslProfiles = json.loads(sslProfiles.text)

        for profile in self.profileList:
            resp = self.session.get(profile)
            profile = json.loads(resp.text)
            del profile['selfLink'], profile['generation']
            if 'defaultsFromReference' in profile.keys():
                del profile['defaultsFromReference']
            if profile['kind'].find('client-ssl') > -1:
                self.sslProfileList.append(profile['name'])
            elif profile not in self.profileConfig:
                self.profileConfig.append(profile)

            # for sslProfile in sslProfiles['items']:
            #     if sslProfile['name'] == profile:
            #
            #         certInfo = sslProfile['certKeyChain'][0]
            #
            #         key = self.session.get(self.session.url + certInfo['keyReference']['link'][
            #             certInfo['keyReference']['link'].index('/mgmt'):])
            #         key = json.loads(key.text)
            #         if key not in self.keys:
            #             self.keys.append(key)
            #
            #         cert = self.session.get(self.session.url + certInfo['certReference']['link'][
            #             certInfo['certReference']['link'].index('/mgmt'):])
            #         cert = json.loads(cert.text)
            #         del cert['bundleCertificatesReference'], cert['certValidatorsReference']
            #         if cert not in self.certs:
            #             self.certs.append(cert)
            #
            #         chain = self.session.get(self.session.url + certInfo['chainReference']['link'][
            #             certInfo['chainReference']['link'].index('/mgmt'):])
            #         chain = json.loads(chain.text)
            #         del chain['bundleCertificatesReference'], chain['certValidatorsReference']
            #         if chain not in self.chains:
            #             self.chains.append(chain)
            #
            #         del sslProfile['certReference'], sslProfile['chainReference'], \
            #             sslProfile['defaultsFromReference'], sslProfile['keyReference'], sslProfile['selfLink']
            #         del certInfo['certReference'], certInfo['chainReference'], certInfo['keyReference']
            #         sslProfile['certKeyChain'] = [certInfo]
            #         if sslProfile not in self.profileConfig:
            #             self.profileConfig.append(sslProfile)

        # Remove Duplicates if they exist
        self.ruleConfig = [dict(x) for x in set(tuple(y.items()) for y in self.ruleConfig)]
        self.monitorConfig = [dict(x) for x in set(tuple(y.items()) for y in self.monitorConfig)]
        self.persistConfig = [dict(x) for x in set(tuple(y.items()) for y in self.persistConfig)]
        self.sslProfileList = list(set(self.sslProfileList))

    def generateData(self):
        self.data = {
            'VIPs': [],
            'Pools': [],
            'memberUpdates': [{
                        'host': 'server_name',
                        'IP': 'ip_address',
                        'newIP': 'new_ip_ipaddress'
                    }],
            'vipList': [],
            'sslProfiles': []
        }
        self.data['sslProfiles'] = self.sslProfileList
        for vip in self.vipConfig:
            self.data['VIPs'].append(
                {
                    'name': vip['name'],
                    'newName': '',
                    'IP': vip['destination'][vip['destination'].index('Common/')+len('Common/'):
                                 vip['destination'].index(':')],
                    'newIP': ''
                }
            )
            self.data['vipList'].append(vip['destination'][vip['destination'].index('Common/')+len('Common/'):
                                 vip['destination'].index(':')])
        self.data['vipList'] = list(set(self.data['vipList']))

        for pool in self.poolConfig:
            self.data['Pools'].append(
                {
                    'name': pool['name'],
                    'newName': '',
                    'members': pool['members'],
                    'newMembers': []
                }
            )

    def modifyConfigs(self, data):
        # Change the VIP addresses, names, and pool names
        for vip in self.vipConfig:
            newInfo = next(x for x in data['VIPs'] if x['name'] == vip['name'])
            vip['destination'] = vip['destination'].replace(newInfo['IP'], newInfo['newIP'])
            vip['name'] = newInfo['newName']
            vip['fullPath'] = '/Common/' + newInfo['newName']

            pool = next(x for x in data['Pools'] if x['name'] == vip['pool'].replace('/Common/', ''))
            vip['pool'] = '/Common/' + pool['newName']

        # Change the Pool names and member info
        for pool in self.poolConfig:
            newInfo = next(x for x in data['Pools'] if x['name'] == pool['name'])
            pool['name'] = newInfo['newName']
            if len(newInfo['newMembers']) > 0:
                pool['members'] = newInfo['newMembers']
                continue
            else:
                for member in pool['members']:
                    try:
                        y = next(x for x in data['memberUpdates'] if x['IP'] == member['address'])
                    except StopIteration:
                        newInfo['newMembers'].append(member)
                        continue
                    newInfo['newMembers'].append({
                        'name': y['host'].lower() + member['name'][member['name'].index(':'):],
                        'address': y['newIP']
                    })
            pool['members'] = newInfo['newMembers']

        # Change pool names in iRules if applicable
        for rule in self.ruleConfig:
            for pool in data['Pools']:
                rule['apiAnonymous'] = rule['apiAnonymous'].replace(pool['name'], pool['newName'])

    def postToLTM(self, post):
        if isinstance(post, dict):
            path = post['kind']
            path = path.split(':')
            del path[len(path) - 1]
            path = '/'.join(path)

            resp = self.session.post(self.session.url + path, data=json.dumps(post))
            return resp

        elif isinstance(post, list):
            for x in post:
                if not isinstance(x, dict):
                    return 'Configuration List contains non-dictionary object.  Remove and resubmit'

            responses = []
            for x in post:
                path = x['kind']
                path = path.split(':')
                del path[len(path) - 1]
                path = '/'.join(path)

                resp = self.session.post(self.session.url + path, data=json.dumps(post))
                responses.append(resp)

            return responses

        else:
            return 'POST data must be JSON'

    def get(self, path='/mgmt/tm/ltm/virtual'):
        resp = self.session.get(self.session.url + path)
        resp = json.loads(resp.text)
        resp = resp['items']
        return resp
