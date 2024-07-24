import os
import requests
import json
import time
import pathlib
# from storage.utils import S3
from ipaddress import IPv4Network
from data.environments import FirewallPolicy
from githubapi.utils import GithubAPI


class CheckpointObject():
    name: str=''
    type: str

    def __init__(self, **kwargs):
        for arg in kwargs:
            self.__setattr__(arg.replace('-', '_'), kwargs[arg])


class CheckpointAPI:
    Policy: FirewallPolicy
    GatewaysAndServers: str

    def __init__(self):
        self.LoggedIn = False
        self.SID = ''
        self.ReadOnly = False
        self.SessionName = ''
        self.SessionDescription = ''
        self.Domain = ''
        self.Username = 'corpsvcfwlautomation'
        self.Password = ''
        self.IPAddress = ''
        self.UID = ''
        # self.s3 = S3()
        self.gh = GithubAPI()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.LoggedIn:
            self.DiscardChanges()
            self.Logout()

    def SetPolicy(self, PolicyName: str):
        self.Policy = FirewallPolicy(PolicyName)

    def PostJSON(self, URI, Payload):
        if self.LoggedIn and self.SID:
            print(f'Sending POST to Checkpoint {URI}. Data={json.dumps(Payload)}')
            resp = requests.post('https://' + self.IPAddress + URI, json=Payload, headers={'X-chkp-sid': self.SID},
                                 verify=False)

            print(resp, resp.json())

            return resp

    def DiscardChanges(self):
        discardURI = '/web_api/discard'

        # Payload should be empty JSON
        JSON = {}

        self.PostJSON(discardURI, JSON)

    def Login(self):
        # if not self.Username:
        #     # Prompt for username
        #     self.Username = input("Enter Username:")
        #
        # if not self.Password:
        #     # Prompt for Password
        #     self.Password = getpass.getpass(prompt='Enter Password:')

        # Get the environment variable

        if self.Username and self.Password and self.IPAddress and not self.LoggedIn:

            # Set the Login URI
            LoginURI = '/web_api/login'

            # Create the login request JSON
            payload = {
                "user": self.Username,
                "password": self.Password,
                "domain": self.Domain,
                "session-name": self.SessionName,
                "session-description": self.SessionDescription,
                "read-only": self.ReadOnly
            }

            resp = requests.post(f'https://{self.IPAddress}{LoginURI}', json=payload, verify=False)
            # resp = requests.post('https://' + self.IPAddress + LoginURI, data=json.dumps(JSON),
            #                      headers={'Content-Type': 'application/json'}, verify=False)

            if self.IPAddress == '10.26.1.96' and resp.status_code != 200:
                print('Login to primary MDS failed.  Logging into alternate: 10.64.1.250')
                self.IPAddress = '10.64.1.250'
                resp = requests.post(f'https://{self.IPAddress}{LoginURI}', json=payload, verify=False)

            print(resp)

            # Check to make sure our login was successful.
            if resp.status_code >= 300:
                print(resp.json())
                print(resp.reason)
                raise Exception('Call to Login was unsuccessful')

            logininfo = resp.json()

            # Set the info on the class
            self.SID = logininfo['sid']
            self.LoggedIn = True
            self.UID = logininfo['uid']
            # self.GatewaysAndServers = \
            #     self.PostJSON('/web_api/show-gateways-and-servers', {'details-level': 'full', 'limit': 500}).json()[
            #         'objects']
            print('Logged in successfully')

    @classmethod
    def LoginToDomain(cls, Domain, username: str=None, password: str=None):
        api = cls()
        api.SessionName = 'Automation Testing'
        api.SessionDescription = 'Automation Testing'
        api.IPAddress = '10.26.1.96'
        api.Username = (username if username else os.getenv('FWUsername'))
        api.Password = (password if password else os.getenv('FWPassword'))
        api.Domain = Domain
        api.Login()
        return api

    def Logout(self):
        if self.SID and self.LoggedIn:
            # Discard any remaining changes so that you don't orphan the session
            self.DiscardChanges()

            # Now we can logout
            LogoutURI = '/web_api/logout'

            # Payload should be empty JSON
            JSON = {}

            # POST the JSON
            self.PostJSON(LogoutURI, JSON)

            # clear out the variables
            self.SID = ''
            self.LoggedIn = False
            print('Logged Out Successfully.')

    def GetTaskStatus(self, TaskID: str=None, TaskDict: dict=None):
        URI = '/web_api/show-task'

        if TaskID:
            JSON = {
                "task-id": TaskID
            }

            resp = self.PostJSON(URI, JSON)

            return resp
        elif TaskDict:
            TaskID = TaskDict['tasks'][0]['task-id']
            JSON = {
                "task-id": TaskID
            }

            resp = self.PostJSON(URI, JSON)

            return resp

    def PublishChanges(self):

        URI = '/web_api/v1/publish'
        JSON = {}

        # Attempt a publish and get a task-id
        taskinfo = self.PostJSON(URI, JSON)

        print(taskinfo.json())

        # Make sure we got a success code back before proceeding...
        if taskinfo.status_code >= 300:
            raise Exception('Non-Success Status Code when attempting to publish changes.')

        # Now we need to wait to ensure that the publish itself is successful by checking the status...
        x = 0
        taskinfo = taskinfo.json()
        while x <= 5:
            Status = self.GetTaskStatus(taskinfo['task-id']).json()

            if Status['tasks'][0]['progress-percentage'] == 100:
                if Status['tasks'][0]['status'] != 'succeeded':
                    # The publish failed.
                    print('Publish failed. Discarding changes...')
                    print(Status)
                    self.DiscardChanges()
                    break
                else:
                    print('Publish successful')
                    break
            else:
                time.sleep(5)
                print('Publish not complete. Percent Complete...' + str(Status['tasks'][0]['progress-percentage']))

            x += 1
        if x == 5:
            raise Exception('Unable to successfully publish changes. Task to publish did not succeed.')

    def CreateDomainObject(self, Domain, Color, Comment):

        # Check for some common issues
        if "*" in Domain:
            raise Exception('Wildcard DNS rules are not allowed')
        elif "/" in Domain or ":" in Domain:
            raise Exception("Domain format was passed as a URL and not in FQDN format")

        # Common issues not found so we will proceed...

        # Remove www.
        Domain.replace("www.", "")

        # Domains in checkpoint must begin with a "."
        if Domain[0:1] != ".":
            Domain = "." + Domain

        URI = '/web_api/add-dns-domain'

        JSON = {
            "name": Domain,
            "is-sub-domain": False,
            "color": Color,
            "comments": Comment
        }

        resp = self.PostJSON(URI, JSON)

        return resp

    def SetGroupMembership(self, ObjectName, GroupName, AddOrRemove):
        if AddOrRemove.lower() == 'add':

            print(f'Adding {ObjectName} to {GroupName}')
            URI = '/web_api/set-group'

            JSON = {
                "name": GroupName,
                "members": {
                    "add": ObjectName
                }
            }

            resp = self.PostJSON(URI, JSON)

            return resp
        elif AddOrRemove.lower() == 'remove':
            print(f'Removing {ObjectName} from {GroupName}')
            URI = '/web_api/set-group'

            JSON = {
                "name": GroupName,
                "members": {
                    "remove": ObjectName
                }
            }

            resp = self.PostJSON(URI, JSON)

            return resp
        else:
            raise Exception('Not a valid operation for SetGroupMembership')

    def CreateNetworkObject(self, SubnetName, SubnetCIDR, Color, Comment):
        URI = '/web_api/add-network'

        subnetinfo = SubnetCIDR.split('/')

        subnet = subnetinfo[0]

        masklength = subnetinfo[1]

        JSON = {
            "name": SubnetName,
            "subnet": subnet,
            "mask-length": masklength,
            "comments": Comment,
            "color": Color
        }

        resp = self.PostJSON(URI, JSON)

        return resp

    def CreateNewHost(self, ObjectName, IPAddress, Color, Comment):
        URI = '/web_api/add-host'

        JSON = {
            "name": ObjectName,
            "ip-address": IPAddress,
            "color": Color,
            "comments": Comment
        }

        resp = self.PostJSON(URI, JSON)

        return resp

    def CreateService(self, Protocol, Ports, Comment: str=''):
        URI = f'/web_api/add-service-{Protocol.lower()}'

        for x in Ports.split('-'):
            assert str(x).isdigit()

        Name = f'{Protocol.upper()}-{Ports}'

        JSON = {
            "name": Name,
            "port": Ports,
            "color": 'black',
            "comments": Comment
        }

        resp = self.PostJSON(URI, JSON)

        return resp

    def SearchObjects(self, Filter, Object: str='object'):
        URI = '/web_api/show-objects'

        JSON = {
            "type": Object,
            "filter": Filter
        }

        resp = self.PostJSON(URI, JSON)

        return resp

    def GetObjects(self, Filter: str='', Object: str='object'):
        URI = '/web_api/show-objects'

        JSON = {
            "type": Object,
            "filter": Filter
        }

        resp = self.PostJSON(URI, JSON)

        objects = resp.json()['objects']
        # objects.sort(key=lambda x: x['name'])

        return objects if objects else None

        # if resp.json()['total'] > 0:
        #     for obj in resp.json()['objects']:
        #         objects.append(CheckpointObject(**obj))
        #
        #     objects.sort(key=lambda x: x.name)
        #     return objects
        # else:
        #     return None

    def ObjectExists(self, Name: str, Type: str):
        search = self.GetObjects(Name, Type)

        if search:
            if len(search) == 0:
                return None
            else:
                for obj in search:
                    if obj.name == Name and obj.type == Type:
                        return obj
                return None
        else:
            return None

    def DeleteNetworkObject(self, NetworkCIDR):

        # Let's search for the object
        search = self.SearchObjects(NetworkCIDR).json()

        # resultcount = 0
        # for result in search['objects']:
        #     if result['type'] == 'network':
        #         deletable_object = result
        #         resultcount += 1
        #         break
        #
        # # We need to make sure we found something
        # if resultcount == 0:
        #     raise Exception("Unable to locate network in search. Exiting")

        try:
            deletableObject = next(result for result in search['objects'] if result['type'] == 'dns-domain')
        except StopIteration:
            raise Exception("Unable to locate network in search. Exiting")

        # We found something...continuing to delete.
        URI = '/web_api/delete-network'

        JSON = {
            "uid": deletableObject['uid']
        }

        resp = self.PostJSON(URI, JSON)

        return resp

    def DeleteDomainObject(self, object_name):
        # Let's search for the object
        search = self.SearchObjects(object_name).json()

        # resultcount = 0
        # for result in search['objects']:
        #     if result['type'] == 'dns-domain':
        #         deletableObject = result
        #         resultcount += 1
        #         break
        #
        # # We need to make sure we found something
        # if resultcount == 0:
        #     raise Exception("Unable to locate domain object in search. Exiting")

        try:
            deletable_object = next(result for result in search['objects'] if result['type'] == 'dns-domain')
        except StopIteration:
            raise Exception("Unable to locate domain object in search. Exiting")

        # We found something...continuing to delete.
        uri = '/web_api/delete-dns-domain'

        payload = {
            "uid": deletable_object['uid']
        }

        resp = self.PostJSON(uri, payload)

        return resp

    def DeleteHostObject(self, object_name):

        # Let's search for the object
        search = self.SearchObjects(object_name).json()

        # resultcount = 0
        # for result in search['objects']:
        #     if result['type'] == 'host':
        #         deletableObject = result
        #         resultcount += 1
        #         break
        #
        # # We need to make sure we found something
        # if resultcount == 0:
        #     raise Exception("Unable to locate host object in search. Exiting")

        try:
            deletable_object = next(result for result in search['objects'] if result['type'] == 'dns-domain')
        except StopIteration:
            raise Exception("Unable to locate host object in search. Exiting")

        # We found something...continuing to delete.
        uri = '/web_api/delete-host'

        payload = {
            "uid": deletable_object['uid']
        }

        resp = self.PostJSON(uri, payload)

        return resp

    def DeleteRangeObject(self, object_name):

        # Let's search for the object
        search = self.SearchObjects(object_name).json()

        # resultcount = 0
        # for result in search['objects']:
        #     if result['type'] == 'address-range':
        #         deletableObject = result
        #         resultcount += 1
        #         break
        #
        # # We need to make sure we found something
        # if resultcount == 0:
        #     raise Exception("Unable to locate address range object in search. Exiting")

        try:
            deletable_object = next(result for result in search['objects'] if result['type'] == 'address-range')
        except StopIteration:
            raise Exception("Unable to locate address range in search. Exiting")

        # We found something...continuing to delete.
        uri = '/web_api/delete-address-range'

        payload = {
            "uid": deletable_object['uid']
        }

        resp = self.PostJSON(uri, payload)

        return resp

    def DeleteRuleByID(self, UID):
        URI = '/web_api/delete-access-rule'

        payload = {'uid': UID}

        resp = self.PostJSON(f'https://{self.IPAddress}{URI}', payload)

        return resp

    def CreateThreatProfile(self, object_name, impact, severity, ips_new, ips_exclude, ips_impact):
        uri = '/web_api/add-threat-profile'

        payload = {
            "name": object_name,
            "active-protections-performance-impact": impact,
            "active-protections-severity": severity,
            "ips": 'True',
            "ips-settings": {
                "newly-updated-protections": ips_new,
                "exclude-protection-with-performance-impact": ips_impact,
                "exclude-protection-with-performance-impact-mode": ips_exclude
            }
        }

        resp = self.PostJSON(uri, payload)

        return resp

    def ModifyIPS(self, profile_name, protection_name, protection_action):
        uri = '/web_api/set-threat-protection'

        payload = {
            "name": protection_name,
            "overrides": [{
                "profile": profile_name,
                "action": protection_action,
                "track": "Log",
                "capture-packets": "false"
            }]
        }

        resp = self.PostJSON(uri, payload)

        return resp.status_code, resp.json

    def GetObjectUsage(self, uid):
        URI = '/web_api/where-used'

        JSON = {
            "uid": uid,
            "indirect": True,
            "indirect-max-depth": 5
        }

        resp = self.PostJSON(URI, JSON)

        return resp

    def CheckForQueuedPush(self, policy_name):
        if f'{policy_name}--{self.Domain}.json' not in self.gh.list_dir('pyapis/checkpoint/policy_push_queue'):
            return True
        else:
            return False

    def VerifyPolicy(self, policy_name):
        """Returns True if policy verification succeeds"""
        URI = '/web_api/verify-policy'

        payload = {'policy-package': policy_name}
        # This yields a task-id that must be retrieved and assessed

        task = self.PostJSON(URI, payload).json()['task-id']

        result = self.GetTaskStatus(task)
        verification_result = result.json()['tasks'][0]['status']

        while result.json()['tasks'][0]['progress-percentage'] < 100:
            time.sleep(5)
            result = self.GetTaskStatus(task)
            verification_result = result.json()['tasks'][0]['status']

        if verification_result == 'succeeded':
            return True, result
        elif verification_result == 'failed':
            return False, result
        else:
            raise Exception('PolicyVerificationAnomaly')

    def QueuePolicyPush(self, PolicyName):
        if not self.CheckForQueuedPush(PolicyName):
            if PolicyName == 'Colo_External':
                # Set the policy information
                PolicyInfo = {
                    'policy-package': PolicyName,
                    'targets': [
                        'frdccoloextfwl',
                        'xrdccoloextfwl',
                        'SLDC-EXT-VS',
                        'TPDC-EXT-VS-FW'
                    ],
                    'threat-prevention': False,
                    'access': True
                }

                # self.s3.write_json(filename=f'{PolicyName}--{self.Domain}.json', content=PolicyInfo,
                #                    path='checkpoint/policy_push_queue')
                self.gh.add_file(file_path=f'pyapis/checkpoint/policy_push_queue/{PolicyName}--{self.Domain}.json',
                                 message='Policy Push Queue', content=json.dumps(PolicyInfo))

            elif PolicyName == 'Colo_Aruba':
                # Set the policy info for Colo Aruba policy
                PolicyInfo = {
                    'policy-package': PolicyName,
                    'targets': [
                        'FRDC-ARB-VS',
                        'SLDC-ARB-VS',
                        'TPDC-ARB-VS',
                        'XRDC-ARB-VS'
                    ],
                    'threat-prevention': False,
                    'access': True
                }
                filepath = pathlib.Path(f'checkpoint/PolicyPushQueue/{PolicyName}--{self.Domain}.json')
                filepath.write_text(json.dumps(PolicyInfo))

                # self.s3.write_json(filename=f'{PolicyName}--{self.Domain}.json', content=PolicyInfo,
                #                    path='checkpoint/policy_push_queue')
                self.gh.add_file(file_path=f'pyapis/checkpoint/policy_push_queue/{PolicyName}--{self.Domain}.json',
                                 message='Policy Push Queue', content=json.dumps(PolicyInfo))

            elif PolicyName == 'QO_Lab-Simplified':
                # Set the policy info for QO Lab
                PolicyInfo = {
                    'policy-package': PolicyName,
                    'targets': [
                        'bldg4qolfwl'
                    ],
                    'threat-prevention': False,
                    'access': True
                }
                # self.s3.write_json(filename=f'{PolicyName}--{self.Domain}.json', content=PolicyInfo,
                #                    path='checkpoint/policy_push_queue')
                self.gh.add_file(file_path=f'pyapis/checkpoint/policy_push_queue/{PolicyName}--{self.Domain}.json',
                                 message='Policy Push Queue', content=json.dumps(PolicyInfo))

            elif PolicyName == 'Parallon-TestDev-Environment':
                # Set the policy info for QO Lab
                PolicyInfo = {
                    'policy-package': PolicyName,
                    'targets': [
                        'pardevfwl01'
                    ],
                    'threat-prevention': False,
                    'access': True
                }

                # self.s3.write_json(filename=f'{PolicyName}--{self.Domain}.json', content=PolicyInfo,
                #                    path='checkpoint/policy_push_queue')
                self.gh.add_file(file_path=f'pyapis/checkpoint/policy_push_queue/{PolicyName}--{self.Domain}.json',
                                 message='Policy Push Queue', content=json.dumps(PolicyInfo))

    def QueuePolicyPushV2(self):
        PolicyInfo = {
            'policy-package': self.Policy.SecurityPolicy,
            'targets': self.Policy.Targets
        }

        # self.s3.write_json(filename=f'{self.Policy.SecurityPolicy}--{self.Policy.Domain}.json', content=PolicyInfo,
        #                    path='checkpoint/policy_push_queue')
        self.gh.add_file(file_path=f'pyapis/checkpoint/policy_push_queue{self.Policy.SecurityPolicy}'
                                   f'--{self.Policy.Domain}.json', message='Queue Policy Push',
                         content=json.dumps(PolicyInfo))

    def GetObjectName(self, info: dict):
        if info['Type'].lower() == 'host':
            objs = self.GetObjects(Filter=info['IP'], Object=info['Type'].lower())
            if objs:
                obj = next(o for o in objs if o.ipv4_address == info['IP'])
                return obj.name
            else:
                name = f'{info["Name"]}_{info["IP"]}'
                self.CreateNewHost(name, info['IP'], 'red', self.SessionDescription)
                return name

        elif info['Type'].lower() == 'network':
            net = IPv4Network(info['IP'], strict=False)
            objs = self.GetObjects(Filter=info['IP'].replace('/', 'm'), Object='network')
            if objs:
                try:
                    obj = next(o for o in objs
                               if o.subnet4 == str(net.network_address) and o.mask_length4 == net.prefixlen)
                    return obj.name
                except StopIteration:
                    name = f'{info["Name"]}_{info["IP"].replace("/", "m")}'
                    self.CreateNetworkObject(name, info['IP'], 'red', self.SessionDescription)
                    return name
            else:
                name = f'{info["Name"]}_{info["IP"].replace("/", "m")}'
                self.CreateNetworkObject(name, info['IP'], 'red', self.SessionDescription)
                return name

    def GetSvcName(self, svc: str):
        protocol, port = svc.split('-')
        objs = self.GetObjects(port, f'service-{protocol.lower()}')

        if not objs:
            name = f'{protocol.upper()}-{port}'
            self.CreateService(Protocol=protocol.upper(), Ports=port)
            return name
        try:
            obj = next(o for o in objs if o.port == port and o.type == f'service-{protocol.lower()}')
            return obj.name
        except StopIteration:
            name = f'{protocol.upper()}-{port}'
            self.CreateService(Protocol=protocol.upper(), Ports=port)
            return name

    @classmethod
    def ParallonDevRule(cls, Sources: list, Destinations: list, Services: list, RuleName: str, Description: str):
        def GetObjectName(info: dict):
            if info['Type'].lower() == 'host':
                objs = session.GetObjects(Filter=info['IP'], Object=info['Type'].lower())
                if objs:
                    obj = next(o for o in objs if o.ipv4_address == info['IP'])
                    return obj.name
                else:
                    name = f'{info["Name"]}_{info["IP"]}'
                    session.CreateNewHost(name, info['IP'], 'red', Description)
                    return name

            elif info['Type'].lower() == 'network':
                net = IPv4Network(info['IP'], strict=False)
                objs = session.GetObjects(Filter=info['IP'].replace('/', 'm'), Object='network')
                if objs:
                    try:
                        obj = next(o for o in objs
                                   if o.subnet4 == str(net.network_address) and o.mask_length4 == net.prefixlen)
                        return obj.name
                    except StopIteration:
                        name = f'{info["Name"]}_{info["IP"].replace("/", "m")}'
                        session.CreateNetworkObject(name, info['IP'], 'red', Description)
                        return name
                else:
                    name = f'{info["Name"]}_{info["IP"].replace("/", "m")}'
                    session.CreateNetworkObject(name, info['IP'], 'red', Description)
                    return name

        def GetSvcName(svc):
            protocol, port = svc.split('-')
            objs = session.GetObjects(port, f'service-{protocol.lower()}')

            if not objs:
                name = f'{protocol.upper()}-{port}'
                session.CreateService(Protocol=protocol.upper(), Ports=port)
                return name
            try:
                obj = next(o for o in objs if o.port == port and o.type == f'service-{protocol.lower()}')
                return obj.name
            except StopIteration:
                name = f'{protocol.upper()}-{port}'
                session.CreateService(Protocol=protocol.upper(), Ports=port)
                return name

        session = cls()
        session.Domain = 'Lab'
        session.SessionName = Description
        session.SessionDescription = Description
        session.IPAddress = '10.26.1.96'
        session.Password = os.getenv('FWPassword')

        session.Login()

        source_objects = set()
        destination_objects = set()
        service_objects = set()

        for source in Sources:
            source_objects.add(GetObjectName(source))

        for destination in Destinations:
            destination_objects.add(GetObjectName(destination))

        for service in Services:
            if service.lower() in ['ping', 'echo']:
                service_objects.add('echo-request')
            else:
                service_objects.add(GetSvcName(service))

        payload = {
            "layer": "Parallon-TestDev-Environment Network",
            "position": {"bottom": "Automated Rules"},
            "service": list(service_objects),
            "name": RuleName,
            "action": "Accept",
            "destination": list(destination_objects),
            "destination-negate": False,
            "enabled": True,
            "source": list(source_objects),
            "source-negate": False,
            "track": {
                "type": "Log"
            },
            "vpn": "Any"
        }

        URI = "/web_api/add-access-rule"

        print('Adding rule in Automated Rules section\n')
        print(URI, str(payload))

        rule = session.PostJSON(URI, payload).json()
        rule_id = rule['uid']

        session.PublishChanges()

        verify_bool, verify_result = session.VerifyPolicy('Parallon-TestDev-Environment')

        if verify_bool:
            print('Rule validation succeeded.  Proceeding with policy push')
            session.QueuePolicyPush('Parallon-TestDev-Environment')
            session.Logout()

            return 200, payload
        else:
            print('Rule validation failed.  D')
            session.DeleteRuleByID(rule_id)
            session.PublishChanges()
            session.Logout()
            return 400, verify_result

    @classmethod
    def CreateAccessRule(cls, Sources: list, Destinations: list, Services: list, RuleName: str, Description: str):
        URI = "/web_api/add-access-rule"

        # Determine what domains and policies need to be updated
        endpoints = [x['IP'] for x in Sources + Destinations]
        policy_list = FirewallPolicy.generate_policy_list(endpoints)

        start_time = time.perf_counter()

        response = {
            'message': 'Policies will be updated and policy push scheduled - However this API is currently disabled'
                       ' so not really',
            'policies': [p for d, p in policy_list],
            'payloads': []
        }

        session = None

        # Loop over domains, Policy iteration happens later
        for domain in set([domain for domain, _ in policy_list]):
            if session:
                session.Logout()

            session = cls()
            session.Domain = domain
            session.SessionName = Description
            session.SessionDescription = Description
            session.IPAddress = '10.26.1.96'
            session.Password = os.getenv('FWPassword')
            session.Login()

            source_objects = set()
            destination_objects = set()
            service_objects = set()

            for source in Sources:
                source_objects.add(session.GetObjectName(source))

            for destination in Destinations:
                destination_objects.add(session.GetObjectName(destination))

            for service in Services:
                if service.lower() in ['ping', 'echo']:
                    service_objects.add('echo-request')
                else:
                    service_objects.add(session.GetSvcName(service))

            for policy in [p for d, p in policy_list if d == domain]:
                session.SetPolicy(policy)

                payload = {
                    "layer": f"{session.Policy.SecurityPolicy} Network",
                    "position": {"bottom": "Automated Rules"},
                    "service": list(service_objects),
                    "name": RuleName,
                    "action": "Accept",
                    "destination": list(destination_objects),
                    "destination-negate": False,
                    "enabled": True,
                    "source": list(source_objects),
                    "source-negate": False,
                    "track": {
                        "type": "Log"
                    },
                    "vpn": "Any"
                }

                print(f'Adding rule in Automated Rules section for policy package {policy}\n')
                print(URI, '\n', json.dumps(payload))

                response['payloads'].append([policy, payload])

                # rule = session.PostJSON(URI, payload).json()
                # rule_id = rule['uid']
                #
                # session.PublishChanges()
                #
                # verify_bool, verify_result = session.VerifyPolicy(session.Policy.SecurityPolicy)
                #
                # if verify_bool:
                #     print('Rule validation succeeded.  Proceeding with policy push')
                #     session.QueuePolicyPushV2()
                # else:
                #     print('Rule validation failed')
                #     session.DeleteRuleByID(rule_id)
                #     session.PublishChanges()
        return 200, response

    @staticmethod
    def GetPolicyPushProgress(PolicyName):
        gh = GithubAPI()
        # file = pathlib.Path(rf'checkpoint/PolicyPushQueue').glob(f'{PolicyName}*.json')
        #
        # for policy in file:
        #     if not policy.name.__contains__('_InProgress'):
        #         return "Waiting to Push Policy"
        #     else:
        #         return policy.read_text()
        # else:
        #     return "Completed"

        jobs = gh.list_dir(f'pyapis/checkpoint/policy_push_queue')

        for job in jobs:
            if PolicyName in job:
                if '_InProgress' not in job:
                    return 'Waiting to Push Policy'
                else:
                    return gh.get_file_content(f'pyapis/checkpoint/policy_push_queue/{PolicyName}.json')
        else:
            return "Completed"

    # @classmethod
    # def CreateVLANInterface(cls, Domain: str, Firewalls: list, Subnet: str, VLAN: int):


def proxy_pac_exception(Hostname: str='', Comment: str='', AddOrRemove: str='', username: str='', password: str='',
                        TicketNumber: str=''):
    api = CheckpointAPI()
    api.SessionName = 'Automated Proxy PAC Bypass rule'
    api.SessionDescription = TicketNumber
    api.Username = username
    api.Password = password
    api.Domain = 'Colo'
    api.IPAddress = '10.26.1.96'
    api.Login()

    if AddOrRemove.lower() == 'add':
        api.CreateDomainObject(Domain=Hostname, Color='red', Comment=Comment)

    api.SetGroupMembership(ObjectName=f'.{Hostname}', GroupName='PAC-File-FQDN-Exceptions', AddOrRemove=AddOrRemove)

    api.PublishChanges()
    api.QueuePolicyPush('Colo_External')
    api.Logout()

    return 200, {'message': 'Request Submitted'}


def AddNetworksToFlexVPN(Networks: list or str, SessionDescription: str, SessionName: str):
    API = CheckpointAPI()
    API.ReadOnly = False
    API.SessionDescription = SessionDescription
    API.SessionName = SessionName
    API.Domain = 'Colo'
    API.IPAddress = '10.26.1.96'

    API.Login()
    if isinstance(Networks, list):
        for network in Networks:
            API.CreateNetworkObject(f'Flex_{network}', network, 'Blue', SessionName)
            API.SetGroupMembership(f'Flex_{network}', 'Flex-VPN-Spoke-Site', 'Add')
    else:
        # Handle if a single network is passed.
        API.CreateNetworkObject(f'Flex_{Networks}', Networks, 'Blue', SessionName)
        API.SetGroupMembership(f'Flex_{Networks}', 'Flex-VPN-Spoke-Site', 'Add')

    API.PublishChanges()
    API.QueuePolicyPush('Colo_Aruba')

    API.Logout()


def RemoveNetworksFromFlexVPN(Networks: list or str, SessionDescription: str, SessionName: str):
    API = CheckpointAPI()
    API.ReadOnly = False
    API.SessionDescription = SessionDescription
    API.SessionName = SessionName
    API.Domain = 'Colo'
    API.IPAddress = '10.26.1.96'

    API.Login()

    if isinstance(Networks, list):
        for network in Networks:
            # Remove the network from the Flex VPN group
            API.SetGroupMembership(f'Flex_{network}', 'Flex-VPN-Spoke-Site', 'Remove')

            # Now let's delete the network from the CMA if it's not used for anything else...
            results = API.SearchObjects(network).json()
            network_object = next(result for result in results['objects'] if result['name'] == f'Flex_{network}')
            usage = API.GetObjectUsage(network_object['uid']).json()

            if usage['used-directly']['total'] == 0 and usage['used-indirectly']['total'] == 0:
                # Delete the object from the CMA since it's not used anywhere else.
                API.DeleteNetworkObject(network)
    else:
        # Remove the network from the Flex VPN group
        API.SetGroupMembership(f'Flex_{Networks}', 'Flex-VPN-Spoke-Site', 'Remove')

        # Now let's delete the network from the CMA if it's not used for anything else...
        results = API.SearchObjects(Networks).json()
        network_object = next(result for result in results['objects'] if result['name'] == f'Flex_{Networks}')
        usage = API.GetObjectUsage(network_object['uid']).json()

        if usage['used-directly']['total'] == 0 and usage['used-indirectly']['total'] == 0:
            # Delete the object from the CMA since it's not used anywhere else.
            API.DeleteNetworkObject(Networks)

    # We're done, let's publish our changes.
    API.PublishChanges()
    API.Logout()

    # Queue Policy Push
    API.QueuePolicyPush('Colo_Aruba')


def generate_policy_list(ips: list):
    policy_list = FirewallPolicy.generate_policy_list(ips)

    return 200, policy_list
