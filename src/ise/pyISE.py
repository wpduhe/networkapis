import json
import os
import re
import requests

base_dir = os.path.dirname(__file__)


class InvalidError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class ERS(object):
    def __init__(self, ise_node, verify=False, disable_warnings=False, timeout=60):
        """
        Class to interact with Cisco ISE via the ERS API
        :param ise_node: IP Address of the primary admin ISE node
        :param verify: Verify SSL cert
        :param disable_warnings: Disable requests warnings
        :param timeout: Query timeout
        """
        self.ise_node = ise_node
        self.user_name = os.getenv('iseuser')
        self.user_pass = os.getenv('isepass')

        self.url_base = f'https://{self.ise_node}:9060/ers'
        self.ise = requests.session()
        self.ise.auth = (self.user_name, self.user_pass)
        self.ise.verify = verify  # http://docs.python-requests.org/en/latest/user/advanced/#ssl-cert-verification
        self.disable_warnings = disable_warnings
        self.timeout = timeout
        self.ise.headers.update({'Connection': 'keep_alive'})

        if self.disable_warnings:
            requests.urllib3.disable_warnings()

    @staticmethod
    def _mac_test(mac):
        """
        Test for valid mac address
        :param mac: MAC address
        :return: MAC Addr/Error
        """
        result = {
            'success': False,
            'response': mac,
            'error': '',
            'raw': '',
        }

        mac = re.sub('[.:-]', '', mac).upper()
        mac = ''.join(mac.split())
        if re.search(r'([0-9A-F]{12})', mac) is not None and len(mac) == 12:
            mac = ":".join(["%s" % (mac[i:i + 2]) for i in range(0, 12, 2)])
            result['success'] = True
            result['response'] = mac
            return result
        else:
            result['response'] = f"{result['response']} Invalid MAC Address"
            result['error'] = "Invalid MAC Address"
            return result

    @staticmethod
    def _oid_test(oid):
        """
        Test for a valid OID
        :param oid: OID in the form of abcd1234-ef56-7890-abcd1234ef56
        :return: True/False
        """
        if re.match(r'^([a-f0-9]{8}-([a-f0-9]{4}-){3}[a-z0-9]{12})$', oid):
            return oid
        else:
            raise InvalidError(f'{oid} Is not a valid Object ID.')

    @staticmethod
    def _pass_ersresponse(result, resp):
        result['response'] = resp.json()['ERSResponse']['messages'][0]['title']
        result['error'] = resp.status_code
        return result

    @staticmethod
    def _404_ersresponse(result, name):
        result['response'] = f'{name} not found, or Timeout occured.'
        result['error'] = 404
        return result

    def get_object(self, url: str, objecttype: str, oid: str = None, name: str = None, ip: str = None, mac: str = None):
        """
        Get generic object lists.
        :param url: Base URL for requesting lists
        :param objecttype: "ERSEndPoint", etc...
        :param oid: ID retreved from previous search.
        :param name: name retreved from previous search.
        :param ip: IP retreved from previous search.
        :param mac: Mac Addr retreved from previous search.
        :return: result dictionary
        """
        self.ise.headers.update({'ACCEPT': 'application/json', 'Content-Type': 'application/json'})

        result = {
            'success': False,
            'response': '',
            'error': '',
            'raw': '',
        }

        name_direct = ('EndPointGroup', 'ERSEndPoint', 'IdentityGroup', 'NetworkDeviceGroup', 'AuthorizationProfile')
        device = None

        try:
            if oid is not None:
                device = oid
                resp = self.ise.get(f'{url}/{oid}', timeout=self.timeout)
            elif name is not None:
                device = name
                if objecttype in name_direct:
                    resp = self.ise.get(f'{url}/name/{name}', timeout=self.timeout)
                else:
                    resp = self.ise.get(f'{url}?filter=name.EQ.{name}', timeout=self.timeout)
                    if resp.json()['SearchResult']['total'] == 1:
                        resp = self.ise.get(resp.json()['SearchResult']['resources'][0]['link']['href'],
                                            timeout=self.timeout)
                    else:
                        return self._404_ersresponse(result, device)
            elif ip is not None:
                device = ip
                resp = self.ise.get(f'{url}?filter=ipaddress.EQ.{ip}', timeout=self.timeout)
                if resp.json()['SearchResult']['total'] == 1:
                    resp = self.ise.get(resp.json()['SearchResult']['resources'][0]['link']['href'],
                                        timeout=self.timeout)
                else:
                    return self._404_ersresponse(result, device)
            elif mac is not None:
                mac = self._mac_test(mac)
                if mac['success']:
                    resp = self.ise.get(f"{url}/name/{mac['response']}", timeout=self.timeout)
                    device = mac['response']
                else:
                    return mac
            else:
                raise InvalidError('One argument required.')
        except requests.exceptions.ConnectionError:
            return self._404_ersresponse(result, device)
        except requests.exceptions.ReadTimeout:
            return self._404_ersresponse(result, device)

        result['raw'] = resp

        if resp.status_code == 200:
            result['success'] = True
            del resp.json()[objecttype]['link']
            result['response'] = resp.json()[objecttype]
            return result
        else:
            return self._404_ersresponse(result, device)

    def get_object_all(self, url: str, pages: int = 10, desc: bool = False, ob_filter: str = None):
        """
        Get generic object lists.
        :param url: Base URL for request
        :param pages: Default 10, 0 for unlimited
        :param desc: Include description
        :param ob_filter: Filter results
        :return: result dictionary
        """
        self.ise.headers.update({'ACCEPT': 'application/json', 'Content-Type': 'application/json'})

        result = {
            'success': False,
            'response': '',
            'error': '',
            'raw': '',
            'total': '',
        }

        if ob_filter is not None:
            resp = self.ise.get(f'{url}?filter={ob_filter}&size=100')
        else:
            resp = self.ise.get(f'{url}?size=100')

        jraw = resp.json()
        comb = []
        if desc is True:
            for i in jraw['SearchResult']['resources']:
                comb.append((i['name'], i['id'], i['description']))
        else:
            for i in jraw['SearchResult']['resources']:
                comb.append((i['name'], i['id']))

        total_pages = int((jraw['SearchResult']['total'] / 100) + (jraw['SearchResult']['total'] % 100 > 0))
        if pages is not None:
            if total_pages > 0:
                if pages == 0 or total_pages < pages:
                    pages = total_pages
                if pages > 1:
                    for x in range(pages - 1):
                        if ob_filter is not None:
                            resp = self.ise.get(F'{url}?filter={ob_filter}&size=100&page={x + 2}')
                        else:
                            resp = self.ise.get(F'{url}?size=100&page={x + 2}')
                        jraw1 = json.loads(resp.text)
                        if desc is True:
                            for i in jraw1['SearchResult']['resources']:
                                comb.append((i['name'], i['id'], i['description']))
                        else:
                            for i in jraw1['SearchResult']['resources']:
                                comb.append((i['name'], i['id']))

        result['raw'] = jraw

        if resp.status_code == 200:
            result['success'] = True
            result['response'] = comb
            result['total'] = jraw['SearchResult']['total']
            return result
        else:
            return self._pass_ersresponse(result, resp)

    def delete_object(self, url: str, objecttype: str, oid: str = None, name: str = None, ip: str = None,
                      mac: str = None):
        """
        Get generic object lists.
        :param url: Base URL for requesting lists
        :param objecttype: "ERSEndPoint", etc...
        :param oid: ID retreved from previous search.
        :param name: name retreved from previous search.
        :param ip: IP retreved from previous search.
        :param mac: Mac Addr retreved from previous search.
        :return: result dictionary
        """
        self.ise.headers.update({'ACCEPT': 'application/json', 'Content-Type': 'application/json'})

        result = {
            'success': False,
            'response': '',
            'error': '',
            'raw': '',
        }

        name_direct = ('EndPointGroup', 'ERSEndPoint', 'IdentityGroup', 'NetworkDeviceGroup', 'AuthorizationProfile')
        device = None
        resp = None

        try:
            if oid is not None:
                device = oid
                resp = self.ise.delete(f'{url}/{oid}', timeout=self.timeout)
            elif name is not None or ip is not None or mac is not None:
                if name is not None:
                    device = name
                    if objecttype in name_direct:
                        resp = self.ise.get(f'{url}/name/{name}', timeout=self.timeout)
                        if objecttype == 'ERSEndPoint':
                            resp = self.ise.delete(f"{url}/endpoint/{resp.json()[objecttype]['id']}",
                                                   timeout=self.timeout)
                        else:
                            resp = self.ise.delete(resp.json()[objecttype]['link']['href'], timeout=self.timeout)
                    else:
                        resp = self.ise.get(f'{url}?filter=name.EQ.{name}', timeout=self.timeout)
                        if resp.json()['SearchResult']['total'] == 1:
                            resp = self.ise.delete(resp.json()['SearchResult']['resources'][0]['link']['href'],
                                                   timeout=self.timeout)
                        else:
                            return self._404_ersresponse(result, device)
                elif ip is not None:
                    device = ip
                    resp = self.ise.get(f'{url}?filter=ipaddress.EQ.{ip}', timeout=self.timeout)
                    if resp.json()['SearchResult']['total'] == 1:
                        resp = self.ise.delete(resp.json()['SearchResult']['resources'][0]['link']['href'],
                                               timeout=self.timeout)
                    else:
                        return self._404_ersresponse(result, device)
                elif mac is not None:
                    device = mac
                    mac = self._mac_test(mac)
                    if mac['success']:
                        resp = self.ise.get(f"{url}?filter=mac.EQ.{mac['response']}", timeout=self.timeout)
                        device = mac['response']
                        if resp.json()['SearchResult']['total'] == 1:
                            resp = self.ise.delete(resp.json()['SearchResult']['resources'][0]['link']['href'],
                                                   timeout=self.timeout)
                        else:
                            return self._404_ersresponse(result, device)
                    else:
                        return mac
            else:
                raise InvalidError('One argument required.')
        except requests.exceptions.ConnectionError:
            return self._404_ersresponse(result, device)
        except requests.exceptions.ReadTimeout:
            return self._404_ersresponse(result, device)

        if resp.status_code == 204:
            result['success'] = True
            result['response'] = f'{device} Deleted Successfully'
            return result
        elif resp.status_code == 404:
            return self._404_ersresponse(result, device)
        else:
            return self._pass_ersresponse(result, resp)

    def post_object(self, url, device, data):
        self.ise.headers.update({'ACCEPT': 'application/json', 'Content-Type': 'application/json'})

        result = {
            'success': False,
            'response': '',
            'error': '',
            'raw': '',
        }

        try:
            resp = self.ise.post(url, data=data, timeout=self.timeout)
        except requests.exceptions.ConnectionError:
            return self._404_ersresponse(result, device)
        except requests.exceptions.ReadTimeout:
            return self._404_ersresponse(result, device)

        result['raw'] = resp

        if resp.status_code == 201 or resp.status_code == 204:
            result['success'] = True
            result['response'] = f'{device} Added Successfully'
            return result
        else:
            return self._pass_ersresponse(result, resp)

    def put_object(self, url, device, data):
        self.ise.headers.update({'ACCEPT': 'application/json', 'Content-Type': 'application/json'})

        result = {
            'success': False,
            'response': '',
            'error': '',
            'raw': '',
        }

        try:
            resp = self.ise.put(url, data=data, timeout=self.timeout)
        except requests.exceptions.ConnectionError:
            return self._404_ersresponse(result, device)
        except requests.exceptions.ReadTimeout:
            return self._404_ersresponse(result, device)

        result['raw'] = resp

        if resp.status_code == 200 or resp.status_code == 204:
            result['success'] = True
            result['response'] = f'{device} Updated Successfully'
            return result
        else:
            return self._pass_ersresponse(result, resp)

    def get_endpointgroup_all(self, pages=10):
        """
        Get all endpoint identity groups
        :return: result dictionary
        """
        return self.get_object_all(f'{self.url_base}/config/endpointgroup', pages, True)

    def get_endpointgroup(self, name=None, oid=None):
        """
        Get endpoint identity group details
        :param name: Name of the identity group
        :param oid: ID of the Identity Group
        :return: result dictionary
        """
        return self.get_object(f'{self.url_base}/config/endpointgroup', 'EndPointGroup', oid=oid, name=name)

    def put_endpointgroup_update(self, oid, name, desc=''):
        """
        Info
        :param oid:
        :param name:
        :param desc:
        :return: info
        """
        data = {
            "EndPointGroup": {
                "id": oid,
                "name": name,
                "description": desc,
                "systemDefined": "false"
            }
        }

        return self.put_object(f'{self.url_base}/config/endpointgroup/{oid}', device=name, data=json.dumps(data))

    def post_endpointgroup_create(self, name, desc=''):
        """
        Info
        :param name:
        :param desc:
        :return: info
        """
        data = {
            "EndPointGroup": {
                "name": name,
                "description": desc,
                "systemDefined": "false"
            }
        }

        return self.post_object(f'{self.url_base}/config/endpointgroup', device=name, data=json.dumps(data))

    def delete_endpointgroup(self, name=None, oid=None):
        """
        Info
        :param name:
        :param oid:
        :return: info
        """
        return self.delete_object(f'{self.url_base}/config/endpointgroup', 'EndPointGroup', oid=oid, name=name)

    def get_endpoint_filter(self, filter, pages=10):
        """
        Get all endpoints
        Filter: [portalUser, staticProfileAssignment, profileId, profile, groupId, staticGroupAssignment, mac]
        EQ 	Equals
        NEQ 	Not Equals
        GT 	Greater Than
        LT 	Less Then
        STARTSW 	Starts With
        NSTARTSW 	Not Starts With
        ENDSW 	Ends With
        NENDSW 	Not Ends With
        CONTAINS 	Contains
        NCONTAINS 	Not Contains
        :return: result dictionary
        """
        return self.get_object_all(f'{self.url_base}/config/endpoint', pages=pages, desc=False, ob_filter=filter)

    def get_endpoint_all(self, pages=10):
        """
        Get all endpoints
        :param pages: default 10 pages, 0 for all
        :return: result dictionary
        """
        return self.get_object_all(f'{self.url_base}/config/endpoint', pages)

    def get_endpoint(self, mac=None, oid=None):
        """
        Get endpoint details
        :param mac: MAC address of the endpoint
        :param oid: id of the endpoint
        :return: result dictionary
        """
        return self.get_object(f'{self.url_base}/config/endpoint', 'ERSEndPoint', oid=oid, mac=mac)

    def get_endpoint_rejected(self):
        """
        Get all endpoint identity groups
        :return: result dictionary
        """
        self.ise.headers.update({'ACCEPT': 'application/json', 'Content-Type': 'application/json'})

        result = {
            'success': False,
            'response': '',
            'error': '',
            'raw': '',
        }

        resp = self.ise.get(f'{self.url_base}/config/endpoint/getrejectedendpoints')
        if resp.status_code == 200:
            result['success'] = True
            result['response'] = resp.json()['OperationResult']['resultValue']
            result['raw'] = resp.json()
            return result
        else:
            return ERS._pass_ersresponse(result, resp)

    def put_endpoint_update(self, data, mac=None, oid=False):
        """
        Update an endpoint to the local user store.
        :param oid:
        :param mac: Macaddress
        :param data: data
        """
        device = oid

        if not oid:
            device = mac
            mac_check = ERS._mac_test(mac)
            if not mac_check['success']:
                return mac_check
            mac = mac_test['response']
            output = self.get_endpoint(mac=mac)
            oid = output['response']['id']

        return self.put_object(f'{self.url_base}/config/endpoint/{oid}', device=device, data=json.dumps(data))

    def put_endpoint_release_rejected(self, mac=None):
        """
        Release endpoint from Rejected list
        :param mac: Macaddress
        """

        mac_check = ERS._mac_test(mac)
        if not mac_check['success']:
            return mac_check
        mac = mac_check['response']
        self.ise.headers.update({'ACCEPT': 'application/json', 'Content-Type': 'application/json'})

        result = {
            'success': False,
            'response': '',
            'error': '',
            'raw': '',
        }

        resp = self.ise.put(f'{self.url_base}/config/endpoint/{mac}/releaserejectedendpoint')
        result['raw'] = resp
        if resp.status_code == 204:
            result['success'] = True
            result['response'] = f'{mac} Released Successfully'
            return result
        else:
            return ERS._pass_ersresponse(result, resp)

    def post_endpoint_create(self,
                             name,
                             mac,
                             group_id,
                             static_profile_assigment='false',
                             static_group_assignment='true',
                             profile_id='',
                             description='',
                             portaluser='',
                             customattributes=None):
        """
        Add a user to the local user store.
        :param name: Name
        :param mac: Macaddress
        :param group_id: OID of group to add endpoint in
        :param static_profile_assigment: Set static profile
        :param static_group_assignment: Set static group
        :param profile_id: OID of profile
        :param description: User description
        :param portaluser: Portal username
        :param customattributes: key value pairs of custom attributes
        :return: result dictionary
        """

        if customattributes is None:
            customattributes = {}
        mac_check = ERS._mac_test(mac)
        if not mac['success']:
            return mac
        mac = mac_check['response']

        data = {"ERSEndPoint": {'name': name, 'description': description, 'mac': mac,
                                'profileId': profile_id, 'staticProfileAssignment': static_profile_assigment,
                                'groupId': group_id, 'staticGroupAssignment': static_group_assignment,
                                'portalUser': portaluser, 'customAttributes': {'customAttributes': customattributes}
                                }
                }

        return self.post_object(f'{self.url_base}/config/endpoint', device=mac, data=json.dumps(data))

    def post_endpoint_create_m(self, mac, data):
        """
        Add a user to the local user store.
        :param mac: Macaddress
        :param data: data
        """

        mac_check = ERS._mac_test(mac)
        if not mac_check['success']:
            return mac_check
        mac = mac_check['response']

        return self.post_object(f'{self.url_base}/config/endpoint', device=mac, data=json.dumps(data))

    def delete_endpoint(self, oid=None, mac=None):
        """
        Delete an endpoint.

        :param oid:
        :param mac: Endpoint Macaddress
        :return: Result dictionary
        """
        return self.delete_object(f'{self.url_base}/config/endpoint', 'ERSEndPoint', oid=oid, mac=mac)

    def get_identitygroup_all(self, pages=10):
        """
        Get all identity groups
        :return: result dictionary
        """
        return self.get_object_all(f'{self.url_base}/config/identitygroup', pages, True)

    def get_identitygroup(self, name=None, oid=None):
        """
        Get identity group details.
        :param oid: ID of the identity group
        :param name: Name of the identity group
        :return: result dictionary
        """
        return self.get_object(f'{self.url_base}/config/identitygroup', 'IdentityGroup', oid=oid, name=name)

    def put_identitygroup_update(self, oid, name, desc='', parent=''):
        """
        Info
        :param oid:
        :param name:
        :param desc:
        :param parent:
        :return: info
        """
        data = {
            "IdentityGroup": {
                "id": oid,
                "name": name,
                "description": desc,
                "parent": parent
            }
        }

        return self.put_object(f'{self.url_base}/config/identitygroup/{oid}', device=name, data=json.dumps(data))

    def post_identitygroup_create(self, name, desc='', parent=''):
        """
        Info
        :param name:
        :param desc:
        :param parent:
        :return: info
        """
        data = {
            "IdentityGroup": {
                "name": name,
                "description": desc,
                "parent": parent
            }
        }

        return self.post_object(f'{self.url_base}/config/identitygroup', device=name, data=json.dumps(data))

    def get_netdevicegroup_all(self, pages=10):
        """
        Get a list tuples of device groups
        :return:
        """
        return self.get_object_all(f'{self.url_base}/config/networkdevicegroup', pages, True)

    def get_netdevicegroup(self, name=None, oid=None):
        """
        Get a device group details
        :param name:
        :param oid:
        :return: result dictionary
        """
        return self.get_object(f'{self.url_base}/config/networkdevicegroup', 'NetworkDeviceGroup', oid=oid, name=name)

    def put_netdevicegroup_update(self, oid, name, desc='', location=''):
        """
        Info
        :param oid:
        :param name:
        :param desc:
        :param location:
        :return: info
        """
        data = {
            "NetworkDeviceGroup": {
                "name": name,
                "description": desc,
                "othername": location
            }
        }

        return self.put_object(f'{self.url_base}/config/networkdevicegroup/{oid}', device=name, data=json.dumps(data))

    def post_netdevicegroup_create(self, name, desc='', location=''):
        """
        Info
        :param name:
        :param desc:
        :param location:
        :return: info
        """
        data = {
            "NetworkDeviceGroup": {
                "name": name,
                "description": desc,
                "othername": location
            }
        }

        return self.post_object(f'{self.url_base}/config/networkdevicegroup', device=name, data=json.dumps(data))

    def delete_netdevicegroup(self, name=None, oid=None):
        """
        Info
        :param name:
        :param oid:
        :return: info
        """
        return self.delete_object(f'{self.url_base}/config/networkdevicegroup', 'NetworkDeviceGroup', oid=oid,
                                  name=name)

    def get_netdevice_all(self, pages=10):
        """
        Get a list of devices
        :param pages: default 10 pages, 0 for all
        :return: result dictionary
        """
        return self.get_object_all(f'{self.url_base}/config/networkdevice', pages, False)

    def get_netdevice(self, oid=None, name=None, ip=None):
        """
        Get a device detailed info.
        :param oid: OID of Network Device
        :param name: Name of Network Device
        :param ip: IP Address of Network Device
        :return: result dictionary
        """
        return self.get_object(f'{self.url_base}/config/networkdevice', 'NetworkDevice', oid=oid, name=name, ip=ip)

    def put_netdevice_update(self, data=None, oid=None):
        """
        Update a Device.

        :param data: json data
        :param oid: Object ID
        :return: Result dictionary
        """
        if data is None:
            raise InvalidError('json data for device update is required.')

        netdevice_name = data['NetworkDevice']['name']

        if oid is None:
            raise InvalidError('OID Required.')

        return self.put_object(f'{self.url_base}/config/networkdevice/{oid}', device=netdevice_name,
                               data=json.dumps(data))

    def post_netdevice_create(self,
                              name,
                              ip_address,
                              radius_key,
                              snmp_ro,
                              dev_group,
                              dev_location,
                              dev_type,
                              description='',
                              snmp_v='TWO_C',
                              dev_profile='Cisco',
                              tacacs_shared_secret=None,
                              tacas_connect_mode_options='ON_LEGACY',
                              data=None):
        """
        Add a device.

        :param tacacs_shared_secret:
        :param tacas_connect_mode_options:
        :param data:
        :param name: name of device
        :param ip_address: IP address of device
        :param radius_key: Radius shared secret
        :param snmp_ro: SNMP read only community string
        :param dev_group: Device group name
        :param dev_location: Device location
        :param dev_type: Device type
        :param description: Device description
        :param snmp_v:
        :param dev_profile: Device profile
        :return: Result dictionary
        """
        if data is None:
            data = {'NetworkDevice': {'name': name,
                                      'description': description,
                                      'authenticationSettings': {
                                          'networkProtocol': 'RADIUS',
                                          'radiusSharedSecret': radius_key,
                                          'enableKeyWrap': 'false',
                                      },
                                      'snmpsettings': {
                                          'version': snmp_v,
                                          'roCommunity': snmp_ro,
                                          'pollingInterval': 3600,
                                          'linkTrapQuery': 'true',
                                          'macTrapQuery': 'true',
                                          'originatingPolicyServicesNode': 'Auto'
                                      },
                                      'profileName': dev_profile,
                                      'coaPort': 1700,
                                      'NetworkDeviceIPList': [{
                                          'ipaddress': ip_address,
                                          'mask': 32
                                      }],
                                      'NetworkDeviceGroupList': [
                                          dev_group, dev_type, dev_location,
                                          'IPSEC#Is IPSEC Device#No'
                                      ]
                                      }
                    }

            if tacacs_shared_secret is not None:
                data['NetworkDevice']['tacacsSettings'] = {
                    'sharedSecret': tacacs_shared_secret,
                    'connectModeOptions': tacas_connect_mode_options
                }

        return self.post_object(f'{self.url_base}/config/networkdevice', device=name, data=json.dumps(data))

    def delete_netdevice(self, name=None, ip=None, oid=None):
        """
        Delete a device.
        :param name: Name of Network Device
        :param ip: IP Address of Network Device
        :param oid:  of Network Device
        :return: Result dictionary
        """
        return self.delete_object(f'{self.url_base}/config/networkdevice', 'NetworkDevice', oid=oid, name=name, ip=ip)

    def get_user_all(self, pages=10):
        """
        Get all internal users
        :return: List of tuples of user details
        """
        return self.get_object_all(f'{self.url_base}/config/internaluser', pages, False)

    def get_user(self, name=None, oid=None):
        """
        Get user detailed info.
        :param name: User ID
        :param oid: Object ID
        :return: result dictionary
        """
        return self.get_object(f'{self.url_base}/config/internaluser', 'InternalUser', oid=oid, name=name)

    def put_user_update(self,
                        user_id,
                        password,
                        user_group_oid,
                        enable='',
                        first_name='',
                        last_name='',
                        email='',
                        description='',
                        oid=None):
        """
        Add a user to the local user store.

        :param oid:
        :param user_id: User ID
        :param password: User password
        :param user_group_oid: OID of group to add user to
        :param enable: Enable password used for Tacacs
        :param first_name: First name
        :param last_name: Last name
        :param email: email address
        :param description: User description
        :return: result dictionary
        """
        data = {"InternalUser": {'name': user_id, 'password': password, 'enablePassword': enable,
                                 'firstName': first_name, 'lastName': last_name, 'email': email,
                                 'description': description, 'identityGroups': user_group_oid}}

        if oid is None:
            raise InvalidError('OID Required.')

        return self.put_object(f'{self.url_base}/config/internaluser/{oid}', device=user_id, data=json.dumps(data))

    def post_user_create(self,
                         user_id,
                         password,
                         user_group_oid,
                         enable='',
                         first_name='',
                         last_name='',
                         email='',
                         description=''):
        """
        Add a user to the local user store.

        :param user_id: User ID
        :param password: User password
        :param user_group_oid: OID of group to add user to
        :param enable: Enable password used for Tacacs
        :param first_name: First name
        :param last_name: Last name
        :param email: email address
        :param description: User description
        :return: result dictionary
        """
        data = {"InternalUser": {'name': user_id, 'password': password, 'enablePassword': enable,
                                 'firstName': first_name, 'lastName': last_name, 'email': email,
                                 'description': description, 'identityGroups': user_group_oid}}

        return self.post_object(f'{self.url_base}/config/internaluser', device=user_id, data=json.dumps(data))

    def delete_user(self, name=None, oid=None):
        """
        Delete a user.
        :param name: User ID
        :param oid: Object ID
        :return: Result dictionary
        """
        return self.delete_object(f'{self.url_base}/config/internaluser', 'InternalUser', oid=oid, name=name)

    def get_authprofile_all(self, pages=10):
        """
        Get all endpoint identity groups
        :return: result dictionary
        """
        return self.get_object_all(f'{self.url_base}/config/authorizationprofile', pages, True)

    def get_authprofile(self, name=None, oid=None):
        """
        Get endpoint identity group details
        :param name: Name of the identity group
        :param oid: ID of the Identity Group
        :return: result dictionary
        """
        return self.get_object(f'{self.url_base}/config/authorizationprofile', 'AuthorizationProfile', oid=oid,
                               name=name)

    def put_authprofile_update(self,
                               name=None,
                               oid=None,
                               desc='',
                               attributes=None,
                               access='ACCESS_ACCEPT',
                               profilename='Cisco'):

        """
        Update Authorization Profile.
        :param oid:
        :param access:
        :param profilename:
        :param name: Name
        :param desc: Description
        :param attributes: Custom Attributes
        :return: result dictionary
        """
        if attributes is None:
            attributes = {}
        if name is not None:
            resp = self.get_object(f'{self.url_base}/config/authorizationprofile', 'AuthorizationProfile', name=name)
            if resp['success']:
                oid = resp['response']['id']
            else:
                return InvalidError(f'{name} not found.')
        elif oid is not None:
            resp = self.get_object(f'{self.url_base}/config/authorizationprofile', 'AuthorizationProfile', oid=oid)
            name = resp['response']['name']
        else:
            InvalidError('Name or OID Required.')

        data = {"AuthorizationProfile": {"id": oid, "name": name, "description": desc, "advancedAttributes": attributes,
                                         "accessType": access, "profileName": profilename}}

        return self.put_object(f'{self.url_base}/config/authorizationprofile/{oid}', device=name, data=json.dumps(data))

    def post_authprofile_create(self,
                                name,
                                desc='',
                                attributes=None,
                                access='ACCESS_ACCEPT',
                                profilename='Cisco'):

        """
        Add a user to the local user store.

        :param name: Name
        :param desc: Description
        :param attributes: Custom Attributes
        :param access: Accept or Deny
        :param profilename: Network Device Group Name
        :return: result dictionary
        """
        if attributes is None:
            attributes = {}
        data = {"AuthorizationProfile": {"name": name, "description": desc, "advancedAttributes": attributes,
                                         "accessType": access, "profileName": profilename}}

        return self.post_object(f'{self.url_base}/config/authorizationprofile', device=name, data=json.dumps(data))

    def delete_authprofile(self, name=None, oid=None):
        """
        Get endpoint identity group details
        :param name: Name of the identity group
        :param oid: ID of the Identity Group
        :return: result dictionary
        """
        return self.delete_object(f'{self.url_base}/config/authorizationprofile', 'AuthorizationProfile', oid=oid,
                                  name=name)

    def get_test(self, url=None):
        self.ise.headers.update({'ACCEPT': 'application/json', 'Content-Type': 'application/json'})
        return self.ise.get(f"{self.url_base}/config/{url}")

    def delete_test(self, url=None):
        self.ise.headers.update({'ACCEPT': 'application/json', 'Content-Type': 'application/json'})
        return self.ise.delete(f"{self.url_base}/config/{url}")

