import os
import requests
from urllib.parse import urlencode


class GenericCI:
    category = None

    def __init__(self, data: dict):
        for attribute in data['attributes']:
            self.__setattr__(attribute, data['attributes'][attribute])

        if 'outbound_relations' in data.keys():
            self.outbound_relations = data['outbound_relations']

        if 'inbound_relations' in data.keys():
            self.outbound_relations = data['inbound_relations']


class ServerCI:
    relevant_fields = ['category', 'ip_address', 'short_description', 'dns_domain', 'os_domain', 'model_number',
                       'os_version', 'correlation_id', 'fqdn', 'name', 'virtual']

    def __init__(self, data):
        for key in data['attributes']:
            if key in self.relevant_fields:
                self.__setattr__(key, data['attributes'][key])

        self.source_data = data


class NetworkCI:
    relevant_fields = ['category', 'device_type', 'ip_address', 'correclation_id', 'model_number', 'name',
                       'serial_number', 'sys_class_name', 'sys_id', 'u_dns_name', 'u_os', 'u_os_version']

    def __init__(self, data):
        for key in data['attributes']:
            if key in self.relevant_fields:
                self.__setattr__(key, data['attributes'][key])

        self.source_data = data


class ServiceCentral:
    def __init__(self):
        self.url = 'https://crm.hcaservices.com/servicecentral/prod'
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers['X-IBM-Client-Id'] = os.getenv('CMDBAPIID')
        self.session.headers['Accept'] = 'application/json'

    @staticmethod
    def load_ci(data: dict):
        ci = GenericCI(data)
        if ci.category.lower() == 'server':
            ci = ServerCI(data)
        elif ci.category.lower() == 'network':
            ci = NetworkCI(data)

        return ci

    def get(self, path):
        r = self.session.get(f'{self.url}{path}')
        return r.json()

    def get_application(self, app_id: str=None):
        path = '/api/now/cmdb/instance/cmdb_ci_appl'

        if app_id is not None:
            path += f'/{app_id}'

            path += '?sysparm_display_value=true'

            r = self.get(path)
            # ci = GenericCI(r['result'])
            # return ci
            return r

        else:
            r = self.get(path=path)
            return r['result']

    def get_server_ci(self, server_id: str=None, query_filter: str=None):
        path = '/api/now/cmdb/instance/cmdb_ci_server'

        if server_id is not None:
            path += f'/{server_id}'

            r = self.get(path)
            ci = self.load_ci(r['result'])
            return ci
        else:
            r = self.get(path)
            return r['result']

    def get_network_ci(self, net_gear_id: str=None, query_filter: str=None):
        path = '/api/now/cmdb/instance/cmdb_ci_netgear'
        params = False

        if net_gear_id is not None:
            path += f'/{net_gear_id}'

            r = self.get(path)
            ci = self.load_ci(r['result'])
            return ci
        elif query_filter is not None:
            params = {'sysparm_query': query_filter}

            if params:
                path += f'?{urlencode(params)}'

                r = self.get(path)
                if len(r['result']) == 1:
                    return self.get_network_ci(net_gear_id=r['result'][0]['sys_id'])
                else:
                    return r['result']
        else:
            r = self.get(path)
            return r['result']
