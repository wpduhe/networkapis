# import json
# import urllib3
# import re
# from tetpyclient import RestClient
#
# urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
#
#
# class TetrationAPI:
#     def __init__(self):
#         self.api = RestClient(server_endpoint='https://xrdc-tetration.mgmt.medcity.net/',
#                               credentials_file='tetration/tetration_credentials.json', verify=False)
#
#     def get(self, path: str):
#         result = self.api.get(path)
#         return result.json()
#
#     def post(self, path: str, data: dict):
#         result = self.api.post(uri_path=path, json_body=json.dumps(data))
#         return result.json()
#
#     def _raw_query(self, search_filter: str= ''):
#         if re.match(r'[.\d+]+', search_filter):
#             req_payload = {
#                 'scopeName': 'Default',
#                 'limit': 255,
#                 'filter': {
#                     'type': 'and',
#                     'filters': [
#                        {
#                           'type': 'contains',
#                           'field': 'ip',
#                           'value': search_filter
#                        }
#                     ]
#                 }
#             }
#         else:
#             req_payload = {
#                 'scopeName': 'Default',
#                 'limit': 255,
#                 'filter': {
#                     'type': 'and',
#                     'filters': [
#                        {
#                           'type': 'contains',
#                           'field': 'hostname',
#                           'value': search_filter
#                        }
#                     ]
#                 }
#             }
#
#         response = self.post(path='/inventory/search', data=req_payload)
#
#         return response
#
#     @classmethod
#     def raw_query(cls, search_filter: str=''):
#         api = cls()
#         response = api._raw_query(search_filter=search_filter)
#
#         return 200, response['results']
#
#     @classmethod
#     def query(cls, search_filter: str= ''):
#         api = cls()
#         response = api._raw_query(search_filter=search_filter)
#
#         results = []
#         for result in response['results']:
#             entry = {
#                 'Hostname': result['host_name'],
#                 'IP': result['ip'],
#                 'Agent': result['agent_type'],
#                 'TagsScope': result['tags_scope_name']
#             }
#             results.append(entry)
#
#         return 200, results
