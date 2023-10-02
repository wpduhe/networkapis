import unittest
import requests
import urllib3
import random
import os


urllib3.disable_warnings()

# Development URL
URL = 'https://pyapisdev.ocp.app.medcity.net'

# Sandbox URL
# URL = 'http://py-ap-is-duhes-stuff-snd.apps.ops2.paas.medcity.net'

PROD_ENV = 'xrdc-az1'  # GETs only
DEV_ENV = 'qol-az1'
CREATE_CUSTOM_EPG_DATA = {
    'APIKey': os.getenv('localapikey'),
    'AppProfileName': 'ap-UnitTest',
    'BridgeDomainName': 'bd-UnitTest',
    'EPGName': 'epg-UnitTest',
    'Description': 'Unit Testing EPG Creation',
    'Subnets': [
        '172.31.254.0/26'
    ],
    'AEPs': [
        'aep-Placeholder'
    ]
}
PROXY_LOCATIONS = ['nas', 'ftw', 'slc', 'tpa', 'orl']
PAC_JSON = {
    'section': 'Direct Rules',
    'host_exp': 'unittest.networkapis.testing',
    'directive': 'DIRECT',
    'comment': 'DELETE ME - Unit Testing of PAC file'
}
PAC_POST_VALIDATION = {
    'Direct Rules': {
        'rules': [
            {
                'comment': '  DELETE ME - Unit Testing of PAC file  ',
                'directive': 'DIRECT',
                'host_exp': 'unittest.networkapis.testing'
            }
        ]
    },
    'Proxy Rules': {
        'rules': []
    }
}
PAC_DELETE_VALIDATION = {
    'Direct Rules': {
        'rules': []
    },
    'Proxy Rules': {
        'rules': []
    }
}
NCM_DATA = {
    'APIKey': os.getenv('localapikey'),
    'Trusted': True
}


class MainTests(unittest.TestCase):

    # def test_001_check_status(self):
    #     """Asserts that the server has started"""
    #     r = requests.get(URL + '/apis/getStatus', verify=False)
    #     self.assertEqual(r.status_code, 200)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # ACI API Tests
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_002_aci_environment_list(self):
        """
        Asserts the following:
          - data/ACIEnvironments.json can be parsed and loaded
          - API endpoint /apis/aci/environment_list is providing results
        """
        r = requests.get(URL + '/apis/aci/environment_list', verify=False)
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.json(), list)

    def test_003_aci_get_tenant_ap_epg(self):
        """
        Asserts the following:
          - Login to APIC works
          - Getting Tenants, APs, and EPGs lists from APIC is working
          - get_epd_data returns data
        """
        r = requests.get(URL + f'/apis/aci/{DEV_ENV}/tenants', verify=False)
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.json(), list)
        tenant = r.json()[random.randint(0, r.json().index(r.json()[-1]))]

        r = requests.get(URL + f'/apis/aci/{DEV_ENV}/{tenant}/aps', verify=False)
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.json(), list)
        ap = r.json()[random.randint(0, r.json().index(r.json()[-1]))]

        r = requests.get(URL + f'/apis/aci/{DEV_ENV}/{tenant}/{ap}/epgs', verify=False)
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.json(), list)
        epg = r.json()[random.randint(0, r.json().index(r.json()[-1]))]

        print(f'Test Case from {DEV_ENV}:  {tenant}/{ap}/{epg}')

        r = requests.get(URL + f'/apis/aci/{DEV_ENV}/get_epg_data/{epg}', verify=False)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['epg_name'], epg)

        print(f'Data returned from get_epg_data for {epg}:  {r.json()}')

    def test_004_aci_get_aeps(self):
        """Asserts that AEP lists will populate"""
        r = requests.get(URL + f'/apis/aci/{DEV_ENV}/aeps', verify=False)
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.json(), list)

    def test_005_aci_get_switch_profiles(self):
        """Asserts that switch profile lists will populate"""
        r = requests.get(URL + f'/apis/aci/{DEV_ENV}/switch_profiles', verify=False)
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.json(), list)

    def test_006_aci_get_aci_vlan(self):
        """Asserts get_aci_vlan() returns data"""
        r = requests.get(URL + f'/apis/aci/{PROD_ENV}/get_aci_vlan/2000', verify=False)
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.json(), list)

    def test_007_aci_get_bd_by_ip_fvsubnet(self):
        """Asserts get_bd_by_ip() returns data given an IP from a fvSubnet"""
        # Test using IP of fvSubnet from QOL-AZ1
        r = requests.get(URL + '/apis/aci/qol-az1/get_bd_by_ip/10.28.160.96', verify=False)
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.json(), dict)

    def test_008_aci_get_bd_by_ip_external_epg(self):
        """Asserts get_bd_by_ip() returns data given an IP from an external EPG"""
        # Test using IP of external EPG from QOL-AZ1
        r = requests.get(URL + '/apis/aci/qol-az1/get_bd_by_ip/10.28.160.64', verify=False)
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.json(), dict)

    def test_009_aci_get_bd_by_ip_interface(self):
        """Asserts get_bd_by_ip() returns data given an IP from an interface on an L3Out"""
        # Test using sub-interface IP from QOL-AZ1
        r = requests.get(URL + '/apis/aci/qol-az1/get_bd_by_ip/10.30.52.50', verify=False)
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.json(), dict)

    def test_010_aci_get_dr_vlans(self):
        """Asserts get_dr_vlans() returns data"""
        r = requests.get(URL + f'/apis/aci/{PROD_ENV}/get_dr_vlans', verify=False)
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.json(), dict)

    def test_011_aci_get_nondr_vlans(self):
        """Asserts get_nondr_vlans returns data"""
        r = requests.get(URL + f'/apis/aci/{PROD_ENV}/get_nondr_vlans', verify=False)
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.json(), dict)

    def test_012_aci_get_nondr_epgs(self):
        """Asserts nondr_epgs returns data"""
        r = requests.get(URL + f'/apis/aci/{PROD_ENV}/nondr_epgs', verify=False)
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.json(), list)

    def test_013_aci_get_dr_epgs(self):
        """Asserts dr_epgs returns data"""
        r = requests.get(URL + f'/apis/aci/{PROD_ENV}/dr_epgs', verify=False)
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.json(), list)

    def test_014_aci_get_pods(self):
        """Asserts pods returns data"""
        r = requests.get(URL + f'/apis/aci/{DEV_ENV}/pods', verify=False)
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.json(), list)

    def test_015_aci_get_teps(self):
        """Asserts teps returns data"""
        r = requests.get(URL + f'/apis/aci/{PROD_ENV}/teps', verify=False)
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.json(), list)

    def test_016_aci_get_next_vlan(self):
        """
        Asserts the following:
          - get_next_vlan returns an available VLAN
          - get_vlan_data returns accurate information given an unused VLAN
          - get_vlan_data returns accurate information given a used VLAN
        """
        # Retrieve the next VLAN
        r = requests.get(URL + f'/apis/aci/{PROD_ENV}/get_next_vlan', verify=False)
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.json(), int)

        vlan = r.json()

        # Ensure the returned VLAN ID is not used
        r = requests.get(URL + f'/apis/v2/aci/{PROD_ENV}/get_vlan_data?VLAN={vlan}', verify=False)
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.json(), list)
        self.assertEqual(len(r.json()), 0)

        # Ensure the preceding VLAN ID is used
        r = requests.get(URL + f'/apis/v2/aci/{PROD_ENV}/get_vlan_data?VLAN={vlan-1}', verify=False)
        self.assertEqual(r.status_code, 200)
        self.assertGreater(len(r.json()), 0)

    # def test_017_aci_create_custom_epg(self):
    #     """
    #     Asserts the following:
    #       - create_custom_epg takes data
    #       - expected data exists
    #       - undo_create_custom_epg does what is expected
    #     """
    #     # TODO: Have to get this test working
    #     r = requests.post(URL + f'/apis/aci/{DEV_ENV}/create_custom_epg', json=self.CREATE_CUSTOM_EPG_DATA,
    #                       verify=False)
    #     self.assertEqual(r.status_code, 200)
    #     with APIC(DEV_ENV) as apic:

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # PAC API Tests
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_100_pac_get_pac_file(self):
        """
        Asserts the following:
          - pac_file GET request returns JSON data
          - pac_file GET request with 'loc' parameter returns PAC file for each PROXY_LOCATION
          - pac_file GET request with 'loc' and 'mobile=True' parameter returns mobile PAC file for each PROXY_LOCATION
        """
        r = requests.get(URL + '/apis/pac_file', verify=False)
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.json(), dict)
        self.assertIn('Direct Rules', r.json().keys())
        self.assertIn('Proxy Rules', r.json().keys())

        for location in PROXY_LOCATIONS:
            r = requests.get(URL + f'/apis/pac_file?loc={location}', verify=False)
            self.assertEqual(r.status_code, 200)
            self.assertIn(f'proxy.{location}.medcity.net:80', r.text)
            r = requests.get(URL + f'/apis/pac_file?loc={location}&mobile=True', verify=False)
            self.assertEqual(r.status_code, 200)
            self.assertIn(f'proxy.{location}.medcity.net:9992', r.text)

    def test_101_pac_post_pac_file(self):
        """Asserts that additions can be made to the PAC file"""
        r = requests.post(URL + f'/apis/pac_file', json=PAC_JSON, verify=False)
        self.assertEqual(r.status_code, 200)

        # Ensure the request created what we expect
        r = requests.get(URL + f'/apis/pac_file?host={PAC_JSON["host_exp"]}&pilot=true', verify=False)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json(), PAC_POST_VALIDATION)

    def test_102_pac_delete_pac_file(self):
        """Asserts that deletions can be conducted from the PAC file"""
        r = requests.delete(URL + f'/apis/pac_file', json=PAC_JSON, verify=False)
        self.assertEqual(r.status_code, 200)

        r = requests.get(URL + f'/apis/pac_file?host={PAC_JSON["host_exp"]}', verify=False)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json(), PAC_DELETE_VALIDATION)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # NCM Testing
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_150_ncm_integration(self):
        """
        Asserts the following:
          - Login to NCM is successful
          - Data can be retrieved from NCM
        """
        r = requests.post(URL + '/apis/admin/get_current_snmp_strings', json=NCM_DATA, verify=False)
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.json(), dict)
        self.assertIsInstance(r.json()['ro'], str)
        self.assertIsInstance(r.json()['rw'], str)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # F5 Testing
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_160_f5_get_environment_list(self):
        """Asserts that JSON data is loaded, parsed, and returned via API"""
        r = requests.get(URL + '/apis/f5/environment_list', verify=False)
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.json(), list)

    def test_161_f5_vip_clone(self):
        """Asserts quite a bit.  This one will have to be well-thought"""
        # Current state is that it returns HTTP 202
        # The question is whether or not to keep it async
        pass
