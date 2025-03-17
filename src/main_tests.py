from apic.classes import *
from apic.utils import APIC, AppInstance
import unittest
import requests
import urllib3
import random
import logging
import time
import os
import sys
import json


urllib3.disable_warnings()

logging.Formatter.converter = time.gmtime
formatter = logging.Formatter(fmt='%(asctime)s.%(msecs)03dZ - %(name)s - %(levelname)s - %(message)s',
                              datefmt='%Y-%m-%dT%H:%M:%S')
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
ch.setFormatter(formatter)
logging.basicConfig(level=logging.DEBUG, handlers=[ch])  # ensures root logger is set to DEBUG
logger = logging.getLogger(__name__)
# Suppress annoying logging from libraries below
logging.getLogger('urllib3.connectionpool').setLevel(logging.WARNING)
logging.getLogger('flask_cors.core').setLevel(logging.WARNING)
logging.getLogger('flask_cors.extension').setLevel(logging.WARNING)
logging.getLogger('paramiko.transport').level = logging.WARNING
logging.getLogger('netmiko').level = logging.WARNING
logging.getLogger('icontrol').level = logging.WARNING
logging.getLogger('flask_cors').level = logging.DEBUG
logging.getLogger('botocore').level = logging.WARNING
logging.getLogger('boto3').level = logging.WARNING
logging.getLogger('github').level = logging.WARNING
logging.getLogger('zeep').level = logging.WARNING


# Development URL
URL = 'https://pyapisdev-netauto.apps.k8s.medcity.net'
# URL = 'http://127.0.0.1:8080'

# Sandbox URL
# URL = 'http://py-ap-is-duhes-stuff-snd.apps.ops2.paas.medcity.net'

PROD_ENV = 'xrdc-az1'  # GETs only
DEV_ENV = 'qol-az1'
DEV_ENV2 = 'qol-az2'
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

INST_PATH = 'pyunittest/qol_az1_pyunittest'

session = requests.Session()
session.trust_env = False

class APICCLassTests(unittest.TestCase):

    def test_002_apic_classes(self):
        for k, v in defined_classes.items():
            # Tests APICObject.load for all defined classes in apic.classes
            logger.debug(f'Testing {k} as {v}')
            if k in ['vmmDomP']:  # Not testing this as we do not use it in our fabrics
                continue
            elif k == InfraRsFuncToEpg.class_:
                # Assert that APICObject loads lists
                objs = APICObject.load(APIC(env=DEV_ENV).get_class(InfraRsFuncToEpg.class_).json()['imdata'])
                self.assertIsInstance(objs, list)

            js = APIC(env=DEV_ENV).get(f'/api/class/{k}.json').json()['imdata'][0]
            obj = APICObject.load(js)
            self.assertIsInstance(obj, v, f'{obj.self_json()} is not type {v}')
            self.assertIsInstance(obj.json(), dict)

            if isinstance(obj, AEP):
                logger.debug('Testing AEP.add_epg()')
                obj.add_epg(epg_dn='uni/tn-TEST/ap-TEST/epg-TEST1', encap=1100)
                infra_generic = obj.get_child_class(InfraGeneric.class_)
                self.assertIsInstance(infra_generic, InfraGeneric,
                                      f'{AEP} failed to add {InfraGeneric} to child objects')
                self.assertEqual(len(infra_generic.get_child_class_iter(InfraRsFuncToEpg.class_)), 1)
                func_to_epg = infra_generic.get_child_class(InfraRsFuncToEpg.class_)
                self.assertIsInstance(func_to_epg, InfraRsFuncToEpg)
                self.assertEqual(func_to_epg.attributes.encap, 'vlan-1100',
                                 f'{AEP} failed to generate correct encapsulation for {InfraRsFuncToEpg}')

                obj.add_epg(epg_dn='uni/tn-TEST/ap-TEST/epg-TEST2', encap=1101)
                self.assertEqual(len(infra_generic.get_child_class_iter(InfraRsFuncToEpg.class_)), 2)
                func_to_epg = infra_generic.get_child_class(InfraRsFuncToEpg.class_)


                logger.debug('Testing AEP.use_domain()')
                obj.use_domain('TEST')
                dom = obj.get_child_class(InfraRsDomP.class_)
                self.assertIsInstance(dom, InfraRsDomP)
                self.assertEqual(dom.attributes.tDn, 'uni/phys-TEST')

            if isinstance(obj, SwitchProfile):
                logger.debug('Testing SwitchProfile.create_switch_profile')
                self.assertRaises(ValueError, obj.create_switch_profile, name='TEST', nodes=[103, 104, 105])
                obj.create_switch_profile(name='TEST', nodes=[103, 104])
                self.assertEqual(len(obj.get_child_class_iter(LeafSelector.class_)), 1)
                sel = obj.get_child_class(LeafSelector.class_)
                self.assertEqual(sel.attributes.name, 'LF-103-104')
                self.assertEqual(sel.attributes.type, 'range')
                self.assertEqual(len(sel.get_child_class_iter(InfraNodeBlock.class_)), 1)
                blk = sel.get_child_class(InfraNodeBlock.class_)
                self.assertEqual(blk.attributes.name, 'LF-103-104')
                self.assertEqual(blk.attributes.from_, '103')
                self.assertEqual(blk.attributes.to_, '104')

            if isinstance(obj, EPG):
                logger.debug('Testing EPG.assign_bd')
                obj.assign_bd(name='Test')
                self.assertEqual(len(obj.get_child_class_iter(FvRsBd.class_)), 1)
                self.assertEqual(obj.get_child_class(FvRsBd.class_).attributes.tnFvBDName, 'Test')
                obj.assign_bd(name='Test-01')
                self.assertEqual(len(obj.get_child_class_iter(FvRsBd.class_)), 1)
                self.assertEqual(obj.get_child_class(FvRsBd.class_).attributes.tnFvBDName, 'Test-01')
                logger.debug('Testing EPG.domain')
                obj.domain(name='phy-dom-TEST')
                self.assertEqual(len(obj.get_child_class_iter(FvRsDomAtt.class_)), 1)
                dom = obj.get_child_class(FvRsDomAtt.class_)
                self.assertEqual(dom.attributes.tDn, 'uni/phys-phy-dom-TEST')
                self.assertRaises(AttributeError, dom.attributes.__getattribute__, 'name')
                obj.domain(name='phy-dom-TEST-01')
                self.assertEqual(len(obj.get_child_class_iter(FvRsDomAtt.class_)), 2)

            if isinstance(obj, BD):
                logger.debug('Testing specifics for BD')
                obj = BD()

                logger.debug('Testing BD.use_vrf')
                obj.use_vrf(name='vrf-test1')
                fvRsCtx = obj.get_child_class(FvRsCtx.class_)
                self.assertEqual(len(obj.get_child_class_iter(FvRsCtx.class_)), 1)
                self.assertEqual(fvRsCtx.attributes.tnFvCtxName, 'vrf-test1')
                obj.use_vrf(name='vrf-test2')
                fvRsCtx = obj.get_child_class(FvRsCtx.class_)
                self.assertEqual(len(obj.get_child_class_iter(FvRsCtx.class_)), 1)
                self.assertEqual(fvRsCtx.attributes.tnFvCtxName, 'vrf-test2')

                logger.debug('Testing BD.layer3')
                obj.layer3()
                self.assertEqual(obj.attributes.arpFlood, 'no')
                self.assertEqual(obj.attributes.unicastRoute, 'yes')
                self.assertEqual(obj.attributes.unkMacUcastAct, 'proxy')
                self.assertEqual(obj.attributes.ipLearning, 'yes')

                logger.debug('Testing BD.add_subnet')
                obj.add_subnet(subnet='192.168.1.1/28', description='test1')
                self.assertEqual(len(obj.get_child_class_iter(Subnet.class_)), 1)
                obj.add_subnet(subnet='192.168.1.17/28', description='test2')
                self.assertEqual(len(obj.get_child_class_iter(Subnet.class_)), 2)

                logger.debug('Testing BD.layer2')
                obj.layer2()
                self.assertEqual(obj.attributes.arpFlood, 'yes')
                self.assertEqual(obj.attributes.unicastRoute, 'no')
                self.assertEqual(obj.attributes.unkMacUcastAct, 'flood')

            if isinstance(obj, FabricNodeBlock):
                logger.debug('Testing FabricNodeBlock specifics')
                self.assertRaises(TypeError, FabricNodeBlock, 103, 104, 105)
                obj = FabricNodeBlock(103, 104)

            if isinstance(obj, Subnet) or isinstance(obj,L3extIP) or isinstance(obj, L3extSubnet) \
                    or isinstance(obj, L3extPath):
                logger.debug(f'Testing {obj}.network as IPv4Network')
                self.assertIsInstance(obj.network, IPv4Network)

            # TODO: Create test for FabricProtPol
            if isinstance(obj, FabricProtPol):
                pass

            # TODO: Create test for InterfacePolicyGroup
            if isinstance(obj, InterfacePolicyGroup):
                pass

            # TODO: Create test for EncapBlock
            if isinstance(obj, EncapBlock):
                pass

            # TODO: Create test for L3Out
            if isinstance(obj, L3Out):
                pass


class AppInstanceTests(unittest.TestCase):

    def setUp(self):
        """This verifies that the loading process works"""
        apps = session.get(URL + '/apis/appinst/applications', verify=False).json()
        self.assertIsInstance(apps, list)
        logger.info(apps)
        self.app = apps[random.randint(0, len(apps) - 1)]
        logger.info(f'Application selected: {self.app}')

        insts = session.get(URL + f'/apis/appinst/applications/{self.app}', verify=False).json()
        logger.info(insts)
        self.inst = insts[random.randint(0, len(insts) - 1)]
        logger.info(f'Instance selected: {self.inst}')

        self.instance = AppInstance.load(f'{self.app}/{self.inst}')

    def test_002_app_instance_json(self):
        self.assertIsInstance(self.instance.json(), dict)

    def test_003_app_instance_path(self):
        self.assertEqual(self.instance.path(), f'applications/{self.app}/{self.inst}')

    def test_004_app_instance_content(self):
        """Test that instance.content() returns valid JSON as string"""
        self.assertIsInstance(json.loads(self.instance.content()), dict)

    def test_005_app_instance_format_name(self):
        """Test name formatting for AppInstance"""
        r = 'test_this'
        t = 'epg-Test-This'
        logger.info(f'Testing format_name for {t}: {self.instance.format_name(t)}')
        self.assertEqual(self.instance.format_name(t), r)
        t = 'epg_Test-This'
        logger.info(f'Testing format_name for {t}: {self.instance.format_name(t)}')
        self.assertEqual(self.instance.format_name(t), r)
        t = 'epg|Test|This'
        logger.info(f'Testing format_name for {t}: {self.instance.format_name(t)}')
        self.assertEqual(self.instance.format_name(t), r)
        t = 'epgTest-This'
        logger.info(f'Testing format_name for {t}: {self.instance.format_name(t)}')
        self.assertEqual(self.instance.format_name(t), r)
        t = 'bd-Test-This'
        logger.info(f'Testing format_name for {t}: {self.instance.format_name(t)}')
        self.assertEqual(self.instance.format_name(t), r)
        t = 'ap-Test-This'
        logger.info(f'Testing format_name for {t}: {self.instance.format_name(t)}')
        self.assertEqual(self.instance.format_name(t), r)

    def test_006_app_instance_generate_config(self):
        """Test generating configuration from application instance data"""
        logger.info(f'Testing AppInstance.generate_config()')
        r = self.instance.generate_config()
        self.assertIsInstance(r, Tenant)

    def test_007_app_instance_generate_config_drt(self):
        """Test generating DRT configuration from application instance data"""
        logger.info(f'Testing AppInstance.generate_config(drt=True)')
        r = self.instance.generate_config(drt=True)
        self.assertIsInstance(r, Tenant)
        self.assertEqual(r.attributes.name.lower()[3:].replace('-', '_'),
                         str(self.instance)[:len(r.attributes.name) - 3])

    def test_008_app_instance_epg_dn(self):
        """Test EPG distinguished name from application instance data"""
        logger.info(f'Testing AppInstance.epg_dn()')
        self.assertEqual(self.instance.epg_dn(),
                         f'uni/tn-{self.instance.currentAZ.env.__getattribute__(self.instance.tenant)}/ap-{self.instance.apName}/epg-{self.instance.epgName}')

    def test_009_app_instance_epg_dn_override(self):
        """Test EPG distinguished name override from application instance data"""
        logger.info(f'Testing AppInstance.epg_dn(override=True)')
        self.assertEqual(self.instance.epg_dn(override=True),
                         f'uni/tn-{self.instance.currentAZ.env.__getattribute__(self.instance.tenant)}/ap-{self.instance.application}/epg-{self.instance}')

    def test_010_app_instance_epg_dn_override_drt(self):
        """Test EPG distinguished name override and drt from application instance data"""
        logger.info(f'Testing AppInstance.epg_dn(override=True, drt=True)')
        self.assertEqual(self.instance.epg_dn(override=True, drt=True),
                         f'uni/tn-tn-{self.instance.originAZ}/ap-{self.instance.application}/epg-{self.instance}')

    def test_011_app_instance_epg_dn_drt(self):
        """Test EPG distinguished name override and drt from application instance data"""
        logger.info(f'Testing AppInstance.epg_dn(drt=True)')
        self.assertEqual(self.instance.epg_dn(drt=True),
                         f'uni/tn-tn-{self.instance.originAZ}/ap-{self.instance.ap_name()}/epg-{self.instance.epg_name()}')

    def test_012_app_instance_placeholder_mapping(self):
        """Test AppInstance.placeholder_mapping()"""
        logger.info(f'Testing AppInstance.placeholder_mapping()')
        test_result = {
            'AEP': 'aep-Placeholders',
            'Tenant': self.instance.tenant_name(),
            'AP': self.instance.ap_name(),
            'EPG': self.instance.epg_name()
        }

        self.assertEqual(self.instance.placeholder_mapping(), test_result)

    def test_013_app_instance_placeholder_mapping(self):
        """Test AppInstance.placeholder_mapping(override=True)"""
        logger.info(f'Testing AppInstance.placeholder_mapping(override=True)')
        test_result = {
            'AEP': 'aep-Placeholders',
            'Tenant': self.instance.tenant_name(),
            'AP': self.instance.application,
            'EPG': f'{self.instance}'
        }

        self.assertEqual(self.instance.placeholder_mapping(override=True), test_result)

    def test_014_app_instance_placeholder_mapping(self):
        """Test AppInstance.placeholder_mapping(drt=True)"""
        logger.info(f'Testing AppInstance.placeholder_mapping(drt=True)')
        test_result = {
            'AEP': 'aep-Placeholders',
            'Tenant': self.instance.tenant_name(drt=True),
            'AP': self.instance.ap_name(),
            'EPG': self.instance.epg_name()
        }

        self.assertEqual(self.instance.placeholder_mapping(drt=True), test_result)

    def test_015_deploy(self):
        logger.info(f'Testing AppInstance.deploy_instance({INST_PATH})')
        instance = AppInstance.load(INST_PATH)

        status, response = AppInstance.deploy_instance(inst_path=INST_PATH)
        self.assertEqual(status, 200)

        tenant = APICObject.load(response['configuration'])
        self.assertIsInstance(tenant, Tenant)

        config_bd = tenant.get_child_class(BD.class_)
        config_ap = tenant.get_child_class(AP.class_)
        config_epg = config_ap.get_child_class(EPG.class_)
        config_subnet = config_bd.get_child_class(Subnet.class_)

        bd = instance.originAZ.get(f'/api/mo/{instance.bd_dn()}.json?rsp-subtree=full&rsp-prop-include=config-only').json()['imdata'][0]
        bd = APICObject.load(bd)
        self.assertIsInstance(bd, BD)
        self.assertEqual(bd.attributes.name, config_bd.attributes.name)
        self.assertEqual(bd.attributes.dn, instance.bd_dn())
        subnets = bd.get_child_class_iter(Subnet.class_)

        epg = instance.originAZ.get(f'/api/mo/{instance.epg_dn()}.json?rsp-subtree=full&rsp-prop-include=config-only').json()['imdata'][0]
        epg = APICObject.load(epg)
        ap_dn = AP.search(epg.attributes.dn).group()
        self.assertIsInstance(epg, EPG)
        self.assertEqual(epg.attributes.dn, instance.epg_dn())
        self.assertIn('fvRsDomAtt', [_.class_ for _ in epg.children])

        ap = instance.originAZ.get(f'/api/mo/{ap_dn}.json?rsp-subtree=full').json()['imdata'][0]
        ap = APICObject.load(ap)
        self.assertIsInstance(ap, AP)
        self.assertEqual(ap.attributes.name, config_ap.attributes.name)

        ife = instance.originAZ.get(f'/api/mo/uni/infra/attentp-aep-Placeholders/gen-default/rsfuncToEpg-[{epg.attributes.dn}].json').json()['imdata'][0]
        ife = APICObject.load(ife)
        self.assertIsInstance(ife, InfraRsFuncToEpg)
        self.assertEqual(ife.attributes.tDn, instance.epg_dn())

        # Remove the instance configuration for now
        # for o in [bd, epg, ife]:
        #     o.remove_admin_props()
        #     o.delete()
        #     logger.info(o.self_json())
        #     r = instance.originAZ.post(configuration=o.self_json())
        #     logger.info(r.json())
        #     self.assertEqual(r.status_code, 200)

    # TODO: Add test for moving instance using PyUnittest instance
    def test_016_move(self):
        logger.info(f'Testing AppInstance.move_instance({INST_PATH})')
        instance = AppInstance.load(INST_PATH)

        start = instance.currentAZ
        target = APIC(env=DEV_ENV2)

        status, response = AppInstance.move_instance(inst_path=INST_PATH, az=DEV_ENV2)
        self.assertEqual(status, 200)

        tenant = APICObject.load(response['configuration'])
        self.assertIsInstance(tenant, Tenant)

        config_bd = tenant.get_child_class(BD.class_)
        config_ap = tenant.get_child_class(AP.class_)
        config_epg = config_ap.get_child_class(EPG.class_)
        config_subnet = config_bd.get_child_class(Subnet.class_)

        # Verify that objects exists in target AZ and not in start AZ
        self.assertFalse(start.get(f'/api/mo/{instance.bd_dn(override=True)}.json').json()['imdata'])
        bd = target.get(f'/api/mo/{instance.bd_dn(override=True)}.json?rsp-subtree=full').json()['imdata'][0]
        bd = APICObject.load(bd)
        self.assertIsInstance(bd, BD)
        self.assertEqual(bd.attributes.name, config_bd.attributes.name)
        self.assertEqual(bd.attributes.dn, instance.bd_dn(override=True))
        subnets = bd.get_child_class_iter(Subnet.class_)

        self.assertFalse(start.get(f'/api/mo/{instance.epg_dn(override=True)}.json').json()['imdata'])
        epg = target.get(f'/api/mo/{instance.epg_dn(override=True)}.json?rsp-subtree=full').json()['imdata'][0]
        epg = APICObject.load(epg)
        ap_dn = AP.search(epg.attributes.dn).group()
        self.assertIsInstance(epg, EPG)
        self.assertEqual(epg.attributes.dn, instance.epg_dn(override=True))
        self.assertIn('fvRsDomAtt', [_.class_ for _ in epg.children])

        ap = target.get(f'/api/mo/{ap_dn}.json?rsp-subtree=full').json()['imdata'][0]
        ap = APICObject.load(ap)
        self.assertIsInstance(ap, AP)
        self.assertEqual(ap.attributes.name, config_ap.attributes.name)

        ife = target.get(f'/api/mo/uni/infra/attentp-aep-Placeholders/gen-default/rsfuncToEpg-[{epg.attributes.dn}].json').json()['imdata'][0]
        ife = APICObject.load(ife)
        self.assertIsInstance(ife, InfraRsFuncToEpg)
        self.assertEqual(ife.attributes.tDn, instance.epg_dn(override=True))

    def test_017_withdraw(self):
        logger.info(f'Testing AppInstance.withdraw_instance({INST_PATH})')
        instance = AppInstance.load(INST_PATH)

        status, response = AppInstance.withdraw_instance(inst_path=INST_PATH)

        # There should be 5 successful deletions: EPG, AP, Subnet, BD, and VLAN association
        self.assertEqual(len( [_['response_code'] for _ in response['deletions'] if _['response_code'] == 200]), 5)

        for network in instance.networks:
            self.assertFalse(instance.currentAZ.get(f'/api/mo/{instance.bd_dn()}/subnet-[{network}].json').json()['imdata'])

        self.assertFalse(instance.currentAZ.get(f'/api/mo/{instance.epg_dn()}.json').json()['imdata'])
        self.assertFalse(instance.currentAZ.get(f'/api/mo/{instance.bd_dn()}.json').json()['imdata'])
        self.assertFalse(instance.currentAZ.get(f'/api/mo/{AP.search(instance.epg_dn()).group()}.json').json()['imdata'])

        # TODO: Test everything more thoroughly


class ACIAPITests(unittest.TestCase):

    def test_002_aci_environment_list(self):
        """
        Asserts the following:
          - data/ACIEnvironments.json can be parsed and loaded
          - API endpoint /apis/aci/environment_list is providing results
        """
        r = session.get(URL + '/apis/aci/environment_list', verify=(True if URL.startswith('http:') else False))
        logger.debug(f'Test of {r.request.url} : HTTP {r.status_code} {r.reason}')
        self.assertEqual(r.status_code, 200)
        logger.debug(r.json())
        self.assertIsInstance(r.json(), list)

    def test_003_aci_get_tenant_ap_epg(self):
        """
        Asserts the following:
          - Login to APIC works
          - Getting Tenants, APs, and EPGs lists from APIC is working
          - get_epg_data returns data
        """
        r = session.get(URL + f'/apis/aci/{DEV_ENV}/tenants', verify=False)
        logger.debug(f'Test of {r.request.url} : HTTP {r.status_code} {r.reason}')
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.json(), list)
        # tenant = r.json()[random.randint(0, r.json().index(r.json()[-1]))]
        tenant = 'QOLab'

        r = session.get(URL + f'/apis/aci/{DEV_ENV}/{tenant}/aps', verify=False)
        logger.debug(f'Test of {r.request.url} : HTTP {r.status_code} {r.reason}')
        self.assertEqual(r.status_code, 200)
        logger.debug(r.json())
        self.assertIsInstance(r.json(), list)
        ap = r.json()[random.randint(0, len(r.json()) - 1)]

        r = session.get(URL + f'/apis/aci/{DEV_ENV}/{tenant}/{ap}/epgs', verify=False)
        logger.debug(f'Test of {r.request.url} : HTTP {r.status_code} {r.reason}')
        self.assertEqual(r.status_code, 200)
        logger.debug(r.json())
        self.assertIsInstance(r.json(), list)
        epg = r.json()[random.randint(0, len(r.json()) - 1)]

        logger.debug(f'Test Case from {DEV_ENV}:  {tenant}/{ap}/{epg}')

        r = session.get(URL + f'/apis/aci/{DEV_ENV}/get_epg_data/{epg}', verify=False)
        logger.debug(f'Test of {r.request.url} : HTTP {r.status_code} {r.reason}')
        self.assertEqual(r.status_code, 200)
        logger.debug(r.json())
        self.assertEqual(r.json()['epg_name'], epg)

    def test_004_aci_get_aeps(self):
        """Asserts that AEP lists will populate and tests usage for random AEP"""
        r = session.get(URL + f'/apis/aci/{DEV_ENV}/aeps', verify=False)
        logger.debug(f'Test of {r.request.url} : HTTP {r.status_code} {r.reason}')
        self.assertEqual(r.status_code, 200)
        logger.debug(r.json())
        self.assertIsInstance(r.json(), list)

        aeps = APICObject.load(APIC(env=DEV_ENV).get_class_config_only('infraRsAttEntP').json()['imdata'])
        aep = aeps[random.randint(0, len(aeps) - 1)]
        aep_name = AEP.search(aep.attributes.tDn).group('name')

        r = session.get(URL + f'/apis/aci/{DEV_ENV}/{aep_name}/usage')
        logger.debug(f'Test of {r.request.url} : HTTP {r.status_code} {r.reason}')
        self.assertEqual(r.status_code, 200)
        logger.debug(r.json())
        if r.json():
            self.assertIsInstance(r.json()[list(r.json().keys())[0]], list)

    def test_005_aci_get_switch_profiles(self):
        """Asserts that switch profile lists will populate"""
        r = session.get(URL + f'/apis/aci/{DEV_ENV}/switch_profiles', verify=False)
        logger.debug(f'Test of {r.request.url} : HTTP {r.status_code} {r.reason}')
        self.assertEqual(r.status_code, 200)
        logger.debug(r.json())
        self.assertIsInstance(r.json(), list)

    def test_006_aci_get_aci_vlan(self):
        """Asserts get_aci_vlan() returns data"""
        r = session.get(URL + f'/apis/aci/{PROD_ENV}/get_aci_vlan/2000', verify=False)
        logger.debug(f'Test of {r.request.url} : HTTP {r.status_code} {r.reason}')
        self.assertEqual(r.status_code, 200)
        logger.debug(r.json())
        self.assertIsInstance(r.json(), list)

    def test_007_aci_get_bd_by_ip_fvsubnet(self):
        """Asserts get_bd_by_ip() returns data given an IP from a fvSubnet. Looking for bridge_domain"""
        # Retrieve random subnet to test
        r = APICObject.load(APIC(env='qol-az1').get_class_config_only('fvSubnet').json()['imdata'])
        subnet = r[random.randint(0, len(r) - 1)]
        ip = IPv4Network(subnet.attributes.ip, strict=False).network_address + 1

        # Test using IP of fvSubnet from QOL-AZ1
        r = session.get(URL + f'/apis/aci/qol-az1/get_bd_by_ip/{ip}', verify=False)
        logger.debug(f'Testing {r.request.url} with IP {ip}')
        logger.debug(f'Test of {r.request.url} : HTTP {r.status_code} {r.reason}')
        self.assertEqual(r.status_code, 200)
        logger.debug(r.json())
        self.assertIsInstance(r.json()['bridge_domain'], str)

    def test_008_aci_get_bd_by_ip_external_epg(self):
        """Asserts get_bd_by_ip() returns data given an IP from an external EPG"""
        # Retrieve random l3extSubnet to test
        r = APICObject.load(APIC(env='qol-az1').get_class_config_only('l3extSubnet').json()['imdata'])
        r = [_ for _ in r if _.attributes.ip != '0.0.0.0/0']
        r = [_ for _ in r if Tenant.search(_.attributes.dn).group('name') != 'infra']
        subnet = r[random.randint(0, len(r) - 1)]
        ip = IPv4Network(subnet.attributes.ip, strict=False).network_address + 1

        # Test using IP of external EPG from QOL-AZ1
        r = session.get(URL + f'/apis/aci/qol-az1/get_bd_by_ip/{ip}', verify=False)
        logger.debug(f'Testing {r.request.url} with IP {ip}')
        logger.debug(f'Test of {r.request.url} : HTTP {r.status_code} {r.reason}')
        self.assertEqual(r.status_code, 200)
        logger.debug(r.json())
        self.assertIsInstance(r.json()['external_networks'], list)

    def test_009_aci_get_bd_by_ip_interface(self):
        """Asserts get_bd_by_ip() returns data given an IP from an interface on an L3Out"""
        # Retrieve random l3extRsPathL3OutAtt to test
        r = APICObject.load(APIC(env='qol-az1').get_class_config_only(L3extPath.class_).json()['imdata'])
        r = [_ for _ in r if _.attributes.addr != '0.0.0.0']
        r = [_ for _ in r if Tenant.search(_.attributes.dn).group('name') != 'infra']  # Required because of multipod
        subnet = r[random.randint(0, len(r) - 1)]
        ip = IPv4Network(subnet.attributes.addr, strict=False).network_address + 1

        # Test using sub-interface IP from QOL-AZ1
        r = session.get(URL + f'/apis/aci/qol-az1/get_bd_by_ip/{ip}', verify=False)
        logger.debug(f'Testing {r.request.url} with IP {ip}')
        logger.debug(f'Test of {r.request.url} : HTTP {r.status_code} {r.reason}')
        self.assertEqual(r.status_code, 200)
        logger.debug(r.json())
        self.assertIsInstance(r.json()['l3out_paths'], list)

    def test_009_aci_get_bd_by_ip_svi(self):
        """Asserts get_bd_by_ip() returns data given an IP from an interface on an L3Out"""
        # Retrieve random l3extIp to test
        r = APICObject.load(APIC(env='xrdc-az1').get_class_config_only(L3extIP.class_).json()['imdata'])
        r = [_ for _ in r if _.attributes.addr != '0.0.0.0']
        r = [_ for _ in r if Tenant.search(_.attributes.dn).group('name') != 'infra']  # Required because of multipod
        subnet = r[random.randint(0, len(r) - 1)]
        ip = IPv4Network(subnet.attributes.addr, strict=False).network_address + 1

        # Test using sub-interface IP from QOL-AZ1
        r = session.get(URL + f'/apis/aci/xrdc-az1/get_bd_by_ip/{ip}', verify=False)
        logger.debug(f'Testing {r.request.url} with IP {ip}')
        logger.debug(f'Test of {r.request.url} : HTTP {r.status_code} {r.reason}')
        self.assertEqual(r.status_code, 200)
        logger.debug(r.json())
        self.assertIsInstance(r.json()['l3out_paths'], list)

    def test_010_aci_get_dr_vlans(self):
        """Asserts get_dr_vlans() returns data"""
        r = session.get(URL + f'/apis/aci/{PROD_ENV}/get_dr_vlans', verify=False)
        logger.debug(f'Test of {r.request.url} : HTTP {r.status_code} {r.reason}')
        self.assertEqual(r.status_code, 200)
        logger.debug(r.json())
        self.assertIsInstance(r.json(), dict)

    def test_011_aci_get_nondr_vlans(self):
        """Asserts get_nondr_vlans returns data"""
        r = session.get(URL + f'/apis/aci/{PROD_ENV}/get_nondr_vlans', verify=False)
        logger.debug(f'Test of {r.request.url} : HTTP {r.status_code} {r.reason}')
        self.assertEqual(r.status_code, 200)
        logger.debug(r.json())
        self.assertIsInstance(r.json(), dict)

    def test_012_aci_get_nondr_epgs(self):
        """Asserts nondr_epgs returns data"""
        r = session.get(URL + f'/apis/aci/{PROD_ENV}/nondr_epgs', verify=False)
        logger.debug(f'Test of {r.request.url} : HTTP {r.status_code} {r.reason}')
        self.assertEqual(r.status_code, 200)
        logger.debug(r.json())
        self.assertIsInstance(r.json(), list)

    def test_013_aci_get_dr_epgs(self):
        """Asserts dr_epgs returns data"""
        r = session.get(URL + f'/apis/aci/{PROD_ENV}/dr_epgs', verify=False)
        logger.debug(f'Test of {r.request.url} : HTTP {r.status_code} {r.reason}')
        self.assertEqual(r.status_code, 200)
        logger.debug(r.json())
        self.assertIsInstance(r.json(), list)

    def test_014_aci_get_pods(self):
        """Asserts pods returns data"""
        r = session.get(URL + f'/apis/aci/{DEV_ENV}/pods', verify=False)
        logger.debug(f'Test of {r.request.url} : HTTP {r.status_code} {r.reason}')
        self.assertEqual(r.status_code, 200)
        logger.debug(r.json())
        self.assertIsInstance(r.json(), list)

    def test_015_aci_get_teps(self):
        """Asserts teps returns data"""
        r = session.get(URL + f'/apis/aci/{PROD_ENV}/teps', verify=False)
        logger.debug(f'Test of {r.request.url} : HTTP {r.status_code} {r.reason}')
        self.assertEqual(r.status_code, 200)
        logger.debug(r.json())
        self.assertIsInstance(r.json(), list)

    def test_016_aci_get_next_vlan(self):
        """
        Asserts the following:
          - get_next_vlan returns an available VLAN
          - get_vlan_data returns accurate information given an unused VLAN
          - get_vlan_data returns accurate information given a used VLAN
        """
        # Retrieve the next VLAN
        r = session.get(URL + f'/apis/aci/{PROD_ENV}/get_next_vlan', verify=False)
        logger.debug(f'Test of {r.request.url} : HTTP {r.status_code} : {r.reason}')
        self.assertEqual(r.status_code, 200)
        logger.debug(r.json())
        self.assertIsInstance(r.json(), int)

        vlan = r.json()

        # Ensure the returned VLAN ID is not used
        r = session.get(URL + f'/apis/v2/aci/{PROD_ENV}/get_vlan_data?VLAN={vlan}', verify=False)
        logger.debug(f'Test of {r.request.url} : HTTP {r.status_code} : {r.reason}')
        self.assertEqual(r.status_code, 200)
        logger.debug(r.json())
        self.assertEqual(r.json(), [])
        self.assertEqual(len(r.json()), 0)

        # Ensure the preceding VLAN ID is used
        r = session.get(URL + f'/apis/v2/aci/{PROD_ENV}/get_vlan_data?VLAN={vlan-1}', verify=False)
        logger.debug(f'Test of {r.request.url} : HTTP {r.status_code} : {r.reason}')
        self.assertEqual(r.status_code, 200)
        logger.debug(r.json())
        self.assertGreater(len(r.json()), 0)

    def test_017_aci_get_interface_policies_by_endpoint(self):
        ips = APICObject.load(APIC(env=DEV_ENV).get_class('fvIp').json()['imdata'])
        ip = ips[random.randint(0, len(ips) - 1)]

        r = session.get(URL + f'/apis/aci/{DEV_ENV}/get_interface_policies_by_endpoint?ip={ip.attributes.addr}')
        logger.debug(f'Test of {r.request.url} : HTTP {r.status_code} {r.reason}')
        self.assertEqual(r.status_code, 200)
        logger.debug(r.json())
        self.assertIsInstance(r.json()['aep'], str)

    def test_018_assign_vlan_to_aep(self):
        payload = {
            'APIKey': os.getenv('localapikey'),
            'assignments': [
                {
                    "vlan_ids": [
                        2000
                    ],
                    "aep": "aep-Placeholders"
                }
            ]
        }

        r = session.post(URL + f'/apis/aci/{DEV_ENV}/assign_vlan_to_aep', json=payload, verify=False)
        logger.debug(f'Test of {r.request.url} : HTTP {r.status_code} {r.reason}')
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.json(), list)

    def test_019_aci_create_custom_epg(self):
        """
        Asserts the following:
          - create_custom_epg takes data
          - expected data exists
          - undo_create_custom_epg does what is expected
        """
        apic = APIC(env=DEV_ENV)

        basename = 'PyUnittest'
        ap_name = f'ap-{basename}'
        bd_name = f'bd-{basename}'
        epg_name = f'epg-{basename}'
        network = '192.168.169.160/30'
        payload = {
            "APIKey": os.getenv('localapikey'),
            "TenantName": apic.env.Tenant,
            "VRFName": apic.env.VRF,
            "AppProfileName": ap_name,
            "BridgeDomainName": bd_name,
            "EPGName": epg_name,
            "Description": "Unittesting NetworkAPIs create_custom_epg_v2",
            "Subnets": [
                network
            ],
            "AEPs": []
        }

        # Send request to create custom EPG
        r = requests.post(URL + f'/apis/v2/aci/{DEV_ENV}/create_custom_epg', json=payload, verify=False)
        logger.debug(f'Test of {r.request.url} : HTTP {r.status_code} {r.reason}')
        logger.debug(r.json())
        self.assertEqual(r.status_code, 200)

        # Verify results in APIC
        ap = APICObject.load(apic.get_class_by_name(fvAp=ap_name).json()['imdata'][0])
        bd = APICObject.load(apic.get_class_by_name(fvBD=bd_name).json()['imdata'][0])
        epg = APICObject.load(apic.get_class_by_name(fvAEPg=epg_name).json()['imdata'][0])
        ife = APICObject.load(apic.get_class('infraRsFuncToEpg').json()['imdata'])
        ife = next(_ for _ in ife if _.attributes.tDn == epg.attributes.dn)
        subnet = bd.pop_child_class('fvSubnet')

        logger.debug(ap.json())
        self.assertIsInstance(ap, AP)
        logger.debug(bd.json())
        self.assertIsInstance(bd, BD)
        logger.debug(epg.json())
        self.assertIsInstance(epg, EPG)
        logger.debug(ife.json())
        self.assertIsInstance(ife, InfraRsFuncToEpg)
        logger.debug(subnet.json())
        self.assertIsInstance(subnet, Subnet)

        self.assertIn(apic.env.Tenant, bd.attributes.dn)
        self.assertIn('fvRsCtx', [_.class_ for _ in bd.children])
        self.assertEqual(bd.attributes.unicastRoute, 'yes')
        self.assertEqual(bd.attributes.unkMacUcastAct, 'proxy')
        self.assertEqual(bd.attributes.ipLearning, 'yes')
        self.assertEqual(bd.attributes.arpFlood, 'no')

        self.assertIn(apic.env.Tenant, ap.attributes.dn)
        self.assertIn('fvAEPg', [_.class_ for _ in ap.children])

        self.assertIn('fvRsDomAtt', [_.class_ for _ in epg.children])
        self.assertIn('fvRsBd', [_.class_ for _ in epg.children])

        self.assertEqual(subnet.attributes.ip, '192.168.169.161/30')
        self.assertEqual(subnet.attributes.scope, 'public')

        # Remove what was created
        for o in [ap, bd, ife]:
            o.remove_admin_props()
            o.delete()
            r = apic.post(configuration=o.json())
            logger.debug(r.json())
            self.assertEqual(r.status_code, 200)


class PACFileTesting(unittest.TestCase):

    def test_100_pac_get_pac_file(self):
        """
        Asserts the following:
          - pac_file GET request returns JSON data
          - pac_file GET request with 'loc' parameter returns PAC file for each PROXY_LOCATION
          - pac_file GET request with 'loc' and 'mobile=True' parameter returns mobile PAC file for each PROXY_LOCATION
        """
        r = requests.get(URL + '/apis/pac_file', verify=False)
        logger.debug(f'Test of {r.request.url} : HTTP {r.status_code} {r.reason}')
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.json(), dict)
        self.assertIn('Direct Rules', r.json().keys())
        self.assertIn('Proxy Rules', r.json().keys())

        for location in PROXY_LOCATIONS:
            r = requests.get(URL + f'/apis/pac_file?loc={location}', verify=False)
            logger.debug(f'Test of {r.request.url} : HTTP {r.status_code} {r.reason}')
            self.assertEqual(r.status_code, 200)
            self.assertIn(f'proxy.{location}.medcity.net:80', r.text)
            r = requests.get(URL + f'/apis/pac_file?loc={location}&mobile=True', verify=False)
            logger.debug(f'Test of {r.request.url} : HTTP {r.status_code} {r.reason}')
            self.assertEqual(r.status_code, 200)
            self.assertIn(f'proxy.{location}.medcity.net:9992', r.text)

    def test_101_pac_post_pac_file(self):
        """Asserts that additions can be made to the PAC file"""
        r = requests.post(URL + f'/apis/pac_file', json=PAC_JSON, verify=False)
        logger.debug(f'Test of {r.request.url} : HTTP {r.status_code} {r.reason}')
        self.assertEqual(r.status_code, 200)

        # Ensure the request created what we expect
        r = requests.get(URL + f'/apis/pac_file?host={PAC_JSON["host_exp"]}&pilot=true', verify=False)
        logger.debug(f'Test of {r.request.url} : HTTP {r.status_code} {r.reason}')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json(), PAC_POST_VALIDATION)

    def test_102_pac_delete_pac_file(self):
        """Asserts that deletions can be conducted from the PAC file"""
        r = requests.delete(URL + f'/apis/pac_file', json=PAC_JSON, verify=False)
        logger.debug(f'Test of {r.request.url} : HTTP {r.status_code} {r.reason}')
        self.assertEqual(r.status_code, 200)

        r = requests.get(URL + f'/apis/pac_file?host={PAC_JSON["host_exp"]}', verify=False)
        logger.debug(f'Test of {r.request.url} : HTTP {r.status_code} {r.reason}')
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
        r = session.post(URL + '/apis/admin/get_current_snmp_strings', json=NCM_DATA, verify=False)
        logger.debug(f'Test of {r.request.url} : HTTP {r.status_code} : {r.reason}')
        self.assertEqual(r.status_code, 200)
        logger.debug(r.json())
        self.assertIsInstance(r.json(), dict)
        self.assertIsInstance(r.json()['ro'], str)
        self.assertIsInstance(r.json()['rw'], str)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # F5 Testing
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_160_f5_get_environment_list(self):
        """Asserts that JSON data is loaded, parsed, and returned via API"""
        r = requests.get(URL + '/apis/f5/environment_list', verify=False)
        logger.debug(f'Test of {r.request.url} : HTTP {r.status_code} {r.reason}')
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.json(), list)

    def test_161_f5_vip_clone(self):
        """Asserts quite a bit.  This one will have to be well-thought"""
        # Current state is that it returns HTTP 202
        # The question is whether to keep it async
        pass
