from ipaddress import IPv4Network
import string
import random
import re


def annotation_parser(annotations: str) -> dict:
    """Parses comma separated string of key, value pairs.  Formatted as key:value,k:v"""
    if not annotations:
        return {}

    metadata = {}
    for kv in annotations.split(','):
        key, value = kv.split(':')
        if value.lower() == 'true':
            metadata[key] = True
        elif value.lower() == 'false':
            metadata[key] = False
        elif re.match(r'^\d+$', value):
            metadata[key] = int(value)
        else:
            metadata[key] = value

    return metadata


def annotation_to_string(annotations: dict) -> str:
    """Returns string representation of a metadata dictionary"""
    annotation_string = ''
    for key, value in annotations.items():
        if isinstance(value, str):
            annotation_string += f'{key.replace(" ", "_")}:{value.replace(" ", "_")},'
        else:
            annotation_string += f'{key.replace(" ", "_")}:{value},'

    return annotation_string.strip(',')


class Attributes:
    def __init__(self, **kwargs):
        if not kwargs == {}:
            for k, v in kwargs.items():
                # if arg == 'annotation':
                #     self.__setattr__(k, annotation_parser(v))
                # else:
                self.__setattr__(k, v)

    def __iter__(self) -> tuple:
        for k, v in self.__dict__.items():
            yield k, v

    def __hasattr__(self, attribute: str) -> bool:
        if attribute in self.__dict__.keys():
            return True
        else:
            return False

    def json(self, empty_fields: bool=False) -> dict:
        json_data = {}
        for attribute in self.__dict__.keys():
            if not self.__getattribute__(attribute) == '':
                # if attribute == 'annotation':
                #     json_data[attribute] = annotation_to_string(self.__getattribute__(attribute).json())
                # else:
                json_data[attribute] = self.__getattribute__(attribute)
            elif empty_fields and self.__getattribute__(attribute) == '':
                json_data[attribute] = ''
        return json_data

    @classmethod
    def load(cls, json_data: dict):
        return cls(**json_data)

    def remove_admin_props(self):
        admin_props = [
            'modTs', 'lcOwn', 'uid', 'monPolDn', 'extMngdBy', 'ownerKey', 'ownerTag', 'lastStateModTs', 'state',
            'unixUserId', 'rn', 'pwdChangeIntervalBegin', 'pwdChangedDate', 'expState', 'fingerprint',
            'certificateDecodeInformation', 'certdn', 'certValidUntil', 'rType', 'stateQual', 'tType', 'tCl',
            'configSt', 'isSharedSrvMsiteEPg', 'pcTag', 'userdom'
        ]
        for _ in admin_props:
            try:
                self.__delattr__(_)
            except AttributeError:
                pass


class APICObject:
    children: list
    class_: str
    attributes: Attributes
    attrs: dict
    _dn_attributes: list
    _dn_template: str
    tf_resource: str

    def __iter__(self):
        for k, v in self.attributes.__dict__.items():
            yield k, v

    def __init__(self, *args, **kwargs):
        if self.attrs:
            self.attributes = Attributes(**self.attrs)
        else:
            self.attributes = Attributes()
        self.children = []
        if kwargs:
            self._set_attributes(**kwargs)

        self._customize_(*args, **kwargs)

    def _customize_(self, *args, **kwargs):
        pass

    @classmethod
    def load(cls, json_data: dict or list):
        if not json_data:
            return None
        if isinstance(json_data, dict):
            pass
        else:
            json_data = json_data[0]

        class_name = list(json_data.keys())[0]
        _class_ = defined_classes.get(class_name)

        if _class_:
            obj = _class_(**json_data[class_name]['attributes'])
        else:
            obj = GenericClass(class_name, **json_data[class_name]['attributes'])

        # obj.attributes = Attributes.load(json_data[obj.class_]['attributes'])
        if 'children' in json_data[class_name].keys() and len(json_data[class_name]['children']) > 0:
            for child in json_data[class_name]['children']:
                child = cls.load(child)
                obj.children.append(child)

        return obj

    def json(self, empty_fields: bool=False):
        try:
            self._dn_constructor()
        except AttributeError:
            pass

        if self.children == list():
            json_data = {
                self.class_: {
                    'attributes': self.attributes.json(empty_fields=empty_fields)
                }
            }
        else:
            json_data = {
                self.class_: {
                    'attributes': self.attributes.json(empty_fields=empty_fields),
                    'children': [obj.json(empty_fields=empty_fields) for obj in self.children]
                }
            }

        return json_data

    def self_json(self):
        try:
            self._dn_constructor()
        except AttributeError:
            pass

        json_data = {
            self.class_: {
                'attributes': self.attributes.json()
            }
        }

        return json_data

    def modify(self):
        self.attributes.__setattr__('status', 'modified')

    def create_modify(self):
        self.attributes.__setattr__('status', 'created,modified')

    def create(self):
        self.attributes.__setattr__('status', 'created')

    def delete(self):
        self.attributes.__setattr__('status', 'deleted')

    def _dn_constructor(self):
        def replacer(mo: re.Match):
            if mo.group(1) in self._dn_attributes:
                return self.__getattribute__(mo.group(1).__str__())

        self.attributes.dn = re.sub(r'\{(\w+)}', replacer, self._dn_template)

    def pop_child_class(self, class_):
        if class_ in [_.class_ for _ in self.children]:
            child = self.children.pop(self.children.index(next(c for c in self.children if c.class_ == class_)))
            return child
        else:
            return None

    def pop_child_class_iter(self, class_):
        children = []
        for child in self.children[:]:
            if child.class_ == class_:
                children += [self.children.pop(child)]
        return children

    def get_child_class(self, class_):
        if class_ in [_.class_ for _ in self.children]:
            child = next(c for c in self.children if c.class_ == class_)
            return child
        else:
            return None

    def get_child_class_iter(self, class_):
        return [c for c in self.children if c.class_ == class_]

    def get_child_tdn(self, dn: str):
        try:
            child = next(c for c in self.children if c.attributes.tdn == dn)
            return child
        except StopIteration:
            return None

    def remove_admin_props(self):
        self.attributes.remove_admin_props()
        for child in self.children:
            child.remove_admin_props()

    def _set_attributes(self, **kwargs):
        for k, v in kwargs.items():
            self.attributes.__setattr__(k, v)


class GenericClass:
    def __init__(self, apic_class: str, **kwargs):
        self.children = []
        self.class_ = apic_class
        self.attributes = Attributes(**kwargs)

    def __iter__(self):
        for k, v in self.attributes.__dict__.items():
            yield k, v

    def json(self, empty_fields: bool=False):
        if self.children == list():
            json_data = {
                self.class_: {
                    'attributes': self.attributes.json(empty_fields=empty_fields)
                }
            }
        else:
            json_data = {
                self.class_: {
                    'attributes': self.attributes.json(empty_fields=empty_fields),
                    'children': list((obj.json(empty_fields=empty_fields) for obj in self.children))
                }
            }

        return json_data

    def self_json(self):
        json_data = {
            self.class_: {
                'attributes': self.attributes.json()
            }
        }

        return json_data

    @classmethod
    def load(cls, json_data: dict or list):
        if not json_data:
            return None
        if isinstance(json_data, dict):
            pass
        else:
            json_data = json_data[0]

        apic_class = list(json_data.keys())[0]
        obj = cls(apic_class)
        obj.attributes = Attributes.load(json_data[apic_class]['attributes'])
        if 'children' in json_data[apic_class].keys() and len(json_data[apic_class]['children']) > 0:
            for child in json_data[apic_class]['children']:
                for key in child.keys():
                    if key in defined_classes.keys():
                        child_obj = defined_classes[key].load(child)
                        obj.children.append(child_obj)
                    else:
                        child_obj = GenericClass.load(json_data=child)
                        obj.children.append(child_obj)

        return obj

    def modify(self):
        self.attributes.__setattr__('status', 'modified')

    def create_modify(self):
        self.attributes.__setattr__('status', 'created,modified')

    def create(self):
        self.attributes.__setattr__('status', 'created')

    def delete(self):
        self.attributes.__setattr__('status', 'deleted')

    def pop_child_class(self, class_):
        if class_ in [_.class_ for _ in self.children]:
            child = self.children.pop(self.children.index(next(c for c in self.children if c.class_ == class_)))
            return child
        else:
            return None

    def get_child_class(self, class_):
        if class_ in [_.class_ for _ in self.children]:
            child = next(c for c in self.children if c.class_ == class_)
            return child
        else:
            return None

    def get_child_class_iter(self, class_):
        return [c for c in self.children if c.class_ == class_]

    def remove_admin_props(self):
        self.attributes.remove_admin_props()
        for child in self.children:
            child.remove_admin_props()


class AEP(APICObject):
    class_ = 'infraAttEntityP'
    attrs = {
        'dn': '',
        'name': ''
    }
    post_uri = '/api/mo/uni/infra.json'

    _dn_template = 'uni/infra/attentp-{name}'
    _dn_attributes = ['name']
    search = re.compile(r'uni/infra/attentp-(?P<name>[^/\]]+)').search
    tf_resource = 'aci_attachable_access_entity_profile'

    def _customize_(self, **kwargs):
        self.infra_generic = None

    def add_epg(self, epg_dn: str, encap: int):
        attach = InfraRsFuncToEpg()
        attach.attributes.tDn = epg_dn
        attach.attributes.encap = f'vlan-{encap}'
        attach.attributes.mode = 'regular'
        attach.create()
        try:
            self.infra_generic = next(child for child in self.children if isinstance(child, InfraGeneric))
        except StopIteration:
            self.infra_generic = InfraGeneric()
        self.infra_generic.children.append(attach)
        if self.infra_generic not in self.children:
            self.children.append(self.infra_generic)

    def add_epg_custom(self, epg_dn: str, encap: int):
        attach = InfraRsFuncToEpg()
        attach.attributes.tDn = (epg_dn if epg_dn.startswith('uni/') else f'uni/{epg_dn}')
        attach.attributes.encap = f'vlan-{encap}'
        attach.attributes.mode = 'regular'
        attach.create_modify()
        try:
            self.infra_generic = next(child for child in self.children if isinstance(child, InfraGeneric))
        except StopIteration:
            self.infra_generic = InfraGeneric()
        self.infra_generic.children.append(attach)
        if self.infra_generic not in self.children:
            self.children.append(self.infra_generic)

    def use_domain(self, domain_name: str):
        domain = InfraRsDomP()
        domain.attributes.tDn = f'uni/phys-{domain_name}'
        self.children.append(domain)


class InfraGeneric(APICObject):
    class_ = 'infraGeneric'
    attrs = {
        'name': 'default',
        'status': 'created,modified'
    }
    tf_resource = 'aci_access_generic'


class InfraRsDomP(APICObject):
    class_ = 'infraRsDomP'
    attrs = {
        'tDn': '',
        'status': 'created,modified'
    }


class SwitchProfile(APICObject):
    class_ = 'infraNodeP'
    attrs = {
        'dn': '',
        'name': ''
    }
    post_uri = '/api/mo/uni/infra.json'

    _dn_attributes = ['name']
    _dn_template = 'uni/infra/nprof-{name}'
    search = re.compile(r'uni/infra/nprof-(?P<name>[^/\]]+)').search
    tf_resource = 'aci_leaf_profile'

    def create_switch_profile(self, name: str, nodes: list):
        if len(nodes) > 2:
            raise ValueError('No more than 2 nodes are supported')

        nodes = list((str(node) for node in nodes))

        self.attributes.name = name
        self.create()

        leaf_selector = LeafSelector()
        node_block = InfraNodeBlock()

        leaf_selector.attributes.name = f'LF-{"-".join(nodes)}'
        leaf_selector.attributes.type = 'range'
        leaf_selector.create()

        node_block.attributes.name = f'LF-{"-".join(nodes)}'
        node_block.attributes.from_ = nodes[0]
        node_block.attributes.to_ = nodes[-1]

        leaf_selector.children.append(node_block)
        self.children.append(leaf_selector)


class LeafSelector(APICObject):
    class_ = 'infraLeafS'
    attrs = {
        'name': '',
        'type': 'range'
    }

    search = re.compile(r'uni/infra/nprof-(?P<infraNodeP>[^/]+)/leaves-(?P<name>[-\w]+)-typ-range').search


class InfraNodeBlock(APICObject):
    class_ = 'infraNodeBlk'
    attrs = {
        'name': '',
        'from_': '',
        'to_': ''
    }

    search = re.compile(r'uni/infra/nprof-(?P<infraNodeP>[^/]+)/leaves-(?P<infraLeafS>[-\w]+)-typ-range/nodeblk-(?P<name>[^/\]]+)').search


class InfraRsFuncToEpg(APICObject):
    class_ = 'infraRsFuncToEpg'
    attrs = {
        'dn': '',
        'tDn': '',
        'encap': '',
        'mode': 'regular',
        'status': 'created'
    }

    search = re.compile(r'uni/infra/attentp-(?P<infraAttEntityP>[^/]+)/gen-default/rsfuncToEpg-\[(?P<epgdn>[^]]+)]').search
    tf_resource = 'aci_epgs_using_function'

    _dn_attributes = ['aep', 'tenant', 'app_profile', 'epg']
    _dn_template = 'uni/infra/attentp-{aep}/gen-default/rsfuncToEpg-[uni/tn-{tenant}/ap-{app_profile}/epg-{epg}]'


class Tenant(APICObject):
    class_ = 'fvTenant'
    attrs = {
        'dn': '',
        'name': '',
        'status': 'modified'
    }

    search = re.compile(r'uni/tn-(?P<name>[^/\]]+)').search
    post_uri = '/api/mo/uni.json'
    tf_resource = 'aci_tenant'


class AP(APICObject):
    class_ = 'fvAp'
    attrs = {
        'dn': '',
        'name': ''
    }

    search = re.compile(r'uni/tn-(?P<fvTenant>[^/\]]+)/ap-(?P<name>[^/\]]+)').search

    _dn_attributes = ['tenant', 'name']
    _dn_template = 'uni/tn-{tenant}/ap-{name}'
    tf_resource = 'aci_application_profile'


class EPG(APICObject):
    class_ = 'fvAEPg'
    attrs = {
        'dn': '',
        'name': '',
        'descr': ''
    }

    search = re.compile(r'uni/tn-(?P<fvTenant>[^/\]]+)/ap-(?P<fvAp>[^/\]]+)/epg-(?P<name>[^/\]]+)').search

    _dn_attributes = ['tenant', 'app_profile', 'name']
    _dn_template = 'uni/tn-{tenant}/ap-{app_profile}/epg-{name}'

    tf_resource = 'aci_application_epg'

    def assign_bd(self, name):
        fvrsbd = self.pop_child_class(class_=FvRsBd.class_)

        if fvrsbd:
            fvrsbd.attributes.tnFvBDName = name
        else:
            fvrsbd = FvRsBd(name)

        self.children.append(fvrsbd)

    def add_subnet(self, subnet: str, description: str=None):
        assert IPv4Network(subnet, strict=False)
        fvsubnet = Subnet(subnet)
        if description:
            fvsubnet.attributes.descr = description
        self.children.append(fvsubnet)

    def domain(self, name):
        fvrsdomatt = FvRsDomAtt(name)
        self.children.append(fvrsdomatt)


class BD(APICObject):
    class_ = 'fvBD'
    attrs = {
        'dn': '',
        'arpFlood': '',
        'unicastRoute': '',
        'descr': '',
        'ipLearning': '',
        'name': '',
        'unkMacUcastAct': '',
        'limitIpLearnToSubnets': 'yes'
    }

    search = re.compile(r'uni/tn-(?P<fvTenant>[^/\]]+)/BD-(?P<name>[^/\]]+)').search
    tf_resource = 'aci_bridge_domain'

    _dn_attributes = ['tenant', 'name']
    _dn_template = 'uni/tn-{tenant}/BD-{name}'

    def layer2(self):
        self.attributes.arpFlood = 'yes'
        self.attributes.unicastRoute = 'no'
        self.attributes.unkMacUcastAct = 'flood'

    def layer3(self):
        self.attributes.arpFlood = 'no'
        self.attributes.unicastRoute = 'yes'
        self.attributes.unkMacUcastAct = 'proxy'
        self.attributes.ipLearning = 'yes'

    def add_subnet(self, subnet: str, description: str=None):
        assert IPv4Network(subnet, strict=False)
        self.layer3()
        fvsubnet = Subnet(subnet)
        if description:
            fvsubnet.attributes.descr = description
        self.children.append(fvsubnet)

    def to_l3_out(self, name: str):
        self.layer3()
        l3out = FvRsBDToOut(name)
        self.children.append(l3out)

    def use_vrf(self, name: str):
        fvrsctx = self.pop_child_class(FvRsCtx.class_)

        if fvrsctx:
            fvrsctx.attributes.tnFvCtxName = name
        else:
            fvrsctx = FvRsCtx(name=name)

        self.children.append(fvrsctx)


class FvRsBd(APICObject):
    class_ = 'fvRsBd'
    attrs = {
        'tnFvBDName': ''
    }

    search = re.compile(r'uni/tn-(?P<fvTenant>[^/\]]+)/ap-(?P<fvAp>[^/\]]+)/epg-(?P<fvAEPg>[^/\]]+)/rsbd').search

    def _customize_(self, name: str='', **kwargs):
        self.attributes.tnFvBDName = name
        if 'name' in dir(self.attributes):
            self.attributes.__delattr__('name')



class FvRsBDToOut(APICObject):
    class_ = 'fvRsBDToOut'
    attrs = {
        'tnL3extOutName': ''
    }

    # def __init__(self, name: str=''):
    #     self.children = []
    #     self.attributes = Attributes(**self.attrs)
    #     self.attributes.tnL3extOutName = name

    def _customize_(self, name: str='', **kwargs):
        self.attributes.tnL3extOutName = name
        if 'name' in dir(self.attributes):
            self.attributes.__delattr__('name')



class Subnet(APICObject):
    class_ = 'fvSubnet'
    attrs = {
        'dn': '',
        'ip': '',
        'name': '',
        'scope': 'public',
        'virtual': 'no'
    }

    search = re.compile(r'uni/tn-(?P<fvTenant>[^/\]]+)/BD-(?P<fvBD>[^/\]]+)/subnet-\[(?P<ip>[^]]+)]').search
    tf_resource = 'aci_subnet'

    _dn_attributes = ['tenant', 'bd', 'ip_network']
    _dn_template = 'uni/tn-{tenant}/BD-{bd}/subnet-[{ip_network}]'

    def _customize_(self, ip: str='', **kwargs):
        assert IPv4Network(ip, strict=False), 'Invalid subnet was provided'
        self.attributes.ip = ip
        self.attributes.scope = 'public'
        self.create()

class Domain(APICObject):
    class_ = 'physDomP'
    attrs = {
        'dn': '',
        'name': ''
    }
    post_uri = '/api/mo/uni.json'

    def vmm(self):
        self.class_ = 'vmmDomP'

    def l3ext(self):
        self.class_ = 'l3extDomP'

    def phys(self):
        self.class_ = 'physDomP'


class FvRsDomAtt(APICObject):
    class_ = 'fvRsDomAtt'
    attrs = {
        'tDn': ''
    }

    tf_resource = 'aci_epg_to_domain'

    def _customize_(self, name: str='', **kwargs):
        self.attributes.tDn = f'uni/phys-{name}'
        if 'name' in dir(self.attributes):
            self.attributes.__delattr__('name')


class Context(APICObject):
    class_ = 'fvCtx'
    attrs = {
        'dn': '',
        'name': ''
    }
    tf_resource = 'aci_vrf'

    _dn_attributes = ['tenant', 'name']
    _dn_template = 'uni/tn-{tenant}/ctx-{name}'


class FvRsCtx(APICObject):
    class_ = 'fvRsCtx'
    attrs = {
        'tnFvCtxName': ''
    }

    def _customize_(self, name: str='', **kwargs):
        self.attributes.tnFvCtxName = name
        if 'name' in dir(self.attributes):
            self.attributes.__delattr__('name')


class Uni(APICObject):
    class_ = 'polUni'
    attrs = {
        'dn': 'uni',
        'status': 'modified'
    }


class Infra(APICObject):
    class_ = 'infraInfra'
    attrs = {
        'dn': 'uni/infra',
        'status': 'modified'
    }


class Fabric(APICObject):
    class_ = 'fabricInst'
    attrs = {
        'dn': 'uni/fabric',
        'status': 'modified'
    }
    post_uri = '/api/mo/uni.json'


class MaintenancePolicy(APICObject):
    class_ = 'maintMaintP'
    attrs = {
        'name': ''
    }

    search = re.compile(r'uni/fabric/maintpol-(?P<name>[^/\]]+)').search

    post_uri = '/api/mo/uni/fabric.json'

    _dn_attributes = ['name']
    _dn_template = 'uni/fabric/maintpol-{name}'

    def set_firmware_version(self, version: str):
        self.attributes.__setattr__('version', 'n9000-1%s' % version)


class MaintenanceGroup(APICObject):
    class_ = 'maintMaintGrp'
    attrs = {
        'name': ''
    }

    search = re.compile(r'uni/fabric/maintgrp-(?P<name>[^/\]]+)').search
    post_uri = '/api/mo/uni/fabric.json'

    _dn_attributes = ['name']
    _dn_template = 'uni/fabric/maintgrp-{name}'

    def use_maintenance_policy(self, name: str):
        ref = GenericClass(apic_class='maintRsMgrpp')
        ref.attributes.__setattr__('tnMaintMaintPName', name)
        ref.create_modify()

        self.children.append(ref)


class FirmwareGroup(APICObject):
    class_ = 'firmwareFwGrp'
    attrs = {
        'name': '',
        'type': 'range',
        'status': 'modified'
    }

    search = re.compile(r'uni/fabric/fwgrp-(?P<name>[^/\]]+)').search
    post_uri = '/api/mo/uni/fabric.json'


class FabricNodeBlock(APICObject):
    class_ = 'fabricNodeBlk'
    attrs = {
        'name': '',
        'from_': '',
        'to_': '',
        'status': 'created'
    }

    search = re.compile(r'uni/fabric/maintgrp-(?P<maintMaintGrp>[^/\]]+)/nodeblk-(?P<name>[-\w+]+)').search

    _dn_attributes = ['group', 'node']
    _dn_template = 'uni/fabric/maintgrp-{group}/nodeblk-blk{node}-{node}'

    def _customize_(self, *args, **kwargs):
        if args:
            self.attributes.name = f'blk{args[0]}-{args[-1]}'
            self.attributes.from_ = str(args[0])
            self.attributes.to_ = str(args[-1])


class OOBAddress(APICObject):
    class_ = 'mgmtRsOoBStNode'
    attrs = {
        'tDn': 'topology/pod-1/node-XXX',
        'addr': '',
        'gw': '',
        'status': 'created'
    }
    post_uri = '/api/mo/uni/tn-mgmt/mgmtp-default/oob-default.json'


class NodeIdentityPolicy(APICObject):
    class_ = 'fabricNodeIdentP'
    attrs = {
        'serial': '{{serial}}',
        'nodeId': '{{leaf}}',
        'name': '{{name}}',
        'role': 'leaf',
        'status': 'created'
    }
    post_uri = '/api/mo/uni/controller/nodeidentpol.json'


class FabricNode(APICObject):
    class_ = 'fabricNode'
    attrs = {
        'serial': '{{serial}}',
        'nodeId': '{{leaf}}',
        'name': '{{name}}',
        'role': 'leaf',
        'status': 'created'
    }


class FabricNodeEp(APICObject):
    class_ = 'fabricNodePEp'
    attrs = {
        'id': '{{serial}}',
        'status': 'created,modified'
    }


class FabricExplicitGEp(APICObject):
    class_ = 'fabricExplicitGEp'
    attrs = {
        'id': '',
        'name': '',
        'status': 'created'
    }


class FabricProtPol(APICObject):
    class_ = 'fabricProtPol'
    attrs = {
        'dn': 'uni/fabric/protpol',
        'status': 'modified'
    }
    post_uri = '/api/mo/uni/fabric.json'

    def add_new_vpc_pair(self, nodes: list):
        pair = FabricExplicitGEp()
        pair.attributes.id = str(nodes[0])
        pair.attributes.name = f'vpc-{nodes[0]}-{nodes[1]}'
        pair.create()

        self.children.append(pair)

        node1 = FabricNodeEp()
        node1.attributes.id = str(nodes[0])
        node1.create()

        node2 = FabricNodeEp()
        node2.attributes.id = str(nodes[1])
        node2.create()

        pair.children.append(node1)
        pair.children.append(node2)


class FabricRsVpcInstPol(APICObject):
    class_ = 'fabricRsVpcInstPol'
    attrs = {
        'tnVpcInstPolName': 'default',
        'status': 'created'
    }


# class InterfacePolicy(APICObject):
#     class_ = 'cdpIfPol'
#     attrs = {
#         'name': '',
#         'status': 'created,modified'
#     }
#
#     def _customize_(self, policy_type: str, **kwargs):
#         policy_type = policy_type.lower()
#
#         if policy_type in ['cdp', 'lldp', 'port-channel']:
#             if policy_type == 'cdp':
#                 self.class_ = 'cdpIfPol'
#                 self.attributes.adminSt = 'enabled'
#             elif policy_type == 'lldp':
#                 self.class_ = 'lldpIfPol'
#                 self.attributes.adminRxSt = 'enabled'
#                 self.attributes.adminTxSt = 'enabled'
#             elif policy_type == 'port-channel':
#                 self.class_ = 'lacpLagPol'
#                 self.attributes.ctrl = 'fast-sel-hot-stdby,graceful-conv,susp-individual'
#                 self.attributes.maxLinks = '16'
#                 self.attributes.minLinks = '1'
#                 self.attributes.mode = 'active'
#         else:
#             raise Exception('This interface policy type is not yet supported')


class IfSpeedPolicy(APICObject):
    class_ = 'fabricHIfPol'
    attrs = {}

    post_uri = '/api/mo/uni/infra.json'


class IfBondPolicy(APICObject):
    class_ = 'lacpLagPol'
    attrs = {
        'ctrl': 'fast-sel-hot-stdby,graceful-conv,susp-individual',
        'maxLinks': '16',
        'minLinks': '1',
        'mode': 'active'
    }

    post_uri = '/api/mo/uni/infra.json'


class IfCDPPolicy(APICObject):
    class_ = 'cdpIfPol'
    attrs = {
        'adminSt': 'enabled'
    }

    post_uri = '/api/mo/uni/infra.json'


class IfLLDPPolicy(APICObject):
    class_ = 'lldpIfPol'
    attrs = {
        'adminRxSt': 'enabled',
        'adminTxSt': 'enabled'
    }

    post_uri = '/api/mo/uni/infra.json'


class InterfacePolicyGroup(APICObject):
    class_ = 'infraAccPortGrp'
    attrs = {
        'name': '',
        'descr': '',
        'status': 'created,modified'
    }

    search = re.compile(r'uni/infra/funcprof/acc(?:portgrp|bundle)-(?P<name>[^/\]]+)').search

    post_uri = '/api/mo/uni/infra/funcprof.json'

    def _customize_(self, **kwargs):
        # CDP and LLDP will always be enabled by default
        cdp_enable = GenericClass('infraRsCdpIfPol')
        cdp_enable.attributes.tnCdpIfPolName = 'CDP-Enable'
        lldp_enable = GenericClass('infraRsLldpIfPol')
        lldp_enable.attributes.tnLldpIfPolName = 'LLDP-Enable'

        self.children = [cdp_enable, lldp_enable]

    def port_channel(self, lacp=True):
        self.class_ = 'infraAccBndlGrp'
        po_policy = GenericClass('infraRsLacpPol')
        po_policy.attributes.tnLacpLagPolName = ('pc-LACP-Active' if lacp is True else 'pc-Static-ON')
        self.children.append(po_policy)

    def use_aep(self, aep_name: str):
        aep = self.get_child_class('infraRsAttEntp')

        if aep:
            aep.attributes.tDn = f'uni/infra/attentp-{aep_name}'
        else:
            aep = GenericClass('infraRsAttEntP', tDn=f'uni/infra/attentp-{aep_name}')
            self.children.append(aep)

    def link_speed(self, speed: int=None):
        """Set speed of interface in Gbps"""
        speed = (speed if speed in [1, 10, 25, 100] else 'default')

        llp = self.get_child_class('infraRsHIfPol')

        if llp:
            llp.attributes.tnFabricHIfPolName=(f'system-link-level-{speed}G-auto' if isinstance(speed, int) else speed)
        else:
            llp = GenericClass('infraRsHIfPol',
                               tnFabricHIfPolName=(f'system-link-level-{speed}G-auto' if isinstance(speed, int) else speed))
            self.children += [llp]


class InterfacePortGroup(InterfacePolicyGroup):
    class_ = 'infraAccPortGrp'
    search = re.compile(r'uni/infra/funcprof/accportgrp-(?P<name>[^/\]]+)').search


class InterfaceBundleGroup(InterfacePolicyGroup):
    class_ = 'infraAccBndlGrp'
    search = re.compile(r'uni/infra/funcprof/accbundle-(?P<name>[^/\]]+)').search



class InterfaceProfile(APICObject):
    class_ = 'infraAccPortP'
    attrs = {
        'name': '',
        'descr': '',
        'status': 'created,modified'
    }

    search = re.compile(r'uni/infra/accportprof-(?P<name>[^/\]]+)').search
    post_uri = '/api/mo/uni/infra.json'

    _dn_attributes = ['name']
    _dn_template = 'uni/infra/accportprof-{name}'


class InfraRsAccPortP(APICObject):
    class_ = 'infraRsAccPortP'
    attrs = {
        'dn': '',
        'tDn': ''
    }

    search = re.compile(r'uni/infra/nprof-(?P<infraNodeP>[^/\]]+)/rsaccPortP-\[uni/infra/accportprof-(?P<name>[^]]+)]').search

    _dn_attributes = ['switch_profile', 'name']
    _dn_template = 'uni/infra/nprof-{switch_profile}/rsaccPortP-[uni/infra/accportprof-{name}]'


class InterfaceSelector(APICObject):
    class_ = 'infraHPortS'
    attrs = {
        'name': '',
        'descr': '',
        'type': 'range',
        'status': 'created,modified'
    }

    search = re.compile(r'uni/infra/accportprof-(?P<infraAccPortP>[^/\]]+)/hports-(?P<name>[-\w]+)-typ-range').search


class InterfaceBlock(APICObject):
    class_ = 'infraPortBlk'
    attrs = {
        'name': '',
        'descr': '',
        'fromPort': '',
        'toPort': '',
        'status': 'created,modified'
    }

    search = re.compile(r'uni/infra/accportprof-(?P<infraAccPortP>[^/]+)/hports-(?P<infraHPortS>[-\w]+)-typ-range/portblk-(?P<name>[-\w]+)').search

    _dn_attributes = ['profile', 'selector', 'name']
    _dn_template = 'uni/infra/accportprof-{profile}/hports-{selector}/portblk-{name}'

    def _customize_(self, **kwargs):
        self.attributes.name = 'block%s' % ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))


class SNMPClientP(APICObject):
    class_ = 'snmpClientP'
    attrs = {
        'dn': '',
        'name': '',
        'addr': ''
    }

    def _customize_(self, addr: str, **kwargs):
        self.attributes.dn = f'uni/fabric/snmppol-default/clgrp-snmpClients/client-[{addr}]'


class VLANPool(APICObject):
    class_ = 'fvnsVlanInstP'
    attrs = {
        'dn': '',
        'allocMode': 'dynamic'
    }

    def _customize_(self, name: str, **kwargs):
        self.attributes.dn = f'uni/infra/vlanns-[{name}]-dynamic'


class EncapBlock(APICObject):
    class_ = 'fvnsEncapBlk'
    attrs = {
        'allocMode': 'static',
        'role': 'external',
        'from': 'vlan-2',
        'to': 'vlan-3966'
    }

    def set_range(self, *vlan_range):
        self.attributes.__setattr__('from', f'vlan-{vlan_range[0]}')
        self.attributes.__setattr__('to', f'vlan-{vlan_range[-1]}')


class OutOfServicePort(APICObject):
    class_ = 'fabricRsOosPath'
    attrs = {
        'lc': 'blacklist'
    }

    _dn_template = 'uni/fabric/outofsvc/rsoosPath-[topology/pod-{pod}/paths-{node}/pathep-[eth1/{port}]]'
    _dn_attributes = ['pod', 'node', 'port']


class OSPFExternalPolicy(APICObject):
    class_ = 'ospfExtP'
    attrs = {
        'areaCost': '1',
        'areaCtrl': 'redistribute',
        'areaId': '',
        'areaType': 'nssa',
        'multipodInternal': 'no'
    }


class L3OutVRF(APICObject):
    class_ = 'l3extRsEctx'
    attrs = {
        'tnFvCtxName': ''
    }

    def _customize_(self, name: str='', **kwargs):
        self.attributes.tnFvCtxName = name
        if 'name' in dir(self.attributes):
            self.attributes.__delattr__('name')


class L3OutDomain(APICObject):
    class_ = 'l3extRsL3DomAtt'
    attrs = {
        'tDn': ''
    }


class L3Out(APICObject):
    class_ = 'l3extOut'
    attrs = {
        'name': '',
        'enforceRtctrl': 'export',
        'descr': ''
    }

    search = re.compile(r'uni/tn-(?P<fvTenant>[^/]+)/out-(?P<name>[^/\]]+)').search

    def ospf_area(self, ospf_area: str) -> OSPFExternalPolicy:
        if IPv4Network(ospf_area):
            _ = OSPFExternalPolicy(areaId=ospf_area)
            self.children.append(_)
            return _

    def vrf(self, name: str):
        _ = L3OutVRF(name=name)
        self.children.append(_)


class L3extIP(APICObject):
    class_ = 'l3extIp'
    attrs = {}

    search = re.compile(r'uni/tn-(?P<fvTenant>[^/]+)/out-(?P<l3extOut>[^/]+)/lnodep-(?P<l3extLNodeP>[^/]+)/lifp-(?P<l3extLIfP>[^/]+)/rspathL3OutAtt-\[(?P<l3extPath>[^]]+]])/mem-[.]/addr-\[(?P<addr>[^]]+)]').search


class L3extPath(APICObject):
    class_ = 'l3extRsPathL3OutAtt'
    attrs = {}

    search = re.compile(r'uni/tn-(?P<fvTenant>[^/]+)/out-(?P<l3extOut>[^/]+)/lnodep-(?P<l3extLNodeP>[^/]+)/lifp-(?P<l3extLIfP>[^/]+)/rspathL3OutAtt-\[(?P<path>[^]]+]])').search


class L3extSubnet(APICObject):
    class_ = 'l3extSubnet'
    attrs = {}

    search = re.compile(r'uni/tn-(?P<fvTenant>[^/]+)/out-(?P<l3extOut>[^/]+)/instP-(?P<l3extInstP>[^/]+)/extsubnet-\[(?P<ip>[^]]+)]').search


class L3extLNodeP(APICObject):
    class_ = 'l3extLNodeP'
    attrs = {'name': ''}

    search = re.compile(r'uni/tn-(?P<fvTenant>[^/]+)/out-(?P<l3extOut>[^/]+)/lnodep-(?P<name>[^/\]]+)').search


class L3extLIfP(APICObject):
    class_ = 'l3extLIfP'
    attrs = {}

    search = re.compile(r'uni/tn-(?P<fvTenant>[^/]+)/out-(?P<l3extOut>[^/]+)/lnodep-(?P<l3extLNodeP>[^/\]]+)/lifp-(?P<name>[^/\]]+)').search


class L3extInstP(APICObject):
    class_ = 'l3extInstP'
    attrs = {}

    search = re.compile(r'uni/tn-(?P<fvTenant>[^/]+)/out-(?P<l3extOut>[^/]+)/instP-(?P<name>[^/]+)').search


defined_classes = {
    'infraAttEntityP': AEP,
    'infraGeneric': InfraGeneric,
    'infraNodeP': SwitchProfile,
    'infraLeafS': LeafSelector,
    'infraNodeBlk': InfraNodeBlock,
    'infraRsFuncToEpg': InfraRsFuncToEpg,  # EPG to VLAN definition assigned to AEPs
    'fvTenant': Tenant,
    'fvAp': AP,
    'fvAEPg': EPG,
    'fvBD': BD,
    'fvRsBd': FvRsBd,
    'fvRsBDToOut': FvRsBDToOut,  # L3Out that a BD is associated with
    'fvSubnet': Subnet,
    'physDomP': Domain,
    'vmmDomP': Domain,
    'l3extDomP': Domain,
    'fvRsDomAtt': FvRsDomAtt,  # Domain association to tenant objects
    'infraRsDomP': InfraRsDomP,
    'fvCtx': Context,  # Also called VRF
    'fvRsCtx': FvRsCtx,
    'polUni': Uni,
    'infraInfra': Infra,
    'fabricInst': Fabric,
    'maintMaintP': MaintenancePolicy,
    'maintMaintGrp': MaintenanceGroup,
    'firmwareFwGrp': FirmwareGroup,
    'fabricNodeBlk': FabricNodeBlock,
    'fabricNode': FabricNode,
    'fabricExplicitGEp': FabricExplicitGEp,  # VPC Domain definition
    'fabricRsVpcInstPol': FabricRsVpcInstPol,  # Default VPC policy found in fabrics
    'infraAccPortGrp': InterfacePortGroup,
    'infraAccBndlGrp': InterfaceBundleGroup,
    'infraAccPortP': InterfaceProfile,
    'infraRsAccPortP': InfraRsAccPortP,
    'infraPortBlk': InterfaceBlock,
    'fabricRsOosPath': OutOfServicePort,
    'fabricHIfPol': IfSpeedPolicy,
    'lacpLagPol': IfBondPolicy,
    'cdpIfPol': IfCDPPolicy,
    'lldpIfPol': IfLLDPPolicy,
    'l3extIp': L3extIP,
    'l3extRsPathL3OutAtt': L3extPath,
    'l3extSubnet': L3extSubnet,
    'l3extLNodeP': L3extLNodeP,
    'l3extLIfP': L3extLIfP
}
