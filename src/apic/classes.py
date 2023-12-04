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
            for arg in kwargs:
                if arg == 'annotation':
                    self.__setattr__(arg, Attributes(**annotation_parser(kwargs[arg])))
                else:
                    self.__setattr__(arg, kwargs[arg])

    def __hasattr__(self, attribute: str):
        if attribute in self.__dict__.keys():
            return True
        else:
            return False

    def json(self):
        json_data = {}
        for attribute in self.__dict__.keys():
            if not self.__getattribute__(attribute) == '':
                if attribute == 'annotation':
                    json_data[attribute] = annotation_to_string(self.__getattribute__(attribute).json())
                else:
                    json_data[attribute] = self.__getattribute__(attribute)
        return json_data

    @classmethod
    def load(cls, json_data: dict):
        return cls(**json_data)

    def remove_admin_props(self):
        admin_props = [
            'modTs', 'lcOwn', 'uid', 'monPolDn', 'extMngdBy', 'ownerKey', 'ownerTag', 'lastStateModTs', 'state',
            'unixUserId', 'rn', 'pwdChangeIntervalBegin', 'pwdChangedDate', 'expState', 'fingerprint',
            'certificateDecodeInformation', 'certdn', 'certValidUntil', 'rType', 'stateQual', 'tType', 'tCl'
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
    _dn_attributes: list
    _dn_template: str
    tf_resource: str

    @classmethod
    def load(cls, json_data: dict or list):
        if isinstance(json_data, dict):
            pass
        else:
            json_data = json_data[0]

        class_name = list(json_data.keys())[0]
        _class_ = defined_classes.get(class_name)

        if _class_:
            obj = _class_()
        else:
            obj = GenericClass(class_name)

        obj.attributes = Attributes.load(json_data[obj.class_]['attributes'])
        if 'children' in json_data[obj.class_].keys() and len(json_data[obj.class_]['children']) > 0:
            for child in json_data[obj.class_]['children']:
                child = cls.load(child)
                obj.children.append(child)

        return obj

    def json(self):
        try:
            self._dn_constructor()
        except AttributeError:
            pass

        if self.children == list():
            json_data = {
                self.class_: {
                    'attributes': self.attributes.json()
                }
            }
        else:
            json_data = {
                self.class_: {
                    'attributes': self.attributes.json(),
                    'children': list((obj.json() for obj in self.children))
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

    def get_child_class(self, class_):
        if class_ in [_.class_ for _ in self.children]:
            child = next(c for c in self.children if c.class_ == class_)
            return child
        else:
            return None

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

    def json(self):
        if self.children == list():
            json_data = {
                self.class_: {
                    'attributes': self.attributes.json()
                }
            }
        else:
            json_data = {
                self.class_: {
                    'attributes': self.attributes.json(),
                    'children': list((obj.json() for obj in self.children))
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
    tf_resource = 'aci_attachable_access_entity_profile'

    def __init__(self, **kwargs):
        self.children = []
        self.attributes = Attributes(**self.attrs)
        if kwargs:
            self._set_attributes(**kwargs)
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

    def __init__(self):
        self.children = []
        self.attributes = Attributes(**self.attrs)


class InfraRsDomP(APICObject):
    class_ = 'infraRsDomP'
    attrs = {
        'tDn': '',
        'status': 'created,modified'
    }

    def __init__(self, **kwargs):
        self.attributes = Attributes(**self.attrs)
        self.children = []
        if kwargs:
            self._set_attributes()


class SwitchProfile(APICObject):
    class_ = 'infraNodeP'
    attrs = {
        'dn': '',
        'name': ''
    }
    post_uri = '/api/mo/uni/infra.json'

    _dn_attributes = ['name']
    _dn_template = 'uni/infra/nprof-{name}'
    tf_resource = 'aci_leaf_profile'

    def __init__(self, **kwargs):
        self.children = []
        self.attributes = Attributes(**self.attrs)
        if kwargs:
            self._set_attributes()

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

    def __init__(self, **kwargs):
        self.children = []
        self.attributes = Attributes(**self.attrs)
        if kwargs:
            self._set_attributes(**kwargs)


class InfraNodeBlock(APICObject):
    class_ = 'infraNodeBlk'
    attrs = {
        'name': '',
        'from_': '',
        'to_': ''
    }

    def __init__(self):
        self.children = []
        self.attributes = Attributes(**self.attrs)


class InfraRsFuncToEpg(APICObject):
    class_ = 'infraRsFuncToEpg'
    attrs = {
        'dn': '',
        'tDn': '',
        'encap': '',
        'mode': 'regular',
        'status': 'created'
    }
    tf_resource = 'aci_epgs_using_function'

    _dn_attributes = ['aep', 'tenant', 'app_profile', 'epg']
    _dn_template = 'uni/infra/attentp-{aep}/gen-default/rsfuncToEpg-[uni/tn-{tenant}/ap-{app_profile}/epg-{epg}]'

    def __init__(self, **kwargs):
        self.children = []
        self.attributes = Attributes(**self.attrs)
        if kwargs:
            self._set_attributes(**kwargs)

    # def create(self, aep: str, epg_dn: str, encap: int or str):
    #     self.attributes.tDn = epg_dn
    #     self.attributes.dn = f'uni/infra/attentp-{aep}/gen-default/rsfuncToEpg-[{epg_dn}]'
    #     self.attributes.encap = f'vlan-{encap}'
    #     return None


class Tenant(APICObject):
    class_ = 'fvTenant'
    attrs = {
        'dn': '',
        'name': '',
        'status': 'modified'
    }
    post_uri = '/api/mo/uni.json'
    tf_resource = 'aci_tenant'

    def __init__(self, **kwargs):
        self.children = []
        self.attributes = Attributes(**self.attrs)
        if kwargs:
            self._set_attributes(**kwargs)


class AP(APICObject):
    class_ = 'fvAp'
    attrs = {
        'dn': '',
        'name': ''
    }

    _dn_attributes = ['tenant', 'name']
    _dn_template = 'uni/tn-{tenant}/ap-{name}'
    tf_resource = 'aci_application_profile'

    def __init__(self, **kwargs):
        self.children = []
        self.attributes = Attributes(**self.attrs)
        if kwargs:
            self._set_attributes(**kwargs)
        self.create_modify()


class EPG(APICObject):
    class_ = 'fvAEPg'
    attrs = {
        'dn': '',
        'name': '',
        'descr': ''
    }

    _dn_attributes = ['tenant', 'app_profile', 'name']
    _dn_template = 'uni/tn-{tenant}/ap-{app_profile}/epg-{name}'

    tf_resource = 'aci_application_epg'

    def __init__(self, **kwargs):
        self.children = []
        self.attributes = Attributes(**self.attrs)
        if kwargs:
            self._set_attributes(**kwargs)

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
    tf_resource = 'aci_bridge_domain'

    _dn_attributes = ['tenant', 'name']
    _dn_template = 'uni/tn-{tenant}/BD-{name}'

    def __init__(self, **kwargs):
        self.children = []
        self.attributes = Attributes(**self.attrs)
        if kwargs:
            self._set_attributes(**kwargs)

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

    def __init__(self, name: str=''):
        self.children = []
        self.attributes = Attributes(**self.attrs)
        self.attributes.tnFvBDName = name


class FvRsBDToOut(APICObject):
    class_ = 'fvRsBDToOut'
    attrs = {
        'tnL3extOutName': ''
    }

    def __init__(self, name: str=''):
        self.children = []
        self.attributes = Attributes(**self.attrs)
        self.attributes.tnL3extOutName = name


class Subnet(APICObject):
    class_ = 'fvSubnet'
    attrs = {
        'dn': '',
        'ip': '',
        'name': '',
        'scope': 'public',
        'virtual': 'no'
    }
    tf_resource = 'aci_subnet'

    _dn_attributes = ['tenant', 'bd', 'ip_network']
    _dn_template = 'uni/tn-{tenant}/BD-{bd}/subnet-[{ip_network}]'

    def __init__(self, subnet: str=''):
        self.children = []
        self.attributes = Attributes(**self.attrs)
        if subnet != '':
            assert IPv4Network(subnet, strict=False)
            self.attributes.ip = subnet
            self.attributes.scope = 'public'
            self.create()


class Domain(APICObject):
    class_ = 'physDomP'
    attrs = {
        'dn': '',
        'name': ''
    }
    post_uri = '/api/mo/uni.json'

    def __init__(self, **kwargs):
        self.children = []
        self.attributes = Attributes(**self.attrs)
        if kwargs:
            self._set_attributes(**kwargs)

    def vmm(self):
        self.class_ = 'vmmDomP'

    def l3ext(self):
        self.class_ = 'l3extDomP'

    def phys(self):
        self.class_ = 'physDomP'


class InfraRsDomAtt(APICObject):
    class_ = 'infraRsDomAtt'
    attrs = {
        'tDn': ''
    }

    def __init__(self, name: str=''):
        self.children = []
        self.attributes = Attributes(**self.attrs)
        self.attributes.tDn = f'uni/phys-{name}'


class FvRsDomAtt(APICObject):
    class_ = 'fvRsDomAtt'
    attrs = {
        'tDn': ''
    }

    tf_resource = 'aci_epg_to_domain'

    def __init__(self, name: str = ''):
        self.children = []
        self.attributes = Attributes(**self.attrs)
        self.attributes.tDn = f'uni/phys-{name}'


class Context(APICObject):
    class_ = 'fvCtx'
    attrs = {
        'dn': '',
        'name': ''
    }
    tf_resource = 'aci_vrf'

    def __init__(self, **kwargs):
        self.children = []
        self.attributes = Attributes(**self.attrs)
        if kwargs:
            self._set_attributes(**kwargs)


class FvRsCtx(APICObject):
    class_ = 'fvRsCtx'
    attrs = {
        'tnFvCtxName': ''
    }

    def __init__(self, name: str=''):
        self.children = []
        self.attributes = Attributes(**self.attrs)
        self.attributes.tnFvCtxName = name


class Uni(APICObject):
    class_ = 'polUni'
    attrs = {
        'dn': 'uni',
        'status': 'modified'
    }

    def __init__(self):
        self.children = []
        self.attributes = Attributes(**self.attrs)


class Infra(APICObject):
    class_ = 'infraInfra'
    attrs = {
        'dn': 'uni/infra',
        'status': 'modified'
    }

    def __init__(self):
        self.children = []
        self.attributes = Attributes(**self.attrs)


class Fabric(APICObject):
    class_ = 'fabricInst'
    attrs = {
        'dn': 'uni/fabric',
        'status': 'modified'
    }
    post_uri = '/api/mo/uni.json'

    def __init__(self):
        self.children = []
        self.attributes = Attributes(**self.attrs)


class MaintenancePolicy(APICObject):
    class_ = 'maintMaintP'
    attrs = {
        'name': ''
    }

    post_uri = '/api/mo/uni/fabric.json'

    _dn_attributes = ['name']
    _dn_template = 'uni/fabric/maintpol-{name}'

    def __init__(self, **kwargs):
        self.children = []
        self.attributes = Attributes(**self.attrs)
        self.create_modify()
        if kwargs:
            self._set_attributes(**kwargs)

    def set_firmware_version(self, version: str):
        self.attributes.__setattr__('version', 'n9000-1%s' % version)


class MaintenanceGroup(APICObject):
    class_ = 'maintMaintGrp'
    attrs = {
        'name': ''
    }
    post_uri = '/api/mo/uni/fabric.json'

    _dn_attributes = ['name']
    _dn_template = 'uni/fabric/maintgrp-{name}'

    def __init__(self, **kwargs):
        self.children = []
        self.attributes = Attributes(**self.attrs)
        self.create_modify()
        if kwargs:
            self._set_attributes(**kwargs)

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
    post_uri = '/api/mo/uni/fabric.json'

    def __init__(self, **kwargs):
        self.children = []
        self.attributes = Attributes(**self.attrs)
        if kwargs:
            self._set_attributes(**kwargs)


class FabricNodeBlock(APICObject):
    class_ = 'fabricNodeBlk'
    attrs = {
        'name': '',
        'from_': '',
        'to_': '',
        'status': 'created'
    }

    _dn_attributes = ['group', 'node']
    _dn_template = 'uni/fabric/maintgrp-{group}/nodeblk-blk{node}-{node}'

    def __init__(self, *args):
        self.children = []
        self.attributes = Attributes(**self.attrs)

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

    def __init__(self, **kwargs):
        self.children = []
        self.attributes = Attributes(**self.attrs)
        if kwargs:
            self._set_attributes(**kwargs)


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

    def __init__(self, **kwargs):
        self.children = []
        self.attributes = Attributes(**self.attrs)
        if kwargs:
            self._set_attributes(**kwargs)


class FabricNode(APICObject):
    class_ = 'fabricNode'
    attrs = {
        'serial': '{{serial}}',
        'nodeId': '{{leaf}}',
        'name': '{{name}}',
        'role': 'leaf',
        'status': 'created'
    }

    def __init__(self, **kwargs):
        self.children = []
        self.attributes = Attributes(**self.attrs)
        if kwargs:
            self._set_attributes(**kwargs)


class FabricNodeEp(APICObject):
    class_ = 'fabricNodePEp'
    attrs = {
        'id': '{{serial}}',
        'status': 'created,modified'
    }

    def __init__(self):
        self.children = []
        self.attributes = Attributes(**self.attrs)


class FabricExplicitGEp(APICObject):
    class_ = 'fabricExplicitGEp'
    attrs = {
        'id': '',
        'name': '',
        'status': 'created'
    }

    def __init__(self, **kwargs):
        self.children = []
        self.attributes = Attributes(**self.attrs)
        if kwargs:
            self._set_attributes(**kwargs)


class FabricProtPol(APICObject):
    class_ = 'fabricProtPol'
    attrs = {
        'dn': 'uni/fabric/protpol',
        'status': 'modified'
    }

    def __init__(self):
        self.children = []
        self.attributes = Attributes(**self.attrs)

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

    def __init__(self):
        self.children = []
        self.attributes = Attributes(**self.attrs)


class InterfacePolicy(APICObject):
    class_ = ''
    attrs = {
        'name': '',
        'status': 'created,modified'
    }

    def __init__(self, policy_type: str, **kwargs):
        self.children = []
        self.attributes = Attributes(**self.attrs)
        if kwargs:
            self._set_attributes(**kwargs)

        policy_type = policy_type.lower()

        if policy_type in ['cdp', 'lldp', 'port-channel']:
            if policy_type == 'cdp':
                self.class_ = 'cdpIfPol'
                self.attributes.adminSt = 'enabled'
            elif policy_type == 'lldp':
                self.class_ = 'lldpIfPol'
                self.attributes.adminRxSt = 'enabled'
                self.attributes.adminTxSt = 'enabled'
            elif policy_type == 'port-channel':
                self.class_ = 'lacpLagPol'
                self.attributes.ctrl = 'fast-sel-hot-stdby,graceful-conv,susp-individual'
                self.attributes.maxLinks = '16'
                self.attributes.minLinks = '1'
                self.attributes.mode = 'active'
        else:
            raise Exception('This interface policy type is not yet supported')


class InterfacePolicyGroup(APICObject):
    class_ = 'infraAccPortGrp'
    attrs = {
        'name': '',
        'descr': '',
        'status': 'created,modified'
    }
    post_uri = '/api/mo/uni/infra/funcprof.json'

    def __init__(self, **kwargs):
        self.attributes = Attributes(**self.attrs)
        if kwargs:
            self._set_attributes(**kwargs)

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
        aep = GenericClass('infraRsAttEntP')
        aep.attributes.tDn = f'uni/infra/attentp-{aep_name}'
        self.children.append(aep)


class InterfaceProfile(APICObject):
    class_ = 'infraAccPortP'
    attrs = {
        'name': '',
        'descr': '',
        'status': 'created,modified'
    }
    post_uri = '/api/mo/uni/infra.json'

    _dn_attributes = ['name']
    _dn_template = 'uni/infra/accportprof-{name}'

    def __init__(self, **kwargs):
        self.children = []
        self.attributes = Attributes(**self.attrs)
        if kwargs:
            self._set_attributes(**kwargs)


class InfraRsAccPortP(APICObject):
    class_ = 'infraRsAccPortP'
    attrs = {
        'dn': '',
        'tDn': ''
    }

    _dn_attributes = ['switch_profile', 'name']
    _dn_template = 'uni/infra/nprof-{switch_profile}/rsaccPortP-[uni/infra/accportprof-{name}]'

    def __init__(self):
        self.children = []
        self.attributes = Attributes(**self.attrs)


class InterfaceSelector(APICObject):
    class_ = 'infraHPortS'
    attrs = {
        'name': '',
        'descr': '',
        'type': 'range',
        'status': 'created,modified'
    }

    def __init__(self, **kwargs):
        self.children = []
        self.attributes = Attributes(**self.attrs)
        if kwargs:
            self._set_attributes(**kwargs)


class InterfaceBlock(APICObject):
    class_ = 'infraPortBlk'
    attrs = {
        'name': '',
        'descr': '',
        'fromPort': '',
        'toPort': '',
        'status': 'created,modified'
    }

    _dn_attributes = ['profile', 'selector', 'name']
    _dn_template = 'uni/infra/accportprof-{profile}/hports-{selector}/portblk-{name}'

    def __init__(self, **kwargs):
        self.children = []
        self.attributes = Attributes(**self.attrs)
        if kwargs:
            self._set_attributes(**kwargs)
        self.attributes.name = 'block%s' % ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))


class SNMPClientP(APICObject):
    class_ = 'snmpClientP'
    attrs = {
        'dn': '',
        'name': '',
        'addr': ''
    }

    def __init__(self, addr: str):
        self.attributes = Attributes(**self.attrs)
        self.attributes.dn = f'uni/fabric/snmppol-default/clgrp-snmpClients/client-[{addr}]'
        self.children = []


class VLANPool(APICObject):
    class_ = 'fvnsVlanInstP'
    attrs = {
        'dn': '',
        'allocMode': 'dynamic'
    }

    def __init__(self, name):
        self.attributes = Attributes(**self.attrs)
        self.attributes.dn = f'uni/infra/vlanns-[{name}]-dynamic'
        self.children = []


class EncapBlock(APICObject):
    class_ = 'fvnsEncapBlk'
    attrs = {
        'allocMode': 'static',
        'role': 'external',
        'from': 'vlan-2',
        'to': 'vlan-3966'
    }

    def __init__(self):
        self.attributes = Attributes(**self.attrs)
        self.children = []

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

    def __init__(self):
        self.attributes = Attributes(**self.attrs)
        self.children = []


class OSPFExternalPolicy(APICObject):
    class_ = 'ospfExtP'
    attrs = {
        'areaCost': '1',
        'areaCtrl': 'redistribute',
        'areaId': '',
        'areaType': 'nssa',
        'multipodInternal': 'no'
    }

    def __init__(self, **kwargs):
        self.attributes = Attributes(**self.attrs)
        self.children = []
        if kwargs:
            self._set_attributes(**kwargs)


class L3OutVRF(APICObject):
    class_ = 'l3extRsEctx'
    attrs = {
        'tnFvCtxName': ''
    }

    def __init__(self, name: str):
        self.attributes = Attributes(**self.attrs)
        self.children = []
        self.attributes.tnFvCtxName = name


class L3OutDomain(APICObject):
    class_ = 'l3extRsL3DomAtt'
    attrs = {
        'tDn': ''
    }

    def __init__(self, **kwargs):
        self.attributes = Attributes(**self.attrs)
        self.children = []
        if kwargs:
            self._set_attributes(**kwargs)


class L3Out(APICObject):
    class_ = 'l3extOut'
    attrs = {
        'name': '',
        'enforceRtctrl': 'export',
        'descr': ''
    }

    def __init__(self, **kwargs):
        self.attributes = Attributes(**self.attrs)
        self.children = []
        if kwargs:
            self._set_attributes(**kwargs)

    def ospf_area(self, ospf_area: str) -> OSPFExternalPolicy:
        if IPv4Network(ospf_area):
            _ = OSPFExternalPolicy(areaId=ospf_area)
            self.children.append(_)
            return _

    def vrf(self, name: str):
        _ = L3OutVRF(name=name)
        self.children.append(_)


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
    'infraRsDomAtt': InfraRsDomAtt,  # Domain association to infra objects
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
    'infraAccPortGrp': InterfacePolicyGroup,
    'infraAccBndlGrp': InterfacePolicyGroup,
    'infraAccPortP': InterfaceProfile,
    'infraRsAccPortP': InfraRsAccPortP,
    'fabricRsOosPath': OutOfServicePort,
    'lacpLagPol': InterfacePolicy,
    'cdpIfPol': InterfacePolicy,
    'lldpIfPol': InterfacePolicy
}
