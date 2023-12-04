import os
import re
import typing


class Terraform:
    def __init__(self):
        pass

    def __repr__(self):
        return 'terraform {\n  required_providers {\n    aci = {\n      source = "ciscodevnet/aci"\n    }\n  }\n}\n'

    def from_string(self):
        return 'terraform {\n  required_providers {\n    aci = {\n      source = "ciscodevnet/aci"\n    }\n  }\n}'


class Provider:
    type_ = 'provider'

    def __init__(self, name: str, **kwargs):
        self.name = name
        self.properties = kwargs

    def __repr__(self):
        spacing = 1
        space_max = max([len(x) for x in self.properties.keys()])
        spacing += space_max

        content = ''

        content += '%s "%s" {\n' % (self.type_, self.name)
        for k, v in self.properties.items():
            content += '  %s= %s\n' % (k.ljust(spacing), v)

        content += '}\n'

        return content

    @classmethod
    def from_string(cls, tf_string: str):
        tf_string = tf_string.replace('\n', '')
        provider_name = re.search(r'^.*?"(\w+)"', tf_string).group(1)
        properties = re.findall(r'\s+?(\w+)\s+=\s+(\S+)', tf_string)
        props = dict()
        for p in properties:
            key, value = p
            props[key] = value

        o = cls(provider_name, **props)
        return o


class Data:
    type_ = 'data'

    def __init__(self, data_source: str, data_name: str, **kwargs):
        self.source = data_source
        self.name = data_name
        self.properties = kwargs

    def __repr__(self):
        spacing = 1
        space_max = max([len(x) for x in self.properties.keys()])
        spacing += space_max

        content = ''

        content += '%s "%s" "%s" {\n' % (self.type_, self.source, self.name)
        for k, v in self.properties.items():
            content += '  %s= %s\n' % (k.ljust(spacing), v)

        content += '}\n'

        return content

    @classmethod
    def from_string(cls, tf_string: str):
        tf_string = tf_string.replace('\n', '')
        data_source, data_name = re.search(r'^.*?"(\w+)"\W+"(\w+)"', tf_string).groups()
        properties = re.findall(r'\s+?(\w+)\s+=\s+(\S+)', tf_string)
        props = dict()
        for p in properties:
            key, value = p
            props[key] = value

        o = cls(data_source, data_name, **props)
        return o


class LocalData:
    type_ = 'locals'

    def __init__(self, **kwargs):
        self.properties = kwargs

    def __repr__(self):
        spacing = 1
        space_max = max([len(x) for x in self.properties.keys()])
        spacing += space_max

        content = ''

        content += '%s {\n' % self.type_
        for k, v in self.properties.items():
            content += '  %s= %s\n' % (k.ljust(spacing), v)

        content += '}\n'

        return content

    @classmethod
    def from_string(cls, tf_string: str):
        tf_string = tf_string.replace('\n', '')
        # resource_type, resource_name = re.search(r'^.*?"(\w+)"\W+"(\w+)"', tf_string).groups()
        properties = re.findall(r'\s+?(\w+)\s+=\s+(\S+)', tf_string)
        props = dict()
        for p in properties:
            key, value = p
            props[key] = value

        o = cls(**props)
        return o


class Resource:
    type_ = 'resource'

    def __init__(self, resource_type: str, resource_name: str, **kwargs):
        self.object = resource_type
        self.name = resource_name
        self.properties = kwargs

    def ref_id(self) -> str:
        return f'{self.object}.{self.name}.id'

    def __repr__(self):
        spacing = 1
        space_max = max([len(x) for x in self.properties.keys()])
        spacing += space_max

        content = ''

        content += '%s "%s" "%s" {\n' % (self.type_, self.object, self.name)
        for k, v in self.properties.items():
            content += '  %s= %s\n' % (k.ljust(spacing), v)

        content += '}\n'

        return content

    @classmethod
    def from_string(cls, tf_string: str):
        tf_string = tf_string.replace('\n', '')
        resource_type, resource_name = re.search(r'^.*?"(\w+)"\W+"(\w+)"', tf_string).groups()
        properties = re.findall(r'\s+?(\w+)\s+=\s+(\S+)', tf_string)
        props = dict()
        for p in properties:
            key, value = p
            props[key] = value

        o = cls(resource_type, resource_name, **props)
        return o


def from_file(path_to_file: str) -> list:
    tf_resources = []

    with open(path_to_file, 'r') as f:
        content = f.read()

    content = re.split(r'\n\n+', content)

    for c in content:
        thingy = class_map[re.search(r'\w+', c).group()].from_string(c)
        tf_resources += [thingy]

    return tf_resources


# TODO: Test resource analysis using C:/Users/jxu8356/Terraform_Starter/QOL-AZ1/nutanix, this uses a common BD across
#  multiple files
def from_directory(path_to_dir: str):
    file_resources = {}
    for file in os.listdir(path_to_dir):
        if file.endswith('.tf'):
            resources = from_file(os.path.join(path_to_dir, file))
            file_resources[file] = resources

    return file_resources


class_map = {
    'resource': Resource,
    'data': Data,
    'locals': LocalData,
    'provider': Provider,
    'terraform': Terraform
}
