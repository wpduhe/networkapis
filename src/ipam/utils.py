import requests
import os
import json
import time
from urllib.parse import urlencode
from ipaddress import IPv4Address, IPv4Network, AddressValueError
from githubapi.utils import GithubAPI
import urllib3
from evolve.evolve_util import EvolveMarketplace
from typing import List, TypedDict


urllib3.disable_warnings()

BIGDEVURL = 'https://igdev3.medcity.net'
BIGQAURL = 'https://igqa.medcity.net'
BIGURL = 'https://big.medcity.net'

AI_KEY = 'IGValidator'
AI_VALUE = '0x29a'
Q_KEY = 'Tools'
Q_VALUE = 'Queued for Management'


def valid_ip(address: str):
    try:
        IPv4Address(address)
        return True
    except AddressValueError:
        return False


def calculate_network_size(num_ips: int):
    num_ips += 3

    if num_ips <= 6:
        return 8
    elif num_ips <= 14:
        return 16
    elif num_ips <= 30:
        return 32
    elif num_ips <= 62:
        return 64
    elif num_ips <= 126:
        return 128
    elif num_ips <= 254:
        return 256
    elif num_ips <= 510:
        return 512
    elif num_ips <= 1022:
        return 1024
    elif num_ips <= 2046:
        return 2048
    elif num_ips <= 4094:
        return 4096
    elif num_ips <= 8190:
        return 8192
    else:
        raise ValueError('Requested network is too large')


class BAMObject:
    def __init__(self, json_data: dict):
        self.properties = None
        self.id = None
        self.type = None
        self.name = None

        for key in json_data.keys():
            self.__setattr__(key, json_data[key])

        if self.properties is not None:
            self.properties = self.convert_properties(self.properties)

    def output(self):
        output = {}

        for attribute in self.__dict__.keys():
            if attribute is not None:
                output[attribute] = self.__getattribute__(attribute)

        try:
            if isinstance(output['properties'], dict):
                output['properties'] = self.convert_properties(output['properties'])
        except KeyError:
            pass

        return output

    def dump_json(self):
        print(json.dumps(self.__dict__, indent=4))

    @staticmethod
    def convert_properties(content):
        """
        :rtype: dict or str
        :param content: str or dict
        :return:

        This method converts the value of the properties attribute from the BAM supplied string to a dict or from
        a dict to the BAM formatted str.
        """

        if isinstance(content, dict):
            content_str = ''

            for key, value in content.items():
                content_str += f'{key}={value}|'

            return content_str.rstrip('|')

        elif isinstance(content, str):
            x = {}

            content = content.split('|')
            for data in content:
                if '=' in data:
                    x[data.split('=')[0]] = data.split('=')[1]

            return x
        else:
            raise TypeError('This method only supports str or dict')


class BIG:
    def __init__(self, dev=False, qa=False):
        self.session = requests.session()
        self.session.verify = False

        if dev:
            self.url = BIGDEVURL
        elif qa:
            self.url = BIGQAURL
        else:
            self.url = BIGURL

        self.login()

        configs = self.get_configurations()

        self.internal = next(config for config in configs if config.name == 'HCA Internal')
        self.external = next(config for config in configs if config.name == 'HCA-External')

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tb):
        self.logout()
        self.session.close()

    def login(self):
        path = '/rest_login'

        data = {
            'username': os.environ.get('ProteusUsername'),
            'password': os.environ.get('ProteusPassword')
        }

        self.session.headers.update({'Accept': 'application/json'})

        r = self.session.post(f'{self.url}{path}', json=data)

        self.session.headers.update({'auth': f'Basic {r.json()["access_token"]}'})

    def logout(self):
        self.session.get(f'{self.url}/logout')

    def get(self, path):
        r = self.session.get(f'{self.url}{path}')
        return r

    def post(self, path: str, data: dict):
        r = self.session.post(f'{self.url}{path}', json=data)
        return r

    def put(self, path: str, data: dict):
        r = self.session.put(f'{self.url}{path}', json=data)
        return r

    def get_configurations(self):
        path = '/api/v1/configurations'

        r = self.get(path)
        configs = [BAMObject(config) for config in r.json()]
        return configs

    def get_entity_by_id(self, entity_id: int):
        path = f'/api/v1/entities/{entity_id}'

        r = self.get(path)

        entity = BAMObject(r.json())

        return entity

    def update_entity_by_id(self, bam_object: BAMObject):
        """Update any BAM object using its ID"""
        path = f'/api/v1/internal/entities/{bam_object.id}'

        r = self.put(path=path, data=bam_object.output())

        if 200 <= r.status_code <= 201:
            return True

        return None

    def get_ip(self, ipaddress: str, internal=True):
        path = f'/api/v1/ip4addresses/{("HCA Internal" if internal else "HCA-External")}/{ipaddress}'

        r = self.get(path)

        if r.ok:
            ip = BAMObject(r.json())
            ip = self.get_entity_by_id(ip.id)
        else:
            return None

        return ip

    def is_ip_available(self, ipaddress: str, internal=True):
        if IPv4Address(ipaddress):
            r = self.get_ip(ipaddress, internal=internal)

            if r:
                return False
            else:
                return True
        else:
            raise AddressValueError

    def assign_ip(self, ipaddress: str, name: str, internal=True):
        path = f'/api/v1/ip4addresses/{("HCA Internal" if internal else "HCA-External")}/{ipaddress}/' \
               f'updateStaticIP4Address'

        data = {
            'name': name
        }

        r = self.post(path, data)

        if r.ok:
            ip = BAMObject(r.json())
            ip = self.get_entity_by_id(ip.id)
        else:
            return None

        return ip

    def assign_next_ip(self, network_cidr: str, name: str, internal=True):
        path = f'/api/v1/ip4networks/{(self.internal.name if internal else self.external.name)}/{network_cidr}/' \
               f'assignNextAvailableStaticIP4Address'

        data = {
            'name': name
        }

        ip = None

        while not ip:
            r = self.post(path, data)

            if r.ok:
                ip = BAMObject(r.json()['ip4Address'])
                ip = self.get_entity_by_id(ip.id)

                return ip
            elif f'No IP addresses available in {network_cidr} with' in r.json()['message']:
                return None

        return None

    def assign_next_ip_from_list(self, network_list: list, name: str):
        network_list = (network for network in network_list)

        network = next(network_list)

        ip = None

        while not ip:
            ip = self.assign_next_ip(network_cidr=network, name=name)

            if ip:
                return ip
            else:
                try:
                    network = next(network_list)
                except StopIteration:
                    return None

    def assign_next_common_ip_range(self, network_list: list, number_of_addresses: int, name: str):
        network_list = [IPv4Network(network, strict=False) for network in network_list]

        if not all(network.num_addresses == network_list[0].num_addresses for network in network_list):
            return None

        network_addresses = network_list[0].num_addresses

        # Get each network from BIG
        bam_networks = []
        for network in network_list:
            n = self.get_network(network.with_prefixlen)

            if not n:
                return None
            else:
                bam_networks.append(n)

        ip_data = {}

        # Get all addresses assigned on each network
        for bam_network, network in zip(bam_networks, network_list):
            r = self.get(f'/api/v1/networks/{bam_network.id}/ip4addresses?count={network_addresses}')
            ip_addresses = r.json()
            ip_addresses = [BAMObject(i) for i in ip_addresses]
            ip_addresses = [IPv4Address(i.properties['address']) for i in ip_addresses]
            offsets = set(int(ip) - int(network.network_address) for ip in ip_addresses)
            ip_data.__setitem__(network, offsets)

        # Combine all offsets into a single set to reveal what ip addresses are not commonly available between all of
        # the networks
        all_offsets = [value for value in ip_data.values()]
        all_offsets = set.union(*all_offsets)

        commonly_available_ips = set()
        for i in range(1, network_addresses - 1):
            if i not in all_offsets:
                commonly_available_ips.add(i)

        assignment_offsets = None

        for offset in commonly_available_ips:
            set_values = set(range(offset, offset + number_of_addresses))
            if all(offset in commonly_available_ips for offset in set_values):
                assignment_offsets = set_values
                break

        if assignment_offsets:
            # Assign the IP ranges in each network
            for network in network_list:
                for offset in assignment_offsets:
                    _ = self.assign_ip(str(network.network_address + offset), name=name)

            return {'Assignments': list(assignment_offsets)}
        else:
            # Range doesn't exist
            return {'message': 'No range that size exists on this set of networks'}

    def assign_ips_by_offsets(self, network_list: list, offsets_and_names: list):
        network_list = (IPv4Network(network, strict=False) for network in network_list)

        for network in network_list:
            for offset, name in offsets_and_names:
                print(offset, name)
                _ = self.assign_ip(ipaddress=str(network.network_address + offset), name=name)

        return {'message': 'All assignments completed'}

    def delete_ip(self, ip: str):
        ip = self.get_ip(ip)

        if ip:
            path = f'/api/v1/ip4addresses/{ip.id}'

            r = self.session.delete(f'{self.url}{path}')

            if r.status_code == 204:
                return True
            else:
                return None

        return None

    def get_network(self, network_cidr, internal=True):
        network, cidr = network_cidr.split('/')
        path = f'/api/v1/ip4networks/{("HCA Internal" if internal else "HCA-External")}/{network}/{cidr}'

        r = self.get(path)

        if r.ok:
            network = BAMObject(r.json())
            network = self.get_entity_by_id(network.id)
        else:
            return None

        return network

    def assign_next_network(self, ip_block_cidr: str, no_of_ips: int, coid: int, asn: int, name: str):
        block = self.get_ip_block(ip_block_cidr)

        if block:
            path = f'/api/v1/ip4blocks/{block.id}/ops/assignNextAvailableIP4Network'

            size = calculate_network_size(num_ips=no_of_ips)

            data = {
                'size': size,
                'coid': str(coid),
                'name': name
            }

            r = self.post(path, data)

            if r.ok:
                network = BAMObject(r.json()['ip4Network'])
                network = self.get_entity_by_id(network.id)
            else:
                return None

            net = IPv4Network(network.properties['CIDR'])

            _ = self.assign_ip(ipaddress=str(net.network_address + 2), name='Reserved for Network')
            _ = self.assign_ip(ipaddress=str(net.network_address + 3), name='Reserved for Network')

            network.properties['ASN'] = asn

            self.update_object(network)

            return network
        return None

    def assign_next_loopback(self, ip_block_cidr: str, coid: int, asn: int, name: str):
        block = self.get_ip_block(ip_block_cidr)

        if block:
            path = f'/api/v1/ip4blocks/{block.id}/ops/assignNextAvailableIP4Network'

            data = {
                'size': 1,
                'coid': str(coid),
                'asn': str(asn),
                'name': name
            }

            r = self.post(path, data)

            if r.ok:
                network = BAMObject(r.json()['ip4Network'])
                network = self.get_entity_by_id(network.id)
            else:
                return None

            net = IPv4Network(network.properties['CIDR'])

            _ = self.assign_ip(ipaddress=str(net.network_address), name=name)

            network.properties['ASN'] = asn

            self.update_object(network)

            return network
        return None

    def assign_next_routed_link(self, ip_block_cidr: str, coid: int, asn: int, name: str, device_1: str, device_2: str):
        block = self.get_ip_block(ip_block_cidr)

        if block:
            path = f'/api/v1/ip4blocks/{block.id}/ops/assignNextAvailableIP4Network'

            data = {
                'size': 4,
                'coid': str(coid),
                'asn': str(asn),
                'name': name
            }

            r = self.post(path, data)

            if r.ok:
                network = BAMObject(r.json()['ip4Network'])
                network = self.get_entity_by_id(network.id)
            else:
                return None

            net = IPv4Network(network.properties['CIDR'])

            _ = self.assign_ip(ipaddress=str(net.network_address + 1), name=device_1)
            _ = self.assign_ip(ipaddress=str(net.network_address + 2), name=device_2)

            network.properties['ASN'] = asn

            self.update_object(network)

            return network
        return None

    def assign_next_network_from_list(self, block_list: list, no_of_ips: int, coid: int, asn: int, name: str):
        ip_blocks = (x for x in block_list)

        subnet = None

        while not subnet:
            try:
                subnet = self.assign_next_network(ip_block_cidr=next(ip_blocks), no_of_ips=no_of_ips, coid=coid,
                                                  asn=asn, name=name)
            except StopIteration:
                return None

        return subnet

    def get_ip_block(self, network_cidr: str):
        params = {
            'keyword': network_cidr,
            'types': 'IP4Block',
            'start': 0,
            'count': 1
        }

        path = f'/api/v1/entities/ops/searchByObjectType?{urlencode(params)}'

        r = self.get(path)

        if r.ok:
            block = BAMObject(r.json()[0])
            block = self.get_entity_by_id(block.id)
        else:
            return None

        return block

    def update_object(self, bam_object: BAMObject, internal=True):
        """Currently only supports updating IP4Address objects"""
        if bam_object.type == 'IP4Address':
            path = f'/api/v1/ip4addresses/{(self.internal.name if internal else self.external.name)}/' \
                   f'{bam_object.properties["address"]}'

            r = self.put(path, bam_object.output())

            if r.ok:
                return True
            else:
                return False

        elif bam_object.type == 'IP4Network':
            # This endpoint doesn't actually exist yet
            path = f'/api/v1/ip4networks/{(self.internal.name if internal else self.external.name)}/' \
                   f'{bam_object.properties["CIDR"]}'

            r = self.put(path, bam_object.output())

            if r.ok:
                return True
            else:
                return False
        else:
            return False

    def get_zone(self, hint: str, internal=True):
        params = {
            'start': 0,
            'count': 1,
            'options': f'hint={hint}|retrieveFields=true',
            'containerid': (self.internal.id if internal else self.external.id)
        }

        path = f'/api/v1/zones/zonesByHint?{urlencode(params)}'

        r = self.get(path)

        if r.ok:
            zone = BAMObject(r.json()[0])
            zone = self.get_entity_by_id(zone.id)
        else:
            return None

        return zone

    def get_host_record(self, fqdn: str, internal=True):
        path = f'/api/v1/hostrecords/{(self.internal.name if internal else self.external.name)}/{fqdn}'

        r = self.get(path)

        if r.ok and len(r.json()) == 1:
            record = BAMObject(r.json()[0])
            record = self.get_entity_by_id(record.id)

            return record
        else:
            return None

    def get_host_records(self, hint: str):
        start = 0
        records = []

        path = f'/api/v1//hostrecords/hostrecordsByHint/?start={start}&options=hint={hint}'

        r = self.get(path=path)

        while r.json():
            records += [BAMObject(j) for j in r.json()]
            start += 10

            path = f'/api/v1//hostrecords/hostrecordsByHint/?start={start}&options=hint={hint}'

            r = self.get(path)

        return records

    def get_next_record_sequence(self, hint: str):
        records = self.get_host_records(hint=hint)

        if not records:
            return 1

        sequence = [int(r.name.split('-')[2]) for r in records]
        sequence.sort()

        logical_sequence = set(range(1, sequence[-1] + 1))

        available_sequence = logical_sequence.symmetric_difference(set(sequence))

        if available_sequence:
            return list(available_sequence)[0]
        else:
            return sequence[-1] + 1

    def add_host_record(self, zone: str, fqdn: str, ip: str, manage: bool=False):
        if IPv4Address(ip):
            zone = self.get_zone(zone)

            path = f'/api/v1/zones/{zone.id}/hostrecords'

            next_sequence = self.get_next_record_sequence(hint=f'^{fqdn[:10]}')

            fqdn = fqdn.replace('#', str(next_sequence))

            data = {
                'host_fqdn': fqdn,
                'ipaddresses': [ip],
                'ttl': 3600,
                'deploy': True,
                'addPTR': True,
                'overrideNamingPolicy': True,
                'queueManagement': manage
            }

            r = self.post(path, data)

            if r.ok:
                record = BAMObject(r.json())
                record = self.get_entity_by_id(record.id)

                return record
            else:
                return None, r

        else:
            raise ValueError('Invalid IP address provided')

    def delete_host_record(self, fqdn: str, internal=True):
        # tptdc-aclf-36-b-h.tdc.tp.mgmt.medcity.net  from QA
        record = self.get_host_record(fqdn=fqdn, internal=internal)

        if record:
            path = f'/api/v1/hostrecords/{record.id}'

            r = self.session.delete(f'{self.url}{path}')
            print(r.status_code, r.json())

            if r.status_code == 204:
                return True
            else:
                return None
        return None

    def manage_device(self, dns_template: str, ip: str, ip_name: str='Not Provided'):
        path = '/api/v1/management/'

        if IPv4Address(ip):
            # Attempt to get IP4Address object
            ip_address = ip
            ip = self.get_ip(ipaddress=ip)

            # If IP4Address Object does not exist, assign it
            if not ip:
                ip = self.assign_ip(ipaddress=ip_address, name=ip_name)

            request_data = {
                'host_fqdn': dns_template,
                'ipaddress': ip.properties['address']
            }

            r = self.post(path=path, data=request_data)

            if r.ok:
                return 200, {'message': f'{ip_address} has been queued for management'}
            else:
                return r.status_code, r.json()


class ManagementJob:
    queue_path = r'pyapis/ipam/job_queue'
    bad_file_path = r'pyapis/ipam/invalid'
    completed_jobs = r'pyapis/ipam/completed_jobs'

    def __init__(self):
        self.run_time = time.time()

    @classmethod
    def load(cls, data: dict):
        job = cls()
        for key in data:
            job.__setattr__(key, data[key])

        return job

    @classmethod
    def create_mgmt_job(cls, job_name: str, delay_in_seconds: int, ip: str, dns_template: str):
        gh = GithubAPI()
        job = cls()
        job.name = job_name
        job.run_time += delay_in_seconds
        IPv4Address(ip)
        job.ip = ip
        job.dns_template = dns_template
        gh.add_file(file_path=f'{job.queue_path}/{job.name}', message='IPAM Job Creation',
                    content=json.dumps(job.__dict__))


EVOLVE_PATH = '/networkapis-ipam/v/1.0.0'


class AddressMixin:
    def get_address(self: EvolveMarketplace, address) -> requests.Response:
        return self.get(f'{EVOLVE_PATH}/api/addresses/get_address/{address}')

    def assign_next_ip(self: EvolveMarketplace, network: str, name: str) -> requests.Response:
        return self.post(f'{EVOLVE_PATH}/api/addresses/assign_next_ip', data=dict(network=network, name=name))

    def assign_next_ip_from_list(self: EvolveMarketplace, networks: list, name: str) -> requests.Response:
        return self.post(f'{EVOLVE_PATH}/api/addresses/assign_next_ip_from_list', data=dict(networks=networks,
                                                                                            name=name))

    def assign_address_series(self: EvolveMarketplace, network: str, names: List[str]) -> requests.Response:
        return self.post(f'{EVOLVE_PATH}/api/addresses/assign_address_series',
                         data=dict(network=network, names=names))

    def assign_addresses_by_offsets(self: EvolveMarketplace, network: str,
                                    assignments: List[TypedDict('Offset', {'name': str, 'offset': int})]) -> \
            requests.Response:
        return self.post(f'{EVOLVE_PATH}/api/addresses/assign_addresses_by_offsets',
                         data=dict(network=network, assignments=assignments))

    def delete_address(self: EvolveMarketplace, addresses: List[str]) -> requests.Response:
        return self.delete(f'{EVOLVE_PATH}/api/addresses', data=dict(addresses=addresses))

    def bulk_reserve(self: EvolveMarketplace,
                     assignments: List[TypedDict('AddressData', {'address': str, 'name': str})]) -> requests.Response:
        return self.post(f'{EVOLVE_PATH}/api/addresses/bulk_reserve', data=dict(assignments=assignments))

    def manage_device(self: EvolveMarketplace, address: str, dns_template) -> requests.Response:
        return self.post(f'{EVOLVE_PATH}/api/dns/manage_device',
                         data=dict(address=address, dns_template=dns_template))


class NetworkMixin:
    def get_network(self: EvolveMarketplace, network) -> requests.Response:
        return self.get(f'{EVOLVE_PATH}/api/networks/{network}')

    def update_network(self: EvolveMarketplace,
                       data: TypedDict('UpdateNetwork', {'network': str, 'keyvalues': dict})) -> requests.Response:
        return self.put(f'{EVOLVE_PATH}/api/networks/update_network', data=data)

    def delete_network(self: EvolveMarketplace, network: str, data: dict or list) -> requests.Response:
        return self.delete(f'{EVOLVE_PATH}/api/networks/{network}', data=data)

    def get_network_by_address(self: EvolveMarketplace, address: str) -> requests.Response:
        return self.get(f'{EVOLVE_PATH}/api/networks/get_network_by_address/{address}')

    def create_next_available_network(self: EvolveMarketplace, no_of_ips: int, name: str, cidr_blocks: List[str],
                                      coid: str, asn: str, market: str) -> requests.Response:
        return self.post(f'{EVOLVE_PATH}/api/networks/create_next_available_network',
                         data=dict(no_of_ips=no_of_ips, name=name, cidr_blocks=cidr_blocks, coid=coid, asn=asn,
                                   market=market))

    def create_next_routed_network(self: EvolveMarketplace, name: str, cidr_block: str, coid: str, asn: str,
                                   market: str) -> requests.Response:
        return self.post(f'{EVOLVE_PATH}/api/networks/create_next_routed_network',
                         data=dict(name=name, cidr_block=cidr_block, coid=coid, asn=asn, market=market))

    def create_next_loopback_address(self: EvolveMarketplace, name: str, cidr_block: str, coid: str, asn: str,
                                     market: str) -> requests.Response:
        return self.post(f'{EVOLVE_PATH}/api/networks/create_next_loopback_address',
                         data=dict(name=name, cidr_block=cidr_block, coid=coid, asn=asn, market=market))


class NetworkAPIIPAM(
        EvolveMarketplace,
        AddressMixin,
        NetworkMixin):

    def __pass__(self):
        pass
