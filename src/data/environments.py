import json
from ipaddress import IPv4Network
from typing import List


class ACIEnvironment:
    Name: str
    DREnv: str
    DataCenter: str
    F5ProdEnvironment: str
    F5QAEnvironment: str
    ADMZDomain: str
    ADMZPolicy: str
    ADMZFirewalls: List[dict]
    IPAddress: str
    DNSName: str
    L3OutCore: str
    L3OutCore_EPG: str
    L3OutADMZ: str
    L3OutADMZ_EPG: str
    Tenant: str
    ADMZTenant: str
    ASN: str
    COID: str
    VRF: str
    ADMZVRF: str
    PhysicalDomain: str
    FirewallAEP: str
    Subnets: list
    ADMZSubnets: list
    VLANRanges: list
    OOBLeafIPRange: str
    OOBLeafGateway: str
    LeafDNSTemplate: str
    FirmwareGroup: str
    EvensMaintenanceGroup: str
    OddsMaintenanceGroup: str
    OOBMaintenanceGroup: str
    StagingMaintenanceGroup: str
    OOBLeafProfile: str
    DataLeafSeries: int
    MgmtLeafSeries: int
    InitLeaf: int
    PrimaryDNS: str
    SecondaryDNS: str
    TertiaryDNS: str
    PreferredNTP: str
    SyslogDest: str
    BLF101Location: str
    BLF102Location: str
    IPSupernet: str

    def __init__(self, env: str=None):
        if env is not None:
            data = json.load(open('data/ACIEnvironments.json', 'r'))
            try:
                env = next(x for x in data['Environments'] if x['Name'].upper() == env.upper())
            except StopIteration:
                raise ValueError('Environment Does Not Exist')

            for key in env:
                self.__setattr__(key, env[key])

    def __exit__(self):
        # TODO: Add process to write the environment back to disk or Gitlab
        return None

    def dump_json(self):
        print(json.dumps(self.__dict__, indent=4))


class NexusEnvironment:
    name: str
    l3switch1: str
    l3switch2: str
    Subnets: List[str]
    vrfs: List[str]
    defaultVRF: str = ''
    ospfArea: str
    ospfID: str
    vlanRange: str
    dhcpRelay: List[str]
    ASN: str
    COID: str
    aciPhysDomain: str = None
    aciAEP: str = None

    def __init__(self, env: str=None):
        if env is not None:
            data = json.load(open('data/NexusEnvironments.json', 'r'))
            try:
                env = next(x for x in data['Environments'] if x['name'] == env.upper())
            except StopIteration:
                raise ValueError('Environment Does Not Exist')

            for key in env:
                self.__setattr__(key, env[key])

    def __exit__(self):
        # TODO: Add process to write the environment back to disk or Gitlab
        return None

    def dump_json(self):
        print(json.dumps(self.__dict__, indent=4))


class F5Environment:
    nameField: str
    devicesField: List[str]
    iPPoolsField: List[str]
    deviceGroupNameField: str

    def __init__(self, env: str=None):
        if env is not None:
            data = json.load(open('data/F5Environments.json', 'r'))
            try:
                env = next(x for x in data if x['nameField'].upper() == env.upper())
            except StopIteration:
                raise ValueError('Environment Does Not Exist')

            for key in env:
                self.__setattr__(key, env[key])

    def __exit__(self):
        # TODO: Add process to write the environment back to disk or Gitlab
        return None

    def dump_json(self):
        print(json.dumps(self.__dict__, indent=4))


class FirewallPolicy:
    SecurityPolicy: str
    Networks: list
    Targets: list
    Domain: str
    Routes: list

    def __init__(self, env: str):
        if env:
            data = json.load(open('data/FirewallPolicies.json'))
            try:
                env = next(x for x in data if x['SecurityPolicy'].upper() == env.upper())
            except StopIteration:
                raise Exception('Environment does not exist')

            for key in env:
                self.__setattr__(key, env[key])

            self.Networks = [IPv4Network(network) for network in self.Networks]

    @classmethod
    def get_policy_by_ip(cls, ip: str):
        frdc_b2b_nat_ranges = [IPv4Network(x) for x in ['10.65.2.0/23', '10.65.24.0/22', '10.65.28.0/23',
                                                        '10.65.30.0/24', '10.65.32.0/21', '10.65.36.0/22',
                                                        '10.65.64.0/19']]

        xrdc_b2b_nat_ranges = [IPv4Network(x) for x in ['10.129.2.0/23', '10.129.24.0/22', '10.129.28.0/24',
                                                        '10.129.32.0/22', '10.129.34.0/23', '10.129.64.0/20',
                                                        '10.129.80.0/21', '10.129.88.0/22']]

        ip = IPv4Network(ip, strict=False)

        data = json.load(open('data/FirewallPolicies.json'))

        for env in data:
            env = cls(env['SecurityPolicy'])

            if env.SecurityPolicy == 'COLO-FRDC-VPN':
                env.Networks += [IPv4Network(net) for net in frdc_b2b_nat_ranges]
            elif env.SecurityPolicy == 'COLO-XRDC-VPN':
                env.Networks += [IPv4Network(net) for net in xrdc_b2b_nat_ranges]

            for network in env.Networks:
                if ip.network_address in list(network.hosts()) or ip.network_address == network.network_address:
                    return env

        # Nothing was found
        if ip.is_global:
            env = cls('Colo_External')
            return env
        else:
            return None

    @staticmethod
    def generate_policy_list(ips: list):

        policy_list = []

        for ip in ips:
            ip = IPv4Network(ip, strict=False)

            policy = FirewallPolicy.get_policy_by_ip(str(ip.network_address))

            if policy:
                if [policy.Domain, policy.SecurityPolicy] not in policy_list:
                    policy_list.append([policy.Domain, policy.SecurityPolicy])

        return list(policy_list)
