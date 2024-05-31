from typing import Optional, List
from pydantic import BaseModel


class PostTester(BaseModel):
    key: str
    key2: str


class AddNewLeafPair(BaseModel):
    AvailabilityZone: str
    APIKey: str
    Switch1_SerialNumber: str
    Switch2_SerialNumber: str
    RackSwitch1: str
    RackSwitch2: str


class AddOOBLeaf(BaseModel):
    AvailabilityZone: str
    APIKey: str
    SerialNumber: str
    Rack: str


class CopyVMMPortGroups(BaseModel):
    AvailabilityZone: str
    VmmDomain: str
    AEP: str


class AEPMapping(BaseModel):
    AEP: str
    Tenant: str
    AP: str
    EPG: str


class CreateSVI(BaseModel):
    APIKey: str
    Environment: str
    vlanName: str
    numberOfIPs: int
    vrf: Optional[str]
    description: Optional[str]
    dhcp: bool = False


class AssignEPGToAEP(BaseModel):
    AvailabilityZone: str
    APIKey: str
    AEPMappings: List[AEPMapping]


class CreateNewEPG(BaseModel):
    APIKey: str
    AppProfileName: str
    BridgeDomainName: str
    EPGName: str
    Description: str
    NumIPsReqd: int
    AEPs: List[str]


class CreateCustomEPG(BaseModel):
    APIKey: str
    AppProfileName: str
    BridgeDomainName: str
    EPGName: str
    Description: str
    Subnets: List[str]
    AEPs: List[str]


class CreateCustomEPGv2(BaseModel):
    APIKey: str
    TenantName: str
    VRFName: str
    AppProfileName: str
    BridgeDomainName: str
    EPGName: str
    Description: str
    Subnets: List[str]
    AEPs: List[str]


class VLANData(BaseModel):
    VLAN: str
    tenant: str
    BD: str
    VRF: str
    EPG: str
    AP: str


class SVIToBD(BaseModel):
    APIKey: str
    NexusEnvironment: str
    ACIEnvironment: str
    suppressL3: bool
    migrate: str
    vlanData: List[VLANData]


class TrunkVlan(BaseModel):
    APIKey: str
    Environment: str
    MAC: List[str]
    vlan: str
    vlanName: str


class WSARoutes(BaseModel):
    prefix: str
    location: str
    requester: str
    APIKey: str


class WSADeployRoutes(BaseModel):
    key: str
    site: str


class WSABuild(BaseModel):
    APIKey: str
    wsa_list: str
    username: str
    password: str


class PACFile(BaseModel):
    section: str
    host_exp: str
    directive: str
    comment: str


class CreateNewAEP(BaseModel):
    AvailabilityZone: str
    AEP: str


class IntfProfile(BaseModel):
    APIKey: str
    AvailabilityZone: str
    AEP: str
    Server_Name: str
    Port_Channel: bool = False
    LACP: bool = False
    Switch_Profile: str
    Interfaces: str


class ACIPortConfig(BaseModel):
    infra_name: str
    switch_profiles: List[str]
    interfaces: str
    port_channel: bool = False
    lacp: bool = False


class PortTemplates(BaseModel):
    PortTemplateName: str
    Configurations: List[ACIPortConfig]


class ACIInterfaceConfiguration(BaseModel):
    APIKey: str
    Configurations: List[PortTemplates]


class ACIReclaimInterfaces(BaseModel):
    APIKey: str
    profile_name: str
    interfaces: str


class TagDefinitions(BaseModel):
    epg_name: str
    tag: str


class TagEPG(BaseModel):
    APIKey: str
    AvailabilityZone: str
    EPGs: List[TagDefinitions]


class ManageDevice(BaseModel):
    ips: List[str]
    dns_template: str


class CreateDREnvironment(BaseModel):
    APIKey: str
    Environment: str


class MigrateToADMZ(BaseModel):
    APIKey: str
    AvailabilityZone: str
    EPG: str
    Tenant: str
    Subnet: str
    NextHopFirewall: str
    FirewallVLAN: str


class IPUpdates(BaseModel):
    ip: str
    name: str


class UpdateIPs(BaseModel):
    APIKey: str
    Updates: List[IPUpdates]


class ProxyPACException(BaseModel):
    Directive: str
    APIKey: str
    AddOrRemove: str
    Hostname: str
    Comment: str
    TicketNumber: str


class FlexVPNNetworksRequests(BaseModel):
    APIKey: str
    Networks: List[str]
    SessionDescription: str
    SessionName: str


class PoolMember(BaseModel):
    server_name: str
    address: str
    port: int


class CustomMonitor(BaseModel):
    type: str
    name: str


class AddMemberToPool(BaseModel):
    APIKey: str
    vip_address: str
    vip_port: int
    member: PoolMember


class RemoveMemberFromPool(BaseModel):
    APIKey: str
    vip_address: str
    vip_port: int
    member_address: str


class CreateAppLB(BaseModel):
    APIKey: str
    name: str
    protocol: str = "tcp"
    port: str = "443"
    custom_monitor: Optional[CustomMonitor]
    members: List[PoolMember]
    address: Optional[str]
    skip_dns: bool = False


class NetIPDef(BaseModel):
    IP: str
    Name: str
    Type: str


class AddFirewallRule(BaseModel):
    Sources: List[NetIPDef]
    Destinations: List[NetIPDef]
    Services: List[str]
    RuleName: str
    Description: str
    APIKey: str


class iPSKMacAdd(BaseModel):
    APIKey: str
    Task: str
    Div: str
    idg: str
    macaddr: str
    UserID: str


class CreateCustomSVI(BaseModel):
    APIKey: str
    subnet: str
    description: str
    vrf: Optional[str]
    vlan: Optional[int]


class RebrandEpgBd(BaseModel):
    APIKey: str
    old_epg_dn: str
    new_epg_dn: str
    new_bd_name: Optional[str]


class CloneAEP(BaseModel):
    APIKey: str
    aep_name: str
    new_aep_name: str


class RebrandAEP(BaseModel):
    APIKey: str
    old_aep_name: str
    new_aep_name: str


class DRTestMove(BaseModel):
    APIKey: str
    epg: str


class GetCurrentSNMPStrings(BaseModel):
    APIKey: str
    Trusted: bool


class DRTRestoreAppInstance(BaseModel):
    APIKey: str
    app_code: str
    instance_name: str


class ChangeEPGEncap(BaseModel):
    APIKey: str
    epg_dn: str
    old_encap: int
    new_encap: int


class UpdateStaticRoute(BaseModel):
    APIKey: str
    tenant: str
    cidr: str
    new_next_hop: str


class MaintenanceGroups(BaseModel):
    APIKey: str


class VlanAssignment(BaseModel):
    vlan_ids: List[int]
    aep: str


class AssignVlanToAep(BaseModel):
    APIKey: str
    assignments: List[VlanAssignment]


class CreateNewAppInstance(BaseModel):
    APIKey: str
    az: str
    no_of_ips: int
    application: str
    instance_name: str
    dmz: bool
    aeps: list


class CreateDRTAppInstance(BaseModel):
    APIKey: str


class ACIMigrateNetwork(BaseModel):
    APIKey: str
    src: str
    dst: str
    network: str
    dst_l3out: str
    dst_nodes: list
    next_hop: str
    external_epg: str
    dst_admz_l3out: str = None
    admz_external_epg: str = None
