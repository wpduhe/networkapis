from nexus import runSSHCommands
from data.information import getNexusEnvironments
from creds.creds import credentials
import re


def getNxVlan(env):

    creds = credentials()

    env = getNexusEnvironments(env)

    ssh = runSSHCommands.sshSession(env['l3switch1'], creds['username'], creds['password'])
    vlan_output = ssh.executeCmd('show vlan brief | inc active')
    ssh.ssh.close()

    vlans = []
    for vlan in vlan_output:
        vlans.append(int(re.search('^\d+', vlan).group()))

    for vlan in env['vlanRange']:
        if vlan in vlans:
            continue
        else:
            break

    return vlan
