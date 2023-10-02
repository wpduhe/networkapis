import re


def nx_string_split(string_config):
    # Requires string output, Useful for napalm _send_command() output
    # string_config = string_config.split('\n\n')
    string_config = re.split(r'\n{2,3}', string_config)
    output = []

    for section in string_config:
        output.append(section.split('\n'))

    if len(output) == 1:
        return output[0]
    else:
        return output


def nx_split_switchport(array):
    # Requires a 'show run' style command where sections are separated by \n\n
    # Takes CLI output and segments it into sections
    # Result is a list of lists that are configurations equivalent to more specific show commands

    # Convert configuration to string
    array = ''.join(array)
    # Remove any '\n\n ' instances
    array = array.replace('\n\n ', '\n ')

    split = re.findall('[A-z0-9]\n[A-z0-9]', array)
    for x in split:
        array = array.replace(x[0] + x[1] + x[2], x[0] + x[1] + x[1] + x[2])
    # Split configuration into sections
    array = array.split('\n\n')
    # Generator expression that feeds into a list
    # Example: configuration = list(nx_split_config(output))
    for x in array:
        yield x.split('\n')


def nx_split_config(array):
    # Requires a 'show run' style command where sections are separated by \n\n
    # Takes CLI output and segments it into sections
    # Result is a list of lists that are configurations equivalent to more specific show commands

    # Convert configuration to string
    array = ''.join(array)
    # Remove any '\n\n ' instances
    array = array.replace('\n\n ', '\n ')
    # Split configuration into sections
    array = array.split('\n\n')
    # Generator expression that feeds into a list
    # Example: configuration = list(nx_split_config(output))
    for x in array:
        yield x.split('\n')


def nx_filter_svi(config):
    # nx_split_config should be run first
    for x in config[:]:
        if x[0].lower().find('vlan') == -1:
            config.remove(x)


def nx_filter_phys(config):
    # nx_split_config should be run first
    for x in config[:]:
        if x[0].lower().find('ethernet') == -1:
            config.remove(x)


def nx_filter_po(config):
    # nx_split_config should be run first
    for x in config[:]:
        if x[0].lower().find('port-channel') == -1:
            config.remove(x)


def nx_filter_lo(config):
    # nx_split_config should be run first
    for x in config[:]:
        if x[0].lower().find('loopback') == -1:
            config.remove(x)


def nx_filter_vlan(config):
    # nx_split_config should be run first
    for x in config[:]:
        if re.search('^vlan [0-9]', x[0].lower()) is None:
            config.remove(x)
    for x in config[:]:
        if ',' in x[0]:
            config.remove(x)


def nx_set_hsrp_passive(output, priority='1'):
    # Requires 'show hsrp brief' output
    import re

    config = ['configure t']

    regex = re.compile(r'Vlan\d+ +\d+')
    for line in output:
        results = regex.search(line)
        if results is not None:
            info = re.split(' +', results.group())
            config.append('interface ' + info[0])
            config.append(' hsrp ' + info[1])
            config.append('  priority ' + priority)

    return config


def nx_set_hsrp_active(output, priority='250'):
    # Requires 'show hsrp brief' output
    import re

    config = ['configure t']

    regex = re.compile(r'Vlan\d+ +\d+')
    for line in output:
        results = regex.search(line)
        if results is not None:
            info = re.split(' +', results.group())
            config.append('interface ' + info[0])
            config.append(' hsrp ' + info[1])
            config.append('  priority ' + priority)
            config.append('  preempt')

    return config


def nx_custom_interface_configs(output, custom):
    import re
    regex = re.compile('^interface')
    config = []
    for config_set in output:
        for line in config_set:
            results = regex.search(line)
            if results is not None:
                config.append(line + '\n')
                for x in custom:
                    config.append(' ' + x + '\n')

    return config


def nx_compare_trunk_vlans(allowed_list, vlan):
    vlan_list = allowed_list.split(',')
    allowed_vlans = []
    for item in vlan_list[:]:
        if '-' in item:
            item = item.split('-')
            for x in range(int(item[0]), int(item[1]) + 1):
                allowed_vlans.append(x)
        else:
            allowed_vlans.append(int(item))

    if int(vlan) in allowed_vlans:
        return True
    else:
        return False

# def nx_filter_l3(config):
#     for x in config[:]:
#         try:
#             x.index(' ip address')
#         except ValueError:
#             config.remove(x)
