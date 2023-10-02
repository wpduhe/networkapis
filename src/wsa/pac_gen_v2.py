from githubapi.utils import GithubAPI
import json


def pac_gen(loc: str, ref='pilot', mobile: bool=False):
    if loc.lower() not in ['nas', 'ftw', 'tpa', 'sdc', 'slc', 'orl']:
        raise ValueError('The location provided does not exist')

    api = GithubAPI()

    file = api.get_file_blob(file_path='pac/pac.json', branch=ref)
    pac_json = json.loads(api.get_file_content(file_path='pac/pac.json', branch=ref))

    proxy = f'proxy.{loc.lower()}.medcity.net:80'

    orl_exceptions = [
        'hca.vigilanzportal.com',
        'www.schedulingexpress.com',
        'schedulingexpress.com',
        'hca.bedwatch.com',
        'www.clinicalpharmacology-ip.com',
        'clinicalpharmacology-ip.com'
    ]

    # Generate standard PAC file
    prx = f'"PROXY {proxy}"'

    data = ''
    data += 'function FindProxyForURL(url, host)\n'
    data += '{\n'
    data += '//PAC FILE\n'
    data += f'//Git Version {file.sha}\n'
    for y in range(len(pac_json)):
        section = next(x for x in pac_json if pac_json[x]['index'] == y)
        # data += '//{:=^75}\n'.format(f'  {section}  ')
        data += f'//   {section:=^75}   \n'
        for rule in pac_json[section]['rules']:
            if 'plainHost' in rule.keys():
                data += '\tif (isPlainHostName(host))  /*{}*/\n'.format(rule['comment'])
                if rule['directive'] == 'DIRECT':
                    data += '\t\treturn "DIRECT";\n'
                elif rule['directive'] == 'PROXY':
                    data += f'\t\treturn {prx};\n'
            else:
                data += '\tif (shExpMatch(host, "{}"))  /*{}*/\n'.format(rule['host_exp'], rule['comment'])
                if rule['directive'] == 'DIRECT':
                    data += '\t\treturn "DIRECT";\n'
                elif rule['directive'] == 'PROXY':
                    if proxy == 'proxy.orl.medcity.net:80':
                        if rule['host_exp'] in orl_exceptions:
                            data += '\t\treturn "PROXY proxy.nas.medcity.net:80";\n'
                        else:
                            data += f'\t\treturn {prx};\n'
                    else:
                        data += f'\t\treturn {prx};\n'

    data += f'//{"   Clean-Up Rule, everything else goes to the proxy   ":=^102}\n'
    data += f'return {prx};\n'
    data += '}'

    # Generate mobile PAC file
    prx = prx.replace('80', '9992')

    mobile_data = ''
    mobile_data += 'function FindProxyForURL(url, host)\n'
    mobile_data += '{\n'
    mobile_data += '//PAC FILE\n'
    mobile_data += f'//Git Version {file.sha}\n'
    for y in range(len(pac_json)):
        section = next(x for x in pac_json if pac_json[x]['index'] == y)
        mobile_data += f'//   {section:=^75}   \n'
        for rule in pac_json[section]['rules']:
            if 'plainHost' in rule.keys():
                mobile_data += '\tif (isPlainHostName(host))  /*{}*/\n'.format(rule['comment'])
                if rule['directive'] == 'DIRECT':
                    mobile_data += '\t\treturn "DIRECT";\n'
                elif rule['directive'] == 'PROXY':
                    mobile_data += f'\t\treturn {prx};\n'
            else:
                mobile_data += '\tif (shExpMatch(host, "{}"))  /*{}*/\n'.format(rule['host_exp'], rule['comment'])
                if rule['directive'] == 'DIRECT':
                    mobile_data += '\t\treturn "DIRECT";\n'
                elif rule['directive'] == 'PROXY':
                    if proxy == 'proxy.orl.medcity.net:80':
                        if rule['host_exp'] in orl_exceptions:
                            mobile_data += '\t\treturn "PROXY proxy.nas.medcity.net:9992";\n'
                        else:
                            mobile_data += f'\t\treturn {prx};\n'
                    else:
                        mobile_data += f'\t\treturn {prx};\n'

    mobile_data += f'//{"   Clean-Up Rule, everything else goes to the proxy   ":=^102}\n'
    mobile_data += f'return {prx};\n'
    mobile_data += '}'

    # Having issues with Ansible Workflow calling this multiple times per second because of GitHub
    # Because of this, it may be necessary to just return the data without writing it to a repo
    if mobile:
        print(f'Returning mobile data for {loc}')
        return mobile_data
    else:
        print(f'Returning data for {loc}')
        return data
