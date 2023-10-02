def getNexusEnvironments(env=''):
    data = [
            {
                'name': 'XRDC-AG1',
                'l3switch1': '10.29.244.12',
                'l3switch2': '10.29.244.13',
                'Subnets': ['10.26.0.0/15'],
                'vrfs': ['bbc', 'hca', 'hcadr', 'hpg', 'par'],
                'ospfArea': ['10.26.0.0'],
                'ospfID': ['1'],
                'vlanRange': (x for x in range(50, 2000)),
                'dhcpRelay': ['10.26.31.125', '10.90.10.125'],
                'ASN': '65500',
                'COID': '99934',
                'aciPhysDomain': 'phy-dom-AG1',
                'aciAEP': 'aep-XRDC-AG1'
            }, {
                'name': 'XRDC-AG2',
                'l3switch1': '10.29.244.52',
                'l3switch2': '10.29.244.53',
                'Subnets': ['10.230.0.0/15', '10.232.0.0/16', '10.248.0.0/16', '10.249.0.0/16'],
                'vrfs': ['bbc', 'drtest', 'hca', 'hcadr', 'hpg', 'par', 'pcld'],
                'ospfArea': '10.230.0.0',
                'ospfID': '1',
                'vlanRange': (x for x in range(2001, 4095)),
                'dhcpRelay': ['10.26.31.125', '10.90.10.125'],
                'ASN': '65500',
                'COID': '99934',
                'aciPhysDomain': 'phy-dom-AG2',
                'aciAEP': 'aep-XRDC-AG2'
            }, {
                'name': 'FRDC-AG1',
                'l3switch1': '10.64.255.76',
                'l3switch2': '10.64.255.77',
                'Subnets': ['10.64.0.0/16', '10.90.0.0/16', '10.94.0.0/15'],
                'vrfs': ['drtest'],
                'ospfArea': '10.64.0.0',
                'ospfID': '1',
                'vlanRange': (x for x in range(50, 2000)),
                'dhcpRelay': ['10.90.10.125', '10.226.21.12'],
                'ASN': '65501',
                'COID': '99927',
                'aciPhysDomain': 'phy-dom-AG1',
                'aciAEP': 'aep-FRDC-AG1'
            }, {
                'name': 'FRDC-AG2',
                'l3switch1': '10.64.255.78',
                'l3switch2': '10.64.255.79',
                'Subnets': ['10.90.0.0/16', '10.94.0.0/15'],
                'vrfs': ['drtest'],
                'ospfArea': '10.94.0.0',
                'ospfID': '1',
                'vlanRange': (x for x in range(2001, 4094)),
                'dhcpRelay': ['10.90.10.125', '10.226.21.12'],
                'ASN': '65501',
                'COID': '99927',
                'aciPhysDomain': 'phy-dom-AG2',
                'aciAEP': 'aep-FRDC-AG2'
            }, {
                'name': 'QOL',
                'l3switch1': '10.28.12.2',
                'l3switch2': '10.28.12.3',
                'Subnets': ['10.28.0.0/19'],
                'vrfs': ['hca'],
                'ospfArea': '10.28.0.0',
                'ospfID': '1',
                'vlanRange': (x for x in range(50, 4095)),
                'ASN': '65500',
                'COID': '99934',
                'aciPhysDomain': 'phy-dom-Test',
                'aciAEP': 'aep-Migrate-Test'
            }, {
                'name': 'DRDC',
                'l3switch1': '10.224.96.8',
                'l3switch2': '10.227.96.9',
                'Subnets': ['10.224.0.0/17'],
                'vrfs': ['bbc', 'drtest', 'hca', 'hcadr'],
                'ospfArea': '10.224.0.0',
                'ospfID': '1',
                'vlanRange': (x for x in range(50, 4095)),
                'dhcpRelay': ['10.224.90.49'],
                'ASN': '65506',
                'COID': '99933'
            }
        ]

    if env != '':
        try:
            data = next(x for x in data if x['name'] == env)
        except StopIteration:
            return 'Environment Not Defined'
    return data
