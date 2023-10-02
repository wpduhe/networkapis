import sys
import netmiko
import os


def wlc_power(ip):
    current_device = {
        'host': ip,
        'username': os.getenv('netmgmtuser'),
        'password': os.getenv('netmgmtpass'),
        'device_type': 'cisco_wlc',
        'banner_timeout': 8
    }

    dbmlist = []
    dbmulist = []
    chalist = []
    chblist = []
    dbmlistb = []
    dbmulistb = []
    chaulist = []
    chbulist = []
    response = []

    try:
        net_conn = netmiko.ConnectHandler(**current_device)
    except:
        return 404, f"Exception {sys.exc_info()[0]}"

    fra = net_conn.send_command('show advanced fra', use_textfsm=True)
    response.append(f"{'FRA State:':20}{fra[0]['fra_state']:20}")
    minmax = net_conn.send_command('show advanced 802.11a txpower', use_textfsm=True)
    minmaxb = net_conn.send_command('show advanced 802.11b txpower', use_textfsm=True)
    response.append(f"{'Max Power A:':20}{minmax[0]['max_power']:20}")
    response.append(f"{'Min Power A:':20}{minmax[0]['min_power']:20}")
    response.append(f"{'Max Power B:':20}{minmaxb[0]['max_power']:20}")
    response.append(f"{'Min Power B:':20}{minmaxb[0]['min_power']:20}")
    response.append(f"{'Threshold A:':20}{minmax[0]['threshold']:20}")
    response.append(f"{'Threshold B:':20}{minmaxb[0]['threshold']:20}")

    output = net_conn.send_command('show advanced 802.11a summary', use_textfsm=True)
    outputb = net_conn.send_command('show advanced 802.11b summary', use_textfsm=True)

    for x in output:
        if str(x['channel']) == "(Monitor)":
            x['txpowerdbm'] = "Monitor"
        elif x['admin'] == "DISABLED":
            x['txpowerdbm'] = "Disabled"
        elif x['oper'] == "DOWN":
            x['txpowerdbm'] = "Down"
        dbmlist.append(x['txpowerdbm'])
        chalist.append(x['channel'])

    for x in outputb:
        if str(x['channel']) == "(Monitor)":
            x['txpowerdbm'] = "Monitor"
        elif x['admin'] == "DISABLED":
            x['txpowerdbm'] = "Disabled"
        elif x['oper'] == "DOWN":
            x['txpowerdbm'] = "Down"
        dbmlistb.append(x['txpowerdbm'])
        chblist.append(x['channel'])

    dbmlist.sort()
    dbmlistb.sort()

    for x in dbmlist:
        if x not in dbmulist:
            dbmulist.append(x)

    for x in dbmlistb:
        if x not in dbmulistb:
            dbmulistb.append(x)

    response.append('A Radios')

    for x in dbmulist:
        response.append(f'{x}: {dbmlist.count(x)} APs')

    response.append('B Radios')

    for x in dbmulistb:
        response.append(f'{x}: {dbmlistb.count(x)} APs')

    chalist.sort()
    chblist.sort()

    for x in chalist:
        if x not in chaulist:
            chaulist.append(x)

    for x in chblist:
        if x not in chbulist:
            chbulist.append(x)

    response.append('A Channels')

    for x in chaulist:
        response.append(f'{x}: {chalist.count(x)} APs')

    response.append('B Channels')

    for x in chbulist:
        response.append(f'{x}: {chblist.count(x)} APs')

    net_conn.disconnect()
    return 200, response
