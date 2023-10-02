import concurrent.futures
import json
import os
import re
import smtplib

import cryptpandas as crp
import pandas as pd

from datetime import datetime
from ad.adUtil import pyAD
from ise.pyISE import ERS

pyise = ERS(ise_node='xrdclpmgtise01.hca.corpad.net', disable_warnings=True, timeout=60)
pyad = pyAD()

data = crp.read_encrypted(path='data/iPSKListv2.crypt', password=os.getenv('ipskcrypt'))
dataidg = None

# data = pd.read_excel(r'data/iPSKListv2.xlsm', sheet_name='PSK-DB')
# crp.to_encrypted(data, password=os.getenv('ipskcrypt'), path='data/iPSKListv2.crypt')

if dataidg == None:
    idg = pyise.get_endpointgroup_all(pages=0)
    dataidg = pd.DataFrame(idg['response'], columns=['Id Group', 'OID', 'Desc'])

def import_endpoint(row):
    idg = f"SWL-{row[3]}"
    idg_oid = dataidg[dataidg['Id Group'] == idg]['OID'].array[0]
    psk = data[data['Identity Group'] == row[3]][row[2]].array[0]
    vlan = data[data['Identity Group'] == row[3]]['vlan'].array[0]
    desc = f"{row[4]} {str(datetime.now())}"

    node = {"ERSEndPoint": {'name': row[1], 'description': desc, 'mac': row[1],
                            'groupId': idg_oid, 'staticGroupAssignment': 'true',
                            'customAttributes': {'customAttributes': {'iPSK': f"psk={psk}",
                                                                      'mPSK': psk,
                                                                      'iPSKDiv': row[2],
                                                                      'iPSKvlan': vlan}}
                            }
            }

    if row[0] == 'Add':
        respidg = pyise.post_endpoint_create_m(mac=row[1], data=node)
        if "already exists" in respidg['response']:
            resp_get = pyise.get_endpoint(mac=row[1])
            if resp_get['response']['staticGroupAssignment']:
                idgr = dataidg[dataidg['OID'] == resp_get['response']['groupId']]['Id Group'].array[0]
                try:
                    div = re.search(r'^\w+-(\w+)_\w+', idgr).group(1)
                except:
                    div = resp_get['response']['customAttributes']['customAttributes']['iPSKDiv']
                try:
                    idgn = re.search(r'\w+-\w+_(\w+.*)', idgr).group(1)
                except:
                    idgn = re.search(r'\w+-(\w+.*)', idgr).group(1)
                return f"{row[1]} is already part of {div} {idgn}."
            else:
                resp_put = pyise.put_endpoint_update(mac=row[1], oid=resp_get['response']['id'], data=node)
                if resp_put['success']:
                    return f"{row[1]} Added Successfully to {row[2]} {row[3]}"
        else:
            if respidg['success']:
                return f"{respidg['response']} to {row[2]} {row[3]}"
            else:
                return respidg['response']
    elif row[0] == 'Update':
        resp_get = pyise.get_endpoint(mac=row[1])
        if not resp_get['success'] or resp_get['response']['staticGroupAssignment'] is False:
            return f'{row[1]} not found. Update should only be used to overwrite an existing endpoint.'
        else:
            resp_put = pyise.put_endpoint_update(mac=row[1], oid=resp_get['response']['id'], data=node)
            if resp_put['success']:
                idgr = dataidg[dataidg['OID'] == resp_get['response']['groupId']]['Id Group'].array[0]
                try:
                    div = re.search(r'^\w+-(\w+)_\w+', idgr).group(1)
                except:
                    div = resp_get['response']['customAttributes']['customAttributes']['iPSKDiv']
                try:
                    idgn = re.search(r'\w+-\w+_(\w+.*)', idgr).group(1)
                except:
                    idgn = re.search(r'\w+-(\w+.*)', idgr).group(1)
                return f"{row[1]} Updated from {div} {idgn} to {row[2]} {row[3]} Successfully."
            else:
                return f"{resp_put['response']}"
    elif row[0] == 'Remove':
        resp = pyise.delete_endpoint(mac=row[1])
        return resp['response']


def ipsk_multi_add(Task: str, Div: str, idg: str, macaddr: str, UserID: str):
    data_rows = []
    f_results = []
    id_group = re.search(r'^(\w+.*)\s\|\s\w+', idg).group(1)
    list_mac = re.findall(r'[^,;\s\n]+', macaddr)
    receiver = None
    try:
        receiver = pyad.get_user_email(UserID).json()['email']
    except:
        pass
    if len(list_mac) > 500:
        msg = f"Bulk request for iPSK.<br><br> {Task}<br> {Div}<br> {id_group}<br> {list_mac}"
        status, e_result = email_notification(receiver=receiver, msg=msg, userid=UserID,
                                              subject='iPSK Janus Bulk Request')
        return status, e_result

    for item in list_mac:
        mac_test = pyise._mac_test(mac=item)
        item = mac_test['response']
        if mac_test['success']:
            data_rows.append([Task, item, Div, id_group, UserID])
        else:
            f_results.append(mac_test['response'])

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        results = [executor.submit(import_endpoint, row) for row in data_rows]

        for f in concurrent.futures.as_completed(results):
            f_results.append(f.result())

    msg = ""
    for x in f_results:
        msg += f"{x}<br>"
    status, e_result = email_notification(receiver=receiver, msg=msg, userid=UserID, subject='iPSK Janus Results')

    return status, e_result


def tscreds_lookup(ip, userid):
    output = pyise.get_netdevice(ip=ip)
    if not output['success']:
        return 404, output['response']
    elif 'trustsecsettings' in output['response']:
        location = output['response']['NetworkDeviceGroupList'][0]
        div = ise_div_lookup(location)
        status, auth = psk_lookup_auth(userid, div, acs=True)
        if status == 403:
            return 403, 'Unauthorized'
        device_id = output['response']['trustsecsettings']['deviceAuthenticationSettings']['sgaDeviceId']
        sga_pass = output['response']['trustsecsettings']['deviceAuthenticationSettings']['sgaDevicePassword']
        if 'Wireless Controller' in str(output['response']['NetworkDeviceGroupList']):
            resp = f"config cts device-id {device_id} password {sga_pass}"
        else:
            resp = f"cts credential id {device_id} password {sga_pass}"
    else:
        resp = 'Device is in ISE but not configured for Trustsec'
    return 200, resp


def wlcss_lookup(ip, userid):
    output = pyise.get_netdevice(ip=ip)
    if not output['success']:
        return 404, output['response']
    elif 'Wireless Controller' in str(output['response']['NetworkDeviceGroupList']):
        location = output['response']['NetworkDeviceGroupList'][0]
        div = ise_div_lookup(location)
        status, auth = psk_lookup_auth(userid, div, acs=True)
        if status == 403:
            return 403, 'Unauthorized'
        wlc_ss = output['response']['authenticationSettings']['radiusSharedSecret']
        return 200, wlc_ss
    else:
        resp = 'Device is in ISE but is not a Wireless Controller.'
        return 404, resp


def ipsk_div_list():
    divisions = data.columns[2:].values.tolist()
    return 200, divisions


def ipsk_idg_list(all=False, vlan=True):
    idg = []
    if all:
        idg = ['All']
    for index, row in data.iterrows():
        if not row.isnull().values[0] and row[0] != 'Migration':
            if vlan:
                idg.append(f"{row[0]} | {row[1]}")
            else:
                idg.append(row[0])
    return 200, idg


def ipsk_maclookup(mac):
    output = pyise.get_endpoint(mac=mac)
    if output['success'] and output['response']['staticGroupAssignment']:
        idgrp = pyise.get_endpointgroup(oid=output['response']['groupId'])
        try:
            div = re.search(r'^\w+-(\w+)_\w+', idgrp['response']['name']).group(1)
        except:
            div = output['response']['customAttributes']['customAttributes']['iPSKDiv']
        try:
            idg = re.search(r'^\w+-\w+_(\w+.*)', idgrp['response']['name']).group(1)
        except:
            idg = re.search(r'^\w+-(\w+.*)', idgrp['response']['name']).group(1)
        try:
            resp = f"{output['response']['mac']} is part of {div} {idg} - Added by {output['response']['description']}"
        except:
            resp = f"{output['response']['mac']} is part of {div} {idg}"
        return 200, resp
    elif output['success']:
        resp = f"{output['response']['mac']} is not in an Identity Group."
        return 200, resp
    elif not output['success']:
        resp = output['response']
        return 200, resp


def aruba_maclookup(mac):
    output = pyise.get_endpoint(mac=mac)
    if output['success'] and output['response']['staticGroupAssignment']:
        idgrp = pyise.get_endpointgroup(oid=output['response']['groupId'])
        if idgrp['response']['name'] == "SWL-ArubaRAP":
            resp = "Known"
            return 200, resp
    resp = "Unknown"
    return 200, resp


def psk_lookup(div: str, idg: str):
    if idg == 'All':
        div_sheet = pd.DataFrame(data, columns=['Identity Group', 'vlan', div])
        div_sheet.columns = ['Identity Group', 'vlan', 'PSK']
        for row in div_sheet.iterrows():
            if row[1].isnull().values[0]:
                div_sheet = div_sheet.drop(index=row[0])
            if row[1]['Identity Group'] == 'Migration':
                div_sheet = div_sheet.drop(index=row[0])
        results = div_sheet.to_json(orient='table', index=False)
        results = json.loads(results)['data']
        return 200, results
    else:
        psk = {
            'Identity Group': idg,
            'vlan': data[data['Identity Group'] == idg]['vlan'].array[0],
            'PSK': data[data['Identity Group'] == idg][div].array[0]
        }
        return 200, psk


def email_notification(receiver, msg, userid, subject):
    sender = 'corp.wireless@hcahealthcare.com'
    receivers = [receiver, 'corp.wireless@hcahealthcare.com']

    message = ("From: CORP Wireless <corp.wireless@hcahealthcare.com>\n"
               f"To: {', '.join(receivers)}\n"
               f"Subject: {subject}\n"
               "Content-Type: text/html\n"
               "\n"
               f"{msg}<br>"
               f"Requested by {userid}, {receiver}.  If you did not request this, please reply back to this email.")

    try:
        smtpObj = smtplib.SMTP('smtp-gw.nas.medcity.net')
        smtpObj.sendmail(sender, receivers, message)
        return 200, "Successfully sent email"
    except smtplib.SMTPException:
        return 500, "Error: unable to send email"


def psk_lookup_auth(userid, div, acs=False):
    groups = pyad.get_user_groups(userid)
    if groups.status_code == 200:
        groups = groups.json()['groups']
    else:
        return 403, 'Unauthorized'

    if acs:
        if 'CorpAppACSEnt1' in groups:
            return 200, "Authorized"
    if 'CORP-NET-DESIGN' in groups:
        return 200, "Authorized"
    if 'CORP-NET-REGIONAL' in groups:
        return 200, "Authorized"
    if 'CORP-NET-REGIONAL-UC' in groups:
        return 200, "Authorized"
    if div == 'CAP':
        if 'CPDV-TECH-NE' in groups:
            return 200, "Authorized"
    if div == 'COD':
        if 'CODV-TECH-NE' in groups:
            return 200, "Authorized"
    if div == 'CWT':
        if 'CWDV-TECH-NE' in groups:
            return 200, "Authorized"
    if div == 'EFL':
        if 'EFDV-TECH-NETWORK' in groups:
            return 200, "Authorized"
        if 'EFDVNetEng' in groups:
            return 200, "Authorized"
    if div == 'FWD':
        if 'FWDV-TECH-NETWORK' in groups:
            return 200, "Authorized"
    if div == 'GCD':
        if 'GCDV-TECH-NETWORK' in groups:
            return 200, "Authorized"
    if div == 'MAD':
        if 'MADV-TECH-NE' in groups:
            return 200, "Authorized"
    if div == 'MTN':
        if 'MTDV-TECH-NETWORK' in groups:
            return 200, "Authorized"
    if div == 'NCD':
        if 'NCDV-TECH-NE' in groups:
            return 200, "Authorized"
    if div == 'NFL':
        if 'NFDV-TECH-NE' in groups:
            return 200, "Authorized"
    if div == 'NTX':
        if 'NTDV-TECH-NE' in groups:
            return 200, "Authorized"
        if 'NTDV_Dept_Network and Voice Services_MODIFY' in groups:
            return 200, "Authorized"
    if div == 'SAN':
        if 'SADV-TECH-NETWORK' in groups:
            return 200, "Authorized"
    if div == 'SOD':
        if 'SATL-TECH-NE' in groups:
            return 200, "Authorized"
    if div == 'TRI':
        if 'TRDV-TECH-NE' in groups:
            return 200, "Authorized"
    if div == 'WFL':
        if 'WFDV-TECH-NE' in groups:
            return 200, "Authorized"
    if div == 'PSG':
        if 'PSG-TECH-NE' in groups:
            return 200, "Authorized"
    if div == 'ASD':
        if 'CORP-OPS-ASD-UC' in groups:
            return 200, "Authorized"

    return 403, 'Unauthorized'


def ise_div_lookup(location):
    if 'Corporate' in location:
        return 'COR'
    if 'Capital' in location:
        return 'CAP'
    if 'Continental' in location:
        return 'COD'
    if 'CWTexas' in location:
        return 'CWT'
    if 'EastFlorida' in location:
        return 'EFL'
    if 'FarWest' in location:
        return 'FWD'
    if 'GulfCoast' in location:
        return 'GCD'
    if 'MidAmerica' in location:
        return 'MAD'
    if 'Mountain' in location:
        return 'MTN'
    if 'NorthCarolina' in location:
        return 'NCD'
    if 'NorthFlorida' in location:
        return 'NFL'
    if 'NorthTexas' in location:
        return 'NTX'
    if 'SanAntonio' in location:
        return 'SAN'
    if 'SouthAtlantic' in location:
        return 'SOD'
    if 'TriStar' in location:
        return 'TRI'
    if 'WestFlorida' in location:
        return 'WFL'
    if 'ASD' in location:
        return 'ASD'
    return 'Unknown'
