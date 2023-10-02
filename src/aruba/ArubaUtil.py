from aruba.cpUtil import pyCP
from aruba.actUtil import pyACT
from ise.iseUtil import aruba_maclookup
import re
import os

pyact = pyACT(pyact_user=os.getenv('ArubaActu'), pyact_pass=os.getenv('ArubaActp'))
pycp = pyCP(pycp_user=os.getenv('ArubaCPu'), pycp_pass=os.getenv('ArubaCPp'))

state_id = pyact.get_folders()

def mac_test(mac):
    """
    Test for valid mac address
    :param mac: MAC address
    :return: MAC Addr/Error
    """
    result = {
        'success': False,
        'response': mac,
        'error': ''
    }

    mac = re.sub('[.:-]', '', mac).upper()
    mac = ''.join(mac.split())
    if re.search(r'([0-9A-F]{12})', mac) is not None and len(mac) == 12:
        mac = ":".join(["%s" % (mac[i:i + 2]) for i in range(0, 12, 2)])
        result['success'] = True
        result['response'] = mac
        return result
    else:
        result['response'] = f"{result['response']} Invalid MAC Address"
        result['error'] = "Invalid MAC Address"
        return result

def get_rap_status(device=None):
    if device is None:
        return 500, "Mac Address or Serial Number is required"

    rap_data = {
        'Mac': '',
        'Serial': '',
        'Activate Status': '',
        'State': '',
        'Clearpass Status': 'Unknown',
        'ISE Status': 'Unknown'
    }

    mac = mac_test(device)
    if mac['success']:
        mac = mac['response']
        rap = pyact.get_inventory(mac)
    else:
        rap = pyact.get_inventory_serial(device)

    if rap.status_code == 200:
        if rap.json()['totalCount'] == 1:
            rap_data['Mac'] = rap.json()['devices'][0]['mac']
            rap_data['Serial'] = rap.json()['devices'][0]['serialNumber']
            rap_data['Activate Status'] = rap.json()['devices'][0]['status']
            rap_data['State'] = rap.json()['devices'][0]['additionalData']['folder']
    else:
        return 500, "Mac Address or Serial Number is not found."

    cp_status = pycp.get_endpoint_mac(rap_data['Mac'])
    if cp_status.status_code == 200:
        rap_data['Clearpass Status'] = cp_status.json()['status']

    ise_status, ise_results = aruba_maclookup(rap_data['Mac'])
    if ise_status == 200:
        rap_data['ISE Status'] = ise_results

    # msg = f"Mac: {rap_data['mac']}\n Serial: {rap_data['serial']}\n Activate Status: {rap_data['status']}\n State Assigned: {rap_data['state']}\n Clearpass Status: {rap_data['cp_status']}"

    return 200, rap_data

def add_rap(mac, state):
    folderid = ""
    mac = mac_test(mac)
    if mac['success']:
        mac = mac['response']

    for x in state_id.json()['folders']:
        if state.lower() in x['folderName'].lower():
            folderid = x['id']

    outputcp = pycp.patch_endpoint_mac(mac_address=mac, status='Known')
    try:
        if outputcp.json()['title'] == 'Not Found':
            outputcp = pycp.post_endpoint_mac(mac_address=mac, status='Known')
    except:
        pass
    if outputcp.status_code == 200:
        print(f'Success clearpass on {mac}, {state}, {folderid}')
    elif outputcp.status_code == 201:
        print(f'Success clearpass on {mac}, {state}, {folderid}')
    else:
        print(f'Failed clearpass on {mac}, {state}, {folderid}')

    outputact = pyact.post_inventory(device=mac, folderid=folderid)
    if outputact.status_code == 200:
        print(f'Success activate on {mac}, {state}, {folderid}')
    else:
        print(f'Failed activate on {mac}, {state}, {folderid}')
