#!/usr/bin/env python

import urllib3
from apic.utils import APIC, MAC_IP_SEARCH
import requests
import json
import ssl
import logging
from websockets.sync.client import connect
from types import SimpleNamespace
import threading
import time
import sys
import os


# config logging with GMT time stamps and a stream handler.
logging.Formatter.converter = time.gmtime
formatter = logging.Formatter(fmt='%(asctime)s.%(msecs)03dZ - %(name)s - %(levelname)s - %(message)s',
                              datefmt='%Y-%m-%dT%H:%M:%S')

ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
ch.setFormatter(formatter)

logging.basicConfig(level=logging.DEBUG, handlers=[ch])  # ensures root logger is set to DEBUG
logger = logging.getLogger(__name__)

# Suppress annoying logging from libraries below
logging.getLogger('websockets').setLevel(logging.WARNING)


urllib3.disable_warnings()

# Ensure using python3
if sys.version_info[0] < 3:
    raise Exception("Must be using Python 3")


OMIT = ['parallon-dev', 'drdc']

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE


def w_socket():
    # This module starts the initial connect to the APIC Web Socket
    # websocket_url = "wss://" + APIC + "/socket{}".format(token)
    global sockets
    sockets = [(_, connect(f'wss://{_.ip}/socket{_.session.cookies.get("APIC-cookie")}', ssl_context=ctx))
               for _ in fabrics]
    # ws = websocket.create_connection(websocket_url, sslopt={"cert_reqs": ssl.CERT_NONE})
    # print("WebSocket Subscription Status Code: ", ws.status)

    # print (type(ws))
    # return ws


def subscribe():
    global fvip_subscription_ids

    # subscribe to fvIp
    resps = [_.get('/api/class/fvIp.json?subscription=yes&refresh-timeout=60') for _ in fabrics]
    fvip_subscription_ids = [_.json()['subscriptionId'] for _ in resps]


def printws():
    while True:
        for fabric, socket in sockets:
            try:
                ips = socket.recv(timeout=2)

                if isinstance(ips, str):
                    ip = json.loads(ips, object_hook=lambda x: SimpleNamespace(**x))
                    for i in ip.imdata:
                        if i.fvIp.attributes.status == 'deleted':
                            continue
                        elif i.fvIp.attributes.status == 'created':
                            mac, ip = MAC_IP_SEARCH.search(i.fvIp.attributes.dn).groups()
                            logger.info(f'{fabric.env.Name}: Endpoint Add/Update: {mac} with IP address {ip}')
                        else:
                            continue
            except TimeoutError:
                continue


def refresh():
    # This module refreshes the subscription.  Default Timeout for refresh is 60 seconds as also hardcoded in the
    # subscription module "refresh-timeout=60"
    while True:
        time.sleep(30)
        for index, e in enumerate(fabrics):
            _ = e.get(f'/api/subscriptionRefresh.json?id={fvip_subscription_ids[index]}')


def start_thread():
    th = threading.Thread(target=printws)
    th1 = threading.Thread(target=refresh)
    th.start()
    th1.start()


if __name__ == "__main__":
    fabrics = [APIC(env=_, username=os.getenv('netmgmtuser'), password=os.getenv('netmgmtpass'))
               for _ in requests.get('https://pyapis.ocp.app.medcity.net/apis/aci/environment_list',
                                          verify=False).json() if _.lower() not in OMIT]
    print("\n" * 2)
    print("*" * 10, "WebSocket Subscription Status & Messages", "*" * 10)
    w_socket()
    subscribe()
    start_thread()
