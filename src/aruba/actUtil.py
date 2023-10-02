import requests
import time


class pyACT(object):
    def __init__(self, pyact_user, pyact_pass, act_node='activate.arubanetworks.com', verify=True, disable_warnings=True, timeout=30):
        self.url_base = f'https://{act_node}'
        self.user_name = pyact_user
        self.user_pass = pyact_pass
        self.act = requests.session()
        self.act.verify = verify  # http://docs.python-requests.org/en/latest/user/advanced/#ssl-cert-verification
        self.disable_warnings = disable_warnings
        self.timeout = timeout
        self.act.headers.update({'Connection': 'keep_alive', 'Content-Type': 'application/json'})
        self.cookie_expiration = None
        self.act_cookie = None

        if self.disable_warnings:
            requests.urllib3.disable_warnings()

        try:
            self.getCookie()
            if self.act_cookie is None:
                raise Exception("Request for Login failed.")
        except Exception as e:
            print(e)
        else:
            self.cookie_expiration = time.time() + 3500

    def getCookie(self):
        try:
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            payload = f'credential_0={self.user_name}&credential_1={self.user_pass}'
            resp = self.act.post(f'{self.url_base}/LOGIN', data=payload, headers=headers)
            resp.raise_for_status()
        except Exception as e:
            print(e)
            return None
        else:
            self.cookie_expiration = time.time() + 3500
            self.act_cookie = resp.cookies
            return resp.cookies

    class Decorators():
        @staticmethod
        def refreshCookie(decorated):
            def wrapper(api, *args, **kwargs):
                if time.time() > api.cookie_expiration:
                    api.act_cookie = api.getCookie()
                return decorated(api, *args, **kwargs)

            return wrapper

    @Decorators.refreshCookie
    def get_folders(self):
        return self.act.post(f'{self.url_base}/api/ext/folder.json?action=queryFid')

    @Decorators.refreshCookie
    def get_folder_id(self, state):
        output = self.get_folders()
        for x in output.json()['folders']:
            if state in x['folderName'].lower():
                return x['id']

    @Decorators.refreshCookie
    def get_inventory(self, mac):
        payload = "json={\"devices\":[\"" + mac + "\"]}"
        return self.act.post(f'{self.url_base}/api/ext/inventory.json?action=query', data=payload)

    @Decorators.refreshCookie
    def get_inventory_serial(self, serialn):
        payload = "json={\"serialNumbers\":[\"" + serialn + "\"]}"
        return self.act.post(f'{self.url_base}/api/ext/inventory.json?action=query', data=payload)

    @Decorators.refreshCookie
    def post_inventory(self, device, folderid):
        payload = r'json={"updateDevices" : [{"mac": "' + device + '", "folder_id": "' + folderid + r'"}]}'
        return self.act.post(f'{self.url_base}/api/ext/inventory.json?action=update', data=payload)

