import requests
import time

class pyCP(object):
    def __init__(self, pycp_user, pycp_pass, cp_node='naxdc-cppm-1-f-h.xdc.na.mgmt.medcity.net:443/api', verify=False,
                 disable_warnings=True, timeout=10):
        self.url_base = f'https://{cp_node}'
        self.user_name = pycp_user
        self.user_pass = pycp_pass

        self.cp = requests.session()
        self.cp.verify = verify  # http://docs.python-requests.org/en/latest/user/advanced/#ssl-cert-verification
        self.disable_warnings = disable_warnings
        self.timeout = timeout
        self.cp.headers.update({'Connection': 'keep_alive', "Accept": "application/json",
                                "Content-Type": "application/json"})
        self.access_token = None
        self.access_token_expiration = None

        if self.disable_warnings:
            requests.urllib3.disable_warnings()

        try:
            self.access_token = self.getAccessToken()
            if self.access_token is None:
                raise Exception("Request for access token failed.")
        except Exception as e:
            print(e)
        else:
            self.access_token_expiration = time.time() + 3500

    def getAccessToken(self):
        try:
            payload = {
                "client_id": self.user_name,
                "client_secret": self.user_pass,
                "grant_type": "client_credentials"
            }
            resp = self.cp.post(f'{self.url_base}/oauth', headers=self.cp.headers,
                                json=payload, timeout=self.timeout)
            resp.raise_for_status()
        except Exception as e:
            print(e)
            return None
        else:
            self.cp.headers.update({"Authorization": f"Bearer {resp.json()['access_token']}"})
            return resp.json()['access_token']

    class Decorators():
        @staticmethod
        def refreshToken(decorated):
            def wrapper(api, *args, **kwargs):
                if time.time() > api.access_token_expiration:
                    api.access_token = api.getAccessToken()
                return decorated(api, *args, **kwargs)

            return wrapper

    @Decorators.refreshToken
    def get_endpoint_mac(self, mac_address):
        return self.cp.get(f'{self.url_base}/endpoint/mac-address/{mac_address}')

    @Decorators.refreshToken
    def patch_endpoint_mac(self, mac_address, status):
        payload = {
            "mac_address": f"{mac_address}",
            "description": "Updated by ibm6580 - Workaround",
            "status": f"{status}"
        }
        return self.cp.patch(f'{self.url_base}/endpoint/mac-address/{mac_address}', json=payload)

    @Decorators.refreshToken
    def post_endpoint_mac(self, mac_address, status):
        payload = {
            "mac_address": f"{mac_address}",
            "description": "Updated by ibm6580 - Workaround",
            "status": f"{status}"
        }
        return self.cp.post(f'{self.url_base}/endpoint', json=payload)