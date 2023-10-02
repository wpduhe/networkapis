import requests
import time
import os
import base64


class pyAD(object):
    def __init__(self, ad_node='api-dev.internal.medcity.net', verify=True, disable_warnings=False, timeout=10):
        self.url_base = f'https://{ad_node}'
        self.ad = requests.session()
        self.ad.verify = verify  # http://docs.python-requests.org/en/latest/user/advanced/#ssl-cert-verification
        self.disable_warnings = disable_warnings
        self.timeout = timeout
        self.e_auth = os.getenv('EvolveDev')
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
            self.ad.headers.update(
                {'Authorization': f"Basic {base64.b64encode(self.e_auth.encode()).decode()}"})
            resp = self.ad.post(f'{self.url_base}/token?grant_type=client_credentials', headers=self.ad.headers,
                                timeout=self.timeout)
            resp.raise_for_status()
        except Exception as e:
            print(e)
            return None
        else:
            self.ad.headers.update({"Authorization": f"Bearer {resp.json()['access_token']}"})
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
    def get_group_membership(self, groupName):
        return self.ad.get(f'{self.url_base}/active-directory/oauth2/1.0.0/groups/{groupName}/membership')

    @Decorators.refreshToken
    def get_lawson_user(self, user34):
        return self.ad.get(f'{self.url_base}/active-directory/oauth2/1.0.0/lawson/user/{user34}')

    @Decorators.refreshToken
    def get_user(self, user34):
        return self.ad.get(f'{self.url_base}/active-directory/oauth2/1.0.0/user/{user34}/')

    @Decorators.refreshToken
    def get_user_manager(self, user34):
        return self.ad.get(f'{self.url_base}/active-directory/oauth2/1.0.0/user/{user34}/manager')

    @Decorators.refreshToken
    def get_user_email(self, user34):
        return self.ad.get(f'{self.url_base}/active-directory/oauth2/1.0.0/user/email?user34={user34}')

    @Decorators.refreshToken
    def get_user_groups(self, user34):
        return self.ad.get(f'{self.url_base}/active-directory/oauth2/1.0.0/user/groups?user34={user34}')

    @Decorators.refreshToken
    def get_user_thumbnail(self, user34):
        return self.ad.get(f'{self.url_base}/active-directory/oauth2/1.0.0/user/thumbnail?user34={user34}')

    @Decorators.refreshToken
    def get_verify_membership(self, user34, groupName):
        return self.ad.get(
            f'{self.url_base}/active-directory/oauth2/1.0.0/verify/membership?user34={user34}&groupName={groupName}')

