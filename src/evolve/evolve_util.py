import base64
import requests
import os
import time
from typing import ClassVar


class EvolveMarketplace:
    EVOLVE_PRD: ClassVar[str] = 'https://api.internal.medcity.net'
    EVOLVE_DEV: ClassVar[str] = 'https://api-dev.internal.medcity.net'

    def __init__(self, base_url: str=EVOLVE_PRD, verify: bool=True, timeout: int=10, dev: bool=False):

        self.base_url = (self.EVOLVE_DEV if dev else base_url)

        self.session = requests.session()
        self.session.verify = verify
        self.timeout = timeout
        self.e_auth = (os.getenv('EvolveDev') if dev else os.getenv('EvolvePrd'))
        self.access_token = None
        self.access_token_expiration = None

        try:
            self.access_token = self.__get_access_token()
            if self.access_token is None:
                raise Exception("Request for access token failed.")
        except Exception as e:
            print(e)
        else:
            self.access_token_expiration = time.time() + 3500

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tb):
        self.session.close()

    def __get_access_token(self):
        try:
            self.session.headers.update(
                {'Authorization': f"Basic {base64.b64encode(self.e_auth.encode()).decode()}"})
            resp = self.session.post(f'{self.base_url}/token?grant_type=client_credentials',
                                     headers=self.session.headers,
                                     timeout=self.timeout)
            resp.raise_for_status()
        except Exception as e:
            print(e)
            return None
        else:
            self.session.headers.update({"Authorization": f"Bearer {resp.json()['access_token']}"})
            return resp.json()['access_token']

    class Decorators:
        @staticmethod
        def refresh_token(decorated):
            def wrapper(api, *args, **kwargs):
                if time.time() > api.access_token_expiration:
                    api.access_token = api.__get_access_token()
                return decorated(api, *args, **kwargs)

            return wrapper

    @Decorators.refresh_token
    def get(self, uri: str) -> requests.Response:
        if not uri.startswith('/'):
            uri = f'/{uri}'
        return self.session.get(f'{self.base_url}{uri}')

    @Decorators.refresh_token
    def post(self, uri: str, data: dict) -> requests.Response:
        if not uri.startswith('/'):
            uri = f'/{uri}'
        return self.session.post(f'{self.base_url}{uri}', json=data)

    @Decorators.refresh_token
    def put(self, uri: str, data: dict) -> requests.Response:
        if not uri.startswith('/'):
            uri = f'/{uri}'
        return self.session.put(f'{self.base_url}{uri}', json=data)

    @Decorators.refresh_token
    def delete(self, uri: str, data: dict) -> requests.Response:
        if not uri.startswith('/'):
            uri = f'/{uri}'
        return self.session.delete(f'{self.base_url}{uri}', json=data)
