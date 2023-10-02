from bs4 import BeautifulSoup
from xml.etree import ElementTree
import requests
import re
import os


class WSA:
    def __init__(self, host: str, username: str=None, password: str=None):
        self.url = f'https://{host}:8443'
        self.session = requests.session()
        self.session.verify = False
        resp = self.session.get(self.url)
        soup = BeautifulSoup(resp.text)

        form = soup.form
        form = ElementTree.fromstring(str(form))
        referrer = form.find('input/[@name="referrer"]')
        screen = form.find('input/[@name="screen"]')
        csrf_key = form.find('input/[@name="CSRFKey"]')

        self.loginData = {
            'action': 'Login',
            'username': (username if username else os.getenv('netmgmtuser')),
            'password': (password if password else os.getenv('netmgmtpass')),
            'action_type': 'ajax_validation',
            'referrer': referrer.attrib['value'],
            'screen': screen.attrib['value'],
            'CSRFKey': csrf_key.attrib['value']
        }

        self.session.headers['X-Requested-With'] = 'XMLHttpRequest'
        _ = self.session.post(f'https://{host}:8443/login', data=self.loginData)
        del self.loginData['action_type']
        _ = self.session.post(f'https://{host}:8443/login', data=self.loginData)

        # Obtain Session CSRFKey for filling out forms
        resp = self.session.get('{}/system_administration/configuration/configuration_file'.format(self.url))
        self.csrfkey = re.search('CSRFKey=[a-z0-9-]+', resp.text).group()[8:]

    def get(self, path):
        return self.session.get('{url}{path}'.format(url=self.url, path=path))

    def deploy_routes(self):
        files = {
            'action': (None, 'Import'),
            'interface_type': (None, 'Data'),
            'screen': (None, 'network.routes'),
            # 'subTitle': (None, x), # Need to acquire form subTitle; Going to attempt to omit
            'file': ('routes.dat', open('routes.dat', 'r').read(), 'application/octet-stream'),
            'CSRFKey': (None, self.csrfkey)
        }

        load_resp = self.session.post('{}/network/routes'.format(self.url), files=files)

        commit_post = {
            'action': 'Commit',
            'screen': 'commit',
            'logout': '',
            'comment': '',
            'CSRFKey': self.csrfkey
        }

        commit_resp = self.session.post('{}/commit'.format(self.url), data=commit_post)

        return {
            'route_load_response': {
                'status': load_resp.status_code,
                'reason': load_resp.reason
            },
            'commit_response': {
                'status': commit_resp.status_code,
                'reason': commit_resp.reason
            }
        }

    def upload_certs(self):
        file1 = {
            'action': (None, 'ImportRootCACertificate'),
            # 'subTitle': (None, x), # Need to acquire form subTitle; Going to attempt to omit
            'certificate': ('HCA Internal Root CA.crt', open('../pyapis/wsa/HCA Internal Root CA.crt', 'r').read(),
                            'application/x-x509-ca-cert'),
            'CSRFKey': (None, self.csrfkey)
        }

        file2 = {
            'action': (None, 'ImportRootCACertificate'),
            # 'subTitle': (None, x), # Need to acquire form subTitle; Going to attempt to omit
            'certificate': ('HCA Internal Issuing CA 03.crt',
                            open('../pyapis/wsa/HCA Internal Issuing CA 03.crt', 'r').read(),
                            'application/x-x509-ca-cert'),
            'CSRFKey': (None, self.csrfkey)
        }

        self.session.get('{}/network/cert/cert_management'.format(self.url))

        upload1_resp = self.session.post('{}/network/cert/cert_management'.format(self.url), files=file1)
        upload2_resp = self.session.post('{}/network/cert/cert_management'.format(self.url), files=file2)

        commit_post = {
            'action': 'Commit',
            'screen': 'commit',
            'logout': '',
            'comment': '',
            'CSRFKey': self.csrfkey
        }

        commit_resp = self.session.post('{}/commit'.format(self.url), data=commit_post)

        return {
            'Root CA': {
                'status': upload1_resp.status_code,
                'reason': upload1_resp.reason,
                'body': upload1_resp.text
            },
            'Issuing CA 03': {
                'status': upload2_resp.status_code,
                'reason': upload2_resp.reason,
                'body': upload2_resp.text
            },
            'commit_response': {
                'status': commit_resp.status_code,
                'reason': commit_resp.reason,
                'body': commit_resp.text
            }
        }

    def logout(self):
        return self.session.get('{}/login?action=Logout'.format(self.url))
