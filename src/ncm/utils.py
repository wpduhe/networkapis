from ncm_sdk import NcmService
from datetime import datetime
import urllib3
import os


urllib3.disable_warnings()


class NCMIntegration:
    def __init__(self, username: str=None, password: str=None):
        self.url = 'https://xrdclpappncm11.unix.medcity.net:8880/ncm-webapp/services/ApiService'
        if username and password:
            self.ncm = NcmService(self.url, username=username, password=password)
        else:
            self.ncm = NcmService(self.url, username=os.getenv('netmgmtuser'), password=os.getenv('netmgmtpass'))

    def get_snmp_strings(self, trusted: bool=True):
        now = datetime.now()
        snmp_creds = self.ncm.get_credential(name=f'hca-{now.year}-1-{("Trusted" if trusted else "Untrusted")}')
        if not snmp_creds:
            snmp_creds = self.ncm.get_credential(name=f'hca-{now.year - 1}-1-{("Trusted" if trusted else "Untrusted")}')
        return {'ro': snmp_creds['readOnly'], 'rw': snmp_creds['readWrite']}

    @classmethod
    def w_get_snmp_strings(cls, trusted: bool=True):
        ncm = cls()
        return 200, ncm.get_snmp_strings(trusted=trusted)
