from githubapi.utils import GithubAPI
from apic.utils import AppInstance
import logging
import yaml
import sys


formatter = logging.Formatter(fmt='%(asctime)s.%(msecs)03dZ - %(name)s - %(levelname)s - %(message)s',
                              datefmt='%Y-%m-%dT%H:%M:%S')

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
handler.setFormatter(formatter)

logging.basicConfig(level=logging.DEBUG, handlers=[handler])
logger = logging.getLogger(__name__)

logging.getLogger('urllib3').setLevel(logging.WARNING)
logging.getLogger('github').setLevel(logging.WARNING)


def main():
    # TODO: Write this function to create an array of AppInstances and some of their key properties for lookup and
    #  identification purposes
    application_data = []
    for application in gh.list_dir('applications'):
        for instance in gh.list_dir(f'applications/{application}'):
            inst = AppInstance.load(f'{application}/{instance}')
            application += [
                dict(path=inst.path(),
                     epgDn=inst.epg_dn(),
                     networks=list(inst.networks.keys()),
                     instDn=inst.epg_dn(override=True))
            ]

    # Store application data
    if gh.file_exists('pyapis/application_data.yaml'):
        gh.update_file('pyapis/application_data.yaml', message='Updated data',
                       content=yaml.dump(application_data))
    else:
        gh.add_file('pyapis/application_data.yaml', message='Initial Creation',
                    content=yaml.dump(application_data))
    return


if __name__ == '__main__':
    gh = GithubAPI()
    main()
