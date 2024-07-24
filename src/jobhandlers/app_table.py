from githubapi.utils import GithubAPI
from apic.utils import AppInstance
import logging
import yaml
import sys


# TODO: This process is too intense for Github, too many API calls and running into API rate-limit.  Find another
#  solution

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
    # Generate data to make retrieving AppInstance data and references faster.  DON'T store to Github
    application_data = []
    for application in gh.list_dir('applications'):
        for instance in gh.list_dir(f'applications/{application}'):
            logger.debug(f'Processing {application}/{instance}...')
            inst = AppInstance.load(f'{application}/{instance}')
            application_data += [
                dict(path=inst.path(),
                     epgDn=inst.epg_dn(),
                     networks=list(inst.networks.keys()),
                     instDn=inst.epg_dn(override=True))
            ]

    # Store application data
    if gh.file_exists('pyapis/appinst_index.yaml'):
        gh.update_file('pyapis/appinst_index.yaml', message='Updated data',
                       content=yaml.dump(application_data))
    else:
        gh.add_file('pyapis/appinst_index.yaml', message='Initial Creation',
                    content=yaml.dump(application_data))
    return


if __name__ == '__main__':
    logger.debug('Updating AppInstance index data')
    gh = GithubAPI()
    main()
