import os
import time
import base64
from github import Github, GithubObject
from github.GithubException import UnknownObjectException, GithubException


class GithubAPI:
    def __init__(self, access_token: str=None, repo: str=None):
        if access_token:
            self.gh = Github(login_or_token=access_token)
        else:
            self.gh = Github(os.getenv('githubaccesstoken'))

        if repo:
            self.repo = next(repo for repo in self.gh.get_user().get_repos() if repo.full_name == repo)
        else:
            self.repo = next(repo for repo in self.gh.get_user().get_repos()
                             if repo.full_name == 'HCANetworkServices/Network_APIs_Data')

        # print(f'Repository set to {self.repo.full_name}')

    def set_repo(self, repo: str):
        self.repo = next(set_repo for set_repo in self.gh.get_user().get_repos() if set_repo.name == repo)

    def file_exists(self, file_path, branch=GithubObject.NotSet):
        try:
            self.repo.get_contents(file_path, ref=branch)
            return True
        except UnknownObjectException:
            return False
        except GithubException:
            return False

    def get_file_blob(self, file_path, branch=GithubObject.NotSet):
        # Process to retrieve file from Git regardless of size
        file_name = file_path.split('/')[-1]
        file_path = '/'.join(file_path.split('/')[:-1])

        path_contents = self.repo.get_contents(path=file_path, ref=branch)
        file = next(o for o in path_contents if o.name == file_name)

        file = self.repo.get_git_blob(file.sha)

        return file

    def add_file(self, file_path: str, message: str, content: str, branch=GithubObject.NotSet):
        """Creates a new file at the specified path.  Directories are created automatically"""
        if self.file_exists(file_path=file_path):
            raise Exception('The file already exists.  Select a new file name or update the existing file.')
        self.repo.create_file(path=file_path, message=message, content=content, branch=branch)
        return None

    def get_file_content(self, file_path: str, branch=GithubObject.NotSet):
        """
        Returns the contents of the specified file as a string
        :param file_path: str
        :param branch: str
        :return:
        :rtype: str
        """
        file = self.get_file_blob(file_path=file_path, branch=branch)

        # Contents of the file are base64 encoded
        file_contents = base64.b64decode(file.content).decode()
        return file_contents

    def update_file(self, file_path: str, message: str, content, branch=GithubObject.NotSet):
        file = self.get_file_blob(file_path=file_path, branch=branch)

        self.repo.update_file(path=file_path, message=message, content=content, sha=file.sha, branch=branch)
        return None

    def append_to_file(self, file_path: str, message: str, new_content, branch=GithubObject.NotSet):
        """Appends new content to a new line in the specified file"""
        file = self.get_file_blob(file_path=file_path, branch=branch)
        old_content = base64.b64decode(file.content).decode()
        content = f'{old_content}\n{new_content}'
        self.update_file(file_path=file_path, message=message, content=content, branch=branch)
        return None

    def prepend_to_file(self, file_path: str, message: str, new_content, branch=GithubObject.NotSet):
        """Appends new content to a new line in the specified file"""
        file = self.get_file_blob(file_path=file_path, branch=branch)
        old_content = base64.b64decode(file.content).decode()
        if not new_content.endswith('\n'):
            new_content += '\n'
        content = f'{new_content}{old_content}'
        self.update_file(file_path=file_path, message=message, content=content, branch=branch)
        return None

    def delete_file(self, file_path: str, message: str, branch=GithubObject.NotSet):
        file = self.get_file_blob(file_path=file_path, branch=branch)
        self.repo.delete_file(path=file_path, message=message, sha=file.sha, branch=branch)
        return None

    def move_file(self, file_path: str, new_file_path: str, branch=GithubObject.NotSet):
        # Retrieve file contents
        file_content = self.get_file_content(file_path=file_path, branch=branch)

        try:
            self.delete_file(file_path=file_path, message='deleted', branch=branch)
        except:
            raise GithubException(status=500, data='', headers=None)

        try:
            self.add_file(file_path=new_file_path, message='moved', content=file_content, branch=branch)
        except:
            self.add_file(file_path=file_path, message='Move Failed', content=file_content, branch=branch)

        return None

    def list_dir(self, directory_path: str='', branch=GithubObject.NotSet):
        try:
            return [directory.name for directory in self.repo.get_contents(directory_path, ref=branch)]
        except UnknownObjectException:
            return None

    def merge(self):
        pr = self.repo.create_pull(title='Pull Request for pilot to main', body='Merge changes to pilot into main',
                                   base='main', head='pilot')
        time.sleep(1)
        pr.merge()
