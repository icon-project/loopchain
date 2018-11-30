# Copyright 2018 ICON Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""A module for managing Score"""

# This file is obsolete.

import os
import os.path as osp
import shutil
import stat
import zipfile

from git import Repo, Git, GitCmdObjectDB
from git.repo.fun import is_git_dir

from loopchain.blockchain import *
from loopchain.utils import get_valid_filename

logger = logging.getLogger("git")
logger.setLevel(logging.WARNING)


class PeerScore:
    """
    Score를 관리하는 모듈
    """

    def __init__(self,
                 repository_path=conf.DEFAULT_SCORE_REPOSITORY_PATH,
                 score_package=conf.DEFAULT_SCORE_PACKAGE,
                 base=conf.DEFAULT_SCORE_BASE):
        """
        Score 관리모듈 생성자

        :param base: Score Repository 주소
        :param score_package: score 패키지명
        """

        self.__score_base = None
        self.__score_package = None
        self.__scores = {}
        self.__current_version = ''
        self.__score_versions = []
        self.__repository_path = None
        self.__package_path = None
        self.__package_repository = None

        logging.debug('Peer Score Manager : '+repository_path + ' [' + score_package + ']')
        self.__score_base = base
        self.__score_package = score_package
        # check if exist peer_score repository path
        self.__repository_path = osp.abspath(repository_path)

        # package 를 로드
        self.__package_path = osp.join(self.__repository_path, self.__score_package)
        self.load_package()

        # score repository check
        self.__current_version = self.last_version()
        self.score_version(self.__current_version)

    def __str__(self):
        return "SCORE Manager " + self.__score_package + "(" + self.__current_version + ")"

    def id(self):
        return self.__score_package

    def version(self):
        return self.__current_version

    def load_package(self):
        """load SCORE package

        :return:
        """
        is_loaded = False
        logging.debug(f"Package Path : {self.__package_path}")

        # Check Develop Score Package
        if self.__score_package.split('/')[0] == conf.DEVELOP_SCORE_PACKAGE_ROOT and conf.ALLOW_LOAD_SCORE_IN_DEVELOP:
            # 개발 중인 score 를 git 또는 zip 배포 없이 로드를 허용한 경우 폴더 경로를 지정하여 score 를 로드 할 수 있게 한다.
            logging.debug("try load develop score repository")
            self.init_package_in_develop()
            is_loaded = self.load_package_by_local_repository()

        # Check Path Exist
        if osp.exists(self.__package_path):
            logging.debug("try load local repository")
            # 해당 위치가 있으면 해당 위치를 로드
            is_loaded = self.load_package_by_local_repository()

        # Check package file ex) score_package...zip
        if is_loaded is False:
            logging.debug("try load local package file")
            # 해당 위치가 없으면, 일단 파일로 로드를 시도
            # 없다면 리모트 리파지토리에서 패키지를 로드
            is_loaded = self.load_package_by_file()

        # Check remote
        if is_loaded is False:
            logging.debug("try load remote repository")
            # 해당 위치도 없고 파일도 없으면 리모트 리파지토리에서 패키지를 로드
            is_loaded = self.load_package_by_remote()

        if is_loaded is False:
            logging.debug("load package fail")
            # 해당 아이디의 패키지 로드 실패
            raise FileNotFoundError()

        # 로드된 패키지의 버젼을 저장
        self.__list_versions()

    def __list_versions(self):
        """
        Score의 리파지토리에 저장된 버젼들을 확인

        :return:
        """
        self.__score_versions = self.__package_repository.git.rev_list(conf.DEFAULT_SCORE_BRANCH).split()
        logging.debug('Last Score Version :'+str(self.__score_versions[0]))

    def init_package_in_develop(self):
        # delete .git if exist
        os.system("rm -rf " + osp.join(self.__package_path, '.git'))
        os.system("rm -rf " + osp.join(self.__package_path, 'deploy'))

        # init git for make a local repository
        repo = Repo.init(str(self.__package_path))
        repo.git.add('*.py')
        repo.git.add('*.json')
        repo.index.commit('add new files')

    def load_package_by_local_repository(self):
        """
        패키지를 해당 위치의 리파지토리로 로드

        :return:
        """
        logging.debug('load_package_by_local_repository :' +self.__package_path)
        if is_git_dir(osp.join(self.__package_path, '.git')):
            logging.debug("load local path is git directory")
            self.__package_repository = Repo(self.__package_path)
            # check is repository
            self.__package_repository.git.reset('--hard')
            # check branch
            if conf.DEFAULT_SCORE_BRANCH != conf.DEFAULT_SCORE_BRANCH_MASTER:
                self.__package_repository.git.checkout(conf.DEFAULT_SCORE_BRANCH)
            # git pull ?
            self.update_repository()

            return True
        else:
            logging.debug("load local path is not git directory, so all file remove")
            # git 이 아닐경우 삭제
            shutil.rmtree(self.__package_path, True)
            return False

    def load_package_by_file(self):
        """
        패키지를 파일로 로드

        :return:
        """
        # 해당 위치가 없을 경우
        # 1. repository_path 에 해당 패키지의 zip파일이 있다면 패키지 패스에 압축을 풀고, Git 리파지토리 인지 확인
        # 2. repository_path Remote Repository 에서 pull 을 받을 수 있으면 pull을 받음
        # 3. exception을 일으키고, 패키지를 종료 합니다.
        # 리파지토리 위치에 해당 패키지가 있을경우 해당 패키지를 최우선으로 확인하며
        # 패키지파일의 압축을 해제 한다
        # 패키지명에서 파일명으로 전환되지 않는 특수문자 (?/..등) 은 _ 로 통일한다.

        score_package_file = get_valid_filename(self.__score_package)
        logging.debug(self.__repository_path)
        package_file = osp.join(self.__repository_path, score_package_file+".zip")
        logging.debug('load_package_by_file '+str(package_file))
        if osp.isfile(package_file):
            package_zip = zipfile.ZipFile(package_file, 'r')
            # file exists
            logging.debug("load local package file and package file exist")
            # 압축을 패키지 디렉토리에 압축을 해제 합니다.
            # 패키지 디렉토리 생성
            os.makedirs(self.__package_path, exist_ok=True)
            # 파일 압축 해제

            package_zip.extractall(self.__package_path)
            package_zip.close()
            # 압축해제된 패키지 디렉토리를 로드 합니다.
            return self.load_package_by_local_repository()
        else:
            return False

    def load_package_by_remote(self):
        """
        리모트 리파지토리에서 패키지를 로드

        :return:
        """
        # socore package clone from remote repository
        repository_url = self.__score_base + ':' + self.__score_package + '.git'

        # Repository Key 를 직접 등록 합니다.
        logging.debug("git Path :"+self.__package_path)
        # repo = Repo(str(self.__package_path))
        git = Git(os.getcwd())
        # check deploy key
        if os.path.exists(conf.DEFAULT_SCORE_REPOSITORY_KEY):
            st = os.stat(conf.DEFAULT_SCORE_REPOSITORY_KEY)
            # owner read only
            if bool(st.st_mode & stat.S_IRGRP or st.st_mode & stat.S_IROTH):
                os.chmod(conf.DEFAULT_SCORE_REPOSITORY_KEY, 0o600)
            ssh_cmd = 'ssh -o StrictHostKeyChecking=no -i '+conf.DEFAULT_SCORE_REPOSITORY_KEY
            logging.debug("SSH KEY COMMAND : "+ssh_cmd)
            git.custom_environment(GIT_SSH_COMMAND=ssh_cmd)

        logging.debug(f"load_package_by_remote repository_url({repository_url}) package_path({self.__package_path})")
        self.__package_repository = Repo._clone(git, repository_url, self.__package_path, GitCmdObjectDB, None)
        logging.debug(f"load_package_by_remote result({self.__package_repository})")

        if conf.DEFAULT_SCORE_BRANCH != conf.DEFAULT_SCORE_BRANCH_MASTER:
            self.__package_repository.git.checkout(conf.DEFAULT_SCORE_BRANCH)

        return True

    def last_version(self):
        """
        Score의 마지막 버젼을 가져옵니다.

        :return: Score의 마지막 버젼
        """
        return PeerScore.__last_repository_version(self.__package_repository)

    @staticmethod
    def __last_repository_version(repository):
        return repository.git.rev_parse('HEAD')

    def all_version(self):
        """ Load All Version in this Score
        :return: [all versions]
        """
        return self.__package_repository.git.rev_list(conf.DEFAULT_SCORE_BRANCH, '--first-parent').split()

    def update_repository(self):
        """
        Score package 의 리파지토리를 업데이트 한다

        :return:
        """
        if len(self.__package_repository.remotes) > 0:
            self.__package_repository.git.pull('origin', conf.DEFAULT_SCORE_BRANCH)
            self.__list_versions()
            return True
        return False

    def score_version(self, version=None, not_exist_fail=False):
        """
        Score의 버젼을 가져옵니다.

        :param version: Score의 버젼 (sha1 hash)
        :param not_exist_fail: Score의 버젼이 없을경우 익셉션을 일으킴
        :return: version에 맞는 Score
        """
        # if version is None:
        #     version = self.__current_version
        version = self.__current_version

        # Score version이 있으면 score를 바로 로드하고, 없으면 버젼중에서 로드한다
        if version in self.__scores:
            return self.__scores[version]
        else:
            if not_exist_fail:
                raise FileNotFoundError
            return self.load_version(version)

    def load_version(self, version):
        """
        버젼을 로드 합니다.

        :param version:
        :return:
        """
        logging.debug('load score version: ' + str(version))
        score_version_path = osp.join(self.__package_path, 'deploy', str(version))

        logging.debug('package path :'+self.__package_path)
        logging.debug('load_version score path score_version_path:'+str(score_version_path))

        # 이미 받은 버젼일 수도 있으므로
        if is_git_dir(osp.join(score_version_path, '.git')):
            version_repo = Repo(str(score_version_path))
            version_repo.git.reset('--hard')
            version_repo.git.checkout(version)
        elif version in self.__score_versions:
            # 리파지토리에 Score 버젼이 있다면
            repo = Repo(self.__package_path)
            version_repo = repo.clone(str(score_version_path))
            version_repo.git.checkout(version)

        # manager 가 해당 디렉토리의 package.json 파일을 읽어서 실행시킴
        with open(os.path.join(str(score_version_path), 'package.json'), "r") as package:
            score_info = json.loads(package.read())
            package.close()
        score_info["version"] = version

        # score package.json 파일에서 main 함수를 가져와서 실행
        _score_main = osp.join(score_version_path, score_info["main"]+".py")

        # 스코어 정보를 저장하고 출력해 줍니다.
        # score에 package.json 파일의 내용을 입력 해 줍니다.
        self.__scores[version] = util.load_user_score(_score_main)(score_info)

        return self.score_version(version, True)

    def invoke(self, transaction: Transaction, block: Block=None):
        meta = transaction.meta  # tx meta property has copy action so prevent duplicate action().
        # transaction 에서 version을 불러서 실행
        # if Transaction.SCORE_VERSION_KEY in meta:
        #     score_version = self.score_version(meta[Transaction.SCORE_VERSION_KEY])
        # else:
        #     score_version = self.score_version()
        score_version = self.score_version()
        return score_version.invoke(transaction, block)

    def genesis_invoke(self, transaction: Transaction, block: Block=None):
        meta = transaction.meta  # tx meta property has copy action so prevent duplicate action().
        # transaction 에서 version을 불러서 실행
        # if Transaction.SCORE_VERSION_KEY in meta:
        #     score_version = self.score_version(meta[Transaction.SCORE_VERSION_KEY])
        # else:
        #     score_version = self.score_version()
        score_version = self.score_version()
        return score_version.genesis_invoke(transaction, block)

    def query(self, params):
        if Transaction.SCORE_VERSION_KEY in params:
            return self.score_version(params[Transaction.SCORE_VERSION_KEY]).query(params)
        else:
            return self.score_version().query(params)
