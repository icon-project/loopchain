#!/usr/bin/env python
import re

from setuptools import setup, find_packages, Command
from setuptools.command.build_py import build_py
from setuptools.command.develop import develop

install_requires = []
setup_requires = []

with open('requirements.txt') as requirements:
    regex = re.compile('(grpcio)|(protobuf).+')
    for line in requirements:
        req = line.strip()
        install_requires.append(req)
        if regex.search(req):
            setup_requires.append(req)

setup_requires.append('pytest-runner')


class BuildPackageProtos(Command):
    """Command to generate project *_pb2.py modules from proto files."""

    description = 'build grpc protobuf modules'
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        import grpc_tools.command
        grpc_tools.command.build_package_protos(self.distribution.package_dir[''])


class BuildPyCommand(build_py):
    def run(self):
        self.run_command('build_proto_modules')
        build_py.run(self)


class DevelopCommand(develop):
    def run(self):
        self.run_command('build_proto_modules')
        develop.run(self)


setup_options = {
    'name': 'loopchain',
    'description': 'Blockchain consensus engine based on LFT',
    'author': 'ICON foundation',
    'packages': find_packages(),
    'package_dir': {'': '.'},
    'license': "Apache License 2.0",
    'setup_requires': setup_requires,
    'install_requires': install_requires,
    'extras_require': {
        'tests': ['iconsdk==1.1.0', 'pytest>=4.6.3', 'pytest-xprocess>=0.12.1', "pytest-benchmark"],
        'misc': ['bump2version'],
    },
    'entry_points': {
        'console_scripts': [
            'loop=loopchain.__main__:main',
            'loopchain=loopchain.__main__:main'
        ],
    },
    'tests_require': ['pytest'],
    'cmdclass': {
        'build_proto_modules': BuildPackageProtos,
        'build_py': BuildPyCommand,
        'develop': DevelopCommand
    },
    'classifiers': [
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Natural Language :: English',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3 :: Only'
    ]
}

setup(**setup_options)
