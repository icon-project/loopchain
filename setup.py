#!/usr/bin/env python
import os

from setuptools import setup, find_packages
from setuptools.command.build_py import build_py as _build_py
from setuptools.command.develop import develop as _develop

project_root = os.path.abspath(os.path.dirname(__file__))

version = os.environ.get('VERSION')

if version is None:
    with open(os.path.join('.', 'VERSION')) as version_file:
        version = version_file.read().strip()


def generate_proto():
    import grpc_tools.protoc

    proto_path = './loopchain/protos'
    proto_file = os.path.join(proto_path, 'loopchain.proto')

    grpc_tools.protoc.main([
        'grcp_tools.protoc',
        f'-I{proto_path}',
        f'--python_out={proto_path}',
        f'--grpc_python_out={proto_path}',
        f'{proto_file}'
    ])


class build_py(_build_py):
    def run(self):
        generate_proto()
        _build_py.run(self)


class develop(_develop):
    def run(self):
        generate_proto()
        _develop.run(self)


setup_options = {
    'name': 'loopchain',
    'version': version,
    'description': 'Blockchain consensus engine based on LFT',
    'long_description_content_type': 'text/markdown',
    'url': 'https://github.com/icon-project/loopchain',
    'author': 'ICON foundation',
    'author_email': 'foo@icon.foundation',
    'packages': find_packages(exclude=['testcase', 'docs']),
    'license': "Apache License 2.0",
    'entry_points': {
        'console_scripts': [
            'loop=loopchain.__main__:main',
            'loopchain=loopchain.__main__:main'
        ],
    },
    'setup_requires': ['pytest-runner'],
    'cmdclass': {
        'build_py': build_py,
        'develop': develop
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
    ],
    'keywords': '',  # FIXME or delete
    'python_requires': '>=3.6, <=3.7.3',
    'project_urls': {
        'Bug Reports': 'https://github.com/icon-project/loopchain/issues',
        'Source': 'https://github.com/icon-project/loopchain.git',
        'Documentation': 'https://www.icondev.io/docs'
    },
}

setup(**setup_options)
