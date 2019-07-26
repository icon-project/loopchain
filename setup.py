#!/usr/bin/env python
import os

from setuptools import setup, find_packages
from setuptools.command.build_py import build_py as _build_py
from setuptools.command.develop import develop as _develop

with open('requirements.txt') as requirements:
    requires = list(requirements)

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
    'author': 'ICON foundation',
    'packages': find_packages(),
    'license': "Apache License 2.0",
    'install_requires': requires,
    'extras_require': {
        'tests': ['iconsdk==1.1.0', 'pytest>=4.6.3', 'pytest-xprocess>=0.12.1'],
    },
    'entry_points': {
        'console_scripts': [
            'loop=loopchain.__main__:main',
            'loopchain=loopchain.__main__:main'
        ],
    },
    'setup_requires': ['pytest-runner'],
    'tests_require': ['pytest'],
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
    ]
}

setup(**setup_options)
