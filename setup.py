#!/usr/bin/env python
import os

from setuptools import setup, find_packages

with open('requirements.txt') as requirements:
    requires = list(requirements)

version = os.environ.get('VERSION')

if version is None:
    with open(os.path.join('.', 'VERSION')) as version_file:
        version = version_file.read().strip()

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
