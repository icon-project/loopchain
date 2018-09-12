#!/usr/bin/env python
import os

from setuptools import setup, find_packages

with open('requirements.txt') as requirements:
    requires = list(requirements)

version = os.environ.get('VERSION')  # 1.21.5

setup_options = {
    'name': 'loopchain',
    'version': version,
    'description': 'Blockchain consensus engine based on LFT',
    'author': 'ICON foundation',
    'packages': find_packages(),
    'license': "Apache License 2.0",
    'install_requires': requires,
    'entry_points': {
        'console_scripts': [
            'loop=loopchain.__main__:main',
            'loopchain=loopchain.__main__:main'
        ],
    },
    'setup_requires': ['pytest-runner'],
    'tests_requires': ['pytest'],
    'classifiers': [
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Natural Language :: English',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.6.5'
    ]
}

setup(**setup_options)
