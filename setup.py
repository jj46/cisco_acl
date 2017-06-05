#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup

with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = history_file.read()

requirements = [
    'pytest>=3.0.7'
]

test_requirements = [
    'pytest>=3.0.7'
]

setup(
    name='cisco_acl',
    version='0.1.0',
    description="A library for performing many DNS queries very quickly",
    long_description=readme + '\n\n' + history,
    author="Joseph Williams",
    author_email='joseph.williams17@gmail.com',
    url='https://github.com/jj46/cisco_acl',
    packages=[
        'cisco_acl',
    ],
    package_dir={'cisco_acl':
                 'cisco_acl'},
    include_package_data=True,
    install_requires=requirements,
    license="MIT license",
    zip_safe=False,
    keywords='cisco_acl',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
    ],
    test_suite='tests',
    tests_require=test_requirements
)
