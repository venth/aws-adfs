#!/usr/bin/env python

import codecs
from os import path
from platform import system

from setuptools import setup

import versioneer

tests_require = [
    'pytest-runner',
    'pytest',
    'mock',
    'coverage < 4'
]

install_requires = [
    'lxml',
    'click',
    'botocore>=1.12.6',
    'boto3>=1.9.6',
    'requests[security]',
    'configparser',
]

if system() == 'Windows':
    install_requires.append('requests-negotiate-sspi>=0.3.4')

version = versioneer.get_version()

setup(
    name='aws-adfs',
    version=version,
    cmdclass=versioneer.get_cmdclass(),
    description='AWS Cli authenticator via ADFS - small command-line tool '
                'to authenticate via ADFS and assume chosen role',
    long_description=codecs.open(
        path.join(path.abspath(path.dirname(__file__)), 'README.md'),
        mode='r',
        encoding='utf-8'
    ).read(),
    url='https://github.com/venth/aws-adfs',
    download_url='https://github.com/venth/aws-adfs/tarball/{}'.format(version),
    author='Venth',
    author_email='artur.krysiak.warszawa@gmail.com',
    maintainer='Venth',
    keywords='aws adfs console tool',
    packages=['aws_adfs'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: End Users/Desktop',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Python Software Foundation License',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX',
        'Programming Language :: Python',
    ],
    setup_requires=[
        'setuptools',
    ],
    install_requires=install_requires,
    tests_require=tests_require,
    extras_require={
        'test': tests_require
    },
    entry_points={
        'console_scripts': ['aws-adfs=aws_adfs.commands:cli']
    },
    include_package_data=True,
)
