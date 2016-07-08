#!/usr/bin/env python

import codecs
from os import path

from setuptools import setup

version = '0.0.4'

setup(
    name='aws-adfs',
    version=version,
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
        'Development Status :: 4 - Beta',
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

    install_requires=[
        'click==6.6',
        'beautifulsoup4==4.4.1',
        'boto3==1.3.1',
        'requests_ntlm==0.3.0',
        'requests==2.10.0',
        'pycrypto==2.6.1',
        'Crypto==1.4.1',
    ],
    entry_points={
        'console_scripts': ['aws-adfs=aws_adfs.commands:cli']
    },
    include_package_data=True,
)
