#!/usr/bin/env python

from setuptools import setup


setup(
    name='aws-adfs',
    version='0.0.1',
    description='AWS Cli authenticator via ADFS',
    long_description='Small command-line program to authenticate via ADFS and assume chosen role',
    url='https://github.com/venth/aws-adfs',
    author='Venth',
    maintainer='Venth',
    keywords='aws adfs console terminal',
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
    }
)
