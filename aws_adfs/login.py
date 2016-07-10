import configparser
import base64
import getpass
import itertools
import os
import lxml.etree as ET

import boto3
import botocore
import click
import requests
from botocore import client
from cookielib import LWPCookieJar

from . import prepare
from .prepare import adfs_config

# The initial URL that starts the authentication process.
_IDP_ENTRY_URL = 'https://{}/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices'


@click.command()
@click.option(
    '--profile',
    default=lambda: adfs_config.profile,
    help='AWS cli profile that will be authenticated.\n'
         'After successful authentication just use:\n'
         'aws --profile <authenticated profile> <service> ...',
)
@click.option(
    '--region',
    default=lambda: adfs_config.region,
    help='The default AWS region that this script will connect\n'
         'to for all API calls',
)
@click.option(
    '--ssl-verification/--no-ssl-verification',
    default=lambda: adfs_config.ssl_verification,
    help='SSL certificate verification: Whether or not strict certificate\n'
         'verification is done, False should only be used for dev/test',
)
@click.option(
    '--adfs-host',
    default=lambda: adfs_config.adfs_host,
    help='For the first time for a profile it has to be provided, next time for the same profile\n'
         'it will be loaded from the stored configuration',
)
@click.option(
    '--output-format',
    default=lambda: adfs_config.output_format,
    type=click.Choice(['json', 'text', 'table']),
    help='Output format used by aws cli',
)
def login(
        profile,
        region,
        ssl_verification,
        adfs_host,
        output_format,
):
    """
    Authenticates an user with active directory credentials
    """
    config = prepare.get_prepared_config(profile, region, ssl_verification, adfs_host, output_format)

    _verification_checks(config)

    # Try reauthenticating using an existing ADFS session
    principal_roles, assertion = _authenticate(config)

    # If we fail to get an assertion, prompt for credentials and try again
    if assertion is None:
        username, password = _get_user_credentials(config)
        principal_roles, assertion = _authenticate(config, username, password)

        username = '########################################'
        del username
        password = '########################################'
        del password

    principal_arn, config.role_arn = _chosen_role_to_assume(config, principal_roles)

    # Use the assertion to get an AWS STS token using Assume Role with SAML
    conn = boto3.client('sts', config=client.Config(signature_version=botocore.UNSIGNED))
    aws_session_token = conn.assume_role_with_saml(
        RoleArn=config.role_arn,
        PrincipalArn=principal_arn,
        SAMLAssertion=assertion,
        DurationSeconds=3600,
    )

    _store(config, aws_session_token)
    _emit_summary(config)


def _emit_summary(config):
    click.echo(
        """
        Prepared ADFS configuration as follows:
            * AWS Cli profile                           : '{}'
            * AWS region                                : '{}'
            * output format                             : '{}'
            * ssl verification during authentication was: '{}'
            * selected role_arn                         : '{}'
            * ADFS host used for authentication         : '{}'
        """.format(
            config.profile,
            config.region,
            config.output_format,
            'ENABLED' if config.ssl_verification else 'DISABLED',
            config.role_arn,
            config.adfs_host,
        )
    )


def _get_user_credentials(config):
    username = raw_input('Username: ')
    password = getpass.getpass()

    return username, password


def _authenticate(config, username=None, password=None):
    # Initiate session handler
    session = requests.Session()
    session.cookies = LWPCookieJar(filename=config.adfs_cookie_location)

    try:
        session.cookies.load(ignore_discard=True)
    except IOError:
        pass

    # Opens the initial AD FS URL and follows all of the HTTP302 redirects
    response = session.post(
        _IDP_ENTRY_URL.format(config.adfs_host),
        verify=config.ssl_verification,
        headers={'Accept-Language': os.environ['LANG'][:2]},
        data={
            'UserName': username,
            'Password': password,
            'AuthMethod': 'urn:amazon:webservices'
        }
    )

    mask = os.umask(0o177)
    session.cookies.save(ignore_discard=True)
    os.umask(mask)

    del username
    password = '###################################################'
    del password

    # Decode the response
    html = ET.fromstring(response.text.decode('utf8'), ET.HTMLParser())
    assertion = None

    # Check to see if login returned an error
    # Since we're screen-scraping the login form, we need to pull it out of a label
    for element in html.findall('.//form[@id="loginForm"]//label[@id="errorText"]'):
        if element.text is not None:
            click.echo(element.text)
            exit(-1)

    # Retrieve Base64-encoded SAML assertion from form SAMLResponse input field
    for element in html.findall('.//form[@name="hiddenform"]/input[@name="SAMLResponse"]'):
        assertion = element.get('value')

    # If we did not get an error, but also do not have an assertion, then the user needs to authenticate
    if not assertion:
        return None, None

    # Parse the returned assertion and extract the authorized roles
    saml = ET.fromstring(base64.b64decode(assertion))

    aws_roles = map(
        lambda saml2attributevalue: saml2attributevalue.text,
        itertools.chain.from_iterable(
            map(
                lambda saml2attribute: list(
                    saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue')),
                filter(
                    lambda saml2attribute: saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role',
                    saml.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute')
                ),
            )
        )
    )

    # Note the format of the attribute value is principal_arn, role_arn
    principal_roles = map(
        lambda chunks: (chunks[0], chunks[1]),
        filter(
            lambda chunks: 'saml-provider' in chunks[0],
            map(
                lambda role: role.split(','),
                aws_roles,
            )
        )
    )

    return principal_roles, assertion


def _store(config, aws_session_token):
    def store_config(profile, config_location, storer):
        config_file = configparser.RawConfigParser()
        config_file.read(config_location)

        if not config_file.has_section(profile):
            config_file.add_section(profile)

        storer(config_file, profile)

        with open(config_location, 'w+') as f:
            try:
                config_file.write(f)
            finally:
                f.close()

    def credentials_storer(config_file, profile):
        config_file.set(profile, 'aws_access_key_id', aws_session_token['Credentials']['AccessKeyId'])
        config_file.set(profile, 'aws_secret_access_key', aws_session_token['Credentials']['SecretAccessKey'])
        config_file.set(profile, 'aws_session_token', aws_session_token['Credentials']['SessionToken'])
        config_file.set(profile, 'aws_security_token', aws_session_token['Credentials']['SessionToken'])

    def config_storer(config_file, profile):
        config_file.set(profile, 'region', config.region)
        config_file.set(profile, 'output', config.output_format)
        config_file.set(profile, 'adfs_config.ssl_verification', config.ssl_verification)
        config_file.set(profile, 'adfs_config.adfs_host', config.adfs_host)
        config_file.set(profile, 'adfs_config.role_arn', config.role_arn)
        config_file.set(profile, 'source_profile', config.profile)

    store_config(config.profile, config.aws_credentials_location, credentials_storer)
    if config.profile == 'default':
        store_config(config.profile, config.aws_config_location, config_storer)
    else:
        store_config('profile {}'.format(config.profile), config.aws_config_location, config_storer)


def _verification_checks(config):
    if not config.adfs_host:
        click.echo('\'--adfs-host\' parameter need to be supplied')
        exit(-1)


def _chosen_role_to_assume(config, principal_roles):
    chosen_principal_role = filter(
        lambda (_, role_arn): config.role_arn == role_arn,
        principal_roles
    )

    if chosen_principal_role:
        chosen_role_arn = chosen_principal_role[0][0]
        chosen_principal_arn = chosen_principal_role[0][1]
        return chosen_role_arn, chosen_principal_arn

    if len(principal_roles) > 1:
        click.echo('Please choose the role you would like to assume:')
        i = 0
        for (principal_arn, role_arn) in principal_roles:
            role_name = role_arn.split(':role/')[1]
            click.echo('    [ {} -> {} ]: {}'.format(role_name.ljust(30, ' ' if i % 2 == 0 else '.'), i, role_arn))
            i += 1

        selected_index = int(raw_input('Selection: '))

        chosen_principal_arn = principal_roles[selected_index][0]
        chosen_role_arn = principal_roles[selected_index][1]
    else:
        chosen_principal_arn = principal_roles[0][0]
        chosen_role_arn = principal_roles[0][1]

    return chosen_principal_arn, chosen_role_arn
