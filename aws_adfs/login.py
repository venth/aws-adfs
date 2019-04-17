import configparser

import boto3
import botocore
import botocore.exceptions
import botocore.session
import click
from botocore import client
from os import environ
import sys
from . import authenticator
from . import prepare
from . import role_chooser


@click.command()
@click.option(
    '--profile',
    help='AWS cli profile that will be authenticated.\n'
         'After successful authentication just use:\n'
         'aws --profile <authenticated profile> <service> ...',
)
@click.option(
    '--region',
    help='The default AWS region that this script will connect\n'
         'to for all API calls',
)
@click.option(
    '--ssl-verification/--no-ssl-verification',
    default=None,
    help='SSL certificate verification: Whether or not strict certificate\n'
         'verification is done, False should only be used for dev/test',
)
@click.option(
    '--adfs-ca-bundle',
    default=None,
    help='Override CA bundle for SSL certificate verification for ADFS server only.',
)
@click.option(
    '--adfs-host',
    help='For the first time for a profile it has to be provided, next time for the same profile\n'
         'it will be loaded from the stored configuration',
)
@click.option(
    '--output-format',
    type=click.Choice(['json', 'text', 'table']),
    help='Output format used by aws cli',
)
@click.option(
    '--provider-id',
    help='Provider ID, e.g urn:amazon:webservices (optional)',
)
@click.option(
    '--s3-signature-version',
    type=click.Choice(['s3v4']),
    help='s3 signature version: Identifies the version of AWS Signature to support for '
         'authenticated requests. Valid values: s3v4',
)
@click.option(
    '--env',
    is_flag=True,
    help='Read username, password from environment variables (username and password).',
)
@click.option(
    '--stdin',
    is_flag=True,
    help='Read username, password from standard input separated by a newline.',
)
@click.option(
    '--authfile',
    help='Read username, password from a local file (optional)',
)
@click.option(
    '--stdout',
    is_flag=True,
    help='Print aws_session_token in json on stdout.',
)
@click.option(
    '--printenv',
    is_flag=True,
    help='Output commands to set AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN, AWS_DEFAULT_REGION environmental variables instead of saving them to the aws configuration file.',
)
@click.option(
    '--role-arn',
    help='Predefined role arn to selects, e.g. aws-adfs login --role-arn arn:aws:iam::123456789012:role/YourSpecialRole',
)
@click.option(
    '--session-duration',
    help='Define the amount of seconds you want to establish your STS session, e.g. aws-adfs login --session-duration 3600',
    type=int,
)
@click.option(
    '--assertfile',
    help='Use SAML assertion response from a local file'
)
@click.option(
    '--sspi/--no-sspi',
    default=True,
    help='Whether or not to use Kerberos SSO authentication via SSPI, which may not work in some environments.',
)
def login(
        profile,
        region,
        ssl_verification,
        adfs_ca_bundle,
        adfs_host,
        output_format,
        provider_id,
        s3_signature_version,
        env,
        stdin,
        authfile,
        stdout,
        printenv,
        role_arn,
        session_duration,
        assertfile,
        sspi
):
    """
    Authenticates an user with active directory credentials
    """
    config = prepare.get_prepared_config(
        profile,
        region,
        ssl_verification,
        adfs_ca_bundle,
        adfs_host,
        output_format,
        provider_id,
        s3_signature_version,
        session_duration,
    )

    _verification_checks(config)

    # Try re-authenticating using an existing ADFS session
    principal_roles, assertion, aws_session_duration = authenticator.authenticate(config, assertfile=assertfile)

    # If we fail to get an assertion, prompt for credentials and try again
    if assertion is None:
        password = None

        if stdin:
            config.adfs_user, password = _stdin_user_credentials()
        elif env:
            config.adfs_user, password = _env_user_credentials()
        elif authfile:
            config.adfs_user, password = _file_user_credentials(config.profile, authfile)

        if not config.adfs_user:
            config.adfs_user = click.prompt(text='Username', type=str, default=config.adfs_user)

        if not password:
            password = click.prompt('Password', type=str, hide_input=True)

        principal_roles, assertion, aws_session_duration = authenticator.authenticate(config, config.adfs_user, password, sspi=sspi)

        password = '########################################'
        del password

    if(role_arn is not None):
        config.role_arn = role_arn
    principal_arn, config.role_arn = role_chooser.choose_role_to_assume(config, principal_roles)
    if principal_arn is None or config.role_arn is None:
        click.echo('This account does not have access to any roles', err=True)
        exit(-1)

    # Use the assertion to get an AWS STS token using Assume Role with SAML
    # according to the documentation:
    #   http://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_saml_assertions.html
    # This element contains one AttributeValue element that specifies the maximum time that the user
    # can access the AWS Management Console before having to request new temporary credentials.
    # The value is an integer representing the number of seconds, and can be
    # a maximum of 43200 seconds (12 hours). If this attribute is not present,
    # then the maximum session duration defaults to one hour
    # (the default value of the DurationSeconds parameter of the AssumeRoleWithSAML API).
    # To use this attribute, you must configure the SAML provider to provide single sign-on access
    # to the AWS Management Console through the console sign-in web endpoint at
    # https://signin.aws.amazon.com/saml.
    # Note that this attribute extends sessions only to the AWS Management Console.
    # It cannot extend the lifetime of other credentials.
    # However, if it is present in an AssumeRoleWithSAML API call,
    # it can be used to shorten the lifetime of the credentials returned by the call to less than
    # the default of 60 minutes.
    #
    # Note, too, that if a SessionNotOnOrAfter attribute is also defined,
    # then the lesser value of the two attributes, SessionDuration or SessionNotOnOrAfter,
    # establishes the maximum duration of the console session.
    _bind_aws_session_to_chosen_profile(config)
    conn = boto3.client('sts', config=client.Config(signature_version=botocore.UNSIGNED))
    aws_session_token = conn.assume_role_with_saml(
        RoleArn=config.role_arn,
        PrincipalArn=principal_arn,
        SAMLAssertion=assertion,
        DurationSeconds=int(config.session_duration),
    )

    if stdout:
        _emit_json(aws_session_token)
    elif printenv:
        _emit_summary(config, aws_session_duration)
        _print_environment_variables(aws_session_token,config)
    else:
        _store(config, aws_session_token)
        _emit_summary(config, aws_session_duration)


def _bind_aws_session_to_chosen_profile(config):
    try:
        boto3.setup_default_session(profile_name=config.profile)
    except botocore.exceptions.ProfileNotFound:
        pass


def _emit_json(aws_session_token):
    click.echo(
        u"""{{"AccessKeyId": "{}", "SecretAccessKey": "{}", "SessionToken": "{}"}}""".format(
            aws_session_token['Credentials']['AccessKeyId'],
            aws_session_token['Credentials']['SecretAccessKey'],
            aws_session_token['Credentials']['SessionToken']
        )
    )

def _print_environment_variables(aws_session_token,config):
    envcommand = "export"
    if(sys.platform=="win32"):
        envcommand="set"

    click.echo(
        u"""{} AWS_ACCESS_KEY_ID={}""".format(envcommand,aws_session_token['Credentials']['AccessKeyId']))
    click.echo(
        u"""{} AWS_SECRET_ACCESS_KEY={}""".format(envcommand,aws_session_token['Credentials']['SecretAccessKey']))
    click.echo(
        u"""{} AWS_SESSION_TOKEN={}""".format(envcommand,aws_session_token['Credentials']['SessionToken']))
    click.echo(
        u"""{} AWS_DEFAULT_REGION={}""".format(envcommand,config.region))


def _emit_summary(config, session_duration):
    click.echo(
        u"""
        Prepared ADFS configuration as follows:
            * AWS CLI profile                   : '{}'
            * AWS region                        : '{}'
            * Output format                     : '{}'
            * SSL verification of ADFS Server   : '{}'
            * Selected role_arn                 : '{}'
            * ADFS Server                       : '{}'
            * ADFS Session Duration in seconds  : '{}'
            * Provider ID                       : '{}'
            * S3 Signature Version              : '{}'
            * STS Session Duration in seconds   : '{}'
        """.format(
            config.profile,
            config.region,
            config.output_format,
            'ENABLED' if config.ssl_verification else 'DISABLED',
            config.role_arn,
            config.adfs_host,
            session_duration,
            config.provider_id,
            config.s3_signature_version,
            config.session_duration,
        )
    )


def _file_user_credentials(profile, authfile):
    config = configparser.ConfigParser()

    try:
        if len(config.read(authfile)) == 0:
            raise IOError(authfile)
    except IOError as e:
        print('Auth file ({}) not found'.format(e))
        return None, None

    try:
        username = config.get(profile, "username")
    except configparser.Error:
        print('Failed to read username from auth file, section ({}).'.format(profile))
        username = None

    try:
        password = config.get(profile, "password")
    except configparser.Error:
        print('Failed to read password from auth file, section ({}).'.format(profile))
        password = None

    return username, password


def _env_user_credentials():
    try:
        username = environ['username']
    except:
        print('Failed to read username from env')
        username = None

    try:
        password = environ['password']
    except:
        print('Failed to read password from env')
        password = None

    return username, password


def _stdin_user_credentials():
    stdin = click.get_text_stream('stdin').read()
    stdin_lines = stdin.strip().splitlines()
    try:
        username, password = stdin_lines[:2]
    except ValueError:
        print('Failed to read newline separated username and password from stdin.')
        username = None
        password = None

    return username, password


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
        config_file.set(profile, 'adfs_config.role_arn', config.role_arn)
        config_file.set(profile, 'adfs_config.adfs_host', config.adfs_host)
        if config.adfs_user:
            config_file.set(profile, 'adfs_config.adfs_user', config.adfs_user)
        if config.s3_signature_version:
            config_file.set(profile, 's3', '\nsignature_version = {}'.format(config.s3_signature_version))
        config_file.set(profile, 'adfs_config.session_duration', config.session_duration)
        config_file.set(profile, 'adfs_config.provider_id', config.provider_id)

    store_config(config.profile, config.aws_credentials_location, credentials_storer)
    if config.profile == 'default':
        store_config(config.profile, config.aws_config_location, config_storer)
    else:
        store_config('profile {}'.format(config.profile), config.aws_config_location, config_storer)


def _verification_checks(config):
    if not config.adfs_host:
        click.echo('\'--adfs-host\' parameter must be supplied', err=True)
        exit(-1)
