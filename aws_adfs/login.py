import configparser

import boto3
import botocore
import click
from botocore import client

from . import authenticator
from . import prepare
from .prepare import adfs_config


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
    principal_roles, assertion = authenticator.authenticate(config)

    # If we fail to get an assertion, prompt for credentials and try again
    if assertion is None:
        username, password = _get_user_credentials(config)
        principal_roles, assertion = authenticator.authenticate(config, username, password)

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
            * AWS CLI profile                 : '{}'
            * AWS region                      : '{}'
            * Output format                   : '{}'
            * SSL verification of ADFS Server : '{}'
            * Selected role_arn               : '{}'
            * ADFS Server                     : '{}'
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
    config.adfs_user = click.prompt(text='Username', type=str, default=config.adfs_user)
    password = click.prompt('Password', type=str, hide_input=True)

    return config.adfs_user, password


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
        config_file.set(profile, 'adfs_config.adfs_user', config.adfs_user)

    store_config(config.profile, config.aws_credentials_location, credentials_storer)
    if config.profile == 'default':
        store_config(config.profile, config.aws_config_location, config_storer)
    else:
        store_config('profile {}'.format(config.profile), config.aws_config_location, config_storer)


def _verification_checks(config):
    if not config.adfs_host:
        click.echo('\'--adfs-host\' parameter must be supplied', err=True)
        exit(-1)


def _chosen_role_to_assume(config, principal_roles):
    if not principal_roles or len(principal_roles) == 0:
        click.echo('This account does not have access to any roles', err=True)
        exit(-1)

    chosen_principal_role = [role for role in principal_roles if config.role_arn == role[1]]

    if chosen_principal_role:
        chosen_role_arn = chosen_principal_role[0][0]
        chosen_principal_arn = chosen_principal_role[0][1]
        return chosen_role_arn, chosen_principal_arn

    if len(principal_roles) == 1:
        chosen_principal_arn = principal_roles[0][0]
        chosen_role_arn = principal_roles[0][1]
    elif len(principal_roles) > 1:
        click.echo('Please choose the role you would like to assume:')
        i = 0
        for (principal_arn, role_arn) in principal_roles:
            role_name = role_arn.split(':role/')[1]
            click.echo('    [ {} -> {} ]: {}'.format(role_name.ljust(30, ' ' if i % 2 == 0 else '.'), i, role_arn))
            i += 1

        selected_index = click.prompt(text='Selection', type=click.IntRange(0, len(principal_roles)))

        chosen_principal_arn = principal_roles[selected_index][0]
        chosen_role_arn = principal_roles[selected_index][1]

    return chosen_principal_arn, chosen_role_arn
