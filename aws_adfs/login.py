import configparser
import copy
import json
import logging
import os.path
import subprocess
import sys
import urllib
from datetime import datetime, timezone
from os import environ
from platform import system

import boto3
import botocore
import botocore.exceptions
import botocore.session
import click
import requests
from botocore import client

from . import authenticator, helpers, prepare, role_chooser


@click.command()
@click.option(
    '--profile',
    default=lambda: environ.get('AWS_DEFAULT_PROFILE', 'default'),
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
    "--username-password-command",
    help='Read username and password from the output of a shell command (expected JSON format: `{"username": "myusername", "password": "mypassword"}`)',
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
    '--print-console-signin-url',
    is_flag=True,
    help='Output a URL that lets users who sign in to your organization\'s network securely access the AWS Management Console.',
)
@click.option(
    "--console-role-arn",
    help="Role to assume for use in conjunction with --print-console-signin-url",
)
@click.option(
    "--console-external-id",
    help="External ID to pass in assume role for use in conjunction with --print-console-signin-url",
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
    '--no-session-cache',
    is_flag=True,
    help="Do not use AWS session cache in ~/.aws/adfs_cache/ directory.",
)
@click.option("--assertfile", help="Use SAML assertion response from a local file")
@click.option(
    "--sspi/--no-sspi",
    default=system() == "Windows",
    help="Whether or not to use Kerberos SSO authentication via SSPI (Windows only, defaults to True).",
)
@click.option(
    "--duo-factor",
    help="Use a specific Duo factor, overriding the default one configured server side. Known Duo factors that can be used with aws-adfs are `Duo Push`, `WebAuthn Security Key`, and `Phone Call`.",
)
@click.option(
    "--duo-device",
    help="Use a specific Duo device, overriding the default one configured server side. Depends heavily on the Duo factor used. Known Duo devices that can be used with aws-adfs are `phone1` for `Duo Push` and `Phone Call` factors, and the security key ID for `WebAuthn Security Key` factor.",
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
    username_password_command,
    env,
    stdin,
    authfile,
    stdout,
    printenv,
    print_console_signin_url,
    console_role_arn,
    console_external_id,
    role_arn,
    session_duration,
    no_session_cache,
    assertfile,
    sspi,
    duo_factor,
    duo_device,
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
        sspi,
        username_password_command,
        duo_factor,
        duo_device,
    )

    _verification_checks(config)

    # Get session credentials from cache if not expired to avoid invoking the ADFS host uselessly
    session_cache_dir = (
        None
        if no_session_cache or role_arn is None
        else os.path.join(
            os.path.dirname(config.aws_credentials_location), "adfs_cache"
        )
    )
    aws_session_token = _session_cache_get(session_cache_dir, profile)

    aws_session_duration = "Not known when AWS session credentials are retrieved from cache."
    if not aws_session_token:
        # Try re-authenticating using an existing ADFS session
        principal_roles, assertion, aws_session_duration = authenticator.authenticate(config, assertfile=assertfile)

        # If we fail to get an assertion, prompt for credentials and try again
        if assertion is None:
            password = None

            if config.username_password_command:
                config.adfs_user, password = _username_password_command_credentials(
                    username_password_command
                )
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

            principal_roles, assertion, aws_session_duration = authenticator.authenticate(config, config.adfs_user, password)

            helpers.memset_zero(password)
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
        try:
            session = botocore.session.get_session()
            session.set_config_variable('profile', config.profile)
            conn = session.create_client(
                'sts',
                region_name=region,
                config=client.Config(signature_version=botocore.UNSIGNED),
            )
        except botocore.exceptions.ProfileNotFound:
            logging.debug('Profile {} does not exist yet'.format(config.profile))
            session = botocore.session.get_session()
            conn = session.create_client(
                'sts',
                region_name=region,
                config=client.Config(signature_version=botocore.UNSIGNED),
            )

        aws_session_token = conn.assume_role_with_saml(
            RoleArn=config.role_arn,
            PrincipalArn=principal_arn,
            SAMLAssertion=assertion,
            DurationSeconds=int(config.session_duration),
        )

        _session_cache_set(session_cache_dir, profile, aws_session_token)

    if stdout:
        _emit_json(aws_session_token)
    elif printenv:
        _emit_summary(config, aws_session_duration)
        _print_environment_variables(aws_session_token, config)
    elif print_console_signin_url:
        _print_console_signin_url(
            aws_session_token, adfs_host, console_role_arn, console_external_id
        )
    else:
        _store(config, aws_session_token)
        _emit_summary(config, aws_session_duration)


def _emit_json(aws_session_token):
    click.echo(json.dumps({
        "Version": 1,
        "AccessKeyId": aws_session_token['Credentials']['AccessKeyId'],
        "SecretAccessKey": aws_session_token['Credentials']['SecretAccessKey'],
        "SessionToken": aws_session_token['Credentials']['SessionToken'],
        "Expiration": aws_session_token['Credentials']['Expiration'].isoformat()
    }))


def _print_environment_variables(aws_session_token, config):
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
        u"""{} AWS_DEFAULT_REGION={}""".format(envcommand, config.region))


def _print_console_signin_url(
    aws_session_token, adfs_host, console_role_arn, console_external_id
):
    # The steps below come from https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_enable-console-custom-url.html

    if console_role_arn:
        # Step 2: Using the access keys for an IAM user in your AWS account,
        # call "AssumeRole" to get temporary access keys for the federated user

        # Note: Calls to AWS STS AssumeRole must be signed using the access key ID
        # and secret access key of an IAM user or using existing temporary credentials.
        # The credentials can be in EC2 instance metadata, in environment variables,
        # or in a configuration file, and will be discovered automatically by the
        # client('sts') function. For more information, see the Python SDK docs:
        # http://boto3.readthedocs.io/en/latest/reference/services/sts.html
        # http://boto3.readthedocs.io/en/latest/reference/services/sts.html#STS.Client.assume_role

        # FIXME: use botocore instead of boto3: https://github.com/boto/botocore/blob/1.21.49/botocore/credentials.py#L766
        sts_connection = boto3.client(
            "sts",
            aws_access_key_id=aws_session_token["Credentials"]["AccessKeyId"],
            aws_secret_access_key=aws_session_token["Credentials"]["SecretAccessKey"],
            aws_session_token=aws_session_token["Credentials"]["SessionToken"],
        )

        if console_external_id:
            aws_session_token = sts_connection.assume_role(
                RoleArn=console_role_arn,
                RoleSessionName="aws-adfs",
                ExternalId=console_external_id,
            )
        else:
            aws_session_token = sts_connection.assume_role(
                RoleArn=console_role_arn,
                RoleSessionName="aws-adfs",
            )

    # Step 3: Format resulting temporary credentials into JSON
    url_credentials = {}
    url_credentials['sessionId'] = aws_session_token['Credentials']['AccessKeyId']
    url_credentials['sessionKey'] = aws_session_token['Credentials']['SecretAccessKey']
    url_credentials['sessionToken'] = aws_session_token['Credentials']['SessionToken']
    json_string_with_temp_credentials = json.dumps(url_credentials)

    # Step 4. Make request to AWS federation endpoint to get sign-in token. Construct the parameter string with
    # the sign-in action request, a 12-hour session duration, and the JSON document with temporary credentials 
    # as parameters.
    request_parameters = "?Action=getSigninToken"

    # https://signin.aws.amazon.com/federation endpoint returns a HTTP/1.1 400 Bad Request error with AssumeRole credentials when SessionDuration is set
    if not console_role_arn:
        request_parameters += "&SessionDuration=43200"

    request_parameters += "&Session=" + urllib.parse.quote_plus(json_string_with_temp_credentials)
    request_url = "https://signin.aws.amazon.com/federation" + request_parameters
    r = requests.get(request_url)
    # Returns a JSON document with a single element named SigninToken.
    signin_token = json.loads(r.text)

    # Step 5: Create URL where users can use the sign-in token to sign in to
    # the console. This URL must be used within 15 minutes after the
    # sign-in token was issued.
    request_parameters = "?Action=login"
    request_parameters += "&Issuer=" + urllib.parse.quote_plus("https://" + adfs_host + "/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices")
    request_parameters += "&Destination=" + urllib.parse.quote_plus("https://console.aws.amazon.com/")
    request_parameters += "&SigninToken=" + signin_token["SigninToken"]
    request_url = "https://signin.aws.amazon.com/federation" + request_parameters

    # Send final URL to stdout
    click.echo("""\nAWS web console signin URL:\n\n{}""".format(request_url))

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
            * SSPI:                             : '{}'
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
            config.sspi,
        ),
        err=True
    )


def _username_password_command_credentials(username_password_command):
    try:
        logging.debug("Executing `{}`".format(username_password_command))
        proc = subprocess.run(
            username_password_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=True,
            shell=True,
        )
        data = json.loads(proc.stdout)
        username = data["username"]
        password = data["password"]
    except subprocess.CalledProcessError as e:
        logging.error(
            "Failed to execute the `{}` command to retrieve username and password: \n\n{}".format(
                username_password_command, e.output
            )
        )
        username = None
        password = None
    except json.JSONDecodeError as e:
        logging.error(
            "Failed to decode the output of the `{}` command as JSON to retrieve username and password: \n\n{}".format(
                username_password_command, e
            )
        )
        username = None
        password = None

    return username, password


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
            config_file.set(profile, "s3", "\nsignature_version = {}".format(config.s3_signature_version))
        config_file.set(profile, "adfs_config.session_duration", config.session_duration)
        config_file.set(profile, "adfs_config.provider_id", config.provider_id)
        config_file.set(profile, "adfs_config.sspi", config.sspi)
        config_file.set(profile, "adfs_config.duo_factor", config.duo_factor)
        config_file.set(profile, "adfs_config.duo_device", config.duo_device)

    store_config(config.profile, config.aws_credentials_location, credentials_storer)
    if config.profile == 'default':
        store_config(config.profile, config.aws_config_location, config_storer)
    else:
        store_config('profile {}'.format(config.profile), config.aws_config_location, config_storer)


def _verification_checks(config):
    if not config.adfs_host:
        click.echo('\'--adfs-host\' parameter must be supplied', err=True)
        exit(-1)


def _session_cache_set(session_cache_dir, profile, aws_session_credentials):
    if session_cache_dir is None:
        return

    if not os.path.exists(session_cache_dir):
        logging.debug(
            "Cache directory {} does not exist yet, create it.".format(
                session_cache_dir
            )
        )
        os.mkdir(session_cache_dir, 0o700)
    cache_file = os.path.join(session_cache_dir, "{}.json".format(profile))

    aws_session_credentials = copy.deepcopy(aws_session_credentials)
    aws_session_credentials["Credentials"]["Expiration"] = aws_session_credentials[
        "Credentials"
    ]["Expiration"].strftime("%Y-%m-%dT%H:%M:%S%z")

    try:
        # TODO: this probably needs locking of some sort to handle concurrent writes from multiple processes
        with os.fdopen(os.open(cache_file, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600), "w") as f:
            json.dump(aws_session_credentials, f)
            logging.debug(
                "Wrote session credentials to cache file {}.".format(cache_file)
            )
    except Exception as e:
        logging.warning(
            "Failed to write session credentials to cache file {}.".format(cache_file),
            e,
        )
        # TODO: maybe delete corrupt cache file?


def _session_cache_get(session_cache_dir, profile):
    if session_cache_dir is None:
        return

    cache_file = os.path.join(session_cache_dir, "{}.json".format(profile))
    if not os.path.exists(cache_file):
        logging.debug("Cache file {} does not exist yet.".format(cache_file))
        return

    try:
        with open(os.path.join(session_cache_dir, "{}.json".format(profile))) as f:
            aws_session_credentials = json.load(f)
        aws_session_credentials["Credentials"]["Expiration"] = datetime.strptime(
            aws_session_credentials["Credentials"]["Expiration"], "%Y-%m-%dT%H:%M:%S%z"
        )
    except Exception as e:
        logging.warning(
            "Failed to read session credentials from cache file {}.\n{}".format(
                cache_file, e
            )
        )
        return

    if aws_session_credentials["Credentials"]["Expiration"] < datetime.now(
        tz=timezone.utc
    ):
        return

    return aws_session_credentials
