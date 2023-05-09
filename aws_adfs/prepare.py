import logging
import ast
import configparser
import os
import botocore.session
import botocore.exceptions
from platform import system
from types import MethodType
from . import consts


def get_prepared_config(
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
    aad_verification_code=None,
    enforce_role_arn=False
):
    """
    Prepares ADFS configuration for login task.
    The task comprises steps as follows:
        - default configuration preparation,
        - creating aws cli configuration files, if needed
        - loading adf configuration for specified aws profiles
    The configuration is stored in ctx.adfs_config attribute
    :param output_format: output format used by aws cli
    :param adfs_host: fqdn of adfs host that will be used to authenticate user
    :param ssl_verification: SSL certificate verification: Whether or not strict certificate
                             verification is done, False should only be used for dev/test
    :param adfs_ca_bundle: Override CA bundle for SSL certificate
                           verification for ADFS server only.
    :param region: The default AWS region that this script will connect
                   to for all API calls
    :param profile: aws cli profile
    :param provider_id: Provider ID, e.g urn:amazon:webservices (optional)
    :param s3_signature_version: s3 signature version
    :param session_duration: AWS STS session duration (default 1 hour)
    :param sspi: Whether SSPI is enabled
    :param username_password_command: The command used to retrieve username and password information
    :param duo_factor: The specific Duo factor to use
    :param duo_device: The specific Duo device to use
    :param aad_verification_code: If verification code is in config use that for multi-factor authentication
    :param enforce_role_arn: If role_arn is in config then only allow the provided value
    """
    def default_if_none(value, default):
        return value if value is not None else default

    # Normalise duo_factor if specified and we can find a single match
    if duo_factor:
        duo_known_factors = [ value for const, value in vars(consts).items() if const.startswith('DUO_UNIVERSAL_PROMPT_FACTOR_') ]
        duo_factor_matches = []
        for factor in duo_known_factors:
            if duo_factor.lower() in factor.lower().split():
                duo_factor_matches.append(factor)

        if len(duo_factor_matches) == 1:
            logging.debug(u'Normalising duo-factor from "{}" to "{}"'.format(duo_factor, duo_factor_matches[0]))
            duo_factor = duo_factor_matches[0]

    adfs_config = create_adfs_default_config(profile='default')

    adfs_config.profile = default_if_none(profile, adfs_config.profile)

    _create_base_aws_cli_config_files_if_needed(adfs_config)
    _load_adfs_config_from_stored_profile(adfs_config, adfs_config.profile)
    adfs_config.ssl_verification = default_if_none(ssl_verification, adfs_config.ssl_verification)
    adfs_config.adfs_ca_bundle = default_if_none(adfs_ca_bundle, adfs_config.adfs_ca_bundle)
    adfs_config.region = default_if_none(region, adfs_config.region)
    adfs_config.adfs_host = default_if_none(adfs_host, adfs_config.adfs_host)
    adfs_config.output_format = default_if_none(output_format, adfs_config.output_format)
    adfs_config.provider_id = default_if_none(provider_id, adfs_config.provider_id)
    adfs_config.s3_signature_version = default_if_none(
        s3_signature_version,
        adfs_config.s3_signature_version
    )
    adfs_config.session_duration = default_if_none(session_duration, adfs_config.session_duration)
    adfs_config.sspi = default_if_none(sspi, adfs_config.sspi)
    adfs_config.username_password_command = default_if_none(username_password_command, adfs_config.username_password_command)
    adfs_config.duo_factor = default_if_none(duo_factor, adfs_config.duo_factor)
    adfs_config.duo_device = default_if_none(duo_device, adfs_config.duo_device)
    adfs_config.aad_verification_code = aad_verification_code
    adfs_config.enforce_role_arn = enforce_role_arn

    return adfs_config


def create_adfs_default_config(profile):
    config = type('', (), {})()

    # Use botocore session API to get defaults
    session = _create_aws_session(profile)

    # region: The default AWS region that this script will connect
    # to for all API calls
    config.region = session.get_config_variable('region') or 'eu-central-1'

    # aws cli profile to store config and access keys into
    config.profile = session.profile or 'default'

    # output format: The AWS CLI output format that will be configured in the
    # adf profile (affects subsequent CLI calls)
    config.output_format = session.get_config_variable('format') or 'json'

    # aws credential location: The file where this script will store the temp
    # credentials under the configured profile
    config.aws_credentials_location = os.path.expanduser(session.get_config_variable('credentials_file'))
    config.aws_config_location = os.path.expanduser(session.get_config_variable('config_file'))

    # cookie location: The file where this script will store the ADFS session cookies
    config.adfs_cookie_location = os.path.join(os.path.dirname(config.aws_credentials_location), 'adfs_cookies')

    # SSL certificate verification: Whether or not strict certificate
    # verification is done, False should only be used for dev/test
    config.ssl_verification = True

    # Override CA bundle for SSL certificate verification for ADFS server only.
    config.adfs_ca_bundle = None

    # AWS role arn
    config.role_arn = None

    config.adfs_host = None

    config.adfs_user = None

    # aws provider id. (Optional - 9/10 times it will always be urn:amazon:websevices)
    config.provider_id = 'urn:amazon:webservices'

    # Note: if your bucket require CORS, it is advised that you use path style addressing
    # (which is set by default in signature version 4).
    config.s3_signature_version = None

    # AWS STS session duration, default is 3600 seconds
    config.session_duration = int(3600)

    # Whether SSPI is enabled
    config.sspi = system() == "Windows"

    # The command used to retrieve username and password information
    config.username_password_command = None

    # The specific Duo factor and device to use
    config.duo_factor = None
    config.duo_device = None

    return config


def _create_aws_session(profile):

    def _create_and_verify(profile_to_use=None):
        session = botocore.session.Session(profile=profile_to_use)
        session.get_config_variable('region')
        return session

    try:
        session = _create_and_verify(profile)
    except botocore.exceptions.ProfileNotFound:
        try:
            session = _create_and_verify('default')
        except botocore.exceptions.ProfileNotFound:
            session = _create_and_verify()

    return session


def _load_adfs_config_from_stored_profile(adfs_config, profile):

    def get_or(self, profile, option, default_value):
        if self.has_option(profile, option):
            return self.get(profile, option)
        return default_value

    def load_from_config(config_location, profile, loader):
        config = configparser.RawConfigParser()
        config.read(config_location)
        if config.has_section(profile):
            setattr(config, get_or.__name__, MethodType(get_or, config))
            loader(config, profile)

        del config

    def load_config(config, profile):
        adfs_config.region = config.get_or(profile, 'region', adfs_config.region)
        adfs_config.output_format = config.get_or(profile, 'output', adfs_config.output_format)
        adfs_config.ssl_verification = ast.literal_eval(config.get_or(
            profile, 'adfs_config.ssl_verification',
            str(adfs_config.ssl_verification)))
        adfs_config.role_arn = config.get_or(profile, 'adfs_config.role_arn', adfs_config.role_arn)
        adfs_config.adfs_host = config.get_or(profile, 'adfs_config.adfs_host', adfs_config.adfs_host)
        adfs_config.adfs_user = config.get_or(profile, 'adfs_config.adfs_user', adfs_config.adfs_user)
        adfs_config.provider_id = config.get_or(profile, 'adfs_config.provider_id', adfs_config.provider_id)

        adfs_config.s3_signature_version = None
        rawS3SubSection = config.get_or(profile, 's3', None)
        if rawS3SubSection:
            s3SubSection = configparser.RawConfigParser()
            setattr(s3SubSection, get_or.__name__, MethodType(get_or, s3SubSection))
            s3SubSection.read_string('[s3_section]\n' + rawS3SubSection)
            adfs_config.s3_signature_version = s3SubSection.get_or(
                's3_section',
                'signature_version',
                adfs_config.s3_signature_version
            )
        adfs_config.session_duration = config.get_or(
            profile, 'adfs_config.session_duration',
            adfs_config.session_duration)
        adfs_config.sspi = ast.literal_eval(config.get_or(
            profile, 'adfs_config.sspi',
            str(adfs_config.sspi)))
        adfs_config.username_password_command = config.get_or(profile, 'adfs_config.username_password_command', adfs_config.username_password_command)

        adfs_config.duo_factor = config.get_or(profile, "adfs_config.duo_factor", adfs_config.duo_factor)
        if adfs_config.duo_factor == "None":
            adfs_config.duo_factor = None
        adfs_config.duo_device = config.get_or(profile, "adfs_config.duo_device", adfs_config.duo_device)
        if adfs_config.duo_device == "None":
            adfs_config.duo_device = None

    if profile == 'default':
        load_from_config(adfs_config.aws_config_location, profile, load_config)
    else:
        load_from_config(adfs_config.aws_config_location, 'profile ' + profile, load_config)


def _create_base_aws_cli_config_files_if_needed(adfs_config):
    def touch(fname, mode=0o600):
        flags = os.O_CREAT | os.O_APPEND
        with os.fdopen(os.open(fname, flags, mode)) as f:
            try:
                os.utime(fname, None)
            finally:
                f.close()

    aws_config_root = os.path.dirname(adfs_config.aws_config_location)

    if not os.path.exists(aws_config_root):
        os.mkdir(aws_config_root, 0o700)

    if not os.path.exists(adfs_config.aws_credentials_location):
        touch(adfs_config.aws_credentials_location)

    aws_credentials_root = os.path.dirname(adfs_config.aws_credentials_location)

    if not os.path.exists(aws_credentials_root):
        os.mkdir(aws_credentials_root, 0o700)

    if not os.path.exists(adfs_config.aws_config_location):
        touch(adfs_config.aws_config_location)
