import ast
import ConfigParser
import os
from types import MethodType


def get_prepared_config(
        profile,
        region,
        ssl_verification,
        adfs_host,
        rsa_keys,
        output_format,
):
    """
    Prepares ADF configuration for login task.
    The task comprises steps as follows:
        - default configuration preparation,
        - creating aws cli configuration files, if needed
        - loading adf configuration for specified aws profiles
    The configuration is stored in ctx.adfs_config attribute
    :param output_format: output format used by aws cli
    :param rsa_keys: rsa keys used to decrypt / entrypt user's credentials
    :param adfs_host: fqdn of adfs host that will be used to authenticate user
    :param ssl_verification: SSL certificate verification: Whether or not strict certificate
                             verification is done, False should only be used for dev/test
    :param region: The default AWS region that this script will connect
                   to for all API calls
    :param profile: aws cli profile
    """
    adfs_config.profile = profile
    adfs_config.ssl_verification = ssl_verification
    adfs_config.region = region
    adfs_config.adfs_host = adfs_host
    adfs_config.id_rsa_location = rsa_keys[0]
    adfs_config.id_rsa_pub_location = rsa_keys[1]
    adfs_config.output_format = output_format
    _create_base_aws_cli_config_files_if_needed(adfs_config)
    _load_adfs_config_from_stored_profile(adfs_config, profile)

    return adfs_config


def _create_adfs_default_config():
    config = type('', (), {})()
    # region: The default AWS region that this script will connect
    # to for all API calls
    config.region = 'eu-central-1'

    # aws cli profile
    config.profile = 'adfs'

    # output format: The AWS CLI output format that will be configured in the
    # adf profile (affects subsequent CLI calls)
    config.output_format = 'json'

    # aws credential location: The file where this script will store the temp
    # credentials under the configured profile
    config.aws_config_root = os.path.join(os.path.expanduser('~'), '.aws')
    config.aws_credentials_location = os.path.join(config.aws_config_root, 'credentials')
    config.aws_config_location = os.path.join(config.aws_config_root, 'config')

    # rsa identity file location used to decrypt / encrypt password for storage purposes
    config.id_rsa_root = os.path.join(os.path.expanduser('~'), '.ssh')
    config.id_rsa_location = os.path.join(config.id_rsa_root, 'id_rsa')
    config.id_rsa_pub_location = os.path.join(config.id_rsa_root, 'id_rsa.pub')

    # SSL certificate verification: Whether or not strict certificate
    # verification is done, False should only be used for dev/test
    config.ssl_verification = True

    # AWS role arn
    config.role_arn = None

    config.adfs_host = None

    config.adfs_user = None
    config.adfs_password = None
    config.adfs_credentials_loaded = False

    return config


def _load_adfs_config_from_stored_profile(adfs_config, profile):
    def load_from_config(config_location, profile, loader):
        config = ConfigParser.RawConfigParser()
        config.read(config_location)
        if config.has_section(profile):
            def get_or(self, profile, option, default_value):
                if self.has_option(profile, option):
                    return self.get(profile, option)
                return default_value

            setattr(config, get_or.__name__, MethodType(get_or, config, type(config)))
            loader(config, profile)

        del config

    def load_credentials(config, profile):
        adfs_config.adfs_user = config.get_or(profile, 'adfs_config.adfs_user', None)
        adfs_config.adfs_password = config.get_or(profile, 'adfs_config.adfs_password', None)
        adfs_config.id_rsa_location = config.get_or(profile, 'adfs_config.id_rsa_location', adfs_config.id_rsa_location)
        if type(adfs_config.id_rsa_location) is not file:
            adfs_config.id_rsa_location = file(adfs_config.id_rsa_location)
        adfs_config.id_rsa_pub_location = config.get_or(profile, 'adfs_config.id_rsa_pub_location', adfs_config.id_rsa_pub_location)
        if type(adfs_config.id_rsa_pub_location) is not file:
            adfs_config.id_rsa_pub_location = file(adfs_config.id_rsa_pub_location)

        adfs_config.adfs_credentials_loaded = adfs_config.adfs_user and adfs_config.adfs_password

    def load_config(config, profile):
        adfs_config.region = config.get_or(profile, 'region', adfs_config.region)
        adfs_config.output_format = config.get_or(profile, 'output', adfs_config.output_format)
        adfs_config.ssl_verification = ast.literal_eval(config.get_or(
            profile, 'adfs_config.ssl_verification',
            adfs_config.ssl_verification))
        adfs_config.role_arn = config.get_or(profile, 'adfs_config.role_arn', adfs_config.role_arn)
        adfs_config.adfs_host = config.get_or(profile, 'adfs_config.adfs_host', adfs_config.adfs_host)

    load_from_config(adfs_config.aws_credentials_location, profile, load_credentials)
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

    if not os.path.exists(adfs_config.aws_config_root):
        os.mkdir(adfs_config.aws_config_root, 0o700)

    if not os.path.exists(adfs_config.aws_credentials_location):
        touch(adfs_config.aws_credentials_location)

    if not os.path.exists(adfs_config.aws_config_location):
        touch(adfs_config.aws_config_location)


adfs_config = _create_adfs_default_config()
