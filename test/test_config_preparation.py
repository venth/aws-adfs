import mock

from aws_adfs import prepare


class TestConfigPreparation:

    def test_when_there_is_no_profile_use_default_values(self):
        # given profile to read the configuration doesn't exist
        not_existing_profile = 'not_existing_profile'
        prepare.configparser = mock.Mock()
        config_without_non_existing_profile = mock.Mock()
        prepare.configparser.RawConfigParser = mock.Mock(return_value=config_without_non_existing_profile)
        config_without_non_existing_profile.has_section = mock.Mock(return_value=False)

        # and defaults are setup as follows
        default_ssl_config = True
        default_adfs_ca_bundle = None
        default_region = 'default_region'
        default_adfs_host = 'default_adfs_host'
        default_output_format = 'default_output_format'
        default_provider_id = 'default_provider_id'
        default_s3_signature_version = None
        default_session_duration = 3600

        # when configuration is prepared for not existing profile
        adfs_config = prepare.get_prepared_config(
            not_existing_profile,
            default_region,
            default_ssl_config,
            default_adfs_ca_bundle,
            default_adfs_host,
            default_output_format,
            default_provider_id,
            default_s3_signature_version,
            default_session_duration,
        )

        # then resolved config contains defaults values
        assert default_ssl_config == adfs_config.ssl_verification
        assert default_adfs_ca_bundle == adfs_config.adfs_ca_bundle
        assert default_region == adfs_config.region
        assert default_adfs_host == adfs_config.adfs_host
        assert default_output_format == adfs_config.output_format
        assert default_session_duration == adfs_config.session_duration

    def test_when_the_profile_exists_but_lacks_ssl_verification_use_default_value(self):
        # given profile to read the configuration exists
        empty_profile = 'empty_profile'
        prepare.configparser = mock.Mock()
        config_with_the_empty_profile = mock.Mock()
        prepare.configparser.RawConfigParser = mock.Mock(return_value=config_with_the_empty_profile)
        config_with_the_empty_profile.has_section = mock.Mock(return_value=True)

        # and no options are stored in the profile
        config_with_the_empty_profile.has_option = mock.Mock(return_value=False)

        # and defaults are setup as follows
        default_ssl_config = True
        default_adfs_ca_bundle = None
        irrelevant_region = 'irrelevant_region'
        irrelevant_adfs_host = 'irrelevant_adfs_host'
        irrelevant_output_format = 'irrelevant_output_format'
        irrelevant_provider_id = 'irrelevant_provider_id'
        irrelevant_s3_signature_version = 'irrelevant_s3_signature_version'
        irrelevant_session_duration = 'irrelevant_session_duration'

        # when configuration is prepared for existing profile
        adfs_config = prepare.get_prepared_config(
            empty_profile,
            irrelevant_region,
            default_ssl_config,
            default_adfs_ca_bundle,
            irrelevant_adfs_host,
            irrelevant_output_format,
            irrelevant_provider_id,
            irrelevant_s3_signature_version,
            irrelevant_session_duration,
        )

        # then resolved ssl verification holds the default value
        assert default_ssl_config == adfs_config.ssl_verification
        assert default_adfs_ca_bundle == adfs_config.adfs_ca_bundle
