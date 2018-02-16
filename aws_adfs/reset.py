import configparser

import click

from .prepare import create_adfs_default_config


@click.command()
@click.option(
    '--profile',
    help='AWS cli profile that will be removed'
)
def reset(profile):
    """
    removes stored profile
    """
    adfs_config = create_adfs_default_config('default')
    _clear_credentials(adfs_config, profile)
    click.echo('Profile: \'{}\' has been wiped out'.format(profile))


def _clear_credentials(config, profile):
    def store_config(config_location, storer):
        config_file = configparser.RawConfigParser()
        config_file.read(config_location)

        if not config_file.has_section(profile):
            config_file.add_section(profile)

        storer(config_file)

        with open(config_location, 'w+') as f:
            try:
                config_file.write(f)
            finally:
                f.close()

    def profile_remover(config_file):
        config_file.remove_section(profile)
        config_file.remove_section('profile {}'.format(profile))

    store_config(config.aws_credentials_location, profile_remover)
    store_config(config.aws_config_location, profile_remover)
