import configparser

import click

from .prepare import create_adfs_default_config


@click.command(name='list')
def list_profiles():
    """
    lists available profiles
    """

    config = configparser.RawConfigParser()
    adfs_config = create_adfs_default_config('default')
    config.read(adfs_config.aws_config_location)

    profiles = config.sections()

    config.read(adfs_config.aws_config_location)

    if len(profiles) < 1:
        click.echo('No defined profiles')
    else:
        click.echo('Available profiles:')
        for profile in profiles:
            role_arn = config.get(
                profile,
                'adfs_config.role_arn',
                fallback=''
            )
            click.echo(' * {0:<30} | {1}'.format(profile, role_arn))
