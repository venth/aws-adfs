import configparser

import click

from .prepare import adfs_config


@click.command(name='list')
def list_profiles():
    """
    lists available profiles
    """

    config = configparser.RawConfigParser()
    config.read(adfs_config.aws_credentials_location)

    profiles = config.sections()

    config.read(adfs_config.aws_config_location)

    if len(profiles) < 1:
        click.echo('No defined profiles')
    else:
        click.echo('Available profiles:')
        for profile in profiles:
            role_arn = config.get(profile,'adfs_config.role_arn')
            click.echo(' * {} | {}'.format(profile, role_arn))
