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
    if len(profiles) < 1:
        click.echo('No defined profiles')
    else:
        click.echo('Available profiles:')
        for profile in profiles:
            click.echo('    * {}'.format(profile))
