import click

from . import list_profiles
from . import login
from . import reset


@click.group()
def cli():
    pass


cli.add_command(list_profiles.list_profiles)
cli.add_command(login.login)
cli.add_command(reset.reset)
