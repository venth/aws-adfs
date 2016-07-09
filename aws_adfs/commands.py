import click

from . import list_profiles
from . import login
from . import reset
from . import _version


def _print_version(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    click.echo(_version.__version__)
    ctx.exit()


@click.group()
@click.option(
    '--version',
    is_flag=True,
    callback=_print_version,
    expose_value=False,
    is_eager=True,
    help='Show current tool version'
)
def cli():
    pass


cli.add_command(list_profiles.list_profiles)
cli.add_command(login.login)
cli.add_command(reset.reset)
