# -*- coding: utf-8 -*-

import logging
import sys

import click

from . import list_profiles
from . import login
from . import reset
from . import _version


def _print_version(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    click.echo(_version.get_versions()['version'])
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
@click.option(
    '-v', '--verbose',
    default=False,
    is_flag=True,
    help='Enables debug information on stdout. By default log level is set on ERROR'
)
def cli(verbose):
    log_format = '%(asctime)s [%(module)s %(filename)s:%(funcName)s] ' \
                 '[%(process)d-%(processName)s] [%(thread)d-%(threadName)s] ' \
                 '- %(levelname)s: %(message)s'
    logging.basicConfig(
        format=log_format,
        stream=sys.stderr,
        level=logging.DEBUG if verbose else logging.ERROR,
    )


cli.add_command(list_profiles.list_profiles)
cli.add_command(login.login)
cli.add_command(reset.reset)

