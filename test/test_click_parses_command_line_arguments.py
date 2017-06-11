import sys

from aws_adfs import commands


class TestClickParsesCommandLineArguments:

    def test_parses_help_argument(self):
        # when executes aws-adfs --help
        sys.argv = ['aws-adfs', '--help']
        try:
            commands.cli()
        except SystemExit as e:
            # displays help description
            assert e.code == 0
