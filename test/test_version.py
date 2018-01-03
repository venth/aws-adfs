from aws_adfs import commands


class TestVersion:

    def test_returns_version(self):
        # given

        # when
        try:
            result = commands.cli(['--version'])
            assert False
        except SystemExit as e:
            # then
            assert e.code == 0