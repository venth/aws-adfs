import toml
from pathlib import Path

import aws_adfs
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

    def test_versions_are_in_sync(self):
        path = Path(__file__).resolve().parents[1] / "pyproject.toml"
        pyproject = toml.loads(open(str(path)).read())
        pyproject_version = pyproject["tool"]["poetry"]["version"]

        package_init_version = aws_adfs.__version__

        assert package_init_version == pyproject_version.replace("-alpha.", "a").replace("-beta.", "b").replace("-rc.", "rc")
