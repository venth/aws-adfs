import platform
import pytest
from aws_adfs import helpers


class TestHelpersMemsetZero:
    def test_helpers_memset_zero(self):
        if platform.python_implementation() != "CPython":
            pytest.skip(
                "Skipping memset_zero test because Python implementation is not CPython: {}".format(
                    platform.python_implementation()
                )
            )

        secret = "verysecretstring"
        copy = secret

        assert copy is secret

        helpers.memset_zero(secret)

        assert secret == "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        assert copy == "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        assert copy is secret
