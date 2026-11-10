from aws_adfs import role_chooser
from aws_adfs.role_chooser import click
import pytest


def _config():
    config = type('', (), {})()
    config.role_arn = 'irrelevant_role'
    config.enforce_role_arn = False
    return config


def _two_roles():
    return {
        'awesome_account': {
            'first_role_arn': {'name': 'first', 'principal_arn': 'first_principal'},
        },
        'second_account': {
            'second_role_arn': {'name': 'second', 'principal_arn': 'second_principal'},
        },
    }


def test_selection_range_excludes_out_of_bounds_index(monkeypatch):
    # the prompt must only accept 0..len(roles)-1:
    # index len(roles) would crash with IndexError
    captured = {}

    def fake_prompt(**kwargs):
        captured.update(kwargs)
        return 0

    monkeypatch.setattr(click, 'prompt', fake_prompt)
    role_chooser.choose_role_to_assume(config=_config(), principal_roles=_two_roles())

    offered = captured['type']
    assert offered.min == 0
    assert offered.max == 1
    with pytest.raises(click.BadParameter):
        offered.convert('2', None, None)
