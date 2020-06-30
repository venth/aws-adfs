import datetime
import json
from aws_adfs import login
from mock import patch


class TestCredentialProcesJson:

    def setup_method(self, method):
        self.access_key = 'AKIAIOSFODNN7EXAMPLE'
        self.secret_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY'
        self.session_token = 'AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQWLWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGdQrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU9HFvlRd8Tx6q6fE8YQcHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz+scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA=='
        self.expiration = '2020-06-30T20:17:02.439725+00:00'

        self.aws_session_token = {
            'Credentials': {
                'AccessKeyId': self.access_key,
                'SecretAccessKey': self.secret_key,
                'SessionToken': self.session_token,
                'Expiration': self.expiration
            }
        }

    def _replace_echo(self, value):
        return value

    def test_json_includes_version_1(self):
        with patch('click.echo', side_effect = self._replace_echo) as fake_out:
            login._emit_json(self.aws_session_token)

            result = json.loads(fake_out.call_args_list[0].args[0])

            # Version is currently hardlocked at 1, see https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html
            assert result["Version"] == 1
    
    def test_json_has_access_key(self):
        with patch('click.echo', side_effect = self._replace_echo) as fake_out:
            login._emit_json(self.aws_session_token)

            result = json.loads(fake_out.call_args_list[0].args[0])

            assert result["AccessKeyId"] == self.access_key

    def test_json_has_secret_key(self):
        with patch('click.echo', side_effect = self._replace_echo) as fake_out:
            login._emit_json(self.aws_session_token)

            result = json.loads(fake_out.call_args_list[0].args[0])

            assert result["SecretAccessKey"] == self.secret_key

    def test_json_has_session_token(self):
        with patch('click.echo', side_effect = self._replace_echo) as fake_out:
            login._emit_json(self.aws_session_token)

            result = json.loads(fake_out.call_args_list[0].args[0])

            assert result["SessionToken"] == self.session_token

    def test_json_has_valid_expiration(self):
        with patch('click.echo', side_effect = self._replace_echo) as fake_out:
            login._emit_json(self.aws_session_token)

            result = json.loads(fake_out.call_args_list[0].args[0])

            # Expiration must be a , see https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html
            assert result["Expiration"] == self.expiration
