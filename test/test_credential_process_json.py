import datetime
import json
from aws_adfs import login
from unittest.mock import patch


class TestCredentialProcessJson:

    def setup_method(self, method):
        self.access_key = 'AKIAIOSFODNN7EXAMPLE'
        self.secret_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY'
        self.session_token = 'AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQWLWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGdQrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU9HFvlRd8Tx6q6fE8YQcHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz+scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA=='
        self.expiration = datetime.datetime(2020,6,20)

        self.aws_session_token = {
            'Credentials': {
                'AccessKeyId': self.access_key,
                'SecretAccessKey': self.secret_key,
                'SessionToken': self.session_token,
                'Expiration': self.expiration
            }
        }

    capture = ''
    def _replace_echo(self, value):
        self.capture = value

    def test_json_is_valid_credential_process_format(self):
        with patch('click.echo', side_effect = self._replace_echo):
            login._emit_json(self.aws_session_token)

            result = json.loads(self.capture)
            print(result)

            # Version is currently hardlocked at 1, see https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html
            assert result["Version"] == 1
            assert result["AccessKeyId"] == self.access_key
            assert result["SecretAccessKey"] == self.secret_key
            assert result["SessionToken"] == self.session_token
            # Expiration must be ISO8601, see https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html
            assert result["Expiration"] == self.expiration.isoformat()
