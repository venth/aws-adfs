import logging

from aws_adfs import authenticator
from aws_adfs.authenticator import html_roles_fetcher
from aws_adfs.authenticator import account_aliases_fetcher


class AwsAccount:
    def __init__(self, account_no, account_name):
        self.account_no = account_no
        self.account_name = account_name


class AwsRole:
    def __init__(self, account, role_name):
        self.role_name = role_name
        self.principal_arn = 'arn:aws:iam::{}:saml-provider/ADFS'.format(account.account_no)
        self.role_arn = 'arn:aws:iam::{}:role/{}'.format(account.account_no, role_name)


class TestAuthenticator:

    def test_authenticated_and_second_factor_failure_returns_no_roles(self):
        # given an user with valid password
        valid_user = 'valid user'
        valid_password = 'valid password'

        authenticated_response = self._http_response()
        authenticated_response.status_code = 200
        html_roles_fetcher.fetch_html_encoded_roles = lambda **kwargs: \
            (authenticated_response, self.http_session)

        # and there was second factor authentication failure
        authenticator._strategy = (
            lambda *args: (
                lambda: (self.empty_principal_roles,
                         self.empty_assertion,
                         self.irrelevant_session_duration)
            )
        )

        # when calls authenticator
        principal_roles, _, _ = authenticator.authenticate(self.irrelevant_config,
                                                           valid_user,
                                                           valid_password)

        # then there are no principal roles
        assert principal_roles is None

    def test_not_authenticated_returns_no_roles(self):
        # given an user with invalid password or just invalid user
        invalid_user = 'invalid user'
        invalid_password = 'invalid password'

        not_authenticated_response = self._http_response()
        not_authenticated_response.status_code = 403
        html_roles_fetcher.fetch_html_encoded_roles = lambda **kwargs: \
            (not_authenticated_response, self.http_session)

        authenticator._strategy = (
            lambda *args: (
                lambda: (self.empty_principal_roles,
                         self.empty_assertion,
                         self.irrelevant_session_duration)
            )
        )

        forbidden_response = self._http_response()
        forbidden_response.status_code = 403
        self.http_session.post = lambda *args, **kwargs: forbidden_response

        # when calls authenticator
        principal_roles, _, _ = authenticator.authenticate(self.irrelevant_config,
                                                           invalid_user,
                                                           invalid_password)

        # then there are no principal roles
        assert principal_roles is None

    def test_not_authenticated_returns_no_assertion(self):
        # given an user with invalid password or just invalid user
        invalid_user = 'invalid user'
        invalid_password = 'invalid password'

        not_authenticated_response = self._http_response()
        not_authenticated_response.status_code = 403
        html_roles_fetcher.fetch_html_encoded_roles = lambda **kwargs: \
            (not_authenticated_response, self.http_session)

        authenticator._strategy = (
            lambda *args: (
                lambda: (self.empty_principal_roles,
                         self.empty_assertion,
                         self.irrelevant_session_duration)
            )
        )

        forbidden_response = self._http_response()
        forbidden_response.status_code = 403
        self.http_session.post = lambda *args, **kwargs: forbidden_response

        # when calls authenticator
        _, assertion, _ = authenticator.authenticate(self.irrelevant_config,
                                                     invalid_user,
                                                     invalid_password)

        # then
        assert assertion is None

    def test_returns_aws_roles_allowed_for_an_user_along_with_account_alias(self):
        # given a valid user
        valid_user = 'valid user'
        valid_password = 'valid password'

        authenticated_response = self._http_response()
        authenticated_response.status_code = 200
        self.http_session.post = lambda *args, **kwargs: authenticated_response
        html_roles_fetcher.fetch_html_encoded_roles = lambda **kwargs: \
            (authenticated_response, self.http_session)

        authenticator._strategy = (
            lambda *args: (
                lambda: (self.valid_principal_roles,
                         self.valid_assertion,
                         self.irrelevant_session_duration)
            )
        )

        # and its accounts
        expected_roles_cases = [
            {
                'account1': {'iam_arn1': 'role_name1'},
            },
            {
                'account1': {'iam_arn1': 'role_name1'},
                'account2': {'iam_arn2': 'role_name2'},
            },
            {
                'account1': {'iam_arn1': 'role_name1', 'iam_arn2': 'role_name2'},
                'account2': {'iam_arn2': 'role_name2'},
            },
        ]

        for expected_roles in expected_roles_cases:
            authenticator._aggregate_roles_by_account_alias = lambda *args: expected_roles

            # when calls authenticator
            principal_roles, _, _ = authenticator.authenticate(self.irrelevant_config,
                                                               valid_user,
                                                               valid_password)

            # then there are aim roles
            assert principal_roles is not None

            # and they equals expected ones
            assert principal_roles == expected_roles

    def test_groups_iam_roles_by_account_alias(self):
        # given
        account1 = AwsAccount('9999', 'account1')
        aws_role1 = AwsRole(account=account1, role_name='role1')
        aws_role2 = AwsRole(account=account1, role_name='role2')

        account2 = AwsAccount('8888', 'account2')
        aws_role3 = AwsRole(account=account2, role_name='role3')

        arn_principal_account1 = 'arn:aws:iam::9999:saml-provider/ADFS'
        arn_role1 = 'arn:aws:iam::9999:role/role1'

        arn_principal_account2 = 'arn:aws:iam::8888:saml-provider/ADFS'
        arn_role3 = 'arn:aws:iam::8888:role/role3'
        extracted_iam_roles_scenarios = {
            'there are no iam roles': {
                'extracted_iam_roles': [],
                'expected_accounts': {},
                'aliases': {},
            },
            'one account with one role': {
                'extracted_iam_roles': [
                    [aws_role1.principal_arn, aws_role1.role_arn],
                ],
                'expected_accounts': {
                    account1.account_name: {
                        aws_role1.role_arn: {'name': aws_role1.role_name, 'principal_arn': aws_role1.principal_arn},
                    }
                },
                'aliases': {
                    account1.account_no: account1.account_name
                },
            },
            'one account with 2 roles': {
                'extracted_iam_roles': [
                    [aws_role1.principal_arn, aws_role1.role_arn],
                    [aws_role2.principal_arn, aws_role2.role_arn],
                ],
                'expected_accounts': {
                    account1.account_name: {
                        aws_role1.role_arn: {'name': aws_role1.role_name, 'principal_arn': aws_role1.principal_arn},
                        aws_role2.role_arn: {'name': aws_role2.role_name, 'principal_arn': aws_role2.principal_arn},
                    }
                },
                'aliases': {
                    '9999': 'account1'
                },
            },
            'one account with 2 roles and no aliases': {
                'extracted_iam_roles': [
                    [aws_role1.principal_arn, aws_role1.role_arn],
                    [aws_role2.principal_arn, aws_role2.role_arn],
                ],
                'expected_accounts': {
                    account1.account_no: {
                        aws_role1.role_arn: {'name': aws_role1.role_name, 'principal_arn': aws_role1.principal_arn},
                        aws_role2.role_arn: {'name': aws_role2.role_name, 'principal_arn': aws_role2.principal_arn},
                    }
                },
                'aliases': {},
            },
            '2 accounts with 1 role in each of them': {
                'extracted_iam_roles': [
                    [arn_principal_account1, arn_role1],
                    [arn_principal_account2, arn_role3],
                ],
                'expected_accounts': {
                    account1.account_name: {
                        aws_role1.role_arn: {'name': aws_role1.role_name, 'principal_arn': aws_role1.principal_arn},
                    },
                    account2.account_name: {
                        aws_role3.role_arn: {'name': aws_role3.role_name, 'principal_arn': aws_role3.principal_arn},
                    }
                },
                'aliases': {
                    account1.account_no: account1.account_name,
                    account2.account_no: account2.account_name,
                },
            },
            '2 accounts with 1 role in each of them and only first one of the account has alias name ': {
                'extracted_iam_roles': [
                    [arn_principal_account1, arn_role1],
                    [arn_principal_account2, arn_role3],
                ],
                'expected_accounts': {
                    account1.account_name: {
                        aws_role1.role_arn: {'name': aws_role1.role_name, 'principal_arn': aws_role1.principal_arn},
                    },
                    account2.account_no: {
                        aws_role3.role_arn: {'name': aws_role3.role_name, 'principal_arn': aws_role3.principal_arn},
                    }
                },
                'aliases': {
                    account1.account_no: account1.account_name,
                },
            },
        }

        for scenario_name in extracted_iam_roles_scenarios.keys():
            logging.info('=============> Scenario: %s'.format(scenario_name))
            scenario_params = extracted_iam_roles_scenarios[scenario_name]
            account_aliases_fetcher.account_aliases = lambda *args: scenario_params['aliases']
            # when aggregates iam roles by account
            extracted_iam_roles = scenario_params['extracted_iam_roles']
            principal_roles = authenticator._aggregate_roles_by_account_alias(
                session=self.http_session,
                config=self.irrelevant_config,
                username=self.valid_user,
                password=self.valid_password,
                assertion=self.valid_assertion,
                principal_roles=extracted_iam_roles
            )

            # then iam_roles are grouped by account alias
            expected_accounts = scenario_params['expected_accounts']
            assert len(principal_roles.keys()) == len(expected_accounts.keys()), 'scenario name: {}'.format(scenario_name)

            for account_alias in expected_accounts.keys():
                assert account_alias in principal_roles, 'scenario name: {}'.format(scenario_name)
                for iam_role in expected_accounts[account_alias].keys():
                    assert principal_roles[account_alias][iam_role] == \
                           expected_accounts[account_alias][iam_role], 'scenario name: {}'.format(scenario_name)

    def _http_response(self):
        response = type('', (), {})()
        response.url = u'irrelevant_url'
        response.request = type('', (), {})()
        response.request.headers = {}
        response.headers = {}
        response.text = u'irrelevant response body'
        return response

    def setup_method(self, method):
        self.original_fetch_html_encoded_roles = html_roles_fetcher.fetch_html_encoded_roles
        self.orignal_account_aliases = account_aliases_fetcher.account_aliases
        self.orignal_aggregate_method = authenticator._aggregate_roles_by_account_alias
        self.irrelevant_config = type('', (), {})()
        self.irrelevant_config.adfs_host = 'irrelevant host'
        self.irrelevant_config.adfs_cookie_location = 'irrelevant cookie location'
        self.irrelevant_config.ssl_verification = True
        self.irrelevant_config.adfs_ca_bundle = None
        self.irrelevant_config.provider_id = 'irrelevant provider identifier'

        self.http_session = type('', (), {})()
        self.http_session.post = lambda *args, **kwargs: None

        self.empty_principal_roles = None
        self.empty_assertion = None
        self.valid_principal_roles = []
        self.valid_assertion = {}
        self.irrelevant_session_duration = None

        self.valid_user = 'valid user'
        self.valid_password = 'valid password'

    def teardown_method(self, method):
        authenticator._aggregate_roles_by_account_alias = self.orignal_aggregate_method
        account_aliases_fetcher.account_aliases = self.orignal_account_aliases
        html_roles_fetcher.fetch_html_encoded_roles = self.original_fetch_html_encoded_roles
