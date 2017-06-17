from aws_adfs import authenticator
from aws_adfs.authenticator import html_roles_fetcher


class TestAuthenticator:

    def test_authenticated_and_second_factor_failure_returns_no_roles(self):
        # given an user with valid password
        valid_user = 'valid user'
        valid_password = 'valid password'

        authenticated_response = type('', (), {})()
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

        not_authenticated_response = type('', (), {})()
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

        forbidden_response = type('', (), {})()
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

        not_authenticated_response = type('', (), {})()
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

        forbidden_response = type('', (), {})()
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

        authenticated_response = type('', (), {})()
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
        # when aggregates iam roles by account
        authenticator._aggregate_roles_by_account_alias(session=self.http_session,
                                                        config=self.irrelevant_config,
                                                        username=self.valid_user,
                                                        password=self.valid_password,
                                                        assertion=self.valid_assertion,
                                                        principal_roles=extracted_iam_roles
                                                        )

        # then iam_roles are grouped by account alias
        for account_alias in expected_accounts.keys():
            assert principal_roles[account_alias] is not None
            for iam_role in expected_accounts[account_alias].keys():
                assert principal_roles[account_alias] is not None
                assert principal_roles[account_alias][iam_role] == expected_accounts[account_alias][iam_role]

    def setup_method(self):
        self.orignal_aggregate_method = authenticator._aggregate_roles_by_account_alias
        self.irrelevant_config = type('', (), {})()
        self.irrelevant_config.adfs_host = 'irrelevant host'
        self.irrelevant_config.adfs_cookie_location = 'irrelevant cookie location'
        self.irrelevant_config.ssl_verification = True
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

    def teardown_method(self):
        authenticator._aggregate_roles_by_account_alias = self.orignal_aggregate_method
