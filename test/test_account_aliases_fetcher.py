from aws_adfs import account_aliases_fetcher


def _aws_account(account_alias, account_no):
    return u'<div class="saml-account-name">Account: {} ({})</div>'.format(account_alias, account_no)


def _account_page_response(accounts):
    response = type('', (), {})()
    response.text = u'''
    <html>
        <body>
            <div>
                <form>
                    <fieldset>
                        {}
                    </fieldset>
                </form>
            </div>
        </body>
    </html>
    '''.format('\n'.join([account for account in accounts]))

    return response


class TestAccountAliasesFetcher:
    
    def test_returns_empty_account_dictionary_when_no_account_are_named(self):
        # given user with no aws accounts
        self.authenticated_session.post = lambda *args, **kwargs: _account_page_response([])

        # when gets account aliases via fetcher
        accounts = account_aliases_fetcher.account_aliases(self.authenticated_session,
                                                           self.irrelevant_username,
                                                           self.irrelevant_password,
                                                           self.irrelevant_auth_method,
                                                           self.authenticated_saml_response,
                                                           self.irrelevant_config)
        # then returns no accounts
        assert accounts == {}

    def test_returns_one_account_when_one_account_is_listed(self):
        # given user with no aws accounts
        account_no = '123'
        account_alias = 'single'
        self.authenticated_session.post = lambda *args, **kwargs: _account_page_response([_aws_account(account_alias, account_no)])

        # when gets account aliases via fetcher
        accounts = account_aliases_fetcher.account_aliases(self.authenticated_session,
                                                           self.irrelevant_username,
                                                           self.irrelevant_password,
                                                           self.irrelevant_auth_method,
                                                           self.authenticated_saml_response,
                                                           self.irrelevant_config)
        # then returns no accounts
        assert accounts == {account_no: account_alias}

    def test_returns_two_accounts_when_two_accounts_are_listed(self):
        # given user with no aws accounts
        account_no = '1'
        account_alias = 'single'
        second_account_no = '2'
        second_account_alias = 'bingle'
        self.authenticated_session.post = lambda *args, **kwargs: _account_page_response([
            _aws_account(account_alias, account_no),
            _aws_account(second_account_alias, second_account_no),
        ])

        # when gets account aliases via fetcher
        accounts = account_aliases_fetcher.account_aliases(self.authenticated_session,
                                                           self.irrelevant_username,
                                                           self.irrelevant_password,
                                                           self.irrelevant_auth_method,
                                                           self.authenticated_saml_response,
                                                           self.irrelevant_config)
        # then returns no accounts
        assert accounts == {account_no: account_alias, second_account_no: second_account_alias}

    def setup_method(self, method):
        self.authenticated_session = type('', (), {})()
        self.irrelevant_auth_method = {}
        self.irrelevant_username = 'irrelevant username'
        self.irrelevant_password = 'irrelevant password'
        self.authenticated_saml_response = 'irrelevant saml response'
        self.irrelevant_config = type('', (), {})()
        self.irrelevant_config.ssl_verification = True
