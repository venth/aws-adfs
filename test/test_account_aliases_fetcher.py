from aws_adfs import account_aliases_fetcher


def _aws_account(account_alias, account_no):
    return u'<div class="saml-account-name">Account: {} ({})</div>'.format(account_alias, account_no)


def _aws_account_without_alias(account_no):
    return u'<div class="saml-account-name">Account: {}</div>'.format(account_no)


def _account_page_response_text(response_text):
    response = type('', (), {})()
    response.request = type('', (), {})()
    response.request.headers = {}
    response.status_code = 'irrelevant'
    response.headers = {}
    response.text = response_text

    return response


def _account_page_response(accounts):
    return _account_page_response_text(u'''
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
    )


def _failed_account_page_response():
    return _account_page_response_text(u'<html></html>')


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

    def test_returns_accounts_expected_for_real_case_response(self):
        # given response with accounts
        response_text, expected_accounts = self._response_with_expected_aliases()
        self.authenticated_session.post = lambda *args, **kwargs: _account_page_response_text(response_text)

        # when gets account aliases via fetcher
        accounts = account_aliases_fetcher.account_aliases(self.authenticated_session,
                                                           self.irrelevant_username,
                                                           self.irrelevant_password,
                                                           self.irrelevant_auth_method,
                                                           self.authenticated_saml_response,
                                                           self.irrelevant_config)

        # then account numbers matches
        assert accounts.keys() == expected_accounts.keys()

    def test_returns_two_accounts_expected_for_real_case_response(self):
        # given response with accounts
        response_text, expected_accounts = self._response_with_two_expected_aliases()
        self.authenticated_session.post = lambda *args, **kwargs: _account_page_response_text(response_text)

        # when gets account aliases via fetcher
        accounts = account_aliases_fetcher.account_aliases(self.authenticated_session,
                                                           self.irrelevant_username,
                                                           self.irrelevant_password,
                                                           self.irrelevant_auth_method,
                                                           self.authenticated_saml_response,
                                                           self.irrelevant_config)

        # then account numbers matches
        assert accounts.keys() == expected_accounts.keys()

    def test_returns_no_aliases_when_the_call_for_aliases_failed(self):
        # given failed response
        self.authenticated_session.post = lambda *args, **kwargs: _failed_account_page_response()

        # when gets account aliases via fetcher
        accounts = account_aliases_fetcher.account_aliases(self.authenticated_session,
                                                           self.irrelevant_username,
                                                           self.irrelevant_password,
                                                           self.irrelevant_auth_method,
                                                           self.authenticated_saml_response,
                                                           self.irrelevant_config)
        # then there are no aliases
        assert accounts == {}

    def test_returns_full_saml_name_account_when_no_account_alias_is_provided(self):
        # given aws account without alias
        account_no = '123123'
        full_account_name = 'Account: {}'.format(account_no)
        self.authenticated_session.post = lambda *args, **kwargs: _account_page_response([
            _aws_account_without_alias(account_no)
        ])

        # when gets account aliases via fetcher
        accounts = account_aliases_fetcher.account_aliases(self.authenticated_session,
                                                           self.irrelevant_username,
                                                           self.irrelevant_password,
                                                           self.irrelevant_auth_method,
                                                           self.authenticated_saml_response,
                                                           self.irrelevant_config)
        # then uses full account name as the alias
        assert accounts == {account_no: full_account_name}

    def _response_with_expected_aliases(self):
        return u'''
        <html>
        <body>

<div id="container">

  <h1 class="background">Amazon Web Services Login</h1>

  <div id="content">

  <div id="main_error"></div>

  <form id="saml_form" name="saml_form" action="/saml" method="post">
          <input type="hidden" name="RelayState" value="" />
          <input type="hidden" name="SAMLResponse" value="valueofSAMLRESPONSE" />
          <input type="hidden" name="name" value="" />
          <input type="hidden" name="portal" value="" />
          <p style="font-size: 16px; padding-left: 20px;">Select a role:</p>
          <fieldset>
            <div  class="saml-account"> <div onClick="expandCollapse(0);">
              <img id="image0" src="/static/image/down.png" valign="middle"></img>
              <div class="saml-account-name">Account: mydomain-account3 (123456789012)</div>
              </div>
              <hr style="border: 1px solid #ddd;">
              <div id="0" class="saml-account" >
                <div class="saml-role" onClick="checkRadio(this);">
                    <input type="radio" name="roleIndex" value="arn:aws:iam::123456789012:role/ADFS-CloudSearchManager" class="saml-radio" id="arn:aws:iam::123456789012:role/ADFS-CloudSearchManager" />
                    <label for="arn:aws:iam::123456789012:role/ADFS-CloudSearchManager" class="saml-role-description">ADFS-CloudSearchManager</label>
                    <span style="clear: both;"></span>
                </div>
                 </div></div><div  class="saml-account"> <div onClick="expandCollapse(1);">
              <img id="image1" src="/static/image/down.png" valign="middle"></img>
              <div class="saml-account-name">Account: mydomain-account2 (223456789012)</div>
              </div>
              <hr style="border: 1px solid #ddd;">
              <div id="1" class="saml-account" >
                <div class="saml-role" onClick="checkRadio(this);">
                    <input type="radio" name="roleIndex" value="arn:aws:iam::223456789012:role/ADFS-CloudSearchManager" class="saml-radio" id="arn:aws:iam::223456789012:role/ADFS-CloudSearchManager" />
                    <label for="arn:aws:iam::223456789012:role/ADFS-CloudSearchManager" class="saml-role-description">ADFS-CloudSearchManager</label>
                    <span style="clear: both;"></span>
                </div>
                 </div></div><div  class="saml-account"> <div onClick="expandCollapse(2);">
              <img id="image2" src="/static/image/down.png" valign="middle"></img>
              <div class="saml-account-name">Account: mydomain-account1 (323456789012)</div>
              </div>
              <hr style="border: 1px solid #ddd;">
              <div id="2" class="saml-account" >
                <div class="saml-role" onClick="checkRadio(this);">
                    <input type="radio" name="roleIndex" value="arn:aws:iam::323456789012:role/ADFS-Administrator" class="saml-radio" id="arn:aws:iam::323456789012:role/ADFS-Administrator" />
                    <label for="arn:aws:iam::323456789012:role/ADFS-Administrator" class="saml-role-description">ADFS-Administrator</label>
                    <span style="clear: both;"></span>
                </div>

                <div class="saml-role" onClick="checkRadio(this);">
                    <input type="radio" name="roleIndex" value="arn:aws:iam::323456789012:role/ADFS-EMRManager" class="saml-radio" id="arn:aws:iam::323456789012:role/ADFS-EMRManager" />
                    <label for="arn:aws:iam::323456789012:role/ADFS-EMRManager" class="saml-role-description">ADFS-EMRManager</label>
                    <span style="clear: both;"></span>
                </div>
                 </div></div><div  class="saml-account"> <div onClick="expandCollapse(3);">
              <img id="image3" src="/static/image/down.png" valign="middle"></img>
              <div class="saml-account-name">Account: 423456789012</div>
              </div>
              <hr style="border: 1px solid #ddd;">
              <div id="3" class="saml-account" >
                <div class="saml-role" onClick="checkRadio(this);">
                    <input type="radio" name="roleIndex" value="arn:aws:iam::423456789012:role/ADFS-Administrator" class="saml-radio" id="arn:aws:iam::423456789012:role/ADFS-Administrator" />
                    <label for="arn:aws:iam::423456789012:role/ADFS-Administrator" class="saml-role-description">ADFS-Administrator</label>
                    <span style="clear: both;"></span>
                </div>
                 </div></div>
          </fieldset>

          <br>
          <div class="buttoninput" id="input_signin_button">
              <a id="signin_button" class="css3button" href="#" alt="Continue" value="Continue">Sign In</a>
          </div>

  </form>
  </div>
  </body>
  </html>
        ''', {
            '123456789012': 'mydomain-account3',
            '223456789012': 'mydomain-account2',
            '323456789012': 'mydomain-account1',
            '423456789012': '423456789012',
        }

    def _response_with_two_expected_aliases(self):
        return u'''
        <html>
        <body>

<div id="container">

  <h1 class="background">Amazon Web Services Login</h1>

  <div id="content">

  <div id="main_error"></div>

  <form id="saml_form" name="saml_form" action="/saml" method="post">
          <input type="hidden" name="RelayState" value="" />
          <input type="hidden" name="SAMLResponse" value="valueofSAMLRESPONSE" />
          <input type="hidden" name="name" value="" />
          <input type="hidden" name="portal" value="" />
          <p style="font-size: 16px; padding-left: 20px;">Select a role:</p>
<fieldset>
            <div  class="saml-account"> <div onClick="expandCollapse(0);">
              <img id="image0" src="/static/image/down.png" valign="middle"></img>
              <div class="saml-account-name">Account: zefr (123456789012)</div>
              </div>
              <hr style="border: 1px solid #ddd;">
              <div id="0" class="saml-account" >  
                <div class="saml-role" onClick="checkRadio(this);">
                    <input type="radio" name="roleIndex" value="arn:aws:iam::123456789012:role/CORP-ROLE1" class="saml-radio" id="arn:aws:iam::123456789012:role/CORP-ROLE1" />
                    <label for="arn:aws:iam::123456789012:role/CORP-ROLE1" class="saml-role-description">CORP-ROLE1</label>
                    <span style="clear: both;"></span>
                </div>
                
                <div class="saml-role" onClick="checkRadio(this);">
                    <input type="radio" name="roleIndex" value="arn:aws:iam::123456789012:role/CORP-ROLE2" class="saml-radio" id="arn:aws:iam::123456789012:role/CORP-ROLE2" />
                    <label for="arn:aws:iam::123456789012:role/CORP-ROLE2" class="saml-role-description">CORP-ROLE2</label>
                    <span style="clear: both;"></span>
                </div>
                 </div></div>
          </fieldset>
          <br>
          <div class="buttoninput" id="input_signin_button">
              <a id="signin_button" class="css3button" href="#" alt="Continue" value="Continue">Sign In</a>
          </div>

  </form>
  </div>
  </body>
  </html>
        ''', {
            '123456789012': 'zefr',
        }

    def setup_method(self, method):
        self.authenticated_session = type('', (), {})()
        self.irrelevant_auth_method = {}
        self.irrelevant_username = 'irrelevant username'
        self.irrelevant_password = 'irrelevant password'
        self.authenticated_saml_response = 'irrelevant saml response'
        self.irrelevant_config = type('', (), {})()
        self.irrelevant_config.ssl_verification = True
