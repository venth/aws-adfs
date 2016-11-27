import base64

import lxml.etree as ET
import pytest

from aws_adfs import roles_assertion_extractor


class TestAssertionExtractor:

    def test_login_error_causes_error_and_exit(self, capsys):
        # given login page after authentication failure
        login_error_page_result = self._a_page_of_authentication_failure()

        # Error is printed and exit is called
        with pytest.raises(SystemExit):
            # when a login page after failed authentication is extracted
            roles_assertion_extractor.extract(login_error_page_result)

        out, err = capsys.readouterr()
        assert err.startswith("Login error: Incorrect user ID or password")

    def test_missing_saml_assertion_causes_to_return_nothing(self):
        # when a returned result page doesn't contain saml (perhaps session expired)
        roles, assertion, _ = roles_assertion_extractor.extract(self._a_page_of_expired_login())

        # the return nothing - perhaps re-authentication is needed
        assert roles is None
        assert assertion is None

    def test_beer_roles_are_extracted(self):
        # when after successful authentication adfs responded with page containing available roles
        roles, assertion, _ = roles_assertion_extractor.extract(self.a_page_of_allowed_beer_roles())

        # then two beer roles are extracted
        assert len(roles) == 2
        assert assertion is not None

    def test_provides_existing_in_response_session_duration(self):
        # adfs has configured aws session duration
        session_duration_configured_in_adfs = 7200

        # when after successful authentican adfs responds with saml response
        # containing session duration
        roles, assertion, extracted_session_duration = roles_assertion_extractor.extract(
            self.a_page_with_saml_containing_session_duration(session_duration_configured_in_adfs)
        )

        # then responded session duration is extracted
        assert extracted_session_duration == session_duration_configured_in_adfs

    def test_provides_default_session_duration_when_it_is_missing_in_response(self):
        # when after successful authentican adfs responds with saml response
        # without session duration setup
        roles, assertion, extracted_session_duration = roles_assertion_extractor.extract(
            self.a_page_with_saml_without_session_duration()
        )

        # then extracted session duration has default value for boto
        assert extracted_session_duration == roles_assertion_extractor.default_session_duration

    @staticmethod
    def a_page_of_allowed_beer_roles():
        assertion = u'''<samlp:Response Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" Destination="https://signin.aws.amazon.com/saml" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
<Assertion Version="2.0" xmlns="urn:oasis:names:tc:SAML:2.0:assertion">
<AttributeStatement>
  <Attribute Name="https://aws.amazon.com/SAML/Attributes/RoleSessionName">
    <AttributeValue>beer.lover@awesome.company.com</AttributeValue>
  </Attribute>
  <Attribute Name="https://aws.amazon.com/SAML/Attributes/Role">
    <AttributeValue>arn:aws:iam::000000000000:saml-provider/ADFS,arn:aws:iam::000000000000:role/beer-lover</AttributeValue>
    <AttributeValue>arn:aws:iam::000000000000:saml-provider/ADFS,arn:aws:iam::000000000000:role/beer-crafter</AttributeValue>
  </Attribute>
</AttributeStatement>
</Assertion>
</samlp:Response>'''

        encoded_assertion = base64.encodestring(assertion.encode('utf-8')).decode('utf-8')

        return ET.fromstring(
            '''
<html>
  <head>
    <title>Working...</title>
  </head>
  <body>
    <form method="POST" name="hiddenform" action="https://signin.aws.amazon.com:443/saml">
      <input type="hidden" name="SAMLResponse" value="{}" />
    </form>
  </body>
</html>
            '''.format(encoded_assertion),
            ET.HTMLParser(),
        )

    @staticmethod
    def a_page_with_saml_without_session_duration():
        assertion = u'''<samlp:Response Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" Destination="https://signin.aws.amazon.com/saml" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
<Assertion Version="2.0" xmlns="urn:oasis:names:tc:SAML:2.0:assertion">
<AttributeStatement>
  <Attribute Name="https://aws.amazon.com/SAML/Attributes/RoleSessionName">
    <AttributeValue>beer.lover@awesome.company.com</AttributeValue>
  </Attribute>
  <Attribute Name="https://aws.amazon.com/SAML/Attributes/Role">
    <AttributeValue>arn:aws:iam::000000000000:saml-provider/ADFS,arn:aws:iam::000000000000:role/beer-lover</AttributeValue>
    <AttributeValue>arn:aws:iam::000000000000:saml-provider/ADFS,arn:aws:iam::000000000000:role/beer-crafter</AttributeValue>
  </Attribute>
</AttributeStatement>
</Assertion>
</samlp:Response>'''

        encoded_assertion = base64.encodestring(assertion.encode('utf-8')).decode('utf-8')

        return ET.fromstring(
            '''
<html>
  <head>
    <title>Working...</title>
  </head>
  <body>
    <form method="POST" name="hiddenform" action="https://signin.aws.amazon.com:443/saml">
      <input type="hidden" name="SAMLResponse" value="{}" />
    </form>
  </body>
</html>
            '''.format(encoded_assertion),
            ET.HTMLParser(),
        )

    @staticmethod
    def a_page_with_saml_containing_session_duration(session_duration):
        assertion = u'''<samlp:Response Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" Destination="https://signin.aws.amazon.com/saml" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
<Assertion Version="2.0" xmlns="urn:oasis:names:tc:SAML:2.0:assertion">
<AttributeStatement>
  <Attribute Name="https://aws.amazon.com/SAML/Attributes/RoleSessionName">
    <AttributeValue>beer.lover@awesome.company.com</AttributeValue>
  </Attribute>
  <Attribute Name="https://aws.amazon.com/SAML/Attributes/Role">
    <AttributeValue>arn:aws:iam::000000000000:saml-provider/ADFS,arn:aws:iam::000000000000:role/beer-lover</AttributeValue>
    <AttributeValue>arn:aws:iam::000000000000:saml-provider/ADFS,arn:aws:iam::000000000000:role/beer-crafter</AttributeValue>
  </Attribute>
  <Attribute Name="https://aws.amazon.com/SAML/Attributes/SessionDuration">
        <AttributeValue>{}</AttributeValue>
      </Attribute>
</AttributeStatement>
</Assertion>
</samlp:Response>'''.format(session_duration)

        encoded_assertion = base64.encodestring(assertion.encode('utf-8')).decode('utf-8')

        return ET.fromstring(
            '''
<html>
  <head>
    <title>Working...</title>
  </head>
  <body>
    <form method="POST" name="hiddenform" action="https://signin.aws.amazon.com:443/saml">
      <input type="hidden" name="SAMLResponse" value="{}" />
    </form>
  </body>
</html>
            '''.format(encoded_assertion),
            ET.HTMLParser(),
        )

    @staticmethod
    def _a_page_of_expired_login():
        return ET.fromstring(
            '''
<!DOCTYPE html>
<html>
  <head>
    <title>Amazon Web Services Sign-In</title>
    <meta name="viewport" content="width=device-width" />
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"></head>
    <body>
      <div id="container">
        <h1 class="background">Amazon Web Services Login</h1>
        <div id="content">
          <div id="main_error"></div>
          <form id="saml_form" name="saml_form" action="/saml" method="post">
            <input type="hidden" name="RelayState" value="" />
            <input type="hidden" name="SAMLResponse" value="" />
            <input type="hidden" name="name" value="" />
            <p style="font-size: 16px; padding-left: 20px;">Select a role:</p>
          </div>
        </body>
      </html>
            ''',
            ET.HTMLParser(),
        )

    @staticmethod
    def _a_page_of_authentication_failure():
        return ET.fromstring(
            '''
 <!DOCTYPE html>
<html lang="en-US">
    <head>
        <meta http-equiv="X-UA-Compatible" content="IE=10.000"/>
        <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no"/>
        <meta http-equiv="content-type" content="text/html;charset=UTF-8" />
        <meta http-equiv="cache-control" content="no-cache,no-store"/>
        <meta http-equiv="pragma" content="no-cache"/>
        <meta http-equiv="expires" content="-1"/>
        <meta name='mswebdialog-title' content='Connecting to Awesome Company'/>

        <title>Sign In</title>

    </head>
    <body dir="ltr" class="body">
    <div id="fullPage">
        <div id="brandingWrapper" class="float">
            <div id="branding"></div>
        </div>
        <div id="contentWrapper" class="float">
            <div id="content">
                <div id="header">
                    Awesome Company
                </div>
                <div id="workArea">

    <div id="authArea" class="groupMargin">


    <div id="loginArea">
        <div id="loginMessage" class="groupMargin">Sign in with your organizational account</div>

        <form method="post" id="loginForm" autocomplete="off" novalidate="novalidate" onKeyPress="if (event && event.keyCode == 13) Login.submitLoginRequest();" action="/adfs/ls/idpinitiatedsignon" >
            <div id="error" class="fieldMargin error smallText">
                <label id="errorText" for="">Incorrect user ID or password. Type the correct user ID and password, and try again.</label>
            </div>

            <div id="formsAuthenticationArea">
                <div id="userNameArea">
                    <input id="userNameInput" name="UserName" type="email" value="123123@3223.123" tabindex="1" class="text fullWidth"
                        spellcheck="false" placeholder="someone@example.com" autocomplete="off"/>
                </div>

                <div id="passwordArea">
                     <input id="passwordInput" name="Password" type="password" tabindex="2" class="text fullWidth"
                        placeholder="Password" autocomplete="off"/>
                </div>
                <div id="kmsiArea" style="display:none">
                    <input type="checkbox" name="Kmsi" id="kmsiInput" value="true" tabindex="3" />
                    <label for="kmsiInput">Keep me signed in</label>
                </div>
                <div id="submissionArea" class="submitMargin">
                    <span id="submitButton" class="submit" tabindex="4"
                        onKeyPress="if (event && event.keyCode == 32) Login.submitLoginRequest();"
                        onclick="return Login.submitLoginRequest();">Sign in</span>
                </div>
            </div>
            <input id="optionForms" type="hidden" name="AuthMethod" value="FormsAuthentication"/>
        </form>

             <div id="authOptions">
        <form id="options"  method="post" action="https://adfs.awesome.company.com:443/adfs/ls/idpinitiatedsignon">
            <input id="optionSelection" type="hidden" name="AuthMethod" />
            <div class='groupMargin'></div>
        </form>
      </div>

        <div id="introduction" class="groupMargin">

        </div>

    </div>

    </div>

                </div>
                <div id="footerPlaceholder"></div>
            </div>
            <div id="footer">
                <div id="footerLinks" class="floatReverse">
                     <div><span id="copyright">&#169; 2013 Microsoft</span></div>
                </div>
            </div>
        </div>
    </div>
    </body>
</html>
            ''',
            ET.HTMLParser(),
        )
