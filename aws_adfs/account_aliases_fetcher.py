import logging
import re

import lxml.etree as ET


_account_alias_pattern = re.compile("Account: *([^(]+) *\(([0-9]+)\)")
_account_without_alias_pattern = re.compile("Account: *\(?([0-9]+)\)?")


def account_aliases(session, username, password, auth_method, saml_response, config):
    alias_response = session.post(
        'https://signin.aws.amazon.com/saml',
        verify=config.ssl_verification,
        headers={
            'Accept-Language': 'en',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Accept': 'text/plain, */*; q=0.01',
        },
        auth=None,
        data={
            'UserName': username,
            'Password': password,
            'AuthMethod': auth_method,
            'SAMLResponse': saml_response,
        }
    )

    logging.debug(u'''Request:
        * url: {}
        * headers: {}
    Response:
        * status: {}
        * headers: {}
        * body: {}
    '''.format('https://signin.aws.amazon.com/saml',
               alias_response.request.headers,
               alias_response.status_code,
               alias_response.headers,
               alias_response.text))

    html_response = ET.fromstring(alias_response.text, ET.HTMLParser())

    accounts = {}
    account_element_query = './/div[@class="saml-account-name"]'
    for account_element in html_response.iterfind(account_element_query):
        logging.debug(u'Found SAML account name: {}'.format(account_element.text))
        m = _account_alias_pattern.search(account_element.text)
        if m is not None:
            accounts[m.group(2)] = m.group(1).strip()

        if m is None:
            m = _account_without_alias_pattern.search(account_element.text)
            if m is not None:
                accounts[m.group(1)] = m.group(0).strip()

    return accounts
