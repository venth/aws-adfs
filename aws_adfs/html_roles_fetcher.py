import requests
import logging
import os
import lxml.etree as ET

try:
    import cookielib
except ImportError:
    # python 3
    import http.cookiejar as cookielib

_auth_provider = None
_headers={'Accept-Language': 'en'}

# Support for Kerberos SSO on Windows via requests_negotiate_sspi
# also requires tricking the server into thinking we're using IE
# so that it servers up a redirect to the IWA page.
try:
    from requests_negotiate_sspi import HttpNegotiateAuth
    _auth_provider = HttpNegotiateAuth()
    _headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko'
except ImportError:
    pass

# The initial URL that starts the authentication process.
_IDP_ENTRY_URL = 'https://{}/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices'


def fetch_html_encoded_roles(adfs_host, adfs_cookie_location, ssl_verification_enabled, username=None, password=None):
    # Initiate session handler
    session = requests.Session()
    session.cookies = cookielib.LWPCookieJar(filename=adfs_cookie_location)

    try:
        have_creds = (username and password) or _auth_provider
        session.cookies.load(ignore_discard=not(have_creds))
    except IOError as e:
        error_message = getattr(e, 'message', e)
        logging.debug(
            'Attempt to load authentication cookies into session failed. '
            'Re-authentication will be performed. '
            'The error: {}'.format(error_message)
        )

    # Opens the initial AD FS URL and follows all of the HTTP302 redirects
    authentication_url = _IDP_ENTRY_URL.format(adfs_host)
    response = session.post(
        authentication_url,
        verify=ssl_verification_enabled,
        headers=_headers,
        auth=_auth_provider,
        data={
            'UserName': username,
            'Password': password,
            'AuthMethod': 'urn:amazon:webservices'
        }
    )

    logging.debug('''Request:
        * url: {}
        * headers: {}
    Response:
        * status: {}
        * headers: {}
        * body: {}
    '''.format(authentication_url, response.request.headers, response.status_code, response.headers, response.text))

    if response.status_code >= 400:
        session.cookies.clear()

    mask = os.umask(0o177)
    try:
        session.cookies.save(ignore_discard=True)
    finally:
        os.umask(mask)

    del username
    password = '###################################################'
    del password

    # Decode the response
    return ET.fromstring(response.text, ET.HTMLParser())
