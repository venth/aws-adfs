import logging
import os

try:
    import cookielib
except:
    # python 3
    import http.cookiejar as cookielib

import lxml.etree as ET
import requests

# The initial URL that starts the authentication process.
_IDP_ENTRY_URL = 'https://{}/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices'


def fetch_html_encoded_roles(adfs_host, adfs_cookie_location, ssl_verification_enabled, username=None, password=None):
    # Initiate session handler
    session = requests.Session()
    session.cookies = cookielib.LWPCookieJar(filename=adfs_cookie_location)

    try:
        session.cookies.load(ignore_discard=True)
    except IOError as e:
        error_message = e.message if _is_capable_of_providing_error_message() else e
        logging.debug(
            'A try to loaded authenticated cookie into a session failed. '
            'Re-authentication will be performed. '
            'The error: {}'.format(error_message)
        )

    # Opens the initial AD FS URL and follows all of the HTTP302 redirects
    authentication_url = _IDP_ENTRY_URL.format(adfs_host)
    response = session.post(
        authentication_url,
        verify=ssl_verification_enabled,
        headers={'Accept-Language': 'en'},
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
        * headers: '{}'
        * body: '{}'
    '''.format(authentication_url, response.request.headers, response.headers, response.text))

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


def _is_capable_of_providing_error_message():
    capable = True
    try:
        eval("""
            try:
                raise IOError('bumps')
            except IOError as e:
                print(e.message)
        """)
    except SyntaxError:
        capable = False

    return capable
