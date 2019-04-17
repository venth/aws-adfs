import logging
import os
import requests

try:
    import cookielib
except ImportError:
    # python 3
    import http.cookiejar as cookielib

_auth_provider = None
_headers = {'Accept-Language': 'en'}

# Support for Kerberos SSO on Windows via requests_negotiate_sspi
# also requires tricking the server into thinking we're using IE
# so that it servers up a redirect to the IWA page.
try:
    from requests_negotiate_sspi import HttpNegotiateAuth
    _auth_provider = HttpNegotiateAuth
    _headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko'
except ImportError:
    pass

# The initial URL that starts the authentication process.
_IDP_ENTRY_URL = 'https://{}/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp={}'


def fetch_html_encoded_roles(
        adfs_host,
        adfs_cookie_location,
        ssl_verification_enabled,
        provider_id,
        adfs_ca_bundle=None,
        username=None,
        password=None,
        sspi=True
):
    # Initiate session handler
    session = requests.Session()
    session.cookies = cookielib.LWPCookieJar(filename=adfs_cookie_location)

    try:
        have_creds = (username and password) or _auth_provider
        session.cookies.load(ignore_discard=not(have_creds))
    except IOError as e:
        error_message = getattr(e, 'message', e)
        logging.debug(
            u'Attempt to load authentication cookies into session failed. '
            u'Re-authentication will be performed. '
            u'The error: {}'.format(error_message)
        )

    if _auth_provider and sspi:
        domain = None
        if username:
            if '@' in username: # User principal name (UPN) format
                username, domain = username.split('@', 1)
            elif '\\' in username: # Down-level logon name format
                domain, username = username.split('\\', 1)

        auth = _auth_provider(username, password, domain)
        data = None
    else:
        auth = None
        data={
            'UserName': username,
            'Password': password,
            'AuthMethod': provider_id
        }

    if adfs_ca_bundle:
        ssl_verification = adfs_ca_bundle
    else:
        ssl_verification = ssl_verification_enabled

    # Opens the initial AD FS URL and follows all of the HTTP302 redirects
    authentication_url = _IDP_ENTRY_URL.format(adfs_host, provider_id)
    response = session.post(
        authentication_url,
        verify=ssl_verification,
        headers=_headers,
        auth=auth,
        data=data
    )

    logging.debug(u'''Request:
        * url: {}
        * headers: {}
    Response:
        * status: {}
        * headers: {}
        * body: {}
    '''.format(
            authentication_url,
            response.request.headers,
            response.status_code,
            response.headers,
            response.text
       ))

    if response.status_code >= 400:
        session.cookies.clear()

    mask = os.umask(0o177)
    try:
        session.cookies.save(ignore_discard=True)
    finally:
        os.umask(mask)

    del auth
    del data
    del username
    password = '###################################################'
    del password

    # Decode the response
    return response, session
