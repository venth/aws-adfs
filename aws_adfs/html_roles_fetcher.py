import logging
import os
from platform import system
import requests
import hashlib

from . import helpers
from .helpers import trace_http_request

try:
    import cookielib
except ImportError:
    # python 3
    import http.cookiejar as cookielib

_auth_provider = None
_headers = {'Accept-Language': 'en'}

try:
    if system() == 'Windows':
        from requests_negotiate_sspi import HttpNegotiateAuth
        _auth_provider = HttpNegotiateAuth
    else:
        from requests_kerberos import HTTPKerberosAuth, OPTIONAL
        _auth_provider = HTTPKerberosAuth
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
        sspi=None,
):

    # Support for Kerberos SSO on Windows via requests_negotiate_sspi
    # also requires tricking the server into thinking we're using IEq
    # so that it servers up a redirect to the IWA page.
    if sspi:
        _headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko'

    # Initiate session handler
    session = requests.Session()

    # LWPCookieJar has an issue on Windows when cookies have an 'expires' date too far in the future and they are converted from timestamp to datetime.
    # MozillaCookieJar works because it does not convert the timestamps.
    # Duo uses 253402300799 for its cookies which translates into 9999-12-31T23:59:59Z.
    # Windows 64bit maximum date is 3000-12-31T23:59:59Z, and 32bit is 2038-01-18T23:59:59Z.
    # 
    # using the same cookiejar across multiple ADFS hosts causes issues, so use a unique jar per host
    cookiejar_filename = '{}_{}'.format(adfs_cookie_location, hashlib.md5(adfs_host.encode('utf-8')).hexdigest())
    session.cookies = cookielib.MozillaCookieJar(filename=cookiejar_filename)

    try:
        have_creds = (username and password) or (_auth_provider and sspi)
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

        if system() == 'Windows':
            auth = _auth_provider(username, password, domain)
        elif username and domain:
            auth = _auth_provider(principal="{}@{}".format(username, domain), mutual_authentication=OPTIONAL)
        else:
            auth = _auth_provider(mutual_authentication=OPTIONAL)
        data = None
    else:
        auth = None
        data={
            'UserName': username,
            'Password': password,
            'AuthMethod': 'FormsAuthentication'
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
    trace_http_request(response)

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
    if password is not None:
        helpers.memset_zero(password)
    del password

    # Decode the response
    return response, session
