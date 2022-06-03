import base64
import binascii
import click
import lxml.etree as ET

from fido2.client import ClientData, ClientError, Fido2Client
from fido2.hid import CtapHidDevice
try:
    from fido2.pcsc import CtapPcscDevice
except ImportError:
    CtapPcscDevice = None

import logging
import json
import re

from threading import Event, Thread

from .helpers import trace_http_request

try:
    # Python 3
    from urllib.parse import urlparse, parse_qs
    import queue
except ImportError:
    # Python 2
    from urlparse import urlparse, parse_qs
    import Queue as queue

from . import roles_assertion_extractor

_headers = {
    'Accept-Language': 'en',
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko',
    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'Accept': 'text/plain, */*; q=0.01',
}


def extract(html_response, ssl_verification_enabled, session):
    """
    this strategy is based on description from: https://duo.com/docs/duoweb
    :param response: raw http response
    :param html_response: html result of parsing http response
    :return:
    """

    duo_host = _duo_host(html_response)
    duo_request_signature = _duo_request_signature(html_response)
    roles_page_url = _action_url_on_validation_success(html_response)

    click.echo("Sending request for authentication", err=True)
    (sid, preferred_factor, preferred_device, webauthn_supported, auth_signature), initiated = _initiate_authentication(
        duo_host,
        duo_request_signature,
        roles_page_url,
        session,
        ssl_verification_enabled
    )
    if initiated:
        if auth_signature is None:
            click.echo("Waiting for additional authentication", err=True)

            # Trigger default authentication (call, push or WebAuthn with FIDO U2F / FIDO2 authenticator)
            auth_signature = _perform_authentication_transaction(
                duo_host,
                sid,
                preferred_factor,
                preferred_device,
                webauthn_supported,
                session,
                ssl_verification_enabled,
            )
            if auth_signature == "cancelled":
                click.echo("Authentication method cancelled, aborting.")
                exit(-2)
                    
        click.echo('Going for aws roles', err=True)
        return _retrieve_roles_page(
            roles_page_url,
            _context(html_response),
            session,
            ssl_verification_enabled,
            '{}:{}'.format(auth_signature, _app(duo_request_signature)),
        )

    return None, None, None


def _perform_authentication_transaction(duo_host, sid, preferred_factor, preferred_device, webauthn_supported, session, ssl_verification_enabled):
    if (preferred_factor is None or preferred_device is None):
        click.echo("No default authentication method configured.")
        preferred_factor = click.prompt(text='Please enter your desired authentication method (Ex: Duo Push)', type=str)

    transaction_id = _begin_authentication_transaction(
        duo_host,
        sid,
        preferred_factor,
        preferred_device,
        webauthn_supported,
        session,
        ssl_verification_enabled
    )

    transaction_id =_verify_authentication_status(
        duo_host,
        sid,
        transaction_id,
        session,
        ssl_verification_enabled,
    )
    if transaction_id == "cancelled":
        return "cancelled"
    else:
        return _authentication_result(
            duo_host, sid, transaction_id, session, ssl_verification_enabled
        )


def _context(html_response):
    context_query = './/input[@id="context"]'
    element = html_response.find(context_query)
    return element.get('value')


def _retrieve_roles_page(roles_page_url, context, session, ssl_verification_enabled,
                         signed_response):
    logging.debug('context: {}'.format(context))
    logging.debug('sig_response: {}'.format(signed_response))

    data = {
        'AuthMethod': 'DuoAdfsAdapter',
        'Context': context,
        'sig_response': signed_response,
    }
    response = session.post(
        roles_page_url,
        verify=ssl_verification_enabled,
        headers=_headers,
        allow_redirects=True,
        data=data
    )
    trace_http_request(response)

    if response.status_code != 200:
        raise click.ClickException(
            u'Issues during redirection to aws roles page. The error response {}'.format(
                response
            )
        )

    # Save session cookies to avoid having to repeat MFA on each login
    session.cookies.save(ignore_discard=True)

    html_response = ET.fromstring(response.text, ET.HTMLParser())
    return roles_assertion_extractor.extract(html_response)


def _authentication_result(
        duo_host,
        sid,
        duo_transaction_id,
        session,
        ssl_verification_enabled
):
    status_for_url = "https://{}/frame/status".format(duo_host)
    data = {
        'sid': sid,
        'txid': duo_transaction_id
    }
    response = session.post(
        status_for_url,
        verify=ssl_verification_enabled,
        headers=_headers,
        data=data
    )
    trace_http_request(response)

    if response.status_code != 200:
        raise click.ClickException(
            u'Issues during retrieval of a code entered into '
            u'the device. The error response {}'.format(
                response
            )
        )

    json_response = response.json()
    if json_response['stat'] != 'OK':
        raise click.ClickException(
            u'There was an issue during retrieval of a code entered into the device.'
            u' The error response: {}'.format(
                response.text
            )
        )

    if json_response['response']['status_code'] != 'allow':
        raise click.ClickException(
            u'There was an issue during retrieval of a code entered into the device.'
            u' The error response: {}'.format(
                response.text
            )
        )
    result_url = response.json()['response']['result_url']
    duo_result_response = _load_duo_result_url(duo_host, result_url, sid, session, ssl_verification_enabled)
    auth_signature = duo_result_response.json()['response']['cookie']
    return auth_signature

def _load_duo_result_url(
        duo_host,
        result_url,
        sid,
        session,
        ssl_verification_enabled
):
    result_for_url = 'https://{}'.format(duo_host) + result_url
    data = {
        'sid': sid
    }
    response = session.post(
        result_for_url,
        verify=ssl_verification_enabled,
        headers=_headers,
        data=data
    )
    trace_http_request(response)

    if response.status_code != 200:
        raise click.ClickException(
            u'Issues when following the Duo result URL after '
            u'authentication. The error response {}'.format(
                response
            )
        )
    json_response = response.json()
    if json_response['stat'] != 'OK':
        raise click.ClickException(
            u'There was an issue when following the Duo result URL after authentication.'
            u' The error response: {}'.format(
                response.text
            )
        )
    return response

def _verify_authentication_status(duo_host, sid, duo_transaction_id, session,
                                  ssl_verification_enabled):
    responses = []
    while len(responses) < 10:
        status_for_url = "https://{}/frame/status".format(duo_host)
        data = {
            'sid': sid,
            'txid': duo_transaction_id
        }
        response = session.post(
            status_for_url,
            verify=ssl_verification_enabled,
            headers=_headers,
            data=data
        )
        trace_http_request(response)

        if response.status_code != 200:
            raise click.ClickException(
                u'Issues during second factor verification. The error response {}'.format(
                    response
                )
            )

        json_response = response.json()
        if json_response['stat'] != 'OK':
            raise click.ClickException(
                u'There was an issue during second factor verification. The error response: {}'.format(
                    response.text
                )
            )

        if json_response['response']['status_code'] not in ['answered', 'calling', 'pushed', 'webauthn_sent']:
            raise click.ClickException(
                u'There was an issue during second factor verification. The error response: {}'.format(
                    response.text
                )
            )

        if json_response['response']['status_code'] in ['pushed', 'answered', 'allow']:
            return duo_transaction_id

        if json_response['response']['status_code'] == 'webauthn_sent' and len(json_response['response']['webauthn_credential_request_options']) > 0:
            webauthn_credential_request_options = json_response['response']['webauthn_credential_request_options']
            webauthn_credential_request_options["challenge"] = base64.b64decode(webauthn_credential_request_options["challenge"])
            for cred in webauthn_credential_request_options["allowCredentials"]:
                cred["id"] = base64.urlsafe_b64decode(cred["id"] + "==") # Add arbitrary padding characters, unnecessary ones are ignored
                cred.pop("transports")

            webauthn_session_id = webauthn_credential_request_options.pop('sessionId')

            devices = list(CtapHidDevice.list_devices())
            if CtapPcscDevice:
                devices.extend(list(CtapPcscDevice.list_devices()))

            if not devices:
                click.echo("No FIDO U2F / FIDO2 authenticator is eligible.")
                return "cancelled"

            threads = []
            webauthn_response = {
                "sessionId": webauthn_session_id
            }
            rq = queue.Queue()
            cancel = Event()
            for device in devices:
                t = Thread(
                    target=_webauthn_get_assertion,
                    args=(
                        device,
                        webauthn_credential_request_options,
                        duo_host,
                        sid,
                        webauthn_response,
                        session,
                        ssl_verification_enabled,
                        cancel,
                        rq
                    )
                )
                t.daemon = True
                threads.append(t)
                t.start()

            # Wait for first answer
            return rq.get()

        responses.append(response.text)

    raise click.ClickException(
        u'There was an issue during second factor verification. The responses: {}'.format(
            responses
        )
    )


def _webauthn_get_assertion(device, webauthn_credential_request_options, duo_host, sid, webauthn_response, session, ssl_verification_enabled, cancel, rq):
    click.echo("Activate your FIDO U2F / FIDO2 authenticator now: '{}'".format(device), err=True)
    client = Fido2Client(device, webauthn_credential_request_options["extensions"]["appid"])
    try:
        assertion = client.get_assertion(
                webauthn_credential_request_options,
                event=cancel,
        )
        authenticator_assertion_response = assertion.get_response(0)
        assertion_response = assertion.get_assertions()[0]

        webauthn_response["id"] = base64.urlsafe_b64encode(assertion_response.credential["id"]).decode('ascii').rstrip("=") # Strip trailing padding characters
        webauthn_response["rawId"] = webauthn_response["id"]
        webauthn_response["type"] = assertion_response.credential["type"]
        webauthn_response["authenticatorData"] = base64.urlsafe_b64encode(assertion_response.auth_data).decode('ascii')
        webauthn_response["clientDataJSON"] = base64.urlsafe_b64encode(authenticator_assertion_response["clientData"]).decode('ascii')
        webauthn_response["signature"] = binascii.hexlify(assertion_response.signature).decode("ascii")
        webauthn_response["extensionResults"] = authenticator_assertion_response["extensionResults"]
        logging.debug('webauthn_response: {}'.format(webauthn_response))
        
        click.echo("Got response from FIDO U2F / FIDO2 authenticator: '{}'".format(device), err=True)
        rq.put(_submit_webauthn_response(duo_host, sid, webauthn_response, session, ssl_verification_enabled))
    except Exception as e:
        logging.debug("Got an exception while waiting for {}: {}".format(device, e))
        if not cancel.is_set():
            raise
    finally:
        # Cancel the other FIDO U2F / FIDO2 prompts
        cancel.set()

        device.close()


_tx_pattern = re.compile("(TX\|[^:]+):APP.+")


def _tx(request_signature):
    m = _tx_pattern.search(request_signature)
    return m.group(1)


_app_pattern = re.compile(".*(APP\|[^:]+)")


def _app(request_signature):
    m = _app_pattern.search(request_signature)
    return m.group(1)


def _initiate_authentication(duo_host, duo_request_signature, roles_page_url, session,
                             ssl_verification_enabled):
    prompt_for_url = 'https://{}/frame/web/v1/auth'.format(duo_host)
    data = {
        'parent': roles_page_url,
        'java_version': '',
        'flash_version': '',
        'screen_resolution_width': '1280',
        'screen_resolution_height': '800',
        'color_depth': '24',
    }
    response = session.post(
        prompt_for_url,
        verify=ssl_verification_enabled,
        headers={
            'Host': duo_host,
            'User-Agent': "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36",
            'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            'Accept-Language': "en-US,en;q=0.5",
            'Accept-Encoding': "gzip, deflate, br",
            'DNT': "1",
            'Upgrade-Insecure-Requests': "1",
            'Content-Type': "application/x-www-form-urlencoded",
        },
        allow_redirects=True,
        params={
            'tx': _tx(duo_request_signature),
            'parent': roles_page_url,
            'v': '2.3',
        },
        data=data
    )
    trace_http_request(response)

    if response.status_code != 200 or response.url is None:
        return (None, None, None, None, None), False

    o = urlparse(response.url)
    query = parse_qs(o.query)
    html_response = ET.fromstring(response.text, ET.HTMLParser())

    if 'sid' not in query:
        # No need for second factor authentification, Duo directly returned the authentication cookie
        return (None, None, None, None, _js_cookie(html_response)), True

    sid = query['sid']
    preferred_factor = _preferred_factor(html_response)
    preferred_device = _preferred_device(html_response)
    webauthn_supported = _webauthn_supported(html_response)
    return (sid, preferred_factor, preferred_device, webauthn_supported, None), True


def _js_cookie(html_response):
    js_cookie_query = './/input[@name="js_cookie"]'
    element = html_response.find(js_cookie_query)
    return element is not None and element.get('value') or None


def _preferred_factor(html_response):
    preferred_factor_query = './/input[@name="preferred_factor"]'
    element = html_response.find(preferred_factor_query)
    return element is not None and element.get('value') or None


def _preferred_device(html_response):
    preferred_device_query = './/input[@name="preferred_device"]'
    element = html_response.find(preferred_device_query)
    return element is not None and element.get('value') or None


def _webauthn_supported(html_response):
    webauthn_supported_query = './/input[@name="factor"][@value="WebAuthn Credential"]'
    elements = html_response.findall(webauthn_supported_query)
    return len(elements) > 0


def _begin_authentication_transaction(duo_host, sid, preferred_factor, preferred_device, webauthn_supported, session,
                                      ssl_verification_enabled):
    prompt_for_url = "https://{}/frame/prompt".format(duo_host)
    if webauthn_supported and preferred_factor == preferred_device:
        preferred_factor = 'WebAuthn Credential'
    click.echo("Triggering authentication method: '{}' with '{}".format(preferred_factor, preferred_device), err=True)
    data = {
        'sid': sid,
        'factor': preferred_factor,
        'device': preferred_device,
        'post_auth_action': '',
        'out_of_date': '',
    }
    response = session.post(
        prompt_for_url,
        verify=ssl_verification_enabled,
        headers=_headers,
        data=data
    )
    trace_http_request(response)

    if response.status_code != 200:
        raise click.ClickException(
            u'Issues during beginning of the authentication process. The error response {}'.format(
                response
            )
        )

    json_response = response.json()
    if json_response['stat'] != 'OK':
        raise click.ClickException(
            u'Cannot begin authentication process. The error response: {}'.format(response.text)
        )

    return json_response['response']['txid']


def _submit_webauthn_response(duo_host, sid, webauthn_response, session, ssl_verification_enabled):
    prompt_for_url = "https://{}/frame/prompt".format(duo_host)
    data = {
        'sid': sid,
        'device': 'webauthn_credential',
        'factor': "webauthn_finish",
        'response_data': json.dumps(webauthn_response),
    }
    response = session.post(
        prompt_for_url,
        verify=ssl_verification_enabled,
        headers=_headers,
        data=data
    )
    trace_http_request(response)

    if response.status_code != 200:
        raise click.ClickException(
            u'Issues during submitting WebAuthn response for the authentication process. The error response {}'.format(
                response
            )
        )

    json_response = response.json()
    if json_response['stat'] != 'OK':
        raise click.ClickException(
            u'Cannot complete authentication process. The error response: {}'.format(response.text)
        )

    return json_response['response']['txid']


_duo_host_pattern = re.compile("'host': '([^']+)'")


def _duo_host(html_response):
    try:
        duo_host_query = './/form[@id="duo_form"]/following-sibling::script'
        element = html_response.xpath(duo_host_query)[0]
        m = _duo_host_pattern.search(element.text)
        return m.group(1)
    except:
        duo_host_query = './/input[@name="duo_host"]/@value'
        return html_response.xpath(duo_host_query)[0]

_duo_signature_pattern = re.compile("'sig_request': '([^']+)'")


def _duo_request_signature(html_response):
    try:
        duo_signature_query = './/form[@id="duo_form"]/following-sibling::script'
        element = html_response.xpath(duo_signature_query)[0]
        m = _duo_signature_pattern.search(element.text)
        return m.group(1)
    except:
        duo_host_query = './/input[@name="duo_sig_request"]/@value'
        return html_response.xpath(duo_host_query)[0]


def _action_url_on_validation_success(html_response):
    duo_auth_method = './/form[@id="options"]'
    element = html_response.find(duo_auth_method)
    return element.get('action')
