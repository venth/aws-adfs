import click
import lxml.etree as ET

from fido2.client import ClientData, ClientError, U2fClient
from fido2.hid import CtapHidDevice
try:
    from fido2.pcsc import CtapPcscDevice
except ImportError:
    CtapPcscDevice = None

import logging
import json
import re

from threading import Event, Thread

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


def extract(html_response, ssl_verification_enabled, u2f_trigger_default, session):
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
    (sid, preferred_factor, preferred_device, u2f_supported), initiated = _initiate_authentication(
        duo_host,
        duo_request_signature,
        roles_page_url,
        session,
        ssl_verification_enabled
    )
    if initiated:
        click.echo("Waiting for additional authentication", err=True)

        rq = queue.Queue()
        auth_count = 0
        if u2f_supported:
            # Trigger U2F authentication
            auth_count += 1
            t = Thread(
                target=_perform_authentication_transaction,
                args=(
                    duo_host,
                    sid,
                    preferred_factor,
                    preferred_device,
                    True,
                    session,
                    ssl_verification_enabled,
                    rq,
                )
            )
            t.daemon = True
            t.start()

        if u2f_trigger_default or not u2f_supported:
            # Trigger default authentication (call or push) concurrently to U2F
            auth_count += 1
            t = Thread(
                target=_perform_authentication_transaction,
                args=(
                    duo_host,
                    sid,
                    preferred_factor,
                    preferred_device,
                    False,
                    session,
                    ssl_verification_enabled,
                    rq,
                )
            )
            t.daemon = True
            t.start()

        while "Wait for responses":
            auth_signature = rq.get()
            auth_count -= 1
            if auth_signature != "cancelled":
                break
            if auth_count < 1:
                click.echo("All authentication methods cancelled, aborting.")
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


def _perform_authentication_transaction(duo_host, sid, preferred_factor, preferred_device, use_u2f, session, ssl_verification_enabled, rq):
    if (preferred_factor is None or preferred_device is None) and not use_u2f:
        click.echo("No default authentication method configured.", err=True)
        rq.put("cancelled")
        return

    transaction_id = _begin_authentication_transaction(
        duo_host,
        sid,
        preferred_factor,
        preferred_device,
        use_u2f,
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
        rq.put("cancelled")
    else:
        rq.put(
            _authentication_result(
                duo_host, sid, transaction_id, session, ssl_verification_enabled
            )
        )


def _context(html_response):
    context_query = './/input[@id="context"]'
    element = html_response.find(context_query)
    return element.get('value')


def _retrieve_roles_page(roles_page_url, context, session, ssl_verification_enabled,
                         signed_response):
    logging.debug('context: {}'.format(context))
    logging.debug('sig_response: {}'.format(signed_response))

    response = session.post(
        roles_page_url,
        verify=ssl_verification_enabled,
        headers=_headers,
        allow_redirects=True,
        data={
            'AuthMethod': 'DuoAdfsAdapter',
            'Context': context,
            'sig_response': signed_response,
        }
    )
    logging.debug(u'''Request:
            * url: {}
            * headers: {}
        Response:
            * status: {}
            * headers: {}
            * body: {}
        '''.format(roles_page_url, response.request.headers, response.status_code, response.headers,
                   response.text))

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
    response = session.post(
        status_for_url,
        verify=ssl_verification_enabled,
        headers=_headers,
        data={
            'sid': sid,
            'txid': duo_transaction_id
        }
    )
    logging.debug(u'''Request:
        * url: {}
        * headers: {}
    Response:
        * status: {}
        * headers: {}
        * body: {}
    '''.format(status_for_url, response.request.headers, response.status_code, response.headers,
               response.text))

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
    response = session.post(
        result_for_url,
        verify=ssl_verification_enabled,
        headers=_headers,
        data={
            'sid': sid
        }
    )
    logging.debug(u'''Request:
        * url: {}
        * headers: {}
    Response:
        * status: {}
        * headers: {}
        * body: {}
    '''.format(result_for_url, response.request.headers, response.status_code, response.headers,
               response.text))

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
        response = session.post(
            status_for_url,
            verify=ssl_verification_enabled,
            headers=_headers,
            data={
                'sid': sid,
                'txid': duo_transaction_id
            }
        )
        logging.debug(u'''Request:
            * url: {}
            * headers: {}
        Response:
            * status: {}
            * headers: {}
            * body: {}
        '''.format(status_for_url, response.request.headers, response.status_code, response.headers,
                response.text))

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

        if json_response['response']['status_code'] not in ['answered', 'calling', 'pushed', 'u2f_sent']:
            raise click.ClickException(
                u'There was an issue during second factor verification. The error response: {}'.format(
                    response.text
                )
            )

        if json_response['response']['status_code'] in ['pushed', 'answered', 'allow']:
            return duo_transaction_id

        if json_response['response']['status_code'] == 'u2f_sent' and len(json_response['response']['u2f_sign_request']) > 0:
            u2f_sign_requests = json_response['response']['u2f_sign_request']

            # appId, challenge and session is the same for all requests, get them from the first
            u2f_app_id = u2f_sign_requests[0]['appId']
            u2f_challenge = u2f_sign_requests[0]['challenge']
            u2f_session_id = u2f_sign_requests[0]['sessionId']

            devices = list(CtapHidDevice.list_devices())
            if CtapPcscDevice:
                devices.extend(list(CtapPcscDevice.list_devices()))

            if not devices:
                click.echo("No FIDO U2F authenticator is eligible.")
                return "cancelled"

            threads = []
            u2f_response = {
                "sessionId": u2f_session_id
            }
            rq = queue.Queue()
            cancel = Event()
            for device in devices:
                t = Thread(
                    target=_u2f_sign,
                    args=(
                        device,
                        u2f_app_id,
                        u2f_challenge,
                        u2f_sign_requests,
                        duo_host,
                        sid,
                        u2f_response,
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


def _u2f_sign(device, u2f_app_id, u2f_challenge, u2f_sign_requests, duo_host, sid, u2f_response, session, ssl_verification_enabled, cancel, rq):
    click.echo("Activate your FIDO U2F authenticator now: '{}'".format(device), err=True)
    client = U2fClient(device, u2f_app_id)
    try:
        u2f_response.update(
                client.sign(
                u2f_app_id,
                u2f_challenge,
                u2f_sign_requests,
                event=cancel
            )
        )

        # Cancel the other U2F prompts
        cancel.set()
        
        click.echo("Got response from FIDO U2F authenticator: '{}'".format(device), err=True)
        rq.put(_submit_u2f_response(duo_host, sid, u2f_response, session, ssl_verification_enabled))
    except:
        pass
    finally:
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
        data={
            'parent': roles_page_url,
            'java_version': '',
            'flash_version': '',
            'screen_resolution_width': '1280',
            'screen_resolution_height': '800',
            'color_depth': '24',
        }
    )
    logging.debug(u'''Request:
        * url: {}
        * headers: {}
    Response:
        * status: {}
        * headers: {}
        * body: {}
    '''.format(prompt_for_url, response.request.headers, response.status_code, response.headers,
               response.text))

    if response.status_code != 200 or response.url is None:
        return (None, None, None), False

    o = urlparse(response.url)
    query = parse_qs(o.query)

    if 'sid' not in query:
        return (None, None, None), False

    sid = query['sid']
    html_response = ET.fromstring(response.text, ET.HTMLParser())
    preferred_factor = _preferred_factor(html_response)
    preferred_device = _preferred_device(html_response)
    u2f_supported = _u2f_supported(html_response)
    return (sid, preferred_factor, preferred_device, u2f_supported), True


def _preferred_factor(html_response):
    preferred_factor_query = './/input[@name="preferred_factor"]'
    element = html_response.find(preferred_factor_query)
    return element is not None and element.get('value') or None


def _preferred_device(html_response):
    preferred_device_query = './/input[@name="preferred_device"]'
    element = html_response.find(preferred_device_query)
    return element is not None and element.get('value') or None


def _u2f_supported(html_response):
    u2f_supported_query = './/input[@name="factor"][@value="U2F Token"]'
    elements = html_response.findall(u2f_supported_query)
    return len(elements) > 0


def _begin_authentication_transaction(duo_host, sid, preferred_factor, preferred_device, u2f_supported, session,
                                      ssl_verification_enabled):
    prompt_for_url = "https://{}/frame/prompt".format(duo_host)
    if u2f_supported:
        response = session.post(
            prompt_for_url,
            verify=ssl_verification_enabled,
            headers=_headers,
            data={
                'sid': sid,
                'factor': "U2F Token",
                'device': 'u2f_token',
                'post_auth_action': ''
            }
        )
    else:
        click.echo("Triggering default authentication method: '{}'".format(preferred_factor), err=True)
        response = session.post(
            prompt_for_url,
            verify=ssl_verification_enabled,
            headers=_headers,
            data={
                'sid': sid,
                'factor': preferred_factor,
                'device': preferred_device,
                'out_of_date': ''
            }
        )
    logging.debug(u'''Request:
        * url: {}
        * headers: {}
    Response:
        * status: {}
        * headers: {}
        * body: {}
    '''.format(prompt_for_url, response.request.headers, response.status_code, response.headers,
               response.text))

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


def _submit_u2f_response(duo_host, sid, u2f_response, session, ssl_verification_enabled):
    prompt_for_url = "https://{}/frame/prompt".format(duo_host)
    response = session.post(
        prompt_for_url,
        verify=ssl_verification_enabled,
        headers=_headers,
        data={
            'sid': sid,
            'device': 'u2f_token',
            'factor': "u2f_finish",
            'response_data': json.dumps(u2f_response),
        }
    )
    logging.debug(u'''Request:
        * url: {}
        * headers: {}
    Response:
        * status: {}
        * headers: {}
        * body: {}
    '''.format(prompt_for_url, response.request.headers, response.status_code, response.headers,
               response.text))

    if response.status_code != 200:
        raise click.ClickException(
            u'Issues during submitting U2F response for the authentication process. The error response {}'.format(
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
