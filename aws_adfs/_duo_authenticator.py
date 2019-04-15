import click
import lxml.etree as ET

import logging
import re

try:
    # Python 3
    from urllib.parse import urlparse, parse_qs
except ImportError:
    # Python 2
    from urlparse import urlparse, parse_qs

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
    (sid, preferred_factor, preferred_device), initiated = _initiate_authentication(
        duo_host,
        duo_request_signature,
        roles_page_url,
        session,
        ssl_verification_enabled
    )
    if initiated:
        transaction_id = _begin_authentication_transaction(
            duo_host,
            sid,
            preferred_factor,
            preferred_device,
            session,
            ssl_verification_enabled
        )

        click.echo("Waiting for additional authentication", err=True)
        _verify_that_code_was_sent(
            duo_host,
            sid,
            transaction_id,
            session,
            ssl_verification_enabled
        )
        auth_signature = _authentication_result(
            duo_host,
            sid,
            transaction_id,
            session,
            ssl_verification_enabled
        )

        click.echo('Going for aws roles', err=True)
        return _retrieve_roles_page(
            roles_page_url,
            _context(html_response),
            session,
            ssl_verification_enabled,
            '{}:{}'.format(auth_signature, _app(duo_request_signature)),
        )

    return None, None, None


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

def _verify_that_code_was_sent(duo_host, sid, duo_transaction_id, session,
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
                u'Issues during sending code to the devide. The error response {}'.format(
                    response
                )
            )

        json_response = response.json()
        if json_response['stat'] != 'OK':
            raise click.ClickException(
                u'There was an issue during sending code to the device. The error response: {}'.format(
                    response.text
                )
            )

        if json_response['response']['status_code'] not in ['answered', 'calling', 'pushed']:
            raise click.ClickException(
                u'There was an issue during sending code to the device. The error response: {}'.format(
                    response.text
                )
            )

        if json_response['response']['status_code'] in ['pushed', 'answered']:
            return

        responses.append(response.text)

    raise click.ClickException(
        u'There was an issue during sending code to the device. The responses: {}'.format(
            responses
        )
    )



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
    parent = "{}{}".format(
        roles_page_url,
        "&java_version="
        "&flash_version="
        "&screen_resolution_width=1280"
        "&screen_resolution_height=800"
        "&color_depth=24"
    )
    response = session.post(
        prompt_for_url,
        verify=ssl_verification_enabled,
        headers={
            'Host': duo_host,
            'User-Agent': "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:52.0) Gecko/20100101 Firefox/52.0",
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
            'parent': parent,
            'v': '2.3',
        },
        data={
            'parent': parent,
            'java_version': '',
            'flash_version': '22.0.0.209',
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
    return (sid, preferred_factor, preferred_device), True


def _preferred_factor(html_response):
    preferred_factor_query = './/input[@name="preferred_factor"]'
    element = html_response.find(preferred_factor_query)
    return element.get('value')


def _preferred_device(html_response):
    preferred_device_query = './/input[@name="preferred_device"]'
    element = html_response.find(preferred_device_query)
    return element.get('value')


def _begin_authentication_transaction(duo_host, sid, preferred_factor, preferred_device, session,
                                      ssl_verification_enabled):
    prompt_for_url = "https://{}/frame/prompt".format(duo_host)
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
