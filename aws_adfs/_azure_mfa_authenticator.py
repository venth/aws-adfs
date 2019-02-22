import click
import lxml.etree as ET

import logging

from . import roles_assertion_extractor

def extract(html_response, ssl_verification_enabled, session):
    """
    :param html_response: html result of parsing http response
    :param ssl_verification_enabled: bool to enable SSL verification
    :param session: current requests Session object
    :return:
    """

    roles_page_url = _action_url_on_validation_success(html_response)

    click.echo('Additional verification is required. Please check your mobile device', err=True)

    # The POST call in this function hangs until verification is completed
    return _retrieve_roles_page(
        roles_page_url,
        _context(html_response),
        session,
        ssl_verification_enabled
    )

    
def _retrieve_roles_page(roles_page_url, context, session, ssl_verification_enabled):
    response = session.post(
        roles_page_url,
        verify=ssl_verification_enabled,
        allow_redirects=True,
        data={
            'AuthMethod': 'AzureMfaServerAuthentication',
            'Context': context,
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

    html_response = ET.fromstring(response.text, ET.HTMLParser())
    return roles_assertion_extractor.extract(html_response)


def _context(html_response):
    context_query = './/input[@id="context"]'
    element = html_response.find(context_query)
    return element.get('value')

def _action_url_on_validation_success(html_response):
    post_url_query = './/form[@id="options"]'
    element = html_response.find(post_url_query)
    return element.get('action')
