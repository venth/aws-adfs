import time
import logging

import click
import lxml.etree as ET
from . import roles_assertion_extractor
from .helpers import trace_http_request

NOT_AUTHORIZED = 'Not authorized'
MFA_TIMEOUT = 'MFA request expired'


def extract(html_response, ssl_verification_enabled, session):
    return _retrieve_roles_page(html_response, session, ssl_verification_enabled)


def _retrieve_roles_page(html_response, session, ssl_verification_enabled):
    try:
        response = session.post(
            _action_url_on_validation_success(html_response),
            verify=ssl_verification_enabled,
            allow_redirects=True,
            data={
                'AuthMethod': 'SilverfortAdfs',
                'Context': _context(html_response),
            }
        )
        trace_http_request(response)
        if response.status_code != 200:
            raise click.ClickException(
                'Issues during redirection to aws roles page. The error response {}'.format(response))
        html_response = ET.fromstring(response.text, ET.HTMLParser())
        element = html_response.find('.//input[@name="SAMLResponse"]')
        if element is not None:
            logging.debug("Successfully retrieved user SAML token")
            # Save session cookies to avoid having to repeat MFA on each login
            session.cookies.save(ignore_discard=True)
            html_response = ET.fromstring(response.text, ET.HTMLParser())
            return roles_assertion_extractor.extract(html_response)

    except Exception as e:
        error_message = 'Encountered an error while trying to retrieve AWS roles page'
        logging.exception(error_message)
        raise click.ClickException(f"{error_message}: {e}")

    if NOT_AUTHORIZED in response.text:
        raise click.ClickException("Access is denied. User is not authorized")

    if MFA_TIMEOUT in response.text:
        raise click.ClickException("Access is denied. Timeout waiting for MFA approval")

    raise click.ClickException(f"Received an unexpected response: {response}. Returning")


def _context(html_response):
    context_query = './/input[@id="context"]'
    element = html_response.find(context_query)
    return element.get('value')


def _action_url_on_validation_success(html_response):
    post_url_query = './/form[@id="options"]'
    element = html_response.find(post_url_query)

    return element.get('action')
