#
# This code is verified to work in a setup with Azure Active Directory Premium + MFA adapter in a
# hybrid setup with push notifications to the Microsoft Authenticator app for approval.
# See https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-getstarted
#
import click
import lxml.etree as ET

import logging
import time

from . import roles_assertion_extractor
from .helpers import trace_http_request


def extract(html_response, ssl_verification_enabled, session):
    """
    :param html_response: html result of parsing http response
    :param ssl_verification_enabled: bool to enable SSL verification
    :param session: current requests Session object
    :return:
    """

    roles_page_url = _action_url_on_validation_success(html_response)

    click.echo('Additional verification is required. Please check your mobile device', err=True)

    # This function polls until we get a SAMLResponse
    return _retrieve_roles_page(
        roles_page_url,
        _context(html_response),
        session,
        ssl_verification_enabled
    )


def _retrieve_roles_page(roles_page_url, context, session, ssl_verification_enabled):
    seconds_to_wait = 5
    max_attempts = 12
    counter = 1

    while True:
        time.sleep(seconds_to_wait)

        response = session.post(
            roles_page_url,
            verify=ssl_verification_enabled,
            allow_redirects=True,
            data={
                'AuthMethod': 'AzureMfaAuthentication',
                'Context': context,
            }
        )
        trace_http_request(response)

        if response.status_code != 200:
            raise click.ClickException(
                u'Issues during redirection to aws roles page. The error response {}'.format(
                    response
                )
            )

        html_response = ET.fromstring(response.text, ET.HTMLParser())
        element = html_response.find('.//input[@name="SAMLResponse"]')

        if element is not None:
            break

        if counter == max_attempts:
            raise click.ClickException(u'Timeout waiting for MFA approval')

        counter += 1

    # Save session cookies to avoid having to repeat MFA on each login
    session.cookies.save(ignore_discard=True)

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
