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


def extract(html_response, ssl_verification_enabled, verification_code, session):
    """
    :param html_response: html result of parsing http response
    :param ssl_verification_enabled: bool to enable SSL verification
    :param session: current requests Session object
    :return:
    """

    click.echo(_mfa_instructions(html_response), err=True)
    
    return _retrieve_roles_page(
        html_response,
        session,
        ssl_verification_enabled,
        verification_code
    )

def _retrieve_roles_page(html_response, session, ssl_verification_enabled, verification_code):
    seconds_to_wait = 5
    max_attempts = 12
    counter = 1

    while True:
        time.sleep(seconds_to_wait)

        verification_code_text = _verification_code_text(html_response)
        if verification_code_text is not None and verification_code is None:
            verification_code = click.prompt(verification_code_text)
            seconds_to_wait = 0

        response = session.post(
            _action_url_on_validation_success(html_response),
            verify=ssl_verification_enabled,
            allow_redirects=True,
            data={
                'AuthMethod': 'AzureMfaAuthentication',
                'Context': _context(html_response),
                'VerificationCode': verification_code,
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
            raise click.ClickException(u'Unsuccessful MFA verification' if verification_code else u'Timeout waiting for MFA approval')

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

def _mfa_instructions(html_response):
    mfa_instructions_query = './/p[@id="instructions"]'
    element = html_response.find(mfa_instructions_query)
    return element.text if element is not None else ''

def _verification_code_text(html_response):
    verification_code_query = './/input[@id="verificationCodeInput"]'
    element = html_response.find(verification_code_query)
    return None if element is None else element.get('placeholder')
