import click
import lxml.etree as ET

import logging
import re

from . import run_command

try:
    # Python 3
    from urllib.parse import urlparse, parse_qs
except ImportError:
    # Python 2
    from urlparse import urlparse, parse_qs

from . import roles_assertion_extractor
from .helpers import trace_http_request


def extract(html_response, ssl_verification_enabled, mfa_token_command, mfa_token, session):
    """
    :param response: raw http response
    :param html_response: html result of parsing http response
    :return:
    """

    roles_page_url = _action_url_on_validation_success(html_response)

    if mfa_token_command:
      data = run_command.run_command(mfa_token_command)
      rsa_securid_code = data['mfa_token']
      logging.debug(f"using RSA SecurID token from command: {rsa_securid_code}")
    elif mfa_token:
      rsa_securid_code = mfa_token
      logging.debug(f"using RSA SecurID token from env: {rsa_securid_code}")
    else:
      rsa_securid_code = click.prompt(text='Enter your RSA SecurID token', type=str, hide_input=True)

    click.echo('Going for aws roles', err=True)
    return _retrieve_roles_page(
        roles_page_url,
        _context(html_response),
        session,
        ssl_verification_enabled,
        rsa_securid_code,
    )

def _context(html_response):
    context_query = './/input[@id="context"]'
    element = html_response.find(context_query)
    return element.get('value')


def _retrieve_roles_page(roles_page_url, context, session, ssl_verification_enabled,
                         rsa_securid_code):
    response = session.post(
        roles_page_url,
        verify=ssl_verification_enabled,
        allow_redirects=True,
        data={
            'AuthMethod': 'SecurIDAuthentication',
            'Context': context,
            'Passcode': rsa_securid_code,
        }
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

def _action_url_on_validation_success(html_response):
    vip_auth_method = './/form[@id="options"]'
    element = html_response.find(vip_auth_method)
    return element.get('action')
