import logging
import lxml.etree as ET

from . import account_aliases_fetcher
from . import _duo_authenticator as duo_auth
from . import _rsa_authenticator as rsa_auth
from . import _symantec_vip_access as symantec_vip_access
from . import _azure_mfa_authenticator as azure_mfa_auth
from . import html_roles_fetcher
from . import roles_assertion_extractor


def authenticate(config, username=None, password=None, assertfile=None, sspi=True):

    response, session = html_roles_fetcher.fetch_html_encoded_roles(
        adfs_host=config.adfs_host,
        adfs_cookie_location=config.adfs_cookie_location,
        ssl_verification_enabled=config.ssl_verification,
        adfs_ca_bundle=config.adfs_ca_bundle,
        provider_id=config.provider_id,
        username=username,
        password=password,
        sspi=sspi
    )

    assertion = None
    aws_session_duration = None

    aggregated_principal_roles = None
    if response.status_code == 200:
        extract_strategy = _strategy(response, config, session, assertfile)

        principal_roles, assertion, aws_session_duration = extract_strategy()

        if assertion is None:
            logging.debug(u'''Cannot extract saml assertion from request's response. Re-authentication needed?:
                * url: {}
                * headers: {}
            Response:
                * status: {}
                * headers: {}
                * body: {}
            '''.format(
                response.url,
                response.request.headers,
                response.status_code,
                response.headers,
                response.text
            ))
            logging.error(u'Cannot extract saml assertion. Re-authentication needed?')
        else:
            aggregated_principal_roles = _aggregate_roles_by_account_alias(session,
                                                                           config,
                                                                           username,
                                                                           password,
                                                                           assertion,
                                                                           principal_roles)

    else:
        logging.debug(u'''Cannot extract roles from request's response:
                * url: {}
                * headers: {}
            Response:
                * status: {}
                * headers: {}
                * body: {}
            '''.format(
            response.url,
            response.request.headers,
            response.status_code,
            response.headers,
            response.text
        ))
        logging.error(u'Cannot extract roles from response')

    logging.debug(u'Roles along with principals found after authentication: {}'.format(aggregated_principal_roles))

    return aggregated_principal_roles, assertion, aws_session_duration


def _aggregate_roles_by_account_alias(session,
                                      config,
                                      username,
                                      password,
                                      assertion,
                                      principal_roles):
    account_aliases = account_aliases_fetcher.account_aliases(session, username, password, config.provider_id, assertion, config)
    aggregated_accounts = {}
    for (principal_arn, role_arn) in principal_roles:
        role_name = role_arn.split(':role/')[1]
        account_no = role_arn.split(':')[4]

        if account_no not in account_aliases:
            account_aliases[account_no] = account_no

        if account_aliases[account_no] not in aggregated_accounts:
            aggregated_accounts[account_aliases[account_no]] = {}
        aggregated_accounts[account_aliases[account_no]][role_arn] = {'name': role_name, 'principal_arn': principal_arn}
    return aggregated_accounts


def _strategy(response, config, session, assertfile=None):

    html_response = ET.fromstring(response.text, ET.HTMLParser())

    def _plain_extractor():
        def extract():
            return roles_assertion_extractor.extract(html_response)
        return extract

    def _duo_extractor():
        def extract():
            return duo_auth.extract(html_response, config.ssl_verification, session)
        return extract

    def _symantec_vip_extractor():
        def extract():
            return symantec_vip_access.extract(html_response, config.ssl_verification, session)
        return extract

    def _file_extractor():
        def extract():
            return roles_assertion_extractor.extract_file(assertfile)
        return extract

    def _rsa_auth_extractor():
        def extract():
            return rsa_auth.extract(html_response, config.ssl_verification, session)
        return extract

    def _azure_mfa_extractor():
        def extract():
            return azure_mfa_auth.extract(html_response, config.ssl_verification, session)
        return extract

    if assertfile is None:
        chosen_strategy = _plain_extractor
    else:
        chosen_strategy = _file_extractor

    if _is_duo_authentication(html_response):
        chosen_strategy = _duo_extractor
    elif _is_symantec_vip_authentication(html_response):
        chosen_strategy = _symantec_vip_extractor
    elif _is_rsa_authentication(html_response):
        chosen_strategy = _rsa_auth_extractor
    elif _is_azure_mfa_authentication(html_response):
        chosen_strategy = _azure_mfa_extractor

    return chosen_strategy()


def _is_duo_authentication(html_response):
    duo_auth_method = './/input[@id="authMethod"]'
    element = html_response.find(duo_auth_method)
    duo = element is not None
    duo = duo and element.get('value') == 'DuoAdfsAdapter'
    return duo

def _is_symantec_vip_authentication(html_response):
    auth_method = './/input[@id="authMethod"]'
    element = html_response.find(auth_method)
    return (
        element is not None
        and element.get('value') == 'SymantecVipAdapter'
    )

def _is_rsa_authentication(html_response):
    auth_method = './/input[@id="authMethod"]'
    element = html_response.find(auth_method)
    return (
        element is not None
        and element.get('value') == 'SecurIDAuthentication'
    )

def _is_azure_mfa_authentication(html_response):
    auth_method = './/input[@id="authMethod"]'
    element = html_response.find(auth_method)
    return (
        element is not None
        and element.get('value') == 'AzureMfaServerAuthentication'
    )
