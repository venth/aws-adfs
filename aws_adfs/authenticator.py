import lxml.etree as ET

from . import _duo_authenticator as duo_auth
from . import html_roles_fetcher
from . import roles_assertion_extractor


def authenticate(config, username=None, password=None):

    response, session = html_roles_fetcher.fetch_html_encoded_roles(
        adfs_host=config.adfs_host,
        adfs_cookie_location=config.adfs_cookie_location,
        ssl_verification_enabled=config.ssl_verification,
        provider_id=config.provider_id,
        username=username,
        password=password,
    )

    extract_strategy = _strategy(response, config, session)

    return extract_strategy()


def _strategy(response, config, session):

    html_response = ET.fromstring(response.text, ET.HTMLParser())

    def _plain_extractor():
        def extract():
            return roles_assertion_extractor.extract(html_response)
        return extract

    def _duo_extractor():
        def extract():
            return duo_auth.extract(html_response, config.ssl_verification, session)
        return extract

    chosen_strategy = _plain_extractor

    if _is_duo_authentication(html_response):
        chosen_strategy = _duo_extractor

    return chosen_strategy()


def _is_duo_authentication(html_response):
    duo_auth_method = './/input[@id="authMethod"]'
    element = html_response.find(duo_auth_method)
    duo = element is not None
    duo = duo and element.get('value') == 'DuoAdfsAdapter'
    return duo
