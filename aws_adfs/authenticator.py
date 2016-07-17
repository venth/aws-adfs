from . import html_roles_fetcher
from . import roles_assertion_extractor


def authenticate(config, username=None, password=None):

    html = html_roles_fetcher.fetch_html_encoded_roles(
        adfs_host=config.adfs_host,
        adfs_cookie_location=config.adfs_cookie_location,
        ssl_verification_enabled=config.ssl_verification,
        username=username,
        password=password,
    )
    return roles_assertion_extractor.extract(html)
