import mock

from aws_adfs import html_roles_fetcher


class TestFetchHtmlEncodedRoles:

    def test_missing_cookie_and_credentials_results_with_empty(self):
        # given adfs host which doesn't care that ssl is enabled or not
        adfs_host = 'adfs.awsome.com'
        ssl_verification_is_irrelevant = False

        requests = html_roles_fetcher.requests = mock.Mock()

        new_session = mock.Mock()
        requests.Session = mock.Mock(return_value=new_session)
        empty_response = mock.Mock()
        empty_response.text = '<html></html>'
        new_session.post = mock.Mock(return_value=empty_response)

        # and there isn't authentication cookie stored
        there_is_no_cookie_on_the_location = 'no/authenticated/cookie/stored'

        html_roles_fetcher.cookielib = mock.Mock()
        cookie_jar = mock.Mock()
        html_roles_fetcher.cookielib.LWPCookieJar = mock.Mock(return_value=cookie_jar)
        cookie_jar.load = mock.Mock(side_effect=IOError('No cookie. Still hungry'))

        # and credentials are not provided
        no_credentials_provided = None

        # when a call against adfs host is performed
        html = html_roles_fetcher.fetch_html_encoded_roles(
            adfs_host=adfs_host,
            adfs_cookie_location=there_is_no_cookie_on_the_location,
            ssl_verification_enabled=ssl_verification_is_irrelevant,
            username=no_credentials_provided,
            password=no_credentials_provided,
        )

        # then returned html is empty
        assert html.text is None

    def test_always_use_en_on_accept_language(self):
        # given adfs host which doesn't care that ssl is enabled or not
        adfs_host = 'adfs.awsome.com'
        ssl_verification_is_irrelevant = False

        requests = html_roles_fetcher.requests = mock.Mock()

        new_session = mock.Mock()
        requests.Session = mock.Mock(return_value=new_session)
        empty_response = mock.Mock()
        empty_response.text = '<html></html>'
        new_session.post = mock.Mock(return_value=empty_response)

        # and authentication cookie isn't relevant
        there_is_no_cookie_on_the_location = 'no/authenticated/cookie/stored'

        html_roles_fetcher.cookielib = mock.Mock()
        html_roles_fetcher.cookielib.LWPCookieJar = mock.Mock(return_value=mock.Mock())

        # and credentials are not provided
        no_credentials_provided = None

        # when a call against adfs host is performed
        html = html_roles_fetcher.fetch_html_encoded_roles(
            adfs_host=adfs_host,
            adfs_cookie_location=there_is_no_cookie_on_the_location,
            ssl_verification_enabled=ssl_verification_is_irrelevant,
            username=no_credentials_provided,
            password=no_credentials_provided,
        )

        # then en was requested as preferred language
        new_session.post.assert_called_with(
            html_roles_fetcher._IDP_ENTRY_URL.format(adfs_host),
            verify=ssl_verification_is_irrelevant,
            headers={'Accept-Language': 'en'},
            data={
                'UserName': no_credentials_provided,
                'Password': no_credentials_provided,
                'AuthMethod': 'urn:amazon:webservices'
            }
        )
