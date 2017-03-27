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
        empty_response.status_code = 400
        new_session.post = mock.Mock(return_value=empty_response)

        # and there isn't authentication cookie stored
        there_is_no_cookie_on_the_location = 'no/authenticated/cookie/stored'

        cookie_jar = mock.Mock()
        cookie_jar.load = mock.Mock(side_effect=IOError('No cookie. Still hungry'))
        cookie_jar.clear = mock.Mock()
        html_roles_fetcher.cookielib = mock.Mock()
        html_roles_fetcher.cookielib.LWPCookieJar = mock.Mock(return_value=cookie_jar)

        # and credentials are not provided
        no_credentials_provided = None

        # and provider_id are not provided
        no_provider_id_provided = None

        # when a call against adfs host is performed
        fetched_response, session = html_roles_fetcher.fetch_html_encoded_roles(
            adfs_host=adfs_host,
            adfs_cookie_location=there_is_no_cookie_on_the_location,
            ssl_verification_enabled=ssl_verification_is_irrelevant,
            provider_id=no_provider_id_provided,
            username=no_credentials_provided,
            password=no_credentials_provided,
        )

        # then returned html is empty
        assert fetched_response == empty_response
        cookie_jar.clear.assert_called()

    def test_always_use_en_on_accept_language(self):
        # given adfs host which doesn't care that ssl is enabled or not
        adfs_host = 'adfs.awsome.com'
        provider_id = None
        ssl_verification_is_irrelevant = False

        requests = html_roles_fetcher.requests = mock.Mock()

        new_session = mock.Mock()
        requests.Session = mock.Mock(return_value=new_session)
        empty_response = mock.Mock()
        empty_response.status_code = 200
        empty_response.text = '<html></html>'
        new_session.post = mock.Mock(return_value=empty_response)

        # and authentication cookie isn't relevant
        there_is_no_cookie_on_the_location = 'no/authenticated/cookie/stored'

        cookie_jar = mock.Mock()
        cookie_jar.load = mock.Mock(side_effect=IOError('No cookie. Still hungry'))
        cookie_jar.clear = mock.Mock()
        html_roles_fetcher.cookielib = mock.Mock()
        html_roles_fetcher.cookielib.LWPCookieJar = mock.Mock(return_value=cookie_jar)

        # and credentials are not provided
        no_credentials_provided = None

        # and authentication provider is irrelevant (adfs or windws sspi)
        authenticator_is_irrelevant = None

        # and provider_id are not provided
        no_provider_id_provided = None

        # when a call against adfs host is performed
        html_roles_fetcher.fetch_html_encoded_roles(
            adfs_host=adfs_host,
            adfs_cookie_location=there_is_no_cookie_on_the_location,
            ssl_verification_enabled=ssl_verification_is_irrelevant,
            provider_id=no_provider_id_provided,
            username=no_credentials_provided,
            password=no_credentials_provided,
        )

        # then en was requested as preferred language
        new_session.post.assert_called_with(
            html_roles_fetcher._IDP_ENTRY_URL.format(adfs_host, provider_id),
            verify=ssl_verification_is_irrelevant,
            auth=authenticator_is_irrelevant,
            headers={'Accept-Language': 'en'},
            data={
                'UserName': no_credentials_provided,
                'Password': no_credentials_provided,
                'AuthMethod': provider_id
            }
        )

        cookie_jar.clear.assert_not_called()
