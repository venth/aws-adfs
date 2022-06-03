import base64
import binascii
import click
import lxml.etree as ET

from fido2.client import ClientData, ClientError, Fido2Client
from fido2.hid import CtapHidDevice

try:
    from fido2.pcsc import CtapPcscDevice
except ImportError:
    CtapPcscDevice = None

import logging
import json
import re

from threading import Event, Thread

from .helpers import trace_http_request

try:
    # Python 3
    from urllib.parse import urlparse, parse_qs
    import queue
except ImportError:
    # Python 2
    from urlparse import urlparse, parse_qs
    import Queue as queue

from . import roles_assertion_extractor

_headers = {
    "Accept-Language": "en",
    "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    "Accept": "text/plain, */*; q=0.01",
}


def extract(html_response, ssl_verification_enabled, session, duo_factor, duo_device):
    """
    this strategy is based on description from: https://guide.duo.com/universal-prompt
    :param response: raw http response
    :param html_response: html result of parsing http response
    :return:
    """

    duo_url = _duo_url(html_response)
    adfs_context = _adfs_context(html_response)
    adfs_auth_method = _adfs_auth_method(html_response)
    roles_page_url = _action_url_on_validation_success(html_response)

    click.echo("Sending request for authentication", err=True)
    (
        sid,
        xsrf,
        preferred_factor,
        preferred_device,
        webauthn_supported,
        auth_signature,
        duo_url,
    ), initiated = _initiate_authentication(
        duo_url,
        adfs_context,
        adfs_auth_method,
        roles_page_url,
        session,
        ssl_verification_enabled,
    )
    if initiated:
        if auth_signature is None:
            click.echo("Waiting for additional authentication", err=True)

            if preferred_factor is None or preferred_device is None:
                click.echo("No default authentication method configured.")
                preferred_factor = click.prompt(
                    text="Please enter your desired authentication method (Ex: Duo Push)",
                    type=str,
                )

            if webauthn_supported and preferred_factor == preferred_device:
                preferred_factor = "WebAuthn Security Key"

            # Trigger default authentication (call, push or WebAuthn with FIDO U2F / FIDO2 authenticator)
            signed_response = _perform_authentication_transaction(
                duo_url,
                sid,
                xsrf,
                duo_factor if duo_factor else preferred_factor,
                duo_device if duo_device else preferred_device,
                webauthn_supported,
                session,
                ssl_verification_enabled,
            )
            if signed_response == "cancelled":
                click.echo("Authentication method cancelled, aborting.")
                exit(-2)

        click.echo("Going for aws roles", err=True)
        return _retrieve_roles_page(
            roles_page_url,
            adfs_context,
            session,
            ssl_verification_enabled,
            signed_response,
        )

    return None, None, None


def _perform_authentication_transaction(
    duo_url,
    sid,
    xsrf,
    factor,
    device,
    webauthn_supported,
    session,
    ssl_verification_enabled,
):
    duo_host = re.sub(
        r"/frame/frameless/v4/auth.*",
        "",
        duo_url,
    )

    txid = _begin_authentication_transaction(
        duo_host,
        sid,
        factor,
        device,
        webauthn_supported,
        session,
        ssl_verification_enabled,
    )

    txid = _verify_authentication_status(
        duo_host,
        sid,
        txid,
        session,
        ssl_verification_enabled,
    )
    if txid == "cancelled":
        return "cancelled"
    else:
        return _authentication_result(duo_host, sid, txid, factor, xsrf, session, ssl_verification_enabled)


def _context(html_response):
    context_query = './/input[@id="context"]'
    element = html_response.find(context_query)
    return element.get("value")


def _retrieve_roles_page(roles_page_url, context, session, ssl_verification_enabled, signed_response):
    logging.debug("context: {}".format(context))
    logging.debug("signed_response: {}".format(signed_response))

    html_response = ET.fromstring(signed_response.text, ET.HTMLParser())
    context = html_response.find('.//input[@name="context"]').get("value")
    duo_code = html_response.find('.//input[@name="duo_code"]').get("value")
    state = html_response.find('.//input[@name="state"]').get("value")
    authMethod = html_response.find('.//input[@name="authMethod"]').get("value")
    adfs_url = html_response.find('.//form[@class="adfs_form"]').get("action")

    data = {
        "duo_code": duo_code,
        "state": state,
        "context": context,
        "authMethod": authMethod,
    }
    response = session.post(
        adfs_url,
        verify=ssl_verification_enabled,
        headers=_headers,
        allow_redirects=True,
        data=data,
    )
    trace_http_request(response)

    if response.status_code != 200:
        raise click.ClickException("Issues during redirection to aws roles page. The error response {}".format(response))

    # Save session cookies to avoid having to repeat MFA on each login
    session.cookies.save(ignore_discard=True)

    html_response = ET.fromstring(response.text, ET.HTMLParser())
    return roles_assertion_extractor.extract(html_response)


def _authentication_result(duo_host, sid, txid, factor, xsrf, session, ssl_verification_enabled):
    status_for_url = duo_host + "/frame/v4/status"
    data = {"sid": sid, "txid": txid}
    response = session.post(status_for_url, verify=ssl_verification_enabled, headers=_headers, data=data)
    trace_http_request(response)

    if response.status_code != 200:
        raise click.ClickException(
            "Issues during retrieval of a code entered into the device. The error response {}".format(response)
        )

    json_response = response.json()
    if json_response["stat"] != "OK":
        raise click.ClickException(
            "There was an issue during retrieval of a code entered into the device."
            " The error response: {}".format(response.text)
        )

    if json_response["response"]["status_code"] != "allow":
        raise click.ClickException(
            "There was an issue during retrieval of a code entered into the device."
            " The error response: {}".format(response.text)
        )

    return _load_duo_result_url(duo_host, sid, txid, factor, xsrf, session, ssl_verification_enabled)


def _load_duo_result_url(duo_host, sid, txid, factor, xsrf, session, ssl_verification_enabled):
    result_for_url = duo_host + "/frame/v4/oidc/exit"
    data = {
        "sid": sid,
        "txid": txid,
        "factor": factor,
        "device_key": "",
        "_xsrf": xsrf,
        "dampen_choice": False,
    }
    response = session.post(result_for_url, verify=ssl_verification_enabled, headers=_headers, data=data)
    trace_http_request(response)

    if response.status_code != 200:
        raise click.ClickException(
            "Issues when following the Duo result URL after authentication. The error response {}".format(response)
        )

    return response


def _verify_authentication_status(duo_host, sid, txid, session, ssl_verification_enabled):
    status_for_url = duo_host + "/frame/v4/status"

    responses = []
    while len(responses) < 10:
        data = {"sid": sid, "txid": txid}
        response = session.post(status_for_url, verify=ssl_verification_enabled, headers=_headers, data=data)
        trace_http_request(response)

        if response.status_code != 200:
            raise click.ClickException("Issues during second factor verification. The error response {}".format(response))

        json_response = response.json()
        if json_response["stat"] != "OK":
            raise click.ClickException(
                "There was an issue during second factor verification. The error response: {}".format(response.text)
            )

        if json_response["response"]["status_code"] not in [
            "answered",
            "calling",
            "pushed",
            "webauthn_sent",
        ]:
            raise click.ClickException(
                "There was an issue during second factor verification. The error response: {}".format(response.text)
            )

        if json_response["response"]["status_code"] in ["pushed", "answered", "allow"]:
            return txid

        if (
            json_response["response"]["status_code"] == "webauthn_sent"
            and len(json_response["response"]["webauthn_credential_request_options"]) > 0
        ):
            webauthn_credential_request_options = json_response["response"]["webauthn_credential_request_options"]
            webauthn_credential_request_options["challenge"] = base64.b64decode(webauthn_credential_request_options["challenge"])
            for cred in webauthn_credential_request_options["allowCredentials"]:
                cred["id"] = base64.urlsafe_b64decode(
                    cred["id"] + "=="
                )  # Add arbitrary padding characters, unnecessary ones are ignored
                cred.pop("transports")

            webauthn_session_id = webauthn_credential_request_options.pop("sessionId")

            devices = list(CtapHidDevice.list_devices())
            if CtapPcscDevice:
                devices.extend(list(CtapPcscDevice.list_devices()))

            if not devices:
                click.echo("No FIDO U2F / FIDO2 authenticator is eligible.")
                return "cancelled"

            threads = []
            webauthn_response = {"sessionId": webauthn_session_id}
            rq = queue.Queue()
            cancel = Event()
            for device in devices:
                t = Thread(
                    target=_webauthn_get_assertion,
                    args=(
                        device,
                        webauthn_credential_request_options,
                        duo_host,
                        sid,
                        webauthn_response,
                        session,
                        ssl_verification_enabled,
                        cancel,
                        rq,
                    ),
                )
                t.daemon = True
                threads.append(t)
                t.start()

            # Wait for first answer
            return rq.get()

        responses.append(response.text)

    raise click.ClickException("There was an issue during second factor verification. The responses: {}".format(responses))


def _webauthn_get_assertion(
    device,
    webauthn_credential_request_options,
    duo_host,
    sid,
    webauthn_response,
    session,
    ssl_verification_enabled,
    cancel,
    rq,
):
    click.echo(
        "Activate your FIDO U2F / FIDO2 authenticator now: '{}'".format(device),
        err=True,
    )
    client = Fido2Client(device, webauthn_credential_request_options["extensions"]["appid"])
    try:
        assertion = client.get_assertion(
            webauthn_credential_request_options,
            event=cancel,
        )
        authenticator_assertion_response = assertion.get_response(0)
        assertion_response = assertion.get_assertions()[0]

        webauthn_response["id"] = (
            base64.urlsafe_b64encode(assertion_response.credential["id"]).decode("ascii").rstrip("=")
        )  # Strip trailing padding characters
        webauthn_response["rawId"] = webauthn_response["id"]
        webauthn_response["type"] = assertion_response.credential["type"]
        webauthn_response["authenticatorData"] = base64.urlsafe_b64encode(assertion_response.auth_data).decode("ascii")
        webauthn_response["clientDataJSON"] = base64.urlsafe_b64encode(authenticator_assertion_response["clientData"]).decode(
            "ascii"
        )
        webauthn_response["signature"] = binascii.hexlify(assertion_response.signature).decode("ascii")
        webauthn_response["extensionResults"] = authenticator_assertion_response["extensionResults"]
        logging.debug("webauthn_response: {}".format(webauthn_response))

        click.echo(
            "Got response from FIDO U2F / FIDO2 authenticator: '{}'".format(device),
            err=True,
        )
        rq.put(_submit_webauthn_response(duo_host, sid, webauthn_response, session, ssl_verification_enabled))
    except Exception as e:
        logging.debug("Got an exception while waiting for {}: {}".format(device, e))
        if not cancel.is_set():
            raise
    finally:
        # Cancel the other FIDO U2F / FIDO2 prompts
        cancel.set()

        device.close()


_tx_pattern = re.compile("(TX\|[^:]+):APP.+")


def _tx(request_signature):
    m = _tx_pattern.search(request_signature)
    return m.group(1)


_app_pattern = re.compile(".*(APP\|[^:]+)")


def _app(request_signature):
    m = _app_pattern.search(request_signature)
    return m.group(1)


def _initiate_authentication(
    duo_url,
    adfs_context,
    adfs_auth_method,
    roles_page_url,
    session,
    ssl_verification_enabled,
):
    data = {
        "adfs_context": adfs_context,
        "adfs_auth_method": adfs_auth_method,
    }
    response = session.post(
        duo_url,
        verify=ssl_verification_enabled,
        headers=_headers,
        allow_redirects=True,
        data=data,
    )
    trace_http_request(response)

    if response.status_code != 200 or response.url is None:
        return (None, None, None, None, None, None, None), False

    duo_url = response.url
    o = urlparse(duo_url)
    query = parse_qs(o.query)
    html_response = ET.fromstring(response.text, ET.HTMLParser())

    sid = query.get("sid")
    if sid is None:
        # No need for second factor authentification, Duo directly returned the authentication cookie
        return (None, None, None, None, None, _js_cookie(html_response), duo_url), True

    tx = html_response.find('.//input[@name="tx"]').get("value")
    xsrf = html_response.find('.//input[@name="_xsrf"]').get("value")

    data = {
        "tx": tx,
        "parent": "None",
        "_xsrf": xsrf,
        "java_version": "",
        "flash_version": "",
        "screen_resolution_width": "",
        "screen_resolution_height": "",
        "color_depth": "",
        "ch_ua_error": "",
        "client_hints": "",
        "is_cef_browser": "",
        "is_ipad_os": "",
        "is_ie_compatibility_mode": "",
        "is_user_verifying_platform_authenticator_available": "",
        "user_verifying_platform_authenticator_available_error": "",
        "acting_ie_version": "",
        "react_support": "",
        "react_support_error_message": "",
    }
    response = session.post(
        duo_url,
        verify=ssl_verification_enabled,
        headers=_headers,
        allow_redirects=True,
        data=data,
    )
    trace_http_request(response)

    html_response = ET.fromstring(response.text, ET.HTMLParser())
    preferred_factor = _preferred_factor(html_response)
    preferred_device = _preferred_device(html_response)
    webauthn_supported = _webauthn_supported(html_response)
    xsrf = _xsrf(html_response)
    return (sid, xsrf, preferred_factor, preferred_device, webauthn_supported, None, duo_url), True


def _js_cookie(html_response):
    js_cookie_query = './/input[@name="js_cookie"]'
    element = html_response.find(js_cookie_query)
    return element is not None and element.get("value") or None


def _preferred_factor(html_response):
    preferred_factor_query = './/input[@name="preferred_factor"]'
    element = html_response.find(preferred_factor_query)
    return element is not None and element.get("value") or None


def _preferred_device(html_response):
    preferred_device_query = './/input[@name="preferred_device"]'
    element = html_response.find(preferred_device_query)
    return element is not None and element.get("value") or None


def _webauthn_supported(html_response):
    webauthn_supported_query = './/input[@name="factor"][@value="WebAuthn Credential"]'
    elements = html_response.findall(webauthn_supported_query)
    return len(elements) > 0


def _xsrf(html_response):
    xsrf_query = './/input[@name="_xsrf"]'
    element = html_response.find(xsrf_query)
    return element is not None and element.get("value") or None


def _begin_authentication_transaction(
    duo_host,
    sid,
    preferred_factor,
    preferred_device,
    webauthn_supported,
    session,
    ssl_verification_enabled,
):
    duo_url = duo_host + "/frame/v4/prompt"

    click.echo(
        "Triggering authentication method: '{}' with '{}".format(preferred_factor, preferred_device),
        err=True,
    )

    data = {
        "sid": sid,
        "factor": preferred_factor,
        "device": preferred_device,
    }
    response = session.post(duo_url, verify=ssl_verification_enabled, headers=_headers, data=data)
    trace_http_request(response)

    if response.status_code != 200:
        raise click.ClickException(
            "Issues during beginning of the authentication process. The error response {}".format(response)
        )

    json_response = response.json()
    if json_response["stat"] != "OK":
        raise click.ClickException("Cannot begin authentication process. The error response: {}".format(response.text))

    return json_response["response"]["txid"]


def _submit_webauthn_response(duo_host, sid, webauthn_response, session, ssl_verification_enabled):
    prompt_for_url = duo_host + "/frame/v4/prompt"

    data = {
        "sid": sid,
        "device": "webauthn_credential",
        "factor": "webauthn_finish",
        "response_data": json.dumps(webauthn_response),
    }
    response = session.post(prompt_for_url, verify=ssl_verification_enabled, headers=_headers, data=data)
    trace_http_request(response)

    if response.status_code != 200:
        raise click.ClickException(
            "Issues during submitting WebAuthn response for the authentication process. The error response {}".format(response)
        )

    json_response = response.json()
    if json_response["stat"] != "OK":
        raise click.ClickException("Cannot complete authentication process. The error response: {}".format(response.text))

    return json_response["response"]["txid"]


def _duo_url(html_response):
    duo_url_query = './/form[@id="adfs_form"]/@action'
    return html_response.xpath(duo_url_query)[0]


def _adfs_context(html_response):
    adfs_context_query = './/form[@id="adfs_form"]/input[@name="adfs_context"]/@value'
    return html_response.xpath(adfs_context_query)[0]


def _adfs_auth_method(html_response):
    adfs_auth_method_query = './/form[@id="adfs_form"]/input[@name="adfs_auth_method"]/@value'
    return html_response.xpath(adfs_auth_method_query)[0]


def _action_url_on_validation_success(html_response):
    duo_auth_method = './/form[@id="options"]'
    element = html_response.find(duo_auth_method)
    return element.get("action")
