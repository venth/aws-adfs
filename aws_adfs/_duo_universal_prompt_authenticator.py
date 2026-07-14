import binascii
import click
import lxml.etree as ET

from fido2.client import Fido2Client
from fido2.hid import CtapHidDevice
from fido2.utils import websafe_decode, websafe_encode

try:
    from fido2.pcsc import CtapPcscDevice
except ImportError:
    CtapPcscDevice = None

import logging
import json
import re
import time

from threading import Event, Thread

from .consts import (
    DUO_UNIVERSAL_PROMPT_FACTOR_DUO_PUSH,
    DUO_UNIVERSAL_PROMPT_FACTOR_PHONE_CALL,
    DUO_UNIVERSAL_PROMPT_FACTOR_WEBAUTHN,
    DUO_UNIVERSAL_PROMPT_FACTOR_PASSCODE,
)
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
        pwl_ctx,
    ), initiated = _initiate_authentication(
        duo_url,
        adfs_context,
        adfs_auth_method,
        roles_page_url,
        session,
        ssl_verification_enabled,
    )
    if initiated:
        # Duo migrated some tenants to the "pwl" Universal Prompt: a single page
        # app driven by /prompt/{akey}/auth/* JSON endpoints keyed by an authkey
        # instead of the older sid-based /frame/v4/* endpoints (upstream #446).
        if pwl_ctx is not None:
            click.echo("Waiting for additional authentication", err=True)

            if duo_factor:
                preferred_factor = duo_factor
            if duo_device:
                preferred_device = duo_device

            signed_response = _pwl_perform_authentication_transaction(
                pwl_ctx,
                preferred_factor,
                preferred_device,
                session,
                ssl_verification_enabled,
            )
            if signed_response == "cancelled":
                click.echo("Authentication method cancelled, aborting.")
                exit(-2)

            click.echo("Going for aws roles", err=True)
            return _pwl_retrieve_roles_page(
                signed_response,
                roles_page_url,
                adfs_context,
                session,
                ssl_verification_enabled,
            )

        if auth_signature is None:
            click.echo("Waiting for additional authentication", err=True)

            # Override preferred factor value if it the same as the device, which means WebAuthn
            if webauthn_supported and preferred_factor == preferred_device:
                preferred_factor = DUO_UNIVERSAL_PROMPT_FACTOR_WEBAUTHN

            # Prioritize configuration or command-line parameters factor and device over server-side preferred ones
            if duo_factor:
                preferred_factor = duo_factor
            if duo_device:
                preferred_device = duo_device

            if preferred_factor is None:
                click.echo("No default authentication method configured.")
                preferred_factor = click.prompt(
                    text=f'Please enter your desired authentication method (e.g. "{DUO_UNIVERSAL_PROMPT_FACTOR_DUO_PUSH}", "{DUO_UNIVERSAL_PROMPT_FACTOR_PASSCODE}", "{DUO_UNIVERSAL_PROMPT_FACTOR_PHONE_CALL}", or "{DUO_UNIVERSAL_PROMPT_FACTOR_WEBAUTHN}")',
                    type=str,
                )

            # In case of WebAuthn, the device must be "None"
            # In the case of Passcode the device is unimportant
            if preferred_factor in (DUO_UNIVERSAL_PROMPT_FACTOR_WEBAUTHN, DUO_UNIVERSAL_PROMPT_FACTOR_PASSCODE):
                preferred_device = "None"

            if preferred_device is None and preferred_factor not in (DUO_UNIVERSAL_PROMPT_FACTOR_WEBAUTHN, DUO_UNIVERSAL_PROMPT_FACTOR_PASSCODE):
                click.echo("No default authentication device configured.")
                preferred_device = click.prompt(
                    text=f'Please enter your desired authentication device (e.g. "phone1" with "{DUO_UNIVERSAL_PROMPT_FACTOR_DUO_PUSH}" or "{DUO_UNIVERSAL_PROMPT_FACTOR_PHONE_CALL}"), or "None" with "{DUO_UNIVERSAL_PROMPT_FACTOR_WEBAUTHN}" or "{DUO_UNIVERSAL_PROMPT_FACTOR_PASSCODE}"',
                    type=str,
                )

            # Trigger default authentication (call, push or WebAuthn with FIDO U2F / FIDO2 authenticator)
            signed_response = _perform_authentication_transaction(
                duo_url,
                sid,
                xsrf,
                preferred_factor,
                preferred_device,
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
        r"/frame/frameless/v\d+/auth.*",
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
            "HTTP status code not 200 during UP retrieval of a code entered into the device."
            "The error response: {}".format(response)
        )

    json_response = response.json()
    if json_response["stat"] != "OK":
        raise click.ClickException(
            "'stat' not ok during UP retrieval of a code entered into the device."
            " The error response: {}".format(response.text)
        )

    if json_response["response"]["status_code"] != "allow":
        raise click.ClickException(
            "Response 'status_code' not 'allow' during UP retrieval of a code entered into the device."
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
            f"HTTP status code not 200 when following the Duo result URL after authentication. The error response {response} - {response.url} - {response.text}"
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
                "'stat' not OK during UP second factor verification. The error response: {}".format(response.text)
            )

        if json_response["response"]["status_code"] not in [
            "answered",
            "calling",
            "pushed",
            "webauthn_sent",
            "allow"
        ]:
            raise click.ClickException(
                "Bad 'status_code' during UP second factor verification. The error response: {}".format(response.text)
            )

        if json_response["response"]["status_code"] == "pushed":
            verification_code = json_response["response"].get("risk_based_factor_selection_data", {}).get("step_up_code")
            if verification_code:
                click.echo(
                    f"Verified Duo Push MFA code: {verification_code}",
                    err=True,
                )

        if json_response["response"]["status_code"] in ["pushed", "answered", "allow"]:
            return txid

        if (
            json_response["response"]["status_code"] == "webauthn_sent"
            and len(json_response["response"]["webauthn_credential_request_options"]) > 0
        ):
            webauthn_credential_request_options = json_response["response"]["webauthn_credential_request_options"]
            webauthn_credential_request_options["challenge"] = websafe_decode(webauthn_credential_request_options["challenge"])
            for cred in webauthn_credential_request_options["allowCredentials"]:
                cred["id"] = websafe_decode(cred["id"])
                cred.pop("transports", None)

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

    raise click.ClickException("Number of responses exceeded during UP second factor verification. The responses: {}".format(responses))


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

        webauthn_response["id"] = websafe_encode(assertion_response.credential["id"])
        webauthn_response["rawId"] = webauthn_response["id"]
        webauthn_response["type"] = assertion_response.credential["type"]
        webauthn_response["authenticatorData"] = websafe_encode(assertion_response.auth_data)
        webauthn_response["clientDataJSON"] = websafe_encode(authenticator_assertion_response["clientData"])
        webauthn_response["signature"] = binascii.hexlify(assertion_response.signature).decode("ascii")
        extension_results = authenticator_assertion_response["extensionResults"]
        if extension_results:
            webauthn_response["extensionResults"] = extension_results
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
        return (None, None, None, None, None, None, None, None), False

    duo_url = response.url
    o = urlparse(duo_url)
    query = parse_qs(o.query)
    html_response = ET.fromstring(response.text, ET.HTMLParser())

    if _is_pwl_prompt(html_response):
        logging.info("Detected Duo pwl Universal Prompt (authkey-based flow)")
        pwl_ctx = _pwl_context(html_response, duo_url)
        return (None, None, None, None, None, None, duo_url, pwl_ctx), True

    sid = query.get("sid")
    if sid is None:
        logging.info("No need for second factor authentification, "
                     "Duo directly returned the authentication cookie")
        return (None, None, None, None, None, _js_cookie(html_response), duo_url, None), True

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
    for res in response.history:
        logging.info(f"history: {res} - {res.url}")

    # API BREAKING CHANGE. There's now a callback that has to happen here
    logging.info(f"duo_url: {duo_url}")
    logging.info(f"response.url: {response.url}")
    try:
        callback_response = session.post(
            response.url,
            verify=ssl_verification_enabled,
            headers=_headers,
            allow_redirects=True,
            params={"sid": sid, "tx": tx},
            data=data,
        )
        trace_http_request(callback_response)
        # Do not overwrite the response unconditionally. If this breaks for some users, we'll need to find out how the response
        # differs and how to use that for a decision what to do.
        # In the case where it's not needed, "stat": "FAIL" can be seen in the response.
        content_type = callback_response.headers.get('content-type')
        logging.debug(f"Callback response content type: {content_type}")
        if 'application/json' in content_type:
            callback_json = callback_response.json()
            if callback_json["stat"] == "OK":
                logging.info("Callback stat OK, using response.")
                response = callback_response
            else:
                logging.debug("Callback stat not OK, ignoring response.")
        else:
            logging.debug("Callback did not return json, ignoring response.")
    except Exception as e:
        logging.error("Error doing callback", exc_info=e)
        logging.error(f"ignoring: {e}")
    logging.info("Callback completed")

    html_response = ET.fromstring(response.text, ET.HTMLParser())
    preferred_factor = _preferred_factor(html_response)
    preferred_device = _preferred_device(html_response)
    webauthn_supported = _webauthn_supported(html_response)
    xsrf = _xsrf(html_response)
    return (sid, xsrf, preferred_factor, preferred_device, webauthn_supported, None, duo_url, None), True


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
    webauthn_supported_query = './/option[@name="webauthn"]'
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
        "Triggering authentication method: '{}' with '{}'".format(preferred_factor, preferred_device),
        err=True,
    )

    data = {
        "sid": sid,
        "factor": preferred_factor,
        "device": preferred_device,
    }

    # Prompt for a passcode?
    if preferred_factor == DUO_UNIVERSAL_PROMPT_FACTOR_PASSCODE:
        passcode = None
        while not passcode or not re.match(r'^[0-9]{6,}$', passcode):
            passcode = click.prompt('Enter passcode (6+ digit number)', hide_input=True)
        data['passcode'] = passcode
        data['device'] = 'None'

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


# ---------------------------------------------------------------------------
# Duo "pwl" Universal Prompt (single page app) support.
#
# Newer Duo tenants serve a JavaScript prompt whose root element exposes an
# akey/authkey and no longer a sid. Authentication is driven by JSON endpoints
# under /prompt/{akey}/auth/* identified by the authkey plus session cookies.
# See upstream issue #446.
# ---------------------------------------------------------------------------

_PWL_BROWSER_FEATURES = json.dumps(
    {
        "touch_supported": False,
        "platform_authenticator_status": "unavailable",
        "webauthn_supported": False,
        "screen_resolution_height": 1080,
        "screen_resolution_width": 1920,
        "screen_color_depth": 24,
        "is_uvpa_available": False,
        "client_capabilities_uvpa": False,
    }
)


def _is_pwl_prompt(html_response):
    # The pwl Universal Prompt root element carries the akey/authkey used to
    # drive the JSON auth endpoints.
    return bool(html_response.xpath("//*[@data-authkey]"))


def _pwl_context(html_response, duo_url):
    root = html_response.xpath("//*[@data-authkey]")[0]
    parsed = urlparse(duo_url)
    query = parse_qs(parsed.query)
    req_trace_group = root.get("data-req-trace-group") or query.get("req_trace_group", [None])[0]
    return {
        "host": parsed.netloc,
        "akey": root.get("data-akey"),
        "authkey": root.get("data-authkey"),
        "req_trace_group": req_trace_group,
    }


def _pwl_url(ctx, path):
    return "https://{}/prompt/{}{}".format(ctx["host"], ctx["akey"], path)


def _pwl_headers(ctx, json_body=False):
    headers = {
        "Accept": "application/json",
        "X-Requested-With": "XMLHttpRequest",
        "X-Duo-Req-Trace-Group": ctx.get("req_trace_group") or "",
    }
    if json_body:
        headers["Content-Type"] = "application/json"
    return headers


def _pwl_check_ok(response, context):
    if response.status_code != 200:
        raise click.ClickException(
            "HTTP {} while {}. The error response: {}".format(response.status_code, context, response.text)
        )
    try:
        body = response.json()
    except ValueError:
        raise click.ClickException("Non-JSON response while {}: {}".format(context, response.text))
    if body.get("stat") != "OK":
        raise click.ClickException("Duo returned a non-OK status while {}: {}".format(context, response.text))
    return body


def _pwl_find_devices(obj):
    # Recursively collect device descriptors (dicts that carry a "pkey").
    found = []
    if isinstance(obj, dict):
        if "pkey" in obj:
            found.append(obj)
        for value in obj.values():
            found.extend(_pwl_find_devices(value))
    elif isinstance(obj, list):
        for value in obj:
            found.extend(_pwl_find_devices(value))
    return found


def _pwl_select_pkey(payload, device):
    devices = _pwl_find_devices(payload)
    logging.info(
        "pwl devices discovered: {}".format(
            [{k: d.get(k) for k in ("pkey", "name", "index", "device")} for d in devices]
        )
    )
    if not devices:
        raise click.ClickException(
            "Could not find any Duo devices in the prompt payload: {}".format(json.dumps(payload))
        )

    if device and device != "None":
        for candidate in devices:
            if device in (candidate.get("index"), candidate.get("device"), candidate.get("name")):
                return candidate["pkey"]
        match = re.match(r"phone(\d+)$", device)
        if match:
            index = int(match.group(1)) - 1
            if 0 <= index < len(devices):
                return devices[index]["pkey"]

    return devices[0]["pkey"]


def _pwl_get_payload(ctx, session, ssl_verification_enabled):
    response = session.get(
        _pwl_url(ctx, "/auth/payload"),
        verify=ssl_verification_enabled,
        headers=_pwl_headers(ctx),
        params={"authkey": ctx["authkey"], "browser_features": _PWL_BROWSER_FEATURES},
    )
    trace_http_request(response)
    body = _pwl_check_ok(response, "fetching the Duo authentication payload")
    logging.info("pwl payload response: {}".format(json.dumps(body.get("response"))))
    return body["response"]


def _pwl_initialize_pre_authn(ctx, session, ssl_verification_enabled):
    # The SPA calls /pre_authn/initialization first to establish the server-side
    # auth session; /auth/payload returns HTTP 400 if this is skipped.
    response = session.get(
        _pwl_url(ctx, "/pre_authn/initialization"),
        verify=ssl_verification_enabled,
        headers=_pwl_headers(ctx),
        params={"authkey": ctx["authkey"], "is_ipad": "false"},
    )
    trace_http_request(response)
    _pwl_check_ok(response, "initializing the Duo pre-authentication session")


def _pwl_evaluate_pre_authn(ctx, session, ssl_verification_enabled):
    # Best-effort: the SPA performs a pre-auth risk evaluation before offering
    # factors. It is not required to trigger a push, so failures are ignored.
    try:
        response = session.get(
            _pwl_url(ctx, "/pre_authn/evaluation"),
            verify=ssl_verification_enabled,
            headers=_pwl_headers(ctx),
            params={
                "authkey": ctx["authkey"],
                "browser_features": _PWL_BROWSER_FEATURES,
                "local_trust_choice": "undecided",
            },
        )
        trace_http_request(response)
        logging.info("pwl pre_authn/evaluation response: {}".format(response.text))
    except Exception as e:
        logging.info("pwl pre_authn/evaluation failed (continuing): {}".format(e))


def _pwl_perform_authentication_transaction(ctx, factor, device, session, ssl_verification_enabled):
    if factor is None:
        factor = click.prompt(
            text="Please enter your desired authentication method (Ex: Duo Push)", type=str
        )

    _pwl_initialize_pre_authn(ctx, session, ssl_verification_enabled)
    _pwl_evaluate_pre_authn(ctx, session, ssl_verification_enabled)
    payload = _pwl_get_payload(ctx, session, ssl_verification_enabled)

    if factor == DUO_UNIVERSAL_PROMPT_FACTOR_DUO_PUSH:
        return _pwl_authenticate_push(ctx, payload, device, session, ssl_verification_enabled)

    if factor == DUO_UNIVERSAL_PROMPT_FACTOR_PHONE_CALL:
        return _pwl_authenticate_phone_call(ctx, payload, device, session, ssl_verification_enabled)

    raise click.ClickException(
        "The Duo factor '{}' is not yet supported with the new Duo Universal Prompt (pwl) flow. "
        "Currently supported: '{}' and '{}'.".format(
            factor, DUO_UNIVERSAL_PROMPT_FACTOR_DUO_PUSH, DUO_UNIVERSAL_PROMPT_FACTOR_PHONE_CALL
        )
    )


def _pwl_authenticate_push(ctx, payload, device, session, ssl_verification_enabled):
    pkey = _pwl_select_pkey(payload, device)
    click.echo(
        "Triggering authentication method: '{}' with '{}'".format(
            DUO_UNIVERSAL_PROMPT_FACTOR_DUO_PUSH, device or pkey
        ),
        err=True,
    )
    response = session.post(
        _pwl_url(ctx, "/auth/factors/push/auth"),
        verify=ssl_verification_enabled,
        headers=_pwl_headers(ctx, json_body=True),
        data=json.dumps({"authkey": ctx["authkey"], "pkey": pkey}),
    )
    trace_http_request(response)
    body = _pwl_check_ok(response, "initiating Duo Push")
    step_up_code = body["response"].get("step_up_code")
    if step_up_code:
        click.echo(
            "Duo Mobile is requesting a verification code. "
            "Enter this code on your phone to approve the push: {}".format(step_up_code),
            err=True,
        )
    push_txid = body["response"].get("push_txid") or body["response"].get("txid")
    logging.info("pwl push_txid: {}".format(push_txid))
    return _pwl_poll_status(ctx, "push", push_txid, session, ssl_verification_enabled)


def _pwl_authenticate_phone_call(ctx, payload, device, session, ssl_verification_enabled):
    pkey = _pwl_select_pkey(payload, device)
    click.echo(
        "Triggering authentication method: '{}' with '{}'".format(
            DUO_UNIVERSAL_PROMPT_FACTOR_PHONE_CALL, device or pkey
        ),
        err=True,
    )
    response = session.post(
        _pwl_url(ctx, "/auth/factors/phone_call"),
        verify=ssl_verification_enabled,
        headers=_pwl_headers(ctx, json_body=True),
        data=json.dumps({"authkey": ctx["authkey"], "pkey": pkey}),
    )
    trace_http_request(response)
    body = _pwl_check_ok(response, "initiating Duo phone call")
    txid = body["response"].get("txid") or body["response"].get("push_txid")
    logging.info("pwl phone_call txid: {}".format(txid))
    return _pwl_poll_status(ctx, "phone_call", txid, session, ssl_verification_enabled)


def _pwl_poll_status(ctx, factor_path, txid, session, ssl_verification_enabled):
    if not txid:
        raise click.ClickException("Duo did not return a transaction id when starting authentication.")

    status_url = _pwl_url(ctx, "/auth/factors/{}/status".format(factor_path))
    saw_good_news = "false"
    for _ in range(60):
        response = session.get(
            status_url,
            verify=ssl_verification_enabled,
            headers=_pwl_headers(ctx),
            params={"authkey": ctx["authkey"], "push_txid": txid, "saw_good_news": saw_good_news},
        )
        trace_http_request(response)
        body = _pwl_check_ok(response, "polling Duo authentication status")
        result = body["response"].get("result", body["response"])
        logging.info("pwl status result: {}".format(json.dumps(result)))

        result_status = str(result.get("result") or result.get("status_code") or "").upper()
        if result_status in ("SUCCESS", "ALLOW"):
            result_url = result.get("result_url")
            if result_url:
                return _pwl_fetch_result(ctx, result_url, session, ssl_verification_enabled)
            # The pwl flow does not return a result_url; finalize the auth to
            # obtain the OIDC redirect url back to ADFS.
            return _pwl_finalize_auth(ctx, session, ssl_verification_enabled)
        if result_status in ("FAILURE", "DENY", "FRAUD", "ERROR"):
            raise click.ClickException("Duo authentication was denied or failed: {}".format(json.dumps(result)))

        saw_good_news = "true"
        time.sleep(1)

    raise click.ClickException("Timed out waiting for Duo authentication approval.")


def _pwl_finalize_auth(ctx, session, ssl_verification_enabled):
    response = session.get(
        _pwl_url(ctx, "/auth/finalize_auth"),
        verify=ssl_verification_enabled,
        headers=_pwl_headers(ctx),
        params={"authkey": ctx["authkey"]},
    )
    trace_http_request(response)
    body = _pwl_check_ok(response, "finalizing the Duo authentication")
    redirect_url = body["response"].get("url")
    logging.info("pwl finalize_auth url: {}".format(redirect_url))
    return _pwl_fetch_result(ctx, redirect_url, session, ssl_verification_enabled)


def _pwl_fetch_result(ctx, result_url, session, ssl_verification_enabled):
    if not result_url:
        raise click.ClickException("Duo did not provide a completion url after successful authentication.")

    url = result_url if result_url.startswith("http") else "https://{}{}".format(ctx["host"], result_url)
    # Following the result URL runs the OIDC redirect chain back to ADFS, which
    # returns the page that completes the SAML round-trip.
    response = session.get(
        url,
        verify=ssl_verification_enabled,
        headers=_headers,
        allow_redirects=True,
    )
    trace_http_request(response)
    logging.info("pwl result final url: {}".format(response.url))
    return response


def _pwl_retrieve_roles_page(signed_response, roles_page_url, adfs_context, session, ssl_verification_enabled):
    # Persist cookies so subsequent logins can reuse the Duo session.
    session.cookies.save(ignore_discard=True)

    html_response = ET.fromstring(signed_response.text, ET.HTMLParser())

    # Case 1: ADFS already returned the SAML auto-POST page (the roles page).
    if html_response.find('.//input[@name="SAMLResponse"]') is not None:
        return roles_assertion_extractor.extract(html_response)

    # Case 2: an intermediate OIDC "code" form must be posted back to ADFS,
    # mirroring the behaviour of the older Universal Prompt flow.
    return _retrieve_roles_page(
        roles_page_url,
        adfs_context,
        session,
        ssl_verification_enabled,
        signed_response,
    )
