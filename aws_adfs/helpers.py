import ctypes
import logging
import platform
import sys


def memset_zero(secret):
    if platform.python_implementation() == 'CPython':
        strlen = len(secret)
        offset = sys.getsizeof(secret) - strlen - 1
        ctypes.memset(id(secret) + offset, 0, strlen)


def trace_http_request(response):
    request = response.request
    logging.debug(
        """\
================================================================================
Request:
* url: {}
* headers: {}
* body: {}
================================================================================
Response:
* status: {}
* headers: {}
* body: {}
================================================================================
            """.format(
            request.url, request.headers, request.body, response.status_code, response.headers, response.text
        )
    )
