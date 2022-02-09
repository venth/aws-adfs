import ctypes
import logging
import platform
import sys

def memset_zero(secret):
    if platform.python_implementation() == 'CPython':
        strlen = len(secret)
        offset = sys.getsizeof(secret) - strlen - 1
        ctypes.memset(id(secret) + offset, 0, strlen)

def trace_http_request(url, request_headers, request_data, response_status, response_headers, response_body):
    logging.debug(u'''Request:
        * url: {}
        * headers: {}
        * data: {}
    Response:
        * status: {}
        * headers: {}
        * body: {}
    '''.format(url, request_headers, request_data, response_status, response_headers, response_body))
