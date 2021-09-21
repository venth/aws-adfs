import ctypes
import platform
import sys

def memset_zero(secret):
    if platform.python_implementation() == 'CPython':
        strlen = len(secret)
        offset = sys.getsizeof(secret) - strlen - 1
        ctypes.memset(id(secret) + offset, 0, strlen)