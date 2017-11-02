#!/usr/bin/env python

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

import os
import subprocess
import sys

if os.environ.get('LC_CTYPE', '') == 'UTF-8':
    os.environ['LC_CTYPE'] = 'en_US.UTF-8'

from awscli import clidriver


def decorate():
    old_stderr = sys.stderr
    redirected_error = sys.stderr = StringIO()
    try:
        driver = clidriver.create_clidriver()
        return_code = driver.main()
    finally:
        sys.stderr = old_stderr

    error_text = redirected_error.getvalue()

    if _was_token_expired(return_code, error_text):
        _re_authenticate(driver)
        clidriver.main()
    elif error_text is not None:
        old_stderr.write(error_text)


def _re_authenticate(driver):
    profile = driver.session.get_config_variable('profile')
    profile = 'default' if profile is None else profile
    subprocess.check_call('aws-adfs login --profile {}'.format(profile), shell=True)


def _was_token_expired(return_code, error_text):
    error_text = error_text or ''
    error_text = error_text.lower()
    return return_code != 0 and \
           u'expired' in error_text and \
           u'token' in error_text


if __name__ == '__main__':
    sys.exit(decorate())
