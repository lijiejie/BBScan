#!/usr/bin/env python
#
#  Common functions
#

import time
import urlparse


def get_time():
    return time.strftime('%H:%M:%S', time.localtime())


def parse_url(url):
    _ = urlparse.urlparse(url, 'http')
    if not _.netloc:
        _ = urlparse.urlparse('http://' + url, 'http')
    return _.scheme, _.netloc, _.path if _.path else '/'
