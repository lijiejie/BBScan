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


def decode_response_text(txt, charset=None):
    if charset:
        try:
            return txt.decode(charset)
        except:
            pass

    for _ in ['UTF-8', 'GB2312', 'GBK', 'iso-8859-1', 'big5']:
        try:
            return txt.decode(_)
        except:
            pass

    try:
        return txt.decode('ascii', 'ignore')
    except:
        pass

    raise Exception('Fail to decode response Text')
