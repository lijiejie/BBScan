#!/usr/bin/env python
#
#  Common functions
#

import time
import urlparse
import re


def print_msg(msg):
    print '[%s] %s' % (time.strftime('%H:%M:%S', time.localtime()), msg)


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


# calculate depth of a given URL, return tuple (url, depth)
def cal_depth(self, url):
    if url.find('#') >= 0:
        url = url[:url.find('#')]  # cut off fragment
    if url.find('?') >= 0:
        url = url[:url.find('?')]  # cut off query string

    if url.startswith('//'):
        return '', 10000  # //www.baidu.com/index.php

    if not urlparse.urlparse(url, 'http').scheme.startswith('http'):
        return '', 10000  # no HTTP protocol

    if url.lower().startswith('http'):
        _ = urlparse.urlparse(url, 'http')
        if _.netloc == self.host:  # same hostname
            url = _.path
        else:
            return '', 10000  # not the same hostname

    while url.find('//') >= 0:
        url = url.replace('//', '/')

    if not url:
        return '/', 1  # http://www.example.com

    if url[0] != '/':
        url = '/' + url

    url = url[: url.rfind('/') + 1]

    if url.split('/')[-2].find('.') > 0:
        url = '/'.join(url.split('/')[:-2]) + '/'

    depth = url.count('/')
    return url, depth


def save_user_script_result(self, status, url, title):
    self.lock.acquire()
    #print '[+] [%s] %s' % (status, url)
    if url not in self.results:
        self.results[url] = []
    _ = {'status': status, 'url': url, 'title': title}
    self.results[url].append(_)
    self.lock.release()


def get_domain_sub(host):
    if re.search('\d+\.\d+\.\d+\.\d+', host.split(':')[0]):
        return ''
    else:
        return host.split('.')[0]
