#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
#  Common functions
#

import urlparse
import re
import struct
import platform
from gevent import socket


def clear_queue(this_queue):
    try:
        while True:
            this_queue.get_nowait()
    except Exception as e:
        return


def parse_url(url):
    _ = urlparse.urlparse(url, 'http')
    if not _.netloc:
        _ = urlparse.urlparse('https://' + url, 'http')
    return _.scheme, _.netloc, _.path if _.path else '/'


def decode_response_text(txt, charset=None):
    if charset:
        try:
            return txt.decode(charset)
        except Exception as e:
            pass
    for _ in ['UTF-8', 'GBK', 'GB2312', 'iso-8859-1', 'big5']:
        try:
            return txt.decode(_)
        except Exception as e:
            pass
    try:
        return txt.decode('ascii', 'ignore')
    except Exception as e:
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


def save_script_result(self, status, url, title, vul_type=''):
    self.lock.acquire()
    # print '[+] [%s] %s' % (status, url)
    if url not in self.results:
        self.results[url] = []
    _ = {'status': status, 'url': url, 'title': title, 'vul_type': vul_type}
    self.results[url].append(_)
    self.lock.release()


def get_domain_sub(host):
    if re.search(r'\d+\.\d+\.\d+\.\d+', host.split(':')[0]):
        return ''
    else:
        return host.split('.')[0]


def escape(html):
    return html.replace('&', '&amp;').\
        replace('<', '&lt;').replace('>', '&gt;').\
        replace('"', '&quot;').replace("'", '&#39;')


def is_port_open(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        if s.connect_ex((host, int(port))) == 0:
            return True
        else:
            return False
    except Exception as e:
        return False
    finally:
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
            s.close()
        except Exception as e:
            pass


def scan_given_ports(confirmed_open, confirmed_closed, host, ports):
    checked_ports = confirmed_open.union(confirmed_closed)
    ports_open = set()
    ports_closed = set()

    for port in ports:
        if port in checked_ports:   # 不重复检测已确认端口
            continue
        if is_port_open(host, port):
            ports_open.add(port)
        else:
            ports_closed.add(port)

    return ports_open.union(confirmed_open), ports_closed.union(confirmed_closed)


if __name__ == '__main__':
    print(is_port_open('119.84.78.81', 80))
