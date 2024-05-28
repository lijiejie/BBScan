#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#

from urllib.parse import urlparse
import re
import asyncio
import platform
import socket
import dns.asyncresolver
import time


def get_dns_resolver():
    resolver = dns.asyncresolver.Resolver()
    for server in ['114.114.114.114', '180.76.76.76', '8.8.8.8']:  # Add public DNS Server
        if server not in resolver.nameservers:
            resolver.nameservers.append(server)
    return resolver


if platform.system() == 'Windows':
    try:
        def _call_connection_lost(self, exc):
            try:
                self._protocol.connection_lost(exc)
            finally:
                if hasattr(self._sock, 'shutdown'):
                    try:
                        if self._sock.fileno() != -1:
                            self._sock.shutdown(socket.SHUT_RDWR)
                    except Exception as e:
                        pass
                self._sock.close()
                self._sock = None
                server = self._server
                if server is not None:
                    server._detach()
                    self._server = None

        asyncio.proactor_events._ProactorBasePipeTransport._call_connection_lost = _call_connection_lost
    except Exception as e:
        pass


def is_ip_addr(s):
    pattern_ip = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    ret = pattern_ip.search(s)
    return True if ret else False


def clear_queue(this_queue):
    try:
        while True:
            this_queue.get_nowait()
    except Exception as e:
        return


def parse_url(url):
    _ = urlparse(url, 'http')
    if not _.netloc:
        _ = urlparse('https://' + url, 'http')
    return _.scheme, _.netloc, _.path if _.path else '/'


# calculate depth of a given URL, return tuple (url, depth)
def cal_depth(self, url):
    if url.find('#') >= 0:
        url = url[:url.find('#')]  # cut off fragment
    if url.find('?') >= 0:
        url = url[:url.find('?')]  # cut off query string

    while url.find('/./') >= 0:
        url = url.replace('/./', '/')

    if url.startswith('//'):
        return '', 10000  # //www.baidu.com/index.php

    if not urlparse(url, 'http').scheme.startswith('http'):
        return '', 10000  # no HTTP protocol

    if url.lower().startswith('http'):
        _ = urlparse(url, 'http')
        if _.netloc == self.host or _.netloc == '%s:%s' % (self.host, self.port):  # same hostname
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
    # print('cal_depth', url, depth)
    return url, depth


async def save_script_result(self, status, url, title, vul_type=''):
    async with self.lock:
        # print '[+] [%s] %s' % (status, url)
        if url not in self.results:
            self.results[url] = []
        _ = {'status': status, 'url': url, 'title': title, 'vul_type': vul_type}
        self.results[url].append(_)


def get_domain_sub(host):
    if re.search(r'\d+\.\d+\.\d+\.\d+', host.split(':')[0]):
        return ''
    else:
        return host.split('.')[0]


def escape(html):
    return html.replace('&', '&amp;').\
        replace('<', '&lt;').replace('>', '&gt;').\
        replace('"', '&quot;').replace("'", '&#39;')


sem = asyncio.Semaphore(100)

resolver = get_dns_resolver()


async def is_port_open(host, port):
    if not port:
        return True

    try:
        async with sem:
            start_time = time.time()
            if not is_ip_addr(host):
                answers = await resolver.resolve(host, "A")
                host = answers[0].address

            fut = asyncio.open_connection(host, int(port))
            reader, writer = await asyncio.wait_for(fut, timeout=10)
            writer.close()
            try:
                await writer.wait_closed()    # application data after close notify (_ssl.c:2730)
            except Exception as e:
                print('is_port_open.wait_closed.exception:', type(e))
            return True
    except (asyncio.exceptions.TimeoutError, ConnectionRefusedError) as e:
        pass
    except Exception as e:
        print('is_port_open.exception:', e.__class__.__name__, str(e), host, port,
              'elapsed %.2f seconds' % (time.time() - start_time))
        return False


def get_http_title(html_doc):
    if not html_doc:
        return ''
    m = re.search('<title>(.*?)</title>', html_doc, re.IGNORECASE)
    return m.group(1) if m else ''


def clear_url(base_url):
    if base_url.startswith('unknown://'):
        base_url = base_url[len('unknown://'):]
    if base_url.endswith(':None'):
        base_url = base_url[:-len(':None')]
    return base_url


async def scan_given_ports(host, ports, confirmed_open, confirmed_closed):
    checked_ports = confirmed_open.union(confirmed_closed)
    ports_open = set()
    ports_closed = set()

    scanning_ports = []
    threads = []
    for port in ports:
        if port not in checked_ports:   # 不重复检测已确认端口
            scanning_ports.append(port)
            threads.append(is_port_open(host, port))
    ret = await asyncio.gather(*threads)
    for i in range(len(threads)):
        if ret[i]:
            ports_open.add(scanning_ports[i])
        else:
            ports_closed.add(scanning_ports[i])

    return ports_open.union(confirmed_open), ports_closed.union(confirmed_closed)


async def test():
    r = await is_port_open('www.baidu.com', 80)
    print(r)


def run_test_is_port_open():
    loop = asyncio.get_event_loop()
    task = loop.create_task(test())
    loop.run_until_complete(task)


if __name__ == '__main__':
    run_test_is_port_open()
