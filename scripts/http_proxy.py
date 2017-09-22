#!/usr/bin/env python
# coding=utf-8

import socket
import requests
requests.packages.urllib3.disable_warnings()
from lib.common import save_user_script_result


def do_check(self, url):
    if url != '/':
        return
    ip = self.host.split(':')[0]
    ports_open = is_port_open(ip)
    headers = {
        "User-Agent": "BugScan plugins http_proxy v0.1",
        "Connection": "close"
    }

    for port in ports_open:
        proxy_url = "http://{}:{}".format(ip, port)
        proxy = {"http": proxy_url, "https": proxy_url}
        try:
            _ = requests.get('http://weibo.com/robots.txt', headers=headers, proxies=proxy, timeout=10.0)
            code = _.status_code
            html = _.text
            if code == 200 and html.find("http://weibo.com/sitemap.xml") >= 0:
                save_user_script_result(self, '', '%s:%s' % (ip, port), 'HTTP Proxy Found')

        except Exception as e:
            pass


def is_port_open(arg):
    ports_open = []
    for port in [80, 8080, 8088, 8888]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3.0)
            if s.connect_ex((arg, port)) == 0:
                ports_open.append(port)
        except Exception as e:
            pass
        finally:
            s.close()
    return ports_open
