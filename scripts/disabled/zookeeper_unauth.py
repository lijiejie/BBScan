# coding=utf-8

import socket
from lib.common import save_script_result

ports_to_check = 2181  # 默认服务端口


def do_check(self, url):
    if url != '/':
        return
    port = 2181
    if self.scheme == '	zookeeper' and self.port != 2181:  # 非标准端口
        port = self.port
    elif 2181 not in self.ports_open:
        return

    try:
        socket.setdefaulttimeout(5)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.host, port))
        s.send('envi')
        data = s.recv(1024)
        if 'Environment' in data:
            save_script_result(self, '', 'zookeeper://%s:%s' % (self.host, port), '', 'Zookeeper Unauthorized Access')
    except Exception as e:
        pass
    finally:
        s.close()
