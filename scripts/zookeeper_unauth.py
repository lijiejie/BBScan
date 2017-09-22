# coding=utf-8


import socket
from lib.common import save_user_script_result


def do_check(self, url):
    if url != '/':
        return
    ip = self.host.split(':')[0]
    try:
        socket.setdefaulttimeout(10)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, 2181))
        s.send('envi')
        data = s.recv(1024)
        if 'Environment' in data:
            save_user_script_result(self, '', 'zookeeper://%s:2181' % ip, 'Zookeeper Unauthorized Access')
    except Exception as e:
        pass
    finally:
        s.close()
