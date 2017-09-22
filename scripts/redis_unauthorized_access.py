#!/usr/bin/python

import socket
from lib.common import save_user_script_result


def do_check(self, url):
    if url != '/':
        return
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        host = self.host.split(':')[0]
        s.connect((host, 6379))
        payload = '\x2a\x31\x0d\x0a\x24\x34\x0d\x0a\x69\x6e\x66\x6f\x0d\x0a'
        s.send(payload)
        data = s.recv(1024)
        s.close()
        if "redis_version" in data:
            save_user_script_result(self, '', 'redis://' + host + ':6379', 'Redis Unauthorized Access' )
    except Exception as e:
        s.close()
