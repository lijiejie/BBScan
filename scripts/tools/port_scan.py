#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# ports_to_check 设置为 想要扫描的1个或多个端口
# python BBScan.py --scripts-only --script port_scan --host www.baidu.com --network 16 --save-ports ports_80.txt

ports_to_check = [80]


def do_check(self, url):
    pass