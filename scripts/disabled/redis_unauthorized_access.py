#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import asyncio
from lib.common import save_script_result


ports_to_check = 6379    # 默认扫描端口


async def do_check(self, url):
    if url != '/':
        return
    port = 6379
    # 非标准端口，不需要检查6379端口是否开放
    # 支持用户传入目标 redis://test.ip:16379 来扫描非标准端口上的Redis服务
    if self.scheme == 'redis' and self.port != 6379:
        port = self.port
    elif 6379 not in self.ports_open:
        return

    try:
        host = self.host.split(':')[0]
        reader, writer = await asyncio.open_connection(host, port)
        payload = b'\x2a\x31\x0d\x0a\x24\x34\x0d\x0a\x69\x6e\x66\x6f\x0d\x0a'
        writer.write(payload)
        await writer.drain()
        data = await reader.read(1024)
        writer.close()
        if b"redis_version" in data:
            await save_script_result(self, '', 'redis://%s:%s' % (host, port), 'Redis Unauthorized Access')
    except Exception as e:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()  # application data after close notify (_ssl.c:2730)
        except Exception as e:
            pass
