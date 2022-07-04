# coding=utf-8

import asyncio
from lib.common import save_script_result

ports_to_check = 2181  # 默认服务端口


async def do_check(self, url):
    if url != '/':
        return
    port = 2181
    if self.scheme == '	zookeeper' and self.port != 2181:  # 非标准端口
        port = self.port
    elif 2181 not in self.ports_open:
        return

    try:
        reader, writer = await asyncio.open_connection(self.host, port)
        writer.write(b'envi')
        await writer.drain()
        data = await reader.read(1024)
        writer.close()
        if b'Environment' in data:
            await save_script_result(self, '', 'zookeeper://%s:%s' % (self.host, port), '', 'Zookeeper Unauthorized Access')
    except Exception as e:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()  # application data after close notify (_ssl.c:2730)
        except Exception as e:
            pass
