#!/usr/bin/python
# -*- encoding: utf-8 -*-

import motor.motor_asyncio
from lib.common import save_script_result


ports_to_check = 27017    # 默认扫描端口


async def do_check(self, url):
    if url != '/':
        return
    port = 27017
    if self.scheme == 'mongodb' and self.port != 27017:    # 非标准端口
        port = self.port
    elif 27017 not in self.ports_open:
        return
    try:
        client = motor.motor_asyncio.AsyncIOMotorClient(self.host, port)
        ret = await client.list_database_names()
        detail = "%s MongoDB Unauthorized Access : %s" % (self.host, ",".join(ret))
        await save_script_result(self, '', 'mongodb://%s:%s' % (self.host, port), detail)
    except Exception as e:
        pass
