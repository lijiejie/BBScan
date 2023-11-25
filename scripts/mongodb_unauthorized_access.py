#!/usr/bin/python
# -*- encoding: utf-8 -*-

import pymongo
from lib.common import save_script_result


ports_to_check = 27017    # 默认扫描端口


def do_check(self, url):
    if url != '/':
        return
    port = 27017
    if self.scheme == 'mongodb' and self.port != 27017:    # 非标准端口
        port = self.port
    elif 27017 not in self.ports_open:
        return
    try:
        conn = pymongo.MongoClient(host=self.host, port=port, connectTimeoutMS=5000, socketTimeoutMS=5000)
        database_list = conn.database_names()
        if not database_list:
            conn.close()
            return
        detail = "%s MongoDB Unauthorized Access : %s" % (self.host, ",".join(database_list))
        conn.close()
        save_script_result(self, '', 'mongodb://%s:%s' % (self.host, port), detail)
    except Exception as e:
        pass
