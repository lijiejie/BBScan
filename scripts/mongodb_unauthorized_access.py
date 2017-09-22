#!/usr/bin/python

import pymongo
from lib.common import save_user_script_result


def do_check(self, url):
    if url != '/':
        return
    try:
        ip = self.host.split(':')[0]
        conn = pymongo.MongoClient(host=ip, port=27017)
        database_list = conn.database_names()
        if not database_list:
            conn.close()
            return
        detail = "%s MongoDB Unauthorized Access : %s" % (ip, ",".join(database_list))
        conn.close()
        save_user_script_result(self, '', 'mongodb://%s:27017' % ip, detail)
    except Exception as e:
        pass
