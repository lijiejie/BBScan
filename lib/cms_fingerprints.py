# -*- encoding: utf-8 -*-
# Indentify web app fingerprints: framework, programming languages, web server, CMS,
# middle-ware, open source software or commercial product etc
# Rules copy from https://github.com/0x727/FingerprintHub

import hashlib
import os
import json
import codecs
import httpx

cur_dir = os.path.dirname(os.path.abspath(__file__))
rule_dir = os.path.join(cur_dir, '../rules/web_fingerprint_v3.json')


class Fingerprint(object):
    def __init__(self):
        self.fav_icons = {}
        self.requests_to_do = {}
        self.rules = {}

        with codecs.open(rule_dir, encoding='utf-8') as f:
            doc = json.loads(f.read())

            for rule in doc:
                # 处理fav hash
                if rule['favicon_hash']:
                    for _hash in rule['favicon_hash']:
                        if _hash:
                            self.fav_icons[_hash] = rule['name']

                key = '^^^'.join([rule['path'], rule['request_method'],
                                  str(rule['request_headers']), rule['request_data']])
                self.requests_to_do[key] = [rule['path'], rule['request_method'],
                                            rule['request_headers'], rule['request_data']]
                if key not in self.rules:
                    self.rules[key] = []
                self.rules[key].append(rule)

    def get_cms_name_via_icon(self, favicon_hash):
        if favicon_hash in self.fav_icons:
            return self.fav_icons[favicon_hash]
        else:
            return

    def get_cms_name(self, key_name, status_code, headers, text, favicon_hash=None):
        cms_names = []
        for rule in self.rules[key_name]:
            if rule['status_code'] != 0:
                # 200 和 206 单独检查
                if rule['status_code'] in [200, 206] and status_code in [200, 206]:
                    pass
                else:
                    if rule['status_code'] != status_code:  # code mismatch
                        continue
            mismatch = False
            if rule['headers']:
                for header_name in rule['headers']:
                    if rule['headers'][header_name] == '*' and header_name in headers:
                        continue
                    if headers.get(header_name, '').find(rule['headers'][header_name]) < 0:
                        mismatch = True
                        break
                if mismatch:
                    continue
            if rule['keyword']:
                for word in rule['keyword']:
                    if text.lower().find(word) < 0 and text.find(word) < 0:
                        mismatch = True
                        break
                if mismatch:
                    continue
            if rule['favicon_hash'] and favicon_hash != rule['favicon_hash']:
                continue
            if rule['name'] not in cms_names:
                cms_names.append(rule['name'])
        return cms_names


if __name__ == '__main__':
    from config import default_headers
    import copy
    f = Fingerprint()

    client = httpx.Client()
    data = client.get('https://demo.jumpserver.org/static/img/facio.ico').read()
    fav_hash = hashlib.md5(data).hexdigest()
    if fav_hash in f.fav_icons:
        print('From fav hash:', f.fav_icons[fav_hash])

    url = 'http://example.com/'

    for key_name in f.rules:
        item = f.requests_to_do[key_name]
        print(key_name)
        print()

        if item[2]:
            headers = copy.deepcopy(default_headers)
            headers.update(item[2])    # update headers
        else:
            headers = default_headers

        resp = None
        if item[1].lower() == 'get':
            resp = client.get(url.rstrip('/') + item[0], headers=headers)
        elif item[1].lower() == 'post':
            data = item[3]
            resp = client.post(url.rstrip('/') + item[0], headers=headers, data=item[3])
        else:
            raise Exception('invalid method')

        if resp:
            cms_name = f.get_cms_name(key_name, resp.status_code, resp.headers, resp.text)
            if cms_name:
                print('cms name is:', cms_name)
