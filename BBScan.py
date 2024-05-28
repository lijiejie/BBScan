#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
 A fast and light-weight web vulnerability scanner. It helps pen-testers pinpoint possibly vulnerable targets from a large number of web servers.
 https://github.com/lijiejie/BBScan
 Li JieJie  my[at]lijiejie.com  https://www.lijiejie.com
"""

import os
# first, change working dir
cur_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(cur_dir)

import sys
import codecs
import asyncio
import httpx
import re
from bs4 import BeautifulSoup
import warnings
import time
import glob
import ipaddress
import ssl
import traceback
import importlib
import copy
import string
import random
import dns.asyncresolver
from urllib.parse import urlparse

from lib.common import clear_queue, parse_url, cal_depth, get_domain_sub, is_port_open, scan_given_ports, \
    is_ip_addr, get_dns_resolver, get_http_title, clear_url
from lib.cmdline import parse_args
from lib.report import save_report
import lib.config as conf
from lib.cms_fingerprints import Fingerprint
import hashlib
from lib.javascript_parser import get_urls_in_js_async


if hasattr(ssl, '_create_unverified_context'):
    ssl._create_default_https_context = ssl._create_unverified_context

from bs4 import MarkupResemblesLocatorWarning
warnings.filterwarnings('ignore', category=MarkupResemblesLocatorWarning)


fingerprint = Fingerprint()


class Scanner(object):
    def __init__(self, timeout=900):
        self.q_results = q_results
        self.args = args
        self.start_time = time.time()
        self.time_out = timeout
        self.links_limit = 100  # max number of folders allowed to scan

    async def init(self):
        await self._init_rules()
        self._init_scripts()

        self.url_queue = asyncio.Queue()  # all urls to scan
        self.urls_processed = set()     # processed urls
        self.urls_enqueued = set()      # entered queue urls
        self.urls_crawled = set()

        self.lock = asyncio.Lock()
        self.results = {}
        self.log_file = None
        self._404_status = -1
        self.conn_pool = None
        self.index_status, self.index_headers, self.index_html_doc = None, {}, ''
        self.scheme, self.host, self.port, self.path = None, None, None, None
        self.domain_sub = ''
        self.base_url = ''
        self.max_depth = 0
        self.len_404_doc = 0
        self.has_http = None
        self.ports_open = None
        self.ports_closed = None
        self.no_scripts = None
        self.status_502_count = 0
        self.timeout_count = 0
        self.timeout_scan_aborted = False
        self.fingerprint_check = True
        self.js_urls = []
        self.index_has_reported = False
        self.urls_regex_found = set()

    async def print_msg(self, msg):
        await self.q_results.put(msg)

    def reset_scanner(self):
        self.start_time = time.time()
        clear_queue(self.url_queue)
        self.urls_processed.clear()
        self.urls_enqueued.clear()
        self.urls_crawled.clear()
        self.results.clear()
        self.log_file = None
        self._404_status = -1
        # self.conn_pool = None    # Bug Fixed, shouldn't set to None right here, used pool can not be closed
        self.index_status, self.index_headers, self.index_html_doc = None, {}, ''
        self.scheme, self.host, self.port, self.path = None, None, None, None
        self.domain_sub = ''
        self.base_url = ''
        self.status_502_count = 0
        self.timeout_count = 0
        self.timeout_scan_aborted = False
        self.fingerprint_check = True
        self.js_urls = []
        self.index_has_reported = False
        self.urls_regex_found = set()

    # scan from a given URL
    async def init_from_url(self, target):
        self.reset_scanner()
        self.scheme = target['scheme']
        self.host = target['host']
        self.port = target['port']
        self.path = target['path']
        self.has_http = target['has_http']
        self.ports_open = target['ports_open']
        self.ports_closed = target['ports_closed']
        self.no_scripts = target['no_scripts'] if 'no_scripts' in target else 0
        self.domain_sub = get_domain_sub(self.host)
        await self.init_final()
        return True

    # Fix me: not yet implemented and tested 2024-05-27
    async def init_from_log_file(self, log_file):
        self.reset_scanner()
        self.log_file = log_file
        self.scheme, self.host, self.path = self._parse_url_from_file()
        self.domain_sub = get_domain_sub(self.host)
        if self.host:
            if self.host.find(':') > 0:
                _ret = self.host.split(':')
                self.host = _ret[0]
                self.port = _ret[1]
            elif self.scheme == 'https':
                self.port = 443
            elif self.scheme == 'http':
                self.port = 80
            else:
                self.port = None
            if await is_port_open(self.host, self.port):
                await self.print_msg('[Port Not Open] %s:%s' % (self.host, self.port))
                return False
            self.has_http = True
            self.no_scripts = 1
            await self.init_final()
            await self.load_all_urls_from_log_file()
            return True
        else:
            host = os.path.basename(log_file).replace('.log', '')
            try:
                await dns.asyncresolver.resolve(host, "A")
                await self.init_from_url(host)     # Fix Me
                return True
            except Exception as e:
                await self.print_msg('[ERROR] Invalid host from log name: %s' % host)
                return False

    async def init_final(self):
        try:
            if self.conn_pool:
                await self.conn_pool.aclose()
        except Exception as e:
            await self.print_msg('conn_pool.aclose exception: %s' % str(e))
        self.conn_pool = None    # after close
        if self.scheme == 'http' and self.port == 80 or self.scheme == 'https' and self.port == 443:
            self.base_url = '%s://%s' % (self.scheme, self.host)
        else:
            self.base_url = '%s://%s:%s' % (self.scheme, self.host, self.port)

        if self.has_http:
            await self.print_msg('Scan %s' % self.base_url)
        else:
            await self.print_msg('Scan %s:%s' % (self.host, self.port) if self.port else 'Scan %s' % self.host)

        if self.has_http:
            limits = httpx.Limits(max_connections=100, max_keepalive_connections=40)
            self.conn_pool = httpx.AsyncClient(headers=conf.default_headers,
                                               proxies=args.proxy, verify=False, limits=limits, follow_redirects=False)

            if self.args.require_index_doc:
                await self.crawl('/', do_not_process_links=True)

        if self.no_scripts != 1:   # 不是重复目标 80 443 跳转的，不需要重复扫描
            # 当前目标disable， 或者 全局开启插件扫描
            if self.args.scripts_only or not self.no_scripts:
                for _ in self.user_scripts:
                    await self.url_queue.put((_, '/'))

        if not self.has_http or self.args.scripts_only:    # 未发现HTTP服务 或  只依赖插件扫描
            return

        self.max_depth = cal_depth(self, self.path)[1] + 5
        if self.args.no_check404:
            self._404_status = 404
        else:
            await self.check_404_existence()
        if self._404_status == -1:
            await self.print_msg('[Warning] HTTP 404 check failed: %s' % self.base_url)
        # elif self._404_status != 404:
        #     await self.print_msg('[Warning] %s has no HTTP 404.' % self.base_url)
        _path, _depth = cal_depth(self, self.path)

        await self.enqueue('/')
        if _path != '/' and not self.log_file:
            await self.enqueue(_path)

    def _parse_url_from_file(self):
        url = ''
        with open(self.log_file) as infile:
            for _line in infile.readlines():
                _line = _line.strip()
                if _line and len(_line.split()) >= 3:
                    url = _line.split()[1]
                    break
        return parse_url(url)

    # load urls from rules/*.txt
    async def _init_rules(self):
        self.text_to_find = []
        self.regex_to_find = []
        self.text_to_exclude = []
        self.regex_to_exclude = []
        self.rules_set = set()
        self.rules_set_root_only = set()

        p_tag = re.compile('{tag="(.*?)"}')
        p_status = re.compile(r'{status=(\d{3})}')
        p_content_type = re.compile('{type="(.*?)"}')
        p_content_type_no = re.compile('{type_no="(.*?)"}')

        _files = self.args.rule_files if self.args.rule_files else glob.glob('rules/*.txt')
        if self.args.fingerprint_only:
            _files = []

        for rule_file in _files:
            with codecs.open(rule_file, 'r', encoding='utf-8') as infile:
                vul_type = os.path.basename(rule_file)[:-4]
                for url in infile.readlines():
                    url = url.strip()
                    if url.startswith('/'):
                        _ = p_tag.search(url)
                        tag = _.group(1) if _ else ''

                        _ = p_status.search(url)
                        status = int(_.group(1)) if _ else 0

                        _ = p_content_type.search(url)
                        content_type = _.group(1) if _ else ''

                        _ = p_content_type_no.search(url)
                        content_type_no = _.group(1) if _ else ''

                        root_only = True if url.find('{root_only}') >= 0 else False

                        rule = (url.split()[0], tag, status, content_type, content_type_no, root_only, vul_type)
                        if root_only:
                            if rule not in self.rules_set_root_only:
                                self.rules_set_root_only.add(rule)
                            else:
                                await self.print_msg('Duplicated root only rule: %s' % str(rule))
                        else:
                            if rule not in self.rules_set:
                                self.rules_set.add(rule)
                            else:
                                await self.print_msg('Duplicated rule: %s' % str(rule))

        re_text = re.compile('{text="(.*)"}')
        re_regex_text = re.compile('{regex_text="(.*)"}')

        file_path = 'rules/white.list'
        if not os.path.exists(file_path):
            await self.print_msg('[ERROR] File not exist: %s' % file_path)
            return
        for _line in codecs.open(file_path, encoding='utf-8'):
            _line = _line.strip()
            if not _line or _line.startswith('#'):
                continue
            _m = re_text.search(_line)
            if _m:
                self.text_to_find.append(_m.group(1))
            else:
                _m = re_regex_text.search(_line)
                if _m:
                    self.regex_to_find.append(re.compile(_m.group(1)))

        file_path = 'rules/black.list'
        if not os.path.exists(file_path):
            await self.print_msg('[ERROR] File not exist: %s' % file_path)
            return
        for _line in codecs.open(file_path, encoding='utf-8'):
            _line = _line.strip()
            if not _line or _line.startswith('#'):
                continue
            _m = re_text.search(_line)
            if _m:
                self.text_to_exclude.append(_m.group(1))
            else:
                _m = re_regex_text.search(_line)
                if _m:
                    self.regex_to_exclude.append(re.compile(_m.group(1)))

    def _init_scripts(self):
        self.user_scripts = []
        if self.args.no_scripts:    # 全局禁用插件，无需导入
            return
        files = 'scripts/*.py'
        if self.args.fingerprint_only:
            files = 'scripts/is_admin_site.py'
        for _script in glob.glob(files):
            script_name_origin = os.path.basename(_script)
            script_name = script_name_origin.replace('.py', '')
            if self.args.script:    # 只导入指定的脚本
                if script_name not in self.args.script and script_name_origin not in self.args.script:
                    continue
            if script_name.startswith('_'):
                continue
            try:
                self.user_scripts.append(importlib.import_module('scripts.%s' % script_name))
            except Exception as e:
                print('[ERROR] Fail to load script %s' % script_name)

    async def http_request(self, url, headers=conf.default_headers, timeout=30, follow_redirects=False):
        try:
            if not url:
                url = '/'
            if not self.conn_pool or self.timeout_scan_aborted:
                return -1, {}, ''
            if self.args.debug:
                await self.print_msg('--> %s' % self.base_url + url)
            resp = await self.conn_pool.get(self.base_url + url,
                                            headers=headers, follow_redirects=follow_redirects, timeout=timeout)
            if resp.headers.get('content-type', '').find('text') >= 0 \
                    or resp.headers.get('content-type', '').find('html') >= 0 \
                    or int(resp.headers.get('content-length', '0')) <= 20480:  # 1024 * 20
                html_doc = resp.text
            else:
                html_doc = ''

            if resp.status_code == 502:    # 502出现超过3次，排除该站点不再扫描
                self.status_502_count += 1
                if self.status_502_count > 3:
                    self.timeout_scan_aborted = True
                    clear_queue(self.url_queue)
                    try:
                        if self.conn_pool:
                            await self.conn_pool.aclose()
                    except Exception as e:
                        pass    #
                    self.conn_pool = None
                    if self.args.debug:
                        await self.print_msg('Website 502 exceeded: %s' % self.base_url)

            return resp.status_code, resp.headers, html_doc
        except httpx.ReadTimeout as e:
            self.timeout_count += 1
            if self.timeout_count >= 3:
                if not self.timeout_scan_aborted:
                    self.timeout_scan_aborted = True
                    await self.print_msg('[Warning] timeout exceeded, scan aborted: %s' % self.base_url)
                clear_queue(self.url_queue)
            return -1, {}, ''
        except (httpx.RequestError, httpx.HTTPStatusError, ssl.SSLError) as e:
            if self.args.debug:
                await self.print_msg('[Request Error] %s %s %s' % (type(e), str(e), self.base_url))
            return -1, {}, ''
        except Exception as e:
            if self.args.debug:
                await self.print_msg('[Request Error] %s %s %s' % (type(e), str(e), self.base_url))
            return -1, {}, ''

    async def check_404_existence(self):
        try:
            try:
                path = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in
                               range(random.randint(10, 30)))
                self._404_status, _, html_doc = await self.http_request('/' + path)
            except Exception as e:
                await self.print_msg('[Warning] HTTP 404 check failed: %s, %s' % (self.base_url, type(e)))
                self._404_status, _, html_doc = -1, {}, ''
            if self._404_status != 404:
                self.len_404_doc = len(html_doc)
        except Exception as e:
            await self.print_msg('[Check_404] Exception %s %s' % (self.base_url, str(e)))

    #
    async def enqueue(self, url):
        try:
            url = str(url)
        except Exception as e:
            return False
        try:
            url_pattern = re.sub(r'\d+', '{num}', url)
            if url_pattern in self.urls_processed or len(self.urls_processed) >= self.links_limit:
                return False

            self.urls_processed.add(url_pattern)
            # await self.print_msg('Entered Queue: %s' % url)
            if not self.args.no_crawl:   # no crawl
                await self.crawl(url)
            if self._404_status != -1:    # valid web service
                rule_set_to_process = [self.rules_set, self.rules_set_root_only] if url == '/' else [self.rules_set]
                for rule_set in rule_set_to_process:
                    for _ in rule_set:
                        if _[5] and url != '/':    # root only
                            continue
                        try:
                            full_url = url.rstrip('/') + _[0]
                        except Exception as e:
                            continue
                        if full_url in self.urls_enqueued:
                            continue
                        url_description = {'prefix': url.rstrip('/'), 'full_url': full_url}
                        item = (url_description, _[1], _[2], _[3], _[4], _[5], _[6])
                        await self.url_queue.put(item)
                        self.urls_enqueued.add(full_url)

            if self.args.full_scan and url.count('/') >= 2:
                await self.enqueue('/'.join(url.split('/')[:-2]) + '/')  # sub folder enqueue

            if url != '/' and not self.no_scripts:
                for script in self.user_scripts:
                    await self.url_queue.put((script, url))
            return True
        except Exception as e:
            await self.print_msg('[_enqueue.exception] %s' % str(e))
            return False

    #
    async def crawl(self, path, do_not_process_links=False):
        try:
            # increase body size to 200 KB
            request_headers = dict(conf.default_headers, Range='bytes=0-204800')
            status, headers, html_doc = await self.http_request(path, headers=request_headers)

            if path == '/':
                self.index_status, self.index_headers, self.index_html_doc = status, headers, html_doc
                if not self.index_has_reported:
                    self.index_has_reported = True
                    title = get_http_title(html_doc)
                    location = headers.get('Location', '')
                    server = headers.get('Server', '')
                    str_headers = ''
                    for key in self.index_headers:
                        # 减少非关键HTTP头的输出
                        if key.lower() in ['connection', 'content-encoding', 'content-security-policy',
                                           'date', 'p3p', 'x-ua-compatible', 'x-ua-compatible', 'cache-control',
                                           'x-xss-protection', 'transfer-encoding', 'last-modified', 'etag']:
                            continue
                        str_headers += '%s: %s\n' % (key, self.index_headers[key])
                    _ = {'status': status, 'url': clear_url(self.base_url), 'title': title, 'server': server,
                         'location': location, 'headers': str_headers}
                    await self.save_result('$Index', _)

                if self.fingerprint_check:
                    # 检查Web指纹
                    cms_name = fingerprint.get_cms_name('/^^^get^^^{}^^^', status, headers, html_doc)
                    if cms_name:
                        await self.save_result(
                            '$Fingerprint', cms_name,
                            msg='[Fingerprint] %s found %s' % (('%s%s' % (self.base_url, path)).rstrip('/'), cms_name))

                # 首页30x跳转，在第二次请求时，需要parse HTML， follow后获取新的HTML
                if not self.args.no_crawl and not do_not_process_links and status in [301, 302]:
                    resp = await self.conn_pool.get(self.base_url + '/',
                                                    headers=conf.default_headers, timeout=20)
                    location = resp.headers.get('Location', '')
                    if location.lower().startswith('http'):
                        scheme, netloc, _path, params, query, fragment = urlparse(location, 'http')
                        if netloc.find(self.host) < 0:   # different host, do not follow
                            location = ''
                        else:
                            location = _path + '?' + query
                    elif location.lower().startswith('/'):
                        pass
                    else:
                        location = '/' + location
                    if location:
                        url, depth = cal_depth(self, resp.headers.get('Location', ''))
                        if depth <= self.max_depth:
                            await self.enqueue(url)
                        # 避免处理错误，直接传入原始path，让httpx处理跳转URL，会重复，多1次请求
                        status, headers, html_doc = await self.http_request(path, headers=request_headers,
                                                                            follow_redirects=True)
                        # 再次检查Web指纹
                        cms_name = fingerprint.get_cms_name('/^^^get^^^{}^^^', status, headers, html_doc)
                        if cms_name:
                            await self.save_result(
                                '$Fingerprint', cms_name,
                                msg='[Fingerprint] %s found %s' % (
                                    ('%s%s' % (self.base_url, path)).rstrip('/'), cms_name))

            if not self.args.no_crawl and not do_not_process_links and html_doc:

                fav_url_found = False
                soup = BeautifulSoup(html_doc, "html.parser")
                for tag in ['link', 'script', 'a']:
                    for link in soup.find_all(tag):
                        origin_url = url = link.get('href', '').strip()
                        if not url:
                            origin_url = url = link.get('src', '').strip()
                        if url.startswith('..'):
                            continue
                        if not url.startswith('/') and url.find('//') < 0:   # relative path
                            url = path + url
                        url, depth = cal_depth(self, url)
                        # print(url, depth)
                        if depth <= self.max_depth:
                            await self.enqueue(url)
                        if self.fingerprint_check and tag == 'link' and str(link.get('rel', '')).find('icon') >= 0:
                            fav_url_found = True
                            fav_url, depth = cal_depth(self, link.get('href', '').strip())
                            if fav_url:    # 非当前域名的icon url，不会请求
                                await self.url_queue.put(('favicon', fav_url, ''))
                        # 解析js获取URL
                        if (path == '/' and tag == 'script' and (self.args.api or not self.args.fingerprint_only) and
                                origin_url not in self.js_urls):
                            self.js_urls.append(origin_url)
                            js_url, depth = cal_depth(self, origin_url)
                            if js_url:
                                if origin_url.lower().startswith('http') and origin_url.find('://') > 0:
                                    origin_url = origin_url.split('://')[1]
                                    if origin_url.find('/') > 0:
                                        origin_url = '/'.join(origin_url.split('/')[1:])
                                await self.url_queue.put(('js_file', origin_url, ''))

                if path == '/' and self.fingerprint_check and not fav_url_found:   # 尝试请求默认favicon，计算hash
                    await self.url_queue.put(('favicon', '/favicon.ico', ''))

                if path == '/' and self.fingerprint_check:
                    self.fingerprint_check = False    # this should only run once for each target
                    # 将CMS识别的其他请求，添加到队列
                    for key_name in fingerprint.rules.keys():
                        if key_name != '/^^^get^^^{}^^^':    # 首页已经默认请求过
                            await self.url_queue.put(('key_name', key_name, ''))

                ret = self.find_text(html_doc)
                if ret:
                    title = get_http_title(html_doc)
                    _ = {'status': status, 'url': '%s%s' % (self.base_url, path), 'title': title, 'vul_type': ret[1]}
                    await self.save_result('/', _)

        except Exception as e:
            await self.print_msg('[crawl Exception] %s %s %s' % (path, type(e), str(e)))

    async def load_all_urls_from_log_file(self):
        try:
            with open(self.log_file) as infile:
                for _line in infile.readlines():
                    _ = _line.strip().split()
                    if len(_) == 3 and (_[2].find('^^^200') > 0 or _[2].find('^^^403') > 0 or _[2].find('^^^302') > 0):
                        url, depth = cal_depth(self, _[1])
                        await self.enqueue(url)
        except Exception as e:
            await self.print_msg('[load_all_urls_from_log_file] %s' % str(e))

    def find_text(self, html_doc):
        for _text in self.text_to_find:
            if html_doc.find(_text) >= 0:
                return True, 'Found [%s]' % _text
        for _regex in self.regex_to_find:
            if _regex.search(html_doc):
                return True, 'Found Regex [%s]' % _regex.pattern
        return False

    def find_exclude_text(self, html_doc):
        for _text in self.text_to_exclude:
            if html_doc.find(_text) >= 0:
                return True
        for _regex in self.regex_to_exclude:
            if _regex.search(html_doc):
                return True
        return False

    async def is_url_valid(self, url, item):
        url_description, tag, status_to_match, content_type, content_type_no, root_only, vul_type = item
        status, headers, html_doc = await self.http_request(url)
        cur_content_type = headers.get('content-type', '')
        cur_content_length = headers.get('content-length', len(html_doc))

        if self.find_exclude_text(html_doc):  # excluded text found
            return False

        if 0 <= int(cur_content_length) <= 10:  # text too short
            return False

        if cur_content_type.find('image/') >= 0:  # exclude image
            return False

        if content_type != 'application/json' and cur_content_type.find('application/json') >= 0 and \
                not url.endswith('.json'):  # invalid json
            return False

        if content_type and cur_content_type.find(content_type) < 0 \
                or content_type_no and cur_content_type.find(content_type_no) >= 0:
            return False  # content type mismatch

        if tag and html_doc.find(tag) < 0:
            return False  # tag mismatch

        if self.find_text(html_doc):
            valid_item = True
        else:
            # status code check
            if status_to_match == 206 and status != 206:
                return False
            if status_to_match in (200, 206) and status in (200, 206):
                valid_item = True
            elif status_to_match and status != status_to_match:
                return False
            elif status in (403, 404) and status != status_to_match:
                return False
            else:
                valid_item = True

            if status == self._404_status and url != '/':
                len_doc = len(html_doc)
                len_sum = self.len_404_doc + len_doc
                if len_sum == 0 or (0.4 <= float(len_doc) / len_sum <= 0.6):
                    return False
        return valid_item

    async def save_result(self, prefix, item, msg=None):
        async with self.lock:
            if prefix not in self.results:
                self.results[prefix] = []
            if item not in self.results[prefix]:
                self.results[prefix].append(item)
                if msg:
                    await self.print_msg(msg)

    async def scan_worker(self):
        while True:
            if time.time() - self.start_time > self.time_out and not self.timeout_scan_aborted:
                self.timeout_scan_aborted = True
                clear_queue(self.url_queue)
                await self.print_msg('[ERROR] Timed out task: %s' % self.base_url)
                return
            try:
                item = self.url_queue.get_nowait()
            except Exception as e:
                return
            try:
                if len(item) == 3:
                    if item[0] == 'favicon':
                        resp = await self.conn_pool.get(self.base_url + item[1],
                                                        headers=conf.default_headers,
                                                        follow_redirects=False, timeout=20)
                        fav_hash = hashlib.md5(resp.content).hexdigest()
                        if fav_hash in fingerprint.fav_icons:
                            cms_name = fingerprint.fav_icons[fav_hash]
                            await self.save_result('$Fingerprint', cms_name,
                                                   msg='[Fingerprint] %s found %s' % (self.base_url, cms_name))

                    elif item[0] == 'key_name':
                        key_name = item[1]
                        req_item = fingerprint.requests_to_do[key_name]
                        if req_item[2]:
                            headers = copy.deepcopy(conf.default_headers)
                            headers.update(req_item[2])  # update headers
                        else:
                            headers = conf.default_headers
                        resp = None
                        if req_item[1].lower() == 'get':
                            resp = await self.conn_pool.get(self.base_url + req_item[0], headers=headers)
                        elif req_item[1].lower() == 'post':
                            data = req_item[3]
                            resp = await self.conn_pool.post(self.base_url + req_item[0], headers=headers, data=data)

                        if resp:
                            cms_name = fingerprint.get_cms_name(key_name, resp.status_code, resp.headers, resp.text)
                            if cms_name:
                                await self.save_result('$Fingerprint', cms_name,
                                                       '[Fingerprint] %s found %s' % (self.base_url, cms_name))

                    elif item[0] == 'js_file':
                        _path = item[1] if item[1].startswith('/') else '/' + item[1]
                        status, headers, js_doc = await self.http_request(_path)
                        if headers['content-type'].find('javascript') >= 0:
                            urls_regex, all_path_items, data_leak_found = await get_urls_in_js_async(
                                asyncio.get_event_loop(), js_doc, self.base_url + item[1], self.args.api, self)
                            # 目前并没有尝试请求匹配到的两组 疑似API接口，有误报，需要先优化正则，减少误报后，再添加
                            # 对于接口测试，这里应该是1个非常重要的检测点
                            if self.args.api:
                               self.urls_regex_found = self.urls_regex_found.union(urls_regex)

                            for item in all_path_items:
                                if type(item[2]) is str:
                                    if self.args.api:
                                        urls_regex.add(item[2])
                                    # await self.url_queue.put(('api_endpoint', item[2], ''))
                                    url, depth = cal_depth(self, item[2])
                                    if depth <= self.max_depth:
                                        await self.enqueue(url)

                            if data_leak_found:
                                for item in data_leak_found:
                                    _ = {'status': 200, 'url': self.base_url + _path,
                                         'title': '%s (%s)' % (item[1], item[2]), 'vul_type': 'JS Info Leak'}
                                    await self.save_result('/', _, '[JS Info Leak] %s : %s' % (_['url'], _['title']))

                    continue
                elif len(item) == 2:  # Script Scan
                    check_func = getattr(item[0], 'do_check')
                    # await self.print_msg('Begin %s %s' % (os.path.basename(item[0].__file__), item[1]))
                    await check_func(self, item[1])
                    # await self.print_msg('End %s %s' % (os.path.basename(item[0].__file__), item[1]))
                    continue
                else:
                    url_description, tag, status_to_match, content_type, content_type_no, root_only, vul_type = item
                    prefix = url_description['prefix']
                    url = url_description['full_url']

                    if url.find('{sub}') >= 0:
                        if not self.domain_sub:
                            continue
                        url = url.replace('{sub}', self.domain_sub)

            except Exception as e:
                await self.print_msg('[scan_worker.1] %s, %s, %s' % (str(e), self.base_url, item))
                # await self.print_msg(traceback.format_exc())
                continue
            if not item or not url:
                break

            try:
                valid_item = await self.is_url_valid(url, item)

                if valid_item:
                    _ = url.split('/')
                    _[-1] = 'fptest' + _[-1]
                    url_fp_test = '/'.join(_)  # add false positive test prefix
                    ret = await self.is_url_valid(url_fp_test, item)
                    if ret:
                        valid_item = False
                if valid_item:
                    status, headers, html_doc = await self.http_request(url)
                    title = get_http_title(html_doc)
                    _ = {'status': status, 'url': '%s%s' % (self.base_url, url), 'title': title, 'vul_type': vul_type}
                    await self.save_result(prefix, _)
            except Exception as e:
                await self.print_msg('[scan_worker.2][%s] %s, %s' % (url, str(e), item))
                # await self.print_msg(traceback.format_exc())

    async def scan(self, threads=6):
        try:
            all_threads = []
            for i in range(threads):
                t = self.scan_worker()
                all_threads.append(t)
            await asyncio.gather(*all_threads)

            for key in self.results.keys():
                # too many URLs found under this folder, deduplicate results
                if len(self.results[key]) > 10:
                    vul_type_count = {}
                    for item in copy.deepcopy(self.results[key]):
                        if item['vul_type'] not in vul_type_count:
                            vul_type_count[item['vul_type']] = 1
                        else:
                            vul_type_count[item['vul_type']] += 1
                            if vul_type_count[item['vul_type']] >= 3:
                                self.results[key].remove(item)
            return clear_url(self.base_url), self.results, self.urls_regex_found

        except Exception as e:
            await self.print_msg('[scan exception] %s' % str(e))
        finally:
            try:
                await self.conn_pool.aclose()
            except Exception as e:
                pass


async def scan_process():
    s = Scanner(args.timeout * 60)
    await s.init()
    while True:
        try:
            target = q_targets.get_nowait()
        except asyncio.queues.QueueEmpty as e:
            if conf.process_targets_done and q_targets.qsize() == 0:
                break
            else:
                await asyncio.sleep(0.1)
                continue

        if 'target' in target:
            ret = await s.init_from_url(target['target'])
        elif 'file' in target:
            ret = await s.init_from_log_file(target['file'])
        else:
            continue

        if ret:
            item = await s.scan(threads=args.t)
            if item[1]:
                await q_results.put(copy.deepcopy(item))


async def add_target(target, is_neighbor=False):
    if is_neighbor:
        target['no_scripts'] = 1    # 邻居IP，不启用插件. Bug fixed: 2024/05/03
    if args.debug:
        await q_results.put('New target: %s' % target)
    await q_targets.put({'target': target})
    if args.save_ports and target['ports_open']:
        conf.ports_saved_to_file = True
        if not args.ports_file:
            args.ports_file = open(args.save_ports, 'w')
        for port in target['ports_open']:
            args.ports_file.write('%s:%s\n' % (target['host'], port))
        args.ports_file.flush()
    conf.tasks_count += 1


def is_intranet(ip):
    try:
        ret = ip.split('.')
        if len(ret) != 4:
            return True
        if ret[0] == '10':
            return True
        if ret[0] == '172' and 16 <= int(ret[1]) <= 31:
            return True
        if ret[0] == '192' and ret[1] == '168':
            return True
        return False
    except Exception as e:
        return False


resolver = dns.asyncresolver.Resolver()


async def domain_lookup_check(queue_targets_origin, processed_targets, queue_targets):
    while True:
        try:
            url = queue_targets_origin.get_nowait()
        except asyncio.queues.QueueEmpty as e:
            break
        # scheme netloc path
        if url.find('://') < 0:
            netloc = url[:url.find('/')] if url.find('/') > 0 else url
        else:
            scheme, netloc, path, params, query, fragment = urlparse(url, 'http')

        # host port
        host = netloc.split(':')[0] if netloc.find(':') >= 0 else netloc

        if is_ip_addr(host):
            processed_targets.append(host)
            if args.skip_intranet and is_intranet(host):
                await q_results.put('Private IP target skipped: %s [%s]' % (url, host))
            else:
                await queue_targets.put((url, 0, host))
        else:
            for i in range(5):
                try:
                    answers = await resolver.resolve(host, "A")
                    processed_targets.append(answers[0].address)
                    if args.skip_intranet and is_intranet(answers[0].address):
                        await q_results.put('Private IP target skipped: %s [%s]' % (url, answers[0].address))
                    else:
                        await queue_targets.put((url, 0, answers[0].address))
                    break
                except dns.resolver.NXDOMAIN as e:
                    await q_results.put('No such domain: %s' % host)
                    break
                except Exception as e:
                    if i == 4:    # Failed after 4 retries
                        await q_results.put('Domain lookup failed [%s]: %s' % (e.__class__.__name__, host))


async def do_port_scan_check(queue_targets):
    """
    检测目标的端口是否开放，输入的目标是URL，也可能是网段下的相邻IP
    """
    while True:
        try:
            url, is_neighbor, ip_addr = queue_targets.get_nowait()   # is_neighbor = 1 为相邻网段的IP，优先级降低
        except asyncio.queues.QueueEmpty as e:
            break
        try:
            # scheme netloc path
            if url.find('://') < 0:
                scheme = 'unknown'
                netloc = url[:url.find('/')] if url.find('/') > 0 else url
                path = ''
            else:
                scheme, netloc, path, params, query, fragment = urlparse(url, 'http')

            # host port
            if netloc.find(':') >= 0:
                _ = netloc.split(':')
                host = _[0]
                try:
                    port = int(_[1])
                except:
                    port = None
            else:
                host = netloc
                port = None

            if scheme == 'https' and port is None:
                port = 443
            elif scheme == 'http' and port is None:
                port = 80

            if scheme == 'unknown':
                if port == 80:
                    scheme = 'http'
                if port == 443:
                    scheme = 'https'

            ports_open = set()
            ports_closed = set()

            # 插件不依赖HTTP连接池， 且仅启用插件扫描， 则不需要检查80/443端口的HTTP服务， 直接扫描 require_ports
            if args.scripts_only and args.require_no_http:
                ports_open, ports_closed = await scan_given_ports(ip_addr, args.require_ports, ports_open, ports_closed)
                target = {'scheme': scheme, 'host': host, 'port': port, 'path': path,
                          'has_http': False, 'ports_open': ports_open, 'ports_closed': ports_closed}
                await add_target(target)    # 在只扫插件的情况下，相邻IP也需要启用
                continue

            if port:
                # 指定了 标准端口 或 非标准端口
                has_http = await is_port_open(ip_addr, port)
                if has_http:
                    ports_open.add(port)
                else:
                    ports_closed.add(port)
                if not args.no_scripts:
                    ports_open, ports_closed = \
                        await scan_given_ports(ip_addr, args.require_ports, ports_open, ports_closed)

                target = {'scheme': scheme, 'host': host, 'port': port, 'path': path, 'has_http': has_http,
                          'ports_open': ports_open, 'ports_closed': ports_closed}
                await add_target(target)

            else:
                # 只有域名和IP情况下， 扫默认端口
                port_open_80 = await is_port_open(ip_addr, 80)
                port_open_443 = await is_port_open(ip_addr, 443)

                if port_open_80:
                    ports_open.add(80)
                else:
                    ports_closed.add(80)
                if port_open_443:
                    ports_open.add(443)
                else:
                    ports_closed.add(443)
                if not args.no_scripts:
                    ports_open, ports_closed = \
                        await scan_given_ports(ip_addr, args.require_ports, ports_open, ports_closed)

                if port_open_80 and port_open_443:
                    target = {'scheme': 'https', 'host': host, 'port': 443, 'path': path,
                              'has_http': True, 'ports_open': ports_open, 'ports_closed': ports_closed}
                    await add_target(target, is_neighbor)
                    # 排除 301 HTTP 跳转 HTTPS的目标
                    async with httpx.AsyncClient() as client:
                        r = await client.get('http://%s' % host, follow_redirects=False, timeout=20)
                        if r and not \
                                (r.status_code == 301 and r.headers.get('Location', '').lower().startswith('https')):
                            target = {'scheme': 'http', 'host': host, 'port': 80, 'path': path,
                                      'has_http': True, 'no_scripts': 1,
                                      'ports_open': ports_open, 'ports_closed': ports_closed}
                            await add_target(target)

                elif port_open_443:
                    target = {'scheme': 'https', 'host': host, 'port': 443, 'path': path,
                              'has_http': True, 'ports_open': ports_open, 'ports_closed': ports_closed}
                    # 即使指定的目标，允许插件扫描，邻居也将不启用，节省扫描时间
                    await add_target(target, is_neighbor)
                elif port_open_80:
                    target = {'scheme': 'http', 'host': host, 'port': 80, 'path': path,
                              'has_http': True, 'ports_open': ports_open, 'ports_closed': ports_closed}
                    await add_target(target, is_neighbor)
                elif args.no_scripts:
                    # 80 443 端口不开放， 禁用插件扫描
                    await q_results.put('No ports open: %s' % host)
                elif not is_neighbor or args.scripts_only:
                    # 直接输入目标 或者 对相邻IP应用插件
                    # 80 443 未开放，此时只能检测其他端口的漏洞
                    # 如果没有任何开放的端口，直接跳过该目标
                    if ports_open:
                        target = {'scheme': 'http', 'host': host, 'port': 80, 'path': path,
                                  'has_http': False, 'ports_open': ports_open, 'ports_closed': ports_closed}
                        await add_target(target)
                    else:
                        await q_results.put('[Warning] Target has no open ports: %s' % url)
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            pass
        except Exception as e:
            # import traceback
            # await q_results.put(traceback.format_exc())
            await q_results.put('[port_scan_check.exception] URL is %s, %s' % (url, str(e)))


async def port_scan_check(queue_targets):
    threads = [do_port_scan_check(queue_targets) for _ in range(250)]
    await asyncio.gather(*threads)


async def prepare_targets(target_list):
    """
    Process URL / IP / Domain, port scan
    处理域名、IP，扫描目标端口80 443等端口是否开放
    """
    queue_targets_origin = asyncio.Queue()
    for target in target_list:
        if target.strip() and len(target) > 5:
            # work with https://github.com/lijiejie/subDomainsBrute
            # Delimiter should be ","
            hosts = target.replace(',', ' ').strip().split()
            await queue_targets_origin.put(hosts[0])

    processed_targets = []
    # 将域名解析和端口扫描拆分，可节省约2s.更简单的做法, 可以将DNS解析和端口扫描合并为一个函数，但会损失 2s
    await q_results.put('Domain lookup start.')
    queue_targets = asyncio.Queue()
    # Be careful: 当 DNS查询并发过高时，在家庭网络下会出现较多超时
    threads = [domain_lookup_check(queue_targets_origin, processed_targets, queue_targets) for _ in range(50)]
    await asyncio.gather(*threads)

    if args.network != 32:
        await q_results.put('Process sub network start.')
        num_entered_queue = 0
        for ip in processed_targets:
            if ip.find('/') > 0:    # 子网本身已经处理过
                continue
            _network = u'%s/%s' % ('.'.join(ip.split('.')[:3]), args.network)
            if _network in processed_targets:
                continue
            processed_targets.append(_network)

            if args.network >= 20:
                sub_nets = [ipaddress.IPv4Network(u'%s/%s' % (ip, args.network), strict=False).hosts()]
            else:
                sub_nets = ipaddress.IPv4Network(u'%s/%s' % (ip, args.network), strict=False).subnets(new_prefix=22)
            for sub_net in sub_nets:
                if sub_net in processed_targets:
                    continue
                if type(sub_net) is ipaddress.IPv4Network:    # add network only
                    processed_targets.append(str(sub_net))
                for _ip in sub_net:
                    _ip = str(_ip)
                    if _ip not in processed_targets:
                        await queue_targets.put((_ip, 1, _ip))
                        num_entered_queue += 1
                if num_entered_queue > 65535:    # 队列不宜太长，如果超过一个B段，分多次处理
                    await port_scan_check(queue_targets)
                    num_entered_queue = 0
    if queue_targets.qsize() > 0:    # 还有剩余未处理目标
        await port_scan_check(queue_targets)
    # save ports data
    if args.save_ports and args.ports_file:
        args.ports_file.close()

    conf.process_targets_done = True
    await q_results.put('* Targets DNS resolve and port scan all done.')


async def main():
    for input_file in args.input_files:
        if args.host:
            target_list = args.host
            # Targets input via commandline args, create double processes at most
            if args.network == 32 and len(target_list) * 2 < args.p:
                args.p = len(target_list) * 2
        elif args.f or args.d:
            with codecs.open(input_file, encoding='utf-8') as inFile:
                target_list = inFile.readlines()
                # Targets input via file, create double processes at most
                if args.network == 32 and len(target_list) * 2 < args.p:
                    args.p = len(target_list) * 2
        try:
            clear_queue(q_results)
            clear_queue(q_targets)
            # save report thread
            asyncio.create_task(save_report(args, q_results, input_file))

            conf.process_targets_done = False
            start_time = time.time()

            if args.crawler:
                # 爬虫URL导入，在3.0版本后，还未经测试，仅保留了原逻辑。 待测试
                input_files = glob.glob(args.crawler + '/*.log')
                for _file in input_files:
                    await q_targets.put({'file': _file})
                    conf.tasks_count += 1
                if conf.tasks_count < args.p:
                    args.p = conf.tasks_count
                conf.process_targets_done = True
            else:
                conf.tasks_count = 0
                asyncio.create_task(prepare_targets(target_list))

            all_process = [scan_process() for _ in range(args.p)]
            await q_results.put('%s scan process started' % args.p)
            await asyncio.gather(*all_process)

            cost_time = time.time() - start_time
            cost_min = int(cost_time / 60)
            cost_min = '%s min ' % cost_min if cost_min > 0 else ''
            cost_seconds = '%.1f' % (cost_time % 60)
            await q_results.put('Scanned %s targets in %s%s seconds' % (conf.tasks_count, cost_min, cost_seconds))
        except KeyboardInterrupt as e:
            conf.stop_me = True
            await q_results.put('Scan aborted by user')
            if conf.output_file_name:
                await q_results.put('If you are interested, partial report is: %s' % conf.output_file_name)
            exit(-1)
        except Exception as e:
            traceback.print_exc()
            await q_results.put('[main.exception] %s %s' % (type(e), str(e)))

        conf.stop_me = True
        await asyncio.sleep(3.0)   # report 需要一些时间写入和唤起浏览器


if __name__ == '__main__':
    args = parse_args()
    print('* BBScan %s  https://github.com/lijiejie/BBScan *' % conf.version)
    if args.no_scripts:
        print('* Scripts scan was disabled')
    if args.require_ports:
        print('* Scripts scan port check: %s' % ','.join([str(x) for x in args.require_ports]))
    if sys.version_info.major >= 3 and sys.version_info.minor >= 10:
        loop = asyncio.new_event_loop()
    else:
        loop = asyncio.get_event_loop()
    q_targets = asyncio.Queue()    # targets Queue
    q_results = asyncio.Queue()    # results Queue
    loop.run_until_complete(main())
