#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
 Fast vulnerability scanner
 Scan sensitive information disclosure vulnerabilities for mass targets in a short time
 LiJieJie  my[at]lijiejie.com  http://www.lijiejie.com
"""

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
import os
import ssl
import traceback
import importlib
import platform
import socket
import copy
import dns.asyncresolver
from urllib.parse import urlparse

from lib.common import clear_queue, parse_url, cal_depth, get_domain_sub, is_port_open, scan_given_ports, is_ip_addr
from lib.cmdline import parse_args
from lib.report import save_report
import lib.config as conf


if hasattr(ssl, '_create_unverified_context'):
    ssl._create_default_https_context = ssl._create_unverified_context

warnings.filterwarnings("ignore", category=UserWarning, module='bs4')


if platform.system() == 'Windows':
    try:
        def _call_connection_lost(self, exc):
            try:
                self._protocol.connection_lost(exc)
            finally:
                if hasattr(self._sock, 'shutdown'):
                    try:
                        if self._sock.fileno() != -1:
                            self._sock.shutdown(socket.SHUT_RDWR)
                    except Exception as e:
                        pass
                self._sock.close()
                self._sock = None
                server = self._server
                if server is not None:
                    server._detach()
                    self._server = None

        asyncio.proactor_events._ProactorBasePipeTransport._call_connection_lost = _call_connection_lost
    except Exception as e:
        pass


class Scanner(object):
    def __init__(self, timeout=600):
        self.q_results = q_results
        self.args = args
        self.start_time = time.time()
        self.time_out = timeout
        self.links_limit = 100  # max number of folders to scan

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
        self.conn_pool = None
        self.index_status, self.index_headers, self.index_html_doc = None, {}, ''
        self.scheme, self.host, self.port, self.path = None, None, None, None
        self.domain_sub = ''
        self.base_url = ''
        self.status_502_count = 0
        self.timeout_count = 0

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
            print(e)

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
                                               proxies=args.proxy, verify=False, limits=limits)

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
            await self.print_msg('[Warning] HTTP 404 check failed <%s:%s>' % (self.host, self.port))
        elif self._404_status != 404:
            await self.print_msg('[Warning] %s has no HTTP 404.' % self.base_url)
        _path, _depth = cal_depth(self, self.path)

        await self.enqueue('/')
        if _path != '/' and not self.log_file:
            await self.enqueue(_path)

    #
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
        for _script in glob.glob('scripts/*.py'):
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

    async def http_request(self, url, headers=conf.default_headers, timeout=20):
        try:
            if not url:
                url = '/'
            if not self.conn_pool:
                return -1, {}, ''
            if self.args.debug:
                await self.print_msg('--> %s' % self.base_url + url)
            resp = await self.conn_pool.get(self.base_url + url,
                                            headers=headers, follow_redirects=False, timeout=timeout)
            if resp.headers.get('content-type', '').find('text') >= 0 \
                    or resp.headers.get('content-type', '').find('html') >= 0 \
                    or int(resp.headers.get('content-length', '0')) <= 20480:  # 1024 * 20
                html_doc = resp.text
            else:
                html_doc = ''

            if resp.status_code == 502:    # 502出现3次以上，排除该站点
                self.status_502_count += 1
                if self.status_502_count > 3:
                    clear_queue(self.url_queue)
                    try:
                        if self.conn_pool:
                            await self.conn_pool.aclose()
                    except Exception as e:
                        pass    #
                    self.conn_pool = None
                    # await self.print_msg('Website 502 exceeded: %s' % self.base_url)

            return resp.status_code, resp.headers, html_doc
        except httpx.ReadTimeout as e:
            self.timeout_count += 1
            if self.timeout_count >= 3:
                await self.print_msg('[Warning] timeout exceeded, scan canceled: %s' % self.base_url)
                clear_queue(self.url_queue)
            return -1, {}, ''
        except (httpx.RequestError, httpx.HTTPStatusError, ssl.SSLError) as e:
            return -1, {}, ''
        except Exception as e:
            # await self.print_msg('[Request Error] %s %s %s' % (type(e), str(e), self.base_url))
            return -1, {}, ''

    async def check_404_existence(self):
        try:
            try:
                self._404_status, _, html_doc = await self.http_request('/BBScan-404-existence-check')
            except Exception as e:
                await self.print_msg('[Warning] HTTP 404 check failed: %s' % self.base_url)
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
            headers = dict(conf.default_headers, Range='bytes=0-204800')
            status, headers, html_doc = await self.http_request(path, headers=headers)
            if path == '/':
                self.index_status, self.index_headers, self.index_html_doc = status, headers, html_doc
            if not self.args.no_crawl and not do_not_process_links and html_doc:
                soup = BeautifulSoup(html_doc, "html.parser")
                for link in soup.find_all('a'):
                    url = link.get('href', '').strip()
                    if url.startswith('..'):
                        continue
                    if not url.startswith('/') and url.find('//') < 0:   # relative path
                        url = path + url
                    url, depth = cal_depth(self, url)
                    # print url, depth
                    if depth <= self.max_depth:
                        await self.enqueue(url)
                #
                ret = self.find_text(html_doc)
                if ret:
                    if '/' not in self.results:
                        self.results['/'] = []
                    m = re.search('<title>(.*?)</title>', html_doc)
                    title = m.group(1) if m else ''
                    _ = {'status': status, 'url': '%s%s' % (self.base_url, path), 'title': title, 'vul_type': ret[1]}
                    if _ not in self.results['/']:
                        self.results['/'].append(_)

        except Exception as e:
            await self.print_msg('[crawl Exception] %s %s' % (path, str(e)))

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

    async def scan_worker(self):
        while True:
            if time.time() - self.start_time > self.time_out:
                clear_queue(self.url_queue)
                await self.print_msg('[ERROR] Timed out task: %s' % self.base_url)
                return
            try:
                item = self.url_queue.get_nowait()
            except Exception as e:
                return
            try:
                if len(item) == 2:  # Script Scan
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
                await self.print_msg('[scan_worker.1] %s' % str(e))
                await self.print_msg(traceback.format_exc())
                continue
            if not item or not url:
                break

            try:
                status, headers, html_doc = await self.http_request(url)
                cur_content_type = headers.get('content-type', '')
                cur_content_length = headers.get('content-length', len(html_doc))

                if self.find_exclude_text(html_doc):  # excluded text found
                    continue

                if 0 <= int(cur_content_length) <= 10:  # text too short
                    continue

                if cur_content_type.find('image/') >= 0:  # exclude image
                    continue

                if content_type != 'application/json' and cur_content_type.find('application/json') >= 0 and \
                        not url.endswith('.json'):    # invalid json
                    continue

                if content_type and cur_content_type.find(content_type) < 0 \
                        or content_type_no and cur_content_type.find(content_type_no) >= 0:
                    continue    # content type mismatch

                if tag and html_doc.find(tag) < 0:
                    continue    # tag mismatch

                if self.find_text(html_doc):
                    valid_item = True
                else:
                    # status code check
                    if status_to_match == 206 and status != 206:
                        continue
                    if status_to_match in (200, 206) and status in (200, 206):
                        valid_item = True
                    elif status_to_match and status != status_to_match:
                        continue
                    elif status in (403, 404) and status != status_to_match:
                        continue
                    else:
                        valid_item = True

                    if status == self._404_status and url != '/':
                        len_doc = len(html_doc)
                        len_sum = self.len_404_doc + len_doc
                        if len_sum == 0 or (0.4 <= float(len_doc) / len_sum <= 0.6):
                            continue

                if valid_item:
                    m = re.search('<title>(.*?)</title>', html_doc)
                    title = m.group(1) if m else ''
                    async with self.lock:
                        # await self.print_msg(
                        # '[+] [Prefix:%s] [%s] %s' % (prefix, status, 'http://' + self.host +  url))
                        if prefix not in self.results:
                            self.results[prefix] = []
                        _ = {'status': status, 'url': '%s%s' % (self.base_url, url),
                             'title': title, 'vul_type': vul_type}
                        if _ not in self.results[prefix]:
                            self.results[prefix].append(_)

            except Exception as e:
                await self.print_msg('[scan_worker.2][%s] %s' % (url, str(e)))
                traceback.print_exc()

    async def scan(self, threads=6):
        try:
            all_threads = []
            for i in range(threads):
                t = self.scan_worker()
                all_threads.append(t)
            await asyncio.gather(*all_threads)

            for key in self.results.keys():
                # Over 15 URLs found under this folder, show the first one only
                if len(self.results[key]) > 150:
                    self.results[key] = self.results[key][:1]
            return self.base_url.lstrip('unknown://').rstrip(':None'), self.results
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
            # host, results = await s.scan(threads=args.t)
            item = await s.scan(threads=args.t)
            if item[1]:
                await q_results.put(copy.deepcopy(item))


async def add_target(target, is_neighbor=False):
    if is_neighbor:
        target['no_scripts'] = 0    # 邻居IP，不启用插件
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
            await queue_targets.put((url, 0))
        else:
            try:
                answers = await dns.asyncresolver.resolve(host, "A")
                processed_targets.append(answers[0].address)
                await queue_targets.put((url, 0))
            except Exception as e:
                await q_results.put('Invalid domain: %s' % host)


async def do_port_scan_check(queue_targets):
    """
    检测端口是否开放
    no_scripts
    -> null 无限制
    -> 1 目标重复， 优先级是最高的
    -> 2 邻居，为节省时间而禁用的
    """
    while True:
        try:
            url, is_neighbor = queue_targets.get_nowait()
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

            # 插件不依赖HTTP连接池， 且仅启用插件扫描， 则不需要检查80/443端口的HTTP服务
            if args.scripts_only and args.require_no_http:
                ports_open, ports_closed = await scan_given_ports(host, args.require_ports, ports_open, ports_closed)
                target = {'scheme': scheme, 'host': host, 'port': port, 'path': path,
                          'has_http': False, 'ports_open': ports_open, 'ports_closed': ports_closed}
                await add_target(target)
                continue

            if port:
                # 指定的 标准端口 或 非标准端口
                has_http = await is_port_open(host, port)
                if has_http:
                    ports_open.add(port)
                else:
                    ports_closed.add(port)
                if not args.no_scripts:
                    ports_open, ports_closed = \
                        await scan_given_ports(host, args.require_ports, ports_open, ports_closed)

                target = {'scheme': scheme, 'host': host, 'port': port, 'path': path, 'has_http': has_http,
                          'ports_open': ports_open, 'ports_closed': ports_closed}
                await add_target(target)

            else:
                port_open_80 = await is_port_open(host, 80)
                port_open_443 = await is_port_open(host, 443)
                if port_open_80:
                    ports_open.add(80)
                else:
                    ports_closed.add(80)
                if port_open_443:
                    ports_open.add(80)
                else:
                    ports_closed.add(80)
                if not args.no_scripts:
                    ports_open, ports_closed = \
                        await scan_given_ports(host, args.require_ports, ports_open, ports_closed)

                if port_open_80 and port_open_443:
                    target = {'scheme': 'https', 'host': host, 'port': 443, 'path': path,
                              'has_http': True, 'ports_open': ports_open, 'ports_closed': ports_closed}
                    await add_target(target, is_neighbor)
                    # 排除 301 http 跳转 https
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
                    # 即使指定的一些目标，允许插件扫描，邻居也不启用，节省扫描时间
                    await add_target(target, is_neighbor)
                elif port_open_80:
                    target = {'scheme': 'http', 'host': host, 'port': 80, 'path': path,
                              'has_http': True, 'ports_open': ports_open, 'ports_closed': ports_closed}
                    await add_target(target, is_neighbor)
                elif args.no_scripts:
                    # 80 443 端口不开放， 禁用插件扫描
                    await q_results.put('No ports open: %s' % host)
                elif not is_neighbor or args.scripts_only:
                    # 直接输入目标 或者 对邻居应用插件
                    target = {'scheme': 'http', 'host': host, 'port': 80, 'path': path,
                              'has_http': False, 'ports_open': ports_open, 'ports_closed': ports_closed}
                    await add_target(target)
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            pass
        except Exception as e:
            # import traceback
            # await q_results.put(traceback.format_exc())
            await q_results.put('[port_scan_check] %s' % str(e))


async def port_scan_check(queue_targets):
    threads = [do_port_scan_check(queue_targets) for _ in range(250)]
    await asyncio.gather(*threads)


async def prepare_targets(target_list):
    """
    Process URL / IP / Domain, port scan
    """
    queue_targets_origin = asyncio.Queue()
    for target in target_list:
        if target.strip() and len(target) > 5:
            # work with https://github.com/lijiejie/subDomainsBrute
            # Delimiter should be ","
            hosts = target.replace(',', ' ').strip().split()
            await queue_targets_origin.put(hosts[0])

    processed_targets = []
    # 将域名解析和端口扫描拆分，可节省约2s。 更简单的做法, 可以将DNS解析和端口扫描合并为一个函数，但那样会损失 2s
    await q_results.put('Domain lookup start.')
    queue_targets = asyncio.Queue()
    threads = [domain_lookup_check(queue_targets_origin, processed_targets, queue_targets) for _ in range(250)]
    await asyncio.gather(*threads)

    if args.network != 32:
        await q_results.put('Process sub network start.')
        num_entered_queue = 0
        for ip in processed_targets:
            if ip.find('/') > 0:    # 网络本身已经处理过
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
                if type(sub_net) == ipaddress.IPv4Network:    # add network only
                    processed_targets.append(str(sub_net))
                for _ip in sub_net:
                    _ip = str(_ip)
                    if _ip not in processed_targets:
                        await queue_targets.put((_ip, 1))
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
    await q_results.put('* Targets process all done.')


async def main():
    for input_file in args.input_files:
        if args.host:
            target_list = args.host
            # Targets input via commandline args，create double processes at most
            if args.network == 32 and len(target_list) * 2 < args.p:
                args.p = len(target_list) * 2
        elif args.f or args.d:
            with codecs.open(input_file, encoding='utf-8') as inFile:
                target_list = inFile.readlines()
                # Targets input via file，create double processes at most
                if args.network == 32 and len(target_list) * 2 < args.p:
                    args.p = len(target_list) * 2
        try:
            # save report thread
            asyncio.create_task(save_report(args, q_results, input_file))

            clear_queue(q_results)
            clear_queue(q_targets)
            conf.process_targets_done = False
            start_time = time.time()

            if args.crawler:
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
            await q_results.put('%s scan process created' % args.p)
            await asyncio.gather(*all_process)

            cost_time = time.time() - start_time
            cost_min = int(cost_time / 60)
            cost_min = '%s min ' % cost_min if cost_min > 0 else ''
            cost_seconds = '%.1f' % (cost_time % 60)
            await q_results.put('Scanned %s targets in %s%s seconds' % (conf.tasks_count, cost_min, cost_seconds))
        except KeyboardInterrupt as e:
            conf.stop_me = True
            await q_results.put('Scan aborted by user')
            exit(-1)
        except Exception as e:
            import traceback
            traceback.print_exc()
            await q_results.put('[__main__.exception] %s %s' % (type(e), str(e)))

        conf.stop_me = True
        await asyncio.sleep(5.0)


if __name__ == '__main__':
    args = parse_args()
    print('* BBScan v2.0  https://github.com/lijiejie/BBScan *')
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
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
