#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# A fast vulnerability scanner
# Simple script scan for a Class B Network (65534 hosts) could be processed within 2 minutes
# LiJieJie  my[at]lijiejie.com  http://www.lijiejie.com

import Queue
import re
import threading
from bs4 import BeautifulSoup
import multiprocessing
import time
import glob
import ipaddress
import os
import socket
import ssl
import traceback
import importlib
import signal
import requests
import urllib3
import urlparse
import gevent
from gevent import socket as g_socket
from lib.common import clear_queue, parse_url, decode_response_text, cal_depth, get_domain_sub, \
    is_port_open, scan_given_ports
from lib.cmdline import parse_args
from lib.report import save_report
from lib.connectionPool import HTTPConnPool, HTTPSConnPool
from lib import config


if hasattr(ssl, '_create_unverified_context'):
    ssl._create_default_https_context = ssl._create_unverified_context


class Scanner(object):
    def __init__(self, q_results, timeout=600, args=None):
        self.q_results = q_results
        self.args = args
        self.start_time = time.time()
        self.time_out = timeout
        self.links_limit = 100  # max number of folders to scan

        self._init_rules()
        self._init_scripts()

        self.url_queue = Queue.Queue()  # all urls to scan
        self.urls_processed = set()     # processed urls
        self.urls_enqueued = set()      # entered queue urls
        self.urls_crawled = set()

        self.lock = threading.Lock()
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

    def print_msg(self, msg):
        self.q_results.put(msg)

    def reset_scanner(self):
        self.start_time = time.time()
        self.url_queue.queue.clear()
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

    # scan from a given URL
    def init_from_url(self, target):
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
        self.init_final()
        return True

    def init_from_log_file(self, log_file):
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
            if not is_port_open(self.host, self.port):
                self.print_msg('[Port Not Open] %s:%s' % (self.host, self.port))
                return False
            self.has_http = True
            self.no_scripts = 1
            self.init_final()
            self.load_all_urls_from_log_file()
            return True
        else:
            host = os.path.basename(log_file).replace('.log', '')
            try:
                socket.gethostbyname(host)
                self.init_from_url(host)     # Fix Me
                return True
            except Exception as e:
                self.print_msg('[ERROR] Invalid host from log name: %s' % host)
                return False

    def init_final(self):
        try:
            if self.conn_pool:
                self.conn_pool.close()
        except Exception as e:
            pass

        if self.scheme == 'http' and self.port == 80 or self.scheme == 'https' and self.port == 443:
            self.base_url = '%s://%s' % (self.scheme, self.host)
        else:
            self.base_url = '%s://%s:%s' % (self.scheme, self.host, self.port)

        if self.has_http:
            self.print_msg('Scan %s' % self.base_url)
        else:
            self.print_msg('Scan %s:%s' % (self.host, self.port) if self.port else 'Scan %s' % self.host)

        if self.has_http:
            if self.scheme == 'https':
                self.conn_pool = HTTPSConnPool(self.host, port=self.port, maxsize=self.args.t,
                                               headers=config.default_headers)
            else:
                self.conn_pool = HTTPConnPool(self.host, port=self.port, maxsize=self.args.t,
                                              headers=config.default_headers)
            if self.args.require_index_doc:
                self.crawl('/', do_not_process_links=True)

        if self.no_scripts != 1:   # 不是重复目标 80 443 跳转的，不需要重复扫描
            # 当前目标disable， 或者 全局开启插件扫描
            if self.args.scripts_only or not self.no_scripts:
                for _ in self.user_scripts:
                    self.url_queue.put((_, '/'))

        if not self.has_http or self.args.scripts_only:    # 未发现HTTP服务 或  只依赖插件扫描
            return

        self.max_depth = cal_depth(self, self.path)[1] + 5
        if self.args.no_check404:
            self._404_status = 404
        else:
            self.check_404_existence()
        if self._404_status == -1:
            self.print_msg('[Warning] HTTP 404 check failed <%s:%s>' % (self.host, self.port))
        elif self._404_status != 404:
            self.print_msg('[Warning] %s has no HTTP 404.' % self.base_url)
        _path, _depth = cal_depth(self, self.path)

        self.enqueue('/')
        if _path != '/' and not self.log_file:
            self.enqueue(_path)

    #
    def _parse_url_from_file(self):
        url = ''
        with open(self.log_file) as infile:
            for _line in infile.xreadlines():
                _line = _line.strip()
                if _line and len(_line.split()) >= 3:
                    url = _line.split()[1]
                    break
        return parse_url(url)

    # load urls from rules/*.txt
    def _init_rules(self):
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
            with open(rule_file, 'r') as infile:
                vul_type = os.path.basename(rule_file)[:-4]
                for url in infile.xreadlines():
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
                                self.print_msg('Duplicated root only rule: %s' % str(rule))
                        else:
                            if rule not in self.rules_set:
                                self.rules_set.add(rule)
                            else:
                                self.print_msg('Duplicated rule: %s' % str(rule))

        re_text = re.compile('{text="(.*)"}')
        re_regex_text = re.compile('{regex_text="(.*)"}')

        file_path = 'rules/white.list'
        if not os.path.exists(file_path):
            self.print_msg('[ERROR] File not exist: %s' % file_path)
            return
        for _line in open(file_path):
            _line = _line.strip()
            if not _line or _line.startswith('#'):
                continue
            _m = re_text.search(_line)
            if _m:
                self.text_to_find.append(_m.group(1).decode('utf-8', 'ignore'))
            else:
                _m = re_regex_text.search(_line)
                if _m:
                    self.regex_to_find.append(re.compile(_m.group(1).decode('utf-8', 'ignore')))

        file_path = 'rules/black.list'
        if not os.path.exists(file_path):
            self.print_msg('[ERROR] File not exist: %s' % file_path)
            return
        for _line in open(file_path):
            _line = _line.strip()
            if not _line or _line.startswith('#'):
                continue
            _m = re_text.search(_line)
            if _m:
                self.text_to_exclude.append(_m.group(1).decode('utf-8', 'ignore'))
            else:
                _m = re_regex_text.search(_line)
                if _m:
                    self.regex_to_exclude.append(re.compile(_m.group(1).decode('utf-8', 'ignore')))

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
                self.print_msg('[ERROR] Fail to load script %s' % script_name)

    def http_request(self, url, headers=config.default_headers, timeout=20):
        try:
            if not url:
                url = '/'
            if not self.conn_pool:
                return -1, {}, ''
            if self.args.debug:
                self.print_msg('--> %s' % self.base_url + url)
            resp = self.conn_pool.urlopen('GET', self.base_url + url,
                                          headers=headers, assert_same_host=False,
                                          redirect=False, timeout=timeout, retries=0)
            if resp.headers.get('content-type', '').find('text') >= 0 \
                    or resp.headers.get('content-type', '').find('html') >= 0 \
                    or int(resp.headers.get('content-length', '0')) <= 20480:  # 1024 * 20
                html_doc = decode_response_text(resp.data)
            else:
                html_doc = ''

            if resp.status == 502:    # 502出现3次以上，排除该站点
                self.status_502_count += 1
                if self.status_502_count > 3:
                    self.url_queue.queue.clear()
                    try:
                        if self.conn_pool:
                            self.conn_pool.close()
                    except Exception as e:
                        pass
                    self.conn_pool = None
                    # self.print_msg('Website 502: %s' % self.base_url)

            return resp.status, resp.headers, html_doc
        except urllib3.exceptions.MaxRetryError as e:
            return -1, {}, ''
        except TypeError as e:
            return -1, {}, ''
        except Exception as e:
            self.print_msg(str(e))
            return -1, {}, ''

    # check existence of status 404
    def check_404_existence(self):
        try:
            try:
                self._404_status, _, html_doc = self.http_request('/BBScan-404-existence-check')
            except Exception as e:
                self.print_msg('[Warning] HTTP 404 check failed: %s' % self.base_url)
                self._404_status, _, html_doc = -1, {}, ''
            if self._404_status != 404:
                self.len_404_doc = len(html_doc)
        except Exception as e:
            self.print_msg('[Check_404] Exception %s %s' % (self.base_url, str(e)))

    #
    def enqueue(self, url):
        try:
            url = str(url)
        except Exception as e:
            return False
        try:
            url_pattern = re.sub(r'\d+', '{num}', url)
            if url_pattern in self.urls_processed or len(self.urls_processed) >= self.links_limit:
                return False

            self.urls_processed.add(url_pattern)
            # self.print_msg('Entered Queue: %s' % url)
            if not self.args.no_crawl:   # no crawl
                self.crawl(url)
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
                        self.url_queue.put(item)
                        self.urls_enqueued.add(full_url)

            if self.args.full_scan and url.count('/') >= 2:
                self.enqueue('/'.join(url.split('/')[:-2]) + '/')  # sub folder enqueue

            if url != '/'and not self.no_scripts:
                for script in self.user_scripts:
                    self.url_queue.put((script, url))
            return True
        except Exception as e:
            self.print_msg('[_enqueue.exception] %s' % str(e))
            return False

    #
    def crawl(self, path, do_not_process_links=False):
        try:
            # increase body size to 200 KB
            headers = dict(config.default_headers, Range='bytes=0-204800')
            status, headers, html_doc = self.http_request(path, headers=headers)
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
                        self.enqueue(url)
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
            self.print_msg('[crawl Exception] %s %s' % (path, str(e)))

    #
    def load_all_urls_from_log_file(self):
        try:
            with open(self.log_file) as infile:
                for _line in infile.xreadlines():
                    _ = _line.strip().split()
                    if len(_) == 3 and (_[2].find('^^^200') > 0 or _[2].find('^^^403') > 0 or _[2].find('^^^302') > 0):
                        url, depth = cal_depth(self, _[1])
                        self.enqueue(url)
        except Exception as e:
            self.print_msg('[load_all_urls_from_log_file] %s' % str(e))

    #
    def find_text(self, html_doc):
        for _text in self.text_to_find:
            if html_doc.find(_text) >= 0:
                return True, 'Found [%s]' % _text
        for _regex in self.regex_to_find:
            if _regex.search(html_doc):
                return True, 'Found Regex [%s]' % _regex.pattern
        return False

    #
    def find_exclude_text(self, html_doc):
        for _text in self.text_to_exclude:
            if html_doc.find(_text) >= 0:
                return True
        for _regex in self.regex_to_exclude:
            if _regex.search(html_doc):
                return True
        return False

    #
    def scan_worker(self):
        while True:
            if time.time() - self.start_time > self.time_out:
                self.url_queue.queue.clear()
                self.print_msg('[ERROR] Timed out task: %s' % self.base_url)
                return
            try:
                item = self.url_queue.get(timeout=0.1)
            except Exception as e:
                return
            try:
                if len(item) == 2:  # Script Scan
                    check_func = getattr(item[0], 'do_check')
                    # self.print_msg('Begin %s %s' % (os.path.basename(item[0].__file__), item[1]))
                    check_func(self, item[1])
                    # self.print_msg('End %s %s' % (os.path.basename(item[0].__file__), item[1]))
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
                self.print_msg('[scan_worker.1] %s' % str(e))
                self.print_msg(traceback.format_exc())
                continue
            if not item or not url:
                break

            try:
                status, headers, html_doc = self.http_request(url)
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
                    self.lock.acquire()
                    # self.print_msg('[+] [Prefix:%s] [%s] %s' % (prefix, status, 'http://' + self.host +  url))
                    if prefix not in self.results:
                        self.results[prefix] = []
                    _ = {'status': status, 'url': '%s%s' % (self.base_url, url), 'title': title, 'vul_type': vul_type}
                    if _ not in self.results[prefix]:
                        self.results[prefix].append(_)
                    self.lock.release()
            except Exception as e:
                self.print_msg('[scan_worker.2][%s] %s' % (url, str(e)))
                traceback.print_exc()

    #
    def scan(self, threads=6):
        try:
            all_threads = []
            for i in range(threads):
                t = threading.Thread(target=self.scan_worker)
                t.start()
                all_threads.append(t)
            for t in all_threads:
                t.join()

            for key in self.results.keys():
                # Over 5 URLs found under this folder, keep the first one only
                if len(self.results[key]) > 5:
                    self.results[key] = self.results[key][:1]
            return self.base_url.lstrip('unknown://').rstrip(':None'), self.results
        except Exception as e:
            self.print_msg('[scan exception] %s' % str(e))
        self.conn_pool.close()


def exit_func(_sig, _frame):
    exit(-1)


def scan_process(q_targets, q_results, args, target_process_done):
    reload(socket)
    signal.signal(signal.SIGINT, exit_func)
    s = Scanner(q_results, args.timeout * 60, args=args)
    while True:
        try:
            target = q_targets.get(timeout=0.2)
        except Exception as e:
            if target_process_done.value:
                break
            else:
                continue

        if 'target' in target:
            ret = s.init_from_url(target['target'])
        elif 'file' in target:
            ret = s.init_from_log_file(target['file'])
        else:
            continue

        if ret:
            host, results = s.scan(threads=args.t)
            if results:
                q_results.put((host, results))


def add_target(q_targets, q_results, target, tasks_count, args, is_neighbor=False):
    if is_neighbor:
        target['no_scripts'] = 2    # 邻居IP，不启用插件
    # if args.debug:
    #     q_results.put('New target: %s' % target)
    q_targets.put({'target': target})
    if args.save_ports and target['ports_open']:
        config.ports_saved_to_file = True
        if not args.ports_file:
            args.ports_file = open(args.save_ports, 'w')
        for port in target['ports_open']:
            args.ports_file.write('%s:%s\n' % (target['host'], port))
        args.ports_file.flush()
    tasks_count.value += 1


def domain_lookup_check(queue_targets_origin, processed_targets, queue_targets, q_results):
    """
    解析域名，检查域名有效性
    """
    while True:
        try:
            url = queue_targets_origin.get_nowait()
        except Queue.Empty as e:
            break
        # scheme netloc path
        if url.find('://') < 0:
            netloc = url[:url.find('/')] if url.find('/') > 0 else url
        else:
            scheme, netloc, path, params, query, fragment = urlparse.urlparse(url, 'http')

        # host port
        if netloc.find(':') >= 0:
            _ = netloc.split(':')
            host = _[0]
        else:
            host = netloc

        try:
            ip = g_socket.gethostbyname(host)
            processed_targets.append(ip)
            queue_targets.put((url, 0))
        except Exception as e:
            q_results.put('Invalid domain: %s' % host)


def port_scan_check(queue_targets, q_targets, args, q_results, tasks_count):
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
        except Queue.Empty as e:
            break
        try:
            # scheme netloc path
            if url.find('://') < 0:
                scheme = 'unknown'
                netloc = url[:url.find('/')] if url.find('/') > 0 else url
                path = ''
            else:
                scheme, netloc, path, params, query, fragment = urlparse.urlparse(url, 'http')

            # host port
            if netloc.find(':') >= 0:
                _ = netloc.split(':')
                host = _[0]
                port = int(_[1])
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

            # 插件不依赖HTTP连接池 & 仅启用插件扫描， 则不需要检查80/443端口的HTTP服务
            if args.scripts_only and args.require_no_http:
                ports_open, ports_closed = scan_given_ports(ports_open, ports_closed, host, args.require_ports)
                target = {'scheme': scheme, 'host': host, 'port': port, 'path': path,
                          'has_http': False, 'ports_open': ports_open, 'ports_closed': ports_closed}
                add_target(q_targets, q_results, target, tasks_count, args)
                continue

            if port:
                # 标准端口 或 非标准端口
                has_http = is_port_open(host, port)
                if has_http:
                    ports_open.add(port)
                else:
                    ports_closed.add(port)
                if not args.no_scripts:
                    ports_open, ports_closed = scan_given_ports(ports_open, ports_closed, host, args.require_ports)

                target = {'scheme': scheme, 'host': host, 'port': port, 'path': path, 'has_http': has_http,
                          'ports_open': ports_open, 'ports_closed': ports_closed}
                add_target(q_targets, q_results, target, tasks_count, args)

            else:
                port_open_80 = is_port_open(host, 80)
                port_open_443 = is_port_open(host, 443)
                if port_open_80:
                    ports_open.add(80)
                else:
                    ports_closed.add(80)
                if port_open_443:
                    ports_open.add(80)
                else:
                    ports_closed.add(80)
                if not args.no_scripts:
                    ports_open, ports_closed = scan_given_ports(ports_open, ports_closed, host, args.require_ports)

                if port_open_80 and port_open_443:
                    target = {'scheme': 'https', 'host': host, 'port': 443, 'path': path,
                              'has_http': True, 'ports_open': ports_open, 'ports_closed': ports_closed}
                    add_target(q_targets, q_results, target, tasks_count, args, is_neighbor)
                    # 排除 301 http 跳转 https
                    import grequests
                    r = grequests.map([grequests.get('http://%s' % host, allow_redirects=False, timeout=20)])[0]
                    if r and not (r.status_code == 301 and r.headers.get('Location', '').lower().startswith('https')):
                        target = {'scheme': 'http', 'host': host, 'port': 80, 'path': path,
                                  'has_http': True, 'no_scripts': 1,
                                  'ports_open': ports_open, 'ports_closed': ports_closed}
                        add_target(q_targets, q_results, target, tasks_count, args)

                elif port_open_443:
                    target = {'scheme': 'https', 'host': host, 'port': 443, 'path': path,
                              'has_http': True, 'ports_open': ports_open, 'ports_closed': ports_closed}
                    # 即使指定的一些目标，允许插件扫描，邻居也不启用，节省扫描时间
                    add_target(q_targets, q_results, target, tasks_count, args, is_neighbor)
                elif port_open_80:
                    target = {'scheme': 'http', 'host': host, 'port': 80, 'path': path,
                              'has_http': True, 'ports_open': ports_open, 'ports_closed': ports_closed}
                    add_target(q_targets, q_results, target, tasks_count, args, is_neighbor)
                elif args.no_scripts:
                    # 80 443 端口不开放， 禁用插件扫描
                    q_results.put('No ports open: %s' % host)
                elif not is_neighbor or args.scripts_only:
                    # 直接输入目标 或者 对邻居应用插件
                    target = {'scheme': 'http', 'host': host, 'port': 80, 'path': path,
                              'has_http': False, 'ports_open': ports_open, 'ports_closed': ports_closed}
                    add_target(q_targets, q_results, target, tasks_count, args)

        except requests.exceptions.RequestException as e:
            pass
        except Exception as e:
            import traceback
            q_results.put(traceback.format_exc())
            q_results.put('[port_scan_check] %s' % str(e))


def process_targets(q_targets, args, q_results, queue_targets, tasks_count):
    # 高并发地解析域名，扫描端口
    # 高并发执行短时任务
    # q_results.put('start %s' % time.time())
    threads = [gevent.spawn(port_scan_check, queue_targets, q_targets, args,
                            q_results, tasks_count) for _ in range(1000)]
    gevent.joinall(threads)
    # q_results.put('end %s' % time.time())


def prepare_targets(target_list, q_targets, q_results, args, tasks_count, process_targets_done):
    """
    预处理 URL / IP / 域名，端口发现
    """
    from gevent.queue import Queue
    queue_targets_origin = Queue()
    for target in target_list:
        if target.strip() and len(target) > 5:
            # work with https://github.com/lijiejie/subDomainsBrute
            # Delimiter should be ","
            hosts = target.replace(',', ' ').strip().split()
            queue_targets_origin.put(hosts[0])

    processed_targets = []
    # 将域名解析和端口扫描拆分，可节省约2s
    # 更简单的做法, 可以将DNS解析和端口扫描合并为一个函数，但那样会损失 2s
    q_results.put('Domain lookup start.')
    queue_targets = Queue()
    threads = [gevent.spawn(domain_lookup_check,
                            queue_targets_origin, processed_targets, queue_targets, q_results) for _ in range(500)]
    gevent.joinall(threads)

    if args.network != 32:
        q_results.put('Process sub network start.')
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
                        queue_targets.put((_ip, 1))
                        num_entered_queue += 1
                if num_entered_queue > 65535:    # 队列不宜太长，如果超过一个B段，分多次处理
                    process_targets(q_targets, args, q_results, queue_targets, tasks_count)
                    num_entered_queue = 0
    if queue_targets.qsize() > 0:    # 还有剩余未处理目标
        process_targets(q_targets, args, q_results, queue_targets, tasks_count)
    if args.save_ports and args.ports_file:
        args.ports_file.close()
    process_targets_done.value = 1    # 目标导入完成
    q_results.put('* Targets process all done.')


if __name__ == '__main__':
    args = parse_args()
    print('* BBScan v1.5  https://github.com/lijiejie/BBScan *')
    if args.no_scripts:
        print('* Scripts scan was disabled.')
    if args.require_ports:
        print('* Scripts scan port check: %s' % ','.join([str(x) for x in args.require_ports]))

    q_targets = multiprocessing.Manager().Queue()    # targets Queue
    q_results = multiprocessing.Manager().Queue()    # results Queue
    # is process targets done
    # 目标处理完成，扫描进程才可以开始退出
    process_targets_done = multiprocessing.Value('i', 0)
    tasks_count = multiprocessing.Value('i', 0)    # 任务计数器

    for input_file in args.input_files:
        if args.host:
            target_list = args.host
            # 命令行传入少量Target，至多创建2倍扫描进程
            if args.network == 32 and len(target_list) * 2 < args.p:
                args.p = len(target_list) * 2
        elif args.f or args.d:
            with open(input_file) as inFile:
                target_list = inFile.readlines()
                # 文件读入少量目标，至多创建2倍扫描进程
                if args.network == 32 and len(target_list) * 2 < args.p:
                    args.p = len(target_list) * 2
        try:
            # 生成报告，管理标准输出
            threading.Thread(target=save_report, args=(args, q_results, input_file, tasks_count)).start()

            clear_queue(q_results)
            clear_queue(q_targets)
            process_targets_done.value = 0
            start_time = time.time()

            if args.crawler:
                _input_files = glob.glob(args.crawler + '/*.log')
                for _file in _input_files:
                    q_targets.put({'file': _file})
                    tasks_count.vaule += 1
                if tasks_count.value < args.p:
                    args.p = tasks_count.value    # 仅导入少量网站
                process_targets_done.value = 1
            else:
                # 在独立的进程中，安全地使用 gevent
                tasks_count.value = 0
                p = multiprocessing.Process(
                    target=prepare_targets,
                    args=(target_list, q_targets, q_results, args, tasks_count, process_targets_done))
                p.daemon = True
                p.start()
                time.sleep(1.0)  # 让prepare_targets进程尽快开始执行

            all_process = []
            for _ in range(args.p):
                p = multiprocessing.Process(
                    target=scan_process,
                    args=(q_targets, q_results, args, process_targets_done))
                p.daemon = True
                p.start()
                all_process.append(p)
            q_results.put('%s scan process created.' % args.p)

            while True:
                for p in all_process[:]:
                    if not p.is_alive():
                        all_process.remove(p)
                if not all_process:
                    break
                time.sleep(0.5)

            cost_time = time.time() - start_time
            cost_min = int(cost_time / 60)
            cost_min = '%s min ' % cost_min if cost_min > 0 else ''
            cost_seconds = '%.1f' % (cost_time % 60)
            q_results.put('Scanned %s targets in %s%s seconds.' % (tasks_count.value, cost_min, cost_seconds))
        except KeyboardInterrupt as e:
            config.stop_me = True
            q_results.put('Scan aborted.')
            exit(-1)
        except Exception as e:
            q_results.put('[__main__.exception] %s %s' % (type(e), str(e)))
        config.stop_me = True
