#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# A vulnerability scanner focus on scanning large number of targets in short time with a minimal set of rules.
# LiJieJie    my[at]lijiejie.com    http://www.lijiejie.com

import Queue
import logging
import re
import threading
from bs4 import BeautifulSoup
import multiprocessing
import time
from string import Template
import glob
import ipaddress
import os
import webbrowser
import socket
import sys
import ssl
import codecs
import traceback
import struct
import importlib
import signal
from lib.common import parse_url, decode_response_text, cal_depth, get_domain_sub, escape
from lib.cmdline import parse_args
from lib.report import template
from lib.connectionPool import HTTPConnPool, HTTPSConnPool

if hasattr(ssl, '_create_unverified_context'):
    ssl._create_default_https_context = ssl._create_unverified_context

socket.setdefaulttimeout(30)

USER_AGENT = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36 BBScan/1.4'
HEADERS = {'User-Agent': USER_AGENT, 'Connection': 'Keep-Alive', 'Range': 'bytes=0-102400'}


# print msg with multi-process shared lock
def print_msg(msg):
    global_lock.acquire()
    print '[%s] %s' % (time.strftime('%H:%M:%S', time.localtime()), msg)
    global_lock.release()


class Scanner(object):
    def __init__(self, timeout=600, args=None):
        self.args = args
        self.start_time = time.time()
        self.time_out = timeout
        self.links_limit = 100  # max number of folders to scan

        self._init_rules()
        self._init_scripts()

        self.url_queue = Queue.Queue()  # all urls to scan
        self.urls_processed = set()  # processed urls
        self.urls_enqueued = set()  # entered queue urls
        self.urls_crawled = set()

        self.lock = threading.Lock()
        self.results = {}
        self.log_file = None
        self._404_status = -1
        self.conn_pool = None
        self.index_status, self.index_headers, self.index_html_doc = None, {}, ''
        self.url = ''
        self.schema, self.host, self.port, self.path = None, None, None, None
        self.domain_sub = self.base_url = ''
        self.has_status_404 = True
        self.max_depth = 0
        self.len_404_doc = 0

    # reset scanner
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

    # scan from a given URL
    def init_from_url(self, url):
        self.reset_scanner()
        self.url = 'http://' + url if url.find('://') < 0 else url
        self.schema, self.host, self.path = parse_url(url)
        self.domain_sub = get_domain_sub(self.host)
        self.init_final()

    def init_from_log_file(self, log_file):
        self.reset_scanner()
        self.log_file = log_file
        self.schema, self.host, self.path = self._parse_url_from_file()
        self.domain_sub = get_domain_sub(self.host)
        if self.host:
            self.load_all_urls_from_log_file()
            self.init_final()
            return True
        else:
            host = os.path.basename(log_file).replace('.log', '')
            try:
                socket.gethostbyname(host)
                self.init_from_url(host)
                return True
            except Exception as e:
                print_msg('[ERROR] Invalid host from log name: %s' % host)
                return False

    #
    def init_final(self):
        try:
            if self.conn_pool:
                self.conn_pool.close()
        except Exception as e:
            pass
        default_port = 443 if self.schema.lower() == 'https' else 80
        self.host, self.port = self.host.split(':') if self.host.find(':') > 0 else (self.host, default_port)
        self.port = int(self.port)
        if self.schema == 'http' and self.port == 80 or self.schema == 'https' and self.port == 443:
            self.base_url = '%s://%s' % (self.schema, self.host)
        else:
            self.base_url = '%s://%s:%s' % (self.schema, self.host, self.port)

        is_port_open = self.is_port_open()
        if is_port_open:
            if self.schema == 'https':
                self.conn_pool = HTTPSConnPool(self.host, port=self.port, maxsize=self.args.t * 2, headers=HEADERS)
            else:
                self.conn_pool = HTTPConnPool(self.host, port=self.port, maxsize=self.args.t * 2, headers=HEADERS)

        if self.args.scripts_only or (not is_port_open and not self.args.no_scripts):
            for _ in self.user_scripts:
                self.url_queue.put((_, '/'))
            print_msg('Scan with scripts: %s' % self.host)
            return

        if not is_port_open:
            return

        self.max_depth = cal_depth(self, self.path)[1] + 5
        if self.args.no_check404:
            self._404_status = 404
            self.has_status_404 = True
        else:
            self.check_404_existence()
        if self._404_status == -1:
            print_msg('[Warning] HTTP 404 check failed <%s:%s>' % (self.host, self.port))
        elif not self.has_status_404:
            print_msg('[Warning] %s has no HTTP 404.' % self.base_url)
        _path, _depth = cal_depth(self, self.path)
        self.enqueue('/')
        self.enqueue(_path)
        if not self.args.no_crawl and not self.log_file:
            self.crawl(_path)

    def is_port_open(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5.0)
            if s.connect_ex((self.host, int(self.port))) == 0:
                print_msg('scan web: %s:%s' % (self.host, self.port))
                return True
            else:
                print_msg('[Warning] Fail to connect to %s' % self.base_url)
                return False
        except Exception as e:
            return False
        finally:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
            s.close()

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

    #
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

        for rule_file in glob.glob('rules/*.txt'):
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
                                print_msg('Duplicated root only rule: %s' % str(rule))
                        else:
                            if rule not in self.rules_set:
                                self.rules_set.add(rule)
                            else:
                                print_msg('Duplicated rule: %s' % str(rule))

        re_text = re.compile('{text="(.*)"}')
        re_regex_text = re.compile('{regex_text="(.*)"}')

        file_path = 'rules/white.list'
        if not os.path.exists(file_path):
            print_msg('[ERROR] File not exist: %s' % file_path)
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
            print_msg('[ERROR] File not exist: %s' % file_path)
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

    #
    def _init_scripts(self):
        self.user_scripts = []
        if self.args.no_scripts:  # disable user scripts scan
            return
        for _script in glob.glob('scripts/*.py'):
            script_name = os.path.basename(_script).replace('.py', '')
            if script_name.startswith('_'):
                continue
            try:
                self.user_scripts.append(importlib.import_module('scripts.%s' % script_name))
            except Exception as e:
                print_msg('[ERROR] Fail to load script %s' % script_name)

    #
    def http_request(self, url, headers=HEADERS, timeout=30):
        try:
            if not url:
                url = '/'
            # print_msg('request %s' % self.base_url + url)
            resp = self.conn_pool.urlopen('GET', self.base_url + url,
                                          headers=headers, redirect=False, timeout=timeout, retries=0)
            status = resp.status
            if resp.headers.get('content-type', '').find('text') >= 0 \
                    or resp.headers.get('content-type', '').find('html') >= 0 \
                    or int(resp.headers.get('content-length', '0')) <= 20480:  # 1024 * 20
                html_doc = decode_response_text(resp.data)
            else:
                html_doc = ''

            return status, resp.headers, html_doc
        except Exception as e:
            return -1, {}, ''

    # check existence of HTTP 404
    def check_404_existence(self):
        try:
            try:
                self._404_status, _, html_doc = self.http_request('/BBScan-404-existence-check')
            except Exception as e:
                print_msg('[Warning] HTTP 404 check failed <%s:%s>' % (self.host, self.port))
                self._404_status, _, html_doc = -1, {}, ''
            if self._404_status == 404:
                self.has_status_404 = True
            else:
                self.has_status_404 = False
                self.len_404_doc = len(html_doc)
        except Exception as e:
            logging.error('[Check_404] Exception %s %s' % (self.base_url, str(e)))

    #
    def enqueue(self, url):
        try:
            url = str(url)
            url_pattern = re.sub(r'\d+', '{num}', url)
            if url_pattern in self.urls_processed or len(self.urls_processed) >= self.links_limit:
                return False
            else:
                self.urls_processed.add(url_pattern)
            # print_msg('Entered Queue: %s' % url)
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

            for script in self.user_scripts:
                self.url_queue.put((script, url))
            return True
        except Exception as e:
            print '[_enqueue.exception] %s' % str(e)
            return False

    #
    def crawl(self, path):
        try:
            headers = dict(HEADERS, Range='bytes=0-204800')    # allowed size increased to 200 kb
            status, headers, html_doc = self.http_request(path, headers=headers)
            if path == '/':
                self.index_status, self.index_headers, self.index_html_doc = status, headers, html_doc
            if self.index_html_doc:
                soup = BeautifulSoup(html_doc, "html.parser")
                for link in soup.find_all('a'):
                    url = link.get('href', '').strip()
                    if url.startswith('..'):
                        continue
                    if not url.startswith('/') and url.find('//') < 0:
                        url = path + url
                    url, depth = cal_depth(self, url)
                    # print url, depth
                    if depth <= self.max_depth:
                        self.enqueue(url)
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
            print_msg('[crawl Exception] %s %s' % (path, str(e)))
            traceback.print_exc()

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
            print_msg('[load_all_urls_from_log_file] %s' % str(e))

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
        while self.url_queue.qsize() > 0:
            if time.time() - self.start_time > self.time_out:
                self.url_queue.queue.clear()
                print_msg('[ERROR] Timed out task: %s' % self.base_url)
                return
            try:
                item = self.url_queue.get(timeout=0.1)
            except Exception as e:
                return
            try:
                if len(item) == 2:  # Script Scan
                    check_func = getattr(item[0], 'do_check')
                    # print_msg('Begin %s %s' % (os.path.basename(item[0].__file__), item[1]))
                    check_func(self, item[1])
                    # print_msg('End %s %s' % (os.path.basename(item[0].__file__), item[1]))
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
                print_msg('[scan_worker.1] %s' % str(e))
                traceback.print_exc()
                continue
            if not item or not url:
                break

            # print_msg('[%s]' % url.strip())
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
                    # print '[+] [Prefix:%s] [%s] %s' % (prefix, status, 'http://' + self.host +  url)
                    if prefix not in self.results:
                        self.results[prefix] = []
                    _ = {'status': status, 'url': '%s%s' % (self.base_url, url), 'title': title, 'vul_type': vul_type}
                    if _ not in self.results[prefix]:
                        self.results[prefix].append(_)
                    self.lock.release()
            except Exception as e:
                print_msg('[scan_worker.2][%s] %s' % (url, str(e)))
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
                if len(self.results[key]) > 5:  # Over 5 URLs found under this folder, show first only
                    self.results[key] = self.results[key][:1]
            return self.host, self.results
        except Exception as e:
            print '[scan exception] %s' % str(e)
        self.conn_pool.close()


def exit_func(sig, frame):
    exit(-1)


def scan_process(q_targets, q_results, lock, args, target_process_done):
    signal.signal(signal.SIGINT, exit_func)
    try:
        __builtins__['global_lock'] = lock
    except Exception as e:
        pass
    try:
        setattr(__builtins__, 'global_lock', lock)
    except Exception as e:
        pass

    s = Scanner(args.timeout * 60, args=args)
    while True:
        try:
            target = q_targets.get(timeout=0.5)
        except Exception as e:
            if target_process_done.value:
                break
            else:
                continue

        if target['url']:
            s.init_from_url(target['url'])
        else:
            s.init_from_log_file(target['file'])

        host, results = s.scan(threads=args.t)
        if results:
            q_results.put((host, results))
            lock.acquire()
            for key in results.keys():
                for url in results[key]:
                    print '  [+]%s %s' % (' [%s]' % url['status'] if url['status'] else '', url['url'])
            lock.release()


def save_report(_q_results, _file):
    start_time = time.time()

    a_template = template['markdown'] if args.md else template['html']
    t_general = Template(a_template['general'])
    t_host = Template(a_template['host'])
    t_list_item = Template(a_template['list_item'])
    output_file_suffix = a_template['suffix']
    report_name = '%s_%s%s' % (os.path.basename(_file).lower().replace('.txt', ''),
                               time.strftime('%Y%m%d_%H%M%S', time.localtime()),
                               output_file_suffix)

    html_doc = content = ""
    global STOP_ME
    try:
        while not STOP_ME:
            if _q_results.qsize() == 0:
                time.sleep(0.5)
                continue

            while _q_results.qsize() > 0:
                host, results = _q_results.get()
                _str = ""
                for key in results.keys():
                    for _ in results[key]:
                        _str += t_list_item.substitute(
                            {'status': ' [%s]' % _['status'] if _['status'] else '',
                             'url': _['url'],
                             'title': '[%s]' % _['title'] if _['title'] else '',
                             'vul_type': escape(_['vul_type'].replace('_', ' ')) if 'vul_type' in _ else ''}
                        )
                _str = t_host.substitute({'host': host, 'list': _str})
                content += _str

            cost_time = time.time() - start_time
            cost_min = int(cost_time / 60)
            cost_min = '%s min' % cost_min if cost_min > 0 else ''
            cost_seconds = '%.2f' % (cost_time % 60)
            html_doc = t_general.substitute(
                {'cost_min': cost_min, 'cost_seconds': cost_seconds, 'content': content}
            )

            with codecs.open('report/%s' % report_name, 'w', encoding='utf-8') as outFile:
                outFile.write(html_doc)

        if html_doc:
            print_msg('Scan report saved to report/%s' % report_name)
            if not args.no_browser:
                webbrowser.open_new_tab(os.path.abspath('report/%s' % report_name))
        else:
            print_msg('No vulnerabilities found on sites in %s.' % _file)

    except Exception as e:
        print_msg('[save_report_thread Exception] %s %s' % (type(e), str(e)))
        sys.exit(-1)


def domain_lookup():
    while True:
        try:
            host = queue_hosts.get(timeout=0.1)
        except Queue.Empty as e:
            break
        _schema, _host, _path = parse_url(host)
        try:
            m = re.search(r'\d+\.\d+\.\d+\.\d+', _host.split(':')[0])
            if m:
                q_targets.put({'file': '', 'url': host})
                ips_to_scan.append(m.group(0))
            else:
                ip = socket.gethostbyname(_host.split(':')[0])
                q_targets.put({'file': '', 'url': host})
                ips_to_scan.append(ip)
        except Exception as e:
            print e
            print_msg('[Warning] Invalid domain <%s>' % _host.split(':')[0])


def process_target():
    global target_process_done
    all_threads = []
    for _ in range(10):
        t = threading.Thread(target=domain_lookup)
        all_threads.append(t)
        t.start()
    for t in all_threads:
        t.join()
    if args.network != 32:
        for ip in ips_to_scan:
            if ip.find('/') > 0:
                continue
            _network = u'%s/%s' % ('.'.join(ip.split('.')[:3]), args.network)
            if _network in ips_to_scan:
                continue
            ips_to_scan.append(_network)
            _ips = ipaddress.IPv4Network(u'%s/%s' % (ip, args.network), strict=False).hosts()
            for _ip in _ips:
                _ip = str(_ip)
                if _ip not in ips_to_scan:
                    ips_to_scan.append(_ip)
                    q_targets.put({'file': '', 'url': _ip})
    target_process_done.value = 1
    print_msg('%s targets left to scan' % q_targets.qsize())


if __name__ == '__main__':
    args = parse_args()
    if args.f:
        input_files = [args.f]
    elif args.d:
        input_files = glob.glob(args.d + '/*.txt')
    elif args.crawler:
        input_files = ['crawler']
    elif args.host:
        input_files = ['hosts']  # several hosts from command line

    ips_to_scan = []  # all IPs to scan during current scan

    global_lock = multiprocessing.Manager().Lock()
    print_msg('BBScan v1.4')
    q_results = multiprocessing.Manager().Queue()
    q_targets = multiprocessing.Manager().Queue()
    target_process_done = multiprocessing.Value('i', 0)

    for input_file in input_files:
        if args.host:
            lines = args.host
        elif args.f or args.d:
            with open(input_file) as inFile:
                lines = inFile.readlines()

        try:
            print_msg('Init %s scan process, please wait' % args.p)
            STOP_ME = False
            while q_results.qsize() > 0:
                q_results.get()
            while q_targets.qsize() > 0:
                q_targets.get()
            target_process_done.value = 0
            threading.Thread(target=save_report, args=(q_results, input_file)).start()

            if args.crawler:
                _input_files = glob.glob(args.crawler + '/*.log')
                for _file in _input_files:
                    q_targets.put({'file': _file, 'url': ''})
            else:
                queue_hosts = Queue.Queue()
                for line in lines:
                    if line.strip():
                        # Work with https://github.com/lijiejie/subDomainsBrute
                        # Delimiter "," accepted
                        hosts = line.replace(',', ' ').strip().split()
                        queue_hosts.put(hosts[0])

            threading.Thread(target=process_target).start()

            all_process = []
            for _ in range(args.p):
                p = multiprocessing.Process(
                    target=scan_process, args=(q_targets, q_results, global_lock, args, target_process_done))
                p.daemon = True
                p.start()
                all_process.append(p)
            while True:
                for p in all_process[:]:
                    if not p.is_alive():
                        all_process.remove(p)
                if not all_process:
                    break
                time.sleep(0.1)
        except KeyboardInterrupt as e:
            STOP_ME = True
            print_msg('You aborted the scan.')
            exit(1)
        except Exception as e:
            print_msg('[__main__.exception] %s %s' % (type(e), str(e)))
        STOP_ME = True
