#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# A tiny Batch weB vulnerability Scanner
# my[at]lijiejie.com    http://www.lijiejie.com


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
from dns.resolver import Resolver
from lib.common import print_msg, parse_url, decode_response_text, cal_depth, get_domain_sub
from lib.cmdline import parse_args
from lib.report import template
from lib.connectionPool import HTTPConnPool, HTTPSConnPool


if hasattr(ssl, '_create_unverified_context'):
    ssl._create_default_https_context = ssl._create_unverified_context


socket.setdefaulttimeout(30)


USER_AGENT = 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 ' \
             '(KHTML, like Gecko) Chrome/38.0.2125.111 Safari/537.36 BBScan/1.3'

headers = {'User-Agent': USER_AGENT, 'Connection': 'Keep-Alive','Range': 'bytes=0-10240'}
headers_without_range = {'User-Agent': USER_AGENT, 'Connection': 'Keep-Alive'}


class InfoDisScanner(object):
    def __init__(self, timeout=600, args=None):
        self.args = args
        self.START_TIME = time.time()
        self.TIME_OUT = timeout
        self.LINKS_LIMIT = 100  # max number of Folders to scan

        self.full_scan = args.full_scan
        self._init_rules()
        self._init_scripts()

        self.url_queue = Queue.Queue()  # all urls to scan
        self.urls_processed = set()  # processed urls
        self.urls_enqueued = set()  # entered queue urls

        self.lock = threading.Lock()


    # reset scanner
    def init_reset(self):
        self.START_TIME = time.time()
        self.url_queue.queue.clear()
        self.urls_processed = set()
        self.urls_enqueued = set()
        self.results = {}
        self.log_file = None
        self._404_status = -1
        self.conn_pool = None
        self.index_status, self.index_headers, self.index_html_doc = None, {} , ''

    # scan from a given URL
    def init_from_url(self, url):
        self.init_reset()
        if not url.find('://') > 0:
            self.url = 'http://' + url
        else:
            self.url = url
        self.schema, self.host, self.path = parse_url(url)
        self.domain_sub = get_domain_sub(self.host)
        self.init_final()

    def init_from_log_file(self, log_file):
        self.init_reset()
        self.log_file = log_file
        self.schema, self.host, self.path = self._parse_url_from_file()
        self.domain_sub = get_domain_sub(self.host)
        if self.host:
            self.load_all_urls_from_log_file()
            self.init_final()
        else:
            self.init_from_url(os.path.basename(log_file).replace('.log', ''))

    #
    def init_final(self):
        try:
            self.conn_pool.close()
        except:
            pass
        default_port = 443 if self.schema.lower() == 'https' else 80
        self.host, self.port = self.host.split(':') if self.host.find(':') > 0 else (self.host, default_port)
        self.port = int(self.port)
        if self.schema == 'http' and self.port == 80 or self.schema == 'https' and self.port == 443:
            self.base_url = '%s://%s' % (self.schema, self.host)
        else:
            self.base_url = '%s://%s:%s' % (self.schema, self.host, self.port)

        is_port_open = self.is_port_open()
        if  is_port_open:
            if self.schema == 'https':
                self.conn_pool = HTTPSConnPool(self.host, port=self.port, maxsize=self.args.t * 2, headers=headers)
            else:
                self.conn_pool = HTTPConnPool(self.host, port=self.port, maxsize=self.args.t * 2, headers=headers)

        if self.args.scripts_only or not is_port_open and (not self.args.no_scripts):
            for _ in self.user_scripts:
                self.url_queue.put((_, '/'))
            self.lock.acquire()
            print_msg('Scan with user scripts: %s' % self.host)
            self.lock.release()
            return

        if not is_port_open:
            return

        self.max_depth = cal_depth(self, self.path)[1] + 5
        if self.args.no_check404:
            self._404_status = 404
            self.has_404 = True
        else:
            self.check_404()    # check existence of HTTP 404
        if not self.has_404:
            print_msg('[Warning] %s has no HTTP 404.' % self.host)
        _path, _depth = cal_depth(self, self.path)
        self._enqueue('/')
        self._enqueue(_path)
        if not self.args.no_crawl and not self.log_file:
            self.crawl_index(_path)

    def is_port_open(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5.0)
            if s.connect_ex((self.host, int(self.port))) == 0:
                self.lock.acquire()
                print_msg('Scan web: %s' % self.base_url)
                self.lock.release()
                return True
            else:
                print_msg('[Warning] Fail to connect to %s:%s' % (self.host, self.port))
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
            for line in infile.xreadlines():
                line = line.strip()
                if line and len(line.split()) >= 3:
                    url = line.split()[1]
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

        p_tag = re.compile('{tag="(.*?)"}')
        p_status = re.compile('{status=(\d{3})}')
        p_content_type = re.compile('{type="(.*?)"}')
        p_content_type_no = re.compile('{type_no="(.*?)"}')

        for rule_file in glob.glob('rules/*.txt'):
            with open(rule_file, 'r') as infile:
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

                        rule = (url.split()[0], tag, status, content_type, content_type_no, root_only)
                        if rule not in self.rules_set:
                            self.rules_set.add(rule)
                        else:
                            print 'Dumplicated Rule:', rule

        re_text = re.compile('{text="(.*)"}')
        re_regex_text = re.compile('{regex_text="(.*)"}')

        _file_path = 'rules/white.list'
        if not os.path.exists(_file_path):
            return
        for line in open(_file_path):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            _m = re_text.search(line)
            if _m:
                self.text_to_find.append(
                    _m.group(1).decode('utf-8', 'ignore')
                )
            else:
                _m = re_regex_text.search(line)
                if _m:
                    self.regex_to_find.append(
                        re.compile(_m.group(1).decode('utf-8', 'ignore'))
                    )

        _file_path = 'rules/black.list'
        if not os.path.exists(_file_path):
            return
        for line in open(_file_path):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            _m = re_text.search(line)
            if _m:
                self.text_to_exclude.append(
                    _m.group(1).decode('utf-8', 'ignore')
                )
            else:
                _m = re_regex_text.search(line)
                if _m:
                    self.regex_to_exclude.append(
                        re.compile(_m.group(1).decode('utf-8', 'ignore'))
                    )

    #
    def _init_scripts(self):
        self.user_scripts = []
        if self.args.no_scripts:    # disable user scripts scan
            return
        for _script in glob.glob('scripts/*.py'):
            script_name =  os.path.basename(_script).replace('.py', '')
            if script_name.startswith('_'):
                continue
            try:
                _ = importlib.import_module('scripts.%s' % script_name)
                self.user_scripts.append(_)
            except Exception as e:
                pass

    #
    def _http_request(self, url, timeout=30):
        try:
            if not url:
                url = '/'
            # print 'request', self.base_url + url
            resp = self.conn_pool.urlopen('GET', self.base_url + url, redirect=False, timeout=timeout, retries=0)
            resp_headers = resp.headers
            status = resp.status
            if resp_headers.get('content-type', '').find('text') >= 0 \
                    or resp_headers.get('content-type', '').find('html') >= 0 \
                    or int(resp_headers.get('content-length', '0')) <= 20480:  # 1024 * 20
                html_doc = decode_response_text(resp.data)
            else:
                html_doc = ''

            return status, resp_headers, html_doc
        except Exception as e:
            return -1, {}, ''

    #
    def check_404(self):
        try:
            try:
                self._404_status, headers, html_doc = self._http_request('/BBScan-404-existence-check')
            except:
                self._404_status, headers, html_doc = -1, {}, ''

            self.has_404 = (self._404_status == 404)
            if not self.has_404:
                self.len_404_doc = len(html_doc)
            return self.has_404
        except Exception as e:
            logging.error('[Check_404] Exception %s' % str(e))

    #
    def _enqueue(self, url):
        try:
            url = str(url)
            url_pattern = re.sub('\d+', '{num}', url)
            if url_pattern in self.urls_processed or len(self.urls_processed) >= self.LINKS_LIMIT:
                return False
            else:
                self.urls_processed.add(url_pattern)
            # print 'Entered Queue:', url
            for _ in self.rules_set:
                if _[5] and url != '/':
                    continue
                try:
                    full_url = url.rstrip('/') + _[0]
                except:
                    continue
                if full_url in self.urls_enqueued:
                    continue
                url_description = {'prefix': url.rstrip('/'), 'full_url': full_url}
                item = (url_description, _[1], _[2], _[3], _[4], _[5])
                self.url_queue.put(item)
                self.urls_enqueued.add(full_url)

            if self.full_scan and url.count('/') >= 2:
                self._enqueue('/'.join(url.split('/')[:-2]) + '/')  # sub folder enqueue

            for _ in self.user_scripts:
                self.url_queue.put((_, url))
            return True
        except Exception as e:
            print '[_enqueue.exception] %s' % str(e)
            return False

    #
    def crawl_index(self, path):
        try:
            status, headers, html_doc = self._http_request(path)
            if status != 200:
                try:
                    html_doc = self.conn_pool.urlopen('GET', self.url, headers=headers_without_range, retries=1).data
                    html_doc = decode_response_text(html_doc)
                except Exception as e:
                    pass
            self.index_status, self.index_headers, self.index_html_doc = status, headers, html_doc    # save index content
            soup = BeautifulSoup(html_doc, "html.parser")
            for link in soup.find_all('a'):
                url = link.get('href', '').strip()
                url, depth = cal_depth(self, url)
                if depth <= self.max_depth:
                    self._enqueue(url)
            if self.find_text(html_doc):
                self.results['/'] = []
                m = re.search('<title>(.*?)</title>', html_doc)
                title = m.group(1) if m else ''
                _ = {'status': status, 'url': '%s%s' % (self.base_url, path), 'title': title}
                if _ not in self.results['/']:
                    self.results['/'].append(_)

        except Exception as e:
            logging.error('[crawl_index Exception] %s' % str(e))
            traceback.print_exc()

    #
    def load_all_urls_from_log_file(self):
        try:
            with open(self.log_file) as inFile:
                for line in inFile.xreadlines():
                    _ = line.strip().split()
                    if len(_) == 3 and (_[2].find('^^^200') > 0 or _[2].find('^^^403') > 0 or _[2].find('^^^302') > 0):
                        url, depth = cal_depth(self, _[1])
                        self._enqueue(url)
        except Exception as e:
            logging.error('[load_all_urls_from_log_file Exception] %s' % str(e))
            traceback.print_exc()

    #
    def find_text(self, html_doc):
        for _text in self.text_to_find:
            if html_doc.find(_text) > 0:
                return True
        for _regex in self.regex_to_find:
            if _regex.search(html_doc) > 0:
                return True
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
    def _scan_worker(self):
        while self.url_queue.qsize() > 0:
            if time.time() - self.START_TIME > self.TIME_OUT:
                self.url_queue.queue.clear()
                print_msg('[ERROR] Timed out task: %s' % self.host)
                return
            try:
                item = self.url_queue.get(timeout=0.1)
            except:
                return
            try:
                if len(item) == 2:    # User Script
                    check_func = getattr(item[0], 'do_check')
                    check_func(self, item[1])
                    continue
                else:
                    url_description, tag, status_to_match, content_type, content_type_no, root_only = item
                    prefix = url_description['prefix']
                    url = url_description['full_url']
                    # print url
                    url = url.replace('{sub}', self.domain_sub)
                    if url.find('{hostname_or_folder}') >= 0:
                        _url = url[: url.find('{hostname_or_folder}')]
                        folders = _url.split('/')
                        for _folder in reversed(folders):
                            if _folder not in ['', '.', '..']:
                                url = url.replace('{hostname_or_folder}', _folder)
                                break
                    url = url.replace('{hostname_or_folder}', self.domain_sub)
                    url = url.replace('{hostname}', self.domain_sub)

            except Exception as e:
                logging.error('[_scan_worker Exception] [1] %s' % str(e))
                traceback.print_exc()
                continue
            if not item or not url:
                break

            # print '[%s]' % url.strip()
            try:
                status, headers, html_doc = self._http_request(url)
                cur_content_type = headers.get('content-type', '')

                if self.find_exclude_text(html_doc):  # excluded text found
                    continue

                if ('html' in cur_content_type or 'text' in cur_content_type) and \
                                        0 <= len(html_doc) <= 10:  # text too short
                    continue

                if cur_content_type.find('image/') >= 0:  # exclude image
                    continue

                valid_item = False
                if self.find_text(html_doc):
                    valid_item = True
                else:
                    if cur_content_type.find('application/json') >= 0 and not url.endswith('.json'):  # no json
                        continue

                    if status != status_to_match and status != 206: # status in [301, 302, 400, 404, 501, 502, 503, 505]
                        continue

                    if tag:
                        if html_doc.find(tag) >= 0:
                            valid_item = True
                        else:
                            continue  # tag mismatch

                    if content_type and cur_content_type.find(content_type) < 0 \
                            or content_type_no and cur_content_type.find(content_type_no) >= 0:
                        continue  # type mismatch

                    if self.has_404 or status != self._404_status:
                        if status_to_match in (200, 206) and status == 206:
                            valid_item = True
                        elif status_to_match and status != status_to_match:  # status mismatch
                            continue
                        elif status_to_match != 403 and status == 403:
                            continue
                        else:
                            valid_item = True

                    if not self.has_404 and status in (200, 206) and url != '/' and not tag:
                        _len = len(html_doc)
                        _min = min(_len, self.len_404_doc)
                        if _min == 0:
                            _min = 10.0
                        if float(_len - self.len_404_doc) / _min > 0.3:
                            valid_item = True

                    if status == 206 and tag == '' and cur_content_type.find('text') < 0 and cur_content_type.find('html') < 0:
                        valid_item = True

                if valid_item:
                    m = re.search('<title>(.*?)</title>', html_doc)
                    title = m.group(1) if m else ''
                    self.lock.acquire()
                    # print '[+] [Prefix:%s] [%s] %s' % (prefix, status, 'http://' + self.host +  url)
                    if prefix not in self.results:
                        self.results[prefix] = []

                    _ = {'status': status, 'url': '%s%s' % (self.base_url, url), 'title': title}
                    if _ not in self.results[prefix]:
                        self.results[prefix].append(_)
                    self.lock.release()

                if len(self.results) >= 10:
                    print '[Warning] Over 10 vulnerabilities found [%s], seems to be false positives.' % prefix
                    self.url_queue.queue.clear()
            except Exception as e:
                logging.error('[_scan_worker.Exception][2][%s] %s' % (url, str(e)))
                traceback.print_exc()

    #
    def scan(self, threads=6):
        try:
            all_threads = []
            for i in range(threads):
                t = threading.Thread(target=self._scan_worker)
                t.start()
                all_threads.append(t)
            for t in all_threads:
                t.join()

            for key in self.results.keys():
                if len(self.results[key]) > 5:  # Over 5 URLs found under this folder, show first only
                    self.results[key] = self.results[key][:1]
            return '%s:%s' % (self.host, self.port), self.results
        except Exception as e:
            print '[scan exception] %s' % str(e)
        self.conn_pool.close()


def batch_scan(q_targets, q_results, lock, args):
    s = InfoDisScanner(args.timeout * 60, args=args)
    while True:
        try:
            target = q_targets.get(timeout=1.0)
        except:
            break
        _url = target['url']
        _file = target['file']

        if _url:
            s.init_from_url(_url)
        else:
            s.init_from_log_file(_file)


        host, results = s.scan(threads=args.t)
        if results:
            q_results.put((host, results))
            lock.acquire()
            for key in results.keys():
                for url in results[key]:
                    print '[+] [%s] %s' % (url['status'], url['url'])
            lock.release()


def save_report_thread(q_results, file):
    start_time = time.time()
    a_template = template['markdown'] if args.md else template['html']
    t_general = Template(a_template['general'])
    t_host = Template(a_template['host'])
    t_list_item = Template(a_template['list_item'])
    output_file_suffix = a_template['suffix']

    all_results = []
    report_name = os.path.basename(file).lower().replace('.txt', '') \
                  + '_' + time.strftime('%Y%m%d_%H%M%S', time.localtime()) + output_file_suffix

    global STOP_ME
    try:
        while not STOP_ME:
            if q_results.qsize() == 0:
                time.sleep(0.1)
                continue

            html_doc = ""
            while q_results.qsize() > 0:
                all_results.append(q_results.get())

            for item in all_results:
                host, results = item
                _str = ""
                for key in results.keys():
                    for _ in results[key]:
                        _str += t_list_item.substitute(
                            {'status': _['status'], 'url': _['url'], 'title': _['title']}
                        )
                _str = t_host.substitute({'host': host, 'list': _str})
                html_doc += _str

            cost_time = time.time() - start_time
            cost_min = int(cost_time / 60)
            cost_seconds = '%.2f' % (cost_time % 60)
            html_doc = t_general.substitute(
                {'cost_min': cost_min, 'cost_seconds': cost_seconds, 'content': html_doc}
            )

            with codecs.open('report/%s' % report_name, 'w', encoding='utf-8') as outFile:
                outFile.write(html_doc)

        if all_results:
            print_msg('Scan report saved to report/%s' % report_name)
            if not args.no_browser:
                webbrowser.open_new_tab(os.path.abspath('report/%s' % report_name))
        else:
            lock.acquire()
            print_msg('No vulnerabilities found on sites in %s.' % file)
            lock.release()

    except Exception as e:
        print_msg('[save_report_thread Exception] %s %s' % (type(e), str(e)))
        sys.exit(-1)


def domain_lookup():
    r = Resolver()
    r.timeout = r.lifetime = 10.0
    # r.nameservers = ['182.254.116.116', '223.5.5.5'] + r.nameservers
    while True:
        try:
            host = queue_hosts.get(timeout=0.1)
        except:
            break
        _schema, _host, _path = parse_url(host)
        try:
            m = re.search('\d+\.\d+\.\d+\.\d+', _host.split(':')[0])
            if m:
                q_targets.put({'file': '', 'url': host})
                ips_to_scan.append(m.group(0))
            else:
                answers = r.query(_host.split(':')[0])
                if answers:
                    q_targets.put({'file': '', 'url': host})
                    for _ in answers:
                        ips_to_scan.append(_.address)
        except Exception as e:
            print_msg('Invalid domain: %s' % host)


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

    for file in input_files:
        if args.host:
            lines = args.host
        elif args.f or args.d:
            with open(file) as inFile:
                lines = inFile.readlines()
        try:
            print_msg('Batch web scan start.')
            q_results = multiprocessing.Manager().Queue()
            q_targets = multiprocessing.Manager().Queue()
            lock = multiprocessing.Manager().Lock()
            STOP_ME = False

            threading.Thread(target=save_report_thread, args=(q_results, file)).start()
            print_msg('Report thread created, prepare target Queue...')

            if args.crawler:
                _input_files = glob.glob(args.crawler + '/*.log')
                for _file in _input_files:
                    q_targets.put({'file': _file, 'url': ''})

            else:
                queue_hosts = Queue.Queue()
                for line in lines:
                    if line.strip():
                        # Works with https://github.com/lijiejie/subDomainsBrute
                        # delimiter "," is acceptable
                        hosts = line.replace(',', ' ').strip().split()
                        for host in hosts[:1]:  # Scan the first host or domain only
                            queue_hosts.put(host)

                all_threads = []
                for _ in range(30):
                    t = threading.Thread(target=domain_lookup)
                    t.start()
                    all_threads.append(t)
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

            print_msg('%s targets entered Queue.' % q_targets.qsize())
            print_msg('Create %s sub Processes...' % args.p)
            scan_process = []
            for _ in range(args.p):
                p = multiprocessing.Process(target=batch_scan, args=(q_targets, q_results, lock, args))
                p.daemon = True
                p.start()
                scan_process.append(p)
            print_msg('%s sub process successfully created.' % args.p)
            for p in scan_process:
                p.join()

        except KeyboardInterrupt as e:
            print_msg('[+] User aborted, running tasks crashed.')
            try:
                while True:
                    q_targets.get_nowait()
            except:
                pass

        except Exception as e:
            print_msg('[__main__.exception] %s %s' % (type(e), str(e)))
            traceback.print_exc()
        time.sleep(0.5)
        STOP_ME = True
