#!/bin/env python
# -*- encoding: utf-8 -*-
# A tiny Batch weB vulnerability Scanner
# my[at]lijiejie.com    http://www.lijiejie.com


import urlparse
import httplib
import logging
import re
import threading
import Queue
from bs4 import BeautifulSoup
import multiprocessing
import time
from string import Template
import glob
import ipaddress
import os
import webbrowser
import socket
import urllib2
import sys
import urllib
from lib.common import get_time, parse_url, decode_response_text
from lib.cmdline import parse_args
from lib.report import TEMPLATE_host, TEMPLATE_html, TEMPLATE_list_item


class InfoDisScanner():
    def __init__(self, timeout=600, args=None):
        self.START_TIME = time.time()
        self.TIME_OUT = timeout
        self.args = args
        self.LINKS_LIMIT = 100      # max number of Folders to scan

        self.full_scan = args.full_scan
        self._init_rules()

        self.url_queue = Queue.Queue()     # all urls to scan
        self.urls_processed = []           # urls already in queue
        self.urls_enqueued = []

        self.lock = threading.Lock()
        socket.setdefaulttimeout(20)


    def init_reset(self):
        self.START_TIME = time.time()
        self.url_queue.queue.clear()
        self.urls_processed = []           # urls already in queue
        self.urls_enqueued = []
        self.results = {}
        self.file = None


    def init_from_url(self, url):
        self.init_reset()
        self.url = url
        if not url.find('://') > 0: self.url = 'http://' + url
        self.schema, self.host, self.path = parse_url(url)
        self.init_final()


    def init_from_file(self, log_file):
        self.init_reset()
        self.file = log_file
        self.schema, self.host, self.path = self._parse_url_from_file()
        self.load_all_urls_from_file()
        self.init_final()


    def init_final(self):
        self.max_depth = self._cal_depth(self.path)[1] + 3     # max depth to scan
        if self.args.no_check404:
            self._404_status = 404
            self.has_404 = True
        else:
            self.check_404()           # check existence of HTTP 404
            if self._404_status == -1:
                return
        if not self.has_404:
            print '[%s] [Warning] %s has no HTTP 404.' % (get_time(), self.host)
        _path, _depth = self._cal_depth(self.path)
        self._enqueue('/')
        self._enqueue(_path)
        if not self.args.no_crawl and not self.file:
            self.crawl_index(_path)


    def _parse_url_from_file(self):
        with open(self.file) as inFile:
            line = inFile.readline().strip()
            if line:
                url = line.split()[1]
            else:
                url = ''
            return parse_url(url)


    def _cal_depth(self, url):
        # calculate depth of a given URL, return tuple (url, depth)
        if url.find('#') >= 0: url = url[:url.find('#')]    # cut off fragment
        if url.find('?') >= 0: url = url[:url.find('?')]    # cut off query string
        if url.startswith('//'):
            return '', 10000    # //www.baidu.com/index.php, ignored
        if not urlparse.urlparse(url, 'http').scheme.startswith('http'):
            return '', 10000    # no HTTP protocol, ignored

        if url.startswith('http'):
            _ = urlparse.urlparse(url, 'http')
            if _.netloc == self.host:    # same hostname
                url = _.path
            else:
                return '', 10000         # not same hostname, ignored
        while url.find('//') >= 0:
            url = url.replace('//', '/')

        if not url:
            return '/', 1         # http://www.example.com

        if url[0] != '/': url = '/' + url
        url = url[: url.rfind('/')+1]
        depth = url.count('/')
        return url, depth


    def _init_rules(self):
        self.text_to_find = []
        self.regex_to_find = []
        self.text_to_exclude = []
        self.regex_to_exclude = []
        self.rules_dict = []

        p_tag = re.compile('{tag="([^"]+)"}')
        p_status = re.compile('{status=(\d{3})}')
        p_content_type = re.compile('{type="([^"]+)"}')
        p_content_type_no = re.compile('{type_no="([^"]+)"}')

        for rule_file in glob.glob('rules/*.txt'):
            infile = open(rule_file, 'r')
            for url in infile.xreadlines():
                url = url.strip()
                if url.startswith('/'):
                    _ = p_tag.search(url); tag = _.group(1).replace("{quote}", '"') if _ else ''
                    _ = p_status.search(url); status = int(_.group(1)) if _ else 0
                    _ = p_content_type.search(url); content_type = _.group(1) if _ else ''
                    _ = p_content_type_no.search(url); content_type_no = _.group(1) if _ else ''
                    url = urllib.unquote(url.split()[0])
                    rule = (url, tag, status, content_type, content_type_no)
                    if not rule in self.rules_dict:
                        self.rules_dict.append(rule)
            infile.close()

        _re = re.compile('{text="(.*)"}')
        _re2 = re.compile('{regex_text="(.*)"}')

        _file_path = 'rules/white.list'
        if not os.path.exists(_file_path):
            return
        for line in open(_file_path):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            _m = _re.search(line)
            if _m:
                self.text_to_find.append( _m.group(1).decode('utf-8', 'ignore') )
            else:
                _m = _re2.search(line)
                if _m:
                    self.regex_to_find.append( re.compile(_m.group(1).decode('utf-8','ignore')) )

        _file_path = 'rules/black.list'
        if not os.path.exists(_file_path):
            return
        for line in open(_file_path):
            line = line.strip()
            if not line or line.startswith('#'): continue
            _m = _re.search(line)
            if _m:
                self.text_to_exclude.append( _m.group(1).decode('utf-8', 'ignore') )
            else:
                _m = _re2.search(line)
                if _m:
                    self.regex_to_exclude.append( re.compile(_m.group(1).decode('utf-8', 'ignore')) )


    def _http_request(self, url, timeout=10):
        try:
            if not url: url = '/'
            conn_fuc = httplib.HTTPSConnection if self.schema == 'https' else httplib.HTTPConnection
            conn = conn_fuc(self.host, timeout=timeout)

            conn.request(method='GET', url=url,
                         headers={'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 '
                                                '(KHTML, like Gecko) Chrome/38.0.2125.111 Safari/537.36 BBScan/1.1',
                                  'Range': 'bytes=0-10240',
                                  'Connection': 'Close'})
            resp = conn.getresponse()
            resp_headers = dict(resp.getheaders())
            status = resp.status
            if resp_headers.get('content-type', '').find('text') >= 0 or \
                            resp_headers.get('content-type', '').find('html') >= 0 or \
                            int(resp_headers.get('content-length', '0')) <= 307200:    # 1024 * 300
                html_doc = decode_response_text(resp.read())
            else:
                html_doc = ''
            conn.close()
            return status, resp_headers, html_doc
        except Exception, e:
            return -1, {}, ''
        finally:
            conn.close()


    def get_status(self, url):
        return self._http_request(url)[0]

    def get_title(sefl, html_doc):
        try:
            soup = BeautifulSoup(html_doc)
            return soup.title.string.encode('utf-8').strip()
        except:
            return ""

    def check_404(self):
        try:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5.0)
                default_port = 443 if self.schema.lower() == 'https' else 80
                host, port = self.host.split(':') if self.host.find(':') > 0 else (self.host, default_port)
                if s.connect_ex((host, int(port))) == 0:
                    s.close()
                    self._404_status, headers, html_doc = \
                        self._http_request('/bbscan_wants__your_response.php')
                else:
                    self._404_status, headers, html_doc = -1, {}, ''
            except:
                self._404_status, headers, html_doc = -1, {}, ''
            finally:
                s.close()

            if self._404_status == -1:
                print '[%s] [ERROR] Fail to connect to %s' % (get_time(), self.host)
            self.has_404 = (self._404_status == 404)
            if not self.has_404:
                self.len_404_doc = len(html_doc)
            return self.has_404
        except Exception, e:
            logging.error("[Check_404] Exception %s" % e)


    def _enqueue(self, url):
        url = str(url)
        _url = re.sub('\d+', '{num}', url)
        if _url in self.urls_processed:
            return False
        elif len(self.urls_processed) >= self.LINKS_LIMIT:
            return False
        else:
            self.urls_processed.append(_url)

        for _ in self.rules_dict:
            try:
                full_url = url.rstrip('/') + _[0]
            except:
                continue
            if full_url in self.urls_enqueued:
                continue
            url_description = {'prefix': url.rstrip('/'), 'full_url': full_url}
            item = (url_description, _[1], _[2], _[3], _[4])
            self.url_queue.put(item)
            self.urls_enqueued.append(full_url)

        if self.full_scan and url.count('/') > 3:
            self._enqueue('/'.join(url.split('/')[:-2]) + '/')

        return True


    def crawl_index(self, path):
        try:
            status, headers, html_doc = self._http_request(path)
            if status != 200:
                try:
                    html_doc = decode_response_text(urllib2.urlopen(self.url).read())
                except Exception,e :
                    pass
            soup = BeautifulSoup(html_doc, "html.parser")
            links = soup.find_all('a')
            for l in links:
                url = l.get('href', '').strip()
                url, depth = self._cal_depth(url)
                if depth <= self.max_depth:
                    self._enqueue(url)
        except Exception, e:
            logging.error('[crawl_index Exception] %s' % e)
            import traceback
            traceback.print_exc()


    def load_all_urls_from_file(self):
        try:
            with open(self.file) as inFile:
                lines = inFile.readlines()
            for line in lines:
                _ = line.split()
                if len(_) == 3 and (_[2].find('^^^200') > 0 or _[2].find('^^^403') > 0):
                    url = urlparse.unquote(_[1])
                    url, depth = self._cal_depth(url)
                    if len(url) >= 70: continue
                    #print url
                    self._enqueue(url)
        except Exception, e:
            logging.error('[load_all_urls_from_file Exception] %s' % e)
            import traceback
            traceback.print_exc()


    def find_text(self, html_doc):
        for _text in self.text_to_find:
            if html_doc.find(_text) > 0:
                return True
        for _regex in self.regex_to_find:
            if _regex.search(html_doc) > 0:
                return  True
        return False


    def exclude_text(self, html_doc):
        for _text in self.text_to_exclude:
            if html_doc.find(_text) > 0:
                return False
        for _regex in self.regex_to_exclude:
            if _regex.search(html_doc) > 0:
                return False
        return True


    def _scan_worker(self):
        while self.url_queue.qsize() > 0:
            if time.time() - self.START_TIME > self.TIME_OUT:
                print '[%s] [ERROR] Timed out task: %s' % (get_time(), self.host)
                return
            try:
                item = self.url_queue.get(timeout=0.1)
            except:
                return
            try:
                url_description, tag, code, content_type, content_type_no = item
                url = url_description['full_url']
                url = url.replace('{sub}', self.host.split('.')[0])
                prefix = url_description['prefix']
                if url.find('{hostname_or_folder}') >= 0:
                    _url = url[: url.find('{hostname_or_folder}')]
                    if _url.count('/') == 1:
                        url = url.replace('{hostname_or_folder}', self.host)
                    elif _url.count('/') > 1:
                        url = url.replace('{hostname_or_folder}', _url.split('/')[-2])
                url = url.replace('{hostname}', self.host)
                if url.find('{parent}') > 0:
                    if url.count('/') >= 2:
                        ret = url.split('/')
                        ret[-2] = ret[-1].replace('{parent}', ret[-2])
                        url =  '/' + '/'.join(ret[:-1])
                    else:
                        continue
            except Exception, e:
                logging.error('[_scan_worker Exception 1] %s' % e)
                continue
            if not item or not url:
                break

            #print '[%s]' % url.strip()
            try:
                status, headers, html_doc = self._http_request(url)

                if headers.get('content-type', '').find('image/') >= 0:    # exclude image type
                    continue

                if html_doc.strip() == '' or len(html_doc) < 10:    # data too short
                    continue

                if not self.exclude_text(html_doc):    # exclude text found
                    continue

                valid_item = False
                if status == 200 and  self.find_text(html_doc):
                    valid_item = True
                else:
                    if status in [400, 404, 503, 502, 301, 302]:
                        continue
                    if  headers.get('content-type', '').find('application/json') >= 0 and \
                            not url.endswith('.json'):    # no json
                        continue

                    if tag:
                        if html_doc.find(tag) >= 0:
                            valid_item = True
                        else:
                            continue    # tag mismatch

                    if content_type and headers.get('content-type', '').find(content_type) < 0 or \
                        content_type_no and headers.get('content-type', '').find(content_type_no) >=0:
                        continue    # type mismatch

                    if self.has_404 or status!=self._404_status:
                        if code and status != code and status != 206:    # code mismatch
                            continue
                        elif code!= 403 and status == 403:
                            continue
                        else:
                            valid_item = True

                    if (not self.has_404) and status in (200, 206) and item[0]['full_url'] != '/' and (not tag):
                        _len = len(html_doc)
                        _min = min(_len, self.len_404_doc)
                        if _min == 0:
                            _min = 10
                        if abs(_len - self.len_404_doc) / _min  > 0.3:
                            valid_item = True

                    if status == 206:
                        if headers.get('content-type', '').find('text') < 0 and headers.get('content-type', '').find('html') < 0:
                            valid_item = True
                        else:
                            continue

                if valid_item:
                    self.lock.acquire()
                    # print '[+] [Prefix:%s] [%s] %s' % (prefix, status, 'http://' + self.host +  url)
                    if not prefix in self.results:
                        self.results[prefix]= []
                    _ = {'status': status, 'url': '%s://%s%s' % (self.schema, self.host, url),'title':self.get_title(html_doc)}
                    if _ not in self.results[prefix]:
                        self.results[prefix].append(_)
                    self.lock.release()

                if len(self.results) >= 10:
                    print 'More than 10 vulnerabilities found for [%s], seems to be false positives, exit.' % prefix
                    return
            except Exception, e:
                logging.error('[InfoDisScanner._scan_worker][2][%s] Exception %s' % (url, e))
                import traceback
                traceback.print_exc()


    def scan(self, threads=10):
        try:
            if self._404_status == -1:
                return self.host, {}
            threads_list = []
            for i in range(threads):
                t = threading.Thread(target=self._scan_worker)
                threads_list.append(t)
                t.start()
            for t in threads_list:
                t.join()
            for key in self.results.keys():
                if len(self.results[key]) > 10:    # more than 20 URLs found under folder: false positives
                    del self.results[key]
            return self.host, self.results
        except Exception, e:
            print '[InfoDisScanner.scan exception] %s' % e


def batch_scan(q_targets, q_results, lock, args):
        s = InfoDisScanner(args.timeout*60, args=args)
        while True:
            try:
                target = q_targets.get(timeout=0.1)
            except:
                break
            _url = target['url']
            _file = target['file']

            #lock.acquire()
            print '[%s] Scan %s' % (get_time(), _url if _url else os.path.basename(_file).rstrip('.log') )
            #lock.release()
            if _url:
                s.init_from_url(_url)
            else:
                if os.path.getsize(_file) > 0:
                    s.init_from_file(_file)
                    if s.host == '':
                        continue
                else:
                    continue
            host, results = s.scan(threads=args.t)
            if results:
                q_results.put( (host, results) )
                for key in results.keys():
                    for url in results[key]:
                        print  '[+] [%s] %s' % (url['status'], url['url'])


def save_report_thread(q_results, file):
        start_time = time.time()
        if args.md:
            a_template = template['markdown']
        else:
            a_template = template['html']

        t_general = Template(a_template['general'])
        t_host = Template(a_template['host'])
        t_list_item = Template(a_template['list_item'])
        output_file_suffix = a_template['suffix']
        

        all_results = []
        
        report_name = os.path.basename(file).lower().replace('.txt', '') + '_' + \
                      time.strftime('%Y%m%d_%H%M%S', time.localtime()) + output_file_suffix 
        
        last_qsize = 0
        global STOP_ME
        try:
            while not (STOP_ME and q_results.qsize() == 0):
                if q_results.qsize() == last_qsize:
                    time.sleep(1.0)
                    continue
                else:
                    last_qsize = q_results.qsize()
                html_doc = ""
                while q_results.qsize() > 0:
                    all_results.append(q_results.get())
                for item in all_results:
                    host, results = item
                    _str = ""
                    for key in results.keys():
                        for _ in results[key]:
                            _str += t_normal.substitute( {'status': _['status'], 'url': _['url'],'title':_['title']} )
                    _str = t_host.substitute({'host': host, 'list': _str})
                    html_doc += _str

                if all_results:
                    cost_time = time.time() - start_time
                    cost_min = int(cost_time / 60)
                    cost_seconds = '%.2f' % (cost_time % 60)
                    html_doc = t_html.substitute({'cost_min': cost_min, 'cost_seconds': cost_seconds, 'content': html_doc})

                    with open('report/%s' % report_name, 'w') as outFile:
                        outFile.write(html_doc)


            if all_results:
                print '[%s] Scan report saved to report/%s' % (get_time(), report_name)
                if args.browser:
                    webbrowser.open_new_tab(os.path.abspath('report/%s' % report_name))
            else:
                lock.acquire()
                print '[%s] No vulnerabilities found on sites in %s.' % (get_time(), file)
                lock.release()
        except IOError, e:
            sys.exit(-1)
        except Exception, e:
            print '[save_report_thread Exception] %s %s' % ( type(e) , str(e))
            sys.exit(-1)


if __name__ == '__main__':
    args = parse_args()

    if args.f:
        input_files = [args.f]
    elif args.d:
        input_files = glob.glob(args.d + '/*.txt')
    elif args.crawler:
        input_files = ['crawler']
    elif args.host:
        input_files = ['hosts']    # several hosts on command line

    scanned_ips = []    # all scanned IPs in current scan

    for file in input_files:
        if args.host:
            lines = [' '.join(args.host)]
        elif args.f or args.d:
            with open(file) as inFile:
                lines = inFile.readlines()
        try:
            print '[%s] Batch web scan start.' % get_time()
            q_results = multiprocessing.Manager().Queue()
            q_targets = multiprocessing.Manager().Queue()
            lock = multiprocessing.Manager().Lock()

            STOP_ME = False
            threading.Thread(target=save_report_thread, args=(q_results, file)).start()
            print '[%s] Report thread created, prepare target Queue...' % get_time()

            if args.crawler:
                _input_files = glob.glob(args.crawler + '/*.log')
                for _file in _input_files:
                    q_targets.put({'file': _file, 'url': ''})

            if args.host or args.f or args.d:
                for line in lines:
                    if line.strip():
                        hosts = line.strip().split()
                        for host in hosts:
                            host = host.strip(',')    # Work with https://github.com/lijiejie/subDomainsBrute
                            _schema, _host, _path = parse_url(host)
                            try:
                                ip = socket.gethostbyname(_host.split(':')[0])
                                if ip:
                                    scanned_ips.append(ip)
                                    q_targets.put({'file': '', 'url': host})
                            except Exception, e:
                                pass

                if args.network != 32:
                    for ip in scanned_ips:
                        if ip.find('/') > 0:
                            continue
                        _network = u'%s/%s' % ('.'.join( ip.split('.')[:3] ), args.network)
                        if _network in scanned_ips:
                            continue
                        _ips = ipaddress.IPv4Network(u'%s/%s' % (ip, args.network), strict=False).hosts()
                        for _ip in _ips:
                            _ip = str(_ip)
                            if _ip not in scanned_ips:
                                scanned_ips.append(_ip)
                                #pool.apply_async(func=batch_scan, args=(_ip, q_results, lock, args, None) ).get(timeout=1)
                                q_targets.put({'file': '', 'url': _ip})
                        scanned_ips.append(_network)
            print '[%s] %s targets entered Queue.' % (get_time(), q_targets.qsize())
            print '[%s] Create %s sub Processes...' % (get_time(), args.p)

            scan_process = []
            for _ in range(args.p):
                p = multiprocessing.Process(target=batch_scan, args=(q_targets, q_results, lock, args))
                p.daemon = True
                p.start()
                scan_process.append(p)
            print '[%s] %s sub process successfully created.' % (get_time(), args.p )
            for p in scan_process:
                p.join()

        except KeyboardInterrupt, e:

            print '[+] [%s] User aborted.' % get_time()
            sys.exit(-1)
        except:
            sys.exit(-1)

        STOP_ME = True

