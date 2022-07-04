#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
#  Parse command line arguments
#


import argparse
import sys
import os
import glob
import re
import codecs


def parse_args():
    parser = argparse.ArgumentParser(prog='BBScan',
                                     formatter_class=argparse.RawTextHelpFormatter,
                                     description='* A fast vulnerability Scanner. *\n'
                                                 '* Find sensitive info disclosure vulnerabilities '
                                                 'from large number of targets *\n'
                                                 'By LiJieJie (http://www.lijiejie.com)',
                                     usage='BBScan.py [options]')

    group_target = parser.add_argument_group('Targets', '')
    group_target.add_argument('--host', metavar='HOST', type=str, default='', nargs='*',
                              help='Scan several hosts from command line')
    group_target.add_argument('-f', metavar='TargetFile', type=str, default='',
                              help='Load new line delimited targets from TargetFile')
    group_target.add_argument('-d', metavar='TargetDirectory', type=str, default='',
                              help='Load all *.txt files from TargetDirectory')
    group_target.add_argument('--crawler', metavar='CrawlDirectory', type=str, default='',
                              help='Load all *.log crawl files from CrawlDirectory')
    group_target.add_argument('--network', metavar='MASK', type=int, default=32,
                              help='Scan all Target/MASK neighbour hosts, \nshould be an integer between 8 and 31')

    group_http = parser.add_argument_group('HTTP SCAN', '')
    group_http.add_argument('--rule', metavar='RuleFileName', type=str, default='', nargs='*',
                            help='Import specified rule files only.')
    group_http.add_argument('-n', '--no-crawl', dest='no_crawl', default=False, action='store_true',
                            help='No crawling, sub folders will not be processed')
    group_http.add_argument('-nn', '--no-check404', dest='no_check404', default=False, action='store_true',
                            help='No HTTP 404 existence check')
    group_http.add_argument('--full', dest='full_scan', default=False, action='store_true',
                            help='Process all sub directories')

    group_scripts = parser.add_argument_group('Scripts SCAN', '')
    group_scripts.add_argument('--scripts-only', dest='scripts_only', default=False, action='store_true',
                               help='Scan with user scripts only')
    group_scripts.add_argument('--script', metavar='ScriptName', type=str, default='', nargs='*',
                               help='Execute specified scripts only')
    group_scripts.add_argument('--no-scripts', dest='no_scripts', default=False, action='store_true',
                               help='Disable all scripts')

    group_concurrent = parser.add_argument_group('CONCURRENT', '')
    group_concurrent.add_argument('-p', metavar='PROCESS', type=int, default=30,
                                  help='Num of processes running concurrently, 30 by default')
    group_concurrent.add_argument('-t', metavar='THREADS', type=int, default=3,
                                  help='Num of scan threads for each scan process, 3 by default')

    group_other = parser.add_argument_group('OTHER', '')

    group_other.add_argument('--proxy', metavar='Proxy', type=str, default=None,
                             help='Set HTTP proxy server')

    group_other.add_argument('--timeout', metavar='Timeout', type=int, default=10,
                             help='Max scan minutes for each target, 10 by default')

    group_other.add_argument('-md', default=False, action='store_true',
                             help='Save scan report as markdown format')

    group_other.add_argument('--save-ports', metavar='PortsDataFile', dest='save_ports', type=str, default='',
                             help='Save open ports to PortsDataFile')

    group_other.add_argument('--debug', default=False, action='store_true',
                             help='Show verbose debug info')

    group_other.add_argument('-nnn', '--no-browser', dest='no_browser', default=False, action='store_true',
                             help='Do not open web browser to view report')

    group_other.add_argument('-v', action='version',
                             version='%(prog)s 2.0 (https://github.com/lijiejie/BBScan)')

    if len(sys.argv) == 1:
        sys.argv.append('-h')

    args = parser.parse_args()
    check_args(args)
    if args.f:
        args.input_files = [args.f]
    elif args.d:
        args.input_files = glob.glob(args.d + '/*.txt')
    elif args.crawler:
        args.input_files = ['crawler']
    elif args.host:
        args.input_files = ['hosts']

    return args


def check_args(args):
    if not (args.f or args.d or args.host or args.crawler):
        msg = 'Args missing! One of following args needs to be specified  \n' \
              '    -f TargetFile \n' \
              '    -d TargetDirectory \n' \
              '    --crawler TargetDirectory \n' \
              '    --host www.host1.com www.host2.com 8.8.8.8'
        print(msg)
        exit(-1)

    if args.f and not os.path.isfile(args.f):
        print('[ERROR] TargetFile not found: %s' % args.f)
        exit(-1)

    if args.d and not os.path.isdir(args.d):
        print('[ERROR] TargetDirectory not found: %s' % args.d)
        exit(-1)

    args.network = int(args.network)
    if not (8 <= args.network <= 32):
        print('[ERROR] Network should be an integer between 24 and 31')
        exit(-1)

    args.rule_files = []
    if args.rule:
        for rule_name in args.rule:
            if not rule_name.endswith('.txt'):
                rule_name += '.txt'
            if not os.path.exists('rules/%s' % rule_name):
                print('[ERROR] Rule file not found: %s' % rule_name)
                exit(-1)
            args.rule_files.append('rules/%s' % rule_name)

    args.require_no_http = True     # all scripts do not need http conn pool
    args.require_index_doc = False  # scripts need index html doc
    args.require_ports = set()      # ports need by scripts
    pattern = re.compile(r'ports_to_check.*?=(.*)')

    if not args.no_scripts:
        if args.script:
            for script_name in args.script:
                if not script_name.lower().endswith('.py'):
                    script_name += '.py'
                    if not os.path.exists('scripts/%s' % script_name):
                        print('* Script file not found: %s' % script_name)
                        exit(-1)

        for _script in glob.glob('scripts/*.py'):
            script_name_origin = os.path.basename(_script)
            script_name = script_name_origin.replace('.py', '')
            if args.script and script_name not in args.script and script_name_origin not in args.script:
                continue
            if script_name.startswith('_'):
                continue
            with codecs.open(_script, encoding='utf-8') as f:
                content = f.read()
                if content.find('self.http_request') > 0:
                    args.require_no_http = False
                if content.find('self.index_') > 0:
                    args.require_no_http = False
                    args.require_index_doc = True

                m = pattern.search(content)
                if m:
                    m_str = m.group(1).strip()
                    if m_str.find('#') > 0:  # remove comments
                        m_str = m_str[:m_str.find('#')]
                    if m_str.find('[') < 0:
                        if int(m_str) not in args.require_ports:
                            args.require_ports.add(int(m_str))
                    else:
                        for port in eval(m_str):
                            if port not in args.require_ports:
                                args.require_ports.add(int(port))

    # save open ports to file
    if args.save_ports:
        args.ports_file = None

    if args.proxy and args.proxy.find('://') < 0:
        args.proxy = 'http://%s' % args.proxy
