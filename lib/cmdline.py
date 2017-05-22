#!/usr/bin/env python
#
#  Parse command line arguments
#


import argparse
import sys
import os


def parse_args():
    parser = argparse.ArgumentParser(prog='BBScan',
                                     formatter_class=argparse.RawTextHelpFormatter,
                                     description='* A tiny Batch weB vulnerability Scanner. *\n'
                                                 'By LiJieJie (http://www.lijiejie.com)',
                                     usage='BBScan.py [options]')

    parser.add_argument('--host', metavar='HOST [HOST2 HOST3 ...]', type=str, default='', nargs='*',
                        help='Scan several hosts from command line')

    parser.add_argument('-f', metavar='TargetFile', type=str, default='',
                        help='Load new line delimited targets from TargetFile')

    parser.add_argument('-d', metavar='TargetDirectory', type=str, default='',
                        help='Load all *.txt files from TargetDirectory')

    parser.add_argument('--crawler', metavar='TargetDirectory', type=str, default='',
                        help='Load all *.log crawler files from TargetDirectory')

    parser.add_argument('--full-scan', dest='full_scan', default=False, action='store_true',
                        help='Process all sub directories.')

    parser.add_argument('-n', '--no-crawl', dest='no_crawl', default=False, action='store_true',
                        help='No crawling, sub folders will not be processed.')

    parser.add_argument('-nn', '--no-check404', dest='no_check404', default=False, action='store_true',
                        help='No HTTP 404 existence check')

    parser.add_argument('-p', metavar='PROCESS', type=int, default=8,
                        help='Num of processes running concurrently, 8 by default')

    parser.add_argument('-t', metavar='THREADS', type=int, default=3,
                        help='Num of scan threads for each scan process, 3 by default')

    parser.add_argument('--network', metavar='MASK', type=int, default=32,
                        help='Scan all Target/MASK hosts, \nshould be an int between 24 and 31')

    parser.add_argument('--timeout', metavar='Timeout', type=int, default=20,
                        help='Max scan minutes for each website, 20 by default')

    parser.add_argument('-nnn', '--no-browser', dest='no_browser', default=False, action='store_true',
                        help='Do not view report with browser after scan finished')

    parser.add_argument('-md', default=False, action='store_true',
                        help='Save scan report as markdown format')

    parser.add_argument('-v', action='version', version='%(prog)s 1.2.3    By LiJieJie (http://www.lijiejie.com)')

    if len(sys.argv) == 1:
        sys.argv.append('-h')

    args = parser.parse_args()
    check_args(args)
    return args


def check_args(args):
    if not args.f and not args.d and not args.host and not args.crawler:
        msg = 'Args missing! One of following args should be specified  \n           ' \
              '-f TargetFile \n           ' \
              '-d TargetDirectory \n           ' \
              '--crawler TargetDirectory \n           ' \
              '--host www.host1.com www.host2.com 8.8.8.8'
        raise Exception(msg)

    if args.f and not os.path.isfile(args.f):
        raise Exception('TargetFile not found: %s' % args.f)

    if args.d and not os.path.isdir(args.d):
        raise Exception('TargetDirectory not found: %s' % args.f)

    args.network = int(args.network)
    if not (24 <= args.network <= 32):
        raise Exception('--network must be an integer between 24 and 31')
