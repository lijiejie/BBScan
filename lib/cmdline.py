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
                                     description='* A tiny Batch weB vulnerability Scanner. *\nBy LiJieJie (http://www.lijiejie.com)',
                                     usage='BBScan.py [options]')

    parser.add_argument('--host', metavar='HOST', type=str, default='',
                        help='Scan a single host')
    parser.add_argument('-f', metavar='TargetFile', type=str, default='',
                        help='Load targets from TargetFile')
    parser.add_argument('-d', metavar='TargetDirectory', type=str, default='',
                        help='Load all *.txt files from TargetDirectory')
    parser.add_argument('-p', metavar='PROCESS', type=int, default=10,
                        help='Num of processes running concurrently, 10 by default')
    parser.add_argument('-t', metavar='THREADS', type=int, default=20,
                        help='Num of scan threads for each scan process, 20 by default')
    parser.add_argument('--network', metavar='MASK', type=int, default=32,
                        help='Scan all Target/mask hosts, \nshould be a int between 24 and 31.')
    parser.add_argument('--timeout', metavar='Timeout', type=int, default=20,
                        help='Max scan minutes for each website, 20 by default')
    parser.add_argument('--browser', default=False, action='store_true',
                        help='Open web browser to view report after scan was finished.')

    parser.add_argument('-v', action='version', version='%(prog)s 1.0    By LiJieJie (http://www.lijiejie.com)')


    if len(sys.argv) == 1:
        sys.argv.append('-h')
    args = parser.parse_args()

    check_args(args)
    return args

def check_args(args):
    if not args.f and not args.d and not args.host:
        msg = 'Use -f to set TargetFile or -d to set TargetDirectory.\n           Use --host to set several hosts'
        raise Exception(msg)

    if args.f and not os.path.isfile(args.f):
        raise Exception('TargetFile not found: %s' % args.f)

    if args.d and not os.path.isdir(args.d):
        raise Exception('TargetDirectory not found: %s' % args.f)

    args.network = int(args.network)
    if not (args.network >=24 and args.network <=32):
        raise Exception('--network must be an integer between 24 and 32')


