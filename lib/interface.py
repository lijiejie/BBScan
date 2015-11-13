# -*- encoding: utf-8 -*-
# Scanner interfaces to implement

class InfoDisScannerBase(object):
    def __init__(self, url, max_depth=2):
        pass

    @staticmethod
    def _init_log(self):
        pass

    @staticmethod
    def _cal_depth(url):
        pass

    def _init_rules(self):
        pass

    @staticmethod
    def _parse_url(url):
        pass

    def _http_request(self, url):
        pass

    def check_404(self):
        pass

    def _enqueue(self):
        pass

    def crawl_index(self):
        pass

    def _scan_worker(self):
        pass

    def scan(self):
        pass