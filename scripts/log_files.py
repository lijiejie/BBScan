
from lib.common import save_script_result


async def do_check(self, url):
    if url == '/' and self.conn_pool:
        folders = ['']
        for log_folder in ['false_positive_log', 'log', 'logs']:
            status, headers, html_doc = await self.http_request('/' + log_folder)

            if status in (301, 302):
                location = headers.get('location', '')
                if location.startswith(self.base_url + '/' + log_folder + '/') or \
                        location.startswith('/' + log_folder + '/'):
                    if log_folder == 'false_positive_log':    # false positive check
                        break
                    folders.append(log_folder)
                    await self.enqueue(log_folder)
                    await self.crawl('/' + log_folder + '/')

            if status == 206 and self._404_status != 206:
                await save_script_result(self, status, self.base_url + '/' + log_folder, '',
                                   'Log File Found')

        url_lst = ['false_positive_access.log', 'access.log', 'www.log', 'error.log', 'log.log', 'sql.log',
                   'log/false_positive_access.log','log/access.log',
                   'errors.log', 'debug.log', 'db.log', 'install.log',
                   'server.log', 'sqlnet.log', 'WS_FTP.log', 'database.log', 'data.log', 'app.log',
                   'false_positive_log.tar.gz', 'log.tar.gz', 'log.rar', 'log.zip',
                   'log.tgz', 'log.tar.bz2', 'log.7z']

        for log_folder in folders:
            for _url in url_lst:
                url_prefix = '/' + log_folder if log_folder else ''
                status, headers, html_doc = await self.http_request(url_prefix + '/' + _url)
                # print '/' + log_folder + '/' + _url
                if status in [206, 200] and headers.get('content-type', '').find('application/') >= 0:
                    if _url == url_lst[0] or _url in ['false_positive_access.log',
                                                      'false_positive_log.tar.gz', 'log/false_positive_access.log']:
                        break
                    # false positive check
                    ret = _url.split('/')
                    ret[-1] = 'fptest' + ret[-1]
                    status, headers, html_doc = await self.http_request(url_prefix + '/' + '/'.join(ret))
                    # print '/' + log_folder + '/' + _url
                    if status in [206, 200] and headers.get('content-type', '').find('application/') >= 0:
                        pass
                    elif self.find_exclude_text(html_doc):
                        pass
                    else:
                        await save_script_result(self, status, self.base_url + url_prefix + '/' + _url,
                                                 '', 'Log File')

        for log_folder in folders:
            for _url in ['log_false_positive.txt', 'log.txt', 'logs.txt']:
                url_prefix = '/' + log_folder if log_folder else ''
                status, headers, html_doc = await self.http_request(url_prefix + '/' + _url)
                # print '/' + log_folder + '/' + _url
                if status == 206 and headers.get('content-type', '').find('text/plain') >= 0:
                    if _url == 'log_false_positive.txt':
                        break
                    await save_script_result(self, status, self.base_url + url_prefix + '/' + _url,
                                             '', 'Log File')
