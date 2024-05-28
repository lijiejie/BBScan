from lib.common import save_script_result


async def do_check(self, url):
    if url == '/' and self.conn_pool:
        if self.index_status == 301 and self.index_headers.get('location', '').find('forum.php') >= 0 or \
                str(self.index_headers).find('_saltkey=') > 0:

            url_lst = ['/config/config_ucenter.php.bak',
                       '/config/.config_ucenter.php.swp',
                       '/config/.config_global.php.swp',
                       '/config/config_global.php.1',
                       '/uc_server/data/config.inc.php.bak',
                       '/config/config_global.php.bak',
                       '/include/config.inc.php.tmp']

            for _url in url_lst:
                status, headers, html_doc = await self.http_request(_url)
                if status == 200 or status == 206:
                    if html_doc.find('<?php') >= 0:
                        await save_script_result(self, status, self.base_url + _url, 'Discuz Backup File Found')

            # getcolor DOM XSS
            status, headers, html_doc = await self.http_request('/static/image/admincp/getcolor.htm')
            if html_doc.find("if(fun) eval('parent.'+fun+'") > 0:
                await save_script_result(self, status, self.base_url + '/static/image/admincp/getcolor.htm',
                                   '', 'Discuz getcolor DOM XSS')
