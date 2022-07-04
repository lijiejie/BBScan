# Wordpress

from lib.common import save_script_result


async def do_check(self, url):
    if url == '/' and self.conn_pool:
        if self.index_html_doc.find('/wp-content/themes/') >= 0:
            url_lst = ['/wp-config.php.inc',
                       '/wp-config.inc',
                       '/wp-config.bak',
                       '/wp-config.php~',
                       '/.wp-config.php.swp',
                       '/wp-config.php.bak']
            for _url in url_lst:
                status, headers, html_doc = await self.http_request(_url)
                if status == 200 or status == 206:
                    if html_doc.find('<?php') >= 0:
                        await save_script_result(self, status, self.base_url + _url, '', 'WordPress Backup File Found')
