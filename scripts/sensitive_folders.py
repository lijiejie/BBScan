from lib.common import save_script_result

folders = """
/admin
/bak
/backup
/conf
/config
/db
/debug
/data
/database
/deploy
/WEB-INF
/install
/manage
/manager
/monitor
/tmp
/temp
/test
"""


async def do_check(self, url):
    if url != '/' or not self.conn_pool or self._404_status == 301:
        return

    _folders = folders.split()

    for _url in _folders:
        if not _url:
            continue
        status, headers, html_doc = await self.http_request(_url)

        if status in (301, 302):
            location = headers.get('location', '')
            if location.startswith(self.base_url + _url + '/') or location.startswith(_url + '/'):
                # save_user_script_result(self, status, self.base_url + _url,
                #                         '', 'Possible Sensitive Folder Found')
                await self.enqueue(_url + '/')
                await self.crawl(_url + '/')

        if status == 206 and self._404_status != 206:
            await save_script_result(self, status, self.base_url + _url, '', 'Possible Sensitive File Found')
