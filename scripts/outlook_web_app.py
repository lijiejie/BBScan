# Outlook Web APP

import httpx
from lib.common import save_script_result


async def do_check(self, url):
    if url == '/' and self.conn_pool:
        if self.index_status == 302 and self.index_headers.get('location', '').lower() == 'https://%s/owa' % self.host:
            await save_script_result(self, 302, 'https://%s' % self.host, 'OutLook Web APP Found')
            return

        status, headers, html_doc = await self.http_request('/ews/')

        if status == 302:
            redirect_url = headers.get('location', '')
            if redirect_url == 'https://%shttp://%s/ews/' % (self.host, self.host):
                await save_script_result(self, 302, 'https://%s' % self.host, 'OutLook Web APP Found')
                return
            if redirect_url == 'https://%s/ews/' % self.host:
                try:
                    async with httpx.AsyncClient() as client:
                        r = await client.head('/ews')
                        if r.status_code == 401:
                            await save_script_result(self, 401, redirect_url, 'OutLook Web APP Found')
                except Exception as e:
                    pass
                return

        elif status == 401:
            if headers.get('Server', '').find('Microsoft-IIS') >= 0:
                await save_script_result(self, 401, self.base_url + '/ews/', 'OutLook Web APP Found')
                return
