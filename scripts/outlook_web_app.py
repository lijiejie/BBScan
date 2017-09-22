# Exchange Outlook Web APP
# /owa/             {status=302}     {tag="/owa/auth/logon.aspx"}

import httplib
from lib.common import save_user_script_result


def do_check(self, url):
    if url == '/' and self.conn_pool:
        if self.index_status == 302 and self.index_headers.get('location', '').lower() == 'https://%s/owa' % self.host:
            save_user_script_result(self, 302, 'https://%s' % self.host, 'OutLook Web APP Found')
            return

        status, headers, html_doc = self._http_request('/ews/')

        if status == 302:
            redirect_url = headers.get('location', '')
            if redirect_url == 'https://%shttp://%s/ews/' % (self.host, self.host):
                save_user_script_result(self, 302, 'https://%s' % self.host, 'OutLook Web APP Found')
                return
            if redirect_url == 'https://%s/ews/' % self.host:
                try:
                    conn = httplib.HTTPSConnection(self.host)
                    conn.request('HEAD', '/ews')
                    if conn.getresponse().status == 401:
                        save_user_script_result(self, 401, redirect_url, 'OutLook Web APP Found')
                    conn.close()
                except:
                    pass
                return

        elif status == 401:
            if headers.get('Server', '').find('Microsoft-IIS') >= 0:
                save_user_script_result(self, 401, self.base_url + '/ews/', 'OutLook Web APP Found')
                return
