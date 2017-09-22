
from lib.common import save_user_script_result

folders = """
/admin
/output
/tmp
/temp
/test
/conf
/config
/db
/database
/install
/open-flash-chart
/jPlayer
/jwplayer
/extjs
/boss
/ckeditor
/cgi-bin
/.ssh
/ckfinder
/.git
/.svn
/editor
/bak
/fck
/.idea
/swfupload
/kibana
/monitor
/htmedit
/htmleditor
/ueditor
/resin-doc
/resin-admin
/tomcat
/zabbix
/WEB-INF
/WEB-INF/classes
/manage
/manager
/test
/temp
/tmp
/cgi-bin
/deploy
/backup
"""


def do_check(self, url):
    if url != '/' or not self.conn_pool or self._404_status == 301:
        return


    _folders = folders.split()

    for _url in _folders:
        status, headers, html_doc = self._http_request(_url)

        if status in (301, 302):
            location = headers.get('location', '')
            if location.startswith(self.base_url + _url + '/') or location.startswith(_url + '/'):
                save_user_script_result(self, status, self.base_url + _url,
                                        'Possible Sensitive Folder Found')

        if status == 206 and self._404_status != 206:
            save_user_script_result(self, status, self.base_url + _url,
                                    'Possible Sensitive File Found')

