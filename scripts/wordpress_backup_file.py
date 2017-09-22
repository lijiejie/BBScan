# Wordpress
# /wp-config.php.inc    {status=200}       {tag="<?php"}
# /wp-login.php         {tag="user_login"}  {status=200}
# /wp-config.inc        {status=200}       {tag="<?php"}
# /wp-config.bak        {status=200}       {tag="<?php"}
# /wp-config.php~       {status=200}       {tag="<?php"}
# /.wp-config.php.swp   {status=200}       {tag="<?php"}
# /wp-config.php.bak    {status=200}       {tag="<?php"}

from lib.common import save_user_script_result


def do_check(self, url):
    if url == '/' and self.conn_pool:
        if self.index_html_doc.find('/wp-content/themes/') >= 0:
            url_lst = ['/wp-config.php.inc',
                       '/wp-config.inc',
                       '/wp-config.bak',
                       '/wp-config.php~',
                       '/.wp-config.php.swp',
                       '/wp-config.php.bak']
            for _url in url_lst:
                status, headers, html_doc = self._http_request(_url)
                print _url
                if status == 200 or status == 206:
                    if html_doc.find('<?php') >= 0:
                        save_user_script_result(self, status, self.base_url + _url, 'WordPress Backup File Found')
