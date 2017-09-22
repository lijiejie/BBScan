
from lib.common import save_user_script_result


def do_check(self, url):
    if url == '/':
        if self.conn_pool and self.index_status in (301, 302):
            for keyword in ['admin', 'login', 'manage', 'backend']:
                if self.index_headers.get('location', '').find(keyword) >= 0:
                    save_user_script_result(self, self.index_status, self.base_url + '/',
                                            'Admin Site Found')
                    break
