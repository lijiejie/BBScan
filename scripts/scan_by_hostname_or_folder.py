# /{hostname_or_folder}.zip         {status=206}    {type="application/octet-stream"}   {root_only}
# /{hostname_or_folder}.rar         {status=206}    {type="application/octet-stream"}   {root_only}
# /{hostname_or_folder}.tar.gz      {status=206}    {type="application/octet-stream"}   {root_only}
# /{hostname_or_folder}.tar.bz2     {status=206}    {type="application/octet-stream"}   {root_only}
# /{hostname_or_folder}.tgz         {status=206}    {type="application/octet-stream"}   {root_only}
# /{hostname_or_folder}.7z          {status=206}    {type="application/octet-stream"}   {root_only}
# /{hostname_or_folder}.log         {status=206}    {type="application/octet-stream"}   {root_only}
#
# /{sub}.zip         {status=206}    {type="application/octet-stream"}   {root_only}
# /{sub}.rar         {status=206}    {type="application/octet-stream"}   {root_only}
# /{sub}.tar.gz      {status=206}    {type="application/octet-stream"}   {root_only}
# /{sub}.tar.bz2     {status=206}    {type="application/octet-stream"}   {root_only}
# /{sub}.tgz         {status=206}    {type="application/octet-stream"}   {root_only}
# /{sub}.7z          {status=206}    {type="application/octet-stream"}   {root_only}
#
# /../{hostname_or_folder}.zip         {status=206}    {type="application/octet-stream"}
# /../{hostname_or_folder}.rar         {status=206}    {type="application/octet-stream"}
# /../{hostname_or_folder}.tar.gz      {status=206}    {type="application/octet-stream"}
# /../{hostname_or_folder}.tar.bz2     {status=206}    {type="application/octet-stream"}
# /../{hostname_or_folder}.tgz         {status=206}    {type="application/octet-stream"}
# /../{hostname_or_folder}.7z          {status=206}    {type="application/octet-stream"}
# /../{hostname_or_folder}.log         {status=206}    {type="application/octet-stream"}

from lib.common import save_user_script_result


def do_check(self, url):
    if not self.conn_pool:
        return
    extensions = ['.zip', '.rar', '.tar.gz', '.tar.bz2', '.tgz', '.7z', '.log']

    if url == '/' and self.domain_sub:
        file_names = [self.host.split(':')[0], self.domain_sub]
        for name in file_names:
            for ext in extensions:
                status, headers, html_doc = self._http_request('/' + name + ext)
                if status == 206 and headers.get('content-type', '').find('application/octet-stream') >= 0:
                    save_user_script_result(self, status, self.base_url + '/' + name + ext,
                                            'Possible Data File Found')

    elif url != '/':
        # sub folders like /aaa/bbb/
        folder_name = url.split('/')[-2]
        url_prefix = url[: -len(folder_name)-1]
        for ext in extensions:
            status, headers, html_doc = self._http_request(url_prefix + folder_name + ext)
            if status == 206 and headers.get('content-type', '').find('application/octet-stream') >= 0:
                save_user_script_result(self, status, self.base_url + url_prefix + folder_name + ext,
                                        'Possible Data File Found')
