# /{hostname_or_folder}.zip         {status=206}    {type="application/"}   {root_only}
# /{hostname_or_folder}.rar         {status=206}    {type="application/"}   {root_only}
# /{hostname_or_folder}.tar.gz      {status=206}    {type="application/"}   {root_only}
# /{hostname_or_folder}.tar.bz2     {status=206}    {type="application/"}   {root_only}
# /{hostname_or_folder}.tgz         {status=206}    {type="application/"}   {root_only}
# /{hostname_or_folder}.7z          {status=206}    {type="application/"}   {root_only}
# /{hostname_or_folder}.log         {status=206}    {type="application/"}   {root_only}
#
# /{sub}.zip         {status=206}    {type="application/"}   {root_only}
# /{sub}.rar         {status=206}    {type="application/"}   {root_only}
# /{sub}.tar.gz      {status=206}    {type="application/"}   {root_only}
# /{sub}.tar.bz2     {status=206}    {type="application/"}   {root_only}
# /{sub}.tgz         {status=206}    {type="application/"}   {root_only}
# /{sub}.7z          {status=206}    {type="application/"}   {root_only}
#
# /../{hostname_or_folder}.zip         {status=206}    {type="application/"}
# /../{hostname_or_folder}.rar         {status=206}    {type="application/"}
# /../{hostname_or_folder}.tar.gz      {status=206}    {type="application/"}
# /../{hostname_or_folder}.tar.bz2     {status=206}    {type="application/"}
# /../{hostname_or_folder}.tgz         {status=206}    {type="application/"}
# /../{hostname_or_folder}.7z          {status=206}    {type="application/"}
# /../{hostname_or_folder}.log         {status=206}    {type="application/"}


from lib.common import save_script_result


async def do_check(self, url):
    if not self.conn_pool:
        return

    extensions = ['.zip', '.rar', '.tar.gz', '.tar.bz2', '.tgz', '.7z', '.log', '.sql']

    if url == '/' and self.domain_sub:
        file_names = [self.host.split(':')[0], self.domain_sub]
        for name in file_names:
            for ext in extensions:
                status, headers, html_doc = await self.http_request('/' + name + ext)
                if status in [206, 200]:
                    if ext == '.sql' and html_doc.find("CREATE TABLE") >= 0:
                        await save_script_result(self, status, self.base_url + '/' + name + ext, '', 'Compressed File')
                    elif headers.get('content-type', '').find('application/') >= 0:
                        status2, headers2, html_doc2 = await self.http_request('/fptest' + name + ext)
                        if status2 in [206, 200] and headers2.get('content-type', '').find('application/') >= 0:
                            pass
                        else:
                            status3, headers3, html_doc3 = await self.http_request('/' + name + 'fptest' + ext)
                            if status3 in [206, 200] and headers3.get('content-type', '').find('application/') >= 0:
                                pass
                            else:
                                await save_script_result(self, status, self.base_url + '/' + name + ext, '',
                                                         'Compressed File')

    elif url != '/' and len(url.split('/')) >= 2:
        # sub folders like /aaa/bbb/
        folder_name = url.split('/')[-2]
        if len(folder_name) >= 4:
            url_prefix = url[: -len(folder_name) - 1]
            for ext in extensions:
                status, headers, html_doc = await self.http_request(url_prefix + folder_name + ext)
                if status == 206 and headers.get('content-type', '').find('application/') >= 0:
                    status2, headers2, html_doc2 = await self.http_request(url_prefix + folder_name + 'fptest' + ext)
                    if status2 == 206 and headers2.get('content-type', '').find('application/') >= 0:
                        pass
                    else:
                        await save_script_result(self, status, self.base_url + url_prefix + folder_name + ext,
                                                 '', 'Compressed File')
