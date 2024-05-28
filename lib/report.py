# -*- encoding: utf-8 -*-
# Generate HTML report

import asyncio
import time
from string import Template
import webbrowser
import sys
import codecs
import os
from lib.common import escape
from lib.consle_width import getTerminalSize
import lib.config as conf


html_head = """
<html>
<head>
<title>BBScan %s Scan Report</title>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<style>
    body {width: 90%%;min-width:960px; margin:auto; margin-top:10px; background:rgb(240,240,240);}
    p {color: #666;}
    h2 {color:#002E8C; font-size: 1em; padding-top:5px;}
    h1 {color:#0969da; font-size: 20px; padding-top:15px;}
    ul li {
    word-wrap: break-word;
    white-space: -moz-pre-wrap;
    white-space: pre-wrap;
    margin-bottom:10px;
    }
    span {color: aliceblue;}
    table thead tr th {
        text-align: left;
    }
        
    .leftAlign th,
    .leftAlign td {
        text-align: left !important;  
    }
    
    .purpleRed table {
        background-color: #3d3b63;
        border-collapse: collapse;
        border-radius: 10px;
        color: white;
        overflow: hidden;
        width: auto;
        /*max-width: 100%%;*/
    }
    .purpleRed thead {
        background-color: #f3646c;
        color: white;
    }
    .purpleRed th {
        letter-spacing: 0.3px;
        text-shadow: 0 1px 1px #2b2a466b;
    }
    .purpleRed table > thead > tr > th {
        border: 1px solid rgba(0, 0, 0, 0.1);
    }
    .purpleRed td {
        background-color: #3d3b63;
        color: white;
        font-size: 12px;
        word-break: break-all;
    }
    .purpleRed .vulRow td {
        background-color: #775bc9;
        color: white;
        font-size: 14px;
    }    
    .purpleRed td a {
      color: lightpink;
    }
    .purpleRed td strong {
        color: white;
    }
    .purpleRed td,
    .purpleRed th {
        border: 1px solid rgba(0, 0, 0, 0.1);
        padding: 11px;
    }
    .purpleRed thead th:hover,
    .purpleRed thead tr:hover,
    .purpleRed th:hover {
        background-color: #f3646c;
    }
    .purpleRed tbody tr:hover td,
    .purpleRed tbody tr:hover td a {
        background-color: #a32959;
        color: white;
    }

    a:link { 
      text-decoration: none; 
    } 
    a:visited { 
      text-decoration: none; 
    } 
    a:hover { 
      text-decoration: none; 
    } 
    a:active { 
      text-decoration: none; 
    }
    pre {
      overflow: auto;
      color: #ccffff;
      width:0;
      min-width:100%%;
    }
    pre::-webkit-scrollbar{
      height:6px;
      background-color: #ccffff;
      }
    pre::-webkit-scrollbar-thumb{
      background: #f3646c;
      border-radius:1px;
    }
    .apiRow td {
        background-color: darkslategrey;
    }
    .apiLinks {
        display: none;
        flex-wrap: wrap;
    }
    .apiLinks a {
        margin-right: 20px;
        margin-bottom: 5px;
    }
    button {padding-top: 3px; padding-bottom: 3px;}
</style>
<script>
    function switchShowHeaders(){
      btn = document.getElementById('switchBtn');
      if (btn.innerText === 'Hide Headers') {
          btn.innerText = 'Show Headers';
          display = 'none';
      } else {
          btn.innerText = 'Hide Headers';
          display = 'block';
      }
      for (let item of document.getElementsByTagName('pre')) {
        item.style.display = display;
      }
    }

    function showVulnerableTargets(){
      btn = document.getElementById('switchTargetBtn');
      if (btn.innerText === 'Show Vulnerable Targets Only') {
          btn.innerText = 'Show All Targets';
          all_rows = document.getElementsByTagName('tr');
          for (let i = 1; i < all_rows.length; i++) {
              if (all_rows[i].className.indexOf('vulRow') < 0 && all_rows[i].className.indexOf('apiRow') < 0) {
                  if (i === all_rows.length-1 || all_rows[i+1].className.indexOf('vulRow') < 0){
                      all_rows[i].style.display = 'none';
                  }
                  // api 行需要隐藏
                  if (i+1 <= all_rows.length-1 && all_rows[i+1].className.indexOf('apiRow') >= 0){
                        all_rows[i+1].style.display = 'none';
                  }
              }
          }
      } else {
          btn.innerText = 'Show Vulnerable Targets Only';
          for (let item of document.getElementsByTagName('tr')) {
              item.style.display = 'table-row';
          }
      }
    }
    function doSearch(reset){
        all_rows = document.getElementsByTagName('tr');
        keyword = document.getElementById('keyword').value;
        for (let i = 1; i < all_rows.length; i++) {
            item = all_rows[i];
            if (reset || item.innerText.indexOf(keyword) !== -1){
                item.style.display = 'table-row';
              } else {
                item.style.display = 'none';
              }
        }
    }
    function showLinks(linkID){
        element = document.getElementById(linkID);
        if (!element.style.display || element.style.display === 'none') {
            element.style.display = 'flex';
        } else {
            element.style.display = 'none';
        }
    }    
</script>
</head>
<body>

<h1>BBScan %s Scan Report</h1>
<p>Scanned <font color=red>${tasks_processed_count}</font> targets in 
<font color=green>${cost_min} ${cost_seconds} seconds</font>. 
<font color=red>${vulnerable_hosts_count}</font> vulnerable hosts found in total. </p>
<div style="padding-bottom: 10px;display: flex">
    <button id="switchBtn" onclick="switchShowHeaders()">Hide Headers</button>
    <button id="switchTargetBtn" onclick="showVulnerableTargets()" style="margin-left: 20px;margin-right: 30px;">Show Vulnerable Targets Only</button>
    <input id="keyword" type="text" style="width: 150px;outline:none;">
    <button id="searchBtn" onclick="doSearch()" style="margin-left: 10px;margin-right:10px;">Search</button>
    <button id="resetBtn" onclick="doSearch(true)">Reset</button>
    <button style="margin-left: auto; margin-right: 10px"><a href="https://github.com/lijiejie/BBScan/issues" target="_blank">Report Bugs</a></button>
</div>
<table class="purpleRed" style="width:100%%">
  <thead>
    <tr><th>Target</th><th>Fingerprint</th><th>Status</th><th>Web Server</th><th>Title</th><th width="40%%">Response Headers</th></tr>
  </thead>
""" % (conf.version, conf.version)

first_row = Template("""
     <tr> <td><a href="${url}" target="_blank">${url}</a></td> <td>${fingerprint}</td> <td>${status}</td> 
       <td>${server}</td> 
       <td><span>${title}</span></td> <td width="40%%"><pre>${headers}</pre></td> 
     </tr>
""")

vul_row = Template("""
     <tr class="vulRow"> <td colspan="2" style="text-align:right">${vul_type}</td> 
       <td>${status}</td> <td colspan="2" style="text-align:center"><span>${title}</span></td>
       <td><a href="${url}" target="_blank">${url}</a></td> 
     </tr>
""")

api_row = Template("""
     <tr class="apiRow"> 
     <td colspan="6"><button onclick="showLinks('${link_id}')">Display API Endpoints [ Found ${num_found} ]</button><div class="apiLinks" id="${link_id}">${api_urls}</div></td> 
     </tr>
""")

html_tail = """
</table>
<script>
    var input = document.getElementById('keyword');
    input.addEventListener("keypress", function(event) {
      if (event.key === "Enter") {
        event.preventDefault();
        document.getElementById("searchBtn").click();
      }
    });
</script>
</body>
</html>
"""


# template for markdown
markdown_general = """
# BBScan Scan Report
Version: %s
Num of targets: ${tasks_processed_count}
Num of vulnerable hosts: ${vulnerable_hosts_count}
Time elapsed: ${cost_min} ${cost_seconds} seconds
${content}
""" % conf.version

markdown_host = """
## ${host}
${list}
"""

markdown_list_item = """* [${status}] ${title} ${url}
"""

markdown = {
    'general': markdown_general,
    'host': markdown_host,
    'list_item': markdown_list_item,
    'suffix': '.md'
}


async def save_report(args, q_results, _file):

    start_time = time.time()

    report_dir = 'report/%s' % time.strftime('%Y%m%d', time.localtime())
    for dir_name in ['report', report_dir]:
        if not os.path.exists(dir_name):
            os.mkdir(dir_name)

    report_name = '%s_%s.html' % (os.path.basename(_file).lower().replace('.txt', ''),
                                  time.strftime('%H%M%S', time.localtime()))

    vulnerable_hosts_count = 0
    console_width = getTerminalSize()[0] - 2
    debug_file = codecs.open('debug.log', 'w', encoding='utf-8') if args.debug else None

    outfile = None
    api_links_id = 0

    try:
        while not conf.stop_me or q_results.qsize() > 0:
            if q_results.qsize() == 0:
                await asyncio.sleep(0.1)
                continue

            while q_results.qsize() > 0:
                item = await q_results.get()
                if type(item) is str:    # print msg only
                    message = '[%s] %s' % (time.strftime('%H:%M:%S', time.localtime()), item)
                    if args.debug:
                        debug_file.write(message + '\n')
                    # 对于大范围扫描情形，不换行引起滚屏，只在行内显示
                    if not args.debug and args.network <= 22 and \
                            (item.startswith('Scan ') or item.startswith('No ports open')):
                        sys.stdout.write(message + (console_width - len(message)) * ' ' + '\r')
                    else:
                        print(message)
                    continue

                host, results, urls_regex_found = item

                if not outfile:
                    outfile = codecs.open('%s/%s' % (report_dir, report_name), 'w', encoding='utf-8')
                    outfile.write(html_head)
                    conf.output_file_name = '%s/%s' % (report_dir, report_name)

                fingerprint = results.get('$Fingerprint', [''])[0]
                index = results.get('$Index', [{}])[0]
                index['fingerprint'] = '<br/>'.join(fingerprint)

                content = first_row.substitute(index)
                outfile.write(content)

                vuln_found = False
                for key in results.keys():
                    if key.startswith('$'):
                        continue
                    vuln_found = True
                    for item in results[key]:
                        item['vul_type'] = escape(item['vul_type'].replace('_', ' ')) if 'vul_type' in item else ''
                        content = vul_row.substitute(item)
                        outfile.write(content)

                if vuln_found:
                    vulnerable_hosts_count += 1

                if args.api and urls_regex_found:
                    api_links_id += 1
                    links = ''
                    for url in sorted(urls_regex_found):
                        if url.find('://') >= 0:
                            link = '<a href="%s" target="_blank">%s</a>' % (url, url)
                        elif url.lower().startswith('/'):
                            link = '<a href="%s" target="_blank">%s</a>' % (host + url, url)
                        else:
                            link = '<a href="%s" target="_blank">%s</a>' % (host + '/' + url, url)
                        links += link

                    content = api_row.substitute({'api_urls': links, 'num_found': len(urls_regex_found),
                                                  'link_id': 'apiLinks' + str(api_links_id)})
                    outfile.write(content)

        if args.debug and debug_file:
            debug_file.close()

        if conf.ports_saved_to_file:
            print('* Ports data saved to %s' % args.save_ports)

        if outfile:
            outfile.write(html_tail)
            outfile.close()
            with codecs.open('%s/%s' % (report_dir, report_name), 'r', encoding='utf-8') as f:
                content = f.read()
            cost_time = time.time() - start_time
            cost_min = int(cost_time / 60)
            cost_min = '%s min' % cost_min if cost_min > 0 else ''
            cost_seconds = '%.1f' % (cost_time % 60)
            content = content.replace('${tasks_processed_count}', str(conf.tasks_count)).replace(
                '${vulnerable_hosts_count}', str(vulnerable_hosts_count)).replace(
                '${cost_min}', str(cost_min)).replace('${cost_seconds}', str(cost_seconds))
            os.remove('%s/%s' % (report_dir, report_name))
            with codecs.open('%s/%s' % (report_dir, report_name), 'w', encoding='utf-8') as f:
                f.write(content)

            print('\n* %s vulnerable targets on sites in total.' % vulnerable_hosts_count)
            print('* Scan report saved to report/%s/%s' % (report_dir, report_name))
            if not args.no_browser:
                webbrowser.open_new_tab(os.path.abspath('%s/%s' % (report_dir, report_name)))
        else:
            print('\n* No vulnerabilities found on sites in %s.' % _file)

    except Exception as e:
        print('[save_report_thread Exception] %s %s' % (type(e), str(e)))
        import traceback
        traceback.print_exc()
        sys.exit(-1)
