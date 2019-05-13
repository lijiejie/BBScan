# -*- encoding: utf-8 -*-
# report template


# template for html
html_general = """
<html>
<head>
<title>BBScan Scan Report</title>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<style>
    body {width:960px; margin:auto; margin-top:10px; background:rgb(240,240,240);}
    p {color: #666;}
    h2 {color:#002E8C; font-size: 1em; padding-top:5px;}
    ul li {
    word-wrap: break-word;
    white-space: -moz-pre-wrap;
    white-space: pre-wrap;
    margin-bottom:10px;
    }
    span {color: purple;}
</style>
</head>
<body>
<p>Scan finished in <font color=green>${cost_min} ${cost_seconds} seconds</font>. <b>BBScan v 1.4</b></p>
${content}
</body>
</html>
"""

html_host = """
<h2>${host}</h2>
<ul>
${list}
</ul>
"""

html_list_item = """
 <li class="normal"> ${status} <span>${vul_type}</span> ${title}  <a href="${url}" target="_blank">${url}</a></li>
"""

html = {
    'general': html_general,
    'host': html_host,
    'list_item': html_list_item,
    'suffix': '.html'
}


# template for markdown
markdown_general = """
# BBScan Scan Report
Version:v 1.4
Time cost: ${cost_min} ${cost_seconds} seconds
${content}
"""

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


# summary
template = {
    'html': html,
    'markdown': markdown
}
