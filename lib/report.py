# -*- encoding: utf-8 -*-
# report template


# template for html
html_general = """
<html>
<head>
<title>BBScan Report</title>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<style>
    body {width:960px; margin:auto; margin-top:10px; background:rgb(200,200,200);}
    p {color: #666;}
    h2 {color:#002E8C; font-size: 1em; padding-top:5px;}
    ul li {
    word-wrap: break-word;
    white-space: -moz-pre-wrap;
    white-space: pre-wrap;
    margin-bottom:10px;
    }
</style>
</head>
<body>
<p>Please consider to contribute some rules to make BBScan more efficient.  <b>BBScan v 1.3</b></p>
<p>Current Scan finished in ${cost_min} min ${cost_seconds} seconds.</p>
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
 <li class="normal">${status} [${title}] <a href="${url}" target="_blank">${url}</a></li>
"""

html = {
    'general': html_general,
    'host': html_host,
    'list_item': html_list_item,
    'suffix': '.html'
}


# template for markdown
markdown_general = """
# BBScan Report 
Please consider to contribute some rules to make BBScan more efficient.
Version:v 1.3
TimeUsage: ${cost_min} min ${cost_seconds} seconds
${content}
"""

markdown_host = """
## ${host}
${list}
"""

markdown_list_item = """* ${status} ${title} ${url}
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
