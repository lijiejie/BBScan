# -*- encoding: utf-8 -*-

TEMPLATE_html = """
<html>
<head>
<title>BBScan Report</title>
<style>
    body {width:960px; margin:auto; margin-top:10px; background:rgb(200,200,200);}
    p {color: #666;}
    h2 {color:#002E8C; font-size: 1em; padding-top:5px;}
</style>
</head>
<body>
<p>Please consider to contribute some rules to make BBScan more efficient.  <b>BBScan v 1.0</b></p>
<p>Current Scan was finished in ${cost_min} min ${cost_seconds} seconds.</p>
${content}
</body>
</html>
"""

TEMPLATE_host = """
<h2>${host}</h2>
<ul>
${list}
</ul>
"""

TEMPLATE_severity_high = """
 <li class="high">[${status}] <a href="${url}" target="_blank">${url}</a></li>
"""

TEMPLATE_severity_normal = """
 <li class="normal">[${status}] <a href="${url}" target="_blank">${url}</a></li>
"""
