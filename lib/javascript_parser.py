# -*- encoding: utf-8 -*-
# Parse Javascript file and try to find API interfaces and possible data leaks


import time
from pyjsparser import parse
import copy
import re


async def get_urls_in_js_async(loop, code, js_url, with_regex, self):
    start_time = time.time()
    all_path_items, data_leak_found, error = await loop.run_in_executor(None, get_urls_in_js, code)
    if self.args.debug:
        await self.print_msg('Parse Js: %s, cost %.2f seconds' % (js_url, time.time() - start_time))
        if error:
            await self.print_msg('Js parse failed, url: %s %s' % (js_url, error))

    # key关键词误报临时处理，待优化
    for item in copy.deepcopy(data_leak_found):
        if item[1] == 'key' and (
                code.find('this.%s(' % item[2]) > 0 or code.find('%s:function(' % item[2]) > 0 or
                code.find('{key:"%s",value:function' % item[2]) > 0 or
                code.find('{key:"%s",fn:function' % item[2]) > 0 or
                code.find('{key:"%s",get:function' % item[2]) > 0 or
                code.find('{key:"%s",set:function' % item[2]) > 0):
            # await self.print_msg('js parse, remove %s' % item)
            data_leak_found.remove(item)
    if with_regex:
        urls = extract_urls_regex(code)
    else:
        urls = set([])
    return urls, all_path_items, data_leak_found


def is_interested_var_name(var_name):
    # 查找 key / token / secret 泄露
    var_name = var_name.lower()
    for word in ['key', 'token', 'secret', 'password']:
        if var_name == word:
            return True
        if var_name.endswith('_' + word) or var_name.find('_' + word + '_') >= 0 or var_name.endswith(word + '_'):
            return True

    return False


def extract_urls_regex(code):
    # Regex from: https://github.com/Threezh1/JSFinder/blob/master/JSFinder.py
    regex_str = r"""

      (?:"|')                               # Start newline delimiter

      (
        ((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
        [^"'/]{1,}\.                        # Match a domainname (any character + dot)
        [a-zA-Z]{2,}[^"']{0,})              # The domainextension and/or path

        |

        ((?:/|\.\./|\./)                    # Start with /,../,./
        [^"'><,;| *()(%%$^/\\\[\]]          # Next character can't be...
        [^"'><,;|()]{1,})                   # Rest of the characters can't be

        |

        ([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
        [a-zA-Z0-9_\-/.]{1,}                # Resource name
        \.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
        (?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters

        |

        ([a-zA-Z0-9_\-/]{1,}/               # REST API (no extension) with /
        [a-zA-Z0-9_\-/]{3,}                 # Proper REST endpoints usually have 3+ chars
        (?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters

        |

        ([a-zA-Z0-9_\-]{1,}                 # filename
        \.(?:php|asp|aspx|jsp|json|
             action|html|js|txt|xml)        # . + extension
        (?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters

      )

      (?:"|')                               # End newline delimiter

    """
    pattern = re.compile(regex_str, re.VERBOSE)
    result = re.finditer(pattern, code)
    if not result:
        return None
    ret = set()
    # 初步过滤误报，待优化正则表达式
    for match in result:
        item = match.group().strip('"').strip("'")
        if (item.count('/') == 1 and item.startswith('application/') or item.startswith('text/') or
                item.startswith('audio/') or item.startswith('multipart/') or item.startswith('video/')):
            continue
        if url_in_known_sites(item):
            continue
        if item.count('/') == 2 and all(x.lower() in ['yyyy', 'yy', 'mm', 'm', 'dd', 'd'] for x in item.split('/')):
            continue
        if item in ['/./']:
            continue
        if any(item.endswith(x) for x in ['.vue', '.jpg', '.png', '.svg', '.gif']):
            continue
        ret.add(item)
    return ret


def url_in_known_sites(url):
    for site in ['registry.npmjs.org', 'www.w3.org', 'github.com', 'registry.npmjs.org', 'ant.design']:
        if url.startswith('http://' + site) or url.startswith('https://' + site):
            return True


def get_expression_value(exp):
    value = ''
    try:
        if exp['type'] == 'Literal':    # 常量
            return exp['value']
        elif exp['type'] == 'BinaryExpression':    # 二元操作符
            for key in exp:
                if 'type' in exp[key] and exp[key]['type'] == 'Literal':
                    # select a str which has most slash /
                    if type(exp[key]['value']) is str and exp[key]['value'].count('/') > value.count('/'):
                        value = exp[key]['value']
        elif exp['type'] == 'ObjectExpression':    # 对象, 字典
            for property in exp['properties']:
                tmp = get_expression_value(property['value'])
                if type(tmp) is str and tmp.count('/') > value.count('/'):
                    value = tmp
    except Exception as e:
        print('get_expression_value.exception: %s' % str(e))
    return value


def get_urls_in_js(code):
    try:
        r = parse(code)
    except Exception as e:
        return [], [], str(e)
    traverse_list = [r]    # 从root 开始遍历
    all_path_items = []
    data_leak_found = []
    counter = 0
    while True:
        counter += 1
        if len(traverse_list) == 0 or counter > 10000:
            return all_path_items, data_leak_found, None
        item = traverse_list.pop()
        if type(item) is dict:
            for key in item:
                if type(item[key]) in (list, dict):
                    traverse_list.append(item[key])

                # 变量声明
                if key == 'type' and item['type'] == 'VariableDeclarator':
                    if 'id' in item:
                        var_name = item['id']['name'].lower()
                        if var_name.find('path') >= 0 or var_name.find('uri') >= 0 or var_name.find('url') >= 0:
                            if 'init' not in item or not item['init'] or 'value' not in item['init']:
                                continue
                            path = item['init']['value']
                            if path:
                                all_path_items.append(['a_value', var_name, path])
                        if is_interested_var_name(var_name):
                            if 'init' not in item or not item['init'] or 'value' not in item['init']:
                                continue
                            value = item['init']['value']
                            if value:
                                data_leak_found.append(['a_value', var_name, value])

                if key == 'key':
                    if 'name' not in item['key']:
                        continue
                    var_name = item['key']['name'].lower()
                    if var_name.find('path') >= 0 or var_name.find('uri') >= 0 or var_name.find('url') >= 0:
                        if item['value']['type'] == 'Literal':
                            if item['value']['value']:
                                all_path_items.append(['a_value', var_name, item['value']['value']])
                        elif item['value']['type'] == 'BinaryExpression':
                                val = get_expression_value(item['value'])
                                if val:
                                    all_path_items.append(['a_value',  var_name, get_expression_value(item['value'])])
                    if is_interested_var_name(var_name):
                        if item['value']['type'] == 'Literal':
                            if item['value']['value']:
                                data_leak_found.append(['a_value', var_name, item['value']['value']])
                        elif item['value']['type'] == 'BinaryExpression':
                                val = get_expression_value(item['value'])
                                data_leak_found.append(['a_value', var_name, val])

                # 函数调用
                if key == 'callee':
                    if 'property' not in item['callee'] or 'name' not in item['callee']['property']:
                        continue
                    func_name = item['callee']['property']['name']
                    # 处理ajax请求的参数
                    if func_name.lower() in ['get', 'post', 'put', 'ajax']:
                        if item['arguments']:
                            val = get_expression_value(item['arguments'][0])
                            if val:
                                all_path_items.append(['a_function', func_name, val])
                    if is_interested_var_name(func_name):
                        if item['arguments']:
                            val = get_expression_value(item['arguments'][0])
                            if val:
                                data_leak_found.append(['a_function', func_name, val])

        elif type(item) is list:
            for child_item in item:
                if type(child_item) in (list, dict):
                    traverse_list.append(child_item)
