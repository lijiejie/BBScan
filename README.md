# BBScan 1.5 #

**BBScan** 是一个高并发漏洞扫描工具，可用于

* 高危漏洞爆发后，编写简单插件或规则，进行全网扫描
* 作为巡检组件，集成到已有漏洞扫描系统中

BBScan能够在1分钟内

* 对超过2万个IP地址进行指定端口发现，同时，进行漏洞验证。例如，Samba  MS17010漏洞
* 对超过1000个网站进行HTTP服务发现(80/443)，同时，请求某个指定URL，完成漏洞检测

------

**BBScan** is a super fast vulnerability scanner. 

* A class B network (65534 hosts) could be scanned within 4 minutes (ex. Detect Samba MS17010)
* Up to find more than 1000 target's web services and meanwhile, detect the vulnerability associated with a specified URL within one minute 

------

### Install ###

	pip2.7 install -r requirements.txt

### 开始使用

* ##### **使用1个或多个插件，扫描某个B段**

```
python BBScan.py --scripts-only --script redis_unauthorized_access --host www.site.com --network 16
```

上述命令将使用 `redis_unauthorized_access` 插件，扫描 www.site.com/16，扫描过程将持续 2~4 分钟。

* ##### 使用1个或多个规则，扫描文件中的所有目标

```
python BBScan.py --no-scripts --rule git_and_svn --no-check404 --no-crawl -f iqiyi.txt
```

使用 `git_and_svn` 文件中的规则，扫描 `iqiyi.txt` 文件中的所有目标，每一行一个目标

`--no-check404`  指定不检查404状态码

`--no-crawl` 指定不抓取子目录

通过指定上述两个参数，可显著减少HTTP请求的数量。

### 参数说明 ###

**如何设定扫描目标** 

	  --host [HOST [HOST ...]]
	                        该参数可指定1个或多个域名/IP
	  -f TargetFile         从文件中导入所有目标，目标以换行符分隔
	  -d TargetDirectory    从文件夹导入所有.txt文件，文件中是换行符分隔的目标
	  --network MASK        设置一个子网掩码(8 ~ 31)，配合上面3个参数中任意一个。将扫描
	  						Target/MASK 网络下面的所有IP

**HTTP扫描**

	  --rule [RuleFileName [RuleFileName ...]]
	                        扫描指定的1个或多个规则
	  -n, --no-crawl        禁用页面抓取，不处理页面中的其他链接
	  -nn, --no-check404    禁用404状态码检查
	  --full                处理所有子目录。 /x/y/z/这样的链接，/x/ /x/y/也将被扫描

**插件扫描**

	  --scripts-only        只启用插件扫描，禁用HTTP规则扫描
	  --script [ScriptName [ScriptName ...]]
	                        扫描指定1个或多个插件
	  --no-scripts          禁用插件扫描

**并发**

```
  -p PROCESS            扫描进程数，默认30。建议设置 10 ~ 50之间
  -t THREADS            单个目标的扫描线程数, 默认3。建议设置 3 ~ 10之间
```

**其他参数**

	  --timeout TIMEOUT     单个目标最大扫描时间（单位:分钟），默认10分钟
	  -md                   输出markdown格式报告
	  --save-ports PortsDataFile
	                        将端口开放信息保存到文件 PortsDataFile，可以导入再次使用
	  --debug               打印调试信息
	  -nnn, --no-browser    不使用默认浏览器打开扫描报告
	  -v                    show program's version number and exit

### 使用技巧

* **如何把BBScan当做一个快速的端口扫描工具使用？**

找到scripts/tools/port_scan.py，填入需要扫描的端口号列表。把文件移动到scripts下。执行

```
python BBScan.py --scripts-only --script port_scan --host www.baidu.com --network 16 --save-ports ports_80.txt
```

`--save-ports`  是一个非常有用的参数，可以将每次任务执行过程发现的端口，保存到文件中

* **如何观察执行过程**

请设置 `--debug` 参数，观察是否按照预期，执行插件，发起HTTP请求

* **如何编写插件**

请参考scripts文件夹下的插件内容。self参数是一个Scanner对象，可使用Scanner对象的任意方法、属性。

`self.host`  `self.port` 是目标主机和端口

`self.ports_open` 是开放的端口列表，是所有插件共享的。 一般不在插件执行过程中再单独扫描端口

`self.conn_pool` 是HTTP连接池

`self.http_request` 可发起HTTP GET请求

`self.index_headers`  `self.index_status` `self.index_html_doc` 是请求首页后返回的，一旦扫描器发现有插件依赖，会预先请求首页，保存下来，被所有插件公用

