# BBScan 1.4 #

A vulnerability scanner focus on scanning large number of targets in short time with a minimal set of rules.

**BBScan** 用于渗透测试前期，快速地对大量目标进行扫描，发现信息泄露等常见漏洞，找到可能的突破入口。 

它的特点是快速，规则配置简单。

## Change Log

* [2019-05-13]  BBScan 1.4 with scan strategy optimized.

## Install ##

Install required packages with pip

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
	  --crawler CrawlDirectory
	                        Load all *.log crawl files from CrawlDirectory
	  --full                Process all sub directories.
	  -n, --no-crawl        No crawling, sub folders will not be processed.
	  -nn, --no-check404    No HTTP 404 existence check
	  --scripts-only        Scan with user scripts only
	  --no-scripts          Disable user scripts scan
	  -p PROCESS            Num of processes running concurrently, 30 by default
	  -t THREADS            Num of scan threads for each scan process, 3 by default
	  --network MASK        Scan all Target/MASK hosts,
	                        should be an int between 24 and 31
	  --timeout Timeout     Max scan minutes for each website, 10 by default
	  -nnn, --no-browser    Do not auto open web browser after scan finished
	  -md                   Save scan report as markdown format
	  -v                    show program's version number and exit


**1. Scan several hosts from command line** 

	python BBScan.py  --host www.a.com www.b.com

**2. Scan www.target.com and all the other IPs under www.target.com/28**

	python BBScan.py  --host www.target.com --network 28
	
**3. Load newline delimited targets from file and scan**
	
	python BBScan.py -f wandoujia.com.txt

**4. Load all targets from Directory(\*.txt file only) and scan**

	python BBScan.py -d targets/

**5. Load crawler logs from Directory(\*.log file only) and scan**

	python BBScan.py --crawler crawler_logs/

crawler log files should be formarted first:

			. GET http://www.iqiyi.com/ HTTP/1.1^^^200
			. POST http://www.pps.tv/login.php HTTP/1.1^^^user=admin&passwd=admin^^^200