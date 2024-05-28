# BBScan 3.0 #

`BBScan` 是一个高并发的、轻量级的Web漏洞扫描工具。它帮助安全工程师从大量目标中，快速发现，定位可能存在弱点的目标，辅助半自动化测试。

`BBScan` is a fast and light-weight web vulnerability scanner. It helps pen-testers pinpoint possibly vulnerable targets from a large number of web servers.

* Scan common web vulnerabilities: **Data Leaks** / **Directory Traversal** /  **Admin Backends**
* Extract **API Endpoints** from .js file, Scan **Token/Secrets/Pass/Key Leaks**
* Recognize **Web Fingerprints**: web frameworks, programming languages, CMS,  middle-ware, open source software or commercial product name 

### Test Reports 

Brute sub names for *.baidu.com *.qq.com *.bytedance.com with [subDomainsBrute](https://github.com/lijiejie/subDomainsBrute) and then 

send the output files to BBScan,  scan reports are as shown below

* [qq.com_report.html](https://www.lijiejie.com/python/BBScan/qq.com_report.html)      

* [bytedance.com_report.html](https://www.lijiejie.com/python/BBScan/bytedance.com_report.html)       

* [baidu.com_report.html](https://www.lijiejie.com/python/BBScan/baidu.com_report.html)

### Install ###

Require Python 3.6+

	pip3 install -r requirements.txt

### Chang Log

* **2024-05-27** 
  * **New Features**：
    * CMS识别功能，Web指纹来自 [FingerprintHub](https://github.com/0x727/FingerprintHub)  Credit to [@0x727](https://github.com/0x727)
    * JavaScript解析支持，提取拼接API接口，支持检测Key/Secret/Token泄露
    * 通过正则表达式提取URL，From: https://github.com/Threezh1/JSFinder  Credit to [@Threezh1](https://github.com/Threezh1)
  * **减少漏报**：优化减少DNS查询次数，提高稳定性
  * **减少误报**：优化了误报验证逻辑
  * ``**界面优化**：输出更加易用的Web报告

### Usage

* ##### Scan from file

```
python BBScan.py -f urls.txt --api
```

* **Scan from command line**

```
python BBScan.py --host www.test.com https://test2.com http://test3.com:8080 10.1.2.3
```

* ##### Scan with specified rules only

```
python BBScan.py --rule git_and_svn -f urls.txt
```

### Key Arguments   ###

* `--network MASK`    

  You scan involve other IPs under the same network to a scan

  * `--host www.baidu.com --network 24`
  * `-f urls.txt --network 28`

* `--fp, --fingerprint`

  Under this mode, only fingerprint scan performed only, this helps to save some time by disable rule/script based scan.

* `--api`

  Gather and display all API interfaces extracted from .js file
  
* `--skip, --skip-intranet`

  Skip scanning private IP targets. 

```	(venv_py) python BBScan.py
	usage: BBScan.py [options]
	
	
	
	Targets:
	
	  --host [HOST [HOST ...]]
	                        Scan several hosts from command line
	  -f TargetFile         Load new line delimited targets from TargetFile
	  -d TargetDirectory    Load all *.txt files from TargetDirectory
	  --crawler CrawlDirectory
	                        Load all *.log crawl files from CrawlDirectory
	  --network MASK        Scan all Target/MASK neighbour hosts,
	                        should be an integer between 8 and 31
	  --skip, --skip-intranet
	                        Do not scan private IPs, when you are not under the same network with the target
	
	Rule Based SCAN:
	
	  --rule [RuleFileName [RuleFileName ...]]
	                        Import specified rule files only.
	  -n, --no-crawl        No crawling, sub folders will not be processed
	  --no-check404         No HTTP 404 existence check
	  --full                Process all sub directories
	  --fp, --fingerprint   Disable rule and script scan, only check fingerprint
	
	Script Based SCAN:
	
	  --scripts-only        Scan with user scripts only
	  --script [ScriptName [ScriptName ...]]
	                        Execute specified scripts only
	  --no-scripts          Disable all scripts
	
	CONCURRENT:
	
	  -p PROCESS            Num of processes running concurrently, 30 by default
	  -t THREADS            Num of scan threads for each scan process, 3 by default
	
	OTHER:
	
	  --proxy Proxy         Set HTTP proxy server
	  --timeout Timeout     Max scan minutes for each target, 10 by default
	  --api                 Gather and display all API interfaces extracted from .js file
	  --save-ports PortsDataFile
	                        Save open ports to PortsDataFile
	  --debug               Show verbose debug info
	  --no-browser          Do not open web browser to view report
	
```