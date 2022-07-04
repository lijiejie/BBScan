# BBScan 2.0 #

**BBScan** 是一个高并发、轻量级的信息泄露扫描工具。

它可以在短时间内完成数十万目标的扫描，帮助渗透工程师从大量无标签的主机中，定位到可能存在弱点的目标，进行下一步半自动化测试，或者是开启重量级扫描器。 它可以作为一个轻量级插件，集成到自动化扫描系统中。

因为其python插件扫描，跟作者即将释出的工具高度一致。2.0之后的版本，我们将只关注信息泄露扫描。

**BBScan** is a fast and light weighted information disclosure vulnerabilitiy scanner.

Scan thousands of targets can be done in serveral minutes，which can help pentesters filter possible vulnerable hosts from large number of unlabeled targets. It can be integrated as a scan component in other scanner projects.

### 安装 Install ###

Require python3.6+

	pip3 install -r requirements.txt

### 使用 Usage

* ##### **从文件导入目标  Import urls from file**

```
python BBScan.py -f urls.txt
```

* ##### 指定多个规则  Enable specified rules only

```
python BBScan.py --rule git_and_svn -f urls.txt
```

### 参数  Parameters ###

	Targets:
	
	  --host [HOST [HOST ...]]
	                        Scan several hosts from command line
	  -f TargetFile         Load new line delimited targets from TargetFile
	  -d TargetDirectory    Load all *.txt files from TargetDirectory
	  --crawler CrawlDirectory
	                        Load all *.log crawl files from CrawlDirectory
	  --network MASK        Scan all Target/MASK neighbour hosts,
	                        should be an integer between 8 and 31
	
	HTTP SCAN:
	
	  --rule [RuleFileName [RuleFileName ...]]
	                        Import specified rule files only.
	  -n, --no-crawl        No crawling, sub folders will not be processed
	  -nn, --no-check404    No HTTP 404 existence check
	  --full                Process all sub directories
	
	Scripts SCAN:
	
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
	  -md                   Save scan report as markdown format
	  --save-ports PortsDataFile
	                        Save open ports to PortsDataFile
	  --debug               Show verbose debug info
	  -nnn, --no-browser    Do not open web browser to view report
	  -v                    show program's version number and exit
