# BBScan 1.5 #

**BBScan** can within 1 minute

* The designated port was discovered for more than 20,000 IP addresses, and the vulnerability was verified. For example, Samba MS17010 vulnerability
* Perform HTTP service discovery (80/443) for more than 1,000 websites, and at the same time, request a specified URL to complete vulnerability detection

------

**BBScan** is a super fast vulnerability scanner. 

* A class B network (65534 hosts) could be scanned within 4 minutes (ex. Detect Samba MS17010)
* Up to find more than 1000 target's web services and meanwhile, detect the vulnerability associated with a specified URL within one minute 

------

### Install ###

	pip2.7 install -r requirements.txt

### start using

* ##### **Use one or more plug-ins to scan a certain B segment**

```
python BBScan.py --scripts-only --script redis_unauthorized_access --host www.site.com --network 16
```

The above command will use the redis_unauthorized_accesswidget, the scan www.site.com/16, the scanning process will last 2-4 minutes.

* ##### Use 1 or more rules to scan all targets in the file

```
python BBScan.py --no-scripts --rule git_and_svn --no-check404 --no-crawl -f iqiyi.txt
```

Use `git_and_svn` file rules, scan `iqiyi.txt` all the files in the target, a goal each row

`--no-check404`   Specify not to check the 404 status code

`--no-crawl` Specify not to crawl subdirectories

By specifying the above two parameters, the number of HTTP requests can be significantly reduced.

### Parameter Description ###

**How to set scan targets** 

	  --host [HOST [HOST ...]]
	                        This parameter can specify 1 or more domain names/IP
	  -f TargetFile         Import all targets from the file, the targets are separated by newlines
	  -d TargetDirectory    Import all .txt files from the folder, the file is the target separated by newline
	  --network MASK        Set a subnet mask (8 ~ 31) to match any of the above 3 parameters. Will scan
	  						Target/MASK All IPs under the network

**HTTP scanning**

	  --rule [RuleFileName [RuleFileName ...]]
	                        Scan the specified 1 or more rules
	  -n, --no-crawl        Disable page crawling, do not process other links in the page
	  -nn, --no-check404    Disable 404 status code checking
	  --full                Process all subdirectories. Links like /x/y/z/, /x/ /x/y/ will also be scanned

**Plug-in scanning**

	  --scripts-only        Only enable plugin scanning, disable HTTP rule scanning
	  --script [ScriptName [ScriptName ...]]
	                        Scan to specify 1 or more plugins
	  --no-scripts          Disable plugin scanning

**Concurrent**

```
  -p PROCESS            The number of scanning processes, the default is 30. It is recommended to set between 10 ~ 50
  -t THREADS            The number of scanning threads for a single target, the default is 3. It is recommended to set between 3 ~ 10
```

**Other parameters**

	  --timeout TIMEOUT     Maximum scan time for a single target (unit: minute), the default is 10 minutes
	  -md                   Output markdown format report
	  --save-ports PortsDataFile
	                        Save port opening information to the file PortsDataFile, which can be imported and reused
	  --debug               Print debugging information
	  -nnn, --no-browser    Open the scan report without using the default browser
	  -v                    show program's version number and exit

### Skills

* **How to use BBScan as a fast port scanning tool?**

Find scripts/tools/port_scan.py，and fill in the list of port numbers to be scanned. Move the file to scripts. carried out

```
python BBScan.py --scripts-only --script port_scan --host www.baidu.com --network 16 --save-ports ports_80.txt
```

`--save-ports`   It is a very useful parameter that can save the ports discovered during each task execution to a file

* **How to observe the execution process**

Please set the `--debug` parameters, see if as expected, the implementation of plug-ins, sends an HTTP request

* **How to write a plugin**

Please refer to the plug-in content under the scripts folder. The self parameter is a Scanner object, and any method and attribute of the Scanner object can be used.

`self.host`  `self.port` Is the target host and port

`self.ports_open` It is a list of open ports, shared by all plugins. Generally, the port is not scanned separately during the execution of the plug-in

`self.conn_pool`  Is the HTTP connection pool

`self.http_request` Can initiate HTTP GET request

`self.index_headers`  `self.index_status` `self.index_html_doc` It is returned after requesting the homepage. Once the scanner finds plugin dependencies, it will request the homepage in advance, save it, and be shared by all plugins

