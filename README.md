# BBScan #

**BBScan** is a tiny **B**atch we**B** vulnerability **Scan**ner.

## Feathers ##

* It has a quite small but efficient set of rules
* It can auto add **Target/mask** network hosts to scanner
* Quite few false positives

## Requirements ##
* Python 2.7.x
* BeautifulSoup4==4.3.2
* py2-ipaddress==3.4.1

with pip installed, you can install required packages

> pip install -r requirements.txt

## Usage ##

	usage: BBScan.py [options]

	* A tiny Batch weB vulnerability Scanner. By LiJieJie *

	optional arguments:
	  -h, --help          show this help message and exit
	  --host HOST         Scan a single host
	  -f TargetFile       Load targets from TargetFile
	  -d TargetDirectory  Load all *.txt files from TargetDirectory
	  -p PROCESS          Num of processes running concurrently, 10 by default
	  -t THREADS          Num of scan threads for each scan process, 20 by default
	  --network MASK      Scan all Target/mask hosts, 
			      		  should be a int between 24 and 31.
	  --timeout Timeout   Max scan minutes for each website, 20 by default
	  --browser           Open web browser to view report after scan was finished.
	  -v                  show program's version number and exit

**1. Scan a single host www.target.com** 

	python BBScan.py  --host www.target.com --browser

**2. Scan www.target.com and all the other ips in www.target.com/28 networks**

	python BBScan.py  --host www.target.com --network 28 --browser
	
**3. Load some targets from file**
	
	python BBScan.py -f wandoujia.com.txt

**4. Load all targets from Directory**

	python BBScan.py -d targets/


## 说明 ##

	这是一个迷你的批量信息泄漏扫描脚本。规则字典非常小，但是尽量保证准确和可利用。

	--network 参数用于设置子网掩码，小公司设为28~30，中等规模公司设置26~28，大公司设为24~26

	当然，尽量避免设为24，扫描过于耗时，除非是想在各SRC多刷几个漏洞。

	该插件是从内部扫描器中抽离出来的，感谢 Jekkay Hu<34538980[at]qq.com> 
	
	如果你有非常有用的规则，请找几个网站验证测试后，再 pull request
	
脚本还会优化，接下来的事:

- 增加有用规则，将规则更好地分类，细化
- 后续可以直接从 rules\request 文件夹中导入HTTP_request
- 优化扫描逻辑