# Recon 

## TCP Scan 
```bash
sudo ../Tools/scan.sh  192.168.175.24 
[sudo] password for kali: 
[*] Running rustscan...
[*] Running nmap on ports: 22,8000
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-24 21:29 +07
Nmap scan report for 192.168.175.24
Host is up (0.031s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b9:bc:8f:01:3f:85:5d:f9:5c:d9:fb:b6:15:a0:1e:74 (ECDSA)
|_  256 53:d9:7f:3d:22:8a:fd:57:98:fe:6b:1a:4c:ac:79:67 (ED25519)
8000/tcp open  http    WSGIServer 0.2 (Python 3.10.6)
|_http-cors: GET POST PUT DELETE OPTIONS PATCH
|_http-server-header: WSGIServer/0.2 CPython/3.10.6
|_http-title: Gerapy
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.80 seconds

```
## TCP 80 

![[Challenge/ProvingGround/Levram/IMG/001.png]]

### Try admin:admin


![[Challenge/ProvingGround/Levram/IMG/002.png]]

![[Challenge/ProvingGround/Levram/IMG/003.png]]

# Exploit 

![[Challenge/ProvingGround/Levram/IMG/004.png]]
จากด้านบนจะเห็นว่า exploit ยังคงมี error โดยไปติดอยู่ที่ Project list ให้ลองทดสอบ Create Project เพิ่มเข้าไป 

![[Challenge/ProvingGround/Levram/IMG/005.png]]

# Shell as app
![[Challenge/ProvingGround/Levram/IMG/006.png]]


# Priv esc

ตรวจสอบ cap บนเครื่องเป้าหมายจะพบว่ามี python 
```bash
getcap -r / 2>/dev/null
```

ref: https://gtfobins.github.io/gtfobins/python/?source=post_page-----d033737f0025---------------------------------------

![[Challenge/ProvingGround/Levram/IMG/007.png]]

# Shell as root 
![[Challenge/ProvingGround/Levram/IMG/008.png]]

# PWN 