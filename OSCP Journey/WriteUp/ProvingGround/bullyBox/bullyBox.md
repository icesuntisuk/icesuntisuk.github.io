
# Recon 
## TCP Scan
```bash
sudo ../tools/scan.sh 192.168.146.27
[*] Running rustscan...
[*] Running nmap on ports: 22,80
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-03 10:28 EDT
Nmap scan report for 192.168.146.27
Host is up (0.034s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b9:bc:8f:01:3f:85:5d:f9:5c:d9:fb:b6:15:a0:1e:74 (ECDSA)
|_  256 53:d9:7f:3d:22:8a:fd:57:98:fe:6b:1a:4c:ac:79:67 (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.71 seconds
```

## TCP 80
![[Pasted image 20250703213142.png]]

![[Pasted image 20250703213208.png]]

จากนั้นทดสอบ Register สำหรับเข้าสู่ระบบ

![[Pasted image 20250703213428.png]]

# Try to search Exploit 
![[Pasted image 20250703213738.png]]
