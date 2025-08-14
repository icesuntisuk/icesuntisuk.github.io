
# Recon
## TCP Scan

```bash
sudo ../tools/scan.sh 192.168.149.204 
[sudo] password for kali: 
[*] Running rustscan...
[*] Running nmap on ports: 22,80,5000
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-11 04:20 EDT
Nmap scan report for 192.168.149.204
Host is up (0.033s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 f2:5a:a9:66:65:3e:d0:b8:9d:a5:16:8c:e8:16:37:e2 (ECDSA)
|_  256 9b:2d:1d:f8:13:74:ce:96:82:4e:19:35:f9:7e:1b:68 (ED25519)
80/tcp   open  http    Apache httpd 2.4.58 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.58 (Ubuntu)
5000/tcp open  http    Werkzeug httpd 3.0.1 (Python 3.12.3)
|_http-title: Wallpaper Hub - Home
|_http-server-header: Werkzeug/3.0.1 Python/3.12.3
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.79 seconds
```

## TCP 80 
![[Pasted image 20250711152137.png]]

