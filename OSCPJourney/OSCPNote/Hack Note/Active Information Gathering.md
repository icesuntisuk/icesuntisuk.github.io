#[[host]]

```
#host -t $RECORD_TYPE $TARGET 
host -t A megacorpone.com
```

```
#Manual bruteforcing dns
cat list.txt
www
ftp
mail
owa
proxy
router
# Bruteforce dns
for ip in $(cat list.txt); do host $ip.megacorpone.com; done

# Bruteforce IP 200 - 254 
for ip in $(seq 200 254); do host 51.222.169.$ip; done | grep -v "not found"
```

#[[dnsrecon]]
```
# DNS recon Scan 
# -t to specify the type of enumeration to perform (in this case, a standard scan).
dnsrecon -d megacorpone.com -t std

# DNS Bruteforce
dnsrecon -d megacorpone.com -D ~/list.txt -t brt 
```

#dnsenum

```
#DNS bruteforce 
dnsenum megacorpone.com
```

#[[nslookup]]

```
nslookup -type=TXT info.megacorptwo.com 192.168.50.151 
```

#[[portScan]]

```
#port scan with netcat 
nc -nvv -w 1 -z 192.168.222.52 1-65535 

```
![[ncportscan1.png]]

#[[nmap]]

```
# nmap -Pn -iL <outputFile> -p<portNumber> <target> -oG nmap/smtp_exercise

nmap --script http-* 192.168.50.6 

# Search CVE 
nmap -sV -p- 192.168.222.0/24 

# Scan CVE on target IP 
sudo -sCV -p 443 --script "vuln" 192.168.222.222 

```

#[[rustscan]]

```

# Port Scan 
rustscan -a 192.168.222.0/24 

# Scan port 43 
rustscan -a 192.168.222.0/24 -p 43 

```

#[[powershellPortScan]]

```
Test-NetConnection -Port 445 192.168.50.151
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.50.151", $_)) "TCP port $_ is open"} 2>$null
```

#[[SMB]]

```
# SCA SMB
sudo nmap -Pn -p139,445 -sCV 192.168.222.0/24 

# Windows view file share Command 
net view \\dc01 //all

# Crackmap 
netexec smb 192.168.222.0/24 -u '' -p '' --shares 
netexec smb 192.168.222.0/24 -u 'alfred' -p '' --shares 

# enum4linux 
enum4linux -a 192.168.22.13 
```

#[[SMTP]]

```
rustscan -a 192.168.222.0/24 -p 25 --ulimit 5000 
nc -nv 192.168.50.8 25
```

```python
#!/usr/bin/python

import socket
import sys

if len(sys.argv) != 3:
        print("Usage: vrfy.py <username> <target_ip>")
        sys.exit(0)

# Create a Socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the Server
ip = sys.argv[2]
connect = s.connect((ip,25))

# Receive the banner
banner = s.recv(1024)

print(banner)

# VRFY a user
user = (sys.argv[1]).encode()
s.send(b'VRFY ' + user + b'\r\n')
result = s.recv(1024)

print(result)

# Close the socket
s.close()
```

```
python3 smtp.py root 192.168.50.8
python3 smtp.py johndoe 192.168.50.8

# Windows SMTP
Test-NetConnection -Port 25 192.168.50.8 
# Enable Telnet client 
dism /online /Enable-Feature /FeatureName:TelnetClient
telnet 192.168.50.8
```

#[[SNMP]]

```

sudo nmap -sU --open -p 161 192.168.50.1-254 -oG open-snmp.txt

echo public > community
echo private >> community
echo manager >> community

for ip in $(seq 1 254); do echo 192.168.50.$ip; done > ips
onesixtyone -c community -i ips

snmpwalk -c public -v1 -t 10 192.168.50.151

# WIN USER SNMP 
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.4.1.77.1.2.25
iso.3.6.1.4.1.77.1.2.25.1.1.5.71.117.101.115.116 = STRING: "Guest"
iso.3.6.1.4.1.77.1.2.25.1.1.6.107.114.98.116.103.116 = STRING: "krbtgt"
iso.3.6.1.4.1.77.1.2.25.1.1.7.115.116.117.100.101.110.116 = STRING: "student"
iso.3.6.1.4.1.77.1.2.25.1.1.13.65.100.109.105.110.105.115.116.114.97.116.111.114 = STRING: "Administrator"

# WIN PROCESS SNMP 
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.25.4.2.1.2
iso.3.6.1.2.1.25.4.2.1.2.1 = STRING: "System Idle Process"
iso.3.6.1.2.1.25.4.2.1.2.4 = STRING: "System"
iso.3.6.1.2.1.25.4.2.1.2.88 = STRING: "Registry"
iso.3.6.1.2.1.25.4.2.1.2.260 = STRING: "smss.exe"
iso.3.6.1.2.1.25.4.2.1.2.316 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.372 = STRING: "csrss.exe"
iso.3.6.1.2.1.25.4.2.1.2.472 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.476 = STRING: "wininit.exe"
iso.3.6.1.2.1.25.4.2.1.2.484 = STRING: "csrss.exe"
iso.3.6.1.2.1.25.4.2.1.2.540 = STRING: "winlogon.exe"
iso.3.6.1.2.1.25.4.2.1.2.616 = STRING: "services.exe"
iso.3.6.1.2.1.25.4.2.1.2.632 = STRING: "lsass.exe"
iso.3.6.1.2.1.25.4.2.1.2.680 = STRING: "svchost.exe"

snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.25.6.3.1.2
iso.3.6.1.2.1.25.6.3.1.2.1 = STRING: "Microsoft Visual C++ 2019 X64 Minimum Runtime - 14.27.29016"
iso.3.6.1.2.1.25.6.3.1.2.2 = STRING: "VMware Tools"
iso.3.6.1.2.1.25.6.3.1.2.3 = STRING: "Microsoft Visual C++ 2019 X64 Additional Runtime - 14.27.29016"
iso.3.6.1.2.1.25.6.3.1.2.4 = STRING: "Microsoft Visual C++ 2015-2019 Redistributable (x86) - 14.27.290"
iso.3.6.1.2.1.25.6.3.1.2.5 = STRING: "Microsoft Visual C++ 2015-2019 Redistributable (x64) - 14.27.290"
iso.3.6.1.2.1.25.6.3.1.2.6 = STRING: "Microsoft Visual C++ 2019 X86 Additional Runtime - 14.27.29016"
iso.3.6.1.2.1.25.6.3.1.2.7 = STRING: "Microsoft Visual C++ 2019 X86 Minimum Runtime - 14.27.29016"
...

# WIN TCP Listening port 
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.6.13.1.3
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.88.0.0.0.0.0 = INTEGER: 88
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.135.0.0.0.0.0 = INTEGER: 135
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.389.0.0.0.0.0 = INTEGER: 389
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.445.0.0.0.0.0 = INTEGER: 445
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.464.0.0.0.0.0 = INTEGER: 464
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.593.0.0.0.0.0 = INTEGER: 593
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.636.0.0.0.0.0 = INTEGER: 636
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.3268.0.0.0.0.0 = INTEGER: 3268
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.3269.0.0.0.0.0 = INTEGER: 3269
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.5357.0.0.0.0.0 = INTEGER: 5357
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.5985.0.0.0.0.0 = INTEGER: 5985
...

```


