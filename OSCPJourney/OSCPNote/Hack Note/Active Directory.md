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