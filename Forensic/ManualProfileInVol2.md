### การสร้าง Manual Profile  กรณี Version 2 
- ต้องเป็น Kernel Profile เดียวกันถึงจะสามารถอ่าน Mem ได้ 
- Lime memdump ใช้สำหรับ Dump Memory บน Linux [Linux Memory Extractor](https://github.com/504ensicsLabs/LiME)



```bash
# Step 1: ให้สังเกต EMiL มาจาก Lime แสดงว่ามาจาก Linux 
┌──(kali㉿kali)-[~/Desktop]
└─$ strings rpcactf_dump.mem | head
EMiL <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< อยู่ตรงนี้
PAMS
PAMS
4{,%$l
ZRr=
######

# Step 2: เราสามารถตรวจสอบ Linux Version ได้โดยใช้คำสั่ง ให้สังเกต OS ว่าใช้อะไร  
strings rpcactf_dump.mem | grep "Linux version"
---
Linux version 5.15.0-75-generic (buildd@lcy02-amd64-101) (gcc (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0, GNU ld (GNU Binutils for Ubuntu) 2.34) #82~20.04.1-Ubuntu SMP Wed Jun 7 19:37:37 UTC 2023 (Ubuntu 5.15.0-75.82~20.04.1-generic 5.15.99)
---

# Step 3: กรณีหาเจอแล้วเราสามารถใช้ https://github.com/volatilityfoundation/profiles เพื่อดู Version Profile ที่ตรงกัน 

# Step 4: เราสามารถ Dongrade Version ของ Kernel ได้โดยโหลด 2 ส่วนคือ Kernel และ Header 
sudo apt install linux-image-5.15.0-75-generic linux-headers-5.15.0-75-generic

# Step 5: ตรวจสอบบน /boot จะเห็น system.map-5.15.0
ls /boot/ 

# Step 6: Reboot
init 0

# Step 7: โดยให้เข้าไปยัง Boot Manager โดยการกด Del 

# Step 8:  จากนั้นเลือก Version Kernel 5.15.0-75 เพื่อให้ Boot ด้วย Kernel ตามที่เราต้องการ Downgrade 

# Step 9: ตรวจสอบ Kernel ปัจจุบัน
uname -a 

```
การสร้าง profile ใน Vol2 
```bash
# Step 1: ใช้ Tools สำหรับสร้าง Profiles 
cd ./volatility/tools/linux/

make 
####################################################
# กรณี ERROR
nano module.c
# เพิ่ม บรรทัดล่างสุด 
MODULE_LICENSE("GPL");
# save
####################################################
# หรือใช้คำสั่ง ECHO
echo 'MODULE_LICENSE("GPL");' >> module.c
####################################################

# Make ใหม่อีกครั้ง
make  
####################################################


# Step 2: โปรไฟล์ของ Vol 2 จะเป็นไฟล์นามสกลุ .zip โดยเราสามารถสร้างโปรไฟล์ ด้วยคำสั่งดังนี้ 
sudo zip Ubuntu_20.04-Linux5.15.zip module.dwarf /boot/System.map-5.15.0-75-generic 

# Step 3: ย้ายไฟล์ที่สร้างมาไปไว้ที่ 
mv ./Ubuntu_20.04-Linux5.15.zip /volatility2/plugins/overlays/linux/.
ls -la 

# Step 4: ตรวจสอบ info ขึ้นไหม โดยใช้คำสั่ง จะเห็นโปรไฟล์ที่เราสร้างมาเมื่อซักครู่ 
python2 vol.py --info 

# Step 5: นำ Profile ไปใช้ได้ปกติ
.\vol.exe -f .\imagefile profile=Ubuntu_20.04-Linux5.15 -h 
.\vol.exe -f .\imagefile profile=Ubuntu_20.04-Linux5.15 linux_pslist 

```