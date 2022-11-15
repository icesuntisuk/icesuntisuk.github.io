# NEIS1308/NETS2403: การเจาะระบบแบบมีจรรยาบรรณ (Ethical Hacking)

## รายละเอียดรายวิชา
ระบบเครือข่ายและระบบปฏิบัคิการในเชิงลึก เพื่อหาข้อบกพร่องหรือช่องโหว่ ขั้นตอนการทดลองเจาะระบบเทคนิคและเครื่องมือที่ใช้ในการเจาะระบบ การหาจุดบกพร่องของซอฟต์แวร์ การถอดรหัสลับ ไวรัส โทรจัน การดักจับข้อมูล การหาข้อมูลด้านความปลอดภัยจากอินเทอร์เน็ต การทดลองเจาะระบบเว็บไซต์ การตรวจสอบความปลอดภัยเครือข่ายไร้สาย กลไกในการป้องกันระบบจากการบุกรุก การสร้างเครื่องมือสำหรับผู้ทดสอบระบบ จริยธรรมและจรรยาบรรณสำหรับผู้ทดสอบเจาะระบบ การกู้คืนข้อมูล การหาข้อมูล การหาร่องรอยจากการบุกรุกทั้งภายในและภายนอก พ.ร.บ.ว่าด้วยการกระทำความผิดเกี่ยวกับคอมพิวเตอร์

---
ม.เทคโนโลยีมหานคร อาคาร Q ห้อง Q101 

คาบ SAT2: 1030 - 1300

คาบ SAT3: 1330 - 1600

--- 
## Course Syllabus
- Course Introduction
- Network Refresher
- Ethical Hacking Methodology
- Information Gathering
- Scanning & Enumeration
- Vulnerability Scan
- Cryptography
- Exploitation
- Exploit Development (Buffer Overflows) 

---
## Week 1@26 Nov 2022
### Lec 
- Course Introduction
- Ethical Hacking Overview
### Lab 
- Setup environment
- Install VMWare/VirtualBox
- Config netowrk for Hypervisor 
- Install Kali linux
--- 
## Week 2@3 Dec 2022
### Lec
- Network Refresher
  - Introduction
  - OSI Model
  - Layer 2
  - Layer 3
  - Layer 4
  - Common port and Protocols
  - Subnetting
### Lab
- Exploring Kali Linux 
- Sudo Overview 
- Navigating the File System
- Users and Privileges
- Common Network Commands 
- Viewing, Creating and Editing
- Install and Update tools
- Script with Bash
- Know about GIT
--- 
## Week 3@10 Dec 2022
หยุดรัฐธรรมนูญ

--- 
## Week 4@17 Dec 2022
### Lec
- Ethical Hacking Methodology
- Information Gathering (Reconnaissance) 
### Lab
- Passive Recon
- OSINT Framework
  - Identifying target
  - Discovering Email Address
  - Meltego 
  - Hunting Subdomains 
  - Hunting Webtechnology 
  - GHDB 
- Brupsuit
--- 

## Week 5@24 Dec 2022
### Lec
- Scanning & Enumeration
### Lab
- Scanning with Nmap
- Enumeratimg HTTP
- Enumerating SMB
- Enumeration SSH
- Research Potential Vulnerability 
--- 
## Week 6@31 Dec 2022
หยุดวันสิ้นปีใหม่

--- 
## Week 7@7 Jan 2023
### Lec
- VA Scan
### Lab
- Nessus 
- OpenVAS
- Nakivo

--- 
## Week 8@14 Jan 2023
### Lec
- Cryptography 
- Password Attack
### Lab
- Cyberchef
- Bruteforce Attack
--- 

## Week 9@21 Jan 2023
### Lec
- Exploitation
- Bind Shells and Reverse Shell
### Lab
- Bind Shells and Reverse Shell
- MSF 
--- 

## Week 10@28 Jan 2023
### Lec
- Exploit Development (Buffer Overflows)
- Buffer Overflows 

### Lab
- LAB Preparation 
  - Windows 10 or 7
    - Vulnserver (https://github.com/stephenbradshaw/vulnserver)
    - Immunity Debugger
  - Kali Linux
- Spiking 
  - Kali Linux
  - Make Spike script (nano or vim)
  - FIND Vulerable Command by Immunity goto **PAUSED state**

```bash
# Spike script 
# nano stats.spk
s_readline();
s_string("STATS ");
s_string_variable("0");
```

```bash
# TRY to RUN script
generic_send_tcp 192.168.x.x 9999 stats.spk 0 0
```

- Fuzzing 
  - Python Script for FUZZ
```python
#!/usr/bin/python
#FUZZING Script 
import sys, socket
from time import sleep
buffer = "A" * 100
# Enter IP Address of your HOST Here!!!!
HOST = '............'
PORT = 9999

while True:
  try:
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((HOST,PORT))
    s.send(('TRUN /. :/' + buffer))
    s.close()
    sleep(1)
    buffer = buffer + "A"*100
  except:
    print "Fuzzing crashed at %s bytes" % str(len(buffer))
    sys.exit()

 ```

- Find the Offset 
- Overwriting the EIP 
- Finding Bad Characters 
- Finding the Right Mudule
- Generating Shellcode and Gaining Root
- Exploit Development


--- 

## Week 11@21 Jan 2023
### Lec
### Lab

  
--- 

## Week 12@28 Jan 2023
### Lec
### Lab/-

  
--- 

## Week 13@4 Feb 2023
### Lec
### Lab

--- 

## Week 13@11 Feb 2023
### Lec
### Lab
- นักศึกษารายงานผลการ Pentest พร้อมอธิบาย Command อย่างละเอียด
--- 

## Week 14@18 Feb 2023
### Lec
### Lab
- นักศึกษารายงานผลการ Pentest พร้อมอธิบาย Command อย่างละเอียด

--- 


## Week 15@25 Feb 2023
### Lec
### Lab
- นักศึกษารายงานผลการ Pentest พร้อมอธิบาย Command อย่างละเอียด

--- 

## Week 16@4 March 2023
### Lec

### Lab 
รายละเอียด LAB Final exam
- สุ่ม Vulhub Image จากรายงานนักศึกษา จำนวน 2 Images เพื่อนำมาทำการทดสอบระบบ
- รายงานผลการเจาะระบบอย่างละเอียด
- A4 1 แผ่น จดอะไรเข้าไปก็ได้ 
--- 

## Week 17@11-26 March 2023
อาจารย์ต้องส่งข้อสอบ Final ก่อนวันที่ 22 Feb 2023

Final Exam Good luch everybody.

--- 
