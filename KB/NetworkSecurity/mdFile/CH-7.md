# CH-7: ระบบตรวจจับและป้องกันการบุกรุก (IDS/IPS)

## วัตถุประสงค์การเรียนรู้ (Learning Objectives)

เมื่อจบบทนี้แล้ว ผู้เรียนสามารถ:
1. อธิบายความแตกต่างระหว่าง IDS, IPS และความสัมพันธ์กับ Firewall ได้
2. อธิบายเทคนิคการตรวจจับแบบ Signature-based, Anomaly-based, และ Behavior-based พร้อมข้อดีข้อเสีย
3. เปรียบเทียบระบบ NIDS/NIPS, HIDS/HIPS, WIDS, และ NBA ได้
4. ติดตั้งและกำหนดค่า Snort / Suricata / Zeek เพื่อตรวจจับการบุกรุกเบื้องต้นได้
5. เขียน Signature Rule สำหรับตรวจจับการโจมตีเฉพาะรูปแบบได้
6. อธิบายวิธีการหลบเลี่ยงการตรวจจับ (Fragmentation, Encoding, Encryption) และแนวทางป้องกัน
7. อธิบายแนวคิดการแจ้งเตือน การตอบสนองอัตโนมัติ และบทบาทของ AI/ML ใน IDS/IPS

---

# ส่วนที่ 1: พื้นฐาน IDS และ IPS

## 1. ความรู้เบื้องต้นเกี่ยวกับ IDS/IPS

### 1.1 IDS (Intrusion Detection System)

IDS คือระบบที่ทำหน้าที่ **ตรวจจับ (Detect)** การบุกรุกหรือพฤติกรรมที่ผิดปกติบนเครือข่ายหรือระบบ โดยทำงานในโหมด **Passive** — ตรวจสอบ Traffic และแจ้งเตือน แต่ไม่บล็อก Traffic

**ลักษณะการทำงานของ IDS:**
- รับสำเนา Traffic (ผ่าน Port Mirroring / SPAN / TAP)
- วิเคราะห์หาลักษณะการโจมตี
- แจ้งเตือนเมื่อตรวจพบเหตุการณ์ที่น่าสงสัย
- **ไม่แทรกแซง** Traffic จริง

```
IDS Mode:
──────────
Traffic Flow:  [Switch] ──(SPAN)──▶ [IDS Sensor]
                     │                    │
                     │              [Alert/Log]
                     ▼
                 [Destination]
```

### 1.2 IPS (Intrusion Prevention System)

IPS คือระบบที่ทำหน้าที่ **ป้องกัน (Prevent)** การบุกรุก โดยทำงานในโหมด **Inline** — ตรวจสอบ Traffic แบบ Real-time และสามารถบล็อก (Block/Drop) Traffic ที่เป็นอันตรายได้ทันที

**ลักษณะการทำงานของ IPS:**
- วางอยู่ในเส้นทาง Traffic (Inline Mode)
- ตรวจสอบ Traffic ทุก Packet แบบ Real-time
- สามารถ Drop, Reject, หรือ Reset Connection ที่เป็นอันตราย
- ทำงานที่ Latency ต่ำ (ต้องไม่เป็น Bottleneck)

```
IPS Mode:
──────────
Traffic Flow:  [Source] ──▶ [IPS Sensor] ──▶ [Destination]
                                 │
                           [Block/Drop หากพบ]
```

### 1.3 ตารางเปรียบเทียบ IDS vs IPS

| คุณสมบัติ | IDS | IPS |
|:----------|:---:|:---:|
| โหมดการทำงาน | Passive (Monitor) | Inline (Active) |
| การวางตำแหน่ง | Out-of-Band (SPAN/TAP) | In-Line กับ Traffic |
| ผลกระทบต่อ Network Latency | ไม่มี (แค่ดู) | อาจมี (ขึ้นอยู่กับประสิทธิภาพ) |
| การ Block Traffic | ❌ ไม่ได้ | ✅ Drop, Reject, Reset |
| ความเสี่ยง False Positive | ต่ำ (แค่แจ้งเตือน) | สูง (อาจ Block Traffic ปกติ) |
| ความต้องการ Resource | ปานกลาง | สูง |
| การตอบสนอง | Manual (Admin ดู Alert) | Automatic (Real-time Block) |
| การทำ Forensic | ✅ ดี (เก็บ Log ได้หมด) | ปานกลาง (Block ก่อนเห็น) |

### 1.4 ความสัมพันธ์กับ Firewall

Firewall และ IDS/IPS เป็นเทคโนโลยีที่เสริมกัน ไม่ใช่แทนที่กัน:

```
การเปรียบเทียบ:
─────────────────
Firewall:  "อนุญาตหรือปฏิเสธตามกฎ"       ← Policy-Based
IDS/IPS:   "ตรวจจับและป้องกันการโจมตี"   ← Threat-Based

Firewall = ประตูรั้วบ้าน    (ใครเข้าออกได้บ้าง)
IDS      = กล้องวงจรปิด     (เฝ้าดูว่ามีคนร้ายไหม)
IPS      = รปภ.ที่ประตู     (ตรวจสอบและห้ามคนร้ายเข้าทันที)
```

| อุปกรณ์ | การตัดสินใจ | ขึ้นอยู่กับ | ตัวอย่าง |
|:--------|:-----------|:-----------|:---------|
| Firewall | Allow / Deny | IP:Port, Protocol, App-ID, User-ID | ปฏิเสธ SSH จาก Internet |
| IDS | Alert / Log | Signature, Anomaly, Behavioral Pattern | แจ้งเตือนเมื่อพบ SQL Injection |
| IPS | Block / Pass | Signature, Anomaly, Reputation | บล็อก Traffic ที่มี Payload ของ Exploit |
| NGFW | Allow / Deny + IPS | รวมทุกอย่าง | Allow HTTPS แต่ตรวจสอบ SSL ด้วย IPS |

---

## 2. ประเภทของ IDS/IPS

### 2.1 Network-based IDS/IPS (NIDS/NIPS)

**ตำแหน่ง:** วางบนจุดยุทธศาสตร์ของเครือข่าย — ตรวจสอบ Traffic ที่ผ่านทั้ง Segment

**ข้อดี:**
- ตรวจสอบ Traffic ในวงกว้าง — ครอบคลุมหลายระบบ
- ติดตั้งง่าย — ไม่ต้องติดตั้ง Agent บนโฮสต์
- ไม่ส่งผลกระทบต่อระบบที่ได้รับการตรวจสอบ
- ตรวจจับการโจมตีที่มุ่งเป้าไปที่ Network Protocol

**ข้อจำกัด:**
- ตรวจสอบ Traffic ที่เข้ารหัส (SSL/TLS) ไม่ได้ (ถ้าไม่มี SSL Decryption)
- อาจไม่เห็น Traffic ใน Switch Segment ที่ไม่ได้ Mirror
- ประสิทธิภาพเป็นปัญหากับเครือข่ายความเร็วสูง (40G, 100G)
- ไม่สามารถตรวจจับการโจมตีที่เกิดขึ้นภายในโฮสต์ได้

```
การวาง NIDS:
─────────────
Internet ──▶ [Firewall] ──▶ [Switch] ──▶ Internal Network
                                  │
                             [SPAN Port]
                                  │
                             [NIDS Sensor]
                                  │
                            [SIEM / Alert]
```

### 2.2 Host-based IDS/IPS (HIDS/HIPS)

**ตำแหน่ง:** ติดตั้งเป็น Agent บนเครื่อง Server, Workstation, หรือ Endpoint

**ข้อดี:**
- ตรวจสอบกิจกรรมภายในโฮสต์ — File Access, Process, Registry, System Call
- ตรวจจับการโจมตีที่ NIDS ไม่เห็น (Encrypted Traffic, Local Attack)
- ตรวจสอบ Integrity ของไฟล์ (File Integrity Monitoring — FIM)
- ตรวจจับ Malware ที่ทำงานบนเครื่อง

**ข้อจำกัด:**
- ใช้ทรัพยากรของโฮสต์ (CPU, RAM, Disk)
- ต้องติดตั้งและจัดการ Agent ทุกเครื่อง
- อาจถูกโจมตีปิดการทำงาน (Disable) หากผู้โจมตีได้สิทธิ์ Admin
- ไม่เห็นภาพรวมของเครือข่าย

**ตัวอย่าง HIDS ที่นิยม:**
- **OSSEC:** Open Source HIDS — Log Analysis, FIM, Rootkit Detection
- **Wazuh:** Fork ของ OSSEC — รวมกับ SIEM และ Elastic Stack
- **Osquery:** ใช้ SQL Query เพื่อตรวจสอบระบบ (Facebook)
- **Sysmon (Microsoft):** เก็บ Event Detail บน Windows

```
ตัวอย่าง Log จาก OSSEC HIDS:
─────────────────────────────
** Alert 1712839200.12345 - syscheck
Rule: 550 (syscheck_new_entry)
File: /etc/shadow
Action: added
User: root
Hostname: webserver01
```

### 2.3 Wireless IDS/IPS (WIDS/WIPS)

**ตำแหน่ง:** ตรวจสอบคลื่นวิทยุ 802.11 เพื่อตรวจจับภัยคุกคามทาง Wi-Fi

**ความสามารถ:**
- ตรวจจับ Rogue Access Point
- ตรวจจับ Evil Twin Attack
- ตรวจจับ Deauthentication Attack
- ตรวจจับ KRACK และ WPA2 Vulnerability Exploitation
- ตรวจจับ Client Misassociation

### 2.4 Network Behavior Analysis (NBA)

NBA วิเคราะห์พฤติกรรมของ Traffic ในภาพรวม (ไม่เน้นที่เนื้อหาแต่ละ Packet) เพื่อตรวจจับ Anomaly:

**สิ่งที่ NBA ตรวจจับ:**
- **Traffic Spike:** การโจมตี DDoS หรือ WannaCry-style Worm Propagation
- **Unusual Protocol:** Protocol ที่ไม่เคยปรากฏในเครือข่ายมาก่อน
- **Beaconing:** การติดต่อ Command & Control (C2) เป็นช่วงๆ
- **Data Exfiltration:** การส่งข้อมูลปริมาณมากออกนอกเครือข่ายผิดปกติ

```
ตัวอย่าง NBA Detection:
────────────────────────
Time 00:00 - 06:00:  Traffic = 150 Mbps (Baseline)
Time 06:00 - 06:05:  Traffic = 3.2 Gbps (Anomaly detected)
Time 06:05:          Alerta! — DDoS Attack suspected
                     Source IPs: 12,847 unique IPs
                     Dest Port:  443 (HTTPS)
                     Action:     Blackhole routing triggered
```

### 2.5 ตารางเปรียบเทียบประเภท IDS/IPS

| ประเภท | ตำแหน่ง | ตรวจสอบ | จุดเด่น | จุดอ่อน |
|:-------|:-------|:--------|:-------|:--------|
| NIDS/NIPS | เครือข่าย | Network Traffic | ครอบคลุมหลายระบบ | ไม่เห็น Encrypted Traffic |
| HIDS/HIPS | โฮสต์ | System Calls, Files, Processes | ละเอียดระดับโฮสต์ | ใช้ทรัพยากรโฮสต์ |
| WIDS/WIPS | อากาศ | 802.11 Frames | ตรวจจับ Rogue AP | ครอบคลุมเฉพาะ Wi-Fi |
| NBA | เครือข่าย | Traffic Pattern | ตรวจจับ Anomaly | ไม่ตรวจจับ Attack Detail |

---

# ส่วนที่ 2: เทคนิคการตรวจจับ

## 3. Signature-based Detection

### 3.1 หลักการ

Signature-based Detection เปรียบเทียบกิจกรรมบนเครือข่ายหรือระบบกับ **ลายเซ็น (Signature)** ของการโจมตีที่รู้จัก — คล้ายกับ Antivirus ที่ใช้ Virus Definition ในการตรวจจับ Malware

**ตัวอย่าง Signature (รูปแบบง่าย):**
```
ตรวจจับ:   /etc/passwd ใน HTTP Request → Path Traversal Attack
Signature: content:"/etc/passwd"; http_uri;
```

### 3.2 ประเภทของ Signature

| ประเภท Signature | คำอธิบาย | ตัวอย่าง |
|:-----------------|:---------|:---------|
| **Content-Based** | ตรงกับ Byte Sequence ใน Payload | `content:"|FF D8 FF E0|"` (JPEG Header) |
| **Context-Based** | ตรวจสอบตามบริบท (ขนาด, ความถี่) | `dsize:>1000;` (Packet Size) |
| **Protocol-Based** | ตรวจสอบตาม Protocol RFC | ตรวจสอบ HTTP Header ที่ผิดปกติ |
| **State-Based** | ตรวจสอบตาม State ของ Connection | Login Fail ติดต่อกัน 5 ครั้ง |
| **Compound** | หลายเงื่อนไขรวมกัน | Content + Size + Port |

### 3.3 Snort Rule — รูปแบบและไวยากรณ์

Snort Rule แบ่งเป็น 2 ส่วน: **Rule Header** และ **Rule Options**

```
โครงสร้าง Snort Rule:
─────────────────────
[Action] [Protocol] [Source IP] [Source Port] → [Dest IP] [Dest Port] ([Options])

ตัวอย่าง:
alert   tcp        any          any         →   any          80    (msg:"SQL Injection Detected"; content:"SELECT"; nocase; sid:1000001;)
```

**ส่วนประกอบของ Rule Header:**
- `alert` — Action: alert, log, pass, drop, reject, sdrop
- `tcp` — Protocol: tcp, udp, icmp, ip
- `any any` — Source IP และ Port (หรือระบุเจาะจง)
- `→` — ทิศทาง (→, <>, ←)
- `any 80` — Destination IP และ Port

**ส่วนประกอบของ Rule Options (คั่นด้วย ;):**
- `msg:"..."` — ข้อความแจ้งเตือน
- `content:"..."` — Byte Pattern ที่ต้องการค้นหา
- `nocase` — ไม่สนใจตัวพิมพ์เล็ก-ใหญ่
- `sid:XXXX` — Signature ID (ไม่ซ้ำกัน)
- `rev:N` — Revision Number
- `reference:...,...` — ลิงก์อ้างอิง (CVE, URL)
- `classtype:...` — ประเภทการโจมตี

### 3.4 ตัวอย่าง Snort Rules

**Rule 1: ตรวจจับ SQL Injection พื้นฐาน**
```
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
    msg:"SQL Injection - UNION SELECT Detected";
    content:"UNION"; nocase;
    content:"SELECT"; nocase; distance:0; within:10;
    flow:to_server,established;
    sid:1000001; rev:1;
    classtype:web-application-attack;
    reference:cve,2023-1234;
)
```

**Rule 2: ตรวจจับ Buffer Overflow ใน HTTP Header**
```
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
    msg:"Buffer Overflow - Long HTTP Header";
    dsize:>4096;
    flow:to_server,established;
    sid:1000002; rev:1;
    classtype:attempted-admin;
)
```

**Rule 3: ตรวจจับ Port Scan**
```
alert tcp $EXTERNAL_NET any -> $HOME_NET any (
    msg:"Port Scan Detected";
    flags:S;          # SYN flag only
    threshold:type both, track by_src, count 20, seconds 10;
    sid:1000003; rev:1;
    classtype:attempted-recon;
)
```

**Rule 4: ตรวจจับ Malware C2 Beaconing**
```
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (
    msg:"Malware C2 Beacon - Suspicious User-Agent";
    content:"User-Agent|3A|"; http_header;
    content:"Mozilla/5.0"; distance:0;
    pcre:"/^User-Agent:\s*\S{10,30}$/Hmi";
    flow:to_server,established;
    sid:1000004; rev:1;
    classtype:trojan-activity;
)
```

### 3.5 ข้อดีและข้อจำกัดของ Signature-based Detection

**ข้อดี:**
- ความแม่นยำสูงสำหรับการโจมตีที่รู้จัก (False Positive ต่ำ)
- ตรวจจับได้เร็ว — ใช้ Resource น้อย
- สามารถระบุประเภทการโจมตีที่แน่นอนได้
- ง่ายต่อการอัปเดต (เพิ่ม Signature ใหม่เมื่อรู้จัก Attack ใหม่)

**ข้อจำกัด:**
- **ไม่สามารถตรวจจับ Zero-Day Attack** — การโจมตีที่ไม่มี Signature
- **Signature Evasion** — ผู้โจมตีสามารถหลบเลี่ยงได้ (Polymorphic Code, Encoding)
- ต้องอัปเดต Signature Database อย่างสม่ำเสมอ
- Signature ที่ซับซ้อนเกินไปอาจทำให้ประสิทธิภาพลดลง
- **False Negative สูง** หาก Signature ไม่ตรงกับ Variant ของการโจมตี

---

## 4. Anomaly-based Detection

### 4.1 หลักการ

Anomaly Detection สร้าง **Baseline** ของพฤติกรรมปกติของเครือข่ายหรือระบบ แล้วแจ้งเตือนเมื่อพฤติกรรมเบี่ยงเบนไปจาก Baseline อย่างมีนัยสำคัญ

**กระบวนการทำงาน:**
1. **Learning Phase (Training):** เก็บข้อมูลพฤติกรรมปกติในช่วงเวลาหนึ่ง (1-4 สัปดาห์)
2. **Modeling:** สร้าง Statistical Model ของพฤติกรรมปกติ
3. **Detection Phase:** เปรียบเทียบพฤติกรรมปัจจุบันกับ Model
4. **Alerting:** เมื่อค่าเบี่ยงเบนเกิน Threshold ที่กำหนด

### 4.2 ประเภทของ Anomaly Detection

| ประเภท | สิ่งที่วัด | ตัวอย่าง |
|:-------|:---------|:---------|
| **Statistical** | ค่าเฉลี่ย, SD, Distribution | Traffic ที่เพิ่มขึ้น 5 SD จากค่าเฉลี่ย |
| **Machine Learning** | Pattern จาก Train Set | แยก Normal/Attack ด้วย Decision Tree |
| **Protocol-based** | การปฏิบัติตาม RFC | HTTP Request ที่ผิดรูปแบบ |
| **Traffic-based** | ปริมาณ, ความถี่, Flow Size | ICMP Flood, DNS Amplification |

### 4.3 Behavioral-based Detection (UEBA)

UEBA (User and Entity Behavior Analytics) คือเทคนิค Anomaly Detection ที่มุ่งเน้นพฤติกรรมของผู้ใช้และอุปกรณ์:

**พฤติกรรมที่ UEBA ตรวจสอบ:**
- **User Login:** เวลา, สถานที่, อุปกรณ์ที่ผิดปกติ
- **Data Access:** การเข้าถึงข้อมูลที่ไม่เคยเข้าถึงมาก่อน
- **Lateral Movement:** การเข้าถึงระบบอื่นหลังจาก Login
- **Privilege Escalation:** การใช้สิทธิ์ที่สูงขึ้นผิดปกติ

```
ตัวอย่าง UEBA Alert:
────────────────────
User: john.smith (HR Department)
Event: Logged into DB Server (db-prod-01) at 03:14 AM
       This is the FIRST time this user accessed this server.
       User has NEVER logged in outside business hours (08:00-18:00).
       GeoIP: Login from 185.220.101.x (Tor Exit Node)

Risk Score: 92/100 → 🔴 CRITICAL
MITRE ATT&CK: T1078 (Valid Accounts) + T1530 (Data from Cloud Storage)
```

### 4.4 ข้อดีและข้อจำกัดของ Anomaly-based Detection

**ข้อดี:**
- ตรวจจับ Zero-Day Attack และ Novel Attack ได้
- ตรวจจับ Insider Threat ที่ใช้ Credentials ถูกต้อง
- ปรับตัวตามสภาพแวดล้อมได้ (Adaptive Baseline)
- ตรวจจับ Malware C2 Beaconing และ Data Exfiltration ได้ดี

**ข้อจำกัด:**
- **False Positive สูง** — การเปลี่ยนแปลงปกติ (Maintenance, การใช้งานตามฤดูกาล) อาจได้รับการตีความว่าเป็น Anomaly
- ต้องมีข้อมูล Training ที่เพียงพอ
- Baseline อาจล้าสมัย (Concept Drift)
- ผู้โจมตีสามารถ "ฝึก" ระบบให้ชินกับพฤติกรรมผิดปกติได้ (Slow Drip Exfiltration)
- ใช้ทรัพยากรมากกว่า Signature-based

---

## 5. Stateful Protocol Analysis

### 5.1 หลักการ

Stateful Protocol Analysis ตรวจสอบ Protocol Traffic ตามที่กำหนดใน RFC (Request for Comments) โดยติดตาม State ของ Protocol Session ตั้งแต่ต้นจนจบ

### 5.2 Protocol Violation Detection

ตรวจจับการกระทำที่ไม่เป็นไปตาม Protocol RFC:

```
ตัวอย่าง Protocol Violation:
─────────────────────────────
1. SMTP: Command Sequence ผิด → RCPT TO ก่อน MAIL FROM
2. HTTP: Content-Length ≠ Actual Body Size
3. TLS: Certificate ที่หมดอายุหรือ Self-Signed
4. DNS: Response ที่มี Size เกิน 512 bytes โดยไม่มี EDNS0
5. TCP: Flag Combination ที่ผิดปกติ (SYN-FIN, SYN-RST)
```

### 5.3 การตรวจจับที่ซับซ้อนด้วย Protocol Analysis

```
ตัวอย่าง: ตรวจจับ HTTP Request Smuggling
────────────────────────────────────────
การโจมตี: ส่ง HTTP Request ที่มี Content-Length และ Transfer-Encoding
           พร้อมกัน — ทำให้ Front-end Proxy และ Back-end Server
           ตีความ Body แตกต่างกัน

Detection Signature ใน Suricata:
─────────────────────────────────
alert http any any -> any any (
    msg:"HTTP Request Smuggling - CL.TE";
    flow:to_server,established;
    http.request_header;
    content:"Transfer-Encoding"; nocase;
    content:"Content-Length"; nocase;
    sid:2000001; rev:1;
)
```

### 5.4 ข้อดีและข้อจำกัด

**ข้อดี:**
- แม่นยำสำหรับ Protocol-Level Attack
- ตรวจจับ Attack ที่ Signature-Based อาจพลาดได้
- ช่วยลด False Positive (เข้าใจ Context ของ Protocol)

**ข้อจำกัด:**
- ใช้ทรัพยากรมาก (ต้อง Decode Protocol แต่ละ Layer)
- Protocol ใหม่ๆ ต้องเขียน Parser ใหม่
- Protocol ที่ซับซ้อน (SMB, DCE/RPC) ต้องใช้ Parser ขนาดใหญ่
- อาจมี Bugs ใน Parser เอง (Protocol Parser Vulnerability)

---

## 6. การหลบเลี่ยงการตรวจจับ (Evasion Techniques)

### 6.1 Fragmentation

ผู้โจมตีแบ่ง Payload ออกเป็น Fragment ย่อยๆ เพื่อหลบเลี่ยง Signature ที่รอ Pattern ใน Packet เดียว:

```
Normal Packet:
────────────────────────────────────────
[IP Header] [TCP Header] [GET /etc/passwd HTTP/1.1]

Fragmented:
────────────────────────────────────────
Fragment 1: [IP Header] [TCP Header] [GET /etc]
Fragment 2: [IP Header] [/passwd HTT]
Fragment 3: [IP Header] [P/1.1]

IDS: แต่ละ Fragment อาจไม่ตรง Signature
IPS/Firewall: ต้อง Reassemble ก่อนตรวจสอบ
```

**การป้องกัน:** IDS/IPS ต้องทำ IP Reassembly และ TCP Reassembly ก่อนตรวจสอบ — Snort ใช้ `frag3` Preprocessor

### 6.2 Encoding

ผู้โจมตีแปลง Payload ให้อยู่ในรูปแบบอื่นที่ Server เข้าใจ แต่ IDS อาจไม่เข้าใจ:

```
SQL Injection แบบเข้ารหัส:
───────────────────────────
ปกติ:     ' OR 1=1 --
Hex:      0x27204f5220313d31202d2d
URL Encode: %27%20OR%201%3D1%20--
Unicode:  %u0027%u0020OR%u00201%u003D1%u0020%u002D%u002D
Base64:   JyBPUiAxPTEgLS0=
UTF-16:   \x27\x00\x20\x00\x4F\x00\x52\x00\x20\x00...

IDS ที่ตรวจเจอ: ' OR 1=1 --
IDS ที่ตรวจเจอ: %27%20OR%201%3D1%20-- ❌ (อาจไม่ detect ถ้าไม่มี Signature)
```

**การป้องกัน:** IDS ต้องมี Normalization Engine ที่แปลง Encoding กลับเป็นรูปแบบปกติก่อนตรวจสอบ (Snort: `http_inspect`, Suricata: `http.request_uri`)

### 6.3 Encryption

Traffic ที่เข้ารหัส (HTTPS, SSH, VPN) ทำให้ IDS/IPS ไม่สามารถตรวจสอบ Content ได้:

```
Client ──[HTTPS Encrypted]──▶ Server
         │
    NIDS ❌ (มองไม่เห็น Content)
         │
SSL Forward Proxy:  ตรวจสอบได้ (แต่ต้องติดตั้ง CA)
```

**ทางออก:**
1. **SSL Decryption (SSL Forward Proxy)** — ถอดรหัส ตรวจสอบ แล้วเข้ารหัสใหม่
2. **Traffic Metadata Analysis** — ตรวจสอบขนาด Packet, Timing, Certificate Info (JA3 Fingerprint)
3. **HIDS** — Agent บนเครื่องสามารถมองเห็น Traffic หลังจาก Decryption แล้ว

### 6.4 Protocol Obfuscation

ผู้โจมตีใช้ Protocol ที่ผิดปกติหรือซ่อน Traffic ใน Protocol ที่อนุญาต:

```
Tunneling ใน DNS:
───────────────────
Client query:   c2VjcmV0X2RhdGE=.malware-c2.evil.com
DNS Response:   TXT "Y29tbWFuZCA9IGNhdCAvZXRjL3Bhc3N3ZA=="

IDS: DNS Query ปกติ → อาจไม่ตรวจสอบ TXT Record Detail
Prevention: DNS Sinkhole, DNS Firewall with DPI
```

### 6.5 Tool-Assisted Evasion

เครื่องมือที่นิยมใช้หลบเลี่ยง IDS:

| เครื่องมือ | เทคนิค | รายละเอียด |
|:----------|:-------|:-----------|
| **Nmap** | Multiple Scan Techniques | FIN Scan, NULL Scan, Fragment Scan, Decoy Scan |
| **Metasploit** | Payload Encoding | `shikata_ga_nai` — Polymorphic XOR Encoder |
| **SQLMap** | SQL Injection Evasion | Tamper Scripts — Space2Comment, Char2Encode |
| **Veil** | AV/IDS Evasion | เครื่องมือสร้าง Payload ที่หลบเลี่ยง Signature |
| **HTTPS Tunneling** | Protocol Tunneling | ซ่อน C2 Traffic ใน HTTPS |

---

# ส่วนที่ 3: เครื่องมือ IDS/IPS

## 7. Snort

### 7.1 ภาพรวม

Snort คือ Open Source NIDS/NIPS ที่พัฒนาโดย Martin Roesch ในปี 1998 (ปัจจุบันเป็นของ Cisco) เป็นเครื่องมือ IDS/IPS ที่ได้รับการใช้อย่างแพร่หลายที่สุดในโลก

**โหมดการทำงาน:**
- **Sniffer Mode:** อ่าน Packet แล้วแสดงบน Console
- **Packet Logger Mode:** บันทึก Packet ลง Disk
- **NIDS Mode:** วิเคราะห์ Traffic ตาม Rule Set
- **Inline Mode:** ทำงานเป็น IPS (กับ iptables/NFQueue)

### 7.2 สถาปัตยกรรม Snort

```
                            Snort Engine
┌──────────────────────────────────────────────────────────┐
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐ │
│  │ Decode   │  │Preproces-│  │Detection │  │Output    │ │
│  │ Engine   │─▶│sor       │─▶│Engine    │─▶│Module    │ │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘ │
│        │            │              │              │       │
│  Libpcap/    frag3,    Rule Pattern   Alert: syslog, │
│  NFQueue     stream5,  Matching       unified2, JSON  │
│              http_inspect              (lua output)   │
└──────────────────────────────────────────────────────────┘
```

**ส่วนประกอบ:**
1. **Decoder:** แยกส่วนประกอบของ Packet (Ethernet, IP, TCP, UDP, ICMP)
2. **Preprocessors:** จัดเตรียมข้อมูลก่อนส่งให้ Detection Engine (Reassembly, Normalization)
3. **Detection Engine:** เปรียบเทียบ Packet กับ Rule Set
4. **Output Module:** จัดการการแจ้งเตือน (Syslog, Database, JSON File)

### 7.3 Preprocessors ที่สำคัญ

| Preprocessor | หน้าที่ |
|:-------------|:--------|
| `frag3` | IP Fragmentation Reassembly |
| `stream5` | TCP Stream Reassembly, State Tracking |
| `http_inspect` | HTTP Normalization, De-obfuscation |
| `ssl_preprocessor` | ตรวจสอบ SSL/TLS Handshake |
| `smtp_preprocessor` | ตรวจสอบ SMTP Command |
| `dns_preprocessor` | ตรวจสอบ DNS Query/Response |
| `portscan` | ตรวจจับ Port Scan |
| `arp_spoof` | ตรวจจับ ARP Spoofing |

### 7.4 การติดตั้งและการกำหนดค่าพื้นฐาน

```bash
# ติดตั้ง Snort บน Ubuntu/Debian
sudo apt-get install snort

# ไฟล์ config หลัก: /etc/snort/snort.conf
# ไฟล์ rules: /etc/snort/rules/

# ทดสอบ Snort Configuration
sudo snort -T -c /etc/snort/snort.conf

# รัน Snort ในโหมด NIDS
sudo snort -q -A console -c /etc/snort/snort.conf -i eth0

# รัน Snort ในโหมด IPS (Inline)
sudo snort -Q -c /etc/snort/snort.conf -i eth0:eth1
```

### 7.5 การจัดการ Rule Set

Snort ใช้ Rule Set จากแหล่งต่างๆ:

| Rule Set | แหล่งที่มา | จำนวน Rule | ค่าใช้จ่าย |
|:---------|:-----------|:-----------|:----------|
| **Community Rules** | snort.org | ~3,000 | ฟรี |
| **Registered Rules** | snort.org (สมัครฟรี) | ~10,000 | ฟรี |
| **Subscriber Rules** | Talos Intelligence | ~20,000+ | จ่ายเงิน |
| **Emerging Threats (ET)** | proofpoint.com | ~30,000+ | ฟรี/Pro |
| **ET Pro** | proofpoint.com | ~35,000+ | จ่ายเงิน |

---

## 8. Suricata

### 8.1 ภาพรวม

Suricata คือ Open Source IDS/IPS/NSM Engine ที่พัฒนาโดย OISF (Open Information Security Foundation) ในปี 2010 ออกแบบมาเพื่อใช้ประโยชน์จาก Multi-threading และ Hardware Acceleration

### 8.2 ข้อแตกต่างระหว่าง Snort และ Suricata

| คุณสมบัติ | Snort | Suricata |
|:----------|:-----:|:--------:|
| Multi-threading | ❌ (Single Thread) | ✅ (Multi-thread — Auto Scaling) |
| GPU Acceleration | ❌ | ✅ (CUDA, OpenCL) |
| Protocol Detection | ต้องใช้ Preprocessor | ✅ Built-in (HTTP, DNS, TLS, SMB, FTP) |
| IP Reputation | ❌ | ✅ Built-in |
| File Extraction | จำกัด | ✅ Full |
| Lua Scripting | ❌ | ✅ |
| JSON Output | ผ่าน Plugin | ✅ Native |
| PF_RING/AF_PACKET | จำกัด | ✅ รองรับดี |
| Performance (10Gbps+) | ต้อง Tuning มาก | ✅ รองรับดีกว่า |

### 8.3 สถาปัตยกรรม Suricata

```
                           Suricata Engine
┌──────────────────────────────────────────────────────────────┐
│  ┌──────────┐  ┌─────────────┐  ┌──────────┐  ┌──────────┐ │
│  │ Receive   │  │ Decode +    │  │ Detect   │  │ Output   │ │
│  │ Packets   │─▶│ Stream/App  │─▶│ Engine   │─▶│ (JSON,   │ │
│  │ (Multi)   │  │ Layer       │  │ (Multi)  │  │  Eve)    │ │
│  └──────────┘  └─────────────┘  └──────────┘  └──────────┘ │
│        │              │              │              │        │
│  AF_PACKET/    HTTP, DNS, TLS,   Hyperscan/       eve.json │
│  PF_RING       SMB, FTP Parser   Pattern Match              │
│  (Multi Queue)                                            │
└──────────────────────────────────────────────────────────────┘
```

### 8.4 การติดตั้งและการใช้งาน Suricata

```bash
# ติดตั้ง Suricata บน Ubuntu/Debian
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt-get update
sudo apt-get install suricata

# ไฟล์ config: /etc/suricata/suricata.yaml
# Rule path: /etc/suricata/rules/

# ทดสอบ config
sudo suricata -T -c /etc/suricata/suricata.yaml

# รัน Suricata (IDS Mode)
sudo suricata -c /etc/suricata/suricata.yaml -i eth0

# ดูผลลัพธ์แบบ Real-time (eve.json)
sudo tail -f /var/log/suricata/eve.json | jq 'select(.alert) | {timestamp, signature, src_ip, dest_ip}'

# อัปเดต Rules
sudo suricata-update
sudo suricata-update enable-source et/open
sudo systemctl restart suricata
```

### 8.5 Suricata Rule (คล้าย Snort แต่เพิ่มเติม)

```
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"ET MALWARE Possible C2 Beacon";
    flow:to_server,established;
    content:"/gate.php"; http_uri;
    content:"host="; http_client_body;
    content:"pass="; http_client_body;
    pcre:"/^host=[a-z0-9]{16,32}$/Pi";
    pcre:"/^pass=[a-f0-9]{32}$/Pi";
    sid:2834721; rev:3;
    classtype:trojan-activity;
)
```

---

## 9. Zeek (เดิมชื่อ Bro)

### 9.1 ภาพรวม

Zeek คือ Network Security Monitoring (NSM) Framework ที่พัฒนาโดย Lawrence Berkeley National Laboratory แตกต่างจาก Snort/Suricata ตรงที่ Zeek ไม่ได้เป็น IDS ในความหมายเดิม — แต่เป็น **Event-driven Network Analysis Framework** ที่เน้นการบันทึกและวิเคราะห์ Network Activity มากกว่าการ Match Pattern

### 9.2 สถาปัตยกรรม Zeek

```
                   Zeek Framework
┌──────────────────────────────────────────────────────┐
│  ┌──────────────┐         ┌──────────────┐           │
│  │ Event Engine  │         │  Policy       │          │
│  │ (C++)         │────────▶│  Script       │          │
│  │               │  Events │  Interpreter  │          │
│  │ - Libpcap     │         │  (Bro Script) │          │
│  │ - Stream      │         │              │          │
│  │ - Protocol    │         │ - conn.log   │          │
│  │   Parsers     │         │ - http.log   │          │
│  └──────────────┘         │ - dns.log     │          │
│                            │ - ssl.log     │          │
│                            │ - files.log   │          │
│                            └──────────────┘          │
└──────────────────────────────────────────────────────┘
```

### 9.3 ความแตกต่างระหว่าง Zeek และ Snort/Suricata

| คุณสมบัติ | Snort/Suricata | Zeek |
|:----------|:-------------:|:----:|
| แนวคิดหลัก | Signature Matching | Event Analysis & Logging |
| ภาษา Rule | Rule Language | Bro Script (Turing-complete) |
| Output | Alert เป็นหลัก | Log ทุกกิจกรรม + Alert |
| Stateful Protocol | จำกัด | ✅ สมบูรณ์ |
| การวิเคราะห์ | Real-time Pattern Match | Real-time Event + Offline Analysis |
| ความสามารถ Script | จำกัด | สูง (ภาษาโปรแกรมมิ่ง) |
| Forensic Capability | ต่ำ (แค่ Alert) | สูง (Log รายละเอียดทุกอย่าง) |
| การ Integrate | ง่าย (Alert → SIEM) | ต้องพัฒนา Script |

### 9.4 Zeek Logs

```
# conn.log — ทุก Connection ที่เกิดขึ้น
172.16.0.8  53322   192.168.1.100 80   tcp   http   1200  3500   SF   ...

# http.log — ทุก HTTP Request
GET   /index.php    HTTP/1.1    200   OK   Mozilla/5.0   ...

# dns.log — ทุก DNS Query
example.com   A    192.0.2.1    TTL=3600   ...

# ssl.log — ทุก TLS Handshake
server.com    TLSv1.3    TLS_AES_256_GCM_SHA384   valid   ...

# files.log — ทุกไฟล์ที่ส่งผ่านเครือข่าย
image.jpg   image/jpeg    MD5=...   SHA1=...
```

### 9.5 ตัวอย่าง Zeek Script

```zeek
# ตรวจจับ HTTP Request ที่มี SQL Injection Patterns
event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string) {
    
    # SQL Injection Patterns
    local sql_patterns = /SELECT|UNION|DROP|INSERT|DELETE|--/;
    # XSS Patterns
    local xss_patterns = /<script|<iframe|onerror|onload/;
    
    if (sql_patterns in unescaped_URI) {
        NOTICE([$note=SQL_Injection,
                $msg=fmt("SQL Injection detected: %s", unescaped_URI),
                $conn=c]);
    }
    
    if (xss_patterns in unescaped_URI) {
        NOTICE([$note=XSS_Attack,
                $msg=fmt("XSS detected: %s", unescaped_URI),
                $conn=c]);
    }
}
```

---

## 10. การแจ้งเตือน การตอบสนอง และ AI ใน IDS/IPS

### 10.1 แนวคิดการแจ้งเตือน

การแจ้งเตือนที่มีประสิทธิภาพต้องคำนึงถึง:

**1. ลำดับความสำคัญ (Priority):**
```
CRITICAL (P1):  การโจมตีที่กำลังดำเนินการ — ต้องตอบสนองทันที
HIGH (P2):      การโจมตีที่อาจสำเร็จ — ต้องตรวจสอบภายใน 1 ชม.
MEDIUM (P3):    การสแกนหรือ Recon — ตรวจสอบภายใน 24 ชม.
LOW (P4):       Policy Violation, Anomaly — ตรวจสอบตามปกติ
```

**2. การลด False Positive:**
- ใช้ Thresholding — แจ้งเตือนเฉพาะเมื่อเหตุการณ์เกิดซ้ำ N ครั้งในเวลา T
- ใช้ Whitelist — ไม่แจ้งเตือน Traffic จาก Source ที่เชื่อถือได้
- ใช้ Correlation — ต้องมีหลายเงื่อนไขประกอบกันจึงแจ้งเตือน
- ใช้ TI (Threat Intelligence) Feed — ตรวจสอบเฉพาะ IP ที่มี Reputation ไม่ดี

**3. การส่ง Alert:**
```
Alert Pipeline:
───────────────
IDS/IPS → Syslog/JSON → SIEM (Splunk, ELK, QRadar)
                        → Ticketing (ServiceNow, Jira)
                        → Notification (Email, Slack, PagerDuty)
                        → SOAR Playbook (ตอบสนองอัตโนมัติ)
```

### 10.2 การตอบสนองอัตโนมัติ (Automated Response)

**SOAR (Security Orchestration, Automation and Response):**

```
SOAR Playbook — Ransomware Response:
─────────────────────────────────────
Trigger: 🚨 IDS Alert — Ransomware File Extension Detected
Step 1:  🔍 Isolate infected host (via NAC/EDR API)
Step 2:  🛑 Block C2 IP on Firewall (via API)
Step 3:  📸 Snapshot memory and disk (for forensics)
Step 4:  📧 Notify IR team via PagerDuty
Step 5:  📝 Create ticket in ServiceNow (Critical Priority)
Step 6:  📊 Update SIEM with case metadata
```

### 10.3 AI และ Machine Learning ใน IDS/IPS

**บทบาทของ AI/ML:**

| เทคนิค | การประยุกต์ใช้ |
|:-------|:--------------|
| **Supervised Learning (Random Forest, XGBoost)** | แยกประเภท Traffic ว่า Normal หรือ Attack |
| **Unsupervised Learning (K-Means, Autoencoder)** | ตรวจจับ Anomaly โดยไม่ต้องมี Label Data |
| **Deep Learning (CNN, LSTM)** | วิเคราะห์ Network Flow เป็น Sequence |
| **Reinforcement Learning** | ปรับ Threshold แบบ Adaptive |
| **NLP (Natural Language Processing)** | วิเคราะห์ HTTP Payload และ DNS Query |

**ตัวอย่าง AI Detection Pipeline:**

```
Network Traffic
      │
      ▼
┌─────────────┐
│ Feature      │  ← Flow Features: Packet Size, IAT, Duration
│ Extraction   │     Statistical: Mean, SD, Entropy
└──────┬──────┘
       ▼
┌─────────────┐
│ Preprocessing│  ← Normalize, Scale, Encode
└──────┬──────┘
       ▼
┌─────────────┐
│ ML Model     │  ← e.g., Random Forest Classifier
│ Inference    │     (Trained on CIC-IDS-2017 Dataset)
└──────┬──────┘
       ▼
┌─────────────┐
│ Decision     │  ← Score > 0.85 → Attack: Alert + Block
│ Threshold    │     Score 0.5-0.85 → Suspicious: Log + Investigate
└─────────────┘
```

**ข้อควรระวังของ AI/ML:**
- **Adversarial ML:** ผู้โจมตีสร้าง Input ที่หลอก Model ได้
- **Concept Drift:** พฤติกรรมเครือข่ายเปลี่ยนแปลงตลอดเวลา — ต้อง Retrain
- **Explainability:** ทำไม Model ถึงบอกว่า Traffic นี้ผิดปกติ? (XAI)
- **Resource Intensive:** ต้องใช้ GPU สำหรับ Deep Learning

---

## สรุปท้ายบท (Chapter Summary)

1. **IDS vs IPS:** IDS ตรวจสอบและแจ้งเตือน (Passive), IPS ตรวจสอบและบล็อก (Inline) — ทั้งคู่ทำงานร่วมกับ Firewall เพื่อ Defense in Depth

2. **ประเภท IDS/IPS:** NIDS/NIPS (เครือข่าย), HIDS/HIPS (โฮสต์), WIDS/WIPS (ไร้สาย), NBA (พฤติกรรมเครือข่าย) — แต่ละประเภทมีข้อดีข้อเสียต่างกัน ควรใช้ร่วมกัน

3. **เทคนิคการตรวจจับ 3 แบบ:** Signature-based (แม่นยำแต่ตรวจจับ Zero-Day ไม่ได้), Anomaly-based (ตรวจจับสิ่งใหม่ได้แต่ False Positive สูง), Stateful Protocol Analysis (เข้าใจ Protocol Context)

4. **การหลบเลี่ยงการตรวจจับ:** ผู้โจมตีใช้ Fragmentation, Encoding, Encryption, และ Protocol Obfuscation — IDS/IPS ต้องมี Reassembly, Normalization, และ Decryption

5. **เครื่องมือหลัก:** Snort (Single-thread, Enterprise Standard), Suricata (Multi-thread, Performance สูง), Zeek (Event-driven Analysis, Logging ละเอียด)

6. **การตอบสนอง:** ใช้ SOAR สำหรับ Automated Response, ใช้ AI/ML สำหรับตรวจจับ Anomaly ขั้นสูง

---

## คำถามทบทวน (Review Questions)

1. จงอธิบายความแตกต่างระหว่าง IDS และ IPS ในด้านตำแหน่งการวาง, โหมดการทำงาน, และผลกระทบต่อเครือข่าย พร้อมยกตัวอย่างสถานการณ์ที่ควรเลือกใช้แต่ละแบบ

2. หากองค์กรของคุณต้องเลือกระหว่าง NIDS และ HIDS เพียงอย่างเดียว คุณจะเลือกแบบไหน เพราะเหตุใด จงอธิบายข้อดีข้อเสีย

3. จงเปรียบเทียบ Signature-based Detection และ Anomaly-based Detection ในแง่ของความแม่นยำ, การตรวจจับ Zero-Day, False Positive Rate, และ Resource ที่ใช้

4. จงเขียน Snort Rule เพื่อตรวจจับ HTTP Request ที่มี `/etc/shadow` ใน URI พร้อมอธิบายส่วนประกอบแต่ละส่วนของ Rule

5. ผู้โจมตีใช้เทคนิคอะไรในการหลบเลี่ยง IDS/IPS บ้าง จงอธิบาย Fragmentation, Encoding, และ Encryption พร้อมแนวทางการป้องกันแต่ละเทคนิค

6. จงอธิบายความแตกต่างระหว่าง Snort, Suricata, และ Zeek ในแง่ของสถาปัตยกรรม, ความสามารถ, และกรณีการใช้งานที่เหมาะสม

7. UEBA (User and Entity Behavior Analytics) คืออะไร และแตกต่างจาก Signature-based Detection อย่างไร จงยกตัวอย่างพฤติกรรมที่ UEBA สามารถตรวจจับได้

8. ในองค์กรที่มี Traffic วันละ 500 Gbps จงอธิบายความท้าทายในการใช้งาน IDS/IPS และเสนอแนวทางแก้ไข (รวมถึง Hardware Sizing, Rule Management, และ Monitoring)

9. จงอธิบายบทบาทของ AI และ Machine Learning ใน IDS/IPS สมัยใหม่ พร้อมยกตัวอย่างเทคนิคและข้อจำกัด

10. จาก Playbook การตอบสนองอัตโนมัติ (SOAR) สำหรับ Ransomware ในบทนี้ จงวิเคราะห์ว่าหาก Playbook ผิดพลาด (False Positive) จะเกิดผลกระทบอะไรบ้าง และจะออกแบบ Fallback Plan อย่างไร

---

## เอกสารอ้างอิง (References)

1. Stallings, W. (2022). *Cryptography and Network Security: Principles and Practice* (8th ed.). Chapter 21: Intrusion Detection. Pearson.

2. Whitman, M. E., & Mattord, H. J. (2021). *Principles of Information Security* (7th ed.). Chapter 7: Intrusion Detection and Prevention Systems. Cengage Learning.

3. Snort Project. (2024). *Snort User Manual*. Retrieved from https://www.snort.org/documents

4. Suricata Project. (2024). *Suricata User Guide*. Open Information Security Foundation. Retrieved from https://suricata.readthedocs.io/

5. Zeek Project. (2024). *Zeek User Manual*. Retrieved from https://docs.zeek.org/

6. Paxson, V. (1999). "Bro: A System for Detecting Network Intruders in Real-Time." *Proceedings of the 7th USENIX Security Symposium*.

7. NIST Special Publication 800-94 Rev. 1. (2024). *Guide to Intrusion Detection and Prevention Systems (IDPS)*. National Institute of Standards and Technology.

8. Sommer, R., & Paxson, V. (2010). "Outside the Closed World: On Using Machine Learning for Network Intrusion Detection." *IEEE Symposium on Security and Privacy*.

9. MITRE Corporation. (2024). *MITRE ATT&CK Framework — Detection*. Retrieved from https://attack.mitre.org/

10. Cisco Talos Intelligence Group. (2024). *Snort Rule Documentation*. Retrieved from https://talosintelligence.com/
