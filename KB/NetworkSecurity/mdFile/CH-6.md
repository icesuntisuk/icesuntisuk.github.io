# CH-6: เทคโนโลยี Firewall และการแบ่งส่วนเครือข่าย

## วัตถุประสงค์การเรียนรู้ (Learning Objectives)

เมื่อจบบทนี้แล้ว ผู้เรียนสามารถ:
1. อธิบายวิวัฒนาการของ Firewall ตั้งแต่ Packet Filter จนถึง NGFW และเปรียบเทียบข้อดีข้อเสียของแต่ละรุ่นได้
2. ออกแบบสถาปัตยกรรม Firewall (Bastion Host, Screened Subnet, DMZ) สำหรับองค์กรได้
3. สร้าง Security Policy และ Access Control List (ACL) ตามหลัก Least Privilege และ Default Deny ได้
4. อธิบายแนวคิด Network Segmentation, VLAN, DMZ, และ Micro-segmentation ได้
5. อธิบายความสามารถของ NGFW ในด้าน Application Awareness, User Identification, และ SSL Decryption ได้
6. จัดการ Firewall Rules ตามแนวทาง Best Practices — Rule Ordering, Rule Audit, Change Management
7. วิเคราะห์และออกแบบเครือข่ายองค์กรที่มี DMZ จากกรณีศึกษาได้

---

# ส่วนที่ 1: วิวัฒนาการของเทคโนโลยี Firewall

## 1. ภาพรวมของ Firewall

### 1.1 Firewall คืออะไร

Firewall คือระบบรักษาความปลอดภัยเครือข่ายที่ทำหน้าที่กรอง Traffic ระหว่างเครือข่ายที่มีระดับความน่าเชื่อถือต่างกัน โดยทั่วไปคือระหว่าง Internal Network (น่าเชื่อถือ) และ External Network (ไม่น่าเชื่อถือ เช่น อินเทอร์เน็ต) หลักการพื้นฐานของ Firewall คือ **การตัดสินใจอนุญาต (Allow) หรือปฏิเสธ (Deny)** การรับส่งข้อมูลตามกฎที่กำหนดไว้ล่วงหน้า

Firewall เป็นแนวป้องกันแรก (First Line of Defense) ในสถาปัตยกรรมความปลอดภัยเครือข่าย ทำหน้าที่เป็นจุดตรวจสอบเพียงจุดเดียว (Choke Point) ที่ Traffic ทั้งหมดต้องผ่านก่อนเข้าสู่ระบบภายใน

### 1.2 บทบาทของ Firewall ในองค์กร

- **Network Perimeter Security:** ปกป้องขอบเขตเครือข่ายองค์กรจากภัยคุกคามภายนอก
- **Access Control:** ควบคุมการเข้าถึงทรัพยากรเครือข่ายตามนโยบายความปลอดภัย
- **Traffic Filtering:** กรอง Traffic ที่ไม่พึงประสงค์หรือเป็นอันตราย
- **Logging และ Audit:** บันทึกประวัติการรับส่งข้อมูลเพื่อการตรวจสอบ
- **NAT (Network Address Translation):** ซ่อนโครงสร้างเครือข่ายภายใน
- **VPN Termination:** เป็นจุดสิ้นสุดของการเชื่อมต่อ VPN สำหรับ Remote Access

### 1.3 ตารางเปรียบเทียบ Firewall แต่ละรุ่น

| คุณลักษณะ | Packet Filter | Stateful Inspection | Proxy Firewall | NGFW |
|-----------|:------------:|:------------------:|:--------------:|:----:|
| ตรวจสอบ Layer 3-4 | ✅ | ✅ | ✅ | ✅ |
| ตรวจสอบ State ของ Connection | ❌ | ✅ | ✅ | ✅ |
| ตรวจสอบ Payload Layer 7 | ❌ | ❌ | ✅ | ✅ |
| Application Awareness | ❌ | ❌ | จำกัด | ✅ |
| User Identification | ❌ | ❌ | ❌ | ✅ |
| SSL Decryption | ❌ | ❌ | จำกัด | ✅ |
| IPS บูรณาการ | ❌ | ❌ | ❌ | ✅ |
| ประสิทธิภาพ | สูงมาก | สูง | ต่ำ | ปานกลาง-สูง |
| ความปลอดภัย | ต่ำ | ปานกลาง | สูง | สูงมาก |

---

## 2. Packet Filter Firewall — รุ่นที่ 1

### 2.1 หลักการทำงาน

Packet Filter Firewall ทำงานใน Layer 3 (Network) และ Layer 4 (Transport) ของ OSI Model โดยตรวจสอบเฉพาะ Header ของแต่ละ Packet อย่างอิสระ โดยไม่พิจารณาความสัมพันธ์ระหว่าง Packet

**ข้อมูลที่ใช้ในการตัดสินใจ:**
- Source IP Address
- Destination IP Address
- Source Port Number
- Destination Port Number
- Protocol Type (TCP, UDP, ICMP)
- TCP Flags (SYN, ACK, FIN, RST)
- ICMP Type และ Code

### 2.2 Stateless Nature

Packet Filter ถูกเรียกว่า **Stateless Firewall** เพราะตรวจสอบแต่ละ Packet โดยไม่จดจำสถานะของการเชื่อมต่อ ตัวอย่างข้อจำกัด:

- ถ้า Rule อนุญาต Traffic ขาออก (Outbound) บน Port 80/TCP, Firewall จะอนุญาต Packet ขากลับ (Inbound) ที่มี Port 80 เช่นกัน — แม้ Packet นั้นจะไม่ได้เป็นส่วนหนึ่งของการเชื่อมต่อที่ถูกต้องก็ตาม
- ผู้โจมตีสามารถส่ง Packet ที่มี Flag ACK เพื่อหลอก Firewall ให้คิดว่าเป็นส่วนหนึ่งของการเชื่อมต่อที่ถูกตั้งขึ้นแล้ว (ACK Scanning)

### 2.3 Access Control Lists (ACL) แบบ Packet Filter

```
! ตัวอย่าง ACL บน Router (Cisco IOS)
!
! deny any traffic from malicious network
access-list 101 deny ip 203.0.113.0 0.0.0.255 any
!
! allow established connections (ACK flag set)
access-list 101 permit tcp any any established
!
! allow specific services
access-list 101 permit tcp any any eq 80
access-list 101 permit tcp any any eq 443
access-list 101 permit udp any any eq 53
!
! deny everything else
access-list 101 deny ip any any
```

### 2.4 ข้อดีและข้อจำกัด

**ข้อดี:**
- ประสิทธิภาพสูง — ทำงานเร็วเนื่องจากประมวลผลน้อย
- ไม่ต้องการทรัพยากรเครื่องมาก
- เหมาะสำหรับเครือข่ายความเร็วสูง
- ต้นทุนต่ำ (ทำงานบน Router ทั่วไปได้)

**ข้อจำกัด:**
- ไม่ตรวจสอบ Payload — ไม่สามารถป้องกันการโจมตีใน Layer 7
- ไม่เข้าใจ State ของ Connection — เสี่ยงต่อ Packet Spoofing
- ไม่ป้องกัน Fragment Attacks
- บริหารจัดการยากเมื่อมีกฎจำนวนมาก
- ไม่สามารถกรองตาม Application หรือ User

---

## 3. Stateful Inspection Firewall — รุ่นที่ 2

### 3.1 หลักการทำงาน

Stateful Inspection Firewall (หรือ Stateful Firewall) ได้รับการพัฒนาขึ้นโดย Check Point Software ในปี 1994 ด้วยเทคโนโลยีที่เรียกว่า Stateful Multi-Layer Inspection (SMLI) Firewall ชนิดนี้จะติดตาม **สถานะ (State)** ของทุก Connection ที่ผ่านเข้า-ออก โดยสร้าง **State Table** เพื่อเก็บข้อมูล

```
State Table Entry Example:
┌─────────────────────────────────────────────────────────┐
│ Source IP: 10.0.0.10:45012                              │
│ Dest IP:   93.184.216.34:443                            │
│ Protocol:  TCP                                          │
│ State:     ESTABLISHED                                  │
│ Sequence:  0x8A3F2B1C                                   │
│ Window:    65535                                        │
│ Timeout:   3600s                                        │
└─────────────────────────────────────────────────────────┘
```

### 3.2 การติดตาม State ของ Connection

Stateful Firewall จดจำสถานะของ Connection TCP โดยอ้างอิงตาม State Diagram:

1. **SYN_SENT** — เครื่องภายในส่ง SYN ออกไป
2. **SYN_RECEIVED** — ได้รับ SYN-ACK กลับมา
3. **ESTABLISHED** — Three-Way Handshake เสร็จสมบูรณ์
4. **FIN_WAIT** — ฝ่ายใดฝ่ายหนึ่งเริ่มปิด Connection
5. **CLOSED** — Connection ปิดแล้ว

สำหรับ UDP (ซึ่งเป็น Stateless Protocol) Firewall จะจำลอง State โดยใช้ Source/Destination IP:Port และ Timeout

### 3.3 ข้อแตกต่างจาก Packet Filter ที่สำคัญ

| คุณสมบัติ | Packet Filter | Stateful Firewall |
|-----------|:------------:|:-----------------:|
| ตรวจสอบแต่ละ Packet อิสระ | ✅ | ❌ |
| ติดตาม State Connection | ❌ | ✅ |
| อนุญาต Return Traffic อัตโนมัติ | ❌ (ต้องเขียน Rule) | ✅ |
| ป้องกัน IP Spoofing | ต่ำ | ปานกลาง |
| หน่วยความจำที่ใช้ | น้อย | ปานกลาง |
| ประสิทธิภาพ | สูงมาก | สูง |

### 3.4 State Table และ Firewall Policy

Stateful Firewall ใช้ **State Table** ร่วมกับ **Access Control Rules**:

```
Algorithm:
1. Packet arrives at firewall
2. Lookup State Table:
   - If matching entry found → Allow (bypass rule check)
   - If NOT found → Forward to Rule Engine
3. Rule Engine checks ACL:
   - If Allow → Create State Table entry, Forward packet
   - If Deny → Drop packet, Log (optional)
```

ข้อดีคือทำให้กฎกระชับขึ้น — ไม่ต้องเขียนกฎสำหรับ Return Traffic แยกต่างหาก

---

## 4. Proxy Firewall — รุ่นที่ 3

### 4.1 หลักการทำงาน

Proxy Firewall (หรือ Application Gateway) ทำงานใน Layer 7 (Application Layer) โดยทำหน้าที่เป็น **ตัวกลาง (Intermediary)** ระหว่าง Client และ Server Client ไม่ได้เชื่อมต่อไปยัง Server โดยตรง แต่เชื่อมต่อไปยัง Proxy ก่อน แล้ว Proxy จึงเชื่อมต่อไปยัง Server แทน

```
Client → [Proxy Firewall] → Server
     (1) Client เชื่อมต่อ Proxy
     (2) Proxy ตรวจสอบ Content
     (3) Proxy สร้าง Connection ใหม่ไปยัง Server
     (4) Server เห็น IP ของ Proxy ไม่ใช่ IP ของ Client
```

### 4.2 ประเภทของ Proxy

**Forward Proxy:**
- ใช้สำหรับ Client ภายในที่ต้องการเข้าถึงอินเทอร์เน็ต
- ซ่อน IP จริงของ Client
- สามารถ Cache Content เพื่อเพิ่มประสิทธิภาพ
- ใช้กรอง Content ตามนโยบายองค์กร

**Reverse Proxy:**
- วางอยู่หน้า Web Server เพื่อรับ Traffic จากภายนอก
- ปกปิดโครงสร้าง Server ภายใน
- ทำ Load Balancing และ SSL Termination
- ป้องกันการโจมตีระดับ Application (WAF)

**Transparent Proxy:**
- Client ไม่ต้องตั้งค่า Proxy — Traffic ถูก Intercept โดยอัตโนมัติ
- ใช้ในองค์กรเพื่อบังคับใช้นโยบายโดยผู้ใช้ไม่ทราบ
- ต้องใช้เทคนิค Interception (WCCP, Policy-Based Routing)

### 4.3 Application-Level Filtering

Proxy Firewall สามารถตรวจสอบ Content ใน Layer 7 ได้ เช่น:

- **HTTP Proxy:** ตรวจสอบ Method (GET, POST), URL, Headers, Body
- **SMTP Proxy:** ตรวจสอบ Email Content, Attachment, Header
- **FTP Proxy:** ตรวจสอบ Command (GET, PUT), Filename
- **DNS Proxy:** ตรวจสอบ Query Type, Domain Name

```
ตัวอย่าง HTTP Proxy Inspection:
─────────────────────────────────
Request:  GET /../../../etc/passwd HTTP/1.1
Result:   ❌ BLOCKED — Path Traversal detected

Request:  GET /wp-admin/admin-ajax.php HTTP/1.1
Result:   ❌ BLOCKED — Admin interface exposed

Request:  GET /products/category?id=1 UNION SELECT * FROM users HTTP/1.1
Result:   ❌ BLOCKED — SQL Injection detected
```

### 4.4 ข้อดีและข้อจำกัด

**ข้อดี:**
- ความปลอดภัยสูง — Server ไม่เห็น Client โดยตรง
- ตรวจสอบ Content ใน Application Layer ได้
- สามารถทำ Content Filtering และ Caching
- ป้องกัน Protocol-Based Attacks
- Audit Trail ระดับ Application

**ข้อจำกัด:**
- ประสิทธิภาพต่ำ — ต้องสร้าง Connection ใหม่ทุกครั้ง
- ต้องมี Proxy แยกสำหรับแต่ละ Protocol
- ไม่รองรับ Protocol ที่ไม่ใช่ TCP/IP (หรือรองรับได้จำกัด)
- การ Scale ทำได้ยาก
- การตั้งค่าซับซ้อน

---

## 5. Next-Generation Firewall (NGFW) — รุ่นที่ 4

### 5.1 ความเป็นมา

NGFW ได้รับการนิยามโดย Gartner ในปี 2009 โดยมีคุณสมบัติหลักนอกเหนือจาก Stateful Inspection:
1. **Application Awareness** — ระบุและควบคุม Application ได้แม้ใช้ Port ผิด
2. **User Identification** — กำหนด Policy ตามตัวตนผู้ใช้ ไม่ใช่แค่ IP
3. **Integrated IPS** — มีระบบป้องกันการบุกรุกในตัว
4. **SSL/TLS Decryption** — ตรวจสอบ Traffic ที่เข้ารหัส

ผู้ผลิตรายใหญ่: Palo Alto Networks, Fortinet, Cisco (Firepower), Check Point, Juniper (SRX)

### 5.2 Application Awareness (App-ID)

หัวใจของ NGFW คือความสามารถในการระบุ Application ที่ทำงานบนเครือข่าย โดยไม่พึ่งพา Port Number เพียงอย่างเดียว:

**เทคนิคการระบุ Application:**

```
Multi-Layer Identification:
├── Layer 3-4: IP Address, Port, Protocol
├── Layer 7:
│   ├── SSL/TLS Certificate: Common Name (CN), Subject Alternative Name (SAN)
│   ├── HTTP Header: User-Agent, Host, Referer
│   ├── Protocol Decoding: SIP, RTP, FTP Control
│   └── Behavior Analysis: Packet Inter-arrival Time, Packet Size
└── Cloud Lookup (App-ID Cloud)
```

**ตัวอย่างการระบุ Application:**

| Traffic | Port | Device Type | Application Identified |
|---------|:----:|:-----------:|:----------------------:|
| HTTPS 443 | 443 | NGFW | facebook-base (Facebook) |
| HTTPS 443 | 443 | NGFW | youtube-base (YouTube) |
| HTTPS 443 | 443 | NGFW | office365-base (Outlook) |
| TCP 443 | 443 | Packet Filter | HTTPS (ไม่รู้ว่าเป็น App อะไร) |

### 5.3 User Identification (User-ID)

NGFW สามารถกำหนด Policy ตามตัวตนผู้ใช้ แทนการใช้ IP Address ซึ่งเปลี่ยนไปมาได้:

**กลไกการระบุตัวตน:**
- **Active Directory / LDAP Integration:** ดึงข้อมูลผู้ใช้จาก Domain Controller
- **Captive Portal:** ให้ผู้ใช้ล็อกอินผ่าน Web Portal
- **X-Forwarded-For:** อ่านจาก HTTP Header
- **Terminal Services Agent:** ติดตั้ง Agent บน Server องค์กร

```
ตัวอย่าง Policy ที่ใช้ User-ID:
────────────────────────────────────
Rule 1: Allow  user=hr_department  app=workday     → Permit
Rule 2: Allow  user=engineering    app=github       → Permit
Rule 3: Allow  user=any            app=dns          → Permit
Rule 4: Deny   user=intern         app=ssh-outbound → Deny
Rule 5: Deny   user=any            app=tor         → Deny
```

### 5.4 SSL/TLS Decryption

เนื่องจากการรับส่งผ่าน HTTPS ได้รับการเข้ารหัส (ประมาณ 95% ของ Traffic อินเทอร์เน็ตในปี 2024) NGFW ต้องสามารถถอดรหัสเพื่อตรวจสอบ Content ได้:

**การทำงานของ SSL Forward Proxy (Outbound Inspection):**

```
Client → NGFW (ถอดรหัส → ตรวจสอบ → เข้ารหัสใหม่) → Internet
                ↓
         ตรวจสอบหา Malware, C2 Communication,
         Data Exfiltration, Policy Violation
```

**กระบวนการ:**
1. Client ส่ง ClientHello ไปยัง Server
2. NGFW Intercept — สร้าง Connection ไปยัง Server แทน
3. Server ส่ง Certificate ของตนเอง
4. NGFW สร้าง Signed Certificate (ลงนามโดย CA ขององค์กร) ส่งให้ Client
5. Client เชื่อถือ Certificate ของ NGFW (เพราะ CA องค์กรได้รับการ Trusted)

**ข้อควรระวัง:**
- ต้องติดตั้ง CA Certificate ขององค์กรบนอุปกรณ์ผู้ใช้ทุกเครื่อง
- การถอดรหัสต้องเป็นไปตามนโยบายและกฎหมาย (PDPA, พ.ร.บ. ไซเบอร์)
- ผลต่อประสิทธิภาพ — SSL Decryption ใช้ทรัพยากร CPU สูง
- บาง Application ใช้ Certificate Pinning — ทำให้ไม่สามารถถอดรหัส (Decrypt) ได้ (iOS Apps, Banking Apps)

### 5.5 NGFW Architecture

```
                     ┌──────────────────────────┐
                     │     Management Plane      │
                     │  (GUI, CLI, API, Logging) │
                     └──────────┬───────────────┘
                                │
┌───────────────────────────────┼──────────────────────────────┐
│                   Control Plane                               │
│  (Routing, Session Setup, Policy Lookup, User-ID, App-ID)    │
├───────────────────────────────┼──────────────────────────────┤
│                   Data Plane                                  │
│  (Packet Forwarding, SSL Decrypt, IPS, NAT, QoS)             │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐            │
│  │ CPU Core│ │ CPU Core│ │ CPU Core│ │ CPU Core│  ← Parallel│
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘            │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐            │
│  │ ASIC/FPGA for Packet Processing                           │
│  └─────────┘                                                 │
└──────────────────────────────────────────────────────────────┘
```

การแยก Control Plane และ Data Plane ช่วยให้ NGFW มีประสิทธิภาพสูง — Control Plane จัดการ Policy Lookup และ Session Setup, Data Plane จัดการ Packet Forwarding ด้วย Hardware Acceleration

---

# ส่วนที่ 2: สถาปัตยกรรม Firewall และ Network Segmentation

## 6. สถาปัตยกรรม Firewall

### 6.1 Bastion Host

Bastion Host คือระบบคอมพิวเตอร์ที่ตั้งอยู่บนเครือข่ายสาธารณะ (หรือ DMZ) ทำหน้าที่เป็นจุดเข้าสู่เครือข่ายภายในอย่างปลอดภัย โดยได้รับการ Hardened เป็นพิเศษ:

**ลักษณะของ Bastion Host:**
- ระบบปฏิบัติการได้รับการ Hardened — ลบบริการที่ไม่จำเป็นออกทั้งหมด
- ใช้การพิสูจน์ตัวตนแบบหลายปัจจัย (MFA)
- มีระบบ Logging และ Monitoring เข้มงวด
- ติดตั้งเฉพาะซอฟต์แวร์ที่จำเป็นเท่านั้น
- อัปเดตความปลอดภัยสม่ำเสมอ

**การประยุกต์ใช้:**
- SSH Jump Server (Jump Box) สำหรับผู้ดูแลระบบ
- VPN Gateway
- Remote Desktop Gateway

### 6.2 Screened Subnet (DMZ)

DMZ (Demilitarized Zone) คือเครือข่ายย่อยที่ทำหน้าที่เป็น Buffer Zone ระหว่างเครือข่ายภายใน (Internal) และเครือข่ายภายนอก (External) โดยทั่วไปจะมี Firewall สองตัว:

```
                    ┌──────────────────────┐
                    │      Internet        │
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
                    │   External Firewall   │
                    │   (Front-end/ACL)     │
                    └──────────┬───────────┘
                               │
              ┌────────────────▼────────────────┐
              │          DMZ Network            │
              │  ┌─────┐ ┌─────┐ ┌─────┐       │
              │  │ Web │ │ Mail│ │ DNS │       │
              │  └─────┘ └─────┘ └─────┘       │
              └────────────────┬────────────────┘
                               │
                    ┌──────────▼───────────┐
                    │   Internal Firewall   │
                    │   (Back-end/Policy)   │
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
                    │    Internal Network   │
                    │  (Users, Databases)   │
                    └──────────────────────┘
```

**หลักการทำงานของ DMZ:**
- External Firewall: อนุญาต Traffic จากอินเทอร์เน็ตไปยัง DMZ Services (Web, Mail, DNS)
- Internal Firewall: อนุญาตเฉพาะ Traffic ที่จำเป็นจาก DMZ ไปยัง Internal (เช่น DB Query จาก Web Server)
- การโจมตีที่เจาะ Web Server สำเร็จจะสามารถเข้าถึงได้เฉพาะ DMZ — ไม่สามารถเข้าถึง Internal Network ได้โดยตรง
- Internal Firewall เป็นด่านที่สองที่ป้องกันการเข้าถึงเครือข่ายภายใน

### 6.3 แนวทางการออกแบบ DMZ

**Best Practices:**
1. **ใช้หลาย DMZ Zone:** Public DMZ (Web, Mail), Private DMZ (Application Server), Management DMZ
2. **Default Deny:** ทุก Traffic ได้รับการปฏิเสธโดยค่าเริ่มต้น — อนุญาตเฉพาะที่จำเป็น
3. **Stateful Inspection:** Firewall ทุกตัวควรเป็น Stateful
4. **Separation of Services:** แยก Web Server, App Server, Database Server คนละ Zone
5. **Outbound-Only DMZ:** DMZ Servers ไม่ควรเริ่ม Connection ไปยัง Internal

### 6.4 Multi-Tier Architecture

สำหรับองค์กรขนาดใหญ่ ใช้สถาปัตยกรรมแบบหลายชั้น:

```
Internet
    │
    ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Web Tier   │────▶│  App Tier   │────▶│   DB Tier   │
│ (DMZ)       │     │ (Private DMZ)│     │ (Internal)  │
│ HTTP, HTTPS │     │ App Logic   │     │ SQL, Oracle │
└─────────────┘     └─────────────┘     └─────────────┘
    │                     │                     │
    ▼                     ▼                     ▼
┌─────────────────────────────────────────────────────┐
│                    Firewall Rules                     │
│ W→Web: 80,443   Web→App: App Port   App→DB: SQL     │
└─────────────────────────────────────────────────────┘
```

**ข้อดี:** หาก Web Server ถูกเจาะ ผู้โจมตีไม่สามารถเข้าถึง Database โดยตรง — ต้องเจาะ App Server ก่อน (Defense in Depth)

---

## 7. Network Segmentation

### 7.1 แนวคิด Network Segmentation

Network Segmentation คือการแบ่งเครือข่ายออกเป็นส่วนย่อย (Segment) เพื่อ:
1. **จำกัดพื้นผิวการโจมตี (Attack Surface)** — การบุกรุกที่เกิดขึ้นใน Segment หนึ่ง ไม่แพร่กระจายไปทั้งเครือข่าย
2. **ควบคุม Traffic** — กรอง Traffic ระหว่าง Segment ตามนโยบาย
3. **ปฏิบัติตาม Compliance** — PCI DSS, HIPAA, PDPA กำหนดให้แยกเครือข่ายของข้อมูลสำคัญ
4. **เพิ่มประสิทธิภาพ** — ลด Broadcast Domain, ลด Collision

### 7.2 VLAN (Virtual LAN)

VLAN แบ่งเครือข่าย Layer 2 โดยไม่ต้องเปลี่ยนโครงสร้างทางกายภาพ:

```
┌────────────────────────────────────────────────────────┐
│                    Switch (Trunk)                       │
│  ┌───────┐  ┌───────┐  ┌───────┐  ┌───────┐           │
│  │ VLAN 10 │  │ VLAN 20 │  │ VLAN 30 │  │ VLAN 99 │    │
│  │Employees│  │   Guest  │  │ Servers │  │Management│   │
│  │ 10.0.10 │  │10.0.20.0│  │10.0.30.0│  │10.0.99.0│   │
│  └───────┘  └───────┘  └───────┘  └───────┘           │
└────────────────────────────────────────────────────────┘
                        │
         ┌──────────────┴──────────────┐
         │        Router-on-a-Stick      │
         │  (Inter-VLAN Routing + ACL)   │
         └──────────────────────────────┘
```

**ข้อควรระวัง:** VLAN เพียงอย่างเดียวไม่ใช่ Security Control — การโจมตี VLAN Hopping (Double Tagging, Switch Spoofing) สามารถข้าม VLAN ได้หากไม่ได้กำหนดค่าความปลอดภัยที่ถูกต้อง

### 7.3 DMZ Design ระดับองค์กร

องค์กรขนาดใหญ่มักมี DMZ หลายประเภท:

| ประเภท DMZ | การเข้าถึง | ตัวอย่าง Services | ระดับความปลอดภัย |
|:-----------|:----------|:-----------------|:----------------:|
| Public DMZ | อินเทอร์เน็ต → | Web Server, Mail Gateway, DNS | ต่ำ |
| Partner DMZ | คู่ค้าทางธุรกิจ → | API Gateway, EDI, B2B Portal | ปานกลาง |
| Internal DMZ | พนักงาน → | Application Server, File Server | สูง |
| Management DMZ | ผู้ดูแลระบบ → | SSH Jump Host, VPN Gateway | สูงมาก |
| PCI DMZ | เฉพาะระบบที่เกี่ยวข้อง | Payment Gateway, Tokenization | สูงสุด (Isolated) |

### 7.4 Micro-segmentation

Micro-segmentation คือการแบ่งเครือข่ายในระดับ Workload (VM, Container, Pod) โดยใช้นโยบาย granular ที่กำหนด Traffic ระหว่าง Workload แต่ละตัว:

**เทคโนโลยีที่ใช้:**
- **SDN (Software-Defined Networking):** VMware NSX, Cisco ACI
- **Network Policy ใน Kubernetes:** กำหนดว่า Pod ใดสื่อสารกับ Pod ใดได้
- **Host-Based Firewall:** Windows Firewall, iptables, nftables
- **Service Mesh:** Istio, Linkerd (Sidecar Proxy)

```
ตัวอย่าง Micro-segmentation ใน Kubernetes:
─────────────────────────────────────────
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-allow
spec:
  podSelector:
    matchLabels:
      app: api-server
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080
```

**ประโยชน์ของ Micro-segmentation:**
- ลด Blast Radius — การโจมตี Container หนึ่งไม่กระจายไปยัง Container อื่น
- Zero Trust Network — ทุกการสื่อสารต้องได้รับอนุญาตอย่างชัดเจน
- Compliance — ตอบสนองข้อกำหนด PCI DSS, HIPAA เรื่อง Network Segmentation

---

## 8. Security Policy และ Access Control List (ACL)

### 8.1 หลักการสร้าง Security Policy

Security Policy คือชุดกฎที่กำหนดว่า Traffic ใดได้รับอนุญาตและ Traffic ใดได้รับการปฏิเสธ โดยมีหลักการสำคัญ:

**1. Default Deny (Closed Policy):**
``` 
# ตัวอย่าง Default Deny
Rule 100: Allow specific traffic → Permit
Rule 999: Deny all traffic       → Drop (Implicit)
```

**2. Default Allow (Open Policy):**
```
# ตัวอย่าง Default Allow (⚠️ ไม่ปลอดภัย — ไม่แนะนำ)
Rule 100: Deny specific traffic  → Drop
Rule 999: Allow all traffic      → Permit (Implicit)
```

**3. Least Privilege:**
- อนุญาตเฉพาะ Traffic ที่จำเป็นต่อการทำงานเท่านั้น
- ใช้หลักการ "Deny by default, Allow by exception"

### 8.2 องค์ประกอบของ ACL Rule

ACL Rule มาตรฐานประกอบด้วย:

```
[Sequence] [Action] [Protocol] [Source] [Destination] [Port] [Logging]

ตัวอย่าง:
Rule 10    Permit   TCP        10.0.0.0/8     any         80,443    Log
```

**ลำดับความสำคัญ (Rule Ordering):**
- Firewall ประมวลผล Rule จากบนลงล่าง (First Match)
- Rule ที่ละเอียดและเฉพาะเจาะจงควรอยู่บนสุด
- Rule ทั่วไป (Broad Rule) ควรอยู่ล่าง
- มี Implicit Deny ต่อท้ายเสมอ

### 8.3 Best Practices สำหรับ ACL

```
✅ DO:
- ใช้ Group Objects สำหรับ IP/Port ที่ซ้ำกัน
- ระบุ Source และ Destination ให้แคบที่สุด
- ใช้ Comments อธิบายวัตถุประสงค์ของแต่ละ Rule
- ตรวจสอบ Shadow Rules (Rule ที่ได้รับการครอบคลุมโดย Rule อื่นก่อน)
- Audit Rules ทุก 6 เดือน
- ใช้ Change Management สำหรับทุกการเปลี่ยนแปลง

❌ DON'T:
- ใช้ "any any" โดยไม่จำเป็น
- ใช้ Rule "Permit any any" เป็นบรรทัดเดียวกับ Production
- เก็บ Rule ที่ไม่ได้ใช้แล้ว (Stale Rules)
- ใช้ IP Address โดยตรง — ใช้ Group Objects แทน
- แก้ไข Firewall Rules โดยไม่ผ่าน Change Management
```

### 8.4 Rule Lifecycle Management

```
┌─────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│ Request │────▶│  Review  │────▶│  Approve │────▶│Implement │
│ (RFC)   │     │ (Peer)   │     │ (Manager)│     │ (Change) │
└─────────┘     └──────────┘     └──────────┘     └──────────┘
                                                     │
               ┌──────────┐     ┌──────────┐         │
               │  Audit   │◀────│  Retire  │◀────────┘
               │(Quarterly)│    │(Clean up)│
               └──────────┘     └──────────┘
```

### 8.5 การตรวจสอบคุณภาพของ Rule Set

ปัญหาที่พบบ่อยใน Firewall Rule Base:

| ปัญหา | คำอธิบาย | ผลกระทบ |
|:------|:---------|:--------|
| **Shadow Rules** | Rule ที่ไม่เคยถูก Match (ตรงกับ Traffic) เพราะ Rule ก่อนหน้าครอบคลุมอยู่แล้ว | เพิ่มความซับซ้อนโดยไม่จำเป็น |
| **Redundant Rules** | Rule ที่เหมือนกันทุกประการ | สิ้นเปลืองทรัพยากร |
| **Orphan Rules** | Rule ที่อ้างถึง Object ที่ได้รับการลบแล้ว | ทำให้เกิด Error |
| **Overly Permissive** | Rule ที่ใช้ Source/Destination กว้างเกินไป | เสี่ยงด้านความปลอดภัย |
| **No Hit Rules** | Rule ที่ไม่เคยถูก Match (ตรงกับ Traffic) เลยในช่วงเวลาที่กำหนด | ควรตรวจสอบและลบ |

---

## 9. การบริหารจัดการ Firewall Rules

### 9.1 Change Management Process

ทุกการเปลี่ยนแปลง Firewall Rules ควรผ่านกระบวนการ Change Management:

1. **Submit Request:** ผู้ขอกรอกข้อมูล (Change Request Form)
   - เหตุผลที่ต้องเปลี่ยนแปลง
   - รายละเอียด Traffic ที่ต้องการ Allow/Deny
   - ระยะเวลาที่ต้องการ (Permanent/Temporary)
   - ผลกระทบหากเปลี่ยนแปลง

2. **Technical Review:** ผู้ดูแลระบบตรวจสอบ
   - ตรวจสอบผลกระทบต่อกฎที่มีอยู่
   - ตรวจสอบ Shadow/Redundant Rules
   - ประเมินความเสี่ยง

3. **Change Advisory Board (CAB):** อนุมัติ
   - กรณีเร่งด่วน (Emergency Change) — อนุมัติภายหลัง

4. **Implementation:** ทำการเปลี่ยนแปลง
   - ดำเนินการในช่วงเวลาที่กำหนด (Change Window)
   - ติดตามผล — ตรวจสอบว่า Traffic ทำงานถูกต้อง

5. **Verification:** ยืนยันผล
   - ตรวจสอบ Connection
   - ตรวจสอบว่ากฎใหม่ไม่ Conflict กับกฎที่มีอยู่
   - Update Documentation

### 9.2 Rule Audit และ Cleanup

แนวทางการตรวจสอบ Firewall Rules:

```
Tier 1 — รายสัปดาห์ (Automated):
├── ตรวจสอบ Rule ที่มี Hit Count = 0
├── ตรวจสอบ Object ที่ไม่ได้รับการอ้างถึง
└── แจ้งเตือน Shadow Rules

Tier 2 — รายเดือน (Manual Review):
├── ตรวจสอบ Compliance (PCI DSS, SOX)
├── ตรวจสอบ Rule Permissions
└── ทบทวน Change Log

Tier 3 — ราย 6 เดือน (Full Audit):
├── Clean up Rules และ Objects
├── Optimize Rule Order
├── Review Architecture
└── Update Documentation
```

### 9.3 Firewall Rule Base Optimization

เทคนิคการเพิ่มประสิทธิภาพ Rule Base:

1. **Object Grouping:** รวม IP/Port/Service ที่เกี่ยวข้องเป็น Group
2. **Rule Consolidation:** รวม Rule ที่มี Action และ Destination เดียวกัน
3. **Rule Reordering:** จัดลำดับ Rule ที่ได้รับการใช้บ่อยให้อยู่ด้านบน
4. **Remove Stale Rules:** ลบกฎที่ไม่ได้ใช้
5. **Policy Optimization Tools:** ใช้เครื่องมืออย่าง AlgoSec, Tufin, FireMon

---

## 10. กรณีศึกษา: การออกแบบเครือข่ายองค์กรที่มี DMZ

### 10.1 ความต้องการขององค์กร

บริษัทขนาดกลาง (พนักงาน 500 คน) มีความต้องการ:
- เว็บไซต์องค์กรที่ให้บริการทั้งพนักงานและลูกค้า
- อีเมลเซิร์ฟเวอร์สำหรับพนักงาน
- ระบบ ERP และ Database สำหรับพนักงานภายใน
- VPN สำหรับพนักงานที่ทำงานนอกสถานที่
- การเข้าถึงอินเทอร์เน็ตสำหรับพนักงานที่ควบคุมได้
- ระบบ POS สำหรับสาขาย่อย 20 แห่ง

### 10.2 การออกแบบเครือข่าย

```
                    ┌─────────────────────────────────────┐
                    │              INTERNET               │
                    │    (ISP1: 500 Mbps + ISP2: 100 Mbps)│
                    └──────────────┬──────────────────────┘
                                   │
                    ┌──────────────▼──────────────────────┐
                    │        Edge Router (BGP + NAT)       │
                    │   ISP1 Primary, ISP2 Backup (failover)│
                    └──────────────┬──────────────────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              │                    │                     │
              ▼                    ▼                     ▼
   ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
   │  NGFW Cluster     │  │  WAF (Web App    │  │  DDoS Protection │
   │ (Active-Passive)  │  │   Firewall)      │  │  (Cloud-Based)   │
   └────────┬─────────┘  └──────────────────┘  └──────────────────┘
            │
            ▼
┌─────────────────────────────────────────────────────────────┐
│                     PUBLIC DMZ (10.0.10.0/24)                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │ Web Server    │  │ Mail Gateway │  │ DNS Server    │       │
│  │ 10.0.10.10   │  │ 10.0.10.20  │  │ 10.0.10.30   │       │
│  │ (Nginx + TLS) │  │ (Postfix)    │  │ (Bind9 + DNSSEC)     │
│  └──────────────┘  └──────────────┘  └──────────────┘       │
└─────────────────────────────────────────────────────────────┘
            │
            ▼
┌─────────────────────────────────────────────────────────────┐
│                  INTERNAL FIREWALL (NGFW)                     │
│          Rules: Web→App, Mail→Internal, VPN→Internal        │
└─────────────────────────────────────────────────────────────┘
            │
            ▼
┌─────────────────────────────────────────────────────────────┐
│               APPLICATION DMZ (10.0.20.0/24)                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │ App Server    │  │ API Gateway  │  │ VPN Gateway   │       │
│  │ 10.0.20.10   │  │ 10.0.20.20  │  │ 10.0.20.30   │       │
│  │ (ERP System)  │  │ (REST API)   │  │ (WireGuard)   │       │
│  └──────────────┘  └──────────────┘  └──────────────┘       │
└─────────────────────────────────────────────────────────────┘
            │
            ▼
┌─────────────────────────────────────────────────────────────┐
│                     INTERNAL NETWORK                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │ VLAN 10: HR  │  │ VLAN 20: Eng│  │ VLAN 30: Fin │       │
│  │ 10.0.30.0/24 │  │10.0.40.0/24 │  │ 10.0.50.0/24│       │
│  └──────────────┘  └──────────────┘  └──────────────┘       │
│  ┌──────────────┐  ┌──────────────┐                          │
│  │ VLAN 99: Mgmt│  │ DB Server     │                          │
│  │ 10.0.99.0/24 │  │ 10.0.60.10  │                          │
│  └──────────────┘  └──────────────┘                          │
└─────────────────────────────────────────────────────────────┘
            │
            ▼
┌─────────────────────────────────────────────────────────────┐
│                    BRANCH OFFICES (20 sites)                  │
│  Site-to-Site VPN (IPsec) Tunnel from SG3000 at each site   │
└─────────────────────────────────────────────────────────────┘
```

### 10.3 Security Policy ตัวอย่าง

```
=== EXTERNAL FIREWALL POLICY ===
─────────────────────────────────
Rule    Source       Dest           Service      Action  Log
───     ──────       ────           ───────      ──────  ───
10      INTERNET     DMZ-Web        HTTPS        Permit  Yes
20      INTERNET     DMZ-Mail       SMTP, SMTPS  Permit  Yes
30      INTERNET     DMZ-DNS        DNS          Permit  Yes
40      DMZ-Web      INTERNET       HTTPS        Permit  Yes
50      ──           ──             ──           ──      ──
999     ANY          ANY            ANY          Deny    Yes
─────────────────────────────────
=== INTERNAL FIREWALL POLICY ===
─────────────────────────────────
Rule    Source       Dest           Service      Action  Log
───     ──────       ────           ───────      ──────  ───
10      DMZ-Web      APP-DMZ        HTTP:8080    Permit  Yes
20      DMZ-Web      APP-DMZ        HTTPS:9443   Permit  Yes
30      DMZ-Mail     INT-DB         SMTP         Permit  Yes
40      APP-DMZ      INT-DB         MYSQL:3306   Permit  Yes
50      VPN-POOL     INT-LAN        RDP, SSH     Permit  Yes
60      INTERNAL     INTERNET       HTTP,HTTPS   Permit  Yes
70      INTERNAL     DMZ-Web        HTTPS        Permit  Yes
80      ──           ──             ──           ──      ──
999     ANY          ANY            ANY          Deny    Yes
─────────────────────────────────
=== MANAGEMENT ACCESS POLICY ===
─────────────────────────────────
Rule    Source       Dest           Service      Action  Log
───     ──────       ────           ───────      ──────  ───
10      MGT-JUMP     ALL-DEVICES    SSH           Permit  Yes
20      MGT-JUMP     FW-CLUSTER     HTTPS:443     Permit  Yes
30      MGT-JUMP     SWITCHES       SSH           Permit  Yes
40      ──           ──             ──           ──      ──
999     ANY          ANY            ANY           Deny   Yes
─────────────────────────────────
```

### 10.4 บทเรียนจากกรณีศึกษา

1. **Defense in Depth:** ใช้ Firewall หลายชั้น — DDoS Protection → WAF → NGFW → Internal Firewall
2. **Segregation of Duties:** DMZ Services ไม่ควรเข้าถึง Database โดยตรง ต้องผ่าน App Server
3. **Management Isolation:** การจัดการอุปกรณ์ทั้งหมดต้องผ่าน Management Network ที่แยกต่างหาก
4. **Redundancy:** Active-Passive Cluster สำหรับ High Availability
5. **Logging Centralization:** Log จาก Firewall ทั้งหมดถูกส่งไปยัง SIEM

---

## สรุปท้ายบท (Chapter Summary)

1. **Firewall มี 4 รุ่นหลัก:** Packet Filter (Stateless, Layer 3-4), Stateful Inspection (ติดตาม Connection State), Proxy Firewall (ตรวจสอบ Layer 7), และ NGFW (App-ID, User-ID, SSL Decryption, IPS ในตัว)

2. **Stateful Firewall** เป็นมาตรฐานขั้นต่ำสำหรับองค์กรในปัจจุบัน — ติดตาม State ของ Connection ผ่าน State Table

3. **Proxy Firewall** ให้ความปลอดภัยสูงสุดในระดับ Application แต่มีข้อจำกัดด้านประสิทธิภาพและความซับซ้อน

4. **NGFW** เป็นมาตรฐานที่แนะนำในปัจจุบัน — รวมความสามารถหลายอย่างในอุปกรณ์เดียว รวมถึง Application Awareness, User Identification, และ SSL Decryption

5. **สถาปัตยกรรม DMZ** ที่ถูกต้อง (Screened Subnet, Firewall สองตัว) ช่วยปกป้องเครือข่ายภายใน แม้ว่า Service ใน DMZ จะถูกโจมตี

6. **Network Segmentation** ด้วย VLAN, DMZ, และ Micro-segmentation ช่วยจำกัดพื้นผิวการโจมตีและปฏิบัติตามข้อกำหนด Compliance

7. **Security Policy** ควรยึดหลัก Default Deny และ Least Privilege — Rule ควรถูกตรวจสอบ (Audit) เป็นประจำ

8. **การบริหารจัดการ Firewall** ต้องมีกระบวนการ Change Management, Rule Review, และ Cleanup ที่เป็นระบบ

---

## คำถามทบทวน (Review Questions)

1. จงอธิบายความแตกต่างระหว่าง Packet Filter Firewall และ Stateful Inspection Firewall พร้อมยกตัวอย่างข้อได้เปรียบของ Stateful Firewall

2. จงอธิบายหลักการทำงานของ Proxy Firewall และความแตกต่างระหว่าง Forward Proxy กับ Reverse Proxy

3. NGFW มีคุณสมบัติที่แตกต่างจาก Firewall รุ่นก่อนหน้าอย่างไรบ้าง จงอธิบาย App-ID, User-ID, และ SSL Decryption

4. จากสถาปัตยกรรม Screened Subnet (Dual Firewall) จงอธิบายว่าหาก Web Server ใน DMZ ถูกโจมตีสำเร็จ ผู้โจมตียังไม่สามารถเข้าถึง Database Server ใน Internal Network ได้อย่างไร

5. จงออกแบบ VLAN Segmentation สำหรับองค์กรที่มี 4 แผนก (HR, Finance, IT, Sales) และมีระบบ POS ที่ต้องเชื่อมต่อกับสาขาย่อย 10 แห่ง

6. จงอธิบายความแตกต่างระหว่าง Micro-segmentation และ VLAN พร้อมยกตัวอย่างเทคโนโลยีที่ใช้ในแต่ละแนวทาง

7. จงเขียน ACL (ในรูปแบบ Cisco IOS หรือ NGFW Policy) สำหรับข้อกำหนดต่อไปนี้:
   - อนุญาต HTTP/HTTPS จาก Internal ไปยัง Internet
   - อนุญาต SSH จาก DMZ ไปยัง Internal Management Network
   - ปฏิเสธ Telnet ทั้งหมด
   - อนุญาต DNS Query จาก Internal ไปยัง Internet
   - Default Deny

8. Shadow Rules คืออะไร และมีผลกระทบอย่างไรต่อความปลอดภัยเครือข่าย จงอธิบายพร้อมยกตัวอย่าง

9. จงอธิบายกระบวนการ Change Management สำหรับการเพิ่ม Firewall Rule ใหม่ และอธิบายว่าเหตุใดจึงต้องมีกระบวนการดังกล่าว

10. จากกรณีศึกษาในบทนี้ จงวิเคราะห์ว่าหากบริษัทนี้ไม่มี WAF และ DDoS Protection จะมีความเสี่ยงอะไรบ้าง และเสนอแนวทางการลดความเสี่ยงโดยใช้เฉพาะ NGFW

---

## เอกสารอ้างอิง (References)

1. Stallings, W. (2022). *Cryptography and Network Security: Principles and Practice* (8th ed.). Chapter 20: Firewalls. Pearson.

2. Whitman, M. E., & Mattord, H. J. (2021). *Principles of Information Security* (7th ed.). Chapter 7: Firewall Technologies. Cengage Learning.

3. Palo Alto Networks. (2024). *Next-Generation Firewall Administrator's Guide*. Retrieved from https://docs.paloaltonetworks.com/

4. NIST Special Publication 800-41 Rev. 1. (2014). *Guidelines on Firewalls and Firewall Policy*. National Institute of Standards and Technology.

5. NIST Special Publication 800-125B. (2016). *Secure Network Design: Firewall and DMZ Architecture*. National Institute of Standards and Technology.

6. Cisco Systems. (2023). *Cisco Secure Firewall Configuration Guide*. Retrieved from https://www.cisco.com/

7. Gartner. (2009). *Defining the Next-Generation Firewall*. Gartner Research.

8. IEEE 802.1Q. (2022). *IEEE Standard for Local and Metropolitan Area Networks—Bridges and Bridged Networks* (VLAN Tagging).

9. Kubernetes Documentation. (2024). *Network Policies*. Retrieved from https://kubernetes.io/docs/concepts/services-networking/network-policies/

10. Stallings, W. (2021). *Network Security Essentials: Applications and Standards* (6th ed.). Chapter 8: Firewalls. Pearson.
