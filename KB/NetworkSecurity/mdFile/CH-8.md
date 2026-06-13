# CH-8: เครือข่ายส่วนตัวเสมือน (Virtual Private Network — VPN)

## วัตถุประสงค์การเรียนรู้ (Learning Objectives)

เมื่อจบบทนี้แล้ว ผู้เรียนสามารถ:
1. อธิบายหลักการและความจำเป็นของ VPN ในการสื่อสารสมัยใหม่ได้
2. เปรียบเทียบประเภทของ VPN: Site-to-Site, Remote Access, Client-based, และ SSL VPN ได้
3. อธิบายความแตกต่างระหว่าง Tunnel Mode และ Transport Mode ใน VPN Tunneling ได้
4. เปรียบเทียบข้อดีข้อเสียของโพรโทคอล VPN ต่างๆ (IPsec, OpenVPN, WireGuard, L2TP, PPTP) ได้
5. อธิบายกลไกการรักษาความปลอดภัยของ VPN — Authentication, Encryption, Integrity, PFS ได้
6. เลือกใช้ VPN และโพรโทคอลให้เหมาะสมกับความต้องการขององค์กรได้
7. ออกแบบ VPN สำหรับองค์กรที่มีสาขาย่อยหลายแห่งจากกรณีศึกษาได้

---

# ส่วนที่ 1: พื้นฐานของ VPN

## 1. หลักการและความจำเป็นของ VPN

### 1.1 VPN คืออะไร

VPN (Virtual Private Network) คือเทคโนโลยีที่สร้าง **ช่องทางการสื่อสารที่ปลอดภัยและเข้ารหัส (Encrypted Tunnel)** บนเครือข่ายสาธารณะ (เช่น อินเทอร์เน็ต) เพื่อเชื่อมต่อเครือข่ายหรืออุปกรณ์ที่อยู่ห่างไกลเข้าด้วยกัน เสมือนว่าอยู่ในเครือข่ายส่วนตัวเดียวกัน

```
VPN Concept:
────────────
[Office Network] ─────[🔒 Internet Tunnel 🔒]───── [Remote User]
    10.0.0.0/8          (Encrypted Traffic)             VPN Client
```

### 1.2 ทำไมต้องใช้ VPN

| ความต้องการ | คำอธิบาย |
|:------------|:---------|
| **การทำงานระยะไกล (Remote Work)** | พนักงานสามารถเข้าถึงทรัพยากรองค์กรจากที่บ้านหรือระหว่างเดินทางได้อย่างปลอดภัย |
| **การเชื่อมต่อระหว่างสาขา (Site-to-Site)** | เชื่อมต่อเครือข่ายของสำนักงานใหญ่กับสาขาโดยไม่ต้องใช้ Leased Line ราคาแพง |
| **ความเป็นส่วนตัว (Privacy)** | ซ่อน Traffic จาก ISP และผู้ให้บริการเครือข่าย |
| **ความปลอดภัยบน Wi-Fi สาธารณะ** | ปกป้องข้อมูลเมื่อใช้ Wi-Fi ในร้านกาแฟ, สนามบิน, โรงแรม |
| **การข้ามข้อจำกัดทางภูมิศาสตร์** | เข้าถึงเนื้อหาที่ถูกจำกัดตามภูมิภาค (Geo-restriction) |
| **การปกปิดตัวตน (Anonymity)** | ซ่อน IP Address จริงของผู้ใช้ |

### 1.3 สถิติการใช้งาน VPN

- การใช้งาน VPN ทั่วโลกเพิ่มขึ้นมากกว่า 400% ตั้งแต่ปี 2019–2024 (จากรายงานของ Global Market Insights)
- องค์กรขนาดใหญ่กว่า 80% ใช้ VPN Site-to-Site สำหรับเชื่อมต่อสาขา
- พนักงานระยะไกลมากกว่า 65% ใช้งาน VPN ทุกวัน
- การโจมตี VPN Gateway เพิ่มขึ้น 250% ในปี 2023–2024 (ตามรายงานของ CISA)

---

## 2. องค์ประกอบของ VPN

### 2.1 ส่วนประกอบหลัก

```
VPN Components:
────────────────
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ VPN Client   │────▶│ VPN Gateway  │────▶│ Target      │
│ (Software/   │     │ (Server/     │     │ Network     │
│  Hardware)   │◀────│  Appliance)  │◀────│ Resources   │
└─────────────┘     └─────────────┘     └─────────────┘
```

1. **VPN Client:** ซอฟต์แวร์หรืออุปกรณ์ที่ติดตั้งบนเครื่องผู้ใช้หรืออุปกรณ์ปลายทาง
2. **VPN Gateway/Server:** อุปกรณ์หรือเซิร์ฟเวอร์ที่รับการเชื่อมต่อ VPN และเชื่อมต่อกับเครือข่ายเป้าหมาย
3. **VPN Tunnel:** ช่องทางการสื่อสารที่เข้ารหัสระหว่าง Client และ Gateway
4. **Authentication Mechanism:** กลไกพิสูจน์ตัวตน (Pre-shared Key, Certificate, MFA)
5. **Encryption Protocol:** โพรโทคอลที่ใช้เข้ารหัสข้อมูล (AES, ChaCha20)

### 2.2 ประเภทของการเชื่อมต่อ VPN

| ประเภท | การเชื่อมต่อ | ผู้ใช้งานทั่วไป | ตัวอย่าง |
|:-------|:------------|:--------------|:---------|
| **Remote Access VPN** | Client → Gateway | พนักงานระยะไกล 1-1,000+ คน | OpenVPN, AnyConnect, WireGuard |
| **Site-to-Site VPN** | Gateway ↔ Gateway | เชื่อมต่อสาขา 2-100+ แห่ง | IPsec Site-to-Site |
| **Client-to-Site VPN** | ลูกค้า → เครือข่ายองค์กร | ลูกค้าภายนอก | SSL VPN Portal |
| **Host-to-Host VPN** | เครื่อง → เครื่องโดยตรง | ผู้ดูแลระบบ | SSH Tunnel, Direct IPsec |

---

## 3. VPN Tunneling

### 3.1 หลักการ Tunneling

Tunneling คือกระบวนการห่อหุ้ม Packet ต้นฉบับทั้งหมด (รวมถึง Header) ไว้ใน Packet ใหม่ เพื่อให้สามารถส่งผ่านเครือข่ายที่มี Protocol ต่างกันได้อย่างปลอดภัย

```
Tunneling Concept:
──────────────────
Original Packet:
┌──────┬────────────────────────────────────┐
│ IP   │  TCP  │        Payload             │
│Header│ Header│                            │
└──────┴────────────────────────────────────┘

After Encapsulation (Tunnel Mode):
┌──────┬──────┬──────┬────────────────────────────────────┐
│ New  │ VPN  │ IP   │  TCP  │        Payload             │
│ IP   │Proto │Header│ Header│                            │
│Header│(ESP) │      │       │                            │
└──────┴──────┴──────┴────────────────────────────────────┘
        └─────────────── Encrypted ───────────────────────┘
```

### 3.2 Tunnel Mode vs Transport Mode

**Transport Mode:**
- เข้ารหัสเฉพาะ Payload (Layer 4 ขึ้นไป)
- IP Header เดิมยังคงอยู่ (มองเห็นปลายทางจริง)
- ใช้สำหรับ Host-to-Host VPN (เชื่อมต่อโดยตรงระหว่างเครื่อง)

```
Transport Mode:
┌──────┬──────────────────────────────┐
│ IP   │  ESP  │  TCP  │   Payload    │
│Header│ Header│ Header│  (Encrypted) │
└──────┴──────────────────────────────┘
```

**Tunnel Mode:**
- เข้ารหัสทั้ง Packet ต้นฉบับ (รวมถึง IP Header เดิม)
- เพิ่ม IP Header ใหม่ (ปลายทางคือ VPN Gateway)
- ใช้สำหรับ Site-to-Site VPN, Remote Access VPN

```
Tunnel Mode:
┌──────┬──────┬──────────────────────────────┐
│ New  │ ESP  │  Original Packet (ทั้งหมด)    │
│ IP   │Header│  ┌──────┬──────┬──────────┐ │
│Header│      │  │ IP   │ TCP  │ Payload  │ │
│      │      │  │Header│Header│          │ │
│      │      │  └──────┴──────┴──────────┘ │
│      │      │         (Encrypted)         │
└──────┴──────┴──────────────────────────────┘
```

**ตารางเปรียบเทียบ:**

| คุณสมบัติ | Transport Mode | Tunnel Mode |
|:----------|:-------------:|:-----------:|
| Encrypts Original IP Header | ❌ | ✅ |
| New IP Header Added | ❌ | ✅ |
| เห็น Source/Destination จริง | ✅ | ❌ (เห็น Gateway) |
| การใช้งานหลัก | Host-to-Host | Site-to-Site, Remote Access |
| ขนาด Overhead | น้อยกว่า | มากกว่า |
| Performance | ดีกว่า | ช้ากว่าเล็กน้อย |

---

## 4. ประเภทของ VPN ตามการใช้งาน

### 4.1 Remote Access VPN

VPN สำหรับพนักงานระยะไกลที่ต้องการเข้าถึงเครือข่ายองค์กรจากนอกสถานที่:

```
Remote Access VPN:
────────────────────
[Remote User] ──[Internet]──▶ [VPN Gateway] ──▶ [Corporate Network]
   Laptop           🔒               │               10.0.0.0/8
  VPN Client     Encrypted     (Authenticate)        Servers,
                   Tunnel       + Authorize         Printers, DB
```

**ลักษณะการทำงาน:**
1. ผู้ใช้ติดตั้ง VPN Client บนเครื่อง (หรือใช้ Built-in Client ของ OS)
2. เชื่อมต่อไปยัง VPN Gateway ที่อยู่ขอบเครือข่ายองค์กร
3. Gateway ตรวจสอบ Authentication (Username/Password + MFA หรือ Certificate)
4. สร้าง Tunnel ที่เข้ารหัส — ผู้ใช้ได้รับ IP Address ในเครือข่ายองค์กร
5. Traffic ทั้งหมดหรือเฉพาะบางส่วนถูกส่งผ่าน Tunnel

**ข้อดี:**
- พนักงานเข้าถึงทรัพยากรภายในได้จากทุกที่
- ควบคุมการเข้าถึงผ่านนโยบายของ Gateway
- รองรับ MFA

**ข้อเสีย:**
- ต้องติดตั้งและจัดการ Client บนเครื่องผู้ใช้ทุกเครื่อง
- ประสิทธิภาพขึ้นอยู่กับคุณภาพอินเทอร์เน็ตของผู้ใช้
- ปัญหา Split Tunneling — Traffic อินเทอร์เน็ตทั่วไปอาจรั่วไหล

### 4.2 Site-to-Site VPN

VPN สำหรับเชื่อมต่อเครือข่ายระหว่างสาขาหรือระหว่างองค์กร:

```
Site-to-Site VPN:
───────────────────
[HQ Network: 10.0.0.0/16]           [Branch: 10.1.0.0/16]
┌─────────────────┐                  ┌─────────────────┐
│  Servers         │                 │  Local Users     │
│  DB, Files, ERP  │                 │  POS Terminals   │
└────────┬────────┘                 └────────┬────────┘
         │                                   │
┌────────▼────────┐                 ┌────────▼────────┐
│ VPN Gateway (HQ)│◀═══ IPsec Tunnel ═══▶│ VPN Gateway(Br)│
│ 203.0.113.10    │    (Encrypted)       │ 198.51.100.20  │
└─────────────────┘                     └─────────────────┘
```

**ลักษณะการทำงาน:**
1. VPN Gateway ทั้งสองฝั่งมี Public IP (หรือผ่าน NAT Traversal)
2. สร้าง IPsec Tunnel ระหว่าง Gateway ทั้งสอง (IKE Phase 1 + Phase 2)
3. Traffic ระหว่างเครือข่ายย่อย (Subnet) ของทั้งสองฝั่งถูกเข้ารหัสและส่งผ่าน Tunnel
4. ผู้ใช้ปลายทางไม่จำเป็นต้องรู้ว่ามี VPN — ทำงานเสมือนอยู่ในเครือข่ายเดียวกัน

**ข้อดี:**
- เชื่อมต่อสาขาโดยไม่ต้องใช้ Leased Line ราคาแพง
- Transparent — ผู้ใช้ไม่ต้องติดตั้งซอฟต์แวร์เพิ่ม
- รองรับ Multiple Sites (Hub-and-Spoke, Full Mesh)

**ข้อเสีย:**
- ต้องใช้ Public IP หรือ NAT Traversal
- การเพิ่ม Site ใหม่ต้องตั้งค่า Gateway เพิ่ม
- Latency สูงกว่า Local Network

### 4.3 SSL VPN

VPN ที่ทำงานผ่าน Web Browser โดยไม่ต้องติดตั้งซอฟต์แวร์ Client (แต่บางรูปแบบก็ต้องติดตั้ง):

**รูปแบบการทำงานของ SSL VPN:**

| รูปแบบ | การทำงาน | ต้องติดตั้ง Client? |
|:-------|:---------|:------------------:|
| **SSL VPN Portal** | เข้าถึง Web Application ผ่าน Browser (HTTPS Reverse Proxy) | ❌ ไม่ต้อง |
| **SSL VPN Tunnel** | สร้าง Tunnel ระดับ Network (ใช้ JavaScript/Java/ActiveX หรือ Native App) | ✅ ต้อง (Thin Client) |
| **Clientless SSL VPN** | เข้าถึงเฉพาะ Web App ที่กำหนด (ไม่สามารถใช้ App อื่นได้) | ❌ ไม่ต้อง |

**ข้อดี:**
- ไม่ต้องติดตั้งซอฟต์แวร์ (Portal Mode)
- เข้าถึงผ่าน Browser ทั่วไป
- ง่ายต่อการใช้งานสำหรับผู้ใช้ที่ไม่เชี่ยวชาญ
- รองรับ BYOD (Bring Your Own Device)

**ข้อเสีย:**
- Clientless Mode รองรับเฉพาะ Web Application (ไม่รองรับ Native App)
- Performance ต่ำกว่า IPsec VPN
- ความปลอดภัยน้อยกว่าถ้าใช้แค่ Browser (Browser Vulnerability)

### 4.4 Client-based VPN

VPN ที่ต้องติดตั้งซอฟต์แวร์ Client บนเครื่องผู้ใช้:

| Client | แพลตฟอร์ม | โพรโทคอล | จุดเด่น |
|:-------|:----------|:---------|:--------|
| **OpenVPN Connect** | Windows, macOS, Linux, iOS, Android | OpenVPN (SSL/TLS) | Open Source, Cross-platform |
| **WireGuard** | Windows, macOS, Linux, iOS, Android | WireGuard Protocol | เร็วที่สุด, Kernel Integration |
| **Cisco AnyConnect** | Windows, macOS, Linux, iOS, Android | SSL VPN + IPsec | Enterprise Features |
| **Palo Alto GlobalProtect** | Windows, macOS, Linux, iOS, Android | SSL VPN + IPsec | Integration with NGFW |
| **Pulse Secure** | Windows, macOS, Linux, iOS, Android | SSL VPN | Enterprise Support |

---

# ส่วนที่ 2: โพรโทคอล VPN

## 5. IPsec VPN

### 5.1 ภาพรวมของ IPsec

IPsec (Internet Protocol Security) คือชุดโพรโทคอลสำหรับรักษาความปลอดภัยของการสื่อสารแบบ IP ทำงานใน Layer 3 ของ OSI Model — ให้บริการ Authentication, Encryption, และ Integrity

**หมายเหตุ:** รายละเอียดเชิงลึกของ IPsec (AH, ESP, IKE, Security Association) ได้กล่าวถึงแล้วใน CH-5: โพรโทคอลเพื่อการสื่อสารที่ปลอดภัย ในบทนี้จะเน้นการนำ IPsec ไปใช้ในบริบทของ VPN

### 5.2 IPsec VPN Architecture

```
IPsec Site-to-Site VPN Setup:
─────────────────────────────
IKE Phase 1 — Main Mode:
──────────────────────────
HQ (203.0.113.10)                       Branch (198.51.100.20)
      │                                        │
      │────────── SA Proposal ─────────────────▶│
      │         (AES-256, SHA-256, DH-14)      │
      │◀───────── SA Accept ───────────────────│
      │────────── DH Public Key ──────────────▶│
      │◀────────── DH Public Key ──────────────│
      │     (Shared Secret Established)         │
      │────────── Authentication ────────────▶│
      │◀────────── Authentication ─────────────│
      │   (IKE SA Established — Secure Channel) │
      │                                        │

IKE Phase 2 — Quick Mode:
──────────────────────────
HQ (203.0.113.10)                       Branch (198.51.100.20)
      │                                        │
      │────────── IPSec SA Proposal ──────────▶│
      │         (ESP, AES-256, Tunnel Mode)    │
      │◀───────── IPSec SA Accept ─────────────│
      │   (Two Unidirectional SAs Established)  │
      │                                        │
      │◀══════ Encrypted Traffic ═════════════▶│
      │    (ESP Tunnel Mode — AES-256-GCM)      │
```

### 5.3 IPsec VPN Configuration Example

```bash
# ตัวอย่าง: IPsec Site-to-Site VPN on strongSwan (Ubuntu)

# /etc/ipsec.conf — HQ Side
conn hq-to-branch
    left=203.0.113.10
    leftsubnet=10.0.0.0/16
    leftcert=hkCert.pem
    right=198.51.100.20
    rightsubnet=10.1.0.0/16
    rightid="CN=branch.example.com"
    auto=start
    ike=aes256-sha256-modp2048      # IKE Phase 1 Proposal
    esp=aes256gcm128-modp2048       # IKE Phase 2 Proposal
    keyingtries=%forever
    dpdaction=restart
```

```bash
# /etc/ipsec.conf — Branch Side
conn branch-to-hq
    left=198.51.100.20
    leftsubnet=10.1.0.0/16
    leftcert=branchCert.pem
    right=203.0.113.10
    rightsubnet=10.0.0.0/16
    rightid="CN=hq.example.com"
    auto=start
    ike=aes256-sha256-modp2048
    esp=aes256gcm128-modp2048
    keyingtries=%forever
    dpdaction=restart
```

### 5.4 IPsec VPN — ข้อดีและข้อจำกัด

**ข้อดี:**
- มาตรฐานสากล — รองรับทุกอุปกรณ์ (Cisco, Palo Alto, Fortinet, Linux, Windows)
- ความปลอดภัยระดับสูง — รองรับ AES-256, SHA-256, PFS
- Tunnel Mode และ Transport Mode
- Site-to-Site VPN ที่มั่นคง
- Perfect Forward Secrecy (PFS)

**ข้อจำกัด:**
- การตั้งค่าซับซ้อน — มีพารามิเตอร์มากมายที่ต้องตรงกันทั้งสองฝั่ง
- ปัญหา NAT Traversal — ต้องใช้ NAT-T (UDP 4500)
- Performance — IKE Handshake ใช้ CPU สูง
- การทำ Mobility — IPsec ไม่รองรับการเปลี่ยน Network (WiFi → Mobile) ระหว่าง Session
- Dead Peer Detection (DPD) ต้องมีการตั้งค่า

---

## 6. OpenVPN

### 6.1 ภาพรวม

OpenVPN คือ Open Source VPN Solution ที่พัฒนาโดย James Yonan ในปี 2001 ทำงานใน SSL/TLS (Layer 7) — ใช้ Port 443/UDP หรือ 443/TCP ทำให้ผ่าน Firewall และ NAT ได้ง่าย

### 6.2 สถาปัตยกรรม OpenVPN

```
OpenVPN Architecture:
──────────────────────
┌──────────────────────────────────────────────┐
│              OpenVPN Server                   │
│  ┌────────────────────────────────────────┐  │
│  │  Management Interface (port 1194)       │  │
│  ├────────────────────────────────────────┤  │
│  │  TLS Authentication | Data Channel      │  │
│  │  (Control Channel)    | (Encrypted)     │  │
│  │   X.509 Certificate   | AES-256-GCM    │  │
│  │   HMAC Authentication | LZ4 Compression │  │
│  └────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────┐  │
│  │  Virtual TUN/TAP Interface              │  │
│  │  TUN: Layer 3 (IP), TAP: Layer 2 (Ethernet)│
│  └────────────────────────────────────────┘  │
│  Routing / NAT to Internal Network           │
└──────────────────────────────────────────────┘
```

**TUN vs TAP:**
- **TUN (Tunnel):** ส่ง Traffic ระดับ IP (Layer 3) — ประสิทธิภาพดีกว่า ใช้สำหรับ Remote Access VPN
- **TAP (Tap):** ส่ง Traffic ระดับ Ethernet (Layer 2) — รองรับ Broadcast, DHCP, NetBIOS ใช้สำหรับ Network Bridge

### 6.3 การเข้ารหัสใน OpenVPN

OpenVPN แยก Control Channel และ Data Channel:

```
Control Channel (TLS):
├── Authentication: X.509 Certificates
├── Key Exchange: TLS Handshake (ECDHE or DHE)
└── HMAC for Packet Authentication

Data Channel:
├── Cipher: AES-256-GCM (แนะนำ), ChaCha20-Poly1305
├── HMAC: HMAC-SHA-256
└── Key Derivation: จาก TLS Keying Material (ผ่าน PRF)
```

### 6.4 OpenVPN Configuration Example

```bash
# /etc/openvpn/server.conf
port 1194
proto udp
dev tun

# Certificate
ca ca.crt
cert server.crt
key server.key
dh dh2048.pem

# Network
server 10.8.0.0 255.255.255.0
push "route 10.0.0.0 255.255.0.0"
push "dhcp-option DNS 10.0.0.5"

# Security
tls-version-min 1.2
cipher AES-256-GCM
auth SHA-256
tls-crypt tls-crypt.key  # TLS Control Channel Encryption
tls-cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384

# Features
keepalive 10 120
compress lz4-v2
push "compress lz4-v2"
user nobody
group nogroup
status openvpn-status.log
verb 3
```

```bash
# client.ovpn
client
dev tun
proto udp
remote vpn.example.com 1194
resolv-retry infinite
nobind

ca ca.crt
cert client.crt
key client.key
tls-crypt tls-crypt.key

cipher AES-256-GCM
auth SHA-256
tls-version-min 1.2
tls-cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384
compress lz4-v2
verb 3
```

### 6.5 OpenVPN — ข้อดีและข้อจำกัด

**ข้อดี:**
- Open Source — ไม่มีค่าใช้จ่าย ตรวจสอบ Code ได้
- รองรับทุก Platform (Desktop, Mobile, Router Firmware)
- ผ่าน Firewall/NAT ได้ดี (ใช้ Port 443)
- ความปลอดภัยสูง — X.509 + TLS + AES-256-GCM
- รองรับ Multi-factor Authentication
- ชุมชนใหญ่ — มี Documentation และ Tutorial มากมาย

**ข้อจำกัด:**
- Performance ด้อยกว่า WireGuard (Single-threaded)
- การตั้งค่า Server ซับซ้อน (ต้องจัดการ Certificate)
- UDP Mode ต้องตั้งค่า Firewall ให้ถูกต้อง
- การ Scale สำหรับผู้ใช้จำนวนมาก (1,000+) ต้อง Tuning

---

## 7. WireGuard

### 7.1 ภาพรวม

WireGuard คือ VPN Protocol ที่พัฒนาโดย Jason A. Donenfeld ในปี 2016 (รวมเข้าใน Linux Kernel 5.6 ปี 2020) ออกแบบมาให้ **เร็ว ง่าย และปลอดภัย** โดยใช้หลักการ Cryptography ที่ทันสมัย

### 7.2 หลักการออกแบบ WireGuard

WireGuard แตกต่างจาก VPN รุ่นก่อนอย่างมีนัยสำคัญ:

| คุณสมบัติ | IPsec / OpenVPN | WireGuard |
|:----------|:---------------:|:---------:|
| **จำนวนโค้ด** | 400,000+ บรรทัด | ~4,000 บรรทัด |
| **Cipher Suite** | หลายตัวเลือก | Fixed (ตัวเดียว) |
| **Key Management** | IKE, PKI, Certificates | Public/Private Key Pair |
| **Handshake** | 6-9 Messages (IKE) | 1-RTT (3 Messages) |
| **Noise Protocol** | ❌ ไม่ใช้ | ✅ Noise_IK |
| **Kernel Integration** | Userspace | ✅ Linux Kernel Built-in |
| **Roaming** | จำกัด (ต้อง DPD) | ✅ สมบูรณ์ (Connection Migration) |

### 7.3 การทำงานของ WireGuard

```
WireGuard Handshake — 1-RTT:
─────────────────────────────
Client (10.0.0.2)                    Server (10.0.0.1)
      │                                      │
      │── (1) Initiation ──────────────────▶│
      │    Static Public Key (Client)        │
      │    Ephemeral Public Key (x25519)     │
      │    Timestamp                        │
      │                                      │
      │◀─ (2) Response ─────────────────────│
      │    Static Public Key (Server)        │
      │    Ephemeral Public Key (x25519)     │
      │    Encrypted Cookie (Anti-DDoS)      │
      │                                      │
      │── (3) Cookie/Data ────────────────▶│
      │    (Encrypted Data Starts Here)     │
      │                                      │
      │◀══════ Encrypted Data (ChaCha20) ═══▶│
```

**Key Features:**
- **Noise Protocol Framework:** WireGuard ใช้ Noise_IK Handshake — ทนทานต่อ DoS และได้รับการพิสูจน์ความปลอดภัยทางคณิตศาสตร์
- **Fixed Cipher Suite:** ChaCha20-Poly1305 (Encryption + MAC), Curve25519 (Key Exchange), BLAKE2s (Hashing), HKDF (Key Derivation)
- **Connection Migration:** เมื่อ IP เปลี่ยน (WiFi → Mobile) WireGuard รักษา Connection ไว้โดยอัตโนมัติ
- **Silent:** ไม่ส่ง Packet เมื่อไม่มี Traffic — ไม่มี Keepalive (ประหยัดแบตเตอรี่)

### 7.4 WireGuard Configuration Example

```bash
# /etc/wireguard/wg0.conf — Server
[Interface]
Address = 10.200.0.1/24
ListenPort = 51820
PrivateKey = <Server-Private-Key>

# Enable IP forwarding (sysctl net.ipv4.ip_forward=1)
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey = <Client1-Public-Key>
AllowedIPs = 10.200.0.2/32

[Peer]
PublicKey = <Client2-Public-Key>
AllowedIPs = 10.200.0.3/32
```

```bash
# /etc/wireguard/wg0.conf — Client
[Interface]
PrivateKey = <Client-Private-Key>
Address = 10.200.0.2/32
DNS = 10.0.0.5

[Peer]
PublicKey = <Server-Public-Key>
Endpoint = vpn.example.com:51820
AllowedIPs = 10.0.0.0/8, 10.200.0.0/16
PersistentKeepalive = 25
```

### 7.5 WireGuard — ข้อดีและข้อจำกัด

**ข้อดี:**
- **เร็วที่สุด:** ประสิทธิภาพเหนือกว่า OpenVPN 3-4 เท่า (Near-native throughput)
- **โค้ดขนาดเล็ก:** ตรวจสอบ Security Audit ได้ง่าย (~4,000 บรรทัด)
- **ความปลอดภัยสูง:** Modern Cryptography, Forward Secrecy, Denial of Service Resistance
- **Roaming สมบูรณ์:** เปลี่ยน Network โดยไม่ขาด Connection
- **Kernel-level:** ติดตั้งใน Linux Kernel — Latency ต่ำมาก
- **การตั้งค่าง่ายมาก:** ไม่ต้องจัดการ Certificate หรือ PKI

**ข้อจำกัด:**
- **ไม่มี Built-in Authentication สำหรับผู้ใช้** — ไม่มี Username/Password, ไม่มี MFA (ต้องใช้ Layer ด้านบน)
- **ไม่มี Logging / Auditing ในตัว**
- **ไม่มี Dynamic IP Assignment** — กำหนด IP ล่วงหน้าใน Config
- **Multi-factor Authentication** — ต้องทำเอง (ผ่าน Pre-shared Key หรือ Auth Script)
- **DDoS on handshake** — แม้จะป้องกันด้วย Cookie แต่ก็ยังมีช่องโหว่ที่ต้องระวัง

---

## 8. L2TP/IPsec

### 8.1 ภาพรวม

L2TP (Layer 2 Tunneling Protocol) ไม่ใช่ VPN Protocol ที่แท้จริง — เป็น **Tunneling Protocol** ที่ห่อหุ้ม PPP (Point-to-Point Protocol) แต่ไม่มีการเข้ารหัส ดังนั้นจึงต้องทำงานร่วมกับ IPsec (L2TP/IPsec) เพื่อเพิ่ม Encryption

```
L2TP/IPsec Architecture:
─────────────────────────
┌──────────────┐     ┌──────────────┐
│  L2TP Client  │────▶│ L2TP Server   │
│  (PPP Session)│     │ (PPP Terminate)│
└──────┬───────┘     └──────┬───────┘
       │                    │
       ▼                    ▼
┌──────────────┐     ┌──────────────┐
│  IPsec ESP    │◀═══▶│  IPsec ESP    │
│  (Encryption) │     │  (Encryption) │
└──────────────┘     └──────────────┘
```

### 8.2 L2TP/IPsec vs อื่นๆ

| คุณสมบัติ | L2TP/IPsec | OpenVPN | WireGuard |
|:----------|:----------:|:-------:|:---------:|
| ความซับซ้อนในการตั้งค่า | สูง | ปานกลาง | ต่ำ |
| Security | ดี (AES-256) | ดี (AES-256-GCM) | ดีเยี่ยม (ChaCha20) |
| Performance | ปานกลาง | ปานกลาง | สูงมาก |
| NAT Traversal | ต้องตั้งค่า (IPsec NAT-T) | ✅ ดี (UDP/TCP 443) | ✅ ดี (UDP) |
| Built-in Authentication | ✅ (PPP + IPsec) | ✅ (X.509) | ❌ |
| Mobility/Roaming | ❌ | จำกัด | ✅ สมบูรณ์ |

---

## 9. PPTP (Point-to-Point Tunneling Protocol) — ❌ ไม่ปลอดภัย

### 9.1 ความไม่ปลอดภัยของ PPTP

PPTP เป็น VPN Protocol ที่พัฒนาโดย Microsoft ในยุค Windows 95 (1996) ปัจจุบัน **เลิกใช้งานโดยเด็ดขาด** เนื่องจากช่องโหว่ด้านความปลอดภัยร้ายแรง:

**ปัญหาความปลอดภัยของ PPTP:**

| ปัญหา | รายละเอียด |
|:------|:-----------|
| **MS-CHAPv2 Crackable** | MS-CHAPv2 Authentication สามารถ Crack ได้ภายใน 24 ชม. ด้วย GPU |
| **ใช้ MPPE Encryption** | MPPE (Microsoft Point-to-Point Encryption) ใช้ RC4 ซึ่งมีจุดอ่อน |
| **ไม่มีการตรวจสอบ Integrity** | ไม่มี HMAC — เสี่ยงต่อการถูกแก้ไขข้อมูล (Bit Flipping) |
| **Authentication แบบง่าย** | ใช้เฉพาะ Password — ไม่รองรับ Certificate หรือ MFA |
| **ช่องโหว่ Known Plaintext** | RC4 ในโหมด Stream Cipher ถูกโจมตีได้ด้วย Known Plaintext Attack |

### 9.2 Timeline การโจมตี PPTP

- **1998:** มีการพิสูจน์แล้วว่า MS-CHAPv1 ไม่ปลอดภัย
- **2000:** MS-CHAPv2 เปิดตัว — แก้ปัญหาแต่ยังไม่พอ
- **2012:** Moxie Marlinspike และ David Hulton แสดงการ Crack MS-CHAPv2 ได้ใน 24 ชม.
- **2014:** หน่วยงานความมั่นคงของสหรัฐฯ (NSA) แนะนำให้เลิกใช้ PPTP
- **2020:** Microsoft แนะนำให้เลิกใช้ PPTP ใน Windows 10

**สรุป:** PPTP ควรถูกแทนที่ด้วย WireGuard, OpenVPN, หรือ IPsec ทันที — ไม่ควรใช้ในระบบ Production ไม่ว่ากรณีใดๆ

---

## 10. การเลือกใช้ VPN ให้เหมาะสมกับองค์กร

### 10.1 ตารางเปรียบเทียบโพรโทคอล VPN

| คุณสมบัติ | IPsec IKEv2 | OpenVPN | WireGuard | L2TP/IPsec | PPTP |
|:----------|:----------:|:-------:|:---------:|:----------:|:----:|
| ความปลอดภัย | ✅ สูง | ✅ สูง | ✅ สูงมาก | ✅ ปานกลาง | ❌ ต่ำ |
| Performance | ✅ สูง | ⚠️ ปานกลาง | ✅ สูงมาก | ⚠️ ปานกลาง | ✅ เร็วแต่ไม่ปลอดภัย |
| ตั้งค่าง่าย | ❌ ซับซ้อน | ⚠️ ปานกลาง | ✅ ง่าย | ❌ ซับซ้อน | ✅ ง่าย |
| Cross-platform | ✅ ดี | ✅ ดีมาก | ✅ ดี | ✅ ดี | ✅ ทุก Windows |
| NAT Traversal | ✅ IKEv2 | ✅ ดีมาก | ✅ ดี | ⚠️ ต้องตั้งค่า | ⚠️ มีปัญหา |
| ผ่าน Firewall | ⚠️ ปานกลาง | ✅ ดีมาก | ⚠️ ต้องเปิด Port | ⚠️ ปานกลาง | ✅ ดี |
| MFA Support | ✅ มี | ✅ มี | ❌ ไม่มีในตัว | ✅ มี | ❌ |
| Mobility | ✅ IKEv2 Mobility | ❌ | ✅ สมบูรณ์ | ❌ | ❌ |
| เหมาะกับ | Enterprise Site-to-Site | Enterprise Remote Access | Personal/SMB, Performance | Legacy Systems | ❌ ไม่ควรใช้ |

### 10.2 แนวทางการเลือก VPN ตามสถานการณ์

| สถานการณ์ | โพรโทคอลที่แนะนำ | เหตุผล |
|:----------|:-----------------|:-------|
| **Site-to-Site องค์กรขนาดใหญ่** | IPsec (IKEv2) | มาตรฐานอุตสาหกรรม, รองรับทุกอุปกรณ์ |
| **Remote Access พนักงานทั่วไป** | OpenVPN | ผ่าน Firewall ได้ดี, รองรับ MFA |
| **Remote Access ต้องการ Performance** | WireGuard | เร็วที่สุด, เหมาะกับ Video Conference |
| **Mobile Users (iOS/Android)** | IKEv2 หรือ WireGuard | รองรับ Native, Roaming ดี |
| **Personal VPN** | WireGuard | ตั้งค่าง่าย, เร็ว, ปลอดภัย |
| **องค์กรที่ใช้ MS Remote Access** | SSTP (Microsoft) | ใช้ Port 443, ทำงานกับ Windows |
| **ต้องการ Clientless** | SSL VPN Portal | ไม่ต้องติดตั้ง Client — ใช้ Browser |
| **ระบบ Legacy** | L2TP/IPsec (temporary) | อุปกรณ์เก่าที่ไม่รองรับ OpenVPN/WireGuard |

### 10.3 ปัจจัยในการเลือก

| ปัจจัย | คำถามที่ต้องพิจารณา |
|:-------|:-------------------|
| **Security Requirements** | ต้องการ Authentication แบบใด? ต้องการ MFA? FIPS Compliance? |
| **Scale** | มีจำนวนผู้ใช้เท่าใด? 10, 100, 1,000, 10,000 คน? |
| **Device Types** | Windows, macOS, Linux, iOS, Android — รองรับทุก Platform หรือไม่? |
| **Network Constraints** | Firewall Policy, NAT, Port Restrictions |
| **Performance Requirements** | Bandwidth, Latency Sensitivity (VoIP, Video) |
| **Management** | มีทีมดูแลหรือไม่? ต้องการ Central Management หรือไม่? |
| **Budget** | Open Source vs Commercial Solution |
| **Compliance** | PCI DSS, HIPAA, PDPA, GDPR Requirements |

---

## 11. กรณีศึกษา: การออกแบบ VPN สำหรับองค์กรที่มีสาขาย่อยหลายแห่ง

### 11.1 สถานการณ์

บริษัท ABC Corporation:
- **สำนักงานใหญ่ (HQ):** กรุงเทพฯ — พนักงาน 500 คน, Data Center
- **สาขาใหญ่ (Branch 1):** ภูเก็ต — พนักงาน 100 คน
- **สาขากลาง (Branch 2):** เชียงใหม่ — พนักงาน 50 คน
- **สาขาย่อย (Branch 3-5):** ระยอง, ขอนแก่น, สงขลา — พนักงาน 20-30 คนต่อสาขา
- **พนักงาน Remote:** 30 คน (ทำงานที่บ้าน, ระหว่างเดินทาง)
- **จุดขาย (POS):** 50 จุดทั่วประเทศ (ร้านค้าปลีก, เคาน์เตอร์บริการ)
- **Partner Connection:** 3 บริษัทคู่ค้าที่ต้องเชื่อมต่อระบบ

### 11.2 ความต้องการ

1. สาขาทุกแห่งต้องเข้าถึงระบบ ERP, Database, และ File Server ที่ HQ
2. พนักงาน Remote ต้องเข้าถึงทรัพยากรภายในด้วยความปลอดภัยสูง
3. POS ต้องการ Connection ที่เสถียรและปลอดภัย
4. คู่ค้าต้องเข้าถึงเฉพาะบางระบบ (API Gateway) เท่านั้น
5. จะต้องมี High Availability — หาก Gateway ที่ HQ ล้ม สาขาต้องยังทำงานได้

### 11.3 การออกแบบ VPN

```
Design Overview:
─────────────────
                          ┌────────────────────────┐
                          │      HEAD OFFICE         │
                          │      (กรุงเทพฯ)          │
                          │                          │
                          │  ┌────────────────────┐  │
                          │  │  VPN Concentrator    │  │
                          │  │  (Active-Active)     │  │
                          │  │  Cluster HA          │  │
                          │  │  Public IP:           │  │
                          │  │  203.0.113.10/11     │  │
                          │  └──────────┬─────────┘  │
                          │             │             │
                          │     Internal Network      │
                          │    ┌──────────────┐      │
                          │    │  Internal     │      │
                          │    │  DNS, AD, ERP │      │
                          │    │  DB Cluster   │      │
                          │    └──────────────┘      │
                          └────────────┬─────────────┘
                                       │
                                       │
         ┌─────────┬─────────┬─────────┼─────────┬─────────┐
         │         │         │         │         │         │
         ▼         ▼         ▼         ▼         ▼         ▼
   ┌────────┐┌────────┐┌────────┐┌──────────┐┌────────┐┌────────┐
   │Branch 1││Branch 2││Branch 3││Branch 4-5││Remote  ││Partner │
   │ภูเก็ต   ││เชียงใหม่││ระยอง   ││ขอนแก่น/  ││30 คน   ││3 บริษัท │
   │100 คน  ││ 50 คน  ││ 30 คน  ││สงขลา     ││OpenVPN ││IPsec   │
   │IPsec   ││IPsec   ││IPsec   ││IPsec     ││Client  ││Site-to-│
   │Site-to-││Site-to-││Site-to-││Site-to-  ││        ││Site    │
   │Site    ││Site    ││Site    ││Site      ││        ││Limited │
   └────────┘└────────┘└────────┘└──────────┘└────────┘└────────┘
        │         │         │          │         │         │
   POS 50 จุด ───────────────────────────────────────────────
        (4G Router with IPsec to HQ)
```

### 11.4 การเลือกโพรโทคอลตามกลุ่มผู้ใช้

| กลุ่ม | โพรโทคอล | รายละเอียด |
|:------|:----------|:-----------|
| **สาขาขนาดใหญ่** (Branch 1-2) | **IPsec Site-to-Site** | Gateway-to-Gateway, Tunnel Mode, AES-256-GCM, PFS |
| **สาขาขนาดกลาง-เล็ก** (Branch 3-5) | **IPsec Site-to-Site** | Hub-and-Spoke topology เชื่อมต่อตรงถึง HQ |
| **พนักงาน Remote** | **OpenVPN (SSL)** | ผ่าน Firewall ได้ดี, รองรับ MFA + Certificate + Username/Password |
| **POS Terminal** | **WireGuard** | ต้องการ Performance สูง + Connection Migration (4G สลับเครือข่าย) |
| **Partner Access** | **IPsec Site-to-Site (จำกัด)** | เชื่อมต่อเฉพาะ DMZ — ไม่สามารถเข้าถึง Internal Network |

### 11.5 นโยบายความปลอดภัย

```
Security Policy:
─────────────────

1. Authentication:
   ├── IPsec Site-to-Site: Pre-shared Key + Certificate
   ├── OpenVPN (Remote):   Certificate + Username/Password + MFA (TOTP)
   ├── WireGuard (POS):    Public/Private Key + Pre-shared Key
   └── Partner IPsec:      Certificate + Restricted Source IP

2. Encryption:
   ├── IPsec: AES-256-GCM + SHA-256 + DH Group 14 (2048-bit)
   ├── OpenVPN: AES-256-GCM + TLS 1.3 + ECDHE P-384
   └── WireGuard: ChaCha20-Poly1305 + Curve25519

3. Segmentation:
   ├── VPN Users → VLAN 100 (Remote Access)
   ├── Branch Networks → VLAN 200-205 (Site-to-Site)
   ├── POS Network → VLAN 300 (Isolated, Internet-only access)
   └── Partner Network → VLAN 400 (DMZ, restricted access)

4. Access Control:
   ├── Remote Users: เข้าถึงได้เฉพาะ Application Server (ไม่ถึง Database โดยตรง)
   ├── Branch: เข้าถึง Internal Network เต็ม (ผ่าน Firewall Policy)
   ├── POS: เข้าถึงเฉพาะ POS Server (TCP 443) + DNS
   └── Partner: เข้าถึงเฉพาะ API Gateway (HTTPS) — ไม่สามารถ SSH หรือ RDP
```

### 11.6 High Availability Design

```
HA Architecture:
─────────────────
VPN Concentrator Cluster (Active-Active):
├── Node 1: wg-hq-01.example.com (203.0.113.10)
├── Node 2: wg-hq-02.example.com (203.0.113.11)
├── VIP:    203.0.113.12 (Floating IP)
└── Health Check: ICMP + Port 51820

Failover:
├── Primary Link: ISP1 (500 Mbps Fiber)
├── Secondary: ISP2 (100 Mbps 4G Backup)
└── Site-to-Site: IPsec DPD + Auto-failover

Redundancy at Branch:
├── Main Router: IPsec Tunnel to wg-hq-01
├── Backup: 4G Failover → WireGuard Tunnel
└── Auto-detect: OSPF / BGP Routing
```

### 11.7 บทเรียนและข้อเสนอแนะ

1. **ไม่ใช้ Hub-and-Spoke สำหรับทุก Traffic:** จากประสบการณ์ การส่ง Traffic สาขาไปยังสาขาอื่นผ่าน HQ ช้า — ควรใช้ Full Mesh สำหรับสาขาขนาดใหญ่
2. **Monitoring สำคัญ:** ใช้ VPN Monitoring Tool (Zabbix, PRTG) ตรวจสอบ Tunnel Status, Latency, Packet Loss
3. **Bandwidth Management:** Remote Users ควรมี Bandwidth Limit — ป้องกันคนเดียวใช้ Bandwidth หมด
4. **Logging และ Audit:** VPN Gateway ต้อง Log การเชื่อมต่อทุกครั้ง — ส่งไปยัง SIEM
5. **Firmware Updates:** อัปเดต Firmware ของ VPN Gateway อย่างสม่ำเสมอ — ช่องโหว่ VPN Gateway ถูกโจมตีมากขึ้น
6. **Split Tunneling Policy:** กำหนดว่าผู้ใช้ Remote ควรส่ง Traffic ใดผ่าน VPN — ควรส่งเฉพาะ Traffic ที่จำเป็น (ไม่ส่ง Netflix หรือ YouTube ผ่าน VPN)

---

## สรุปท้ายบท (Chapter Summary)

1. **VPN** สร้างช่องทางการสื่อสารที่ปลอดภัยบนเครือข่ายสาธารณะ — จำเป็นสำหรับการทำงานระยะไกลและการเชื่อมต่อสาขา

2. **Tunneling** คือการห่อหุ้ม Packet ต้นฉบับใน Packet ใหม่ — มี 2 โหมด: Transport Mode (เข้ารหัสเฉพาะ Payload) และ Tunnel Mode (เข้ารหัสทั้ง Packet)

3. **ประเภทของ VPN ตามการใช้งาน:** Remote Access, Site-to-Site, SSL VPN, และ Client-based — แต่ละแบบเหมาะกับสถานการณ์ต่างกัน

4. **IPsec** เป็นมาตรฐาน Site-to-Site VPN ที่มีความปลอดภัยสูงแต่ตั้งค่าซับซ้อน — ใช้ IKE สำหรับ Key Exchange และ ESP สำหรับ Encryption

5. **OpenVPN** เป็น Open Source VPN ที่ยืดหยุ่น รองรับหลาย Platform ผ่าน Firewall ได้ดี — เหมาะสำหรับ Remote Access Enterprise

6. **WireGuard** เป็น VPN ที่เร็วที่สุด — โค้ดขนาดเล็ก, Cryptography ทันสมัย, Kernel Integration, Roaming สมบูรณ์ — เหมาะกับ Performance-critical Applications

7. **PPTP** ไม่ปลอดภัย — ห้ามใช้เด็ดขาด — โปรดย้ายไปใช้ WireGuard, OpenVPN, หรือ IPsec

8. **การเลือก VPN** ต้องพิจารณา Security, Performance, Scale, Device Types, Network Constraints, และ Budget

9. **การออกแบบ VPN สำหรับองค์กร** ต้องมี High Availability, Segmentation, Monitoring, และ Incident Response Plan

---

## คำถามทบทวน (Review Questions)

1. จงอธิบายความแตกต่างระหว่าง Transport Mode และ Tunnel Mode ใน VPN พร้อมยกตัวอย่างการใช้งานที่เหมาะสมของแต่ละโหมด

2. เปรียบเทียบ Site-to-Site VPN และ Remote Access VPN ในแง่ของ Gateway, Client, และ Security Requirements

3. จงอธิบายข้อดีและข้อเสียของ SSL VPN Portal Mode เมื่อเทียบกับ Full Tunnel VPN

4. เปรียบเทียบ OpenVPN และ WireGuard ในด้าน: ความเร็ว, ความปลอดภัย, ความง่ายในการตั้งค่า, และการสนับสนุน MFA

5. จงอธิบายว่าเหตุใด PPTP จึงไม่ปลอดภัย และควรใช้โพรโทคอลใดแทนสำหรับ Legacy Systems

6. ในกรณีศึกษาของบริษัท ABC Corporation จงวิเคราะห์ว่าหากใช้ WireGuard แทน IPsec สำหรับการเชื่อมต่อสาขา จะมีข้อดีและข้อเสียอย่างไร

7. NAT Traversal คืออะไร และเหตุใดจึงเป็นปัญหาสำหรับ IPsec VPN? จงอธิบายวิธีแก้ไขด้วย NAT-T

8. จงออกแบบนโยบาย Split Tunneling สำหรับพนักงาน Remote — Traffic ใดควรผ่าน VPN และ Traffic ใดไม่ควร?

9. จงอธิบาย Perfect Forward Secrecy (PFS) และความสำคัญต่อความปลอดภัยของ VPN

10. หาก VPN Gateway ขององค์กรถูกโจมตีจนระบบล่ม จะมีแผนสำรอง (Disaster Recovery) อย่างไร? จงออกแบบ HA Architecture สำหรับ VPN Concentrator

---

## เอกสารอ้างอิง (References)

1. Kaufman, C., Perlman, R., & Speciner, M. (2022). *Network Security: Private Communication in a Public World* (3rd ed.). Chapter 15-17: IPsec, VPNs. Addison-Wesley.

2. Stallings, W. (2022). *Cryptography and Network Security: Principles and Practice* (8th ed.). Chapter 19: IP Security. Pearson.

3. Donenfeld, J. A. (2017). "WireGuard: Next Generation Kernel Network Tunnel." *Proceedings of the 2017 Network and Distributed System Security Symposium (NDSS)*.

4. OpenVPN Inc. (2024). *OpenVPN Community Resources*. Retrieved from https://community.openvpn.net/

5. WireGuard Project. (2024). *WireGuard Documentation*. Retrieved from https://www.wireguard.com/

6. NIST Special Publication 800-77 Rev. 1. (2020). *Guide to IPsec VPNs*. National Institute of Standards and Technology.

7. Microsoft Corporation. (2020). *PPTP is deprecated in Windows 10*. Retrieved from Microsoft Docs.

8. IETF RFC 7296. (2014). *Internet Key Exchange Protocol Version 2 (IKEv2)*.

9. IETF RFC 8446. (2018). *The Transport Layer Security (TLS) Protocol Version 1.3*.

10. CISA. (2023). *Guidance on Securing VPNs*. Cybersecurity and Infrastructure Security Agency.
