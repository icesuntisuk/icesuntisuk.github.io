# CH-5: โพรโทคอลเพื่อการสื่อสารที่ปลอดภัย

## วัตถุประสงค์การเรียนรู้ (Learning Objectives)

เมื่อจบบทนี้แล้ว ผู้เรียนสามารถ:
1. อธิบายหลักการรักษาความปลอดภัยในแต่ละ Layer ของ OSI Model และระบุโพรโทคอลที่เกี่ยวข้องได้
2. อธิบายการทำงานของ TLS Handshake Protocol ทั้ง TLS 1.2 และ TLS 1.3 พร้อมเปรียบเทียบข้อแตกต่างได้
3. วิเคราะห์โครงสร้างของ Cipher Suite และอธิบายบทบาทของแต่ละองค์ประกอบได้
4. อธิบายสถาปัตยกรรมของ IPsec เปรียบเทียบ AH และ ESP รวมถึง Transport Mode และ Tunnel Mode ได้
5. อธิบายกระบวนการเข้ารหัสของ SSH และเปรียบเทียบวิธีการรับรองตัวตนรูปแบบต่างๆ ได้
6. เปรียบเทียบจุดแข็งและจุดอ่อนด้านความปลอดภัยระหว่างโพรโทคอล HTTPS, FTPS, SFTP, SMTPS, DNS over HTTPS/TLS และ WireGuard ได้
7. วิเคราะห์กลไกการโจมตี SSL/TLS ที่สำคัญในประวัติศาสตร์ และออกแบบมาตรการป้องกันได้
8. กำหนดค่าโพรโทคอลความปลอดภัยตามมาตรฐาน Mozilla SSL Configuration Guidelines และ OWASP Transport Layer Protection ได้

---

## 1. หลักการรักษาความปลอดภัยในแต่ละ Layer ของ OSI Model

### 1.1 OSI Model และตำแหน่งของ Security Protocol

การทำความเข้าใจ OSI Model 7 ชั้นมีความสำคัญต่อการออกแบบระบบรักษาความปลอดภัยในเครือข่าย เนื่องจากโพรโทคอลความปลอดภัยแต่ละชนิดทำงานใน Layer ที่แตกต่างกัน ซึ่งมีข้อดีและข้อจำกัดต่างกันไป

```
┌───────────────┬──────────────────────┬─────────────────────────────────────┐
│ OSI Layer     │ โพรโทคอลความปลอดภัย  │ ฟังก์ชันความปลอดภัย                    │
├───────────────┼──────────────────────┼─────────────────────────────────────┤
│ 7.Application │ HTTPS, SMTPS, FTPS,  │ รักษาความปลอดภัยเฉพาะแอปพลิเคชัน       │
│               │ SFTP, SSH, DNSSEC    │                                     │
│ 6.Presentation│ TLS/SSL              │ เข้ารหัสข้อมูลก่อนส่งไปยัง Session    │
│ 5.Session     │ SSH, SOCKS5, TLS     │ จัดการ Session อย่างปลอดภัย           │
│ 4.Transport   │ TLS, DTLS, QUIC      │ รักษาความปลอดภัยของ Segment          │
│ 3.Network     │ IPsec, WireGuard     │ รักษาความปลอดภัยของ Packet           │
│ 2.Data Link   │ MACsec, 802.1X       │ รักษาความปลอดภัยของ Frame            │
│ 1.Physical    │ —                    │ ความปลอดภัยทางกายภาพ                 │
└───────────────┴──────────────────────┴─────────────────────────────────────┘
```

### 1.2 การรักษาความปลอดภัยในแต่ละ Layer: ข้อดีและข้อเสีย

| Layer | รูปแบบการป้องกัน | ข้อดี | ข้อเสีย |
|-------|-----------------|------|--------|
| **Application Layer** | เข้ารหัสที่ระดับแอปพลิเคชัน (HTTPS, SMTPS) | ควบคุมความปลอดภัยเฉพาะ Application ได้, รู้จักโครงสร้างข้อมูล | ต้อง implement ทุก Application แยกกัน |
| **Transport Layer** | TLS, DTLS — เข้ารหัส Segment | โปร่งใสต่อ Application, ใช้กับหลายโพรโทคอล | ไม่ปกปิด IP Header, ต้องจัดการ Certificate |
| **Network Layer** | IPsec — เข้ารหัส Packet ทั้งหมด | ป้องกันทุกอย่างตั้งแต่ Layer 3 ขึ้นไป | ซับซ้อน, Performance Overhead สูง |
| **Data Link Layer** | MACsec, 802.1X — เข้ารหัส Frame | เร็วมาก, เหมาะกับ LAN/Link-local | ไม่รองรับ Routing ข้ามเครือข่าย |

### 1.3 การเลือก Layer สำหรับรักษาความปลอดภัย

หลักการสำคัญในการเลือก Layer:

1. **ยิ่ง Layer ต่ำ ยิ่งครอบคลุมกว้าง** — Network Layer Security (IPsec) ป้องกันทุก Application ที่ใช้ IP
2. **ยิ่ง Layer สูง ยิ่งควบคุมละเอียด** — Application Layer Security รู้จักข้อมูลและสามารถใช้ Policy ตามเนื้อหาได้
3. **End-to-End vs Link-by-Link** — TLS ให้ End-to-End Security (ระหว่าง Client และ Server) ส่วน IPsec ใน Tunnel Mode ให้ Site-to-Site Security
4. **Protocol Overhead** — การเข้ารหัสใน Layer ต่ำ (Data Link) มี Overhead น้อยกว่า Layer สูง

---

## 2. SSL/TLS (Secure Sockets Layer / Transport Layer Security)

### 2.1 วิวัฒนาการของ SSL/TLS

SSL/TLS เป็นโพรโทคอลความปลอดภัยที่ใช้กันอย่างแพร่หลายที่สุดสำหรับการสื่อสารบนอินเทอร์เน็ต พัฒนาโดย Netscape ในปี 1995 และต่อมาได้รับการนำไปกำหนดเป็นมาตรฐานโดย IETF ในชื่อ TLS

| เวอร์ชัน | ปี | สถานะปัจจุบัน | ช่องโหว่สำคัญ |
|----------|-----|---------------|--------------|
| SSL 1.0 | — | ไม่เคยเผยแพร่ต่อสาธารณะ | — |
| SSL 2.0 | 1995 | **ยกเลิก** — RFC 6176 | Weak MAC, ไม่ป้องกัน Padding |
| SSL 3.0 | 1996 | **ยกเลิก** — RFC 7568 | POODLE (CVE-2014-3566) |
| TLS 1.0 | 1999 | **ยกเลิก** — RFC 8996 (2021) | BEAST, Lucky13 |
| TLS 1.1 | 2006 | **ยกเลิก** — RFC 8996 (2021) | CBC Timing Attacks |
| TLS 1.2 | 2008 | **ปลอดภัย** (ใช้งานแพร่หลาย) | ขึ้นอยู่กับ Cipher Suite ที่เลือก |
| TLS 1.3 | 2018 | **ปลอดภัยที่สุด** — แนะนำให้ใช้ | 0-RTT Replay (ในบางกรณี) |

### 2.2 TLS Handshake Protocol — กลไกการสร้างการเชื่อมต่อที่ปลอดภัย

TLS Handshake เป็นกระบวนการที่ Client และ Server ตกลงกันเกี่ยวกับพารามิเตอร์ความปลอดภัย ก่อนเริ่มการสื่อสารที่เข้ารหัส

#### 2.2.1 TLS 1.2 Handshake (2-RTT)

TLS 1.2 Handshake ใช้เวลา 2 Round Trip Times (RTT) ก่อนเริ่มส่งข้อมูล:

```
Client                                      Server
  │                                           │
  │──── ClientHello ────────────────────────→│  RTT 1
  │   (Protocol Version: 1.2                 │
  │    Cipher Suites: 30+ options             │
  │    Random: r_client                       │
  │    Session ID / Session Ticket            │
  │    Extensions: SNI, ALPN, etc.)          │
  │                                           │
  │←── ServerHello ──────────────────────────│
  │   (Selected Cipher Suite:                 │
  │    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384  │
  │    Random: r_server                       │
  │    Session ID)                            │
  │                                           │
  │←── Certificate ──────────────────────────│
  │   (Server's Certificate Chain)            │
  │                                           │
  │←── ServerKeyExchange ────────────────────│
  │   (ECDHE Public Key, Signature)           │
  │                                           │
  │←── ServerHelloDone ──────────────────────│
  │                                           │
  │── ClientKeyExchange ────────────────────→│  RTT 2
  │   (Client ECDHE Public Key)               │
  │                                           │
  │── ChangeCipherSpec ─────────────────────→│
  │── Finished ─────────────────────────────→│
  │   (Encrypted Handshake Messages)          │
  │                                           │
  │←── ChangeCipherSpec ─────────────────────│
  │←── Finished ─────────────────────────────│
  │                                           │
  │══════ Secure Data (Record Protocol) ══════│
```

**ขั้นตอน TLS 1.2 Handshake โดยละเอียด:**

1. **ClientHello** — Client ส่งเวอร์ชัน TLS ที่รองรับ, รายการ Cipher Suite ที่รองรับ, Random Number, Session ID (ถ้ามี), และ Extensions (SNI, ALPN)
2. **ServerHello** — Server เลือก Cipher Suite, ส่ง Random Number และ Session ID
3. **Certificate** — Server ส่ง Certificate Chain (Server Certificate + Intermediate CA)
4. **ServerKeyExchange** — Server ส่ง ECDHE Public Key และ Digital Signature เพื่อยืนยัน
5. **ServerHelloDone** — Server บอกว่า "ส่งข้อมูลครบแล้ว"
6. **ClientKeyExchange** — Client ส่ง ECDHE Public Key
7. **ChangeCipherSpec** — ทั้งสองฝ่ายเปลี่ยนไปใช้ Cipher Parameters ที่ตกลงกัน
8. **Finished** — ส่งข้อความที่เข้ารหัสแล้วเพื่อยืนยัน Handshake สมบูรณ์

#### 2.2.2 TLS 1.3 Handshake (1-RTT)

TLS 1.3 ปฏิรูป Handshake Protocol ใหม่ทั้งหมด ลดจาก 2 RTT เหลือ 1 RTT และเพิ่ม 0-RTT สำหรับการ Resume Session:

```
Client                                      Server
  │                                           │
  │──── ClientHello ────────────────────────→│  RTT 1
  │   (Protocol Version: 1.3                 │  (ลดเหลือ 1 RTT)
  │    Key Share: ECDHE Public Key           │
  │    Cipher Suites: 5 options (AEAD only)  │
  │    Random: r_client                       │
  │    Extensions: SNI, ALPN, PSK, etc.)     │
  │                                           │
  │←── ServerHello ──────────────────────────│
  │   (Selected Cipher Suite:                 │
  │    TLS_AES_256_GCM_SHA384                 │
  │    Key Share: ECDHE Public Key            │
  │    Random: r_server)                      │
  │                                           │
  │←── EncryptedExtensions ──────────────────│
  │←── Certificate ──────────────────────────│
  │←── CertificateVerify ────────────────────│
  │←── Finished ─────────────────────────────│
  │                                           │
  │── Finished ─────────────────────────────→│
  │                                           │
  │══════ Secure Data (Record Protocol) ══════│
```

**การปรับปรุงที่สำคัญใน TLS 1.3:**
- **1-RTT Handshake** — รวม Key Exchange ใน ClientHello/ServerHello ทันทีโดยใช้ Key Share
- **0-RTT (Early Data)** — Client สามารถส่งข้อมูล Application ใน ClientHello ได้ทันทีสำหรับ Session Resume (มีความเสี่ยง Replay Attack)
- **ลบ Algorithm ที่ไม่ปลอดภัย** — RSA Key Exchange, CBC Mode, RC4, 3DES, SHA-1 ได้รับการตัดออกทั้งหมด
- **Cipher Suite ลดลง** — จาก 30+ เหลือเพียง 5 Cipher Suite (AEAD เท่านั้น)
- **EncryptedExtensions** — ส่วนขยายได้รับการเข้ารหัส (SNI, ALPN ได้รับการซ่อนจากผู้โจมตี)
- **Certificate Encryption** — Certificate ได้รับการเข้ารหัสในการส่ง (Privacy improvement)

#### 2.2.3 TLS 1.2 vs TLS 1.3 เปรียบเทียบโดยละเอียด

| คุณสมบัติ | TLS 1.2 | TLS 1.3 |
|-----------|---------|---------|
| **Round Trip** | 2 RTT | 1 RTT (0-RTT สำหรับ Resume) |
| **Cipher Suite** | 30+ ตัวเลือก | 5 ตัวเลือก (AEAD เท่านั้น) |
| **Perfect Forward Secrecy** | Optional (ต้องเลือก ECDHE/DHE) | **บังคับ** |
| **Key Exchange** | RSA, DH, ECDH, DHE, ECDHE | เฉพาะ ECDHE, DHE |
| **Symmetric Cipher** | AES-CBC, AES-GCM, ChaCha20, RC4, 3DES | เฉพาะ AEAD: AES-GCM, ChaCha20-Poly1305, AES-CCM |
| **Hash** | MD5, SHA-1, SHA-224, SHA-256, SHA-384 | SHA-256, SHA-384 |
| **Handshake Encryption** | หลังจาก ChangeCipherSpec | **ทั้ง Handshake (EncryptedExtensions)** |
| **0-RTT** | ไม่มี | มี (Replay Risk) |
| **Session Resumption** | Session ID, Session Ticket | PSK (Pre-Shared Key) + 0-RTT |
| **Algorithm Negotiation** | Server เลือกจาก Client รายการ | Server เลือก, Client ต้องส่ง Key Share ล่วงหน้า |
| **Downgrade Protection** | SCSV | Downgrade SCSV + Message |

### 2.3 โครงสร้างของ Cipher Suite

Cipher Suite คือชุดของ Algorithm ที่ทำงานร่วมกันใน TLS โดยแต่ละ Cipher Suite ประกอบด้วย 4 ส่วนหลัก:

```
  TLS     _ ECDHE   _ RSA   _ WITH   _ AES_256_GCM   _ SHA384
  │          │         │                │               │
  └───┬───   └──┬──    └──┬──           └──┬──          └──┬──
Protocol  Key Exch.  Auth.        Bulk Encryption      PRF / MAC
(TLS)    (ECDHE)    (RSA)        (AES-256-GCM)        (SHA-384)
```

#### 2.3.1 องค์ประกอบของ Cipher Suite

| องค์ประกอบ | หน้าที่ | ตัวอย่าง Algorithm |
|------------|--------|-------------------|
| **Key Exchange** | ใช้ตกลง Session Key ระหว่าง Client-Server อย่างปลอดภัย | RSA, DHE, ECDHE, PSK |
| **Authentication** | ใช้ยืนยันตัวตนของ Server (และ Client ใน mTLS) | RSA, ECDSA, EdDSA |
| **Bulk Encryption** | ใช้เข้ารหัสข้อมูลจำนวนมากระหว่าง Session | AES-GCM, AES-CCM, ChaCha20-Poly1305 |
| **PRF / MAC** | ใช้สร้าง Key Material และตรวจสอบ Integrity | SHA-256, SHA-384, HMAC |

#### 2.3.2 การถอดรหัสชื่อ Cipher Suite

ตัวอย่าง Cipher Suite 5 ตัวที่ TLS 1.3 กำหนด (RFC 8446):

| Cipher Suite (Hex) | ชื่อเต็ม |
|-------------------|---------|
| `0x1301` | TLS_AES_128_GCM_SHA256 |
| `0x1302` | TLS_AES_256_GCM_SHA384 |
| `0x1303` | TLS_CHACHA20_POLY1305_SHA256 |
| `0x1304` | TLS_AES_128_CCM_SHA256 |
| `0x1305` | TLS_AES_128_CCM_8_SHA256 |

**โน้ต:** ใน TLS 1.3 Key Exchange และ Authentication ได้รับการแยกออกจาก Cipher Suite — ทุกรายการใช้ ECDHE หรือ DHE เท่านั้น

### 2.4 TLS Record Protocol

TLS Record Protocol เป็นชั้นที่อยู่ใต้ Handshake Protocol และเหนือ Transport Layer (TCP) ทำหน้าที่รับข้อมูลจากชั้นบน (Handshake, Alert, Application Data) และเข้ารหัสก่อนส่งไปยัง TCP:

```
┌──────────────────────────────────────────────────────────┐
│                     Application Data                       │
├──────────────────────────────────────────────────────────┤
│                                                          │
│   TLS Record Protocol                                     │
│   ┌──────────────────────────────────────────────────┐   │
│   │ 1. Fragment — ตัดข้อมูลเป็น Record (16KB สูงสุด)  │   │
│   │ 2. Compress (Optional — ไม่ใช้ใน TLS 1.3)        │   │
│   │ 3. MAC (TLS 1.2) / AEAD (TLS 1.3)               │   │
│   │ 4. Encrypt — เข้ารหัสด้วย Cipher ที่ตกลง          │   │
│   │ 5. Record Header — Content Type, Version, Length │   │
│   └──────────────────────────────────────────────────┘   │
├──────────────────────────────────────────────────────────┤
│                        TCP                                │
└──────────────────────────────────────────────────────────┘
```

**รูปแบบ TLS Record:**

```
┌─────────┬─────────┬──────────────────┬──────────────────┐
│ 1 byte  │ 2 bytes │ 2 bytes          │ Variable          │
├─────────┼─────────┼──────────────────┼──────────────────┤
│ Type    │ Version │ Length           │ Data (เข้ารหัส)    │
└─────────┴─────────┴──────────────────┴──────────────────┘
```

**Content Type ที่สำคัญ:**

| ค่า | ประเภท | คำอธิบาย |
|-----|--------|----------|
| `0x14` | ChangeCipherSpec | แจ้งเปลี่ยน Cipher Parameters (TLS 1.2 เท่านั้น) |
| `0x15` | Alert | แจ้งเตือนข้อผิดพลาดหรือปิดการเชื่อมต่อ |
| `0x16` | Handshake | ข้อมูล Handshake (Certificate, Key Exchange, ฯลฯ) |
| `0x17` | Application Data | ข้อมูล Application ที่เข้ารหัสแล้ว |
| `0x18` | Heartbeat | Heartbeat Extension (ได้รับการใช้ใน Heartbleed) |

### 2.5 TLS Extensions ที่สำคัญ

TLS Extensions ช่วยเพิ่มฟังก์ชันการทำงานให้กับ TLS:

| Extension | หน้าที่ | ความสำคัญ |
|-----------|--------|-----------|
| **SNI (Server Name Indication)** | Client บอกชื่อ Hostname ที่ต้องการเชื่อมต่อ | รองรับ Virtual Hosting (หลาย Certificate บน IP เดียว) |
| **ALPN (Application-Layer Protocol Negotiation)** | Client และ Server ตกลง Protocol ชั้นบน (HTTP/2, HTTP/3) | จำเป็นสำหรับ HTTP/2 และ HTTP/3 |
| **Key Share** | Client ส่ง ECDHE Public Key ล่วงหน้า (TLS 1.3) | ลด RTT |
| **PSK (Pre-Shared Key)** | Resume Session โดยใช้ PSK (TLS 1.3) | รองรับ 0-RTT |
| **Supported Groups** | Client แจ้ง Elliptic Curves ที่รองรับ | ปลอดภัยขึ้น (Curve25519, P-256) |
| **Certificate Transparency** | ส่ง SCT (Signed Certificate Timestamp) | ตรวจสอบ Certificate ว่าไม่ได้รับการออกโดยมิชอบ |
| **OCSP Stapling** | Server ส่ง OCSP Response พร้อม Certificate | ผู้ใช้ไม่ต้องเชื่อมต่อ OCSP Server แยก |

### 2.6 DTLS (Datagram TLS)

DTLS เป็น TLS ที่ปรับให้ทำงานบน UDP (Datagram) แทน TCP:

| คุณสมบัติ | TLS | DTLS |
|-----------|-----|------|
| **Transport** | TCP | UDP |
| **Sequence** | TCP จัดลำดับเอง | ต้องจัดการ Sequence Number เอง |
| **Packet Loss** | TCP จัดการ | ต้องจัดการเอง (Retransmission) |
| **MTU** | TCP จัดการ Segmentation | ต้องจัดการ Fragment เอง |
| **Latency** | สูงกว่า (TCP Overhead) | ต่ำกว่า (UDP) |
| **การใช้งาน** | HTTPS, SMTPS, FTPS | WebRTC, VoIP, IoT, VPN (OpenVPN Data Channel) |

**DTLS เวอร์ชันปัจจุบัน:** DTLS 1.2 (RFC 6347) และ DTLS 1.3 (RFC 9147)

---

## 3. IPsec (Internet Protocol Security)

### 3.1 ภาพรวมของ IPsec

IPsec เป็นชุดโพรโทคอลสำหรับรักษาความปลอดภัยในระดับ Network Layer (Layer 3) ของ OSI Model ให้บริการ 4 ด้าน:

1. **Authentication** — ยืนยันว่า Packet มาจากแหล่งที่ถูกต้อง
2. **Encryption** — เข้ารหัสข้อมูลใน Packet
3. **Integrity** — ตรวจสอบว่า Packet ไม่ได้รับการเปลี่ยนแปลงระหว่างทาง
4. **Anti-Replay** — ป้องกันการส่ง Packet ซ้ำ (Replay Attack)

### 3.2 สถาปัตยกรรม IPsec

IPsec ประกอบด้วยองค์ประกอบหลักหลายส่วนที่ทำงานร่วมกัน:

```
┌────────────────────────────────────────────────────┐
│                    IPsec System                      │
├────────────┬───────────┬─────────────┬─────────────┤
│   AH       │    ESP    │    IKE      │   SA/SAD    │
│ (Auth.     │ (Auth. +  │ (Key Mgmt)  │ (Security   │
│  Header)   │  Encrypt) │             │  Assoc.)    │
├────────────┴───────────┴─────────────┴─────────────┤
│              SPD (Security Policy Database)          │
│     → กำหนดว่า Traffic ไหนต้องเข้ารหัส/ข้าม/Block     │
└────────────────────────────────────────────────────┘
```

### 3.3 Security Association (SA) และ Security Policy Database (SPD)

| องค์ประกอบ | หน้าที่ |
|-----------|--------|
| **SA (Security Association)** | ความสัมพันธ์ด้านความปลอดภัยระหว่าง 2 ฝ่าย — กำหนด Algorithm, Key, SPI |
| **SAD (SA Database)** | ตารางเก็บ SA ที่ใช้งานอยู่ทั้งหมด |
| **SPD (Security Policy Database)** | ตาราง Policy กำหนดว่า Traffic ไหนต้องทำอะไร (IPsec/Bypass/Discard) |
| **SPI (Security Parameters Index)** | ตัวเลข 32-bit ที่ใช้ระบุ SA ใน SAD |

### 3.4 Authentication Header (AH)

AH (Protocol Number 51) ให้บริการ Authentication และ Integrity แต่ **ไม่มีการเข้ารหัสข้อมูล**:

```
Packet Structure (Transport Mode):
┌──────────┬────────────┬──────────────────────────┐
│ IP Header│ AH Header  │ Payload (TCP/UDP, Plain) │
└──────────┴────────────┴──────────────────────────┘
         └───── Authenticated (ICV covers entire packet) ─────┘
```

**AH Header ประกอบด้วย:**

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├────────────────────────────────────────────────────────────────┤
│ Next Header    │ Payload Length │          RESERVED             │
├────────────────────────────────────────────────────────────────┤
│                  Security Parameters Index (SPI)                │
├────────────────────────────────────────────────────────────────┤
│                    Sequence Number                              │
├────────────────────────────────────────────────────────────────┤
│                                                               │
│              Integrity Check Value (ICV) — HMAC-SHA256         │
│                                                               │
├────────────────────────────────────────────────────────────────┤
```

| ฟิลด์ | ขนาด | คำอธิบาย |
|------|------|----------|
| Next Header | 8 bits | ประเภทของ Payload ที่ตามมา (TCP=6, UDP=17) |
| Payload Length | 8 bits | ความยาวของ AH Header |
| RESERVED | 16 bits | สำรอง (ตั้งค่าเป็น 0) |
| SPI | 32 bits | ระบุ SA สำหรับ Packet นี้ |
| Sequence Number | 32 bits | ป้องกัน Replay Attack |
| ICV | Variable | HMAC (HMAC-SHA256-128 หรือ HMAC-SHA1-96) |

**ข้อควรระวัง:** AH ไม่สามารถใช้งานกับ NAT ได้ เนื่องจาก AH ตรวจสอบความถูกต้องของ (authenticate) IP Header รวมถึง Source/Destination IP ซึ่ง NAT ต้องเปลี่ยนแปลง

### 3.5 Encapsulating Security Payload (ESP)

ESP (Protocol Number 50) ให้บริการ Authentication + Integrity + Encryption:

**Packet Structure (Transport Mode):**

```
┌──────────┬──────────────┬───────────────────┬──────────────┬──────────────┐
│ IP Header │ ESP Header   │ Payload           │ ESP Trailer   │ ESP Auth     │
│          │ (SPI, Seq#)  │ (TCP/UDP,         │ (Padding,     │ (ICV —       │
│          │              │  เข้ารหัส)         │  Pad Length,  │  HMAC)       │
│          │              │                   │  Next Header) │              │
└──────────┴──────────────┴───────────────────┴──────────────┴──────────────┘
                         ├── Encrypted ────────┤
                         ├────────── Authenticated ───────────┤
```

- **Encrypted:** Payload + ESP Trailer (Padding, Pad Length, Next Header)
- **Authenticated:** ESP Header + Payload + ESP Trailer + ESP Auth

### 3.6 IPsec Modes: Transport vs Tunnel

#### 3.6.1 Transport Mode

ใช้สำหรับเชื่อมต่อแบบ Host-to-Host โดยตรง (เช่น ผู้ใช้เชื่อมต่อไปยัง Server โดยตรง):

```
ก่อน IPsec:
[IP Header: src=PC, dst=Server] [TCP] [Data]

หลัง IPsec — Transport Mode:
[IP Header: src=PC, dst=Server] [ESP/AH] [TCP] [Data]
                                  └─────── Protected ────────┘
```

**ลักษณะ:** IP Header ดั้งเดิมไม่ได้รับการเข้ารหัส (ใช้ Routing ได้ตามปกติ) มีเฉพาะ Payload ที่ได้รับการป้องกัน

#### 3.6.2 Tunnel Mode

ใช้สำหรับ Site-to-Site VPN (Gateway-to-Gateway):

```
ก่อน IPsec:
[IP Header: src=PC1, dst=PC2] [TCP] [Data]

หลัง IPsec — Tunnel Mode:
[New IP Header: src=GW1, dst=GW2] [ESP/AH] [Orig IP Header] [TCP] [Data]
                                     └──────── Entire Packet Protected ────────┘
```

**ลักษณะ:** Packet ดั้งเดิมทั้งหมด (รวม IP Header ต้นทาง) ได้รับการเข้ารหัสและใส่ใน IP Header ใหม่

#### 3.6.3 เปรียบเทียบ Transport Mode vs Tunnel Mode

| คุณสมบัติ | Transport Mode | Tunnel Mode |
|-----------|---------------|-------------|
| **Payload Protection** | เข้ารหัสเฉพาะ Payload | เข้ารหัสทั้ง Packet ดั้งเดิม |
| **IP Header** | IP Header ดั้งเดิม (ไม่เข้ารหัส) | IP Header ใหม่สำหรับ Gateway |
| **การใช้งานหลัก** | Host-to-Host โดยตรง | Site-to-Site VPN, Remote Access VPN |
| **Performance** | ดีกว่า (Overhead น้อยกว่า) | Overhead มากกว่า (Header เพิ่ม) |
| **Routing** | Routing ตาม IP ดั้งเดิม | Routing ตาม Gateway IP |

### 3.7 IKE (Internet Key Exchange) และ IKEv2

IKE เป็นโพรโทคอลสำหรับสร้าง Security Association (SA) ระหว่างฝ่าย IPsec โดยอัตโนมัติ IKEv2 (RFC 7296) เป็นเวอร์ชันปัจจุบันที่ปรับปรุงจาก IKEv1:

**ขั้นตอน IKEv2 โดยละเอียด:**

```
Phase 1: IKE_SA_INIT (2 messages)
───────────────┬──────────────────────────────────────┬──────────────
Initiator      │                                     │ Responder
              │──── HDR, SAi1, KEi, Ni ────────────→│
              │←── HDR, SAr1, KEr, Nr, [CERTREQ] ──│
              │                                     │
              ⇒ IKE SA Established (Diffie-Hellman) ⇐

Phase 2: IKE_AUTH (2 messages)
───────────────┬──────────────────────────────────────┬──────────────
              │──── HDR, SK {IDi, [CERT,] AUTH,      │
              │         SAi2, TSi, TSr} ────────────→│
              │←── HDR, SK {IDr, [CERT,] AUTH,       │
              │         SAr2, TSi, TSr} ─────────────│
              │                                     │
              ⇒ First IPsec SA (Child SA) Established ⇐

Phase 3: CREATE_CHILD_SA (2 messages, optional)
───────────────┬──────────────────────────────────────┬──────────────
              │──── HDR, SK {SA, Ni, KEi, TSi,      │
              │         TSr} ──────────────────────→│
              │←── HDR, SK {SA, Nr, KEr, TSi,      │
              │         TSr} ───────────────────────│
              │                                     │
              ⇒ Additional Child SA Established       ⇐
```

**คุณสมบัติเด่นของ IKEv2:**
- **MOBIKE (Mobility and Multihoming)** — รองรับการเปลี่ยน Network Interface (เช่น จาก Wi-Fi → Mobile Data)
- **Dead Peer Detection (DPD)** — ตรวจสอบ Peer ที่หายไปได้รวดเร็วกว่า
- **Faster Rekeying** — ลดจำนวน Message ในการ Renew Key
- **NAT Traversal (NAT-T)** — รองรับ IPsec ผ่าน NAT ได้ดีกว่า

### 3.8 IPsec vs TLS

| คุณสมบัติ | IPsec | TLS |
|-----------|-------|-----|
| **OSI Layer** | Network (Layer 3) | Transport/Presentation (Layer 4-6) |
| **การใช้งานหลัก** | VPN (Site-to-Site, Remote Access) | HTTPS, SMTP, FTP |
| **Application Transparency** | โปร่งใส — ไม่ต้องแก้ Application | Application ต้องรองรับ |
| **Encryption Scope** | ทั้ง Packet (Tunnel Mode) | เฉพาะ Payload |
| **Authentication** | Machine-based (Certificate/PSK) | Server/Client Certificate |
| **Performance** | Overhead สูงกว่า | Overhead ปานกลาง |
| **NAT Compatibility** | ต้องใช้ NAT-T | ปกติไม่มีปัญหา |
| **Remote Access** | ต้องติดตั้ง Client Software | ใช้ Browser ได้ทันที |
| **Perfect Forward Secrecy** | รองรับ (ผ่าน IKE/DH) | รองรับ (ผ่าน ECDHE) |

---

## 4. SSH (Secure Shell)

### 4.1 ความรู้เบื้องต้น

SSH เป็นโพรโทคอลสำหรับการเชื่อมต่อ Remote Shell และ Service อย่างปลอดภัย ทำงานบน Port TCP/22 พัฒนาโดย Tatu Ylönen ในปี 1995 เพื่อแทนที่ Telnet, rlogin, rsh, และ rcp ที่ไม่มีความปลอดภัย

### 4.2 สถาปัตยกรรม SSH แบบ 3 ชั้น

SSH ประกอบด้วย 3 Layer ที่ทำงานซ้อนกัน:

```
┌──────────────────────────────────────────────────────────┐
│              Connection Layer (SSH-CONN)                   │
│  — Channel Management (Session, Port Forwarding, X11)    │
├──────────────────────────────────────────────────────────┤
│              User Authentication Layer (SSH-AUTH)         │
│  — ตรวจสอบตัวตนผู้ใช้ (Password, Public Key, GSSAPI)      │
├──────────────────────────────────────────────────────────┤
│              Transport Layer (SSH-TRANS)                  │
│  — Key Exchange (DH/ECDH), Encryption, Integrity, MAC    │
├──────────────────────────────────────────────────────────┤
│                        TCP                                │
└──────────────────────────────────────────────────────────┘
```

#### 4.2.1 Transport Layer (SSH-TRANS)

กระบวนการ Key Exchange และการสร้าง Session:

```
Client                                      Server
  │                                           │
  │──── TCP Connection (Port 22) ────────────→│
  │                                           │
  │──── SSH Protocol Version ────────────────→│
  │   (SSH-2.0-OpenSSH_9.3)                   │
  │←── SSH Protocol Version ──────────────────│
  │   (SSH-2.0-OpenSSH_9.3)                   │
  │                                           │
  │==== Key Exchange (DH/ECDH) ===============│
  │                                           │
  │──── Key Exchange Init ──────────────────→│
  │   (Algorithms: curve25519-sha256,          │
  │    aes256-ctr, hmac-sha2-256)             │
  │←── Key Exchange Reply ────────────────────│
  │   (Selected Algorithms, Host Key)          │
  │                                           │
  │==== DH Key Exchange ======================│
  │                                           │
  │──── DH Init (e = g^x mod p) ────────────→│
  │←── DH Reply (f = g^y mod p, H, signature)│
  │                                           │
  │⇒ Shared Secret K = g^{xy} mod p           │
  │⇒ Session ID = Hash(K || H)               │
  │⇒ Encryption Key = Derived from K          │
  │                                           │
  │==== Secure Channel (Encrypted) ===========│
  │                                           │
  │──── Service Request: ssh-userauth ───────→│
  │←── Service Accept ────────────────────────│
  │                                           │
  │==== User Authentication Layer Starts =====│
```

#### 4.2.2 User Authentication Layer (SSH-AUTH)

SSH รองรับวิธีการรับรองตัวตนผู้ใช้หลายรูปแบบ ตรวจสอบตามลำดับที่กำหนดใน Server Configuration:

| วิธีการ | คำอธิบาย | ระดับความปลอดภัย |
|---------|----------|-----------------|
| **Password Authentication** | ใช้ Username + Password ปกติ | **ต่ำ** — เสี่ยง Brute Force, Phishing |
| **Public Key Authentication** | ใช้ RSA/ECDSA/Ed25519 Key Pair | **สูง** — แนะนำให้ใช้ |
| **Keyboard-Interactive** | ตอบคำถาม (รวมถึง OTP, TOTP, 2FA) | **สูงมาก** — เมื่อใช้กับ 2FA |
| **Host-Based Authentication** | ตรวจสอบ Hostname และ Public Key ของเครื่องที่เชื่อมต่อ | **ปานกลาง** — ใช้ในระบบ Trusted Host |
| **GSSAPI Authentication** | ใช้ Kerberos authentication | **สูง** — สำหรับ Enterprise Environment |

**Public Key Authentication (กลไกการทำงาน):**

```
1. Client เสนอ Public Key ให้ Server (ssh-rsa AAA...)
2. Server ตรวจสอบ Public Key ใน ~/.ssh/authorized_keys
3. Server ส่ง Challenge (Random Number) ที่เข้ารหัสด้วย Public Key
4. Client ถอดรหัสด้วย Private Key และส่ง Response กลับ
5. Server ตรวจสอบ Response → ยอมรับหรือปฏิเสธ
```

#### 4.2.3 Connection Layer (SSH-CONN)

เมื่อ Authentication เสร็จสมบูรณ์ Connection Layer จะจัดการ Channel ต่างๆ:

| Channel Type | หน้าที่ |
|-------------|--------|
| **Session** | Shell Session ปกติ |
| **direct-tcpip** | Local Port Forwarding |
| **tcpip-forward** | Remote Port Forwarding |
| **x11** | X11 Forwarding (GUI Application ระยะไกล) |
| **subsystem** | SFTP, SCP subsystems |

### 4.3 SSH Key Exchange Algorithms

SSH รองรับ Key Exchange Algorithm หลายประเภท โดยเรียงตามความปลอดภัย:

| Algorithm | Curve/Basis | ความปลอดภัย | ปีที่แนะนำ |
|-----------|-------------|-------------|-----------|
| **curve25519-sha256** | Curve25519 | **สูงมาก** | 2014 |
| **ecdh-sha2-nistp256** | NIST P-256 | สูง | 2010 |
| **ecdh-sha2-nistp384** | NIST P-384 | สูง | 2010 |
| **diffie-hellman-group16-sha512** | 4096-bit MODP | สูง | 2015 |
| **diffie-hellman-group14-sha256** | 2048-bit MODP | ปานกลาง | 2006 |

**คำแนะนำสำหรับการตั้งค่า OpenSSH Server (`/etc/ssh/sshd_config`):**

```bash
# Key Exchange Algorithms
KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256,ecdh-sha2-nistp384,diffie-hellman-group16-sha512

# Ciphers
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com

# MACs
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com

# Host Key Algorithms
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,ecdsa-sha2-nistp256

# Authentication
PubkeyAuthentication yes
PasswordAuthentication no
PermitRootLogin prohibit-password
```

### 4.4 การใช้งาน SSH ในระบบเครือข่าย

#### 4.4.1 Port Forwarding (Tunneling)

| ประเภท | คำสั่ง | คำอธิบาย |
|--------|--------|----------|
| **Local Port Forwarding** | `ssh -L 8080:internal:80 user@gateway` | ส่ง Port Local → Remote |
| **Remote Port Forwarding** | `ssh -R 8080:localhost:80 user@gateway` | ส่ง Port Remote → Local |
| **Dynamic Port Forwarding** | `ssh -D 1080 user@gateway` | SOCKS Proxy Tunnel |

**Local Port Forwarding — แผนภาพ:**

```
┌──────────────┐              ┌──────────────┐          ┌──────────────┐
│    Client    │              │   SSH Server  │          │  Internal    │
│              │              │   (Gateway)   │          │   Server     │
│ localhost:   │── SSH Tunnel─→│              │──TCP───→│ internal:80  │
│ 8080         │              │  forward:     │          │              │
└──────────────┘              │  localhost:80 │          └──────────────┘
                              └──────────────┘
```

#### 4.4.2 SSH File Transfer

| วิธีการ | โพรโทคอลพื้นฐาน | Port | จุดเด่น |
|--------|----------------|------|--------|
| **SCP** | SSH | 22 | ง่าย, เร็ว (legacy) |
| **SFTP** | SSH (SSH-CONN Subsystem) | 22 | มีฟังก์ชันจัดการไฟล์ (resume, list, delete) |
| **rsync over SSH** | SSH | 22 | ส่งเฉพาะส่วนที่เปลี่ยนแปลง (delta) |

#### 4.4.3 SSH Agent และ Key Management

**ssh-agent** เป็นโปรแกรมที่เก็บ Private Key ใน Memory เพื่อไม่ต้องป้อน Passphrase ทุกครั้ง:

```bash
# เริ่ม ssh-agent และเพิ่ม Key
eval $(ssh-agent -s)
ssh-add ~/.ssh/id_ed25519

# Forward Agent (เชื่อมต่อข้าม Hop โดยไม่ต้องเก็บ Key)
ssh -A user@gateway
```

### 4.5 Hardening SSH

| การตั้งค่า | ค่าแนะนำ | เหตุผล |
|-----------|---------|--------|
| `Port` | 22 (หรือเปลี่ยน) | เปลี่ยน Port ช่วยลด Automated Scan |
| `PermitRootLogin` | prohibit-password หรือ no | ป้องกันการเข้าถึง Root โดยตรง |
| `PasswordAuthentication` | no | ใช้ Public Key Authentication เท่านั้น |
| `PubkeyAuthentication` | yes | เปิดใช้งาน Key Authentication |
| `AllowUsers` | user1 user2 | จำกัดผู้ใช้ที่สามารถ SSH ได้ |
| `MaxAuthTries` | 3 | จำกัดจำนวนครั้งลอง Authentication |
| `ClientAliveInterval` | 300 | ตรวจสอบ Idle Connection ทุก 5 นาที |
| `UsePAM` | yes | เปิด PAM สำหรับ 2FA |
| `LogLevel` | VERBOSE | บันทึกประวัติการเข้าถึงละเอียดขึ้น |
| `Banner` | /etc/ssh/banner | แสดงข้อความเตือนทางกฎหมาย |

---

## 5. การเปรียบเทียบความปลอดภัยระหว่างโพรโทคอล

### 5.1 HTTP → HTTPS → HTTP/3 (QUIC)

| คุณสมบัติ | HTTP/1.1 | HTTPS (HTTP/1.1 + TLS) | HTTP/2 (+ TLS) | HTTP/3 (QUIC + TLS 1.3) |
|-----------|---------|----------------------|---------------|------------------------|
| **Port** | TCP 80 | TCP 443 | TCP 443 | UDP 443 |
| **Encryption** | ❌ ไม่มี | ✅ TLS | ✅ TLS | ✅ TLS 1.3 (Built-in) |
| **Transport** | TCP | TCP | TCP | **QUIC (UDP + TLS 1.3)** |
| **Multiplexing** | ❌ (1 req/conn) | ❌ (1 req/conn) | ✅ Multiplexed | ✅ Multiplexed (ไม่มี Head-of-Line Blocking) |
| **Connection Setup** | 1 RTT (TCP) | 3 RTT (TCP + TLS 1.2) | 3 RTT | **1 RTT** (QUIC + TLS 1.3) |
| **0-RTT** | ❌ | ❌ | ❌ | ✅ |
| **Head-of-Line Blocking** | TCP Level | TCP Level | TCP Level | **ไม่มี** (QUIC) |

**HTTP/3 (QUIC) — การเชื่อมต่อ:**

```
QUIC Connection Setup (1 RTT):
Client                                      Server
  │                                           │
  │──── Initial (ClientHello, Version,       │
  │         CRYPTO Frame) ──────────────────→│  RTT 1
  │←── Initial + Handshake (ServerHello,     │
  │         Certificate, Finished) ──────────│
  │                                           │
  │══════ Secure Data Transfer (HTTP/3 Frames) ════│
```

**0-RTT (Session Resume):**
```
Client                                      Server
  │                                           │
  │──── 0-RTT (HTTP Request, Early Data) ───→│  RTT 0
  │←── Server Response ──────────────────────│
  │                                           │
  │══════ Continue Normal Communication ══════│
```

### 5.2 FTP → FTPS → SFTP

| คุณสมบัติ | FTP | FTPS (FTP over TLS) | SFTP |
|-----------|-----|---------------------|------|
| **Port** | TCP 21 | TCP 990 (Implicit) / 21 (Explicit) | TCP 22 |
| **Protocol Basis** | FTP พื้นฐาน | FTP + TLS | SSH |
| **Encryption** | ❌ ไม่มี | ✅ TLS | ✅ SSH Encryption |
| **Authentication** | Username/Password | Certificate + Password | Public Key + Password |
| **Data Channel** | แยก Control/Data | แยก Control/Data | **รวมใน Channel เดียว** |
| **Firewall Friendly** | ❌ (ต้องเปิดหลายพอร์ต) | ❌ | ✅ (ใช้พอร์ตเดียว) |
| **NAT Compatible** | ❌ (Active Mode) | ❌ | ✅ |
| **Directory Listing** | แยก Channel | แยก Channel | **ใน Channel เดียว** |
| **Resume Transfer** | ✅ | ✅ | ✅ |
| **Permission Management** | ❌ | ❌ | ✅ (Unix Permissions) |

**รูปแบบ Active vs Passive FTP (ผลต่อความปลอดภัย):**

```
Active Mode:
Client:1025 ←───── Server:21 (Control)
Client:1025 ─────→ Server:20 (Data)  ← Client ต้องรับการเชื่อมต่อจาก Server

Passive Mode:
Client:1025 ←───── Server:21 (Control)
Client:1026 ─────→ Server:30000 (Data)  ← Client เชื่อมต่อไปยัง Server
```

### 5.3 SMTP → SMTPS → STARTTLS

| คุณสมบัติ | SMTP (Plain) | SMTPS (SMTP over TLS) | STARTTLS |
|-----------|-------------|----------------------|----------|
| **Port** | TCP 25 | TCP 465 | TCP 587 |
| **Encryption Method** | ❌ ไม่มี | ✅ TLS ตั้งแต่เริ่มเชื่อมต่อ | 🔄 Upgrade: Plain → TLS |
| **การใช้งานหลัก** | Server-to-Server Relay | Submission (Deprecated) | Submission (RFC 6409) |
| **Authentication** | ไม่บังคับ | Required | Required |
| **Downgrade Risk** | — | ต่ำ | **สูง** — STRIPTLS Attack |
| **MTA-STS** | — | — | ใช้ MTA-STS ป้องกัน Downgrade |

**MTA-STS (SMTP MTA Strict Transport Security, RFC 8461):**

MTA-STS เป็นกลไกป้องกันการโจมตี STRIPTLS สำหรับ SMTP:
1. เจ้าของ Domain เผยแพร่ Policy ที่ `mta-sts.example.com`
2. Server ส่ง TLS Report ให้ผู้ส่งตรวจสอบ
3. ถ้า TLS ล้มเหลว → ไม่ส่ง (Reject) แทนที่จะ Fallback เป็น Plaintext

### 5.4 DNS Security: DNSSEC, DNS over TLS, DNS over HTTPS

| คุณสมบัติ | DNSSEC | DNS over TLS (DoT) | DNS over HTTPS (DoH) |
|-----------|--------|-------------------|---------------------|
| **Port** | UDP/TCP 53 | TCP 853 | TCP 443 |
| **Encryption** | ❌ (เฉพาะ Signature) | ✅ TLS | ✅ TLS (HTTPS) |
| **Integrity** | ✅ Digital Signature | ✅ TLS | ✅ TLS |
| **Authentication** | ✅ Chain of Trust | ❌ (Certificate-Based) | ❌ (Certificate-Based) |
| **Privacy** | ❌ (ข้อมูลเปิด) | ✅ (เข้ารหัส) | ✅ (เข้ารหัส) |
| **Performance** | Slow (Signature Verification) | ดี | ดี |
| **Adoption** | ต่ำ (ซับซ้อน) | ปานกลาง | **สูง** (Cloudflare 1.1.1.1, Google 8.8.8.8) |
| **Standard** | RFC 4033-4035 | RFC 7858 | RFC 8484 |

**DNS Security Stack — ควรรวมทุกชั้น:**

```
┌─────────────────────────────────────────────┐
│  Application (Browser/OS)                    │
├─────────────────────────────────────────────┤
│  DNS over HTTPS (DoH) / DNS over TLS (DoT)   │  ← Privacy + Integrity
├─────────────────────────────────────────────┤
│  DNSSEC Validation                           │  ← Authentication + Integrity
├─────────────────────────────────────────────┤
│  Authoritative DNS Server                    │
└─────────────────────────────────────────────┘
```

### 5.5 WireGuard — โพรโทคอล VPN สมัยใหม่

WireGuard เป็นโพรโทคอล VPN ที่ออกแบบมาให้เรียบง่าย ปลอดภัย และมีประสิทธิภาพสูง:

**จุดเด่นของ WireGuard เทียบกับ IPsec:**

| คุณสมบัติ | IPsec (IKEv2) | WireGuard |
|-----------|---------------|-----------|
| **Codebase** | >100,000 บรรทัด (strongSwan) | ~4,000 บรรทัด |
| **Cipher** | กำหนดเองได้ | **ChaCha20-Poly1305 (บังคับ)** |
| **Key Exchange** | IKEv2 (DH/ECDH) | **Noise Protocol (Curve25519)** |
| **Authentication** | Certificate, PSK | **Public Key (Static)** |
| **Handshake** | 4-6 messages | **1-RTT (Noise IK)** |
| **Perfect Forward Secrecy** | ✅ | ✅ |
| **Kernel Integration** | มี (บางระบบ) | ✅ **Built-in Linux Kernel 5.6+** |
| **Roaming** | MOBIKE (ซับซ้อน) | **Built-in (No Re-handshake)** |
| **Configuration** | ซับซ้อน (หลาย Parameter) | **ง่าย (Key + Endpoint เท่านั้น)** |

**WireGuard Configuration — ตัวอย่างการตั้งค่า:**

```ini
# /etc/wireguard/wg0.conf
[Interface]
PrivateKey = gN65BqVyI5dy3EY...  # Private Key (Curve25519)
Address = 10.0.0.1/24
ListenPort = 51820

[Peer]
PublicKey = xTIBAOD+z6Gj6P...  # Public Key ของ Peer
AllowedIPs = 10.0.0.2/32, 192.168.1.0/24
Endpoint = peer.example.com:51820
PersistentKeepalive = 25
```

### 5.6 ตารางเปรียบเทียบความปลอดภัยแบบรวม

| โพรโทคอล | Port | Encryption | Authentication | Integrity | PFS | OSI Layer |
|-----------|------|-----------|---------------|-----------|-----|-----------|
| **HTTPS** (TLS 1.3) | 443 | ✅ AES-GCM / ChaCha20 | ✅ Certificate | ✅ AEAD | ✅ | Transport/App |
| **FTPS** (TLS) | 990 | ✅ TLS | ✅ Cert + PW | ✅ | ✅* | Transport/App |
| **SFTP** | 22 | ✅ SSH | ✅ Public Key | ✅ HMAC | ✅ | Transport/App |
| **SMTPS** (TLS) | 465 | ✅ TLS | ✅ Certificate | ✅ | ✅* | Transport/App |
| **IMAPS** (TLS) | 993 | ✅ TLS | ✅ Certificate | ✅ | ✅* | Transport/App |
| **POP3S** (TLS) | 995 | ✅ TLS | ✅ Certificate | ✅ | ✅* | Transport/App |
| **IPsec** (ESP) | 50, 4500 | ✅ AES | ✅ PSK/Cert | ✅ HMAC | ✅ | Network |
| **WireGuard** | 51820 | ✅ ChaCha20 | ✅ Public Key | ✅ Poly1305 | ✅ | Network |
| **SSH** | 22 | ✅ AES-CTR | ✅ Public Key | ✅ HMAC | ✅ | Transport/App |
| **DNSSEC** | 53 | ❌ | ✅ Signature | ✅ Signature | ❌ | Application |

*PFS ขึ้นอยู่กับ Cipher Suite ที่เลือก (ต้องใช้ ECDHE)

---

## 6. การโจมตี SSL/TLS ในประวัติศาสตร์

SSL/TLS ผ่านการโจมตีที่รุนแรงมากมายตลอดประวัติศาสตร์ การทำความเข้าใจการโจมตีเหล่านี้ช่วยให้เข้าใจจุดอ่อนของโพรโทคอลและการป้องกันที่ถูกต้อง

### 6.1 ไทม์ไลน์การโจมตี SSL/TLS

```
1995 ─ SSL 2.0 — Weak MAC, Protocol Downgrade
1996 ─ SSL 3.0 Released
1999 ─ TLS 1.0 Released

2009 ────┬── BEAST (CBC Predictable IV)
2011 ────├── CRIME (Compression Oracle)
          ├── WinShock (Schannel)
2013 ────├── Lucky13 (CBC Timing)
          ├── RC4 Biases (Plaintext Recovery)
2014 ────├── Heartbleed (CVE-2014-0160)
          ├── POODLE (SSL 3.0 CBC)
          ├── POODLE TLS (TLS CBC)
2015 ────├── FREAK (Export-Grade RSA)
          ├── LOGJAM (Export-Grade DH)
2016 ────├── DROWN (Cross-Protocol, CVE-2016-0800)
          ├── Sweet32 (3DES Birthday)
2017 ────├── ROBOT (Bleichenbacher Oracle)
          ├── KRACK (WPA2 — ไม่ใช่ TLS)
2018 ────├── TLS 1.3 Released
2019 ────├── ALPACA (Cross-Protocol, CVE-2021-36222)
          ├── Raccoon Attack (CVE-2020-1968)
2020 ────├── TLStorm (CVE-2022-26320, UPS/Firmware)
          └── TLS 1.3 Adoption > 50%
```

### 6.2 การโจมตีแต่ละประเภทโดยละเอียด

#### 6.2.1 BEAST (Browser Exploit Against SSL/TLS) — CVE-2011-3389

| รายละเอียด | คำอธิบาย |
|-----------|---------|
| **ปีที่พบ** | 2011 (Juliano Rizzo, Thai Duong) |
| **เป้าหมาย** | TLS 1.0 CBC Mode Cipher |
| **หลักการ** | ใช้ IV ที่สามารถคาดเดาได้ใน CBC Mode เพื่อถอดรหัส Cookie ทีละ byte |
| **เงื่อนไข** | ผู้โจมตีต้องสามารถ MITM และ inject JavaScript ได้ |
| **ผลกระทบ** | ถอดรหัส Cookie ใน HTTPS Session ได้ |

**การป้องกัน:**
- อัปเกรดเป็น TLS 1.1+ (CBC ใช้ Explicit IV)
- ใช้ RC4 เป็นการชั่วคราว (แต่ RC4 ก็ไม่ปลอดภัย)
- **ปัจจุบัน: ใช้ TLS 1.2+ กับ AEAD Cipher**

#### 6.2.2 CRIME (Compression Ratio Info-leak Made Easy) — CVE-2012-4929

| รายละเอียด | คำอธิบาย |
|-----------|---------|
| **ปีที่พบ** | 2012 |
| **เป้าหมาย** | TLS Compression |
| **หลักการ** | ใช้ Compression Oracle — ถ้าเดา Cookie ถูก ข้อมูลจะบีบอัดได้ดีขึ้น ส่งผลให้ขนาดเล็กลง |
| **ผลกระทบ** | ถอดรหัส Session Cookie ได้ |
| **การป้องกัน** | ปิด TLS Compression (RFC 3749) |

#### 6.2.3 Heartbleed (CVE-2014-0160)

| รายละเอียด | คำอธิบาย |
|-----------|---------|
| **ปีที่พบ** | 2014 (Google Security, Codenomicon) |
| **เป้าหมาย** | OpenSSL 1.0.1 ถึง 1.0.1f (Heartbeat Extension) |
| **หลักการ** | Buffer Over-read — ส่ง Heartbeat Request ความยาว 64KB แต่บอก Length เป็น 64KB → Server อ่าน Memory เกินขนาด |
| **ผลกระทบ** | รั่วไหลของ Private Key, Session Key, Password, และข้อมูลใน Memory |
| **จำนวนที่ได้รับผลกระทบ** | เซิร์ฟเวอร์กว่า 500,000 เครื่อง (17% ของ HTTPS Servers ในปี 2014) |

```
Heartbleed — การทำงาน:
1. ผู้โจมตีส่ง Heartbeat Request:
   [Type=1][Payload Length=0xFFFF][Payload="hi"]
   
2. Server ตอบ Heartbeat Response โดยใช้ Length ที่ผู้โจมตีส่ง:
   [Type=1][Payload Length=0xFFFF][Payload="hi" + Private_Key + Session_Keys + ...]
                                                              └── Memory Leak (64KB)
```

**การป้องกัน:**
- อัปเกรด OpenSSL เป็น 1.0.1g หรือสูงกว่า
- Revoke Certificate ที่เคยอยู่บนเซิร์ฟเวอร์ที่ได้รับผลกระทบ
- เปลี่ยน Session Key และ Password ทั้งหมด

#### 6.2.4 POODLE (Padding Oracle On Downgraded Legacy Encryption) — CVE-2014-3566

| รายละเอียด | คำอธิบาย |
|-----------|---------|
| **ปีที่พบ** | 2014 (Google) |
| **เป้าหมาย** | SSL 3.0 (CBC Mode) |
| **หลักการ** | Padding Oracle Attack — บังคับให้ Client Downgrade ไปใช้ SSL 3.0 ที่ไม่มี padding verification ที่ถูกต้อง |

```
POODLE Attack — ขั้นตอน:
1. MITM บล็อก TLS 1.2 Handshake
2. Client Fallback → SSL 3.0
3. SSL 3.0 CBC → Padding Byte ไม่ถูกตรวจสอบ
4. ผู้โจมตีสามารถเดา Plaintext ทีละ byte โดยสังเกตว่าการเข้ารหัสสำเร็จหรือไม่
```

**การป้องกัน:**
- ปิดการใช้งาน SSL 3.0 และ TLS 1.0
- TLS_FALLBACK_SCSV (Signaling Cipher Suite Value for Downgrade Protection)
- **ปัจจุบัน: ใช้ TLS 1.2+ เท่านั้น**

#### 6.2.5 FREAK (Factoring RSA Export Keys) — CVE-2015-0204

| รายละเอียด | คำอธิบาย |
|-----------|---------|
| **ปีที่พบ** | 2015 |
| **เป้าหมาย** | Export-Grade RSA (512-bit) |
| **หลักการ** | ผู้โจมตีบังคับให้ Server/Client ใช้ RSA Export Key (512-bit) ซึ่งสามารถ Factor ได้ |

```
FREAK Attack:
1. Client สนับสนุน RSA แต่ผู้โจมตี MITM → แก้ ClientHello เป็น "RSA_EXPORT"
2. Server ส่ง RSA Export Certificate (512-bit)
3. ผู้โจมตี Factoring RSA-512 → ถอดรหัส Pre-Master Secret
4. Session Key ถูกถอดรหัส → HTTPS Traffic เปิด
```

**การป้องกัน:**
- ปิดการใช้งาน EXPORT Cipher Suite ทั้งหมด
- อัปเดต OpenSSL และ Secure Transport (Apple)

#### 6.2.6 LOGJAM (CVE-2015-4000)

| รายละเอียด | คำอธิบาย |
|-----------|---------|
| **ปีที่พบ** | 2015 |
| **เป้าหมาย** | Export-Grade Diffie-Hellman (512-bit, 768-bit) |
| **หลักการ** | ผู้โจมตี Downgrade DH Parameter ให้เหลือ 512-bit → Precompute Discrete Log |

**การป้องกัน:**
- ใช้ DH Parameter ≥ 2048-bit
- ใช้ ECDHE แทน DHE

#### 6.2.7 DROWN (Decrypting RSA with Obsolete and Weakened eNcryption) — CVE-2016-0800

| รายละเอียด | คำอธิบาย |
|-----------|---------|
| **ปีที่พบ** | 2016 |
| **เป้าหมาย** | Cross-Protocol Attack (SSLv2 → TLS) |
| **หลักการ** | ใช้ SSLv2 ที่เปิดอยู่บน Server เดียวกันเพื่อถอดรหัส TLS Connection |

```
DROWN Attack:
1. Server รัน HTTPS (TLS) พอร์ต 443
2. Server เดียวกันรัน SSLv2 พอร์ตอื่น (SMTP, POP3, IMAP) ที่ใช้ Certificate เดียวกัน
3. ผู้โจมตีใช้ SSLv2 Weakness ถอดรหัส Pre-Master Secret ของ TLS Connection
```

**ผลกระทบ:** 33% ของ HTTPS Servers เสี่ยงต่อ DROWN ในปี 2016

**การป้องกัน:**
- ปิด SSLv2 ทั้งหมด
- ใช้ Certificate ที่แตกต่างกันสำหรับ Service ต่างๆ (Key Separation)

#### 6.2.8 ROBOT (Return Of Bleichenbacher's Oracle Threat) — CVE-2017-17382

| รายละเอียด | คำอธิบาย |
|-----------|---------|
| **ปีที่พบ** | 2017 |
| **เป้าหมาย** | RSA Encryption (PKCS#1 v1.5) |
| **หลักการ** | Bleichenbacher Oracle — Server บอกว่า PKCS#1 v1.5 padding ถูกต้องหรือไม่ → ถอดรหัส Pre-Master Secret |
| **ผลกระทบ** | ถอดรหัส Session Key ได้ใน TLS ที่ใช้ RSA Key Exchange |

**การป้องกัน:**
- ใช้ ECDHE Key Exchange (Perfect Forward Secrecy)
- ใช้ TLS 1.3 (ไม่รองรับ RSA Key Exchange)

#### 6.2.9 ALPACA (Application Layer Protocol Confusion) — CVE-2021-36222

| รายละเอียด | คำอธิบาย |
|-----------|---------|
| **ปีที่พบ** | 2021 |
| **เป้าหมาย** | Cross-Protocol Attack (HTTPS ↔ FTP, SMTP, etc.) |
| **หลักการ** | ผู้โจมตีทำให้ Browser ส่ง HTTPS Request ไปยัง FTP/SMTP Server ที่มี Certificate ถูกต้อง |

```
ALPACA Attack:
1. ผู้โจมตีควบคุม FTP Server ที่มี Certificate ถูกต้อง (หรือใช้ self-signed)
2. ผู้ใช้เปิด Browser → ไปที่ https://attacker-ftp.com
3. Browser ส่ง HTTP Request ไปยัง FTP Server — non-printable chars เป็น garbage
4. บน FTP Server ที่มี bugs → อ่าน HTTP Request เป็น FTP Command
5. Cookie และ Authentication Token รั่วไหล
```

**การป้องกัน:**
- ใช้ ALPN extension (Application-Layer Protocol Negotiation)
- ตรวจสอบว่า Certificate SAN ตรงกับ Service Protocol

#### 6.2.10 Raccoon Attack (CVE-2020-1968)

| รายละเอียด | คำอธิบาย |
|-----------|---------|
| **ปีที่พบ** | 2020 |
| **เป้าหมาย** | DH Key Exchange ใน TLS |
| **หลักการ** | Timing Side-channel ใน DH Key Exchange — ถ้า DH Secret มี Leading Zero จะมีการคำนวณที่ไม่สม่ำเสมอ |

**การป้องกัน:**
- ใช้ ECDHE แทน DHE
- ใช้ TLS 1.3

### 6.3 สรุป: Cipher Suite ที่ปลอดภัยและไม่ปลอดภัย

| Algorithm | สถานะ | ปัญหา |
|-----------|--------|-------|
| **RC4** | ❌ ไม่ปลอดภัย | Biases, Plaintext Recovery |
| **3DES** | ❌ ไม่ปลอดภัย | Sweet32 (Birthday Attack ที่ 32GB) |
| **CBC Mode (TLS 1.0)** | ❌ ไม่ปลอดภัย | BEAST, Lucky13 |
| **RSA Key Exchange** | ❌ ไม่ปลอดภัย | ROBOT, ไม่มี PFS |
| **DHE < 2048-bit** | ❌ ไม่ปลอดภัย | LOGJAM |
| **AES-GCM** | ✅ ปลอดภัย | AEAD, Recommended |
| **ChaCha20-Poly1305** | ✅ ปลอดภัย | AEAD, Mobile-optimized |
| **ECDHE + AES-GCM** | ✅ ปลอดภัยที่สุด | PFS + AEAD |

### 6.4 เครื่องมือตรวจสอบความปลอดภัย SSL/TLS

| เครื่องมือ | คำอธิบาย | การใช้งาน |
|-----------|----------|----------|
| **SSL Labs (Qualys)** | ให้ Grade A+ สำหรับ HTTPS | https://www.ssllabs.com/ssltest/ |
| **testssl.sh** | Command-line SSL Scanner | `testssl.sh example.com` |
| **tlspretense** | TLS Test Framework | ทดสอบ Cipher Suite, Protocol Version |
| **zmap + tls-scan** | สแกน TLS ทั้ง subnet | สแกนแบบ Mass Scan |

---

## 7. Best Practices สำหรับการกำหนดค่าโพรโทคอลความปลอดภัย

### 7.1 Mozilla SSL Configuration Generator

Mozilla ให้คำแนะนำการตั้งค่า TLS สำหรับ Server 3 ระดับ:

| ระดับ | คำอธิบาย | เหมาะกับ |
|-------|----------|----------|
| **Modern** | TLS 1.3 only, AEAD only | บริการที่ต้องการความปลอดภัยสูงสุด |
| **Intermediate** | TLS 1.2 + 1.3, AEAD + ปลอดภัย | ทั่วไป (แนะนำ) |
| **Old** | รองรับ legacy client | ระบบเก่าที่ต้องรองรับ Client รุ่นเก่า |

**ตัวอย่าง Nginx Configuration (Intermediate):**

```nginx
server {
    listen 443 ssl http2;
    server_name example.com;

    # Certificate
    ssl_certificate /etc/ssl/certs/example.com.pem;
    ssl_certificate_key /etc/ssl/private/example.com.key;

    # Protocol
    ssl_protocols TLSv1.2 TLSv1.3;
    
    # Cipher Suites (Intermediate)
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';
    
    # DH Parameters
    ssl_dhparam /etc/ssl/dhparam.pem;
    
    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 1.1.1.1 8.8.8.8;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
    
    # Security Headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
}
```

### 7.2 CAA (DNS Certification Authority Authorization)

CAA Resource Record (RFC 6844, RFC 8659) กำหนดว่า CA ใดบ้างที่สามารถออก Certificate สำหรับ Domain ได้:

```
example.com.    IN  CAA 0 issue "letsencrypt.org"
example.com.    IN  CAA 0 issuewild ";"       ; No wildcard certificates
example.com.    IN  CAA 0 iodef "mailto:security@example.com"
```

| ฟิลด์ | คำอธิบาย |
|-------|----------|
| **issue** | CA ที่ได้รับอนุญาตให้ออก Certificate สำหรับ Domain นี้ |
| **issuewild** | CA ที่ได้รับอนุญาตให้ออก Wildcard Certificate |
| **iodef** | URL/Email สำหรับรายงานการละเมิดนโยบาย |

### 7.3 DANE (DNS-Based Authentication of Named Entities)

DANE (RFC 6698) ใช้ DNSSEC เพื่อระบุ Certificate ที่ถูกต้องสำหรับ Service โดยตรง โดยไม่ต้องพึ่ง CA:

```
_443._tcp.example.com. IN TLSA 3 1 1 (
    abcd1234... )  ; SHA-256 Hash ของ Certificate
```

| DANE Parameter | ค่าที่ใช้ |
|---------------|----------|
| **Certificate Usage** | 0 = CA Constraint, 1 = Service Certificate, 2 = Trust Anchor, 3 = Domain-Issued |
| **Selector** | 0 = Full Certificate, 1 = SubjectPublicKeyInfo |
| **Matching Type** | 0 = Full, 1 = SHA-256, 2 = SHA-512 |

### 7.4 HSTS (HTTP Strict Transport Security)

HSTS (RFC 6797) บอก Browser ว่า Domain นี้ **ต้องใช้ HTTPS เท่านั้น**:

```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

| พารามิเตอร์ | คำอธิบาย |
|-----------|----------|
| **max-age** | ระยะเวลา (วินาที) ที่ Browser จำว่า Domain นี้ต้องใช้ HTTPS — แนะนำ 2 ปี (63072000) |
| **includeSubDomains** | ใช้กับ Subdomain ทั้งหมด |
| **preload** | ขอให้ Browser รวม Domain ใน HSTS Preload List (Chrome, Firefox, Safari) |

### 7.5 Certificate Transparency (CT) Monitoring

Certificate Transparency (RFC 6962) บังคับให้ CA ทุกรายต้องส่ง Certificate ที่ออกทั้งหมดไปยัง Public Log:

**การตรวจสอบ CT:**

```bash
# ตรวจสอบ SCT (Signed Certificate Timestamp) ใน Certificate ด้วย openssl
openssl s_client -connect example.com:443 -servername example.com </dev/null 2>/dev/null \
  | openssl x509 -text -noout | grep -A 10 "Signed Certificate Timestamp"

# ตรวจสอบ Certificate ใน CT Log
curl -s "https://crt.sh/?q=example.com&output=json" | jq .
```

### 7.6 IPsec/IKEv2 Best Practices

| การตั้งค่า | ค่าแนะนำ |
|-----------|---------|
| **IKE Encryption** | AES-256-GCM |
| **IKE Integrity** | SHA-256 |
| **IKE DH Group** | Group 14 (2048-bit) หรือ Group 19 (256-bit ECP) |
| **IPsec Encryption** | AES-256-GCM |
| **IPsec PFS** | DH Group 14 หรือ 19 |
| **Lifetime** | IKE SA: 24 ชม., IPsec SA: 1 ชม. (หรือ 2.5 GB) |
| **DPD** | Dead Peer Detection — ทุก 10 วินาที |
| **NAT-T** | เปิด (UDP 4500) |

### 7.7 SSH Hardening Checklist

```bash
# SSH Hardening — /etc/ssh/sshd_config
Protocol 2
Port 22                                    # หรือเปลี่ยนพอร์ต
AddressFamily inet                         # IPv4 only

# Authentication
PermitRootLogin prohibit-password          # ห้าม Root Login ด้วย Password
PubkeyAuthentication yes
PasswordAuthentication no                  # ใช้ Key เท่านั้น
AuthenticationMethods publickey            # หรือ publickey,keyboard-interactive

# Key Exchange
KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
HostKeyAlgorithms ssh-ed25519

# Session
ClientAliveInterval 300
ClientAliveCountMax 0
MaxAuthTries 3
MaxSessions 10

# Logging
LogLevel VERBOSE
SyslogFacility AUTH
```

---

## 8. สรุปท้ายบท (Chapter Summary)

### สาระสำคัญของบทนี้

1. **การรักษาความปลอดภัยในแต่ละ Layer ของ OSI Model** — แต่ละ Layer มีโพรโทคอลความปลอดภัยที่แตกต่างกัน ตั้งแต่ Application Layer (HTTPS, SMTPS) ไปจนถึง Network Layer (IPsec, WireGuard) และ Data Link Layer (MACsec, 802.1X)

2. **SSL/TLS** — เป็นโพรโทคอลความปลอดภัยที่ใช้กันแพร่หลายที่สุด ปัจจุบันควรใช้ TLS 1.3 ซึ่งลด Handshake จาก 2 RTT เหลือ 1 RTT ตัด Algorithm ที่ไม่ปลอดภัยออกทั้งหมด และบังคับใช้ Perfect Forward Secrecy

3. **IPsec** — ให้ความปลอดภัยระดับ Network Layer (Layer 3) ประกอบด้วย AH (Authentication + Integrity), ESP (Authentication + Integrity + Encryption), และ IKE สำหรับจัดการ Key โดยรองรับ 2 โหมดการทำงานคือ Transport Mode (Host-to-Host) และ Tunnel Mode (Site-to-Site VPN)

4. **SSH** — เป็นโพรโทคอลสำหรับ Remote Administration และ File Transfer อย่างปลอดภัย มีสถาปัตยกรรม 3 ชั้น (Transport, Authentication, Connection) รองรับการ Public Key Authentication, Port Forwarding, และ Tunneling

5. **WireGuard** — โพรโทคอล VPN สมัยใหม่ที่มี Codebase เล็ก (~4,000 บรรทัด) ใช้ Curve25519 และ ChaCha20-Poly1305 เป็นค่าเริ่มต้น เร็วกว่าและตั้งค่าง่ายกว่า IPsec

6. **การโจมตี SSL/TLS** — การโจมตีที่สำคัญตลอดประวัติศาสตร์ ได้แก่ BEAST, POODLE, Heartbleed, FREAK, LOGJAM, DROWN, ROBOT, และ ALPACA ทุกการโจมตีสามารถป้องกันได้ด้วยการกำหนดค่าที่ถูกต้อง — ใช้ TLS 1.3, AEAD Cipher, ECDHE Key Exchange, และปิด Algorithm ที่ไม่ปลอดภัย

7. **Best Practices** — การตั้งค่าที่แนะนำ: Mozilla Intermediate Profile, HSTS, CAA Record, DANE, Certificate Transparency Monitoring, และ OCSP Stapling

### Mind Map ของบทนี้

```
                        ┌── Layer 2: MACsec, 802.1X
                        ├── Layer 3: IPsec, WireGuard
        OSI Security ───├── Layer 4: TLS, DTLS
                        ├── Layer 5-6: SSH, TLS
                        └── Layer 7: HTTPS, SMTPS, FTPS

                        ┌── TLS 1.2: 2-RTT Handshake
                        ├── TLS 1.3: 1-RTT Handshake (+0-RTT)
        SSL/TLS ────────├── Cipher Suite: KEX + Auth + Cipher + MAC
                        ├── DTLS: TLS over UDP (IoT, VoIP)
                        └── TLS Attacks: BEAST → POODLE → Heartbleed → DROWN → ROBOT

                        ┌── AH: Authentication + Integrity (No Encrypt)
        IPsec ──────────├── ESP: Authentication + Integrity + Encryption
                        ├── Transport Mode (Host-to-Host)
                        ├── Tunnel Mode (Site-to-Site VPN)
                        └── IKEv2: Key Exchange (4 messages)

                        ┌── 3-Layer Architecture: TRANS → AUTH → CONN
        SSH ────────────├── Public Key Authentication (Ed25519)
                        ├── Port Forwarding: Local, Remote, Dynamic
                        ├── SFTP / SCP / rsync
                        └── Hardening: No Password, Key Only

                        ┌── HTTPS (TLS) → Web
        Protocol ───────├── FTPS/SFTP → File Transfer
        Comparison ─────├── SMTPS/STARTTLS → Email
                        ├── DoH/DoT → DNS Privacy
                        └── WireGuard → Modern VPN

                        ┌── BEAST (TLS 1.0 CBC)
                        ├── CRIME (Compression)
                        ├── Heartbleed (OpenSSL Bug)
        TLS Attacks ────├── POODLE (SSL 3.0 CBC)
                        ├── FREAK (Export RSA)
                        ├── LOGJAM (Export DH)
                        ├── DROWN (Cross-Protocol SSLv2)
                        ├── ROBOT (Bleichenbacher)
                        └── ALPACA (Protocol Confusion)

                        ┌── TLS 1.3 + AEAD + ECDHE
        Best ───────────├── HSTS + CAA + DANE
        Practices ──────├── CT Monitoring + OCSP Stapling
                        └── Mozilla SSL Configuration Generator
```

---

## คำถามทบทวน (Review Questions)

1. จงอธิบายความแตกต่างระหว่าง TLS Handshake ใน TLS 1.2 และ TLS 1.3 — TLS 1.3 ลด RTT ได้อย่างไร?
2. IPsec ทำงานใน Layer ใดของ OSI Model? จงอธิบายความแตกต่างระหว่าง Transport Mode และ Tunnel Mode พร้อมยกตัวอย่างการใช้งาน
3. เปรียบเทียบความแตกต่างของ AH และ ESP ใน IPsec — เมื่อใดควรใช้ AH และเมื่อใดควรใช้ ESP?
4. SSH ใช้หลักการใดในการรักษาความปลอดภัย? จงอธิบาย 3 ชั้นสถาปัตยกรรมของ SSH
5. เปรียบเทียบข้อดีข้อเสียของ FTPS และ SFTP — ถ้าคุณต้องออกแบบระบบรับส่งไฟล์สำหรับองค์กร คุณจะเลือกใช้โพรโทคอลใด? เพราะเหตุใด?
6. อธิบายการโจมตี Heartbleed (CVE-2014-0160) — หลักการทำงาน, ผลกระทบ, และแนวทางการป้องกัน
7. จงอธิบายความแตกต่างระหว่างการโจมตี POODLE และ DROWN — เป้าหมายและวิธีการโจมตีต่างกันอย่างไร?
8. WireGuard แตกต่างจาก IPsec อย่างไรบ้าง? จุดเด่นของ WireGuard ที่ทำให้ได้รับความนิยมเพิ่มขึ้นคืออะไร?
9. จงอธิบายกลไกของ HSTS, CAA, และ DANE — ทั้ง 3 อย่างนี้ช่วยเพิ่มความปลอดภัยให้กับ HTTPS ได้อย่างไร?
10. ถ้าเป็นผู้ดูแลระบบที่ต้องกำหนดค่า TLS สำหรับเว็บเซิร์ฟเวอร์ จงเลือก Cipher Suite และการตั้งค่าที่ปลอดภัย (ตาม Mozilla Intermediate Profile) พร้อมอธิบายเหตุผล

---

## เอกสารอ้างอิง (References)

1. IETF RFC 8446. (2018). *The Transport Layer Security (TLS) Protocol Version 1.3*. https://datatracker.ietf.org/doc/rfc8446/
2. IETF RFC 4301. (2005). *Security Architecture for the Internet Protocol*. https://datatracker.ietf.org/doc/rfc4301/
3. IETF RFC 7296. (2014). *Internet Key Exchange Protocol Version 2 (IKEv2)*. https://datatracker.ietf.org/doc/rfc7296/
4. IETF RFC 4251. (2006). *The Secure Shell (SSH) Protocol Architecture*. https://datatracker.ietf.org/doc/rfc4251/
5. IETF RFC 4253. (2006). *The Secure Shell (SSH) Transport Layer Protocol*. https://datatracker.ietf.org/doc/rfc4253/
6. IETF RFC 5246. (2008). *The Transport Layer Security (TLS) Protocol Version 1.2*. https://datatracker.ietf.org/doc/rfc5246/
7. IETF RFC 6797. (2012). *HTTP Strict Transport Security (HSTS)*. https://datatracker.ietf.org/doc/rfc6797/
8. IETF RFC 6962. (2013). *Certificate Transparency*. https://datatracker.ietf.org/doc/rfc6962/
9. IETF RFC 6844. (2013). *DNS Certification Authority Authorization (CAA) Resource Record*. https://datatracker.ietf.org/doc/rfc6844/
10. IETF RFC 6698. (2012). *The DNS-Based Authentication of Named Entities (DANE) Transport Layer Security (TLS) Protocol*. https://datatracker.ietf.org/doc/rfc6698/
11. IETF RFC 7858. (2016). *Specification for DNS over Transport Layer Security (TLS)*. https://datatracker.ietf.org/doc/rfc7858/
12. IETF RFC 8484. (2018). *DNS Queries over HTTPS (DoH)*. https://datatracker.ietf.org/doc/rfc8484/
13. IETF RFC 9000. (2021). *QUIC: A UDP-Based Multiplexed and Secure Transport*. https://datatracker.ietf.org/doc/rfc9000/
14. IETF RFC 9001. (2021). *Using TLS to Secure QUIC*. https://datatracker.ietf.org/doc/rfc9001/
15. IETF RFC 9147. (2021). *The Datagram Transport Layer Security (DTLS) Protocol Version 1.3*. https://datatracker.ietf.org/doc/rfc9147/
16. Donenfeld, J. A. (2017). *WireGuard: Next Generation Kernel Network Tunnel*. Proceedings of the 2017 Network and Distributed System Security Symposium (NDSS). https://www.wireguard.com/papers/wireguard.pdf
17. Stallings, W. (2022). *Cryptography and Network Security: Principles and Practice* (8th ed.). Pearson.
18. Rescorla, E. (2018). *SSL and TLS: Designing and Building Secure Systems*. Addison-Wesley.
19. Mozilla. (2024). *Mozilla SSL Configuration Generator*. https://ssl-config.mozilla.org/
20. OWASP. (2024). *Transport Layer Protection Cheat Sheet*. https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html
21. AlFardan, N. J., & Paterson, K. G. (2013). *Lucky Thirteen: Breaking the TLS and DTLS Record Protocols*. IEEE Symposium on Security and Privacy.
22. Bock, H., et al. (2019). *The ALPACA Attack: Breaking TLS through Application-Layer Protocol Confusion*. USENIX Security Symposium.
23. Aviram, N., et al. (2016). *DROWN: Breaking TLS using SSLv2*. USENIX Security Symposium.
24. US-CERT. (2014). *Heartbleed Vulnerability (CVE-2014-0160)*. https://www.cisa.gov/news-events/alerts/2014/04/08/openssl-heartbleed-vulnerability
25. CISA. (2023). *Transport Layer Security (TLS) Best Practices*. https://www.cisa.gov/resources-tools/resources/transport-layer-security-tls-best-practices
