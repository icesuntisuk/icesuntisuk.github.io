# CH-4: โครงสร้างพื้นฐานกุญแจสาธารณะ (PKI) และการจัดการ Certificate

## วัตถุประสงค์การเรียนรู้ (Learning Objectives)

เมื่อจบบทนี้แล้ว ผู้เรียนสามารถ:
1. อธิบายองค์ประกอบของ PKI — CA, RA, VA, Certificate Repository, HSM — และ Trust Model (Hierarchical, Mesh, Web of Trust) ได้
2. อธิบายโครงสร้างของ X.509 v3 Certificate ฟิลด์และ Extension ที่สำคัญ พร้อมความแตกต่างระหว่าง DER, PEM, PKCS#12 Encoding ได้
3. อธิบาย Certificate Chain การตรวจสอบความน่าเชื่อถือ (Path Validation ตาม RFC 5280) และบทบาทของ Trust Store ได้
4. อธิบาย Certificate Lifecycle Management — ตั้งแต่ CSR, Issuance, Auto-Enrollment (ACME/SCEP/EST), Renewal, จนถึง Expiration
5. เปรียบเทียบ CRL, Delta CRL, OCSP, และ OCSP Stapling — ข้อดี ข้อเสีย และกรณีการใช้งานที่เหมาะสม
6. อธิบาย Certificate Transparency (CT) — กลไกการตรวจจับ Certificate ปลอม — และประยุกต์ใช้กับกรณีศึกษา DigiNotar และ Comodo
7. อธิบายการประยุกต์ใช้ PKI ใน TLS, Code Signing, S/MIME, IoT Device Identity, และ Document Signing
8. วิเคราะห์ภัยคุกคามต่อ PKI — CA Compromise, Weak Key Generation, SHA-1 Deprecation — และมาตรการป้องกัน

---

## 1. ความรู้เบื้องต้นเกี่ยวกับ PKI

### 1.1 PKI คืออะไร?

**Public Key Infrastructure (PKI)** คือโครงสร้างพื้นฐานที่ประกอบด้วยนโยบาย มาตรฐาน บุคลากร ฮาร์ดแวร์และซอฟต์แวร์ ที่ใช้ในการสร้าง จัดการ แจกจ่าย ใช้งาน จัดเก็บ และเพิกถอน Digital Certificate — เพื่อให้สามารถใช้งาน Public Key Cryptography ได้อย่างน่าเชื่อถือในวงกว้าง

PKI แก้ปัญหาสำคัญของ Asymmetric Cryptography: **"ฉันจะเชื่อถือ Public Key นี้ได้อย่างไรว่ามันเป็นของคนที่ฉันคิดว่าควรจะเป็น"** — PKI ตอบคำถามนี้ด้วยการมี Third Party ที่เชื่อถือได้ (CA) เป็นผู้รับรองความถูกต้องของ Public Key

### 1.2 ความสำคัญของ PKI ในปัจจุบัน

| การใช้งาน | บทบาทของ PKI |
|-----------|-------------|
| **TLS/SSL (HTTPS)** | รับรองตัวตนเว็บเซิร์ฟเวอร์ — เข้ารหัสการสื่อสาร — ป้องกัน MITM |
| **Email Security (S/MIME)** | ลงนามและเข้ารหัสอีเมล — ยืนยันตัวตนผู้ส่ง — ป้องกัน Phishing |
| **Code Signing** | ยืนยันว่าซอฟต์แวร์มาจากผู้พัฒนาจริง — ตรวจสอบว่า Code ไม่ถูกแก้ไข |
| **VPN (IPsec, OpenVPN)** | รับรองอุปกรณ์ที่เชื่อมต่อ — แทน PSK (Pre-Shared Key) |
| **IoT** | Identity Management สำหรับอุปกรณ์ IoT — การ Onboarding และ Revocation |
| **Document Signing** | ลงนามเอกสารดิจิทัล — มีผลทางกฎหมาย (e-Signature) |
| **802.1X (Network Access)** | Authentication ของอุปกรณ์ก่อนเชื่อมต่อเครือข่าย (EAP-TLS) |
| **Government (National ID, e-Passport)** | รับรองตัวตนประชาชน — ป้องกันการปลอมแปลงเอกสาร |

### 1.3 Trust Models (แบบจำลองความเชื่อถือ)

PKI สามารถจัดโครงสร้างความเชื่อถือได้หลายรูปแบบ:

| Trust Model | โครงสร้าง | ข้อดี | ข้อเสีย | ตัวอย่าง |
|------------|-----------|------|---------|---------|
| **Single CA** | CA ตัวเดียวรับรองทุกคน | ง่าย, จัดการไม่ซับซ้อน | Single Point of Failure — ถ้า CA ถูกละเมิด ทุกคนเสียหาย | Enterprise PKI เล็ก |
| **Hierarchical CA** | Root CA → Intermediate CA(s) → End Entity | **มาตรฐานจริง** — Root CA Offline (ปลอดภัย), Load Distribution, Policy Separation | ซับซ้อนกว่า, ต้องจัดการ Chain | **PKI ทั่วโลก (TLS, S/MIME)** |
| **Mesh / Cross-Certification** | CA หลายตัวรับรองซึ่งกันและกัน | ไม่ต้องมี CA กลาง, ยืดหยุ่น | ซับซ้อนมาก, Cross-Certification Path ยาก | Government PKI (ACES, SAFE) |
| **Web of Trust** | ผู้ใช้รับรองกันเอง — ไม่มี CA | ไม่ต้องมี CA, Decentralized | Scalability ต่ำ, Trust Model ซับซ้อน | PGP/GPG |
| **Bridge CA** | CA กลางเชื่อมต่อ CA ต่างๆ | เชื่อม PKI ต่างองค์กรได้ | Single Point of Failure สำหรับ Cross-Cert | US Federal PKI (FPKI) |

**Hierarchical CA — แบบจำลองที่ใช้ใน TLS:**

```
┌─────────────────────────────────────────┐
│  Root CA (Offline — Air-Gapped)         │
│  └── ใช้งานเฉพาะการ Sign Intermediate   │
│  └── เก็บใน HSM หรือ Safe              │
│  └── อายุ Certificate: 20-30 ปี          │
└────────────────┬────────────────────────┘
                 │
    ┌────────────┴────────────┐
    │                         │
    ▼                         ▼
┌──────────────────┐  ┌──────────────────┐
│ Intermediate CA 1 │  │ Intermediate CA 2│
│ (Online)         │  │ (Online)         │
│ └── ออก Server   │  │ └── ออก Code     │
│     Certificates │  │     Signing Cert │
│ อายุ Cert: 3-5 ปี│  │ อายุ Cert: 5 ปี │
└────────┬─────────┘  └────────┬─────────┘
         │                     │
         ▼                     ▼
    End Entity             End Entity
    Certificate            Certificate
    (Server Cert)          (Code Sign)
```

---

## 2. องค์ประกอบของ PKI

### 2.1 ภาพรวมองค์ประกอบ

| องค์ประกอบ | ตัวย่อ | บทบาทหลัก | ตัวอย่าง |
|-----------|--------|-----------|---------|
| **Certificate Authority** | CA | ออกและรับรอง Digital Certificate — ถือ Root Key ที่สำคัญที่สุด | DigiCert, Let's Encrypt, Microsoft AD CS |
| **Registration Authority** | RA | ตรวจสอบตัวตนผู้ขอ Certificate ก่อนส่งต่อให้ CA | ส่วนหนึ่งของ CA หรือแยกอิสระ |
| **Validation Authority** | VA | ตรวจสอบสถานะ Certificate แบบ Real-time — ให้บริการ OCSP | OCSP Responder |
| **Certificate Repository** | — | ที่เก็บ Certificate และ CRL สำหรับให้ Client ดาวน์โหลด | LDAP Directory, HTTP Server, Public CT Log |
| **Hardware Security Module** | HSM | ฮาร์ดแวร์สำหรับเก็บ Private Key อย่างปลอดภัย — ป้องกันการขโมย | YubiHSM, Thales Luna, AWS CloudHSM |
| **Certificate Policy** | CP | เอกสารนโยบาย — ระบุกฎเกณฑ์และแนวทางปฏิบัติของ PKI | "CP for Public TLS Certificates" |
| **Certificate Practice Statement** | CPS | เอกสารรายละเอียดการดำเนินงานของ CA — วิธีปฏิบัติจริง | DigiCert CPS |
| **End Entity** | — | ผู้ใช้ปลายทางที่ถือ Certificate และ Key Pair | Web Server, User, Device, Software |

### 2.2 Certificate Authority (CA)

CA คือ **หัวใจของ PKI** — ทำหน้าที่ออกและลงนามใน Digital Certificate โดยใช้ Private Key ของตนเอง

| ประเภท CA | ลักษณะ | อายุ Certificate | การรักษาความปลอดภัย |
|-----------|--------|-----------------|-------------------|
| **Root CA (Offline)** | ไม่เชื่อมต่อเครือข่าย — ใช้เฉพาะ Sign Intermediate CA | 20-30 ปี | Air-Gapped, HSM, Multi-Person Access, Safe Deposit |
| **Intermediate CA** | เชื่อมต่อเครือข่าย — ออก End Entity Certificates | 3-10 ปี | HSM หรือ Software Key, Access Control, Logging |
| **Public CA** | บริการออก Certificate ให้บุคคล/องค์กรทั่วไป | ตามนโยบาย | Audit ตาม WebTrust, CA/Browser Forum |
| **Private CA (Enterprise)** | ออก Certificate ภายในองค์กร | ตามนโยบาย | องค์กรกำหนดนโยบายเอง |

**การปกป้อง Root CA Private Key — Best Practices:**
- **Offline/Air-Gapped** — ไม่เชื่อมต่อเครือข่ายใดๆ
- **เก็บใน HSM** (Hardware Security Module) — ถ้า Key ออกจาก HSM แสดงว่าถูกละเมิด
- **Multi-Person Control** — ต้องมีคน N คน (เช่น 3 in 5) เพื่อใช้งาน Root Key
- **Physical Security** — เก็บใน Safe หรือ Vault ที่มีการควบคุม
- **Limited Use** — ใช้เฉพาะการ Sign Intermediate CA Certificate (ทุก 3-10 ปี)

### 2.3 Registration Authority (RA)

RA ทำหน้าที่ตรวจสอบตัวตนก่อนที่ CA จะออก Certificate — แยก Responsibility ออกจาก CA เพื่อความปลอดภัย:

**หน้าที่ของ RA:**
1. รับ CSR (Certificate Signing Request) จาก End Entity
2. ตรวจสอบตัวตนตามระดับความน่าเชื่อถือ (DV/OV/EV)
3. ตรวจสอบว่า Applicant ครอบครอง Private Key จริง (ผ่าน CSR Signature)
4. อนุมัติหรือปฏิเสธคำขอ
5. ส่งต่อไปยัง CA เพื่อลงนามและออก Certificate

**RA Security:**
- กรณี Comodo (2011): ผู้โจมตีเข้าถึง RA Account ได้ → ขอ Certificate ปลอม 9 ใบ
- RA ที่ปลอดภัยต้องมี: MFA, IP Restriction, Audit Log, Separation of Duties

### 2.4 Hardware Security Module (HSM)

HSM คือฮาร์ดแวร์เฉพาะทางสำหรับเก็บ Private Key และทำ Cryptographic Operations อย่างปลอดภัย:

| คุณสมบัติ | HSM (Hardware) | Software Key Storage |
|-----------|---------------|---------------------|
| **การเก็บ Key** | Key ไม่สามารถออกจาก HSM ได้ (FIPS 140-2/3) | Key อยู่ใน Memory หรือ Disk |
| **การป้องกัน** | Tamper-Proof — ถ้ามีการงัดแงะ Key จะได้รับการลบ | ขึ้นอยู่กับ OS Security |
| **Performance** | Hardware Acceleration — AES, RSA, ECC เร็วมาก | ใช้ CPU |
| **ราคา** | แพง ($500-$100,000+) | ฟรี |
| **การใช้งาน** | Root CA, Intermediate CA, Code Signing, Payment | Development, Personal |

### 2.5 Certificate Policy (CP) vs Certificate Practice Statement (CPS)

| เอกสาร | คำอธิบาย | เปรียบเทียบ |
|--------|----------|------------|
| **Certificate Policy (CP)** | **นโยบาย** — ว่า CA ควรทำอะไร (สูง, นามธรรม) | "CA ต้องตรวจสอบตัวตนก่อนออก Certificate" |
| **CPS** | **วิธีปฏิบัติ** — ว่า CA ทำจริงอย่างไร (ละเอียด, ปฏิบัติ) | "RA ตรวจสอบโดยการโทรศัพท์ยืนยัน + ส่งอีเมล + ตรวจสอบเอกสารราชการ" |

เอกสารทั้งสองเป็นข้อบังคับสำหรับ Public CA ที่ผ่านการ Audit ตาม WebTrust

---

## 3. โครงสร้างของ X.509 Certificate

### 3.1 รูปแบบการจัดเก็บ Certificate

| รูปแบบ | ลักษณะ | Extension | การใช้งาน |
|--------|--------|-----------|----------|
| **DER (Distinguished Encoding Rules)** | Binary — ใช้ ASN.1 Encoding | `.cer`, `.crt`, `.der` | Windows, Java |
| **PEM (Privacy Enhanced Mail)** | Base64 ของ DER — มี Header/Footer | `.pem`, `.crt`, `.key` | Linux, OpenSSL, Web Servers |
| **PKCS#12 / PFX** | Container — เก็บ Certificate + Private Key (เข้ารหัส) | `.p12`, `.pfx` | Windows, Import/Export |
| **PKCS#7 / P7B** | เก็บเฉพาะ Certificate (Chain) — ไม่มี Private Key | `.p7b`, `.p7c` | Windows, Java |

**ตัวอย่าง PEM Certificate:**
```
-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIQKj0Gt3mzP7mFk3LQ8X9VzANBgkqhkiG9w0BAQsFADB
... base64 encoded data ...
-----END CERTIFICATE-----
```

### 3.2 ฟิลด์ใน X.509 v3 Certificate

```
Certificate ::= SEQUENCE {
    tbsCertificate       TBSCertificate,     -- ข้อมูล Certificate (To Be Signed)
    signatureAlgorithm   AlgorithmIdentifier, -- Algorithm ของ Signature
    signatureValue       BIT STRING           -- Digital Signature จาก CA
}

TBSCertificate ::= SEQUENCE {
    version         [0]  EXPLICIT INTEGER DEFAULT v1,  -- v1, v2, หรือ v3
    serialNumber         INTEGER,                      -- เลข Serial (ไม่ซ้ำ)
    signature            AlgorithmIdentifier,           -- Algorithm ของ Signature
    issuer               Name,                          -- DN ของผู้ออก
    validity             Validity,                      -- ระยะเวลา
    subject              Name,                          -- DN ของเจ้าของ
    subjectPublicKeyInfo SubjectPublicKeyInfo,           -- Public Key
    issuerUniqueID  [1]  IMPLICIT BIT STRING OPTIONAL,  -- v2+
    subjectUniqueID [2]  IMPLICIT BIT STRING OPTIONAL,  -- v2+
    extensions      [3]  EXPLICIT Extensions OPTIONAL   -- v3+
}
```

### 3.3 คำอธิบายฟิลด์สำคัญ

| ฟิลด์ | คำอธิบาย | ตัวอย่าง |
|------|----------|---------|
| **Version** | เวอร์ชันของ X.509 — ปัจจุบันใช้ v3 | v3 (2) |
| **Serial Number** | เลขเฉพาะของ Certificate — ไม่ซ้ำกันใน CA เดียวกัน | `04:9F:3B:...` (20 ไบต์) |
| **Signature Algorithm** | Algorithm ที่ CA ใช้ลงนาม Certificate | sha256WithRSAEncryption, ecdsa-with-SHA384 |
| **Issuer** | Distinguished Name (DN) ของ CA ที่ออก | `CN=DigiCert Global CA, O=DigiCert Inc, C=US` |
| **Validity: Not Before** | วันที่เริ่มมีผล | `Jan 1 00:00:00 2025 GMT` |
| **Validity: Not After** | วันที่หมดอายุ | `Jan 1 23:59:59 2026 GMT` |
| **Subject** | DN ของเจ้าของ Certificate | `CN=*.example.com, O=Example Corp, L= Bangkok, C=TH` |
| **Subject Public Key Info** | Algorithm + Public Key Value | RSA (2048 bits) หรือ ECDSA (P-256) |

### 3.4 Distinguished Name (DN)

DN ใช้ระบุตัวตนของเจ้าของ Certificate (Subject) หรือผู้ออก Certificate (Issuer):

| Attribute | ชื่อเต็ม | ตัวอย่าง |
|-----------|---------|---------|
| **CN** | Common Name | `www.example.com`, `John Doe` |
| **O** | Organization | `Example Company Ltd.` |
| **OU** | Organizational Unit | `IT Department`, `Security` |
| **L** | Locality | `Bangkok`, `San Francisco` |
| **ST** | State / Province | `Bangkok`, `California` |
| **C** | Country (ISO 3166-1 alpha-2) | `TH`, `US`, `JP` |
| **E** | Email Address | `admin@example.com` |

**ตัวอย่าง:**
```
Subject: CN = *.example.com, O = Example Corp, L = Bangkok, ST = Bangkok, C = TH
Issuer:  CN = DigiCert Global G2 TLS RSA SHA256 2020 CA1, O = DigiCert Inc, C = US
```

### 3.5 X.509 v3 Extensions

Extensions คือส่วนสำคัญที่ทำให้ X.509 v3 มีความยืดหยุ่นและปลอดภัยกว่าเวอร์ชันก่อนหน้า:

| Extension | Critical? | คำอธิบาย | ตัวอย่างค่า |
|-----------|-----------|----------|-----------|
| **Basic Constraints** | ✅ ใช่ | ระบุว่า Certificate นี้เป็น CA หรือไม่ และ Depth ของ Chain | `CA:TRUE`, `CA:FALSE, pathlen:0` |
| **Key Usage** | ✅ ใช่ | จำกัดการใช้งาน Key | `digitalSignature, keyEncipherment, keyCertSign` |
| **Extended Key Usage** | 🔶 ขึ้นอยู่กับ | ระบุวัตถุประสงค์เฉพาะ | `serverAuth, clientAuth, codeSigning, emailProtection` |
| **Subject Alternative Name (SAN)** | 🔶 | รายการ Domain/Email/IP ที่ Certificate ใช้ได้ | `DNS:*.example.com, DNS:example.com` |
| **CRL Distribution Points** | ❌ ไม่ | URL สำหรับ Download CRL | `http://crl.digicert.com/...` |
| **Authority Information Access (AIA)** | ❌ ไม่ | URL ของ OCSP Responder + Issuer Certificate | `http://ocsp.digicert.com` |
| **Certificate Policies** | ❌ ไม่ | นโยบายที่ CA ใช้ในการออก Certificate | Policy OID |
| **Subject Key Identifier** | ❌ ไม่ | Hash ของ Public Key — ใช้สร้าง Chain | `a4:8b:...` |
| **Authority Key Identifier** | ❌ ไม่ | อ้างอิงถึง Public Key ของ CA ที่ลงนาม | `keyid:a4:8b:...` |
| **SCT (Signed Certificate Timestamp)** | ❌ ไม่ | หลักฐานว่า Certificate ได้รับการบันทึกใน CT Log | จาก Certificate Transparency |
| **OCSP Must-Staple** | ❌ ไม่ | บอก Client ว่า Server ต้องส่ง OCSP Stapling | |

**ความแตกต่าง X.509 v1, v2, v3:**

| เวอร์ชัน | เพิ่มจากเวอร์ชันก่อน | ปี |
|---------|-------------------|-----|
| **v1** | ฟิลด์พื้นฐาน — Issuer, Subject, Public Key, Validity | 1988 |
| **v2** | Issuer Unique ID, Subject Unique ID (ไม่ค่อยได้ใช้) | 1993 |
| **v3** | **Extensions** — ทำให้ Certificate มีความยืดหยุ่นและปลอดภัย | 1996 |

---

## 4. Certificate Chain และการตรวจสอบความน่าเชื่อถือ

### 4.1 Certificate Chain

Certificate Chain (หรือ Certification Path) คือลำดับชั้นของ Certificate ที่เชื่อมต่อจาก End Entity Certificate ไปยัง Root CA Certificate ที่เชื่อถือได้ (Trust Anchor):

```
Root CA Certificate (Self-Signed)
├── Subject = Issuer (CA รับรองตนเอง)
├── Basic Constraints: CA:TRUE
└── อยู่ใน Trust Store ของ OS/Browser
        ↑ ลงนามโดย (Signature จาก Root CA Private Key)
Intermediate CA Certificate
├── Issuer = Root CA Subject
├── Subject = Intermediate CA
├── Basic Constraints: CA:TRUE, pathlen:0
└── Key Usage: keyCertSign
        ↑ ลงนามโดย (Signature จาก Intermediate CA Private Key)
End Entity Certificate (Server Certificate)
├── Issuer = Intermediate CA Subject
├── Subject = *.example.com
├── Basic Constraints: CA:FALSE
├── Key Usage: digitalSignature, keyEncipherment
├── Extended Key Usage: serverAuth
└── SAN: DNS:*.example.com, DNS:example.com
```

### 4.2 กระบวนการตรวจสอบ Certificate (Path Validation)

ตาม RFC 5280 — การตรวจสอบ Certificate ประกอบด้วย 6 ขั้นตอน:

| ขั้นตอน | รายละเอียด | ถ้าล้มเหลว |
|---------|-----------|-----------|
| **1. Chain Building** | สร้างเส้นทางจาก End Entity → Root — ต้องหาลำดับที่ถูกต้อง | Certificate Not Trusted |
| **2. Signature Verification** | ตรวจสอบ Signature ในแต่ละระดับ — ใช้ Public Key ของถัดไป | Invalid Signature |
| **3. Validity Period** | ตรวจสอบวันที่ — Certificate ต้องยังไม่หมดอายุและยังไม่เริ่มมีผล | Certificate Expired |
| **4. Revocation Check** | ตรวจสอบว่า Certificate ได้รับการเพิกถอนหรือไม่ (CRL/OCSP) | Revoked Certificate |
| **5. Policy Check** | ตรวจสอบ Key Usage, Extended Key Usage — Certificate ใช้ถูกวัตถุประสงค์หรือไม่ | Not Authorized |
| **6. Name Check** | ตรวจสอบ Common Name หรือ SAN ตรงกับ Domain Name ที่เรียก | Name Mismatch |

### 4.3 Trust Store

Trust Store คือชุดของ Root CA Certificate ที่ระบบปฏิบัติการหรือ Browser เชื่อถือโดยปริยาย (Trust Anchor):

| ระบบ | ที่เก็บ Trust Store | จำนวน Root CA (ประมาณ) |
|------|-------------------|----------------------|
| **Windows** | Certificate Store (mmc) | ~200 |
| **macOS / iOS** | Keychain | ~150 |
| **Linux (Ubuntu/Debian)** | `/etc/ssl/certs/ca-certificates.crt` | ~150 |
| **Linux (RHEL/CentOS)** | `/etc/pki/tls/certs/ca-bundle.crt` | ~150 |
| **Android** | `/system/etc/security/cacerts/` | ~120 |
| **Firefox** | Built-in (อิสระจาก OS) | ~140 |
| **Chrome** | ใช้ Trust Store ของ OS | ตาม OS |

**ข้อควรรู้เกี่ยวกับ Trust Store:**
- การเพิ่ม Root CA ลงใน Trust Store = การเชื่อถือ Certificate ทั้งหมดที่ CA นั้นออก
- การลบ Root CA ออกจาก Trust Store = ทำให้ Certificate ทั้งหมดที่ CA นั้นรับรองไม่น่าเชื่อถือ
- Windows และ macOS อัปเดต Trust Store ผ่าน Windows Update / macOS Update
- Firefox จัดการ Trust Store ของตนเอง — อิสระจาก OS

### 4.4 Cross-Certification

Cross-Certification คือการที่ CA หนึ่งรับรอง CA อีกตัว — ทำให้ Certificate จาก PKI ต่างกันสามารถ Trust กันได้:

```
CA A (VeriSign) ←──── Cross-Certificate ────→ CA B (GlobalSign)
                        (CA A รับรอง CA B)
                             │
                             ▼
              Certificate ที่ออกโดย CA B
              ก็สามารถ Trust ผ่าน CA A ได้
```

**การใช้งาน:** US Federal PKI (FPKI) ใช้ Bridge CA เพื่อเชื่อมต่อ PKI ของหน่วยงานรัฐต่างๆ

---

## 5. การบริหารจัดการ Certificate Lifecycle

### 5.1 วงจรชีวิตของ Certificate

```
    ┌─────────────────────────────────────────────────────────────┐
    │                 Certificate Lifecycle                       │
    │                                                             │
    │  1. Key Generation ──── 2. CSR ──── 3. Verification        │
    │       (สร้าง Key Pair)    (ขอ Certificate)   (RA ตรวจสอบ)  │
    │                                                             │
    │  4. Issuance ────── 5. Distribution ────── 6. Installation │
    │  (CA ออก Cert)      (ส่ง Cert กลับ)       (ติดตั้งบนระบบ)  │
    │                                                             │
    │  ════════════════════ 7. Usage ═══════════════════════════  │
    │                                                             │
    │  8. Monitoring ────── 9. Renewal / Re-key ──── 10. Expiry  │
    │  (ตรวจสอบ Cert)       (ต่ออายุ / เปลี่ยน Key)  (หมดอายุ)    │
    │                           │                                │
    │                           ├── Revocation (ถ้า Key รั่ว)    │
    │                           │    ├── CRL / OCSP             │
    │                           │    └── CT Log                 │
    │                           └── Archive (เก็บประวัติ)       │
    └─────────────────────────────────────────────────────────────┘
```

### 5.2 Key Generation

**ข้อควรปฏิบัติในการสร้าง Key Pair:**

| ข้อควรทำ | คำอธิบาย |
|----------|---------|
| **สร้าง Key บนเครื่องที่จะใช้งาน** | อย่าสร้าง Key ที่เครื่องอื่นแล้วส่งมา — Private Key จะรั่วระหว่างทาง |
| **ใช้ Key Size ที่ปลอดภัย** | RSA 2048+ บิต หรือ ECC P-256+ |
| **ป้องกัน Private Key** | File Permission 600, HSM หรือ TPM สำหรับ Production |
| **Backup Private Key** | ถ้า Key หาย → Certificate ใช้งานไม่ได้ — Backup ด้วยความปลอดภัยสูง |
| **แยก Key ตามการใช้งาน** | ไม่ใช้ Key เดียวกันสำหรับ TLS, Code Signing, Email |

**คำสั่ง OpenSSL สำหรับสร้าง Key Pair และ CSR:**

```bash
# สร้าง Private Key (RSA 2048) + CSR ในคำสั่งเดียว
openssl req -new -newkey rsa:2048 -nodes \
    -keyout server.key -out server.csr \
    -subj "/C=TH/ST=Bangkok/L=Bangkok/O=Example Corp/CN=www.example.com"

# สร้าง Private Key ก่อน (ECC P-256)
openssl ecparam -genkey -name prime256v1 -out server.key

# สร้าง CSR จาก Key ที่มีอยู่
openssl req -new -key server.key -out server.csr \
    -subj "/C=TH/O=Example Corp/CN=www.example.com" \
    -addext "subjectAltName=DNS:www.example.com,DNS:example.com"
```

### 5.3 CSR (Certificate Signing Request)

CSR ประกอบด้วยข้อมูลสำคัญ 3 ส่วน:
1. **Public Key** — Key ที่ขอให้ CA รับรอง
2. **Distinguished Name** — ข้อมูลเจ้าของ (CN, O, OU, L, ST, C)
3. **Signature** — ลงนาม CSR ด้วย Private Key (พิสูจน์ว่าครอบครอง Key)

```
-----BEGIN CERTIFICATE REQUEST-----
MIICxjCCAa4CAQAwXjELMAkGA1UEBhMCVEgxEjAQBgNVBAgMCUJhbmdrb2sxCzAJ
... base64 ...
-----END CERTIFICATE REQUEST-----
```

**การตรวจสอบ CSR (โดย RA):**
```bash
# ดูเนื้อหา CSR
openssl req -in server.csr -noout -text

# ตรวจสอบว่า CSR ลงนามด้วย Private Key จริงหรือไม่
openssl req -in server.csr -noout -verify
```

### 5.4 การตรวจสอบตัวตน (Validation)

| ระดับ | การตรวจสอบ | ใช้เวลานาน | ราคาประมาณ/ปี | การใช้งาน |
|-------|-----------|-----------|-------------|----------|
| **DV (Domain Validation)** | ตรวจสอบว่าเป็นเจ้าของ Domain — ผ่านอีเมล, DNS Record, HTTP Challenge | นาที-ชม. | **ฟรี** (Let's Encrypt) หรือ $10-50 | เว็บไซต์ทั่วไป, Blog, SME |
| **OV (Organization Validation)** | ตรวจสอบตัวตนองค์กร — DBD, ทะเบียนการค้า, โทรศัพท์ยืนยัน | 1-3 วัน | $50-200 | เว็บไซต์ธุรกิจ |
| **EV (Extended Validation)** | ตรวจสอบละเอียด — เอกสารนิติบุคคล, บัตรประชาชน, สถานที่ตั้ง, โทรศัพท์ | 3-10 วัน | $200-800 | ธนาคาร, E-commerce, หน่วยงานรัฐ |

**DV Automation — ACME Protocol (Let's Encrypt):**

ACME (Automatic Certificate Management Environment) — RFC 8555 — เป็นโปรโทคอลที่ทำให้การขอ Certificate DV เป็นแบบอัตโนมัติเต็มรูปแบบ:
```
Client ───────────── ACME Protocol ──────────→ CA (Let's Encrypt)
  │                                              │
  ├── สร้าง Key Pair + CSR                      │
  ├── POST to New Order ──────────────────────→│
  │←── Challenges (HTTP-01 หรือ DNS-01) ───────┤
  ├── แก้ Challenge (วางไฟล์หรือ TXT Record)    │
  ├── POST to Challenge ──────────────────────→│
  │←── CA ตรวจสอบ Challenge ──────────────────┤
  │←── Certificate ────────────────────────────┤
  └── ติดตั้ง Certificate                        └── Auto-Renewal ทุก 60-90 วัน
```

### 5.5 การแจกจ่ายและการติดตั้ง

**Certificate Bundle Composition:**
```
Certificate Bundle (chain.pem):
├── End Entity Certificate (server.crt)        ← ลงนามโดย Intermediate
├── Intermediate CA Certificate                ← ลงนามโดย Root CA
└── Root CA Certificate (optional)             ← Self-Signed

การ Config บน Web Server:
- SSLCertificateFile: chain.pem (หรือ server.crt + intermediate.crt รวมกัน)
- SSLCertificateKeyFile: server.key (Private Key — ป้องกันด้วย file permission 400)

การตรวจสอบการติดตั้ง:
openssl s_client -connect example.com:443 -showcerts
```

### 5.6 การต่ออายุ Certificate (Renewal)

**แนวทางปฏิบัติที่แนะนำ:**
- **ต่ออายุก่อนหมดอายุ 30-60 วัน** — ป้องกัน Service Disruption
- **ใช้ Key เดิม (Same Key Renewal)** — CSR ใช้ Public Key เดิม — CA รับรอง Key เดิมอีกครั้ง
- **ใช้ Key ใหม่ (New Key Renewal)** — สร้าง Key Pair ใหม่ — **แนะนำ** เพื่อความปลอดภัย
- **Automated Renewal** — Let's Encrypt (ACME) ต่ออายุอัตโนมัติทุก 60-90 วัน

| วิธี | คำอธิบาย | ข้อดี | ข้อเสีย |
|-----|---------|------|---------|
| **Same Key** | ใช้ Key Pair เดิม — CSR เก่า (ถ้ายังไม่หมดอายุ) | ไม่ต้องเปลี่ยน Key ทุกที่ | ถ้า Key รั่ว ปัญหายังอยู่ |
| **New Key** | สร้าง Key Pair ใหม่ → CSR ใหม่ | เพิ่มความปลอดภัย (Key Rotation) | ต้องแจกจ่าย Key ใหม่ |

### 5.7 Certificate Monitoring

| เครื่องมือ | ฟังก์ชัน | รูปแบบ |
|-----------|---------|--------|
| **Certbot (EFF)** | Auto-renewal สำหรับ Let's Encrypt — Apache/Nginx | CLI |
| **acme.sh** | ACME Client Script — รองรับหลาย DNS API | Bash |
| **Caddy** | Web Server ที่ Auto-HTTPS — จัดการ Certificate อัตโนมัติ | Web Server |
| **cert-manager (Kubernetes)** | จัดการ Certificate ใน Kubernetes | Kubernetes |
| **OpenSCAD / Step CA** | Private CA สำหรับองค์กร — ACME Protocol | CLI + API |
| **SSL Labs** | ตรวจสอบการ Config TLS | Web |

---

## 6. Certificate Revocation: CRL vs OCSP

### 6.1 เหตุผลที่ต้อง Revoke Certificate

| เหตุผล | ตัวอย่าง |
|--------|---------|
| **Private Key ถูกเปิดเผย** | Heartbleed — Private Key รั่วจาก Memory Leak |
| **Private Key ถูกขโมย** | HSM ถูกขโมย, Laptop หาย |
| **เจ้าของ Certificate เปลี่ยนองค์กร** | พนักงาน (1) ที่ถือ Certificate ของบริษัทลาออก |
| **Certificate ออกโดยไม่ถูกต้อง** | DigiNotar — ออก Certificate ปลอม |
| **Domain Name เปลี่ยนเจ้าของ** | Domain ขายต่อ — Owner ใหม่ไม่ควรใช้ Certificate เดิม |
| **Cessation of Operation** | ระบบปิดตัว — Certificate ไม่จำเป็นอีกต่อไป |

### 6.2 CRL (Certificate Revocation List)

CRL เป็นลิสต์ของ Serial Number ของ Certificate ที่ได้รับการเพิกถอน — ออกโดย CA และลงนามด้วย Private Key ของ CA:

```
Certificate Revocation List:
├── Version
├── Signature Algorithm (sha256WithRSAEncryption)
├── Issuer (DN ของ CA)
├── This Update (วันที่ออก CRL)
├── Next Update (วันที่ CRL ถัดไป)
├── Revoked Certificates:
│   ├── Serial Number: 0x4A3B..., Revocation Date: Jan 15 2025
│   ├── Serial Number: 0x7C1D..., Revocation Date: Feb 20 2025
│   └── ... (รายการ Serial Numbers)
└── Signature (ลงนามโดย CA)

ตัวอย่าง URL: http://crl.digicert.com/DigiCertGlobalCA.crl
```

**ประเภทของ CRL:**

| ประเภท | คำอธิบาย | ขนาด | การใช้งาน |
|--------|---------|------|----------|
| **Full CRL (Base CRL)** | รายการ Revoked ทั้งหมดตั้งแต่เริ่ม | ใหญ่ | CA เล็ก |
| **Delta CRL** | เฉพาะ Revoked ตั้งแต่ Full CRL ล่าสุด | เล็ก | CA ใหญ่ (ประหยัด Bandwidth) |
| **Freshest CRL** | ลิงก์ไปยัง Delta CRL | เล็ก | ใช้ร่วมกับ Full CRL |
| **Indirect CRL** | CRL ที่รวม Revoked จากหลาย CA | กลาง | PKI Complex |

**ข้อจำกัดของ CRL:**
- **ขนาดใหญ่** — สำหรับ CA ใหญ่ (DigiCert) CRL อาจมีหลาย MB
- **Latency** — CRL อัปเดตตามรอบ (ทุก 6-24 ชม.) — Certificate ที่ได้รับการ Revoke ใหม่ๆ อาจไม่ปรากฏ
- **ไม่ Real-time** — ในช่วงเวลาระหว่างที่ CA ยังไม่ออก CRL ใหม่ Certificate ที่ได้รับการ Revoke อาจยังได้รับการเชื่อถือ

### 6.3 OCSP (Online Certificate Status Protocol)

OCSP — RFC 6960 — เป็นโปรโทคอลที่ใช้ตรวจสอบสถานะ Certificate แบบ Real-time:

```
Client                               OCSP Responder
  │                                        │
  ├── OCSP Request ─────────────────────→ │
  │   Serial Number: 0x4A3B...             │
  │   Issuer: CN=DigiCert Global CA...     │
  │                                        │
  │←── OCSP Response ────────────────────┤
  │   Status: Good / Revoked / Unknown     │
  │   This Update: (เวลาปัจจุบัน)          │
  │   Next Update: (เวลาที่ Response หมดอายุ)│
  │   Signature (ลงนามโดย CA)             │
  │                                        │
  ถ้า Status = Good → Certificate ยังใช้ได้
  ถ้า Status = Revoked → Certificate ถูกเพิกถอน
  ถ้า Status = Unknown → CA ไม่รู้จัก Certificate นี้
```

**ข้อดีของ OCSP:**
- **Real-time** — ข้อมูลทันสมัย
- **ขนาดเล็ก** — ตรวจสอบทีละ Certificate ไม่ต้องดาวน์โหลด CRL ทั้งหมด
- **ประสิทธิภาพ** — ใช้ Bandwidth น้อย

**ข้อเสียของ OCSP:**
- **ต้องออนไลน์ทุกครั้ง** — ถ้า OCSP Responder ล่ม → ไม่สามารถตรวจสอบได้ (Fail closed vs Fail open)
- **Privacy** — CA รู้ว่าผู้ใช้กำลังเยี่ยมชมเว็บไซต์ใด (Client ส่ง Serial Number → CA รู้ว่ากำลังเข้าถึง domain ใด)
- **ภาระ CA** — ต้องตอบ OCSP Request จำนวนมาก
- **Single Point of Failure** — ถ้า OCSP Responder Down → Client อาจข้ามการตรวจสอบ (Soft-fail)

### 6.4 OCSP Stapling (RFC 6066, RFC 6961)

OCSP Stapling แก้ปัญหาด้าน Privacy และ Performance ของ OCSP โดยให้เว็บเซิร์ฟเวอร์เป็นผู้ขอ OCSP Response จาก CA แล้วแนบไปกับ TLS Handshake:

```
แบบปกติ (OCSP):
Client ─── TLS Handshake ───→ Server
                                  Client ต้องติดต่อ OCSP Responder แยก → Slow + Privacy Leak

แบบ OCSP Stapling:
        ───(1) Server ขอ OCSP Response ──→ CA (ทุก 4-48 ชม.)
        ←──(2) OCSP Response ───────────────┤
Server ───(3) TLS Handshake + OCSP Response ──→ Client (Client ไม่ต้องติดต่อ CA)
                                                  ├── เร็วขึ้น (ลด Round Trip)
                                                  ├── Privacy ดี (CA ไม่รู้ Client)
                                                  └── Server มี OCSP Response ใน Cache
```

**ข้อดีของ OCSP Stapling เหนือ OCSP ปกติ:**
- **Privacy** — CA ไม่รู้ว่า Client กำลังเข้าถึง domain ใด
- **Performance** — Client ไม่ต้องติดต่อ OCSP Responder — ลด Latency
- **Reliability** — ไม่มี Single Point of Failure ที่ Client side

**OCSP Must-Staple (Extension):**
- Certificate Extension ที่บอก Client ว่า "Server **ต้อง**ส่ง OCSP Stapling"
- ถ้า Server ส่ง TLS Handshake โดยไม่มี OCSP Stapling → Client ปฏิเสธการเชื่อมต่อ
- ป้องกันการโจมตี Downgrade ที่ Client ข้ามการตรวจสอบ Revocation

### 6.5 การเปรียบเทียบ CRL, OCSP, OCSP Stapling

| คุณสมบัติ | CRL | Delta CRL | OCSP | OCSP Stapling |
|-----------|-----|-----------|------|--------------|
| **Real-time** | ❌ (ทุก 6-24 ชม.) | ❌ แต่ถี่กว่า | ✅ | ✅ |
| **ขนาดข้อมูล** | ใหญ่ (MB) | เล็ก | เล็ก (few bytes) | เล็ก |
| **Privacy** | ✅ ดี (ไม่ส่ง Serial) | ✅ ดี | ❌ แย่ (CA รู้ Client) | ✅ ดี |
| **Offline** | ✅ รองรับ | ✅ รองรับ | ❌ ต้องออนไลน์ | ✅ (Server Cache) |
| **ภาระ CA** | น้อย | ปานกลาง | **มาก** | ปานกลาง (Server Cache) |
| **Latency** | สูง (ต้อง Download) | ปานกลาง | ต่ำ | **ต่ำที่สุด** |
| **การใช้งานจริง** | Legacy | CA ขนาดใหญ่ | ปัจจุบัน | **แนะนำ** |

### 6.6 แนวทางปฏิบัติในปัจจุบันสำหรับ Browser

| Browser | วิธีตรวจสอบ Revocation | หมายเหตุ |
|---------|----------------------|---------|
| **Chrome** | CRLSet (Google ส่ง CRLSet อัปเดตทุก 30 นาที) + OCSP (Soft-fail) | CRLSet เป็น Default — OCSP ใช้เมื่อไม่เจอใน CRLSet |
| **Firefox** | CRLite (Compact CRL — ดาวน์โหลดทุก 6 ชม.) + OCSP | CRLite ใหม่กว่า CRLSet |
| **Safari** | OCSP (Hard-fail — ถ้า OCSP ไม่ตอบ → ไม่เชื่อมต่อ) | Privacy Issue — Apple เปลี่ยนเป็น OCSP Stapling มากขึ้น |
| **Edge** | CRLSet + OCSP (เหมือน Chrome) | |

**CRLSet และ CRLite** เป็นวิธีการใหม่ที่ Google และ Mozilla พัฒนาขึ้น — แทนที่การให้ Client ตรวจสอบ Revocation เอง โดย CA ส่งรายการ Revoked Certificate (Compact) ไปยัง Browser โดยตรง

---

## 7. Certificate Transparency (CT)

### 7.1 ปัญหาที่ CT แก้ไข

ก่อนมี CT: เมื่อ CA ออก Certificate ไม่ถูกต้อง (เช่น DigiNotar, Comodo) — ไม่มีวิธีตรวจจับอย่างรวดเร็ว
- CA ถูกบุกรุก → ออก Certificate ปลอม → นำไปใช้ MITM ได้
- กว่าจะตรวจพบ: อาจใช้เวลาหลายวันถึงหลายเดือน
- เหยื่อไม่รู้ว่ามี Certificate ของตัวเองถูกออกโดยไม่ได้รับอนุญาต

### 7.2 หลักการของ Certificate Transparency

Certificate Transparency — RFC 6962 — เสนอโดย Ben Laurie, Adam Langley, Emilia Kasper (Google, 2013):

```
1. ทุก Certificate ที่ออกโดย Public CA ต้องถูกบันทึกลงใน Public CT Log
2. CT Log เป็น Merkle Tree — ตรวจสอบได้ว่า Certificate อยู่ใน Log หรือไม่
3. CA ส่ง Certificate ไปยัง CT Log → Log ส่ง SCT (Signed Certificate Timestamp) กลับ
4. CA แนบ SCT ไปกับ Certificate (Extension หรือ TLS Extension)
5. Client ตรวจสอบ SCT — ถ้าไม่มี → ไม่เชื่อถือ Certificate
```

```
                           CT Log (Merkle Tree)
                                │
    ┌─────────── CA ────────────┤
    │                           │
    ▼                           ▼
Certificate + SCT           Audit ตรวจสอบ
(แนบ SCT ไปกับ TLS)        (Monitor ว่าไม่มี Cert ปลอม)
```

### 7.3 CT Log Structure

```
Merkle Tree (Hash Tree):
          ┌──── R (Root Hash) ────┐
          │                        │
    ┌──── H1 ────┐          ┌──── H2 ────┐
    │            │          │            │
  H1_1         H1_2       H2_1         H2_2
  │            │          │            │
Cert-1       Cert-2     Cert-3        Cert-4

SCT = Signed Certificate Timestamp
   ├── Log ID (Public Key ของ CT Log)
   ├── Timestamp (ตอนที่ถูกบันทึก)
   ├── Merkle Tree Hash
   └── Signature (ลงนามโดย CT Log)
```

**ประโยชน์ของ CT:**
- **Detect Rogue Certificate** — Domain Owner สามารถตรวจสอบ CT Log ว่ามี Certificate ของตัวเองถูกออกโดยไม่ได้รับอนุญาตหรือไม่
- **Audit CA** — CA ทุกแห่งต้องส่ง Certificate ไปยัง CT Log — สามารถตรวจสอบการทำงานของ CA ได้
- **Historical Record** — เก็บประวัติ Certificate ทั้งหมด — ใช้ในการสืบสวน

### 7.4 CT ในปัจจุบัน

- **Chrome** (2018+): Certificate ที่ไม่มี SCT จะไม่ได้รับการเชื่อถือ
- **Apple (iOS/macOS)** (2018+): บังคับ SCT สำหรับ Certificate ที่ออกหลังตุลาคม 2018
- **CA/Browser Forum**: ข้อบังคับว่า Public CA ต้องส่ง Certificate ทุกใบเข้า CT Log

---

## 8. การประยุกต์ใช้ PKI ในเครือข่าย

### 8.1 TLS/SSL (HTTPS)

| องค์ประกอบ | Certificate |
|-----------|-------------|
| **Server Certificate** | รับรองตัวตนของเว็บเซิร์ฟเวอร์ — มี SAN=Domain Name — EKU=serverAuth |
| **Client Certificate** (mTLS) | รับรองตัวตนของผู้ใช้หรืออุปกรณ์ — EKU=clientAuth |
| **Root CA** | DigiCert, Let's Encrypt (ISRG), GlobalSign |
| **Validation** | CRL / OCSP / OCSP Stapling / CT |

**Mutual TLS (mTLS):**
- ทั้ง Client และ Server มี Certificate
- ใช้ใน: API Security (Service Mesh — Istio, Linkerd), IoT, Zero Trust
- ข้อดี: ไม่ต้องใช้ Password หรือ API Key — Authentication ผ่าน Certificate

### 8.2 Code Signing

| รายละเอียด | คำอธิบาย |
|-----------|----------|
| **วัตถุประสงค์** | ยืนยันว่าซอฟต์แวร์มาจากผู้พัฒนาจริง และไม่ถูกแก้ไข |
| **ระบบปฏิบัติการ** | Windows (Authenticode), macOS (Gatekeeper), Android (APK Signing) |
| **EKU** | `codeSigning` |
| **การทำงาน** | Developer ลงนาม Binary/Installer ด้วย Code Signing Certificate |
| **Timestamp** | ลงนาม Timestamp พร้อม Signature — Certificate หมดอายุแล้ว Signature ยังใช้ได้ |
| **SmartScreen** | Windows Defender SmartScreen ตรวจสอบ Signature ก่อนรัน |

**การโจมตีที่เกี่ยวข้อง:**
- SolarWinds (2020): Malicious DLL ถูก Sign ด้วย Certificate จริง (Supply Chain Attack)
- **Lesson:** Code Signing Certificate ต้องปลอดภัยที่สุด — เก็บใน HSM

### 8.3 Email Security (S/MIME)

| คุณสมบัติ | S/MIME | PGP/GPG |
|-----------|--------|---------|
| **มาตรฐาน** | PKCS#7 / CMS | OpenPGP (RFC 4880) |
| **Trust Model** | **Hierarchical PKI** (CA-based) | **Web of Trust** |
| **การใช้งาน** | Enterprise, Outlook, Apple Mail | Technical Users, Linux |
| **Certificate** | X.509 (ต้องซื้อ/ขอจาก CA) | PGP Key (สร้างเอง ไม่ต้องมี CA) |
| **EKU** | `emailProtection` | — |
| **การออกแบบ** | Sign + Encrypt | Sign + Encrypt |

**S/MIME Workflow:**

```
Sender:
├── Sign: Hash(Email) → Sign ด้วย Private Key → Signature
├── Encrypt: สร้าง Session Key → Encrypt Email → Encrypt Session Key ด้วย Recipient's Public Key
└── ส่ง: Encrypted Email + Encrypted Session Key + Signature

Recipient:
├── Decrypt: Decrypt Session Key ด้วย Private Key → Decrypt Email
├── Verify: Verify Signature ด้วย Sender's Public Key
└── อ่าน Email → ตรวจสอบว่าเป็นของ Sender จริง
```

### 8.4 IoT Device Identity

| ความท้าทาย | แนวทางแก้ไขด้วย PKI |
|------------|-------------------|
| **อุปกรณ์นับล้านตัว** | CA + Auto-Provisioning (ACME, EST, CMP) |
| **Key อยู่ใน Device** | TPM (Trusted Platform Module) — Key ออกจาก TPM ไม่ได้ |
| **Revocation** | OCSP Stapling (Device ขอ OCSP Response) |
| **อายุอุปกรณ์ 5-10 ปี** | Certificate Renewal อัตโนมัติ |

**IoT PKI Workflow:**
```
1. Manufacturing: โหลด Device Certificate + Unique Key เข้า TPM
2. Onboarding: Device เชื่อมต่อ → ส่ง Certificate → Server ตรวจสอบ
3. Operation: Device ↔ Server สื่อสารผ่าน TLS ด้วย Certificate
4. Revocation: ถ้า Device ถูกบุกรุก → Revoke Certificate → Block การสื่อสาร
```

### 8.5 Document Signing

| มาตรฐาน | การใช้งาน |
|---------|----------|
| **PDF Signing (PAdES)** | ลงนาม PDF — รองรับโดย Adobe Acrobat |
| **XML Signing (XAdES)** | ลงนามเอกสาร XML — EU e-Signature |
| **CMS/PKCS#7 (CAdES)** | ลงนามข้อมูลทั่วไป |
| **Timestamp** | RFC 3161 — เพิ่ม Timestamp พร้อม Signature |

---

## 9. กรณีศึกษา: การโจมตี CA และผลกระทบ

### 9.1 DigiNotar (2011) — CA ล้มละลาย

| รายการ | รายละเอียด |
|--------|------------|
| **วันที่ตรวจพบ** | 19 กรกฎาคม 2011 |
| **ผู้โจมตี** | Unknown (เชื่อว่าเกี่ยวข้องกับอิหร่าน) |
| **ผล** | CA ของเนเธอร์แลนด์ล้มละลาย — Trust ได้รับการเพิกถอนใน 1 เดือน |

**Timeline:**
```
มิ.ย. 2011 — ผู้โจมตีเจาะระบบ DigiNotar — เข้าถึง Root CA
                └── Server ที่ไม่มี Patch — Windows Server 2003
                └── No HSM — Software Key
                └── No monitoring — ตรวจไม่พบการเข้าถึงผิดปกติ
   ↓
19 ก.ค. 2011 — ออก Certificate ปลอมสำหรับ *.google.com
                └── รวมถึง Yahoo, Skype, Twitter, Facebook, Mozilla
   ↓
27 ส.ค. 2011 — Google ตรวจพบ Certificate ปลอม (Certificate Pinning)
                └── Google แจ้ง DigiNotar + Dutch Gov
   ↓
29 ส.ค. 2011 — Mozilla, Microsoft, Apple, Google เพิกถอน Trust
                └── DigiNotar Root CA ถูกลบออกจาก Trust Store ทั้งหมด
   ↓
ก.ย. 2011 — DigiNotar ยื่นล้มละลาย
                └── บริษัทที่มีอายุ 10 ปี ต้องปิดตัว
```

**บทเรียนจาก DigiNotar:**
1. **HSM จำเป็น** — DigiNotar ไม่ใช้ HSM — Private Key อยู่ใน Software — ถูกขโมยได้
2. **Air-Gap Root CA** — Root CA ต้องไม่เชื่อมต่อ Internet
3. **Monitoring** — ต้องมี IDS/IPS + Audit Log — ตรวจพบการกระทำผิดปกติ
4. **Incident Response Plan** — DigiNotar ไม่มีแผน — ตอบสนองช้า
5. **Certificate Pinning** — Google ตรวจพบเพราะ Pinning — ไม่ใช่ระบบของ CA
6. **CA สูญเสีย Trust = ตาย** — เมื่อ Trust ได้รับการเพิกถอน CA ไม่สามารถอยู่รอด

### 9.2 Comodo (2011) — RA Account ถูกบุกรุก

| รายการ | รายละเอียด |
|--------|------------|
| **วันที่ตรวจพบ** | 15 มีนาคม 2011 |
| **ผู้โจมตี** | "ComodoHacker" — อ้างว่าอยู่ในอิหร่าน |
| **ผล** | Certificate ปลอม 9 ใบ — ตรวจพบเร็ว — Comodo ยังอยู่รอด |

**เหตุการณ์:**
- ผู้โจมตีเจาะ RA Account ของ Comodo (Global Partner)
- ขอ Certificate ปลอมสำหรับ: `mail.google.com`, `www.google.com`, `login.yahoo.com`, `login.skype.com`, `addons.mozilla.org`
- Comodo ตรวจพบภายในวันเดียวกัน — Revoke Certificate ทันที
- Browser ยอมรับ Comodo ต่อ — เพราะตอบสนองเร็ว

**บทเรียน:**
1. **RA Security** — RA Account ต้องมี MFA + IP Restriction
2. **Response Time** — ยิ่งเร็ว โอกาสรอดยิ่งสูง
3. **CT ไม่มีตอนนั้น** — ถ้ามี CT จะตรวจจับได้ตั้งแต่ Certificate ได้รับการบันทึกลง Log

### 9.3 Let's Encrypt (2015-Present) — PKI สำหรับทุกคน

| รายการ | รายละเอียด |
|--------|------------|
| **ก่อตั้ง** | 2015 — Internet Security Research Group (ISRG) |
| **ภารกิจ** | ให้ DV Certificate **ฟรี** แก่ทุกคน — ทำให้ HTTPS เป็น Default |
| **เทคโนโลยี** | ACME Protocol — Auto-Renewal ทุก 60-90 วัน |
| **ผลกระทบ** | HTTPS เพิ่มจาก 40% → >90% ของเว็บไซต์ทั่วโลก |

**นวัตกรรมของ Let's Encrypt:**
1. **ACME Protocol** (RFC 8555) — ขอ Certificate อัตโนมัติเต็มรูปแบบ
2. **DV Only** — ตรวจสอบแค่ Domain Ownership — ไม่ตรวจสอบองค์กร
3. **Short Lived** — Certificate มีอายุ 90 วัน — ลดผลกระทบถ้า Key รั่ว
4. **Auto-Renewal** — Certbot, acme.sh, Caddy — ต่ออายุอัตโนมัติ
5. **Free** — ลด Barrier ในการใช้ HTTPS

---

## 10. ภัยคุกคามต่อ PKI และมาตรการป้องกัน

| ภัยคุกคาม | คำอธิบาย | ผลกระทบ | การป้องกัน |
|-----------|----------|---------|-----------|
| **CA Compromise** | ผู้โจมตีเจาะ CA — ขโมย Private Key | ออก Certificate ปลอม — MITM | HSM, Air-Gap, Multi-Person Control, CT |
| **Weak Key Generation** | สร้าง Key ที่ไม่สุ่มเพียงพอ (ROCA, Debian Weak Keys) | ถอดรหัส Private Key ได้ | ใช้ HSM, Random Source ที่ดี, FIPS Validation |
| **SHA-1 Collision** | สร้าง Certificate ที่มี SHA-1 Hash เดียวกัน (2017) | Signature ปลอมจาก SHA-1 | **เลิกใช้ SHA-1** — ใช้ SHA-256 |
| **Rogue CA in Trust Store** | Root CA ที่ไม่น่าเชื่อถือได้รับการรวมใน Trust Store | Trust CA ปลอม | CA/Browser Forum, Audit, CT |
| **Phishing (Fake Certificate Request)** | ผู้โจมตีขอ DV Certificate สำหรับ Domain ใกล้เคียง | Phishing Site ที่มี HTTPS | EV Certificate (ไม่สามารถหลอกได้), Browser Warnings |
| **Downgrade Attack (SSL Stripping)** | Downgrade HTTPS → HTTP — Certificate ไม่ได้รับการใช้งาน | MITM | HSTS, HSTS Preloading |
| **Revocation Bypass** | Client ข้ามการตรวจสอบ CRL/OCSP | เชื่อถือ Certificate ที่ได้รับการ Revoke | OCSP Must-Staple, CRLSet, CRLite |
| **Quantum Computing** | Shor's Algorithm ทำลาย RSA/ECC | Public Key Cryptography ล้มเหลว | Post-Quantum Cryptography (CRYSTALS-Kyber/Dilithium) |

---

## 11. สรุปท้ายบท (Chapter Summary)

### 11.1 หลักการสำคัญ

| หัวข้อ | สรุป |
|-------|------|
| **PKI** | โครงสร้างพื้นฐานสำหรับจัดการ Digital Certificate — แก้ปัญหาการเชื่อถือ Public Key |
| **Trust Models** | 4 แบบ: Single CA, Hierarchical (มาตรฐาน TLS), Mesh/Cross-Certification, Web of Trust (PGP) |
| **X.509 v3** | ประกอบด้วย TBS Certificate + Signature + Extensions — v3 เพิ่ม Extensions (SAN, Key Usage, Basic Constraints) |
| **Certificate Chain** | Root CA (Trust Anchor) → Intermediate CA(s) → End Entity — ตรวจสอบ Path Validation 6 ขั้นตอน |
| **Lifecycle** | Key Gen → CSR → Verification → Issuance → Distribution → Usage → Renewal → Expiry/Revocation |
| **Revocation** | CRL (ใหญ่, ล่าช้า) → Delta CRL → OCSP (Real-time, Privacy Issue) → **OCSP Stapling** (แนะนำ) |
| **Certificate Transparency** | ทุก Certificate ต้องบันทึกใน Public CT Log — ตรวจจับ Certificate ปลอม (DigiNotar) |
| **ACME / Let's Encrypt** | DV Certificate อัตโนมัติ — HTTPS สำหรับทุกคน — Renewal ทุก 90 วัน |
| **CA Security** | HSM + Air-Gap + Multi-Person Control + CT — CA ที่ไม่ปลอดภัย = ล้มละลาย (DigiNotar) |

### 11.2 ตัวเลขสำคัญที่ควรจำ

| ตัวเลข | ความหมาย |
|--------|----------|
| **2048** | ขนาด RSA Key ขั้นต่ำที่แนะนำ (บิต) |
| **256** | ขนาด ECC Key ที่แนะนำ (P-256, บิต) |
| **20-30 ปี** | อายุ Root CA Certificate |
| **90 วัน** | อายุสูงสุดของ Let's Encrypt Certificate |
| **27** | จำนวนฟิลด์ใน X.509 v3 Certificate |
| **30-60 วัน** | ระยะเวลาควรต่ออายุก่อนหมดอายุ |
| **2011** | ปีที่ DigiNotar และ Comodo ถูกโจมตี |

---

## คำถามทบทวน (Review Questions)

1. PKI ประกอบด้วยองค์ประกอบอะไรบ้าง? จงอธิบายบทบาทของ CA, RA, VA, HSM และความสำคัญของ Trust Model (Hierarchical vs Mesh vs Web of Trust)
2. จงอธิบายความแตกต่างระหว่าง X.509 v1, v2, และ v3 — Extension ใดบ้างที่ Critical และจำเป็นสำหรับ TLS Server Certificate?
3. Certificate Chain Building และ Path Validation ตาม RFC 5280 มีกี่ขั้นตอน? อะไรบ้าง? จงอธิบาย
4. เปรียบเทียบข้อดีข้อเสียระหว่าง CRL, Delta CRL, OCSP, OCSP Stapling — แนวทางใดที่แนะนำสำหรับ Web Server ในปัจจุบัน? เพราะเหตุใด?
5. Certificate Transparency (CT) แก้ปัญหาอะไร? กลไกการทำงานของ SCT (Signed Certificate Timestamp) และ Merkle Tree เป็นอย่างไร?
6. จงอธิบายวงจรชีวิตของ Certificate — ตั้งแต่ Key Generation ไปจนถึง Expiration — พร้อมคำสั่ง OpenSSL สำหรับสร้าง CSR
7. DV, OV, และ EV Certificate แตกต่างกันอย่างไร? ACME Protocol และ Let's Encrypt ทำให้ DV Certificate เปลี่ยนแปลงอุตสาหกรรม PKI อย่างไร?
8. วิเคราะห์กรณี DigiNotar (2011) — สาเหตุการถูกโจมตี ผลกระทบ และบทเรียน — ถ้ามี CT ในตอนนั้นจะช่วยได้อย่างไร?
9. PKI ได้รับการนำไปใช้ใน TLS, Code Signing, S/MIME, IoT Identity อย่างไรบ้าง? จงยกตัวอย่างแต่ละประเภท
10. Quantum Computing มีผลกระทบต่อ PKI อย่างไร? มาตรการรับมือ (Post-Quantum Cryptography) มีอะไรบ้าง?

---

## เอกสารอ้างอิง (References)

### มาตรฐานและ RFC
1. IETF RFC 5280. (2008). *Internet X.509 Public Key Infrastructure Certificate and CRL Profile*.
2. IETF RFC 6960. (2013). *X.509 Internet Public Key Infrastructure Online Certificate Status Protocol (OCSP)*.
3. IETF RFC 6962. (2013). *Certificate Transparency*.
4. IETF RFC 8555. (2019). *Automatic Certificate Management Environment (ACME)*.
5. IETF RFC 6066. (2011). *Transport Layer Security (TLS) Extensions: Extension Definitions* (OCSP Stapling).
6. IETF RFC 4210. (2005). *Internet X.509 Public Key Infrastructure Certificate Management Protocol (CMP)*.
7. ITU-T X.509. (2019). *Information Technology — Open Systems Interconnection — The Directory: Public-Key and Attribute Certificate Frameworks*.

### ตำราหลัก
8. Stallings, W. (2022). *Cryptography and Network Security: Principles and Practice* (8th ed.). Pearson.
9. Ferguson, N., Schneier, B., & Kohno, T. (2010). *Cryptography Engineering*. Wiley.

### รายงานและกรณีศึกษา
10. NIST SP 800-32. (2001). *Introduction to Public Key Technology and the Federal PKI Infrastructure*.
11. CA/Browser Forum. (2024). *Baseline Requirements for the Issuance and Management of Publicly-Trusted Certificates*.
12. Fox-IT. (2011). *Black Tulip: Report of the Investigation into the DigiNotar Certificate Authority Breach*.
13. Comodo. (2011). *Comodo Report of Incident on 15-MAR-2011*.
14. Google Security Blog. (2024). *Certificate Transparency in Chrome*.

### แหล่งข้อมูลเพิ่มเติม
15. Let's Encrypt — https://letsencrypt.org/
16. SSL Labs — https://www.ssllabs.com/
17. Certificate Transparency Log — https://crt.sh/
18. OpenSSL Documentation — https://www.openssl.org/docs/
19. NIST Post-Quantum Cryptography — https://csrc.nist.gov/projects/post-quantum-cryptography

---

*เอกสารนี้เป็นส่วนหนึ่งของรายวิชา Network Security | ภาคเรียนที่ 1 ปีการศึกษา 2569*
