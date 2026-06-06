# CH-6: Authentication และ Session Management


---

## วัตถุประสงค์การเรียนรู้

เมื่อจบบทนี้นักศึกษาสามารถ:

1. อธิบายหลักการของ Password-Based Authentication ตามมาตรฐาน NIST SP 800-63B Rev 4 รวมถึงการเลือกใช้ Password Hashing Algorithm (Argon2id, scrypt, bcrypt, PBKDF2) และการป้องกัน Timing Attack ได้อย่างถูกต้อง
2. เปรียบเทียบปัจจัย MFA ทั้งสามประเภทและเลือกใช้ MFA ที่เหมาะสมตามระดับความปลอดภัย (NIST AAL) พร้อมอธิบายเทคนิคการหลบเลี่ยง MFA และแนวทางป้องกัน
3. ออกแบบระบบ Session Management ที่ปลอดภัยตั้งแต่การสร้าง Session ID ด้วย CSPRNG การควบคุมอายุ Session (Idle Timeout และ Absolute Timeout) การตั้งค่า Cookie Security Attributes และการใช้ JWT อย่างถูกต้อง
4. อธิบายความแตกต่างระหว่าง OAuth 2.0, OpenID Connect และ SAML 2.0 พร้อมเลือกใช้ SSO Solution ที่เหมาะสมกับบริบทขององค์กร
5. ระบุเทคนิคการโจมตีที่เกี่ยวข้องกับ Authentication และ Session Management (Credential Stuffing, Session Hijacking, SAML Token Forgery, MFA Fatigue) พร้อมมาตรการป้องกัน
6. แปลงความรู้ด้าน Authentication Security เป็น Security Requirements และ Test Cases ในกระบวนการพัฒนาซอฟต์แวร์

---

## ขอบเขตและข้อกำหนดด้านจริยธรรมของบทนี้

บทนี้ครอบคลุมหลักการออกแบบระบบ Authentication และ Session Management ที่ปลอดภัย เนื้อหามีตัวอย่างโค้ดเพื่อการเรียนรู้และทำความเข้าใจเทคนิคการป้องกันเท่านั้น กิจกรรมปฏิบัติการทั้งหมดต้องทำในสภาพแวดล้อมที่ได้รับอนุญาต เช่น เครื่องของนักศึกษาเอง เซิร์ฟเวอร์ทดลอง หรือบัญชีทดสอบของบริการคลาวด์ที่อาจารย์จัดให้เท่านั้น

**ข้อควรจำ:** ห้ามนำเทคนิคในบทนี้ไปทดสอบกับระบบของบุคคลอื่นโดยไม่ได้รับอนุญาตเป็นลายลักษณ์อักษร เดิมพันของความปลอดภัยด้าน Authentication คือบัญชีผู้ใช้ ข้อมูลส่วนบุคคล และสิทธิ์ในการเข้าถึงระบบ การออกแบบที่ผิดพลาดอาจนำไปสู่การละเมิดข้อมูลครั้งใหญ่

---

## แผนการเรียนรู้สำหรับ 4 ชั่วโมง

| ช่วงเวลา | หัวข้อ | เป้าหมายการเรียนรู้ | กิจกรรมในชั้นเรียน |
|----------|--------|----------------------|----------------------|
| ชั่วโมงที่ 1 | Password-Based Authentication และ MFA | เข้าใจ NIST SP 800-63B, Password Hashing Algorithms, ปัจจัย MFA และ FIDO2/WebAuthn | เปรียบเทียบ Password Hashing Algorithms และจัดอันดับ MFA ตาม CISA |
| ชั่วโมงที่ 2 | Session Management, SSO และ Federated Identity | เข้าใจ Session Lifecycle, JWT, OAuth 2.0 + PKCE, OIDC, SAML 2.0 และการป้องกัน Common SSO Attacks | วิเคราะห์ JWT Claims และ OAuth Flow Diagram |
| ชั่วโมงที่ 3 | Lab 6.1 และ Lab 6.2 | ฝึกเปรียบเทียบ Hashing Algorithms และ Implement Session Management ด้วย JWT | เขียนโค้ด Hash รหัสผ่านและสร้าง JWT Access + Refresh Token |
| ชั่วโมงที่ 4 | Lab 6.3 และ Lab 6.4 | ฝึกจำลอง Brute Force Attack และลอง OAuth 2.0 Flow | Implement Rate Limiting และทดลอง Authorization Code Flow |

---

## เนื้อหา

### 6.1 Password-Based Authentication

ระบบพิสูจน์ตัวตนด้วยรหัสผ่านเป็นวิธีการที่แพร่หลายที่สุด แต่ก็เป็นเป้าหมายหลักของการโจมตีเช่นกัน การออกแบบระบบ Authentication ที่ปลอดภัยต้องเริ่มจากมาตรฐานการจัดการรหัสผ่าน การเก็บรหัสผ่านที่ถูกต้อง และการป้องกันการโจมตีรูปแบบต่างๆ

#### 6.1.1 NIST SP 800-63B — มาตรฐานการจัดการรหัสผ่าน

NIST Special Publication 800-63B Revision 4 (เผยแพร่ครั้งสุดท้าย July 2025) เป็นมาตรฐานหลักที่กำหนดแนวทางการจัดการรหัสผ่านและ Authentication Assurance Levels (AAL) 3 ระดับ ได้แก่ AAL1, AAL2, AAL3

**ข้อกำหนดสำคัญด้าน Memorized Secrets (รหัสผ่าน) จาก NIST SP 800-63B-4:**

| หัวข้อ | ข้อกำหนด |
|--------|----------|
| ความยาวขั้นต่ำ (ผู้ใช้เลือกเอง) | อย่างน้อย 8 ตัวอักษร |
| ความยาวขั้นต่ำ (ระบบสุ่มให้) | อย่างน้อย 6 ตัวอักษร (สามารถเป็นตัวเลขล้วน) |
| ความยาวสูงสุดที่ควรอนุญาต | อย่างน้อย 64 ตัวอักษร |
| การตัดทอน (Truncation) | **ห้ามทำ** — ต้องนำรหัสผ่านทั้งหมดไปแฮช |
| การบังคับความซับซ้อน | **ไม่ควรบังคับ** — ไม่ต้องผสมตัวพิมพ์ใหญ่/เล็ก/ตัวเลข/สัญลักษณ์ |
| การบังคับเปลี่ยนรหัสผ่านตามรอบ | **ไม่ควรบังคับ** — ยกเว้นมีหลักฐานการถูกเจาะ |
| Password Managers | **สนับสนุน** ให้ผู้ใช้ใช้ Password Managers เพื่อสร้างรหัสผ่านที่ยาวและสุ่ม |
| การตรวจสอบรหัสผ่านรั่วไหล | ต้องตรวจสอบกับ Blocklist ของรหัสผ่านที่เคยรั่วไหล |

**ประเด็นสำคัญ:** NIST ฉบับนี้แนะนำให้เลิกใช้แนวปฏิบัติเดิมที่บังคับความซับซ้อนของรหัสผ่านและการเปลี่ยนรหัสผ่านทุก 90 วัน เนื่องจากงานวิจัยพบว่าการปฏิบัติเหล่านี้ไม่ได้เพิ่มความปลอดภัยแต่กลับทำให้ผู้ใช้เลือกรหัสผ่านที่คาดเดาได้ง่ายขึ้น

#### 6.1.2 การเก็บรหัสผ่านที่ปลอดภัย — Password Hashing Algorithms

**หลักการพื้นฐาน:**
- ต้องเก็บรหัสผ่านในรูปแบบ **Hash** เท่านั้น ห้ามเก็บ Plaintext เด็ดขาด
- ห้ามใช้ Hash algorithms ทั่วไป (MD5, SHA-1, SHA-256) โดยตรงเพราะมีความเร็วสูงจึงถูกนำมาใช้ในการแคร็ก
- ต้องใช้ **Password Hashing Functions** ที่ออกแบบมาให้ช้า (Memory-hard / CPU-hard)

**ตารางเปรียบเทียบอัลกอริทึมตาม OWASP Password Storage Cheat Sheet:**

| อัลกอริทึม | ลำดับแนะนำ | การตั้งค่าขั้นต่ำ | ข้อดี/ข้อควรระวัง |
|------------|-----------|-----------------|-------------------|
| **Argon2id** | 1 (ดีที่สุด) | m=19456 (19 MiB), t=2, p=1 | ป้องกันทั้ง Side-channel และ GPU attacks; ชนะเลิศ Password Hashing Competition 2015 |
| **scrypt** | 2 (สำรอง) | N=2^17 (128 MiB), r=8, p=1 | Memory-hard; ใช้เมื่อ Argon2id ไม่พร้อมใช้งาน |
| **bcrypt** | 3 (ระบบเก่า) | Work factor ≥ 10 | นิยมใช้มากที่สุด; มีข้อจำกัด input สูงสุด 72 bytes |
| **PBKDF2** | 4 (FIPS) | 600,000 iterations (HMAC-SHA-256) | NIST แนะนำ; มี FIPS-140 validated implementations |

**ลำดับความปลอดภัย:** Argon2id > scrypt > bcrypt > PBKDF2

**รายละเอียดการตั้งค่า Argon2id (เลือกอย่างใดอย่างหนึ่ง):**
- m=47104 (46 MiB), t=1, p=1
- m=19456 (19 MiB), t=2, p=1
- m=12288 (12 MiB), t=3, p=1
- m=9216 (9 MiB), t=4, p=1
- m=7168 (7 MiB), t=5, p=1

**ตัวอย่างการใช้ Argon2id ใน Python:**

```python
from argon2 import PasswordHasher

ph = PasswordHasher(
    time_cost=2,        # t
    memory_cost=19456,  # m (19 MiB)
    parallelism=1,      # p
    hash_len=32,
    salt_len=16
)

# การแฮชรหัสผ่าน
hash = ph.hash("secure_password_123")

# การตรวจสอบรหัสผ่าน
try:
    ph.verify(hash, "secure_password_123")
    # รหัสผ่านถูกต้อง
except VerifyMismatchError:
    # รหัสผ่านไม่ถูกต้อง
    pass
```

#### 6.1.3 Salt และ Pepper

**Salt:**
- Salt คือค่าสุ่มที่เพิ่มเข้าไปในรหัสผ่านก่อนแฮช **ไม่ซ้ำกันในแต่ละผู้ใช้**
- ป้องกันการโจมตีแบบ **Rainbow Table** และทำให้รหัสผ่านที่เหมือนกันได้ค่าแฮชที่ต่างกัน
- อัลกอริทึมสมัยใหม่ (Argon2id, bcrypt, PBKDF2) จัดการ Salt อัตโนมัติโดยไม่ต้องเขียนโค้ดเพิ่ม
- NIST กำหนดให้ Salt มีความยาวอย่างน้อย **32 บิต**

**Pepper:**
- Pepper คือค่าความลับระดับระบบที่ใช้ร่วมกันทุกบัญชี (ต่างจาก Salt ที่ไม่ซ้ำกัน)
- **เก็บแยกจากฐานข้อมูล** — เช่น ใน Hardware Security Module (HSM), Key Management Service (KMS), หรือ Secret Vault
- ไม่เปิดเผยต่อสาธารณะ — ต่อให้แฮกเกอร์ขโมยฐานข้อมูลไปก็ยังไม่สามารถแคร็กแฮชได้
- ควรมีความยาวอย่างน้อย 32 ตัวอักษร และควรมีกลยุทธ์การหมุนเวียน (Rotation)

**แนวคิดการทำงานของ Salt และ Pepper:**

```text
Hash = PasswordHashingFunction(Password + Salt + Pepper)
```

โดยที่เก็บเฉพาะ Hash และ Salt ในฐานข้อมูล ส่วน Pepper เก็บแยกต่างหากในระบบที่ปลอดภัย

#### 6.1.4 Timing Attack Prevention — Constant-time Comparison

**ปัญหา:** ฟังก์ชันเปรียบเทียบสตริงทั่วไป (เช่น `memcmp()` ใน C, `==` ใน Python, `===` ใน JavaScript) จะ return ทันทีเมื่อเจอตัวอักษรที่ไม่ตรงกัน ทำให้เวลาที่ใช้ในการเปรียบเทียบแตกต่างกันไปตามจำนวนตัวอักษรที่ตรงกัน

**การโจมตี:** แฮกเกอร์สามารถวัดเวลาตอบสนองของเซิร์ฟเวอร์เพื่อเดาทีละตัวอักษร (bit-by-bit) จนได้ค่าความลับทั้งหมด

**การป้องกัน:** ใช้ **Constant-time Comparison** — ฟังก์ชันที่ใช้เวลาเท่ากันเสมอไม่ว่าข้อมูลจะตรงกันกี่ตำแหน่ง:

| ภาษา | ฟังก์ชัน |
|------|----------|
| Python | `secrets.compare_digest(a, b)` |
| Node.js | `crypto.timingSafeEqual(a, b)` |
| PHP | `hash_equals()` |
| Java | `MessageDigest.isEqual()` |

**ตัวอย่างการใช้งานใน Python:**

```python
import secrets

# ไม่ปลอดภัย: timing-dependent comparison
if user_input == stored_hash:
    print("Verified")

# ปลอดภัย: constant-time comparison
if secrets.compare_digest(user_input, stored_hash):
    print("Verified")
```

#### 6.1.5 Passwordless Authentication — WebAuthn, Passkeys

**ภาพรวม:**
- **WebAuthn** (W3C Recommendation) และ **FIDO2** (FIDO Alliance) เป็นมาตรฐาน Passwordless Authentication
- **Passkeys** คือ WebAuthn credentials ที่ sync ข้ามอุปกรณ์ได้ ถูกนำมาใช้โดย Apple, Google, Microsoft
- ใช้ **Public Key Cryptography** — เว็บไซต์เก็บ Public Key ส่วน Private Key อยู่ในอุปกรณ์ผู้ใช้

**สถิติจาก FIDO Alliance State of Passkeys 2026:**
- **5 พันล้าน** Passkeys ถูกใช้งานทั่วโลก
- **90%** ของผู้บริโภคคุ้นเคยกับ Passkeys
- **75%** ได้เปิดใช้ Passkeys แล้วในบางบัญชี
- **68%** ขององค์กรกำลัง deploy, pilot, หรือ rollout Passkeys สำหรับพนักงาน

**Magic Links:**
- ส่งลิงก์ครั้งเดียว (One-time use) ทางอีเมล
- ต้องมี PKCE เพื่อป้องกันการโจมตี
- เสี่ยงต่อ Token Leakage ผ่าน Referrer Header, Email Clients ที่ prefetch URL
- อายุสั้น — แนะนำให้หมดอายุภายใน 10-15 นาที

#### 6.1.6 Credential Stuffing และ Brute Force Protection

**Credential Stuffing:**
- การใช้ Username/Password ที่รั่วไหลจากเว็บอื่นมาไล่ล็อกอินในเว็บเป้าหมาย
- อาวุธ: Automated tools, Combo lists (เช่น Collection #1 ที่มี 2.7 พันล้านคู่)
- ผลกระทบ: การใช้รหัสผ่านซ้ำ (Password Reuse) คือสาเหตุหลัก

**Brute Force:**
- การสุ่มเดารหัสผ่านทีละคู่ (อาจใช้ Dictionary หรือ exhaustive search)
- Online attack — เดาผ่านฟอร์มล็อกอิน
- Offline attack — เดาจาก Hash Database ที่รั่วไหล

**มาตรการป้องกัน (จาก OWASP Authentication Cheat Sheet และ ASVS):**

| มาตรการ | รายละเอียด |
|---------|-----------|
| **Rate Limiting** | จำกัดจำนวนครั้งที่ล็อกอินผิดพลาด — ASVS V2.2.1: ไม่เกิน 100 ครั้งต่อชั่วโมงต่อบัญชี; ใช้ Progressive Delay |
| **Account Lockout** | ล็อกบัญชีชั่วคราว (Soft lockout) เมื่อล็อกอินผิดพลาดหลายครั้ง |
| **CAPTCHA** | ใช้กับฟอร์มล็อกอินที่ต้องใส่รหัสผ่านผิดบ่อย |
| **Breached Password Detection** | ตรวจสอบรหัสผ่านที่ผู้ใช้ตั้งกับฐานข้อมูลรหัสผ่านรั่วไหล (Have I Been Pwned API); ASVS 2.1.7: ต้องตรวจสอบกับ top 3,000+ passwords |
| **MFA** | วิธีที่มีประสิทธิภาพที่สุดในการหยุด Credential Stuffing |

---

### 6.2 Multi-Factor Authentication (MFA)

MFA ใช้ปัจจัยอย่างน้อย 2 ใน 3 ปัจจัยเพื่อยืนยันตัวตน ทำให้การโจมตีเพียงปัจจัยเดียวไม่เพียงพอในการเข้าถึงระบบ

#### 6.2.1 ปัจจัยทั้งสาม

| ปัจจัย | ตัวอย่าง | ความเสี่ยง |
|--------|---------|-----------|
| **Something You Know** (สิ่งที่คุณรู้) | Password, PIN | ถูกขโมยผ่าน Phishing, Keylogger |
| **Something You Have** (สิ่งที่คุณมี) | โทรศัพท์, Hardware Token, Security Key | ถูกขโมย device, SIM swapping |
| **Something You Are** (สิ่งที่คุณเป็น) | ลายนิ้วมือ, Face ID, Iris Scan | ปลอมแปลงได้ทางเทคนิค |

#### 6.2.2 OTP: TOTP vs HOTP

| คุณสมบัติ | TOTP (Time-based) — RFC 6238 | HOTP (HMAC-based) — RFC 4226 |
|-----------|-------------------|-------------------|
| กลไก | ใช้เวลาปัจจุบัน + Secret Key | ใช้ Counter + Secret Key |
| รหัส | เปลี่ยนแปลงทุก 30-60 วินาที | เปลี่ยนแปลงเมื่อถูกขอเท่านั้น |
| อายุสูงสุด | 30 วินาที | ไม่มี (จนกว่าจะถูกใช้) |
| การ Sync | ปัญหาถ้าเวลาไม่ตรง | ปัญหาถ้า Counter ไม่ตรง |

NIST SP 800-63B-4 กำหนดว่า OTP ต้องมีอายุสูงสุด 30 วินาที (TOTP) หรือ 10 นาที (Out-of-band) และ Secret Keys ต้องถูกป้องกันด้วย HSM หรือวิธีการที่เทียบเท่า

#### 6.2.3 FIDO2 / WebAuthn Standard

**FIDO2** = WebAuthn (W3C) + CTAP (Client to Authenticator Protocol, FIDO Alliance)

**สถาปัตยกรรม:**
1. **WebAuthn API** — ทำงานใน Browser สำหรับ Register และ Authenticate
2. **CTAP** — สื่อสารระหว่าง Browser กับ Authenticator (Security Key, Phone, etc.)
3. **Authenticator** — สร้าง Key Pair; Private Key ไม่เคยออกจากอุปกรณ์

**ข้อดีด้านความปลอดภัย:**
- **Phishing-resistant**: ผูกกับ Origin (domain) — ถ้าเป็นเว็บปลอม WebAuthn จะไม่ยอมส่ง credential
- **No shared secrets**: ใช้ Public Key Cryptography — ไม่มีรหัสผ่านให้ขโมย
- **Device-bound** (สำหรับ hardware keys) หรือ **Synced** (ผ่าน cloud services)

**CISA จัดอันดับ MFA จากปลอดภัยที่สุดไปน้อยที่สุด:**

| อันดับ | วิธีการ MFA | คำอธิบาย |
|:-----:|------------|----------|
| 1 | Security Key (FIDO2) | ปลอดภัยที่สุด กัน Phishing |
| 2 | Authenticator App + Number Matching | ผู้ใช้ป้อนตัวเลขตรงกับหน้าจอ |
| 3 | Authenticator App + OTP | รหัส OTP หมุนทุก 30 วินาที |
| 4 | Biometrics | ลายนิ้วมือ ใบหน้า |
| 5 | SMS / Email OTP | อ่อนแอที่สุด เสี่ยง SIM Swapping |

#### 6.2.4 Adaptive / Risk-based Authentication

Adaptive Authentication (หรือ Risk-based Authentication) เป็นระบบที่ปรับระดับการยืนยันตัวตนตามปัจจัยเสี่ยงต่างๆ:

- **Location**: พิกัดทางภูมิศาสตร์, IP Address, ประเทศ
- **Device**: อุปกรณ์ที่เคยรู้จักหรือใหม่
- **Behavior**: รูปแบบการใช้งาน, เวลาที่ล็อกอิน
- **Network**: VPN, Tor, Network anonymizer
- **User Profile**: ระดับสิทธิ์, ประวัติกิจกรรม

**ตัวอย่างการทำงาน:**
- ล็อกอินจากบ้าน (อุปกรณ์เดิม, IP เดิม) → ผ่านโดยไม่ต้อง MFA
- ล็อกอินจากประเทศอื่น (อุปกรณ์ใหม่) → ขอ MFA
- ล็อกอิน + เปลี่ยนข้อมูลสำคัญ → ขอยืนยันตัวตนอีกครั้ง (Step-up Authentication)

#### 6.2.5 MFA Bypass Techniques และการป้องกัน

| เทคนิคโจมตี | คำอธิบาย | การป้องกัน |
|-------------|----------|-----------|
| **MFA Fatigue / Bombing** | ส่ง Push Notification รัวๆ ให้เหยื่อกดยอมรับ | Number Matching, FIDO2 |
| **Phishing** | หลอกให้กรอกรหัสผ่าน + OTP ในหน้าเว็บปลอม | FIDO2/WebAuthn (Phishing-resistant) |
| **SIM Swapping** | ยึดเบอร์โทรศัพท์เหยื่อเพื่อรับ SMS OTP | หลีกเลี่ยง SMS; ใช้ Hardware Token |
| **Man-in-the-Middle** | ดักจับ Traffic ระหว่างผู้ใช้กับเซิร์ฟเวอร์ | TLS, FIDO2, Certificate Pinning |
| **Session Hijacking** | ขโมย Session Token หลัง MFA ผ่านแล้ว | Session Binding (IP, Device Fingerprint) |
| **SAML Token Forgery** | ปลอม SAML Assertion เพื่อเลี่ยง MFA | Validate Signature, Certificate Pinning |
| **Social Engineering** | หลอก Help Desk ให้รีเซ็ต MFA | Identity Verification Process |

#### 6.2.6 การเลือก MFA ตาม NIST AAL

| AAL Level | MFA Requirements | ตัวอย่าง |
|-----------|-----------------|----------|
| **AAL1** | Single-factor หรือ MFA (optional) | Password อย่างเดียว |
| **AAL2** | MFA บังคับ (อย่างน้อย 2 ปัจจัย) | Password + TOTP, Password + Push |
| **AAL3** | MFA + Phishing-resistant | Password + FIDO2 Key, หรือ FIDO2 อย่างเดียว |

**คำแนะนำของ CISA:**
- **Phishing-resistant MFA (FIDO2/Passkeys)** — Gold standard — ควรเป็นเป้าหมายสูงสุด
- **Number Matching** — ทางเลือกระหว่างทางที่ดีกว่า Push Notification ธรรมดา
- **SMS/Email OTP** — ใช้เท่าที่จำเป็น เพราะเสี่ยง SIM Swapping และ Phishing
- **Any MFA is better than no MFA** — เริ่มจากอะไรก็ได้ก่อน แล้วค่อยยกระดับ

---

### 6.3 Session Management ที่ปลอดภัย

Session Management เป็นกลไกที่ทำให้เซิร์ฟเวอร์รู้ว่าคำขอที่เข้ามาเป็นของผู้ใช้คนใด การออกแบบที่ไม่ปลอดภัยอาจนำไปสู่การปลอมแปลงหรือขโมย Session

#### 6.3.1 Session ID Generation

**ข้อกำหนดตาม OWASP Session Management Cheat Sheet และ ASVS V3:**

**Entropy (การสุ่ม):**
- Session ID ต้องมี **อย่างน้อย 64 bits** ของ Entropy
- ใน Hexadecimal: ต้องมีความยาวอย่างน้อย 16 ตัวอักษร (16 chars × 4 bits = 64 bits)
- ทางปฏิบัติแนะนำ 128-256 bits (32-64 hex chars)

**CSPRNG (Cryptographically Secure Pseudorandom Number Generator):**
- ต้องใช้ฟังก์ชันสุ่มที่ปลอดภัย เช่น:

| ภาษา | ฟังก์ชันที่แนะนำ | ห้ามใช้ |
|------|-----------------|--------|
| Python | `secrets.token_hex(32)`, `os.urandom(32)` | `random.random()`, `time.time()` |
| Node.js | `crypto.randomBytes(32).toString('hex')` | `Math.random()`, `Date.now()` |
| Java | `java.security.SecureRandom` | `java.util.Random`, `System.currentTimeMillis()` |

**การคำนวณเวลา Brute Force:**
- ด้วย 64-bit entropy และ 1,000 guessing ต่อวินาที: ประมาณ **584 ล้านปี** ก่อนจะถูกสุ่มเจอ

#### 6.3.2 Session Lifecycle

**Creation:**
- Session ID ถูกสร้างเมื่อผู้ใช้เริ่มต้นเชื่อมต่อ (ก่อนล็อกอิน)
- **ต้องสร้าง Session ID ใหม่** ทุกครั้งที่ล็อกอินสำเร็จ (ป้องกัน Session Fixation)
- ASVS 3.2.1: Verify generates new session token on authentication

**Maintenance:**
- Session ถูกเก็บรักษาไว้ตลอดช่วงการใช้งาน
- ต้องป้องกันไม่ให้ Session ID รั่วไหล (ผ่าน Secure, HttpOnly cookies)
- ASVS 3.2.3: Only store in secure methods (secured cookies or HTML5 session storage)

**Termination:**
- **Idle Timeout**: หมดอายุเมื่อไม่มีการใช้งาน (แนะนำ 15-30 นาที สำหรับ L2-L3)
- **Absolute Timeout**: หมดอายุตามเวลาสูงสุดนับจากเริ่ม (30 วันสำหรับ L1)
- **Session Invalidation**: เมื่อ Logout ต้องทำลาย Session ทั้งฝั่งเซิร์ฟเวอร์และลบ Cookie
- ASVS 3.3.1: Logout และ Expiration ต้อง invalidate session token

**ตาราง Session Timeout ตาม ASVS:**

| ASVS Level | Idle Timeout | Max Timeout |
|-----------|--------------|-------------|
| L1 | 30 วัน | 30 วัน |
| L2 | 30 นาที (หรือ 12 ชั่วโมง active) | 12 ชั่วโมง + 2FA |
| L3 | 15 นาที | 12 ชั่วโมง + 2FA |

#### 6.3.3 Cookie Security Attributes

| Attribute | ค่าแนะนำ | หน้าที่ |
|-----------|---------|--------|
| **Secure** | `true` | ส่ง cookie ผ่าน HTTPS เท่านั้น ป้องกัน MitM |
| **HttpOnly** | `true` | ป้องกัน JavaScript (XSS) อ่านค่า cookie |
| **SameSite** | `Lax` หรือ `Strict` | ป้องกัน CSRF — ไม่ส่ง cookie กับ cross-site request |
| **Path** | `/` | cookie ใช้ได้ทุก path (หรือจำกัดให้แคบลง) |
| **Domain** | ไม่ระบุ | cookie ผูกกับ host ที่ตั้งค่าเท่านั้น |
| **Max-Age / Expires** | กำหนดอายุ | ควรสั้นที่สุดเท่าที่จำเป็น |
| **Prefix `__Host-`** | ใช้เมื่อเป็นไปได้ | บังคับ Secure + Path=/ + ไม่มี Domain |

**การตั้งค่าที่ปลอดภัยที่สุด:**

```http
Set-Cookie: __Host-SID=<session_id>; path=/; Secure; HttpOnly; SameSite=Strict
```

#### 6.3.4 Session Fixation และ Session Hijacking

**Session Fixation:**
- ผู้โจมตีหลอกให้เหยื่อใช้ Session ID ที่แฮกเกอร์รู้ค่า
- **ป้องกัน**: สร้าง Session ID ใหม่ทุกครั้งหลังล็อกอินสำเร็จ

**Session Hijacking:**
- ผู้โจมตีขโมย Session Token (ผ่าน Sniffing, XSS, HAR file leak)
- **ป้องกัน**: Secure + HttpOnly cookies, HTTPS ตลอด session, Session Binding (ผูกกับ IP/Device)

#### 6.3.5 Token-based Authentication — JWT

**JWT (JSON Web Token) — RFC 7519:**

JWT ประกอบด้วยสามส่วน: Header.Payload.Signature

**Signing Algorithms:**

| Algorithm | ประเภท | ข้อดี | ข้อเสีย |
|-----------|--------|------|---------|
| **RS256** | Asymmetric (RSA) | รองรับกว้าง, มี JWK Set | Token ใหญ่กว่า |
| **ES256** | Asymmetric (ECDSA P-256) | Token เล็ก, Sign/Verify เร็ว | ECDSA support ต้องตรง |
| **HS256** | Symmetric (HMAC) | คำนวณเร็ว | ต้องแชร์ Secret ทุก service |

**คำแนะนำ:**
- **Microservices / Multiple services**: RS256 หรือ ES256 (Asymmetric)
- **Single service**: HS256 ได้ (แต่ระวัง Secret leak)
- **ห้ามใช้**: `alg: "none"`, Algorithm Confusion (accept HS256 on RS256 verifier)

**JWT Claims ที่ต้องตรวจสอบทุกครั้ง:**

| Claim | ชื่อเต็ม | หน้าที่ |
|-------|---------|--------|
| `exp` | Expiration Time | เวลาหมดอายุ |
| `nbf` | Not Before | เวลาที่เริ่มใช้ได้ |
| `iss` | Issuer | ผู้ออก Token |
| `aud` | Audience | ผู้รับ Token |
| `jti` | JWT ID | ใช้สำหรับ Revocation |

**ตัวอย่าง JWT Payload:**

```json
{
  "sub": "user_12345",
  "iss": "https://auth.example.com",
  "aud": "https://api.example.com",
  "exp": 1712345678,
  "iat": 1712344678,
  "nbf": 1712344678,
  "jti": "550e8400-e29b-41d4-a716-446655440000",
  "roles": ["user", "admin"]
}
```

**Access Token vs Refresh Token:**

| Token Type | อายุ | Storage | Revocable |
|------------|-----|---------|-----------|
| Access Token | 5-15 นาที | Memory / HttpOnly Cookie | ไม่ (stateless) |
| Refresh Token | 7-30 วัน | HttpOnly Cookie / Server DB | ใช่ (ลบจาก DB) |

**Refresh Token Rotation:**
- ทุกครั้งที่ใช้ Refresh Token — ออก Token ใหม่ และ Invalid ตัวเก่า
- ถ้าเจอการใช้ Refresh Token ตัวเก่าซ้ำ — ถือว่ามีการขโมย — Revoke ทั้ง Family
- "Token family" tracking — reuse detection

**Token Revocation Strategies:**

| วิธี | รายละเอียด |
|------|-----------|
| **Short expiry + Refresh token** (แนะนำ) | Access token หมดอายุเร็ว, Revoke ผ่าน Refresh token |
| **Token blocklist** | Redis list ของ `jti` + TTL |
| **Token versioning** | `tokenVersion` ใน claims, ตรวจสอบกับ DB |

---

### 6.4 Single Sign-On (SSO) และ Federated Identity

SSO ช่วยให้ผู้ใช้ล็อกอินครั้งเดียวและเข้าถึงหลายระบบได้ แต่ก็เพิ่มความซับซ้อนและพื้นผิวการโจมตี

#### 6.4.1 OAuth 2.0 Authorization Framework

**RFC 6749 — OAuth 2.0 และ RFC 9700 — Best Current Practice (January 2025):**

**Authorization Code Flow + PKCE (Recommended Flow):**

```text
Client -> Authorization Server: Authorization Request (code_challenge, state)
User -> Authorization Server: Authenticate + Consent
Authorization Server -> Client: Authorization Code
Client -> Token Endpoint: Code + code_verifier
Token Endpoint -> Client: Access Token (+ Refresh Token)
```

**PKCE (Proof Key for Code Exchange) — RFC 7636:**
- Client สร้าง `code_verifier` (random, ≥ 256 bits)
- ส่ง `code_challenge = SHA256(code_verifier)` ใน Authorization Request
- เมื่อขอ Token ส่ง `code_verifier` ไปตรวจสอบ
- **S256 method** แนะนำ (ไม่ใช่ plain)
- ป้องกัน: Authorization Code Interception Attack, CSRF

**การเปลี่ยนแปลงสำคัญใน OAuth 2.1:**
- **ยกเลิก**: Implicit Grant, Resource Owner Password Credentials Grant
- **บังคับ**: PKCE สำหรับทุก client types
- **แนะนำ**: sender-constrained access tokens (DPoP — RFC 9449, mTLS — RFC 8705)
- **Authorization code lifetime**: ไม่เกิน 10 นาที
- **Redirect URI matching**: ต้อง exact match (string-based)

#### 6.4.2 OpenID Connect (OIDC)

OIDC = OAuth 2.0 + Authentication Layer

**ID Token:**
- JWT format
- Contains claims: `sub`, `iss`, `aud`, `exp`, `iat`, `nonce`
- ใช้ยืนยันตัวตนผู้ใช้ (Identity)
- **อายุ**: 5-60 นาที (ไม่ควรยาว — ใช้ครั้งเดียว)

**UserInfo Endpoint:**
- ใช้ Access Token เพื่อขอข้อมูลผู้ใช้เพิ่มเติม
- Returns claims ตาม scope ที่ได้รับอนุญาต (`openid`, `profile`, `email`, etc.)

**Nonce Parameter:**
- สร้างค่าสุ่ม nonce ใน request — ID Token ต้องมี nonce เดียวกัน
- ป้องกัน Replay Attack

#### 6.4.3 SAML 2.0

SAML (Security Assertion Markup Language) 2.0 — มาตรฐาน Federated Identity แบบ XML-based

**Components:**
- **Identity Provider (IdP)**: ฝ่ายยืนยันตัวตน
- **Service Provider (SP)**: ฝ่ายให้บริการ
- **Assertion**: ข้อมูลยืนยันตัวตน (Authentication + Attribute Statements)

**Common Vulnerabilities (ตาม OWASP SAML Security Cheat Sheet):**

| ช่องโหว่ | คำอธิบาย |
|----------|----------|
| **XML Signature Wrapping** | ปลอมแปลง Assertion โดยใช้ช่องโหว่การตรวจสอบ XML Signature |
| **Golden SAML Attack** | ขโมย Certificate เพื่อปลอม SAML Token จากนั้น impersonate ผู้ใช้ใดก็ได้ |
| **Token Replay** | นำ Assertion เดิมมาใช้ซ้ำในเวลาต่อมา |
| **Redirect URI Manipulation** | เปลี่ยน Destination Endpoint เพื่อขโมย Assertion |

**การป้องกัน:**
- ตรวจสอบ XML Signature อย่างเคร่งครัด
- ใช้ Unique ID และ Timestamp บน Assertion
- Validate Destination / Audience
- ตรวจสอบ Response ไม่ใช่แค่ Request
- **SAML != OAuth** — SAML สำหรับ Authentication, OAuth สำหรับ Authorization

#### 6.4.4 การป้องกัน Common Attacks on SSO

| การโจมตี | คำอธิบาย | การป้องกัน |
|-----------|----------|-----------|
| **CSRF** (Cross-Site Request Forgery) | หลอกเบราว์เซอร์ให้ส่ง Request ไปยัง Authorization Server | `state` parameter (OAuth), `nonce` (OIDC), PKCE, SameSite cookie |
| **Redirect URI Manipulation** | เปลี่ยน redirect_uri เพื่อขโมย Authorization Code | Strict URI validation (OAuth 2.1 กำหนด exact match) |
| **Token Theft** | ขโมย Access Token จาก URL fragment, logs, HAR files | Sender-constrained tokens (DPoP, mTLS), short expiry |
| **Mix-Up Attacks** | หลอกให้ client ส่ง token ไปยัง authorization server ผิด | ตรวจสอบ `iss` claim, client-side issuer verification |
| **PKCE Downgrade** | ลด method จาก S256 เป็น plain | Authorization Server ต้อง enforce S256 |
| **Authorization Code Injection** | ส่ง Authorization Code ที่ขโมยมาเพื่อขอ Token | PKCE (code_verifier mismatch) |

#### 6.4.5 การเลือก SSO Solution

| คุณสมบัติ | Keycloak | Auth0 | Okta | Microsoft Entra ID |
|-----------|----------|-------|------|-------------------|
| **License** | Open Source (Apache 2.0) | Proprietary | Proprietary | Proprietary |
| **Hosting** | Self-hosted / Cloud | Cloud (SaaS) | Cloud (SaaS) | Cloud |
| **Protocols** | OIDC, OAuth2, SAML | OIDC, OAuth2, SAML | OIDC, OAuth2, SAML | OIDC, OAuth2, SAML |
| **MFA** | ✓ (built-in) | ✓ | ✓ | ✓ |
| **LDAP/AD** | ✓ | Limited | ✓ | ✓ (native) |
| **Developer UX** | High | Very High | High | Medium |
| **Data Sovereignty** | Full control | Limited | Limited | Region-dependent |
| **Cost (10K users)** | ~$2,400/yr (infra) | ~$50,000+/yr | ~$96,000-$120,000/yr | ~$5-10/user/month |

**ข้อแนะนำ:**
- **Enterprise ใหญ่** (Microsoft ecosystem): Entra ID
- **Enterprise ใหญ่** (multi-platform): Okta
- **Startup / Developer-first**: Auth0
- **ควบคุมข้อมูลเอง / งบน้อย / Open Source**: Keycloak
- Keycloak ถูกกว่า Auth0 70-90% และถูกกว่า Okta 92%+ ใน scale ใหญ่

---

### 6.5 กรณีศึกษาและเหตุการณ์จริง

#### 6.5.1 SolarWinds Supply Chain Attack (2020)

**รายละเอียด:**
- Nation-state APT (UNC2452) แทรกมัลแวร์ SUNBURST เข้าไปใน SolarWinds Orion (ซอฟต์แวร์ monitoring)
- มีผลถึง 18,000 องค์กร (รวมถึงหน่วยงานรัฐบาลสหรัฐ)
- ค้นพบโดย FireEye (Mandiant) ธันวาคม 2020

**เทคนิคที่เกี่ยวข้องกับ Authentication:**
1. **SAML Token Forgery (T1606.002)**: ผู้โจมตีขโมย SAML signing certificate จาก ADFS เพื่อปลอม SAML tokens
2. **ใช้ SAML tokens ปลอม impersonate users**: เลี่ยง MFA ได้ทั้งหมด
3. **Token Theft — OAuth Access Token ขโมย**: ขโมย OAuth tokens ของ applications
4. **Golden SAML Attack**: สร้าง SAML Assertion ปลอมเพื่อ impersonate users
5. **Web Session Cookie Theft (T1550.004)**: ขโมย duo-sid cookie เพื่อเลี่ยง MFA บน OWA

**บทเรียน:**
- Supply chain attack สามารถเลี่ยง MFA ได้ถ้าแฮกเกอร์มี SAML signing keys
- ต้องป้องกันและ monitor การใช้ SAML signing certificates
- CISA เผยแพร่รายงาน AA20-352A เป็นแนวทางตรวจจับ

#### 6.5.2 Okta Security Incidents

**เหตุการณ์ที่ 1: LAPSUS$ (January-March 2022)**
- แฮกเกอร์ LAPSUS$ ใช้ Social Engineering โจมตีพนักงานของ Sitel (third-party support provider ของ Okta)
- เข้าถึง laptop ของ support engineer เป็นเวลา 5 วัน
- สามารถรีเซ็ตรหัสผ่านและ MFA ของผู้ใช้ (แต่ดาวน์โหลด customer DB ไม่ได้)
- Okta ยุติ session และระงับบัญชีภายใน 30 นาทีจากที่มีการตรวจจับ

**เหตุการณ์ที่ 2: Support System Breach (September-October 2023)**
- พนักงาน Okta ล็อกอิน Google Profile ส่วนตัวบน laptop บริษัท — เก็บ credentials ของ Service Account ไว้
- แฮกเกอร์เข้าถึง Service Account — ดาวน์โหลด HAR files ของลูกค้า 134 ราย
- HAR files มี Session Tokens — **Session Hijacking** กับ 5 ลูกค้า
- การตรวจจับ: BeyondTrust แจ้ง suspicious IP — Okta ระบุและปิดได้ใน 2 สัปดาห์

**Remediation (2023):**
- ปิดใช้งาน Service Account
- บล็อกการใช้ Personal Google Profile บน Chrome Enterprise
- **Network Location Binding** — Session token ผูกกับตำแหน่งเครือข่าย IP

#### 6.5.3 Password Database Breaches

**RockYou! (2009):**
- 32 ล้าน passwords ถูกขโมยจากบริษัทเกมโซเชียล
- เก็บรหัสผ่านใน **Plaintext** — ไม่มีการแฮช
- RockYou.txt กลายเป็น dictionary file มาตรฐานสำหรับการโจมตี

**LinkedIn (2012):**
- 6.5 ล้าน SHA-1 hashes ถูกขโมย
- SHA-1 ไม่เหมาะสมสำหรับ password hashing (เร็วเกินไป)
- การศึกษาของ Qualys: 1.4 ล้าน hashes (22%) ถูกถอดรหัสภายในไม่กี่ชั่วโมง
- แสดง Pattern การตั้งรหัสผ่านที่คาดเดาได้ (เช่น `lsw4linkedin`)

**Collection #1 (2019):**
- 773 ล้าน unique emails, 21 ล้าน unique passwords, 2.7 พันล้าน email/password pairs
- 87 GB ข้อมูลจาก 12,000 files จาก 2,000+ previous breaches
- พบโดย Troy Hunt (Have I Been Pwned)
- **ภัยคุกคามหลัก**: Credential Stuffing — นำ combo lists ไปลองล็อกอินเว็บอื่น
- Collections #2-5: อีก 845 GB, 25 พันล้าน records

#### 6.5.4 Apple — Sign in with Apple และ Hide My Email

**Sign in with Apple (SIWA):**
- เปิดตัว WWDC 2019 — เป็น OAuth 2.0 / OIDC based SSO
- ข้อกำหนด: iOS/macOS apps ที่ใช้ third-party SSO ต้องมี SIWA ด้วย
- **Hide My Email**: สร้างอีเมลสุ่ม Forward ไปยังอีเมลจริง (Privacy protection)
- Private Key ถูกเก็บใน Secure Enclave (อุปกรณ์ Apple)
- ป้องกัน Cross-Site Tracking

**iCloud Private Relay:**
- บริการ VPN-like สำหรับ iCloud+ subscribers
- สอง-hop architecture: ปกปิดทั้ง IP และ DNS queries
- ใช้ QUIC protocol

#### 6.5.5 MFA Fatigue / MFA Bombing

**เทคนิค:**
- ผู้โจมตีมี credentials ที่ถูกต้อง (จาก Phishing หรือ Data breach)
- ส่ง Push Notification ซ้ำๆ ไปยังอุปกรณ์ของเหยื่อ (จำนวนมาก — เช่น 10-100 ครั้ง)
- เหยื่อรำคาญหรือเผลอกด "Approve" — ผู้โจมตีเข้าสู่ระบบได้

**ตัวอย่างในโลกจริง:**
- **Uber Breach (2022)**: แฮกเกอร์ใช้ MFA Fatigue จนเหยื่อยอมรับ — เข้าไปใน AWS และ Slack
- **Microsoft** รายงานว่า MFA bombing เป็นเทคนิคที่เพิ่มขึ้นต่อเนื่อง

**การป้องกัน (ตาม CISA และ Microsoft):**
1. **Number Matching**: ผู้ใช้ต้องป้อนตัวเลขบนหน้าจอล็อกอินใน Push Notification
2. **Phishing-resistant MFA (FIDO2/Passkeys)**: ไม่มีรหัสให้ขโมย
3. **Location/Device Binding**: จำกัดเฉพาะอุปกรณ์ที่รู้จัก
4. **Rate Limiting**: จำกัดจำนวน Push Notification
5. **User Education**: สอนให้ไม่กด Accept โดยไม่ตรวจสอบ

---

### 6.6 สรุปและแนวทางปฏิบัติ

#### 6.6.1 OWASP ASVS — Application Security Verification Standard

**ASVS Version 4.0.3 — V2: Authentication Verification Requirements:**

| ข้อ | รายการ | L1 | L2 | L3 |
|-----|--------|:--:|:--:|:--:|
| 2.1.1 | รหัสผ่านอย่างน้อย 12 ตัวอักษร | ✓ | ✓ | ✓ |
| 2.1.2 | รองรับรหัสผ่านอย่างน้อย 64 ตัวอักษร | ✓ | ✓ | ✓ |
| 2.1.5 | เปลี่ยนรหัสผ่านต้องกรอกรหัสเก่าก่อน | ✓ | ✓ | ✓ |
| 2.1.7 | ตรวจสอบ breached passwords ในการสมัคร | ✓ | ✓ | ✓ |
| 2.1.10 | ไม่บังคับเปลี่ยนรหัสผ่านตามรอบเวลา | ✓ | ✓ | ✓ |
| 2.1.11 | อนุญาตให้ใช้ Password Managers | ✓ | ✓ | ✓ |
| 2.2.1 | Anti-automation (Rate limiting, CAPTCHA) | ✓ | ✓ | ✓ |
| 2.2.1 | ไม่เกิน 100 ครั้งผิดต่อชั่วโมงต่อบัญชี | ✓ | ✓ | ✓ |
| 2.5.x | Secure password recovery | ✓ | ✓ | ✓ |
| 2.7.x | MFA บังคับสำหรับ L2/L3 | | ✓ | ✓ |
| 2.8.x | FIDO2/WebAuthn สำหรับ L3 | | | ✓ |

**ASVS Version 4.0.3 — V3: Session Management Verification Requirements:**

| ข้อ | รายการ | L1 | L2 | L3 |
|-----|--------|:--:|:--:|:--:|
| 3.2.1 | สร้าง Session ID ใหม่เมื่อล็อกอิน | ✓ | ✓ | ✓ |
| 3.2.2 | Session ID มี entropy ≥ 64 bits | ✓ | ✓ | ✓ |
| 3.2.3 | เก็บ Session Token อย่างปลอดภัย | ✓ | ✓ | ✓ |
| 3.2.4 | ใช้ approved cryptographic algorithms | | ✓ | ✓ |
| 3.3.1 | Logout/Expiration — invalidate session | ✓ | ✓ | ✓ |
| 3.3.2 | Session timeout ตามตาราง | ✓ | ✓ | ✓ |
| 3.4.1 | Cookie Secure attribute | ✓ | ✓ | ✓ |
| 3.4.2 | Cookie HttpOnly attribute | ✓ | ✓ | ✓ |
| 3.4.3 | Cookie SameSite attribute | ✓ | ✓ | ✓ |
| 3.4.4 | Cookie `__Host-` prefix | ✓ | ✓ | ✓ |
| 3.5.2 | ใช้ Session tokens แทน static API keys | ✓ | ✓ | ✓ |

#### 6.6.2 OWASP Top 10 2025 — A07 Authentication Failures

OWASP Top 10 2025 ยังคงมี **A07:2025 — Authentication Failures** เป็นหนึ่งในหมวดหมู่

**รายการตรวจสอบสำหรับ A07:**
- อนุญาตให้ใช้ Credential stuffing หรือ Brute force attacks
- ไม่บังคับ MFA (โดยเฉพาะสำหรับ admin accounts)
- ไม่ตรวจสอบรหัสผ่านรั่วไหล (Breached passwords)
- Session ID ถูกเปิดเผยใน URL
- Session ID ไม่ถูก regenerate หลังล็อกอิน
- ไม่มีการตรวจสอบ Password strength ที่เหมาะสม

#### 6.6.3 Microsoft Identity Platform Best Practices

**แนวทางปี 2025-2026:**
1. **Phishing-resistant MFA**: Microsoft ตั้งเป้า 100% ของ user accounts
2. **Conditional Access**: Policy-based access control ตาม risk, device, location
3. **Continuous Access Evaluation (CAE)**: Real-time token validation
4. **Temporary Access Pass (TAP)**: Time-bound credentials สำหรับ onboarding
5. **Token Protection**: Bind tokens to device
6. **Workload Identities**: Secure service accounts, automation accounts

**Passwordless Deployment:**
- Passkeys (FIDO2 Security Keys, Microsoft Authenticator, Windows Hello)
- รองรับ cross-platform — Windows, macOS, iOS, Android
- Number matching สำหรับ Push Notification

#### 6.6.4 NIST SP 800-63B-4 — ประเด็นใหม่

**เอกสารเผยแพร่**: July 2025 (Final), Supersedes SP 800-63B (March 2020)

**ประเด็นใหม่ใน Rev 4:**
1. **Syncable Authenticators**: รองรับ Passkeys ที่ sync ข้ามอุปกรณ์ (Interim guidance April 2024 — normative text)
2. **Integrated syncable authenticators**: อยู่ในมาตรฐานหลักแล้ว
3. **Digital Wallets**: เพิ่มใน Federation Model
4. **Phishing Resistance**: ข้อกำหนดชัดเจนขึ้นสำหรับ AAL3
5. **การปรับข้อกำหนด Memorized Secrets**: ยกเลิก complexity requirements และ periodic change

#### 6.6.5 การแปลงความรู้เป็น Security Requirements และ Test Cases

**ตัวอย่าง Security Requirements สำหรับ Authentication:**

| Requirement ID | Security Requirement | ช่องโหว่ที่เกี่ยวข้อง | Acceptance Criteria |
|----------------|----------------------|------------------------|---------------------|
| SR-AUTH-001 | รหัสผ่านต้องถูกแฮชด้วย Argon2id ก่อนเก็บ | Password Database Breach | code review ไม่พบ plaintext หรือ fast hash (MD5, SHA-1, SHA-256) ใน password column |
| SR-AUTH-002 | ทุก endpoint ล็อกอินต้องมี Rate Limiting | Credential Stuffing / Brute Force | เกิน 100 ครั้งต่อชั่วโมงต้องถูกบล็อกชั่วคราว |
| SR-AUTH-003 | Admin accounts ต้องมี MFA (อย่างน้อย TOTP) | Account Takeover | admin ที่ไม่มี MFA ไม่สามารถล็อกอินได้ |
| SR-SESS-001 | Session ID ต้องสร้างใหม่ทุกครั้งหลังล็อกอินสำเร็จ | Session Fixation | ก่อนและหลังล็อกอินต้องได้ session token ต่างกัน |
| SR-SESS-002 | Cookie ต้องมี Secure, HttpOnly, SameSite=Lax หรือ Strict | Session Hijacking, CSRF | ตรวจสอบ Set-Cookie header ว่ามี attributes ครบ |
| SR-JWT-001 | JWT ต้องตรวจสอบ exp, iss, aud claims และใช้ algorithm ที่ปลอดภัย | JWT Algorithm Confusion | Token ที่มี alg=none หรือผิด algorithm ถูกปฏิเสธ |

**ตัวอย่าง Security Test Cases:**

| Test ID | Test Case | Expected Result | วิธีทดสอบ |
|---------|-----------|-----------------|-----------|
| ST-AUTH-001 | ส่งรหัสผ่านเดิม 101 ครั้งใน 1 ชั่วโมง | ถูกบล็อกหลังจากครั้งที่ 100 | Automation test script |
| ST-AUTH-002 | ล็อกอินด้วยรหัสผ่านที่ถูกต้องหลังถูกบล็อก | ต้องรอจนครบเวลา (ถ้า soft lockout) | Integration test |
| ST-SESS-001 | ตรวจสอบ Session ID ก่อนและหลังล็อกอิน | Session ID ต้องเปลี่ยน | Unit test / Capture cookie |
| ST-SESS-002 | ส่ง Access Token ที่หมดอายุแล้ว | 401 Unauthorized | API test |
| ST-JWT-001 | ปลอมแปลง JWT ด้วย alg=none | 401 Unauthorized | Security test |
| ST-MFA-001 | ส่ง OTP ผิด 3 ครั้งติด | MFA ถูก lockout | Integration test |

---

## Keywords

Authentication, Password Hashing, Argon2id, scrypt, bcrypt, PBKDF2, Salt, Pepper, Timing Attack, Constant-time Comparison, Passwordless, WebAuthn, FIDO2, Passkeys, Multi-Factor Authentication, MFA, TOTP, HOTP, Phishing-resistant, Adaptive Authentication, MFA Fatigue, Session Management, Session ID, CSPRNG, Cookie Security, HttpOnly, SameSite, Session Fixation, Session Hijacking, JWT, Access Token, Refresh Token, Refresh Token Rotation, OAuth 2.0, PKCE, OpenID Connect, OIDC, SAML 2.0, Golden SAML, SSO, Federated Identity, Credential Stuffing, Rate Limiting, NIST SP 800-63B, OWASP ASVS

---

## กิจกรรมปฏิบัติการ

> กิจกรรมทั้งหมดต้องทำในเครื่องของนักศึกษาเองหรือในสภาพแวดล้อมที่ได้รับอนุญาตเท่านั้น ห้ามทดสอบกับระบบจริงของบุคคลอื่นโดยไม่ได้รับอนุญาต

### Lab 6.1: เปรียบเทียบประสิทธิภาพการ Hash รหัสผ่าน

**วัตถุประสงค์:** เข้าใจความแตกต่างด้านประสิทธิภาพและความปลอดภัยระหว่าง Hash Algorithms และผลกระทบต่อการแคร็ก

**เวลาที่ใช้:** 30-45 นาที

**เครื่องมือ:** Python 3, hashcat (optional), Jupyter Notebook หรือ Script

**ขั้นตอน:**

1. ติดตั้ง library ที่จำเป็น:
   ```bash
   pip install argon2-cffi bcrypt passlib
   ```

2. เขียน script เปรียบเทียบเวลา Hash ด้วยอัลกอริทึมต่างๆ:
   ```python
   import time
   import hashlib
   import bcrypt
   from argon2 import PasswordHasher
   
   password = "test_password_123"
   iterations = 100
   
   # MD5 (เร็วมาก — ไม่ปลอดภัย)
   start = time.time()
   for _ in range(iterations):
       hashlib.md5(password.encode()).hexdigest()
   md5_time = (time.time() - start) / iterations
   
   # SHA-256 (เร็ว — ไม่เหมาะกับ password)
   start = time.time()
   for _ in range(iterations):
       hashlib.sha256(password.encode()).hexdigest()
   sha256_time = (time.time() - start) / iterations
   
   # bcrypt (work factor = 10)
   start = time.time()
   for _ in range(iterations):
       bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=10))
   bcrypt_time = (time.time() - start) / iterations
   
   # Argon2id (m=19456, t=2, p=1)
   ph = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)
   start = time.time()
   for _ in range(iterations):
       ph.hash(password)
   argon2_time = (time.time() - start) / iterations
   
   print(f"MD5: {md5_time:.6f} วินาที")
   print(f"SHA-256: {sha256_time:.6f} วินาที")
   print(f"bcrypt (10): {bcrypt_time:.6f} วินาที")
   print(f"Argon2id: {argon2_time:.6f} วินาที")
   ```

3. บันทึกเวลาและคำนวณว่าถ้า attacker มี GPU ที่เดา MD5 ได้ 10,000 ล้านครั้ง/วินาที จะใช้เวลาเดา Argon2id ได้กี่ครั้ง/วินาที

4. (Optional) ทดลอง crack hash ด้วย hashcat หรือ John the Ripper

**สิ่งที่ต้องส่ง:**
1. ตารางเวลา Hash ของแต่ละอัลกอริทึม
2. คำอธิบายว่าเหตุใด MD5 และ SHA-256 จึงไม่เหมาะสมสำหรับ password hashing
3. การคำนวณความสัมพันธ์ระหว่างความช้าของ Hash Algorithm กับความปลอดภัย

---

### Lab 6.2: Implement Session Management ด้วย JWT

**วัตถุประสงค์:** สร้างระบบ Authentication ด้วย JWT รวมถึง Access Token, Refresh Token และ Cookie Security ที่ถูกต้อง

**เวลาที่ใช้:** 45-60 นาที

**เครื่องมือ:** Node.js + Express หรือ Python + Flask

**ตัวอย่าง Node.js:**

```javascript
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// สร้าง Access Token (อายุ 15 นาที)
function generateAccessToken(userId, roles) {
    return jwt.sign(
        { 
            sub: userId,
            roles: roles,
            jti: crypto.randomUUID(),
            iss: 'https://api.example.com',
            aud: 'https://app.example.com'
        },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: '15m' }
    );
}

// สร้าง Refresh Token (อายุ 7 วัน)
function generateRefreshToken(userId) {
    return jwt.sign(
        { 
            sub: userId,
            jti: crypto.randomUUID(),
            type: 'refresh'
        },
        process.env.REFRESH_TOKEN_SECRET,
        { expiresIn: '7d' }
    );
}

// ตรวจสอบ JWT Middleware
function authenticateToken(req, res, next) {
    const token = req.cookies.access_token;
    if (!token) return res.sendStatus(401);
    
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, 
        { issuer: 'https://api.example.com', audience: 'https://app.example.com' },
        (err, user) => {
            if (err) return res.sendStatus(403);
            req.user = user;
            next();
        }
    );
}
```

**ขั้นตอน:**
1. สร้าง Express/Fastify หรือ Flask server พร้อม endpoint `/login`
2. เมื่อล็อกอินสำเร็จ ให้สร้าง Access Token และ Refresh Token
3. ตั้งค่า Cookie ด้วย `Secure`, `HttpOnly`, `SameSite=Strict`
4. สร้าง middleware สำหรับตรวจสอบ JWT
5. สร้าง endpoint `/refresh` สำหรับ Refresh Token Rotation
6. สร้าง endpoint `/logout` สำหรับทำลาย Refresh Token
7. ทดสอบด้วย curl หรือ Postman

**สิ่งที่ต้องส่ง:**
1. โค้ด JWT Implementation ที่สมบูรณ์
2. ตัวอย่าง Cookie Header ที่มีการตั้งค่า Security Attributes
3. คำอธิบายว่าทำไมต้องแยก Access Token และ Refresh Token
4. แผนภาพ Flow การทำงานของ Refresh Token Rotation

---

### Lab 6.3: จำลอง Brute Force Attack และ Rate Limiting

**วัตถุประสงค์:** เข้าใจการทำงานของ Brute Force Attack และ Implement Rate Limiting + Account Lockout

**เวลาที่ใช้:** 30-45 นาที

**เครื่องมือ:** Python + Flask หรือ Node.js + Express

**ขั้นตอน:**

1. สร้าง login endpoint อย่างง่าย:
   ```python
   from flask import Flask, request, jsonify
   from flask_limiter import Limiter
   from flask_limiter.util import get_remote_address
   
   app = Flask(__name__)
   
   limiter = Limiter(
       get_remote_address,
       app=app,
       default_limits=["100 per hour"]
   )
   
   login_attempts = {}
   
   @app.route('/login', methods=['POST'])
   @limiter.limit("5 per minute")
   def login():
       username = request.json.get('username')
       password = request.json.get('password')
       
       # ตรวจสอบ Account Lockout
       if username in login_attempts and login_attempts[username] >= 5:
           return jsonify({"error": "Account locked. Try again in 15 minutes."}), 429
       
       # ตรวจสอบ credentials
       if username == "admin" and password == "correct_password":
           login_attempts[username] = 0
           return jsonify({"message": "Login successful"})
       
       # เพิ่ม failed attempt
       login_attempts[username] = login_attempts.get(username, 0) + 1
       remaining = 5 - login_attempts[username]
       return jsonify({"error": "Invalid credentials", "attempts_remaining": remaining}), 401
   
   if __name__ == '__main__':
       app.run()
   ```

2. เขียน script brute force แบบง่าย (ใน lab):
   ```python
   import requests
   
   url = "http://localhost:5000/login"
   passwords = ["123456", "password", "admin123", "letmein", "correct_password"]
   
   for pwd in passwords:
       response = requests.post(url, json={"username": "admin", "password": pwd})
       print(f"Trying {pwd}: {response.status_code} - {response.json()}")
   ```

3. ทดสอบว่า Rate Limiting และ Account Lockout ทำงานถูกต้อง
4. ทดลองส่ง request เกิน limit แล้วสังเกต HTTP 429 response

**สิ่งที่ต้องส่ง:**
1. โค้ด Rate Limiting Implementation
2. Log การทดสอบที่แสดงการถูกบล็อกหลังจากพยายามเกิน limit
3. คำอธิบายความแตกต่างระหว่าง Rate Limiting แบบ IP-based vs Account-based
4. ข้อเสนอแนะเกี่ยวกับการแจ้งเตือนผู้ใช้ (error message) ว่าควรหรือไม่ควรบอกจำนวนครั้งที่เหลือ

---

### Lab 6.4: ทดลอง OAuth 2.0 Authorization Code Flow + PKCE

**วัตถุประสงค์:** เข้าใจ Flow การทำงานของ OAuth 2.0 Authorization Code Flow ด้วย PKCE และ OIDC

**เวลาที่ใช้:** 45-60 นาที

**เครื่องมือ:** Keycloak (Docker) หรือ Auth0 free tier

**ขั้นตอน (ใช้ Keycloak):**

1. รัน Keycloak ด้วย Docker:
   ```bash
   docker run -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:latest start-dev
   ```

2. สร้าง Realm, Client และ User ใน Keycloak
3. เขียน Client Application (Python หรือ Node.js) ที่ใช้ Authorization Code Flow + PKCE:
   ```python
   import requests
   import secrets
   import hashlib
   import base64
   
   # สร้าง PKCE parameters
   code_verifier = secrets.token_urlsafe(64)
   code_challenge = base64.urlsafe_b64encode(
       hashlib.sha256(code_verifier.encode()).digest()
   ).rstrip('=')
   
   # Step 1: Authorization Request
   auth_url = f"http://localhost:8080/realms/myrealm/protocol/openid-connect/auth"
   params = {
       "client_id": "myclient",
       "response_type": "code",
       "redirect_uri": "http://localhost:3000/callback",
       "scope": "openid profile email",
       "state": secrets.token_hex(16),
       "code_challenge": code_challenge,
       "code_challenge_method": "S256"
   }
   
   # Step 2: User authenticates (จะ redirect ไปยัง browser)
   # Step 3: Token Request
   token_url = f"http://localhost:8080/realms/myrealm/protocol/openid-connect/token"
   token_params = {
       "grant_type": "authorization_code",
       "code": "authorization_code_from_callback",
       "redirect_uri": "http://localhost:3000/callback",
       "client_id": "myclient",
       "code_verifier": code_verifier
   }
   
   response = requests.post(token_url, data=token_params)
   tokens = response.json()
   # tokens contains: access_token, refresh_token, id_token
   ```

4. ตรวจสอบ JWT Claims ใน Access Token และ ID Token
5. เรียก UserInfo Endpoint ด้วย Access Token
6. ทดลองส่ง request โดยไม่มี PKCE (ควรถูกปฏิเสธ)

**สิ่งที่ต้องส่ง:**
1. แผนภาพ Flow Authorization Code + PKCE
2. ตัวอย่าง JWT Payload ของ Access Token และ ID Token
3. คำอธิบายว่า PKCE ป้องกัน Authorization Code Interception อย่างไร
4. เปรียบเทียบความแตกต่างระหว่าง OAuth 2.0 กับ OIDC จากประสบการณ์ใน Lab

---

## คำถามท้ายบท

1. NIST SP 800-63B Rev 4 เปลี่ยนแปลงข้อกำหนดเกี่ยวกับรหัสผ่านอย่างไรเมื่อเทียบกับแนวปฏิบัติเดิม และเหตุใดจึงเปลี่ยนแปลง
2. จงเปรียบเทียบ Argon2id, scrypt, bcrypt และ PBKDF2 ในด้านความปลอดภัย ประสิทธิภาพ และกรณีการใช้งานที่เหมาะสม
3. Salt และ Pepper แตกต่างกันอย่างไร และแต่ละอย่างป้องกันการโจมตีแบบใด
4. Timing Attack Prevention ทำไมต้องใช้ Constant-time Comparison และมีฟังก์ชันอะไรในภาษา Python, Node.js, PHP และ Java
5. จงอธิบายการทำงานของ WebAuthn / FIDO2 / Passkeys โดยใช้หลักการ Public Key Cryptography
6. MFA สามปัจจัยคืออะไรบ้าง CISA จัดอันดับ MFA จากปลอดภัยที่สุดไปน้อยที่สุดอย่างไร
7. TOTP และ HOTP แตกต่างกันอย่างไร และข้อดีข้อเสียของแต่ละแบบ
8. MFA Fatigue / Bombing คืออะไร และมีแนวทางป้องกันอย่างไรบ้าง
9. Session ID Generation ที่ปลอดภัยต้องมีคุณสมบัติอะไรบ้าง และฟังก์ชันใดที่ไม่ควรใช้
10. Cookie Security Attributes (Secure, HttpOnly, SameSite, `__Host-` prefix) แต่ละตัวป้องกันการโจมตีแบบใด
11. Session Fixation แตกต่างจาก Session Hijacking อย่างไร และมีแนวทางป้องกันแต่ละแบบอย่างไร
12. JWT Access Token และ Refresh Token ต่างกันอย่างไร และ Refresh Token Rotation คืออะไร
13. OAuth 2.0 Authorization Code Flow + PKCE ทำงานอย่างไร และ PKCE ป้องกันการโจมตีแบบใด
14. OAuth 2.1 เปลี่ยนแปลงอะไรจาก OAuth 2.0 บ้าง (Implicit Grant, Password Grant, PKCE)
15. OpenID Connect (OIDC) เพิ่มความสามารถอะไรให้กับ OAuth 2.0 และ ID Token แตกต่างจาก Access Token อย่างไร
16. SAML 2.0 มีความเสี่ยงด้านความปลอดภัยอะไรบ้าง (XML Signature Wrapping, Golden SAML) และป้องกันอย่างไร
17. จากกรณี SolarWinds 2020 จงอธิบายว่า SAML Token Forgery และ Golden SAML Attack ส่งผลกระทบอย่างไร
18. จากกรณี Okta 2023 (Support System Breach) จงอธิบายว่า HAR files ทำให้เกิด Session Hijacking ได้อย่างไร
19. จงออกแบบ Security Requirement สำหรับระบบ Authentication ที่รวม Rate Limiting, MFA และ Secure Session Management
20. จงออกแบบ Test Case สำหรับตรวจสอบว่า JWT Implementation มี Algorithm Confusion Vulnerability หรือไม่

---

## สรุปท้ายบท

Authentication และ Session Management เป็นรากฐานสำคัญของความปลอดภัยซอฟต์แวร์ จุดอ่อนในส่วนนี้มักเป็นเป้าหมายแรกของผู้โจมตีเพราะให้ผลตอบแทนสูง — บัญชีผู้ใช้เดียวอาจนำไปสู่การเข้าถึงระบบทั้งองค์กร

Password-Based Authentication ยังคงเป็นวิธีหลัก แต่ต้องยึดตามมาตรฐาน NIST SP 800-63B-4 ซึ่งเน้นความยาวรหัสผ่านมากกว่าความซับซ้อน ไม่บังคับเปลี่ยนรหัสผ่านตามรอบ และสนับสนุนการใช้งาน Password Managers การเก็บรหัสผ่านต้องใช้ Memory-hard Functions โดย Argon2id เป็นตัวเลือกอันดับหนึ่ง รองลงมาคือ scrypt, bcrypt และ PBKDF2 ตามลำดับ การป้องกัน Credential Stuffing และ Brute Force ต้องใช้ Rate Limiting, Account Lockout, Breached Password Detection และ MFA ร่วมกัน

Multi-Factor Authentication (MFA) ช่วยเพิ่มความปลอดภัยอย่างมาก โดย FIDO2/WebAuthn (Passkeys) เป็นมาตรฐานที่มีความปลอดภัยสูงสุดเพราะ phishing-resistant และไม่มี shared secrets MFA Fatigue/Bombing เป็นภัยคุกคามใหม่ที่ต้องป้องกันด้วย Number Matching และ User Education

Session Management ที่ปลอดภัยต้องใช้ Session ID ที่สุ่มด้วย CSPRNG มี entropy 128-256 bits ควบคุมอายุ Session ด้วย Idle Timeout และ Absolute Timeout และตั้งค่า Cookie Security Attributes อย่างถูกต้อง JWT ช่วยให้ stateless authentication แต่ต้องตรวจสอบ claims อย่างเคร่งครัดและใช้ Asymmetric Signatures สำหรับระบบที่มีหลาย services

SSO และ Federated Identity ลดความยุ่งยากของผู้ใช้แต่เพิ่มความซับซ้อนด้านความปลอดภัย OAuth 2.0 + PKCE เป็นมาตรฐานหลักสำหรับ Authorization ส่วน OpenID Connect เพิ่มการ Authentication Layer และ SAML 2.0 ยังคงใช้ในองค์กรขนาดใหญ่ การป้องกัน Common SSO Attacks ต้องใช้ state, nonce, PKCE, strict redirect URI validation และ check issuer claims

กรณีศึกษา SolarWinds, Okta, LinkedIn และ RockYou! แสดงให้เห็นว่าช่องโหว่ด้าน Authentication สร้างความเสียหายระดับโลกได้ การออกแบบที่ปลอดภัยต้องเริ่มจากมาตรฐาน (NIST SP 800-63B, OWASP ASVS) แปลงเป็น Security Requirements และทดสอบด้วย Test Cases ที่ครอบคลุมทุกขั้นตอนของ Authentication Lifecycle

---

## Verification

- **Research process:** ใช้ websearch และ NotebookLM ตรวจสอบข้อมูลประกอบจากแหล่งอ้างอิงหลักก่อนปรับปรุงเนื้อหา
- **NIST SP 800-63B-4:** ยืนยันการเผยแพร่ July 2025, ข้อกำหนด Memorized Secrets Section 5.1.1, และการเปลี่ยนแปลงจาก Rev 3
- **OWASP Password Storage Cheat Sheet:** ยืนยันลำดับอัลกอริทึม Argon2id > scrypt > bcrypt > PBKDF2 และการตั้งค่าขั้นต่ำ
- **OWASP Session Management Cheat Sheet:** ยืนยันข้อกำหนด Session ID Entropy ≥ 64 bits, Cookie Security Attributes
- **OWASP ASVS v4.0.3:** ยืนยัน V2 Authentication และ V3 Session Management Requirements
- **OWASP Top 10 2025:** ยืนยัน A07 Authentication Failures
- **FIDO Alliance State of Passkeys 2026:** ยืนยันสถิติ 5 พันล้าน Passkeys, 90% ผู้บริโภคคุ้นเคย
- **CISA MFA Guidance:** ยืนยันการจัดอันดับ MFA และการแนะนำ Phishing-resistant MFA
- **RFC 6749, RFC 7636, RFC 9700:** ยืนยัน OAuth 2.0, PKCE, และ Best Current Practice January 2025
- **RFC 7519:** ยืนยัน JWT Specification และ Claims
- **SolarWinds 2020:** ยืนยัน CISA AA20-352A, SAML Token Forgery (T1606.002), Golden SAML Attack
- **Okta Incidents:** ยืนยัน LAPSUS$ March 2022 และ Support System Breach October 2023
- **LinkedIn 2012:** ยืนยัน 6.5M SHA-1 hashes และการศึกษา Qualys
- **Collection #1 2019:** ยืนยัน 773M unique emails, 2.7B pairs, 87GB
- **RockYou! 2009:** ยืนยัน 32M passwords plaintext
- **Uber Breach 2022:** ยืนยัน MFA Fatigue Attack
- **Safety boundary:** Labs ระบุให้ทำในเครื่องของนักศึกษาเองหรือสภาพแวดล้อมที่ได้รับอนุญาตเท่านั้น
- **Corrected after review:** (1) ASVS V2.2.6 → V2.2.1 สำหรับ Rate Limiting (2) เวลา Brute Force 64-bit entropy แก้จาก 585 ปีเป็น 584 ล้านปี (3) แก้ไวยากรณ์ภาษาไทยบรรทัด 68
- **Status:** ตรวจสอบข้อมูลหลักแล้ว ไม่มีรายการที่ตั้งใจปล่อยไว้เป็น [UNVERIFIED]

---

## เอกสารอ้างอิงหลัก

1. NIST SP 800-63B Revision 4 — Digital Identity Guidelines: https://pages.nist.gov/800-63-4/sp-800-63b.html
2. OWASP Password Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
3. OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
4. OWASP Session Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
5. OWASP SAML Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html
6. OWASP ASVS v4.0.3 — V2 Authentication, V3 Session Management: https://owasp.org/www-project-application-security-verification-standard/
7. OWASP Top 10 2025 — A07 Authentication Failures: https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/
8. RFC 6749 — OAuth 2.0 Authorization Framework: https://datatracker.ietf.org/doc/html/rfc6749
9. RFC 7636 — PKCE: https://datatracker.ietf.org/doc/html/rfc7636
10. RFC 9700 — Best Current Practice for OAuth 2.0 Security (January 2025): https://datatracker.ietf.org/doc/html/rfc9700
11. RFC 7519 — JSON Web Token (JWT): https://datatracker.ietf.org/doc/html/rfc7519
12. RFC 6238 — TOTP: Time-Based One-Time Password Algorithm: https://datatracker.ietf.org/doc/html/rfc6238
13. RFC 4226 — HOTP: An HMAC-Based One-Time Password Algorithm: https://datatracker.ietf.org/doc/html/rfc4226
14. CISA — Next Level MFA: FIDO Authentication: https://www.cisa.gov/next-level-mfa-fido-authentication
15. CISA — Supply Chain Compromise Detecting APT Activity (AA20-352A): https://www.cisa.gov/news-events/alerts/2020/12/17/aa20-352a
16. FIDO Alliance — State of Passkeys 2026: https://fidoalliance.org/passkeys/
17. Microsoft — Phishing-resistant MFA: https://www.microsoft.com/en-us/security/blog/2024/04/15/phishing-resistant-mfa-is-critical-to-your-security-posture/
18. MITRE ATT&CK — T1606.002 SAML Token Forgery: https://attack.mitre.org/techniques/T1606/002/
19. MITRE ATT&CK — T1550.004 Web Session Cookie Theft: https://attack.mitre.org/techniques/T1550/004/
20. Okta Security — Support System Root Cause Analysis (November 2023): https://sec.okta.com/harfiles
21. Troy Hunt — Collection #1 Data Breach (2019): https://www.troyhunt.com/the-773-million-record-collection-1-data-reach/
22. OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org/
23. IETF OAuth 2.1 draft: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-15
