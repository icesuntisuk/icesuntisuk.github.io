# CH-8: Cryptography สำหรับนักพัฒนาซอฟต์แวร์


---

## วัตถุประสงค์การเรียนรู้

เมื่อจบบทนี้นักศึกษาสามารถ:

1. เข้าใจแนวคิดพื้นฐานของ Cryptographic Primitives และความแตกต่างระหว่าง encryption, hashing, encoding, และ MAC
2. เลือกใช้ Algorithm และโหมดการทำงานที่เหมาะสมสำหรับแต่ละกรณีการใช้งาน
3. อธิบายความแตกต่างระหว่าง Symmetric, Asymmetric Cryptography, และ Hashing พร้อมยกตัวอย่างการประยุกต์ใช้
4. ใช้ Library Cryptography อย่างถูกต้องตามหลักการ Don't Roll Your Own Crypto
5. จัดการ Key Management เบื้องต้น รวมถึงการสร้าง การจัดเก็บ และการหมุนเวียนคีย์
6. เข้าใจแนวคิด Post-Quantum Cryptography และ Crypto Agility
7. อธิบาย PKI, Digital Certificates, และความสำคัญของ Certificate Chain
8. วิเคราะห์และเลือกใช้มาตรการเข้ารหัสที่เหมาะสมในระบบซอฟต์แวร์จริง

---

## ขอบเขตและข้อกำหนดด้านจริยธรรมของบทนี้

บทนี้ครอบคลุมหลักการ Cryptography ที่นักพัฒนาซอฟต์แวร์ต้องรู้ เนื้อหามีตัวอย่างโค้ดเพื่อการเรียนรู้เท่านั้น การใช้ Cryptography ที่ผิดวิธีอาจนำไปสู่ช่องโหว่ที่ร้ายแรงและการละเมิดข้อมูล การตัดสินใจเลือก Algorithm และการจัดการคีย์ต้องกระทำด้วยความรอบคอบและควรได้รับคำปรึกษาจากผู้เชี่ยวชาญด้านความปลอดภัย

**ข้อควรจำ:** การเข้ารหัสไม่ใช่คำตอบของทุกปัญหา — ต้องเข้าใจว่าจะป้องกันอะไร จากใคร และมีมาตรการอื่นเสริมอย่างไร

---

## แผนการเรียนรู้สำหรับ 5 ชั่วโมง

| ช่วงเวลา | หัวข้อ | เป้าหมายการเรียนรู้ | กิจกรรมในชั้นเรียน |
|----------|--------|----------------------|----------------------|
| ชั่วโมงที่ 1 | พื้นฐาน Cryptography สำหรับนักพัฒนา | เข้าใจ Cryptographic Primitives, Kerckhoffs's Principle, และ Common Mistakes | เปรียบเทียบ encryption vs hashing vs encoding และวิเคราะห์ตัวอย่างโค้ดที่ไม่ปลอดภัย |
| ชั่วโมงที่ 2 | Symmetric และ Asymmetric Encryption | เข้าใจ AES-GCM, ChaCha20-Poly1305, RSA, ECC, Hybrid Encryption, Digital Signatures | เปรียบเทียบ AES-ECB กับ AES-GCM และทดลอง Sign/Verify |
| ชั่วโมงที่ 3 | Hashing, MAC, PKI และ Key Management | เข้าใจ SHA-3, HMAC, X.509, Certificate Chain, Key Lifecycle | วิเคราะห์ TLS Certificate Chain และ Certificates |
| ชั่วโมงที่ 4 | Lab 8.1, 8.2, 8.3 | ฝึกใช้งาน cryptography library, เปรียบเทียบ AES modes, ทดลอง Key Exchange | เขียนโค้ดเข้ารหัส/ถอดรหัสด้วย AES-GCM และ ECDSA Sign/Verify |
| ชั่วโมงที่ 5 | Lab 8.4 และ Post-Quantum Cryptography | วิเคราะห์ TLS Handshake และเข้าใจภัยคุกคามจาก Quantum Computer | ใช้ Wireshark วิเคราะห์ TLS และอภิปราย Crypto Agility |

---

## เนื้อหา

### 8.1 พื้นฐาน Cryptography สำหรับนักพัฒนา

Cryptography (การเข้ารหัส) เป็นศาสตร์ของการสื่อสารอย่างลับในที่ที่มีบุคคลที่สาม ( adversary) นักพัฒนาซอฟต์แวร์ไม่จำเป็นต้องเป็นนักคณิตศาสตร์ที่ออกแบบ Algorithm ใหม่ แต่ต้องเข้าใจหลักการพื้นฐานเพื่อเลือกใช้ Algorithm และ Library ได้อย่างถูกต้อง

#### 8.1.1 Cryptographic Primitives

Primitive คือบล็อกพื้นฐานทาง Cryptography ที่นำมาประกอบกันเป็นระบบรักษาความปลอดภัย

| Primitive | หน้าที่ | ตัวอย่าง Algorithm |
|-----------|---------|-------------------|
| Symmetric Encryption | เข้ารหัสและถอดรหัสด้วยคีย์เดียวกัน | AES, ChaCha20 |
| Asymmetric Encryption | เข้ารหัสด้วย Public Key, ถอดรหัสด้วย Private Key | RSA, ECIES |
| Cryptographic Hash | แปลงข้อมูลขนาดใดก็ได้เป็นค่าคงที่ (One-way) | SHA-256, SHA-3 |
| Message Authentication Code (MAC) | ตรวจสอบความถูกต้องและที่มาของข้อมูล | HMAC, Poly1305 |
| Digital Signature | พิสูจน์ตัวตนผู้ส่งและความถูกต้องของข้อมูล | ECDSA, Ed25519, RSA-PSS |
| Key Exchange | สร้าง Shared Secret ระหว่างสองฝ่าย | Diffie-Hellman, ECDH |

#### 8.1.2 Kerckhoffs's Principle

**หลักการ:** ระบบเข้ารหัสควรปลอดภัยแม้ทุกอย่างเกี่ยวกับระบบยกเว้นคีย์ลับจะถูกเปิดเผยต่อสาธารณะ

ในปี 1883 Auguste Kerckhoffs ได้ตีพิมพ์หลักการนี้อธิบายว่าระบบเข้ารหัสไม่ควรพึ่งพาความลับของ Algorithm (Security Through Obscurity) แต่ควรพึ่งพาความลับของคีย์เท่านั้น

**นัยยะสำหรับนักพัฒนา:**
- การใช้ Algorithm ที่เป็นมาตรฐานเปิด (AES, SHA-256) ปลอดภัยกว่าการคิด Algorithm เอง
- การเข้ารหัสที่ "บ้าน" (Proprietary Algorithm) มักถูก Crack ได้ง่ายกว่า
- ห้ามเชื่อว่า "แฮกเกอร์ไม่รู้ว่าเราใช้ Algorithm อะไร" — ใช้ Algorithm ที่ผ่านการตรวจสอบโดยชุมชน cryptographic
- Algorithm ที่ดีต้องผ่านการ Cryptanalysis มาหลายสิบปี

**หลักการตรงข้าม — Security Through Obscurity:**
ความเชื่อที่ว่าระบบจะปลอดภัยถ้าซ่อนวิธีการทำงาน เป็นแนวทางที่ผิดและอันตราย ตัวอย่างความล้มเหลว:
- DVD Content Scramble System (CSS) — ถูก Crack ในไม่กี่ปี
- Microsoft's LM Hash — ใช้วิธีแปลกๆ ที่ไม่เป็นมาตรฐาน ถูก Crack ทันทีที่เปิดเผย Algorithm

#### 8.1.3 Encryption ≠ Hashing ≠ Encoding

นักพัฒนามือใหม่มักสับสนระหว่าง 3 แนวคิดนี้ ซึ่งมีวัตถุประสงค์ต่างกันโดยสิ้นเชิง

| คุณสมบัติ | Encryption | Hashing | Encoding |
|-----------|-----------|---------|----------|
| **วัตถุประสงค์** | รักษาความลับ | ตรวจสอบความถูกต้อง / Identity | แปลงรูปแบบข้อมูล |
| **การย้อนกลับ** | ได้ (ด้วยคีย์) | ไม่ได้ (One-way) | ได้ (ไม่มีคีย์) |
| **ใช้คีย์** | ใช่ | ไม่ | ไม่ |
| **ขนาดผลลัพธ์** | เท่ากับข้อมูลต้นทาง (หรือใกล้เคียง) | คงที่ (เช่น 256 bits) | แปรผันตามข้อมูล |
| **ตัวอย่าง** | AES-GCM, RSA | SHA-256, SHA-3 | Base64, Hex, UTF-8 |
| **ความปลอดภัย** | ใช้ป้องกันข้อมูล | ไม่สามารถใช้ป้องกันความลับ | ไม่มีความปลอดภัยใดๆ |

**ตัวอย่างความสับสนที่พบบ่อยในโค้ด:**
- การใช้ Base64 เป็น "การเข้ารหัส" — Base64 เป็น Encoding ไม่ใช่ Encryption ใครก็ได้สามารถ Decode ได้ทันที
- การใช้ MD5/SHA-256 แทน Password Hashing Algorithm — Hash ทั่วไปเร็วเกินไปสำหรับการเก็บรหัสผ่าน
- การเชื่อว่าการเข้ารหัสข้อมูลแล้ว Hash เหมือนกัน — ความสับสนนี้นำไปสู่ช่องโหว่ร้ายแรง

#### 8.1.4 Don't Roll Your Own Crypto

**หลักการสำคัญที่สุดในบทนี้:** อย่าเขียน Algorithm เข้ารหัสเอง และอย่า implement Cryptographic Protocol เอง

**เหตุผล:**
1. **Cryptography เป็นคณิตศาสตร์ที่ซับซ้อน** — ข้อผิดพลาดเล็กน้อย (เช่น ใช้ modulo ไม่ถูกต้อง) ทำให้ระบบไม่ปลอดภัยโดยสิ้นเชิง
2. **Side-Channel Attacks** — Algorithm ที่ถูกทางคณิตศาสตร์อาจรั่วข้อมูลผ่าน Timing, Power Consumption, Electromagnetic Radiation
3. **Implementation Bugs** — Buffer overflow, memory leak, incorrect padding handling
4. **Protocol Errors** — ใช้ Algorithm ถูก แต่ลำดับหรือวิธีใช้ผิด ทำให้ปลอดภัยไม่ได้

**ตัวอย่างความล้มเหลวจากการ Roll Your Own Crypto:**

| เหตุการณ์ | รายละเอียด | ผลกระทบ |
|-----------|-----------|----------|
| **WhatsApp (2011)** | ใช้ OTR Protocol ที่ implement เอง — ข้อผิดพลาดทำให้ Message Integrity เสีย | ต้องแก้ไขทั้งหมด |
| **NATO (2014)** | ใช้ BitLocker แต่คีย์ถูก hardcode ใน BIOS | การเข้ารหัสไม่มีประโยชน์ |
| **Tesla (2014-2017)** | ใช้ Algorithm เข้ารหัสเองใน key fob — ถูก Crack ด้วยเครื่อง $600 | ยานพาหนะถูกขโมย |
| **Dual_EC_DRBG (2006-2015)** | NSA แทรก backdoor ใน PRNG มาตรฐาน NIST — RSA ใช้ในผลิตภัณฑ์ | ต้องเลิกใช้ Algorithm |
| **ค้นพบ Vulnerability ใน crypto library ปี 2024** | OpenSSL, GnuTLS, และอื่นๆ ยังมีช่องโหว่ให้แก้ตลอด | แม้ library ที่มีคนใช้มากที่สุดก็ยังมี Bug |

**แนวทางที่ถูกต้อง:**
- ใช้ Library ที่ผ่านการตรวจสอบ (Audited Cryptographic Library) เช่น:
  - **Python:** `cryptography` library, `PyCryptodome`
  - **JavaScript/Node.js:** `crypto` built-in, `libsodium.js`
  - **Java:** `Java Cryptography Architecture (JCA)`, `Bouncy Castle`
  - **Go:** `crypto/aes`, `crypto/ecdsa`, `golang.org/x/crypto`
  - **Rust:** `ring`, `rustls`, `aes-gcm`
- ใช้ Library ที่มี **libtomcrypt** หรือ **NaCL** (Networking and Cryptography library) — Daniel J. Bernstein ออกแบบให้ใช้งานง่ายและปลอดภัย
- ใช้ **libsodium** (fork ของ NaCL) — มี binding ในทุกภาษา สำคัญ: Sodium ปลอดภัยเมื่อใช้ฟังก์ชันระดับสูง (crypto_box, crypto_secretbox) แทนการประกอบ Primitive เอง

#### 8.1.5 Common Mistakes ในการใช้ Cryptography

| ข้อผิดพลาด | คำอธิบาย | แนวทางแก้ไข |
|-----------|----------|-------------|
| **ใช้ ECB mode** | รูปแบบการเข้ารหัสแบบ Block เดียว — ข้อมูลที่เหมือนกันได้ Ciphertext เดียวกัน | ใช้ GCM, CTR, หรือ CBC แทน |
| **ใช้ IV/Nonce ซ้ำ** | Initialization Vector ที่ซ้ำกันทำลายความปลอดภัยของ GCM และ CTR | สุ่ม IV ด้วย CSPRNG ทุกครั้ง |
| **Static IV** | IV ที่ตายตัวทำให้ Ciphertext Pattern ถูกวิเคราะห์ได้ | IV ต้องสุ่มและไม่ซ้ำกันเด็ดขาด |
| **Weak Key Generation** | ใช้ `random()` แทน CSPRNG ในการสร้างคีย์ | ใช้ `os.urandom()`, `secrets.token_bytes()` |
| **Hardcoded Keys** | ฝังคีย์ไว้ใน Source Code | ใช้ Environment Variable หรือ Secret Manager (HashiCorp Vault, AWS KMS) |
| **ใช้ Hash แทน MAC** | ใช้ SHA-256 ตรวจสอบความถูกต้องโดยไม่มีคีย์ | ใช้ HMAC หรือ GCM ที่มี Authentication |
| **Padding Oracle Attack** | ใช้ CBC + PKCS7 โดยไม่ตรวจสอบ Padding ก่อน MAC | ใช้ GCM (Authenticated Encryption) แทน |
| **Algorithm Confusion** | ส่ง Algorithm Name ใน Message แล้วรับมาจากผู้โจมตี | กำหนด Algorithm ไว้ที่ Server เท่านั้น |
| **Key Length ไม่พอ** | ใช้ RSA 512-bit หรือ DES 56-bit | AES-128 ขึ้นไป, RSA-2048 ขึ้นไป, ECC P-256 ขึ้นไป |
| **ไม่ตรวจ Certificate** | ใช้ HTTPS แต่ไม่ได้ตรวจสอบ Certificate Hostname | ใช้ Library ที่ตรวจสอบ Certificate อัตโนมัติ |

---

### 8.2 Symmetric Encryption

Symmetric Encryption (การเข้ารหัสแบบสมมาตร) ใช้คีย์เดียวกันในการเข้ารหัสและถอดรหัส เป็นวิธีที่เร็วและมีประสิทธิภาพสูง เหมาะสำหรับการเข้ารหัสข้อมูลปริมาณมาก

#### 8.2.1 Block Ciphers: AES

**AES (Advanced Encryption Standard)** เป็นมาตรฐานการเข้ารหัสที่ NIST รับรองในปี 2001 แทน DES ที่ถูก Crack แล้ว (56-bit key ถูก Brute Force ในปี 1998 ภายใน 56 ชั่วโมงด้วยเครื่อง Deep Crack)

**รูปแบบ AES:**

| ประเภท | ขนาดคีย์ | ขนาด Block | จำนวน Round | ความปลอดภัย |
|--------|---------|------------|-------------|-------------|
| AES-128 | 128 bits (16 bytes) | 128 bits | 10 | เพียงพอสำหรับข้อมูลทั่วไป |
| AES-192 | 192 bits (24 bytes) | 128 bits | 12 | Secret/Top Secret (US Government) |
| AES-256 | 256 bits (32 bytes) | 128 bits | 14 | ความปลอดภัยสูงสุด |

**ข้อเท็จจริงเกี่ยวกับ AES:**
- AES ยังไม่ถูก Crack ทางคณิตศาสตร์ (2026) — การโจมตีที่ดีที่สุดลดความแข็งแรงจาก 2^128 เหลือ 2^126.1 (ไม่เป็นผลในทางปฏิบัติ)
- การใช้ AES-256 แทน AES-128 เพิ่มความปลอดภัยเพียงเล็กน้อย (128 bits ก็เพียงพอต่อการ Brute Force) แต่ AES-256 ช้ากว่าเล็กน้อย (~5-20% บน CPU ที่มี AES-NI, ถึง ~40% ในระบบที่ไม่มี Hardware Acceleration)
- AES เป็นมาตรฐานของรัฐบาลสหรัฐฯ (FIPS 197) และเป็นที่ยอมรับทั่วโลก

#### 8.2.2 Modes of Operation

Block Cipher เข้ารหัสข้อมูลทีละ Block (16 bytes สำหรับ AES) — Modes of Operation กำหนดวิธีจัดการข้อมูลที่ยาวกว่า 1 Block

| Mode | Authentication | IV/Nonce | ความปลอดภัย | คำแนะนำ |
|------|---------------|----------|-------------|---------|
| **ECB** | ไม่ | ไม่ | **ไม่ปลอดภัย** | **ห้ามใช้เด็ดขาด** |
| **CBC** | ไม่ | 16 bytes (random) | ปานกลาง | เสี่ยง Padding Oracle Attack |
| **CTR** | ไม่ | 8-16 bytes (unique) | ปานกลาง | ไม่มีการตรวจสอบ Integrity |
| **GCM** | **มี** (GMAC) | 12 bytes (recommended) | **ปลอดภัย** | **แนะนำให้ใช้** |
| **CCM** | มี | 7-13 bytes | ปลอดภัย | ใช้ใน IoT, ช้ากว่า GCM |
| **ChaCha20-Poly1305** | มี (Poly1305) | 12 bytes | **ปลอดภัย** | **แนะนำ** (เร็วใน Software) |

**ECB Mode — ห้ามใช้เด็ดขาด:**

ECB (Electronic Codebook) เข้ารหัสแต่ละ Block ด้วยคีย์เดียวกัน — ข้อมูลต้นทาง Block เดียวกันให้ Ciphertext Block เดียวกัน ทำให้เห็น Pattern ของข้อมูล

```text
Plaintext:  [Block 1] [Block 2] [Block 3] ... [Block N]
                |         |         |             |
                v         v         v             v
Ciphertext: [CT 1]    [CT 2]    [CT 3]    ... [CT N]

# ถ้า Block 1 == Block 5 → CT 1 == CT 5
```

**ตัวอย่างที่เห็นได้ชัด: การเข้ารหัสภาพ (ECB Penguin):**
เมื่อเข้ารหัสภาพด้วย AES-ECB รูปภาพที่ได้ยังคงเห็น "เค้าโครง" ของภาพเดิม — นี่คือปัญหา ECB's Pattern Problem ที่ทำให้ ECB ใช้ในทางปฏิบัติไม่ได้

**GCM (Galois/Counter Mode) — โหมดแนะนำสำหรับข้อมูลทั่วไป:**

GCM เป็น Authenticated Encryption (AEAD — Authenticated Encryption with Associated Data) ที่ให้ทั้งการรักษาความลับ (Encryption) และการตรวจสอบความถูกต้อง (Authentication) ในขั้นตอนเดียว

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# สร้างคีย์ (256 bits)
key = AESGCM.generate_key(bit_length=256)

# สร้าง Nonce (12 bytes = 96 bits)
nonce = os.urandom(12)

# ข้อมูลที่จะเข้ารหัส
plaintext = b"ขอมลลบบทความจำเปนทตองปองกน"

# Associated Data — ข้อมูลที่ไม่เข้ารหัสแต่ต้องการตรวจสอบ Integrity
aad = b"header-metadata"

# เข้ารหัส
aesgcm = AESGCM(key)
ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

# ถอดรหัส
plaintext_decrypted = aesgcm.decrypt(nonce, ciphertext, aad)
```

**ข้อควรระวัง GCM:**
- **Nonce ซ้ำ = หายนะ:** ถ้าใช้ Nonce ซ้ำกับคีย์เดียวกัน ผู้โจมตีสามารถกู้คืนคีย์ได้ — ต้องสุ่มหรือใช้ Counter ที่ถูกต้องเท่านั้น
- **Nonce ความยาว:** แนะนำ 12 bytes (96 bits) — ถ้าใช้น้อยกว่านี้จะมีการประมวลผลเพิ่ม (GHASH) ที่ซับซ้อน
- **ความยาว Nonce:** 12 bytes = 2^96 ค่า — โอกาสซ้ำน้อยมาก จึงสุ่มได้
- **Maximum Message Length:** GCM มีข้อจำกัด — ไม่ควรเข้ารหัสข้อความที่ยาวเกิน 2^39 - 256 bits (~64 GB) ด้วยคีย์- Nonce คู่เดียวกัน

**ChaCha20-Poly1305:**

ChaCha20-Poly1305 (RFC 8439) เป็น Authenticated Encryption ที่ออกแบบโดย Daniel J. Bernstein ทำงานเร็วกว่า AES-GCM ในระบบที่ไม่มี Hardware Acceleration สำหรับ AES (เช่น มือถือรุ่นเก่า, IoT)

```python
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os

key = ChaCha20Poly1305.generate_key()
nonce = os.urandom(12)

chacha = ChaCha20Poly1305(key)
ciphertext = chacha.encrypt(nonce, plaintext, aad)
plaintext_decrypted = chacha.decrypt(nonce, ciphertext, aad)
```

**ตารางเปรียบเทียบ AES-GCM กับ ChaCha20-Poly1305:**

| คุณสมบัติ | AES-GCM | ChaCha20-Poly1305 |
|-----------|---------|-------------------|
| **Algorithm** | AES (AES-NI) + GHASH | ChaCha20 + Poly1305 |
| **ความเร็ว (มี HW support)** | เร็วมาก (AES-NI) | ช้ากว่า (~1.5-2x) |
| **ความเร็ว (ไม่มี HW support)** | ช้า | เร็วกว่า |
| **ความปลอดภัย** | สูง | สูง (ออกแบบมาเทียบเท่า) |
| **Nonce size** | 12 bytes (recommended) | 12 bytes |
| **Side-channel resistance** | ปานกลาง (GHASH ไวต่อ Timing) | ดี (ออกแบบให้ Constant-time) |
| **การใช้งานใน TLS** | TLS 1.3 (AEAD หลัก) | TLS 1.3 (required cipher) |
| **Performance Ratio** | 1x (baseline) | ~1.5-2x ช้ากว่าเมื่อเทียบต่อ byte |

#### 8.2.3 Initialization Vector (IV) / Nonce

IV และ Nonce เป็นค่าที่สุ่มหรือไม่ซ้ำ ซึ่งใช้เพื่อให้การเข้ารหัสครั้งเดียวกันให้ผลลัพธ์ต่างกัน

**หลักการสำคัญ:**
- **IV สำหรับ CBC:** ต้องสุ่ม (Random) — ไม่จำเป็นต้องเป็นความลับ ส่งไปกับ Ciphertext ได้
- **Nonce สำหรับ GCM/CTR:** **ห้ามซ้ำเด็ดขาด** ถ้าใช้ Nonce ซ้ำกับ AES-GCM หรือ ChaCha20-Poly1305 ผู้โจมตีสามารถกู้คืน Keystream ได้
- **Nonce สำหรับ CTR:** ห้ามซ้ำเด็ดขาด เช่นเดียวกับ GCM

**แนวทางการจัดการ Nonce (GCM):**
1. **Counter-based:** ใช้ Counter ที่เพิ่มขึ้นเสมอ — ปลอดภัยแน่ แต่ต้องจัดการ State (เช่น เก็บ Counter ใน Database)
2. **Random:** สุ่ม 12 bytes — แนะนำ กรณีที่ Nonce 12 bytes โอกาสซ้ำ 2^96 — ถ้าเข้ารหัสน้อยกว่า 2^32 ครั้ง โอกาสซ้ำ < 2^-64 (ปลอดภัย)
3. **Larger Nonce:** ถ้าไม่แน่ใจ ใช้ XChaCha20-Poly1305 (Nonce 24 bytes) — ลดความเสี่ยง Nonce ซ้ำ

**ตัวอย่างการจัดการ Nonce ที่ผิดพลาด:**
```python
# ไม่ปลอดภัย: Static nonce
nonce = b"000000000000"  # ซ้ำทุกครั้ง!
ciphertext1 = aesgcm.encrypt(nonce, b"Hello", None)
ciphertext2 = aesgcm.encrypt(nonce, b"World", None)
# ถ้า nonce ซ้ำ → Keystream เดียวกัน → XOR จะเปิดเผยข้อมูล

# ปลอดภัย: Random nonce
nonce = os.urandom(12)
ciphertext1 = aesgcm.encrypt(nonce, b"Hello", None)
# เก็บ nonce นี้ไว้กับ ciphertext เพื่อใช้ตอนถอดรหัส
```

#### 8.2.4 Key Derivation Functions (KDF)

KDF ใช้ในการแปลงข้อมูลที่มี Entropy ต่ำ (เช่น รหัสผ่าน) หรือคีย์ที่มี Entropy สูงแต่ต้องการปรับรูปแบบ ให้เป็นคีย์ที่มีความยาวตามต้องการ

| KDF | การใช้งานหลัก | ข้อควรรู้ |
|-----|--------------|----------|
| **PBKDF2** (RFC 2898) | Key Derivation จาก Password | OWASP และ IETF แนะนำ — ต้องมี Iteration count สูง (600,000 สำหรับ HMAC-SHA-256 อ้างอิงจาก OWASP Password Storage Cheat Sheet) |
| **Argon2** | Key Derivation จาก Password | **ดีที่สุด** — Memory-hard ป้องกัน GPU/ASIC |
| **scrypt** | Key Derivation จาก Password | Memory-hard — ใช้เมื่อ Argon2 ไม่พร้อม |
| **HKDF** (RFC 5869) | Key Derivation จาก High-Entropy Source | ใช้ขยายคีย์ที่มี Entropy สูง (เช่น Shared Secret จาก ECDH) |

**ตัวอย่างการใช้ PBKDF2:**
```python
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os

password = b"my_strong_password"
salt = os.urandom(16)  # ขนาด 16 bytes

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,          # 32 bytes = 256 bits สำหรับ AES-256
    salt=salt,
    iterations=600000,  # 600,000 iterations
)

key = kdf.derive(password)  # สร้างคีย์
```

**ตาราง Algorithm Selection สำหรับ Symmetric Encryption:**

| กรณีใช้งาน | Algorithm ที่แนะนำ | หมายเหตุ |
|-----------|-------------------|----------|
| ข้อมูลทั่วไป | AES-256-GCM | ปลอดภัย, เร็ว (มี HW) |
| Mobile/IoT (ไม่มี HW AES) | ChaCha20-Poly1305 | เร็วกว่า AES-GCM |
| ข้อมูลขนาดใหญ่ (> 64 GB) | ChaCha20-Poly1305 | GCM มีข้อจำกัดความยาว |
| ทำ Streaming | CTR + MAC | แต่แนะนำ GCM หรือ ChaCha20-Poly1305 |
| Disk/File Encryption | AES-256-XTS | โหมดพิเศษสำหรับ Disk |
| TLS 1.3 | AES-256-GCM / ChaCha20-Poly1305 | สองอย่างนี้เท่านั้น |

---

### 8.3 Asymmetric (Public-Key) Cryptography

Asymmetric Cryptography ใช้คีย์สองค่าที่สัมพันธ์กันทางคณิตศาสตร์ ได้แก่ Public Key (เผยแพร่ให้สาธารณะ) และ Private Key (เก็บเป็นความลับ) แก้ปัญหา Key Distribution ของ Symmetric Cryptography

#### 8.3.1 RSA

RSA (Rivest-Shamir-Adleman, 1977) เป็น Algorithm Asymmetric ที่รู้จักกันมากที่สุด อาศัยความยากของการแยกตัวประกอบจำนวนเฉพาะขนาดใหญ่

**ขนาดคีย์ RSA ที่แนะนำ:**

| ขนาดคีย์ | สถานะ | คำแนะนำ |
|---------|-------|---------|
| 1024 bits | **ไม่ปลอดภัย** | ถูก Factor ในปี 2010 (Academic) — ห้ามใช้ |
| 2048 bits | **ปลอดภัย (ปัจจุบัน)** | มาตรฐานขั้นต่ำ — NIST แนะนำถึงปี 2030 |
| 3072 bits | ปลอดภัยสูง | แนะนำถ้าต้องการความปลอดภัยระยะยาว |
| 4096 bits | ปลอดภัยสูงมาก | ช้ากว่า 2048 bits ~4-8 เท่า |

**ข้อจำกัดของ RSA:**
- คีย์ยาว — 2048 bits = 256 bytes
- Encryption ช้า — จำกัดขนาดข้อมูลที่เข้ารหัสได้ (สูงสุด ~ขนาดคีย์ - 42 bytes สำหรับ OAEP)
- Generation คีย์ช้า — อาจใช้เวลาหลายวินาทีสำหรับ 4096 bits
- ไม่มี Perfect Forward Secrecy (PFS) ถ้าใช้ RSA เพียงอย่างเดียว
- กำลังถูกแทนที่ด้วย ECC และ Post-Quantum Algorithms

**ข้อควรระวังการใช้งาน RSA:**
- **Padding คือสิ่งที่ทำให้ RSA ปลอดภัย:** ต้องใช้ OAEP (Optimal Asymmetric Encryption Padding) เท่านั้น — ห้ามใช้ Textbook RSA (ไม่ Padding)
- **RSA-OAEP** (PKCS#1 v2.2): แนะนำ
- **RSA-PKCS1v1.5** (PKCS#1 v1.5): เสี่ยง — ถูกโจมตีได้ด้วย Bleichenbacher Attack (1998) แม้จะมี Mitigation แล้วก็ควรหลีกเลี่ยง
- **RSA-PSS** (Probabilistic Signature Scheme): สำหรับ Digital Signature

#### 8.3.2 Elliptic Curve Cryptography (ECC)

ECC ใช้ Algebraic Structure ของ Elliptic Curve ในการสร้างความสัมพันธ์ทางคณิตศาสตร์ระหว่าง Public และ Private Key จุดเด่นคือให้ความปลอดภัยเทียบเท่า RSA แต่ใช้คีย์สั้นกว่าและเร็วกว่า

**ขนาดคีย์เปรียบเทียบ ECC vs RSA:**

| ความปลอดภัย (bits) | ขนาดคีย์ ECC | ขนาดคีย์ RSA | อัตราส่วน |
|-------------------|-------------|-------------|-----------|
| 80 | 160 bits | 1024 bits | 1:6.4 |
| 112 | 224 bits | 2048 bits | 1:9.1 |
| 128 | 256 bits | 3072 bits | 1:12 |
| 192 | 384 bits | 7680 bits | 1:20 |
| 256 | 521 bits | 15360 bits | 1:29.5 |

**Curve ยอดนิยม:**

| Curve | ความปลอดภัย | การรับรอง | หมายเหตุ |
|-------|-------------|-----------|----------|
| **P-256** (secp256r1) | 128 bits | NIST, ใช้ใน TLS 1.3 | Curve ที่ใช้มากที่สุด |
| **P-384** (secp384r1) | 192 bits | NIST | สำหรับ Secret/Top Secret |
| **P-521** (secp521r1) | 256 bits | NIST | ความปลอดภัยสูงสุด |
| **Curve25519** (X25519) | 128 bits | TLS 1.3 | **แนะนำ** — เร็ว, Constant-time |
| **Ed25519** | 128 bits | TLS 1.3 | **แนะนำ** — Signature Curve |

**ข้อดีของ Curve25519 / Ed25519:**
- ออกแบบโดย Daniel J. Bernstein — Constant-time โดย design (ป้องกัน Side-Channel)
- เร็วมาก — Key Generation, Sign, Verify ทั้งหมดเร็วกว่า P-256
- ไม่มี patents — ใช้ได้ฟรี
- คีย์สั้น — Public Key 32 bytes, Private Key 32 bytes
- ปลอดภัยเมื่อใช้อย่างถูกต้อง — ไม่ต้องกังวลเกี่ยวกับ параметр พิเศษ

```python
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Alice สร้าง Key Pair
alice_private = x25519.X25519PrivateKey.generate()
alice_public = alice_private.public_key()

# Bob สร้าง Key Pair
bob_private = x25519.X25519PrivateKey.generate()
bob_public = bob_private.public_key()

# Alice คำนวณ Shared Secret
alice_shared = alice_private.exchange(bob_public)

# Bob คำนวณ Shared Secret
bob_shared = bob_private.exchange(alice_public)

# alice_shared == bob_shared (Shared Secret เดียวกัน)
# นำ Shared Secret ไปเข้า KDF เพื่อสร้าง Symmetric Key
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"handshake data",
).derive(alice_shared)
```

#### 8.3.3 Hybrid Encryption

Hybrid Encryption คือการรวมข้อดีของ Symmetric (เร็ว) และ Asymmetric (จัดการคีย์ง่าย) เข้าด้วยกัน เป็นพื้นฐานของ TLS, PGP, และการเข้ารหัสอื่นๆ ในโลกจริง

**กระบวนการ Hybrid Encryption:**
1. สุ่มสร้าง Symmetric Key (Data Encryption Key — DEK)
2. เข้ารหัสข้อมูลด้วย DEK (ใช้ AES-GCM)
3. เข้ารหัส DEK ด้วยผู้รับ's Public Key (ใช้ RSA-OAEP หรือ ECIES)
4. ส่ง Ciphertext + Encrypted DEK ไปให้ผู้รับ
5. ผู้รับถอดรหัส DEK ด้วย Private Key
6. ผู้รับถอดรหัสข้อมูลด้วย DEK

```text
ผู้ส่ง:                                    ผู้รับ:
1. สุ่ม DEK                                
2. เข้ารหัสข้อมูลด้วย AES-GCM(DEK)         
3. เข้ารหัส DEK ด้วย RSA-OAEP(PubKey)      
4. ส่ง [Ciphertext + EncryptedDEK]  →    5. ถอดรหัส DEK ด้วย RSA-OAEP(PrivKey)
                                          6. ถอดรหัสข้อมูลด้วย AES-GCM(DEK)
```

**ตัวอย่าง Hybrid Encryption ด้วย Python:**
```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
import os

# ผู้รับสร้าง RSA Key Pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()

# ผู้ส่ง: Hybrid Encryption
plaintext = b"ข้อความลับที่มีความยาวมาก"
dek = AESGCM.generate_key(bit_length=256)  # 1. สุ่ม DEK
nonce = os.urandom(12)

# 2. เข้ารหัสข้อมูลด้วย DEK
aesgcm = AESGCM(dek)
ciphertext = aesgcm.encrypt(nonce, plaintext, None)

# 3. เข้ารหัส DEK ด้วย Public Key
encrypted_dek = public_key.encrypt(
    dek,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    ),
)

# ส่ง: nonce + encrypted_dek + ciphertext

# ผู้รับ: Hybrid Decryption
# 5. ถอดรหัส DEK ด้วย Private Key
dek_decrypted = private_key.decrypt(
    encrypted_dek,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    ),
)

# 6. ถอดรหัสข้อมูลด้วย DEK
aesgcm_dec = AESGCM(dek_decrypted)
plaintext_decrypted = aesgcm_dec.decrypt(nonce, ciphertext, None)
```

#### 8.3.4 Digital Signatures

Digital Signature คือกลไกที่ให้ผู้รับสามารถยืนยันได้ว่าข้อมูลมาจากผู้ส่งจริง (Authentication) และไม่ถูกแก้ไขระหว่างทาง (Integrity) รวมถึงป้องกันการปฏิเสธ (Non-repudiation)

**กระบวนการ:**
- **Sign:** ผู้ใช้ Private Key เซ็นข้อมูล → ได้ Signature
- **Verify:** ผู้อ่านใช้ Public Key ตรวจสอบ Signature ว่าตรงกับข้อมูล

**Algorithm Digital Signature:**

| Algorithm | Curve/ขนาด | ความปลอดภัย | ความเร็ว | คำแนะนำ |
|-----------|-----------|-------------|---------|---------|
| **Ed25519** | Curve25519 | 128 bits | เร็วมาก | **แนะนำ** — เร็ว, Constant-time |
| **ECDSA P-256** | secp256r1 | 128 bits | เร็ว | ใช้ใน TLS, Bitcoin |
| **ECDSA P-384** | secp384r1 | 192 bits | ปานกลาง | สำหรับระดับสูง |
| **RSA-PSS** | 2048+ bits | 128+ bits | Sign ช้า | ระบบเก่า, Legacy |
| **RSA-PKCS1v1.5** | 2048+ bits | 128+ bits | Sign ช้า | **หลีกเลี่ยง** — เปราะบาง |
| **DSA** | 1024-3072 bits | - | ช้า | เลิกใช้ |

```python
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import hashes

# สร้าง Key Pair
private_key = ed25519.Ed25519PrivateKey.generate()
public_key = private_key.public_key()

# เซ็นข้อมูล
message = b"ขอมลทตองการเซ็น"
signature = private_key.sign(message)

# ตรวจสอบ Signature
try:
    public_key.verify(signature, message)
    print("ลายเซ็นถูกต้อง — ข้อมูลไม่ถูกแก้ไข")
except Exception:
    print("ลายเซ็นไม่ถูกต้อง — ข้อมูลถูกแก้ไขหรือไม่ใช่ผู้ส่งจริง")
```

**การใช้งาน Digital Signature ในทางปฏิบัติ:**
- **Code Signing:** เซ็นโปรแกรมเพื่อยืนยันว่ามาจากผู้พัฒนาจริง (Microsoft Authenticode, Apple Code Signing)
- **Software Update:** เซ็นไฟล์อัปเดตเพื่อป้องกันการแทรกมัลแวร์
- **Git Commit Signing:** เซ็น Git commit เพื่อยืนยันตัวตนผู้ commit (GPG หรือ SSH)
- **Document Signing:** e-signature ในเอกสารอิเล็กทรอนิกส์
- **JWT:** ใช้ Signature เพื่อยืนยันว่า Token ถูกสร้างโดย Authorization Server จริง

#### 8.3.5 Key Exchange และ Perfect Forward Secrecy

**Diffie-Hellman (DH) Key Exchange:**

DH Protocol (Whitfield Diffie และ Martin Hellman, 1976) เป็นวิธีการที่สองฝ่ายสามารถตกลงใช้คีย์ร่วมกัน (Shared Secret) ได้โดยไม่ต้องส่งคีย์ผ่านช่องทางที่ปลอดภัย

```text
Alice                             Bob
  |                                |
  |--- g^a mod p (Public Value) -->|
  |                                | Bob คำนวณ Shared Secret = (g^a)^b = g^ab
  |<-- g^b mod p (Public Value) ---|
  |                                |
Alice คำนวณ Shared Secret = (g^b)^a = g^ab
```

**Elliptic Curve Diffie-Hellman (ECDH):**

ใช้ ECC แทน Modular Exponentiation — ให้ความปลอดภัยเทียบเท่าแต่ใช้คีย์สั้นกว่าและเร็วกว่า

**Perfect Forward Secrecy (PFS):**

PFS คือคุณสมบัติที่การรั่วไหลของ Long-term Private Key (Server's Private Key) **ไม่** ทำให้ Session Key ในอดีตถูกถอดรหัสได้

- **ไม่มี PFS:** ถ้าแฮกเกอร์ขโมย Private Key ของ Server → สามารถถอดรหัส Session ทั้งหมดที่เคยบันทึกไว้ได้
- **มี PFS:** Session Key ถูกสร้างจาก Ephemeral Key (สุ่มใหม่ทุก Session) — การรั่วของ Private Key ไม่ช่วยถอดรหัส Session เก่า

**PFS สำเร็จได้ด้วย Diffie-Hellman (DHE) หรือ ECDHE (Ephemeral variant):**
```
ECDHE: ใช้ Key Pair ที่สร้างใหม่ทุก Session → ทิ้งเมื่อจบ Session
ถ้า Private Key ปัจจุบันรั่ว → Session เก่าปลอดภัย (เพราะ Key Pair นั้นถูกทิ้งไปแล้ว)
```

**OpenSSL Cipher ที่มี PFS (แนะนำ):**
```text
TLS_AES_256_GCM_SHA384          (TLS 1.3 — ทุก Cipher มี PFS)
TLS_CHACHA20_POLY1305_SHA256    (TLS 1.3)
ECDHE-RSA-AES256-GCM-SHA384     (TLS 1.2)
ECDHE-ECDSA-AES256-GCM-SHA384  (TLS 1.2)
```

**การตรวจสอบ PFS ในเว็บไซต์:**
```bash
# ใช้ openssl ตรวจสอบ PFS
openssl s_client -connect example.com:443 -tls1_2 -cipher 'ECDHE' 2>/dev/null
# ถ้าเชื่อมต่อได้ → เซิร์ฟเวอร์รองรับ PFS
```

---

### 8.4 Cryptographic Hashing

Cryptographic Hash Function แปลงข้อมูล (Message) ขนาดใดก็ได้ให้เป็นค่า Output ขนาดคงที่ (Digest หรือ Hash Value)

**คุณสมบัติของ Cryptographic Hash Function:**
1. **Deterministic:** Input เดียวกัน → Output เดียวกันเสมอ
2. **Fast to Compute:** คำนวณ Hash ได้เร็ว
3. **Preimage Resistance (One-way):** จาก Hash → หา Input เดิมไม่ได้
4. **Second Preimage Resistance:** จาก Input → หา Input อื่นที่ให้ Hash เดียวกันไม่ได้
5. **Collision Resistance:** หา Input สองค่าที่ให้ Hash เดียวกันไม่ได้ (ยาก)

#### 8.4.1 Hash Function ที่ควรรู้จัก

| Algorithm | ขนาด Output | ความปลอดภัย | สถานะ | คำแนะนำ |
|-----------|------------|-------------|-------|---------|
| **MD5** | 128 bits | **แตกแล้ว** | **เลิกใช้** | Collision Attack ทำได้ในวินาที — ใช้แค่ Checksum ที่ไม่เกี่ยวกับความปลอดภัย |
| **SHA-1** | 160 bits | **แตกแล้ว** | **เลิกใช้** | SHAttered (2017) — Google แสดง Collision จริง |
| **SHA-256** | 256 bits | ปลอดภัย | **แนะนำ** | มาตรฐานปัจจุบัน — ใช้สำหรับ Integrity, Digital Signature |
| **SHA-512** | 512 bits | ปลอดภัย | แนะนำ | ปลอดภัยกว่า 256 แต่ช้ากว่า (ใช้ 64-bit ops — เร็วกว่า SHA-256 บน 64-bit CPU) |
| **SHA-3-256** | 256 bits | ปลอดภัย | แนะนำ | โครงสร้างต่างจาก SHA-2 (Sponge) — สำรองเมื่อ SHA-2 ถูก Crack |
| **BLAKE2** | 256/512 bits | ปลอดภัย | แนะนำ | เร็วกว่า SHA-2/3 — ใช้ใน Zcash, Argonid |

**ตัวอย่างการใช้ SHA-256 ใน Python:**
```python
import hashlib

# Hash ข้อมูล
data = b"ขอมลทตองการตรวจสอบความถกตอง"
hash_obj = hashlib.sha256(data)
digest = hash_obj.hexdigest()
# output: "c4c7a3d5f2e1b8a9..."

# ตรวจสอบ Integrity
def verify_integrity(original_data, original_hash):
    current_hash = hashlib.sha256(original_data).hexdigest()
    return current_hash == original_hash
```

#### 8.4.2 การใช้งาน Hash ในซอฟต์แวร์

| การใช้งาน | Algorithm ที่แนะนำ | หมายเหตุ |
|-----------|-------------------|----------|
| Integrity Verification (ไฟล์ดาวน์โหลด) | SHA-256 | เช็ค Checksum ว่าไฟล์ไม่เสียหาย |
| Digital Signature | SHA-256, SHA-512 | Hash ข้อมูลก่อน Sign |
| Password Hashing | **Argon2id, bcrypt, PBKDF2** | **ห้ามใช้ SHA-256 โดยตรง** |
| File Deduplication | SHA-256 | เปรียบเทียบ Content Hash |
| Git | SHA-1 (กำลังเปลี่ยนเป็น SHA-256) | Git ใช้ SHA-1 สำหรับ Commit ID |
| Merkle Tree (Blockchain) | SHA-256 | Bitcoin, Ethereum |

**ข้อสำคัญ — Hash Collision:**

เมื่อเกิด Hash Collision (Input สองค่าที่ให้ Hash เดียวกัน) ความปลอดภัยของระบบที่ใช้ Hash จะถูกทำลาย:

| เหตุการณ์ | ปี | รายละเอียด | ผลกระทบ |
|-----------|-----|-----------|----------|
| MD5 Collision (Wang et al.) | 2004 | Collision ใช้เวลา 1 ชั่วโมงบน IBM P690 | MD5 เริ่มถูกเลิกใช้ |
| MD5 Collision (Marc Stevens) | 2007 | Collision ใน 5 นาทีบน laptop | MD5 เลิกใช้เด็ดขาด |
| SHAttered (SHA-1 Collision) | 2017 | Google + CWI — Collision แรกของ SHA-1 | เบราว์เซอร์เลิกรองรับ SHA-1 certificate |
| SHA-1 Collision (Shattered Paper) | 2017 | ใช้ 6,500 ปี CPU = 110 ปี GPU | Google แสดงว่า SHA-1 เสร็จสมบูรณ์ |
| MD5/GPG Collision | 2018 | Marc Stevens แสดงการปลอม GPG signature | MD5 ถูก blocking จาก GnuPG |

#### 8.4.3 Message Authentication Code (MAC)

HMAC (Hash-based Message Authentication Code) — RFC 2104 — ใช้คีย์ลับร่วมกับ Hash Function เพื่อสร้าง MAC ที่ใช้ตรวจสอบทั้ง Integrity และ Authenticity ของข้อมูล

**ความแตกต่างระหว่าง Hash และ MAC:**

| คุณสมบัติ | Hash ธรรมดา | HMAC |
|-----------|------------|------|
| **ใช้คีย์** | ไม่ | ใช่ |
| **ใครคำนวณได้** | ทุกคน (Public) | เฉพาะคนที่มีคีย์ |
| **ป้องกัน Tampering** | ไม่ (ผู้โจมตีแก้ข้อมูล + Hash ได้) | ใช่ (ไม่มีคีย์ → สร้าง MAC ไม่ได้) |
| **การใช้งาน** | Integrity Check | Integrity + Authentication |

```python
import hmac
import hashlib

# สร้าง HMAC
key = b"secret-key-for-hmac"
message = b"ขอมลทตองการปองกนการปลอมแปลง"

hmac_obj = hmac.new(key, message, hashlib.sha256)
mac = hmac_obj.hexdigest()

# ตรวจสอบ HMAC
def verify_hmac(key, message, mac_to_verify):
    expected_mac = hmac.new(key, message, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_mac, mac_to_verify)
    # ใช้ compare_digest — ป้องกัน Timing Attack!
```

**การประยุกต์ใช้ HMAC ในโลกจริง:**
- **AWS Signature V4:** ใช้ HMAC-SHA256 สำหรับ signing API requests
- **TLS:** ใช้ HMAC ใน Record Protocol (TLS 1.2)
- **JWT:** HS256 = HMAC-SHA256 สำหรับ signing tokens
- **OAuth 1.0:** ใช้ HMAC-SHA1 (deprecated)

---

### 8.5 Public Key Infrastructure (PKI) และ Digital Certificates

PKI คือโครงสร้างพื้นฐานที่จัดการการสร้าง จัดเก็บ แจกจ่าย และเพิกถอน Digital Certificates ทำให้สามารถเชื่อมโยง Public Key กับตัวตน (Identity) ที่แท้จริงได้

#### 8.5.1 X.509 Certificates

X.509 (ITU-T, 1988) เป็นมาตรฐาน Digital Certificate ที่ใช้ใน TLS/SSL, Code Signing, Document Signing, และ Email Encryption

**โครงสร้าง X.509 v3 Certificate:**

```text
Certificate:
    Version: 3
    Serial Number: 04:9A:8B:C5:...
    Signature Algorithm: sha256WithRSAEncryption
    Issuer: CN=Let's Encrypt, O=Let's Encrypt, C=US
    Validity:
        Not Before: May 1 00:00:00 2026 GMT
        Not After : Jul 30 00:00:00 2026 GMT
    Subject: CN=example.com, O=Example Corp, C=US
    Subject Public Key Info:
        Public Key Algorithm: id-ecPublicKey
            Public Key: (256 bits)
    Extensions:
        Subject Alternative Name (SAN): DNS:example.com, DNS:www.example.com
        Basic Constraints: CA:FALSE
        Key Usage: Digital Signature, Key Encipherment
        Extended Key Usage: TLS Web Server Authentication, TLS Web Client Authentication
    Signature: (ลายเซ็นของ CA)
```

**องค์ประกอบสำคัญของ X.509 Certificate:**
- **Subject** — เจ้าของ Certificate (โดเมน, บริษัท, บุคคล)
- **Issuer** — ผู้ออก Certificate (CA)
- **Subject Public Key Info** — Public Key พร้อม Algorithm
- **Validity** — วันหมดอายุ
- **Extensions** — ข้อมูลเพิ่มเติม (SAN, Key Usage, Basic Constraints)
- **Signature** — ลายเซ็นของ CA ยืนยันความถูกต้อง

#### 8.5.2 Certificate Authority (CA)

CA คือองค์กรที่เชื่อถือได้ (Trusted Third Party) ทำหน้าที่ออก Certificate หลังจากตรวจสอบตัวตนของผู้ขอ

**ประเภทของ CA:**

| ประเภท | การตรวจสอบ | ราคา | การแสดงผล |
|--------|-----------|------|-----------|
| **DV (Domain Validation)** | ตรวจสอบว่าควบคุม Domain ได้ | ฟรี - ~$10/ปี | HTTPS, ล็อกสีเขียว |
| **OV (Organization Validation)** | ตรวจสอบว่ามีตัวตนทางกฎหมาย | ~$100-300/ปี | HTTPS, แสดงบริษัท |
| **EV (Extended Validation)** | ตรวจสอบอย่างละเอียด (Green Bar) | ~$200-600/ปี | **เลิกใช้** — เบราว์เซอร์ไม่แสดง Green Bar แล้ว |

**ตัวอย่าง CA ที่น่าเชื่อถือ (2026):**
- Let's Encrypt (ฟรี, DV only, Automated)
- DigiCert
- Sectigo
- GlobalSign
- Entrust

#### 8.5.3 Certificate Chain และ Chain of Trust

Certificate Chain คือลำดับ Certificate ที่เชื่อมโยงจาก End-entity Certificate (โดเมน) ไปยัง Root CA (รากฐานความเชื่อถือ)

```text
Root CA Certificate (Self-signed)
    └── Intermediate CA Certificate 1
        └── Intermediate CA Certificate 2
            └── Server Certificate (example.com)
```

**การทำงานของ Chain of Trust:**
1. Browser มีรายการ Root CA Certificates ที่เชื่อถือ (Trust Store)
2. Server ส่ง Certificate Chain (Server Cert + Intermediate CAs)
3. Browser ตรวจสอบ Signature แต่ละระดับ: Server ← Intermediate2 ← Intermediate1 ← Root
4. ถ้า Signature ทุกจุดถูกต้อง และ Root อยู่ใน Trust Store → เชื่อถือได้

**การตรวจสอบ Certificate ใน Browser:**

```bash
# ใช้ openssl ดู Certificate Chain
openssl s_client -connect example.com:443 -showcerts

# ตรวจสอบว่า Certificate หมดอายุหรือไม่
openssl x509 -in cert.pem -text -noout | grep "Not Before\|Not After"

# ตรวจสอบ SAN
openssl x509 -in cert.pem -text -noout | grep "Subject Alternative Name"
```

**ข้อผิดพลาดที่พบบ่อย:**
- **Certificate Chain ไม่สมบูรณ์:** ส่งแค่ Server Cert โดยไม่มี Intermediate CAs บางเบราว์เซอร์อาจเชื่อมต่อได้ (มี Cache) แต่บางเครื่องเชื่อมต่อไม่ได้
- **Root CA หมดอายุ:** Root CA มักมีอายุ 20-25 ปี ถ้าหมดอายุ Trust Store จะปฏิเสธ
- **SAN ไม่รวมโดเมน:** ถ้า Certificate ไม่มี SAN ของโดเมนนั้นๆ Browser จะแสดง Warning

#### 8.5.4 Certificate Revocation

เมื่อ Private Key ของ Certificate รั่วไหล หรือ CA พบว่าออก Certificate ผิด ต้องมีการเพิกถอน Certificate

**กลไกการ Revocation:**

| กลไก | วิธีการ | จุดอ่อน |
|------|--------|---------|
| **CRL (Certificate Revocation List)** | CA เผยแพร่รายการ Serial Number ที่ถูกเพิกถอน | ขนาด CRL ใหญ่, ต้องดาวน์โหลดทั้งหมด, ไม่ Real-time |
| **OCSP (Online Certificate Status Protocol)** | Browser ถาม CA แบบ Real-time ว่า Certificate ยังใช้ได้หรือไม่ | Privacy (CA รู้ว่าเข้าเว็บไหน), ต้องมี Internet ตลอด |
| **OCSP Stapling** | Server ขอ OCSP Response ล่วงหน้า แล้วแนบไปกับ TLS Handshake | Server side implementation, Privacy ดีกว่า OCSP |
| **CRLite / CRLSets** | Browser รวบรวม CRL ที่จำเป็น (Firefox, Chrome) | ต้อง Trust Browser vendor |

**เหตุการณ์สำคัญเกี่ยวกับ Revocation:**

| เหตุการณ์ | ปี | รายละเอียด |
|-----------|-----|-----------|
| **DigiNotar Hack** | 2011 | CA ถูกแฮก — ออก Fake Certificate สำหรับ Google, Yahoo, CIA → DigiNotar ถูกเพิกถอน Trust → ล้มละลาย |
| **Comodo** | 2011 | Registrar เข้าถึงบัญชีโดยไม่ได้รับอนุญาต — ออก Certificate ปลอม 9 ใบสำหรับ Google, Yahoo, Skype |
| **Symantec (Thawte, VeriSign, GeoTrust)** | 2017 | พบ Certificate ที่ไม่ถูกต้อง มากกว่า 30,000 ใบ → เบราว์เซอร์ทยอยเลิก Trust (ตั้งแต่วันที่ 30 เมษายน 2018) |
| **Let's Encrypt** | 2020 | มี Certificate ที่ออกผิดพลาดมากกว่า 3 ล้านใบ (~2 ล้าน unique certificates) ในวันที่ 1 มีนาคม 2020 → Revoke ภายใน 24 ชั่วโมง — ยกย่องว่าจัดการดี |

#### 8.5.5 การจัดการ Keys และ Secrets

Key Management คือหนึ่งในส่วนที่ยากที่สุดของ Cryptography — Algorithm ที่ดีที่สุดไม่มีประโยชน์ถ้าคีย์ถูกรั่วไหล

**Key Lifecycle:**

```text
สร้างคีย์ → จัดเก็บ → ใช้งาน → หมุนเวียน → เพิกถอน → ทำลาย
```

| ขั้นตอน | แนวทางปฏิบัติ |
|--------|--------------|
| **สร้างคีย์** | ใช้ CSPRNG (Cryptographically Secure PRNG) เช่น `os.urandom()` |
| **จัดเก็บ** | ใช้ Secret Manager, HSM, หรือ OS Key Store อย่า Hardcode |
| **ใช้งาน** | โหลดคีย์ใน Memory เท่านั้น ไม่เขียนลง Disk |
| **หมุนเวียน** | เปลี่ยนคีย์ตามรอบ (ทุก 90 วัน - 2 ปี ขึ้นอยู่กับระดับความปลอดภัย) |
| **เพิกถอน** | เมื่อคีย์หาย เครื่องถูกขโมย หรือพนักงานลาออก — Revoke Certificate / คีย์ |
| **ทำลาย** | ต้องลบให้ถาวร — Zero-fill, Cryptographic Erase (ใน HSM) |

**ห้าม Hardcode Keys โดยเด็ดขาด:**

```python
# ไม่ปลอดภัย: Hardcoded Key
AES_KEY = b"my-secret-key-123"  # ใน Source Code — ใครอ่าน Source ก็ได้คีย์!

# ปลอดภัย: Environment Variable
import os
AES_KEY = os.environ.get("ENCRYPTION_KEY").encode()
# คีย์ ไม่ได้อยู่ใน Source Code — อยู่ใน Environment

# ปลอดภัยกว่า: Secret Manager
import boto3
client = boto3.client('kms')
response = client.decrypt(
    CiphertextBlob=encrypted_key_from_env,
    KeyId='alias/my-key'
)
AES_KEY = response['Plaintext']
```

**แนวทางเก็บ Keys ใน Production:**

| วิธี | ระดับความปลอดภัย | การจัดการ | เหมาะกับ |
|------|-----------------|-----------|----------|
| Environment Variables | ปานกลาง | ง่าย | Development, Testing |
| .env file (ไม่ commit) | ปานกลาง | ง่าย | Development |
| Docker Secrets | ปานกลาง | ปานกลาง | Container |
| HashiCorp Vault | สูง | ซับซ้อน | Enterprise |
| AWS KMS / GCP Cloud KMS | สูงมาก | ปานกลาง | Cloud Native |
| Azure Key Vault | สูงมาก | ปานกลาง | Azure |
| Hardware Security Module (HSM) | สูงสุด | ซับซ้อนมาก | Banking, Government |

---

### 8.6 Post-Quantum Cryptography

Quantum Computer มีศักยภาพในการทำลาย Algorithm Cryptography ที่ใช้กันอยู่ในปัจจุบัน — นี่คือภัยคุกคามที่นักพัฒนาต้องเตรียมพร้อม

#### 8.6.1 ภัยคุกคามจาก Quantum Computer

**Shor's Algorithm (Peter Shor, 1994):**
- สามารถแก้ปัญหา **Integer Factorization** ได้ในเวลาพหุนาม → ทำลาย RSA
- สามารถแก้ปัญหา **Discrete Logarithm** ได้ในเวลาพหุนาม → ทำลาย DSA, DH, ECDH, ECDSA

**Grover's Algorithm (Lov Grover, 1996):**
- สามารถค้นหาใน Space ขนาด N ได้ในเวลา √N → ลดความปลอดภัยของ AES-128 จาก 2^128 → 2^64
- **ผลกระทบ:** AES-256 (2^256 → 2^128) — ยังปลอดภัย; AES-128 (2^128 → 2^64) — เสี่ยง

| Algorithm | สถานะหลัง Quantum | สาเหตุ |
|-----------|-------------------|--------|
| **RSA** | **แตก** | Shor's Algorithm |
| **ECDSA / ECDH** | **แตก** | Shor's Algorithm |
| **DSA** | **แตก** | Shor's Algorithm |
| **AES-256** | ปลอดภัย (ลดเหลือ 128 bits) | Grover's Algorithm — ยังเพียงพอ |
| **AES-128** | เสี่ยง | Grover's Algorithm — เหลือ 64 bits |
| **SHA-256** | ปลอดภัย (ลดเหลือ 128 bits) | Grover's Algorithm — ยังเพียงพอ |
| **SHA-3** | ปลอดภัย | Grover's Algorithm |

**เส้นเวลา (Timeline) — การคาดการณ์:**

| ช่วงเวลา | สถานการณ์ |
|----------|-----------|
| 2024-2026 | NIST เลือกมาตรฐาน Post-Quantum Algorithms |
| 2026-2030 | การเริ่มเปลี่ยนผ่าน (Migration) |
| 2030-2035 | Quantum Computer ขนาด 1,000+ Logical Qubits อาจเริ่มทำลาย RSA-2048 |
| 2035+ | Post-Quantum กลายเป็นมาตรฐานใหม่ |

**Harvest Now, Decrypt Later:**

การโจมตีที่ผู้ไม่หวังดีบันทึกข้อมูลเข้ารหัสทั้งหมดในวันนี้ เพื่อรอวันที่มี Quantum Computer ถอดรหัสได้ — ข้อมูลที่ต้องการเก็บเป็นความลับระยะยาว (เช่น เอกสารราชการลับ, เวชระเบียน) เสี่ยงตั้งแต่ตอนนี้

#### 8.6.2 NIST Post-Quantum Cryptography Standards

NIST เริ่มกระบวนการคัดเลือก Post-Quantum Cryptography Algorithms ในปี 2016 หลังจากศึกษามากว่า 6 ปี ได้ประกาศ Algorithm ที่ได้รับคัดเลือกในเดือนกรกฎาคม 2022 โดยปัจจุบัน NIST ใช้ชื่อมาตรฐาน FIPS ดังนี้:

| Algorithm (ชื่อโครงการ) | ชื่อมาตรฐาน FIPS | ประเภท | การใช้งาน |
|------------------------|-----------------|--------|-----------|
| **CRYSTALS-Kyber** | **ML-KEM** (FIPS 203) | Key Encapsulation Mechanism (KEM) | ใช้แทน ECDH/RSA สำหรับ Key Exchange |
| **CRYSTALS-Dilithium** | **ML-DSA** (FIPS 204) | Digital Signature | ใช้แทน ECDSA/RSA-PSS สำหรับ Signature |
| **FALCON** | **FN-DSA** (FIPS 206 — อยู่ระหว่างพัฒนา) | Digital Signature | Signature ที่ Token เล็กกว่า Dilithium (แต่ซับซ้อนกว่า) |
| **SPHINCS+** | **SLH-DSA** (FIPS 205) | Digital Signature (Stateless) | ใช้ Hash-based — Conservative แต่ Token ใหญ่, Sign ช้า |

**ขนาดคีย์เปรียบเทียบ:**

| Algorithm | Public Key Size | Private Key Size | Signature Size |
|-----------|----------------|-----------------|----------------|
| Kyber-512 | 800 bytes | 1,632 bytes | - |
| Kyber-768 | 1,184 bytes | 2,400 bytes | - |
| Dilithium2 | 1,312 bytes | 2,528 bytes | 2,420 bytes |
| Dilithium5 | 2,592 bytes | 4,864 bytes | 4,595 bytes |
| Falcon-512 | 897 bytes | 1,281 bytes | 666 bytes |
| SPHINCS+-S (128) | 32 bytes | 64 bytes | 7,856 bytes |
| **RSA-2048 (เทียบ)** | 256 bytes | 256 bytes | 256 bytes |
| **Ed25519 (เทียบ)** | 32 bytes | 32 bytes | 64 bytes |

**ข้อสังเกต:** Post-Quantum Algorithms มี Public Key และ Signature ที่ใหญ่กว่า ECC/RSA มาก — การออกแบบ Protocol ต้องคำนึงถึง Size Overhead

#### 8.6.3 Crypto Agility

Crypto Agility คือความสามารถของระบบในการเปลี่ยน Algorithm Cryptography ได้โดยไม่ต้องแก้ไขโครงสร้างพื้นฐานทั้งหมด — เป็นคุณสมบัติที่สำคัญสำหรับการเปลี่ยนผ่านสู่ Post-Quantum

**หลักการออกแบบระบบให้ Crypto Agile:**

1. **แยก Cryptographic Layer:** ไม่ผูก Algorithm ไว้กับ Business Logic
2. **ใช้ Abstraction:** กำหนด Interface (เข้ารหัส, ถอดรหัส, เซ็น, ตรวจสอบ) โดยไม่ระบุ Algorithm ตายตัว
3. **Negotiable Algorithms:** Protocol ต้องรองรับการตกลง Algorithm (Cipher Suite Negotiation)
4. **Versioning & Migration Plan:** มีแผนอัปเกรด Algorithm โดยไม่ Downtime
5. **Hybrid Mode:** ใช้ Algorithm ปัจจุบัน + Post-Quantum Algorithm พร้อมกันในระหว่าง Migration

**ตัวอย่างการออกแบบ Crypto Agility:**

```python
class CryptoProvider(ABC):
    """Abstract interface — ไม่ผูกกับ Algorithm ใด Algorithm หนึ่ง"""
    
    @abstractmethod
    def encrypt(self, plaintext: bytes, aad: bytes = None) -> bytes:
        pass
    
    @abstractmethod
    def decrypt(self, ciphertext: bytes, aad: bytes = None) -> bytes:
        pass
    
    @abstractmethod
    def sign(self, message: bytes) -> bytes:
        pass
    
    @abstractmethod
    def verify(self, message: bytes, signature: bytes) -> bool:
        pass

# Implementation แบบ Hybrid: AES-GCM + Kyber
class HybridCryptoProvider(CryptoProvider):
    def __init__(self):
        self.classic_cipher = AESGCM(...)
        self.pq_kem = KyberKEM(...)
    
    def encrypt(self, plaintext, aad=None):
        # เข้ารหัสด้วยทั้ง AES-GCM และ Kyber
        # เก็บ Ciphertext + Algorithm Identifier
        pass
```

---

### 8.7 กรณีศึกษาและเหตุการณ์จริง

#### 8.7.1 Heartbleed (CVE-2014-0160)

**รายละเอียด:**
- ช่องโหว่ใน OpenSSL (มีผลกับ 1.0.1 — 1.0.1f)
- Buffer over-read ใน TLS Heartbeat Extension
- ผู้โจมตีสามารถอ่าน Memory ของ Server ได้ครั้งละ 64 KB (แต่ทำซ้ำได้เรื่อยๆ)
- ไม่ต้อง Authentication — ทุกคนที่เชื่อมต่อ TLS อ่าน Memory ได้

**ผลกระทบ:**
- รั่วไหล Private Key — แฮกเกอร์ขโมย Private Key จาก Memory
- รั่วไหล Session Keys, Passwords, และ User Data
- มีผลกับเซิร์ฟเวอร์ ~17% (500,000+) ของ HTTPS Servers
- OpenSSL เป็น Library Cryptography ที่ได้รับความนิยมสูงสุด

**บทเรียน:**
- Library Cryptography ที่มีคนใช้มากที่สุดก็มี Bug ได้
- Memory Safety ในภาษา C เป็นปัญหา — Buffer Over-read
- ต้องมี Monitoring และ Patch Management ที่รวดเร็ว
- การใช้ Memory-safe Language (Rust, Go) สำหรับ Cryptography กำลังได้รับความนิยม

#### 8.7.2 CRIME, BREACH, และ POODLE (TLS Attacks)

| Attack | ปี | เป้าหมาย | วิธีการ |
|--------|-----|---------|--------|
| **CRIME** (CVE-2012-4929) | 2012 | TLS Compression | บีบอัดข้อมูลก่อนเข้ารหัส → ขนาด Ciphertext บอกข้อมูล |
| **BREACH** (CVE-2013-3587) | 2013 | HTTP Compression | HTTP Response Body ถูกบีบอัด → ขนาดบอกข้อมูล |
| **POODLE** (CVE-2014-3566) | 2014 | SSL 3.0 | จัดการ Padding ใน CBC Mode → อ่านข้อมูลทีละ Byte |

**บทเรียน:**
- อย่าบีบอัดข้อมูลก่อนเข้ารหัสร่วมกับข้อมูลที่ผู้โจมตีควบคุมได้ (ไม่ใช้ TLS Compression)
- SSL 3.0 ถูก Deprecated — ใช้ TLS 1.2+ เท่านั้น
- Side-Channel Attacks อาศัย Observable Behavior (เวลา, ขนาด) — ต้องมี Constant-time Implementation

#### 8.7.3 Log4Shell (CVE-2021-44228)

**รายละเอียด:**
- ช่องโหว่ใน Apache Log4j library (Java logging framework)
- ผู้โจมตีส่ง String พิเศษใน Header หรือ Input → Log4j ดึง JNDI lookup ที่รันโค้ดบน Server
- CVSS 10.0 — Remote Code Execution
- มีผลกับเซิร์ฟเวอร์นับล้าน

**ความเกี่ยวข้องกับ Cryptography:**
- ถึงแม้ไม่ใช่ช่องโหว่ Cryptography โดยตรง แต่ Log4Shell แสดงให้เห็นว่า **ข้อมูลที่ถูก Log อาจไหลไปยังระบบอื่น**
- ข้อความที่เป็น JNDI lookup ถูกประมวลผล — ไม่ใช่แค่เขียนลง File
- ความปลอดภัยของ Cryptography Library (JCA) ไร้ประโยชน์ถ้า System Security ถูก bypass ได้

#### 8.7.4 Venafi / Microsoft 2024 — Post-Quantum Readiness Report

**รายละเอียด:**
- จากการสำรวจองค์กรทั่วโลก (2024):
  - 75% ขององค์กรยังไม่ได้เตรียมความพร้อมสำหรับ Post-Quantum Cryptography
  - 45% ไม่ทราบว่าต้องทำอะไร
  - 60% ขององค์กรการเงินเริ่มเตรียมการแล้ว
  - เฉลี่ยการเปลี่ยนผ่านใช้เวลา 5-10 ปี

**บทเรียน:**
- ต้องเริ่มสร้าง Crypto Inventory (ทำรายการ Algorithm ที่ใช้ทั่วทั้งองค์กร) ตอนนี้
- Algorithm Classical → Post-Quantum Migration ใช้เวลานาน
- ระบบที่ใช้ RSA-1024 หรือ SHA-1 ต้องรีบเปลี่ยน

#### 8.7.5 การโจมตี Key Management จริง

| เหตุการณ์ | ปี | รายละเอียด |
|-----------|-----|-----------|
| **AWS Keys รั่วจาก Source Code** | 2023 | พบ Access Key ใน GitHub Public Repo → นาทีแรกก็ถูกใช้แล้ว |
| **NPM Package ปลอมขโมย Keys** | 2024 | Malicious Package ใน npm อ่าน Environment Variables |
| **HouseAd (Microsoft)** | 2024 | Key ถูก hardcode ใน Internal App — รั่วจาก Source Code Leak |
| **Cryptomining บน Kubernetes (2024)** | 2024 | แฮกเกอร์หา Kubernetes Secrets จาก Cluster ที่ Config ผิด → ใช้ Cloud Resources ฟรี |

---

### 8.8 สรุปและแนวทางปฏิบัติ

#### 8.8.1 Algorithm Selection Guide

| กรณีใช้งาน | Algorithm ที่แนะนำ | ห้ามใช้ |
|-----------|-------------------|---------|
| **Encrypt Data** | AES-256-GCM, ChaCha20-Poly1305 | ECB mode, RC4, DES |
| **Encrypt at Rest** | AES-256-GCM, AES-256-XTS (disk) | ECB, Static IV |
| **Encrypt in Transit** | TLS 1.3 (AES-GCM, ChaCha20-Poly1305) | SSL 3.0, TLS 1.0, TLS 1.1 |
| **Password Hashing** | Argon2id, bcrypt | MD5, SHA-256 (โดยตรง) |
| **Digital Signature** | Ed25519, ECDSA P-256 | DSA, RSA-PKCS1v1.5 |
| **Key Exchange** | X25519 (ECDHE) | DH-1024, RSA Key Exchange |
| **Integrity Check** | SHA-256, SHA-3-256, HMAC-SHA256 | MD5, SHA-1 |
| **Certificate** | X.509 v3, SHA-256withRSA/ECDSA | SHA-1 Certificate |

#### 8.8.2 Checklist การใช้ Cryptography

- [ ] ใช้ Library ที่ผ่านการตรวจสอบ (ไม่เขียนเอง)
- [ ] ไม่ใช้ ECB Mode — ใช้ GCM หรือ CTR
- [ ] IV/Nonce ถูกสุ่มทุกครั้ง (ไม่ซ้ำเด็ดขาดสำหรับ GCM/ChaCha20)
- [ ] ใช้ Authenticated Encryption (AEAD) — GCM, ChaCha20-Poly1305
- [ ] Hash รหัสผ่านด้วย Argon2id หรือ bcrypt (ไม่ใช่ SHA-256)
- [ ] ใช้ Constant-time Comparison (ไม่ใช่ == / ===)
- [ ] คีย์ถูกเก็บใน Secret Manager หรือ HSM (ไม่ Hardcode)
- [ ] RSA Padding ใช้ OAEP เสมอ (ไม่ใช้ PKCS1v1.5 ถ้าเลี่ยงได้)
- [ ] Hash Algorithm = SHA-256 ขึ้นไป (ไม่ใช้ MD5/SHA-1)
- [ ] TLS 1.3 หรือ TLS 1.2 อย่างน้อย (ไม่ใช้ SSL/ TLS 1.0)
- [ ] ตรวจสอบ Certificate ทุกครั้งใน HTTPS Connection
- [ ] มีแผน Crypto Agility สำหรับ Post-Quantum Migration

#### 8.8.3 OWASP ASVS ที่เกี่ยวข้องกับ Cryptography

**ASVS Version 4.0.3 — Cryptographic Architecture:**

| ข้อ | รายการ | Level |
|-----|--------|:-----:|
| 6.2.1 | Algorithm ต้องเป็น FIPS-approved หรือ NIST-recommended | L1 |
| 6.2.2 | มีการจัดการ Key Lifecycle | L2 |
| 6.2.3 | ใช้ CSPRNG สำหรับสร้าง Key และ Nonce | L2 |
| 6.2.4 | Padding Mode ถูกต้อง (OAEP สำหรับ RSA) | L2 |
| 6.2.5 | ใช้ Authenticated Encryption (GCM, ChaCha20-Poly1305) | L3 |
| 6.2.6 | Key Rotation มีกลไกอัตโนมัติ | L3 |
| 6.2.7 | สามารถเปลี่ยน Algorithm ได้ง่าย (Crypto Agility) | L3 |
| 6.2.8 | มี Post-Quantum Migration Plan | L3 |

---

## Keywords

Cryptography, AES, GCM, ChaCha20, RSA, ECC, ECDSA, Ed25519, Digital Signature, Hash, SHA-256, SHA-3, HMAC, PKI, X.509, Certificate Authority, Key Management, Post-Quantum, Kyber, Dilithium, Crypto Agility, Authenticated Encryption, Perfect Forward Secrecy

---

## กิจกรรมปฏิบัติการ

### Lab 8.1: ใช้ Python Cryptography Library
- ติดตั้ง `cryptography` library
- เข้ารหัส AES-GCM ด้วย key ขนาด 256 bits
- Sign และ Verify ข้อความด้วย ECDSA P-256
- Hash ข้อความด้วย SHA-256 และ HMAC-SHA256
- ตรวจสอบความแตกต่างระหว่าง Encryption, Hashing, และ Encoding

### Lab 8.2: เปรียบเทียบ AES-ECB กับ AES-GCM
- เข้ารหัสภาพ (image file) ด้วย AES-ECB และ AES-GCM
- สังเกต Pattern ที่เหลืออยู่ใน AES-ECB ที่ทำให้เห็นโครงสร้างภาพเดิม
- เปรียบเทียบผลลัพธ์และอธิบายว่าเหตุใด ECB จึงไม่ปลอดภัย

### Lab 8.3: Key Exchange ด้วย ECDH
- สร้าง Key Pair สำหรับ Alice และ Bob ด้วย X25519
- คำนวณ Shared Secret ผ่าน ECDH Exchange
- ใช้ HKDF เพื่อสร้าง AES Key จาก Shared Secret
- ทดลองเข้ารหัสข้อความด้วย AES-GCM โดยใช้ Key จาก ECDH

### Lab 8.4: วิเคราะห์ TLS Handshake ด้วย Wireshark
- ใช้ Wireshark จับ traffic ระหว่าง Browser กับ Server
- วิเคราะห์ TLS Handshake: Cipher Suite, Certificate Chain, Key Exchange
- ระบุ Algorithm ที่ใช้ (ECDHE, AES-GCM, SHA-384)
- ตรวจสอบว่า Server รองรับ PFS หรือไม่

---

## คำถามท้ายบท

1. ทำไมจึงห้ามใช้ ECB mode ในการเข้ารหัสข้อมูลที่มี Pattern? ยกตัวอย่างการโจมตีที่มองเห็น Pattern ได้ชัดเจน

2. AES-GCM แตกต่างจาก AES-CBC อย่างไร? ข้อดีของ GCM คืออะไร และทำไม GCM จึงเป็น Authenticated Encryption?

3. Hybrid Encryption คืออะไร? ทำไมระบบจริง (เช่น TLS, PGP) จึงใช้ทั้ง Symmetric และ Asymmetric Encryption ร่วมกัน?

4. ความแตกต่างระหว่าง hashing และ encryption คืออะไร? ยกตัวอย่างการใช้งานที่ถูกต้องของแต่ละอย่าง

5. ทำไมการใช้ HMAC จึงปลอดภัยกว่าการใช้ SHA-256 เพียงอย่างเดียวในการตรวจสอบ Integrity ของข้อมูล?

6. Post-Quantum Cryptography คืออะไร? Algorithm ใดบ้างที่ NIST เลือกเป็นมาตรฐาน และทำไมนักพัฒนาต้องเตรียมพร้อม?

7. Certificate Chain ใน PKI คืออะไร? อธิบาย Chain of Trust ตั้งแต่ Root CA จนถึง Server Certificate

8. ถ้าต้องออกแบบระบบจัดเก็บรหัสผ่านที่ปลอดภัย ควรใช้ Algorithm อะไร ต้องมี Salt หรือ Pepper หรือไม่ และทำไมถึงห้ามใช้ SHA-256 สำหรับจุดประสงค์นี้

9. Perfect Forward Secrecy (PFS) คืออะไร? Protocol ใดที่ให้ PFS และทำไม PFS จึงสำคัญต่อความปลอดภัยในระยะยาว?

10. Crypto Agility คืออะไร? นักพัฒนาควรออกแบบระบบอย่างไรให้สามารถเปลี่ยน Algorithm Cryptography ได้ง่ายเมื่อเข้าสู่ยุค Post-Quantum?

11. ถ้าพบว่ามีการ Hardcode Encryption Key ไว้ใน Source Code ของโครงการ ซอฟต์แวร์ที่เผยแพร่ไปแล้วควรดำเนินการอย่างไร?

12. Kerckhoffs's Principle กล่าวว่าอย่างไร? จงอธิบายว่าหลักการนี้เกี่ยวข้องกับแนวปฏิบัติ Don't Roll Your Own Crypto อย่างไร

---

## เอกสารอ้างอิง

1. NIST FIPS 197 — Advanced Encryption Standard (AES)
2. NIST SP 800-38D — Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC
3. NIST SP 800-57 — Recommendation for Key Management
4. NIST SP 800-63B-4 — Digital Identity Guidelines: Authentication and Lifecycle Management
5. NIST SP 800-132 — Recommendation for Password-Based Key Derivation
6. NIST IR 8413 — Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process
7. NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA) — Post-Quantum Cryptography Standards
8. RFC 8439 — ChaCha20 and Poly1305 for IETF Protocols
9. RFC 8018 — PKCS #5: Password-Based Cryptography Specification Version 2.1 (PBKDF2)
10. RFC 5869 — HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
11. RFC 7519 — JSON Web Token (JWT)
12. RFC 8032 — Edwards-Curve Digital Signature Algorithm (EdDSA)
13. RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3
14. OWASP Password Storage Cheat Sheet
15. OWASP ASVS (Application Security Verification Standard) Version 4.0.3
16. IBM Security — Cost of a Data Breach Report 2025
17. Shor, P.W. (1994) — Algorithms for Quantum Computation: Discrete Logarithms and Factoring
18. Grover, L.K. (1996) — A Fast Quantum Mechanical Algorithm for Database Search
