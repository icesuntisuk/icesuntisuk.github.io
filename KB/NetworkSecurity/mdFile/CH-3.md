# CH-3: การเข้ารหัสสำหรับ Network Security

## วัตถุประสงค์การเรียนรู้ (Learning Objectives)

เมื่อจบบทนี้แล้ว ผู้เรียนสามารถ:
1. อธิบายหลักการพื้นฐานของ Cryptography — ความแตกต่างระหว่าง Encryption, Decryption, Hashing, Digital Signature — และความสัมพันธ์กับ CIA Triad ได้
2. เปรียบเทียบการเข้ารหัสแบบ Symmetric และ Asymmetric — ข้อดี ข้อเสีย และกรณีการใช้งานที่เหมาะสม — พร้อมยกตัวอย่างอัลกอริทึมสำคัญในแต่ละประเภท
3. อธิบายการทำงานของ AES ในระดับสถาปัตยกรรม (Key Expansion, Rounds, Block Cipher Modes) และความแตกต่างระหว่าง AES-GCM, AES-CBC, AES-CTR ได้
4. อธิบายหลักการทางคณิตศาสตร์ของ RSA, ECC, และ Diffie-Hellman Key Exchange พร้อมเหตุผลที่ ECC ได้รับความนิยมมากขึ้นในปัจจุบัน
5. อธิบายบทบาทของฟังก์ชัน Hash (SHA-2, SHA-3, HMAC) ใน Network Security และความแตกต่างระหว่าง Cryptographic Hash กับ Password Hashing
6. อธิบายแนวคิด Perfect Forward Secrecy (PFS) และความสำคัญใน TLS 1.3
7. อธิบายการประยุกต์ใช้ Cryptography ใน TLS Handshake, IPsec IKEv2, และ SSH พร้อมการทำงานของ Hybrid Cryptosystem
8. อธิบายผลกระทบของ Quantum Computing ต่อ Cryptography และแนวทาง Post-Quantum Cryptography

---

## 1. หลักการพื้นฐานของ Cryptography

### 1.1 คำจำกัดความและเป้าหมาย

Cryptography (การเข้ารหัส) คือศาสตร์แห่งการเขียนและการอ่านข้อความในรูปแบบที่ปกปิดความหมาย โดยมีเป้าหมายหลัก 4 ประการที่สอดคล้องกับ CIA Triad และ AAA:

| เป้าหมาย | คำอธิบาย | ความสัมพันธ์กับ CIA/AAA |
|----------|----------|-----------------------|
| **Confidentiality** | ปกป้องข้อมูลไม่ให้ผู้ไม่ได้รับอนุญาตอ่าน — แม้จะดักจับข้อมูลระหว่างทางก็ไม่สามารถเข้าใจเนื้อหาได้ | Confidentiality |
| **Integrity** | ทำให้แน่ใจว่าข้อมูลไม่ถูกเปลี่ยนแปลงระหว่างทาง — ตรวจจับการแก้ไขได้ | Integrity |
| **Authentication** | ยืนยันตัวตนของผู้ส่งข้อมูล — รู้ว่าข้อมูลมาจากใครจริง | AAA — Authentication |
| **Non-repudiation** | ป้องกันการปฏิเสธที่มาของข้อมูล — ผู้ส่งไม่สามารถปฏิเสธว่าตนเป็นผู้ส่ง | AAA — Accountability |

### 1.2 คำศัพท์พื้นฐาน

| คำศัพท์ | คำอธิบาย |
|---------|----------|
| **Plaintext (ข้อความเดิม)** | ข้อมูลที่ยังไม่ได้เข้ารหัส — อ่านได้ตามปกติ |
| **Ciphertext (ข้อความรหัส)** | ข้อมูลที่ผ่านการเข้ารหัสแล้ว — ไม่สามารถอ่านได้ถ้าไม่มี Key |
| **Encryption (การเข้ารหัส)** | การแปลง Plaintext → Ciphertext โดยใช้ Key และ Algorithm |
| **Decryption (การถอดรหัส)** | การแปลง Ciphertext → Plaintext โดยใช้ Key และ Algorithm |
| **Key (กุญแจ)** | ค่าความลับที่ใช้ในกระบวนการ Encryption/Decryption — ความแข็งแรงของระบบขึ้นอยู่กับการรักษาความลับของ Key |
| **Cipher / Algorithm (ขั้นตอนวิธี)** | ขั้นตอนทางคณิตศาสตร์ที่กำหนดวิธีการ Encryption และ Decryption |
| **Cryptanalysis** | ศาสตร์แห่งการถอดรหัสโดยไม่ต้องมี Key — การโจมตีระบบเข้ารหัส |

### 1.3 ประวัติโดยย่อของ Cryptography

| ยุค | ลักษณะ | ตัวอย่าง | สถานะปัจจุบัน |
|-----|--------|---------|-------------|
| **Classical (โบราณ)** | แทนที่ตัวอักษรหรือสลับตำแหน่ง — ใช้มือหรือเครื่องกลอย่างง่าย | Caesar Cipher (Shift 3), Enigma Machine (WWII) | ไม่ปลอดภัย — ถอดรหัสได้ง่าย |
| **Modern (สมัยใหม่)** | ใช้หลักการทางคณิตศาสตร์และคอมพิวเตอร์ — Algorithm เปิดเผย, Key เป็นความลับ (Kerckhoffs's Principle) | AES, RSA, ECC | ใช้อยู่ในปัจจุบัน |
| **Post-Quantum (หลังควอนตัม)** | ทนทานต่อการโจมตีด้วย Quantum Computer | CRYSTALS-Kyber, CRYSTALS-Dilithium | อยู่ระหว่างกระบวนการกำหนดมาตรฐาน (NIST 2024) |

### 1.4 Kerckhoffs's Principle (หลักการเคอร์คอฟฟ์)

Auguste Kerckhoffs (1883) เสนอหลักการสำคัญของระบบเข้ารหัส: **"ระบบควรจะปลอดภัยแม้ว่าทุกอย่างยกเว้น Key จะถูกเปิดเผยต่อสาธารณะก็ตาม"**

- **Algorithm เปิดเผยได้** — ระบบต้องปลอดภัยแม้ผู้โจมตีรู้ Algorithm ทุกอย่าง
- **Key เท่านั้นที่ต้องเป็นความลับ** — ความปลอดภัยขึ้นอยู่กับการรักษา Key ไม่ใช่การซ่อน Algorithm
- **เหตุผล:** การเปิดเผย Algorithm ให้ผู้เชี่ยวชาญตรวจสอบหาจุดอ่อน ทำให้ระบบแข็งแรงกว่า การซ่อน Algorithm (Security through Obscurity)

### 1.5 ประเภทของการโจมตีทาง Cryptography

| ประเภทการโจมตี | คำอธิบาย | ความยาก |
|----------------|----------|---------|
| **Brute Force** | ลอง Key ทุกค่าที่เป็นไปได้ — ป้องกันด้วย Key Size ที่มากพอ | ง่ายแต่ใช้เวลามาก |
| **Known Plaintext Attack** | ผู้โจมตีมี Plaintext + Ciphertext คู่กัน | ปานกลาง |
| **Chosen Plaintext Attack** | ผู้โจมตีเลือก Plaintext และได้ Ciphertext ที่สอดคล้อง | สูง |
| **Ciphertext Only Attack** | ผู้โจมตีมีเฉพาะ Ciphertext — ยากที่สุด | ยากมาก |
| **Side-Channel Attack** | โจมตีจากข้อมูลภายนอก — Timing, Power Consumption, EM Radiation, Sound | ต้องเข้าถึงฮาร์ดแวร์ |
| **Man-in-the-Middle** | แทรกตัวระหว่างการแลกเปลี่ยน Key — ป้องกันด้วย Certificate Authentication | ปานกลาง |

### 1.6 ระบบ Hybrid Cryptosystem

ในทางปฏิบัติ ระบบส่วนใหญ่ใช้การเข้ารหัสทั้งสองแบบร่วมกัน — **Hybrid Cryptosystem:**

```
ฝ่าย A                                      ฝ่าย B
│                                           │
├─ สร้าง Session Key (Symmetric Key) ──────┤
│   แบบสุ่มสำหรับ Session นี้                │
│                                           │
├─ เข้ารหัส Session Key ด้วย               │
│   Public Key ของ B (Asymmetric) ─────────→│
│                                           ├─ ถอดรหัส Session Key
│                                           │   ด้วย Private Key ของตน
│                                           │
├─ เข้ารหัสข้อมูลทั้งหมดด้วย                 │
│   Session Key (Symmetric) ───────────────→│
│                                           ├─ ถอดรหัสข้อมูลด้วย
│                                           │   Session Key เดียวกัน
│                                           │
│  🔑 Asymmetric = แลกเปลี่ยน Key (ช้า)      │
│  🔐 Symmetric = เข้ารหัสข้อมูล (เร็ว)       │
```

**ข้อดีของ Hybrid Cryptosystem:**
- แก้ปัญหา Key Distribution ของ Symmetric — ใช้ Asymmetric แลกเปลี่ยน Key
- ได้ประสิทธิภาพของ Symmetric สำหรับข้อมูลปริมาณมาก
- รองรับ Digital Signature และ Non-repudiation ผ่าน Asymmetric

---

## 2. การเข้ารหัสแบบ Symmetric (Symmetric Encryption)

### 2.1 หลักการทำงาน

ใช้ **Key เดียวกัน** ทั้งในการเข้ารหัสและถอดรหัส — เรียกอีกอย่างว่า Secret Key Cryptography หรือ Private Key Cryptography:

```
Plaintext + Secret Key → [Encryption] → Ciphertext
Ciphertext + Secret Key → [Decryption] → Plaintext
```

**ข้อดี:**
- เร็วและมีประสิทธิภาพสูง — เหมาะกับข้อมูลปริมาณมาก
- ใช้ทรัพยากร CPU น้อย
- Algorithm ที่ดี (เช่น AES) ใช้ Hardware Acceleration ใน CPU สมัยใหม่ (AES-NI)

**ข้อเสีย:**
- **ปัญหา Key Distribution** — ผู้ส่งและผู้รับต้องมี Key ที่เหมือนกัน การส่ง Key อย่างปลอดภัยเป็นความท้าทาย
- ไม่รองรับ Non-repudiation — Key เหมือนกันทั้งสองฝ่าย พิสูจน์ไม่ได้ว่าใครเป็นผู้สร้างข้อความ
- Scalability ต่ำ — ในระบบที่มี N คน ต้องจัดการ Key = N(N-1)/2 คู่

### 2.2 Stream Cipher vs Block Cipher

| ลักษณะ | Stream Cipher | Block Cipher |
|--------|--------------|-------------|
| **การทำงาน** | เข้ารหัสทีละ 1 บิต หรือ 1 ไบต์ — เหมือน Keystream XOR กับ Plaintext | แบ่งข้อมูลเป็น Block ขนาดคงที่ (เช่น 128 บิต) แล้วเข้ารหัสทีละ Block |
| **ความเร็ว** | เร็วมาก โดยเฉพาะใน Hardware | เร็วกว่าใน Software สมัยใหม่ (AES-NI) |
| **การใช้งาน** | IoT, Embedded Systems, การสื่อสารที่ทรัพยากรจำกัด | TLS, IPsec, Database, Disk Encryption |
| **ตัวอย่าง** | ChaCha20, RC4 (เลิกใช้แล้ว), Salsa20 | AES, DES/3DES, Twofish |
| **ข้อควรระวัง** | ห้ามใช้ Key ซ้ำเด็ดขาด (Two-Time Pad) | ต้องเลือก Mode ที่เหมาะสม (ECB ไม่ปลอดภัย) |

### 2.3 AES (Advanced Encryption Standard)

AES เป็นมาตรฐานการเข้ารหัสที่ใช้กันแพร่หลายที่สุดในโลก — รับรองโดยรัฐบาลสหรัฐฯ (FIPS 197) ในปี 2001 หลังจากแข่งขันกันระหว่าง Rijndael, Serpent, Twofish, RC6, MARS — Rijndael ชนะและกลายเป็น AES

| รายละเอียด | ค่า |
|------------|-----|
| **Block Size** | 128 บิต (16 ไบต์) |
| **Key Size** | 128, 192, หรือ 256 บิต |
| **Structure** | Substitution-Permutation Network (SPN) |
| **Rounds** | 10 (128-bit key), 12 (192-bit key), 14 (256-bit key) |
| **สถานะความปลอดภัย** | ปลอดภัย — ไม่มี Practical Attack ต่อ AES เต็ม Round |
| **Hardware Support** | AES-NI Instruction Set ใน CPU x86 สมัยใหม่ |

**สถาปัตยกรรมของ AES (ต่อ 1 Round):**

```
Plaintext Block (128 bits)
        │
        ▼
┌───────────────┐
│ AddRoundKey   │ ← XOR กับ Round Key
└───────┬───────┘
        ▼
┌───────────────┐
│ SubBytes      │ ← S-Box (16×16 ตารางแทนที่)
└───────┬───────┘
        ▼
┌───────────────┐
│ ShiftRows     │ ← เลื่อนแถว (Row 0 = ไม่เลื่อน, Row 1-3 เลื่อน 1-3)
└───────┬───────┘
        ▼
┌───────────────┐
│ MixColumns    │ ← คูณด้วย Matrix ใน GF(2^8) — ไม่มีใน Round สุดท้าย
└───────┬───────┘
        ▼
┌───────────────┐
│ AddRoundKey   │ ← XOR กับ Round Key ถัดไป
└───────┬───────┘
        ▼
   Ciphertext Block
```

**Key Expansion (การขยาย Key):**
- AES Key (128/192/256 บิต) ถูกขยายเป็น Round Keys ทั้งหมด N+1 Round (สำหรับ AES-128 = 11 Round Keys)
- แต่ละ Round Key มีขนาด 128 บิต (4 words × 32 bits)
- ใช้ RotWord, SubWord, Rcon ในการขยาย Key

### 2.4 โหมดการทำงานของ Block Cipher

Block Cipher เช่น AES สามารถทำงานได้หลายโหมด — แต่ละโหมดมีผลต่อความปลอดภัยและประสิทธิภาพ:

| โหมด | หลักการ | ข้อดี | ข้อเสีย | การใช้งาน |
|------|---------|------|---------|----------|
| **ECB** | แต่ละ Block เข้ารหัสแยกกันอิสระ | ง่าย, ทำ Parallel ได้ | **ไม่ปลอดภัย** — Block ที่เหมือนกันให้ Ciphertext เหมือนกัน — leak รูปแบบข้อมูล | **ห้ามใช้** |
| **CBC** | แต่ละ Block XOR กับ Ciphertext ก่อนหน้า | ปกปิดรูปแบบข้อมูล, มาตรฐานเก่า | ไม่ทำ Parallel (Encryption), Padding Oracle Attack | Legacy Protocols |
| **CTR** | เข้ารหัส Counter Value แล้ว XOR กับ Plaintext | ทำ Parallel ได้ทั้ง Encrypt/Decrypt, Stream-like | ต้องไม่ใช้ Nonce ซ้ำ | Disk Encryption |
| **GCM** | CTR + Authentication Tag (GMAC) | **รวม Encryption + Authentication**, Parallel, ปลอดภัย | ต้องไม่ใช้ Nonce ซ้ำ, ซับซ้อนกว่า | **แนะนำสำหรับ TLS 1.2/1.3, VPN** |
| **CCM** | CTR + CBC-MAC | รวม Encryption + Authentication | ช้ากว่า GCM (ทำ Parallel ไม่ได้) | IEEE 802.11 (Wi-Fi) |

**ECB Visualization Problem — "The ECB Penguin":**

ทำไม ECB ถึงไม่ปลอดภัย? เมื่อใช้ ECB เข้ารหัสรูปภาพที่มีพื้นที่สีเดียวกัน Block ที่มีข้อมูลเหมือนกันจะให้ Ciphertext ที่เหมือนกัน — ทำให้เห็นลวดลายของภาพต้นฉบับ:

```
รูปภาพต้นฉบับ (Plaintext)    →    รูปภาพที่เข้ารหัสด้วย ECB
[Tux (Linux Penguin)]          [ลาย Penguin ยังคงเห็นได้ชัด]
```
การทดสอบนี้แสดงให้เห็นถึงจุดอ่อนสำคัญของ ECB ได้อย่างชัดเจน — เป็นตัวอย่างการสอนคลาสสิก ที่ใช้ในการอธิบายว่าทำไม Block Cipher Mode จึงมีความสำคัญ

### 2.5 ChaCha20

ChaCha20 เป็น Stream Cipher ที่พัฒนาโดย Daniel J. Bernstein (2008) เป็นการปรับปรุงจาก Salsa20:

| คุณสมบัติ | รายละเอียด |
|-----------|-----------|
| **ผู้พัฒนา** | Daniel J. Bernstein (2008) |
| **ประเภท** | Stream Cipher |
| **Key Size** | 256 บิต |
| **โครงสร้าง** | ARX (Add-Rotate-XOR) — ทำงานบน 32-bit Words |
| **Rounds** | 20 (ChaCha20) |
| **ความเร็ว** | เร็วกว่า AES ใน Software (ไม่มี AES-NI) |
| **การใช้งาน** | TLS 1.3 (Cipher Suite: TLS_CHACHA20_POLY1305_SHA256), SSH, WireGuard, OpenVPN |

**ข้อดีของ ChaCha20 เมื่อเทียบกับ AES:**
- **เร็วกว่าใน Software** — โดยเฉพาะบนอุปกรณ์ที่ไม่มี AES-NI (มือถือ, IoT)
- **ทนต่อ Timing Side-Channel** — ไม่มี S-Box Lookup ที่อาจรั่วผ่าน Cache Timing
- **ออกแบบมาให้ปลอดภัย** — ไม่มีจุดอ่อนที่ทราบ

### 2.6 การเปรียบเทียบ Symmetric Ciphers

| อัลกอริทึม | ประเภท | Key Size | Block Size | ความเร็ว (Software) | ความปลอดภัย | สถานะ |
|-----------|--------|---------|-----------|-------------------|------------|--------|
| **AES-256-GCM** | Block (128) | 256 บิต | 128 บิต | เร็วมาก (AES-NI) | สูงมาก | ✅ แนะนำ |
| **ChaCha20-Poly1305** | Stream | 256 บิต | — | เร็วมาก (Software) | สูงมาก | ✅ แนะนำ |
| **AES-128-GCM** | Block (128) | 128 บิต | 128 บิต | เร็วมาก (AES-NI) | สูง | ✅ ปลอดภัย |
| **AES-256-CBC** | Block (128) | 256 บิต | 128 บิต | เร็ว (AES-NI) | สูง | ⚠️ ไม่มี Auth |
| **AES-128-CBC** | Block (128) | 128 บิต | 128 บิต | เร็ว (AES-NI) | สูง | ⚠️ ไม่มี Auth |
| **3DES** | Block (64) | 168 บิต | 64 บิต | ช้า | ปานกลาง | ❌ Deprecated |
| **Blowfish** | Block (64) | 32-448 บิต | 64 บิต | เร็ว | ปานกลาง | ❌ 64-bit Block |
| **Twofish** | Block (128) | 128-256 บิต | 128 บิต | เร็ว | สูง | ไม่นิยม |
| **RC4** | Stream | 40-2048 บิต | — | เร็วมาก | **ต่ำ** | ❌ **เลิกใช้** |

**แนวทางการเลือก Symmetric Cipher สำหรับ Network Security:**
- **TLS 1.3**: AES-256-GCM หรือ ChaCha20-Poly1305
- **IPsec**: AES-256-GCM
- **SSH**: ChaCha20-Poly1305 หรือ AES-256-CTR
- **Disk Encryption**: AES-256-XTS
- **Wi-Fi (WPA3)**: AES-256-GCM (CCMP)

---

## 3. การเข้ารหัสแบบ Asymmetric (Asymmetric Encryption)

### 3.1 หลักการทำงาน

ใช้ **Key สองตัว (Key Pair)** ที่สัมพันธ์กันทางคณิตศาสตร์ แต่ไม่สามารถหา Key หนึ่งจากอีก Key หนึ่งได้ในเวลาอันสมควร:

| Key | การเข้าถึง | หน้าที่ |
|-----|-----------|--------|
| **Public Key (กุญแจสาธารณะ)** | เปิดเผยต่อสาธารณะ — ทุกคนรู้ได้ | ใช้สำหรับ **Encryption** (เข้ารหัส) และ **Verification** (ตรวจสอบลายเซ็น) |
| **Private Key (กุญแจส่วนตัว)** | เก็บเป็นความลับ — เฉพาะเจ้าของเท่านั้น | ใช้สำหรับ **Decryption** (ถอดรหัส) และ **Signing** (ลงนาม) |

**การเข้ารหัส:**
```
Plaintext + Public Key → [Encryption] → Ciphertext
Ciphertext + Private Key → [Decryption] → Plaintext
```

**การลงนาม:**
```
Message + Private Key → Signature
Message + Signature + Public Key → Verify (True/False)
```

**ข้อดี:**
- **ไม่มีปัญหา Key Distribution** — Public Key เผยแพร่ได้อิสระ
- **รองรับ Digital Signature และ Non-repudiation** — Private Key มีคนเดียวเท่านั้น
- **Scalability ดี** — N คน ใช้ Key Pair แค่ N ชุด

**ข้อเสีย:**
- **ช้ามาก** — ช้ากว่า Symmetric 100-1,000 เท่า (ไม่เหมาะกับข้อมูลปริมาณมาก)
- **ใช้ทรัพยากร CPU สูง**
- **Ciphertext มีขนาดใหญ่กว่า Plaintext**
- **เสี่ยงต่อ Quantum Computer** — RSA และ ECC ถูกทำลายด้วย Shor's Algorithm

### 3.2 RSA (Rivest-Shamir-Adleman)

RSA เป็นอัลกอริทึม Asymmetric ที่ใช้กันแพร่หลายที่สุด — พัฒนาโดย Ron Rivest, Adi Shamir, และ Leonard Adleman ในปี 1977

**หลักการทางคณิตศาสตร์:**

RSA อาศัยความยากของการแยกตัวประกอบของจำนวนเฉพาะขนาดใหญ่ (Integer Factorization Problem):

```
1. เลือกจำนวนเฉพาะขนาดใหญ่ 2 ตัว: p และ q
2. คำนวณ n = p × q                     (n = Modulus — ใช้ใน Public และ Private Key)
3. คำนวณ φ(n) = (p-1)(q-1)            (Euler's Totient)
4. เลือกค่า e: 1 < e < φ(n), gcd(e, φ(n)) = 1   (Public Exponent — มักใช้ 65537)
5. คำนวณ d ≡ e^(-1) mod φ(n)         (Private Exponent)

Public Key:  (n, e)
Private Key: (n, d)

Encryption:   c = m^e mod n           (m = plaintext, c = ciphertext)
Decryption:   m = c^d mod n
```

**ความแข็งแรงของ RSA:**
- ขนาดของ n (Modulus) กำหนดความปลอดภัย
- ปัจจุบันแนะนำ **2048-4096 บิต**
- ปัจจัยที่ทำให้ RSA ถูกลดความแข็งแรง: การแยกตัวประกอบที่ดีขึ้น (GNFS), การใช้ Hardware ที่เร็วขึ้น

| RSA Key Size | เทียบ Symmetric | ปีที่ควรปลอดภัยถึง |
|-------------|-----------------|-----------------|
| 1024 บิต | 80 บิต | **เลิกใช้แล้ว** |
| 2048 บิต | 112 บิต | ประมาณ 2030 |
| 3072 บิต | 128 บิต | หลัง 2030 |
| 4096 บิต | 128-152 บิต | หลัง 2030 |

### 3.3 ECC (Elliptic Curve Cryptography)

ECC เป็นอัลกอริทึม Asymmetric ที่ใช้หลักการทางคณิตศาสตร์ของ Elliptic Curve เหนือ Finite Field — พัฒนาโดย Neal Koblitz และ Victor S. Miller (1985)

**หลักการทางคณิตศาสตร์ (โดยสังเขป):**

ECC อาศัยความยากของ Elliptic Curve Discrete Logarithm Problem (ECDLP):

```
สมการ: y² = x³ + ax + b (บน Finite Field)

Point Addition: P + Q = R (กฎของจุดบน Curve)
Scalar Multiplication: k × P = P + P + ... + P (k ครั้ง)

Public Key = Private Key × Generator Point
           = k × G

ความปลอดภัย: การหา k จาก Public Key และ G เป็น ECDLP — ยากมาก
```

**เปรียบเทียบ RSA vs ECC — Key Size ที่ความปลอดภัยเท่ากัน:**

| ความปลอดภัย (เทียบ Symmetric) | RSA Key Size | ECC Key Size | อัตราส่วน |
|------------------------------|-------------|--------------|----------|
| ปานกลาง (~80 บิต) | 1024 บิต | 160 บิต | 6.4:1 |
| สูง (~112 บิต) | 2048 บิต | 224 บิต | 9.1:1 |
| สูงมาก (~128 บิต) | 3072 บิต | 256 บิต | 12:1 |
| สูงที่สุด (~192 บิต) | 7680 บิต | 384 บิต | 20:1 |
| (~256 บิต) | 15360 บิต | 521 บิต | 29.5:1 |

**ข้อดีของ ECC เมื่อเทียบกับ RSA:**
- **Key สั้นกว่า** — 256-bit ECC ≈ 3072-bit RSA
- **เร็วกว่า** ในการสร้าง Key และ Digital Signature
- **ประหยัด Bandwidth** — Certificate เล็กกว่า
- **ประหยัดพลังงาน** — เหมาะกับ Mobile, IoT
- **Secure Enclave / TPM** รองรับ ECC

**ข้อเสียของ ECC:**
- ซับซ้อนกว่า RSA — มี Curve Parameters หลายชุดที่ต้องระวัง
- มี Curve ที่ไม่ปลอดภัย (เช่น Curve ที่ถูก NSA แทรก — Dual_EC_DRBG)
- Patent issues ในอดีต (หมดอายุแล้ว)

**Curve ที่แนะนำ:**
| Curve | ความปลอดภัย | การใช้งาน |
|-------|-------------|-----------|
| **P-256 (secp256r1)** | 128 บิต | TLS, Code Signing — **แนะนำ** |
| **P-384 (secp384r1)** | 192 บิต | US Government (SuitB) |
| **P-521 (secp521r1)** | 256 บิต | ความปลอดภัยสูงสุด |
| **Curve25519 (X25519)** | 128 บิต | **แนะนำ** — Key Exchange ใน TLS 1.3, WireGuard |
| **Ed25519** | 128 บิต | **แนะนำ** — Digital Signature ใน SSH, OpenPGP |

### 3.4 Diffie-Hellman Key Exchange (DH)

DH เป็นโปรโทคอลที่ให้สองฝ่ายสร้าง Shared Secret Key ร่วมกันผ่านช่องทางที่ไม่ปลอดภัย โดยไม่ต้องส่ง Key ไปหากัน — พัฒนาโดย Whitfield Diffie และ Martin Hellman (1976)

**ขั้นตอนการทำงานของ DH:**

```
                  Public Parameters: p (prime), g (generator)
                         └── เปิดเผยต่อสาธารณะ

    Alice                                Bob
    ─────                                ───
    เลือก a (Private Key)                เลือก b (Private Key)
    คำนวณ A = g^a mod p                  คำนวณ B = g^b mod p
              │                                   │
              └────────── A ส่งหา Bob ───────────→│
              │←───────── B ส่งหา Alice ──────────┘
              │                                   │
    s = B^a mod p                         s = A^b mod p
    = (g^b)^a mod p                      = (g^a)^b mod p
    = g^(ab) mod p                       = g^(ab) mod p
              │                                   │
              └───────── Shared Secret ───────────┘
                        s (เหมือนกัน)
```

**Elliptic Curve Diffie-Hellman (ECDH):** DH ที่ใช้ ECC — แทน g^a mod p ด้วย a × G:

```
Alice: Private Key = a, Public Key = A = a × G
Bob:   Private Key = b, Public Key = B = b × G

Shared Secret = a × B = b × A = a × b × G
```

**DH vs ECDH:**

| คุณสมบัติ | DH (Finite Field) | ECDH |
|-----------|-------------------|------|
| **ความปลอดภัยเทียบเท่า** | 2048-bit DH | 256-bit ECDH |
| **ความเร็ว** | ช้ากว่า | เร็วกว่า |
| **ขนาด Key** | ใหญ่ | เล็ก |
| **การใช้งาน** | Legacy | สมัยใหม่ — TLS 1.3 |

### 3.5 เปรียบเทียบ Asymmetric Algorithms

| อัลกอริทึม | ปัญหาคณิตศาสตร์ | Key Size (แนะนำ) | ความเร็ว Encryption | ความเร็ว Decryption | Signature Size |
|-----------|----------------|-----------------|-------------------|-------------------|---------------|
| **RSA** | Integer Factorization | 2048-4096 บิต | เร็ว | ช้า | ใหญ่ |
| **ECC (ECDSA)** | ECDLP | 256-521 บิต | เร็วมาก | เร็วมาก | เล็ก |
| **EdDSA (Ed25519)** | ECDLP (Twisted Edwards) | 256 บิต | เร็วมากที่สุด | เร็วมากที่สุด | เล็กมาก |
| **DH** | Discrete Logarithm | 2048-4096 บิต | — | — | — |
| **ECDH** | ECDLP | 256-521 บิต | — | — | — |

---

## 4. ฟังก์ชัน Hash (Hash Functions)

### 4.1 คุณสมบัติของฟังก์ชัน Hash ที่ดี

Hash Function คือฟังก์ชันที่รับ Input ขนาดเท่าใดก็ได้ และส่ง Output ขนาดคงที่ (Message Digest) — คุณสมบัติที่จำเป็นสำหรับความปลอดภัย:

| คุณสมบัติ | คำอธิบาย | ความสำคัญ |
|-----------|----------|-----------|
| **Fixed Output Size** | Input ขนาดเท่าใดก็ได้ → Output ขนาดคงที่ (เช่น SHA-256 = 256 บิต = 32 ไบต์) | จำเป็น |
| **Deterministic** | Input เดียวกัน → Output เหมือนกันเสมอ | จำเป็น |
| **Pre-image Resistance (One-Way)** | ไม่สามารถหา Input ที่ให้ Hash Output ที่กำหนดได้ — "One-Way Function" | **สำคัญมาก** |
| **Second Pre-image Resistance** | ไม่สามารถหา Input อื่นที่ให้ Hash Output เดียวกับ Input ที่กำหนดได้ | **สำคัญมาก** |
| **Collision Resistance** | ไม่สามารถหา Input 2 Input ใดๆ ที่ให้ Hash Output เดียวกัน | **สำคัญมาก** |

### 4.2 การประยุกต์ใช้ฟังก์ชัน Hash

| การใช้งาน | คำอธิบาย | ตัวอย่าง |
|-----------|----------|---------|
| **Password Storage** | เก็บ Hash ของ Password แทน Password จริง — ถ้าฐานข้อมูลรั่ว Password ยังปลอดภัย | ใช้ **bcrypt, argon2, PBKDF2** (ไม่ใช่ SHA-256 เฉยๆ) |
| **File Integrity** | ตรวจสอบว่าไฟล์ไม่ถูกเปลี่ยนแปลง — เปรียบเทียบ Hash ก่อนและหลังส่ง | SHA-256 Checksum |
| **Digital Signature** | Hash ข้อความก่อนเซ็น — เซ็นเฉพาะ Hash (ประหยัดเวลา) | ECDSA + SHA-256 |
| **Blockchain** | แต่ละ Block มี Hash ของ Block ก่อนหน้า — ทำให้แก้ไขประวัติไม่ได้ | Bitcoin (SHA-256) |
| **HMAC** | Hash + Secret Key — ตรวจสอบ Authentication + Integrity | API Authentication |
| **Message Integrity** | ตรวจสอบว่าข้อความไม่ถูกเปลี่ยนแปลงระหว่างทาง | TLS Record Layer |
| **Deduplication** | ตรวจสอบไฟล์ซ้ำ — เปรียบเทียบ Hash | Backup Systems |

### 4.3 อัลกอริทึม Hash ที่สำคัญ

| อัลกอริทึม | Output Size | โครงสร้าง | ปัจจุบันปลอดภัย? | หมายเหตุ |
|-----------|------------|-----------|----------------|---------|
| **MD5** | 128 บิต | Merkle-Damgård | ❌ **Collision Attack สำเร็จ** | เลิกใช้ — สร้างไฟล์ 2 ไฟล์ที่มี MD5 เดียวกันได้ |
| **SHA-1** | 160 บิต | Merkle-Damgård | ❌ **SHAttered (2017)** — Collision Attack 110,000 USD | เลิกใช้ — Google + CWI สร้าง Collision จริง |
| **SHA-256** | 256 บิต | Merkle-Damgård | ✅ ปลอดภัย | มาตรฐานปัจจุบัน — TLS, Blockchain, Code Signing |
| **SHA-384** | 384 บิต | Merkle-Damgård | ✅ ปลอดภัย | US Government |
| **SHA-512** | 512 บิต | Merkle-Damgård | ✅ ปลอดภัย | ความปลอดภัยสูง |
| **SHA-3-256** | 256 บิต | **Sponge Construction (Keccak)** | ✅ ปลอดภัย | มาตรฐานล่าสุด — NIST 2015 |
| **SHA-3-512** | 512 บิต | Sponge Construction (Keccak) | ✅ ปลอดภัย | อนาคต |
| **BLAKE3** | 256 บิต (ขยายได้) | Merkle Tree + HAIFA | ✅ ปลอดภัย | เร็วมาก — Parallel |

**กรณีศึกษา: SHA-1 Collision (SHAttered — 2017)**

ในเดือนกุมภาพันธ์ 2017 Google และ CWI Amsterdam ประกาศความสำเร็จในการสร้าง SHA-1 Collision ครั้งแรก:
- ใช้เวลาในการคำนวณ: ~6,500 ปี CPU (9 quintillion SHA-1 computations)
- แต่สามารถทำ Parallel ได้ — ใช้เวลา Real-World ≈ 110,000 USD (GPU + Cloud)
- ผลกระทบ: ทำให้ SHA-1 ถูกยกเลิกการใช้งานเร็วขึ้น — Certificate Authorities ห้ามออก SHA-1 Signed Certificate ในปี 2017
- **บทเรียน:** อัลกอริทึม Hash ที่ "คิดว่าปลอดภัย" อาจไม่ปลอดภัยเสมอไป — ต้องติดตามความก้าวหน้าของ Cryptanalysis

### 4.4 SHA-3 (Keccak Sponge Construction)

SHA-3 เป็นมาตรฐานล่าสุดของ NIST (FIPS 202 — 2015) ซึ่งแตกต่างจาก SHA-1 และ SHA-2 อย่างสิ้นเชิง:

**Sponge Construction (แทน Merkle-Damgård):**

```
Input ──────────────►┌─────────────────────────────┐
                     │    Sponge Construction       │
                     │  ┌───────────────────────┐  │
                     │  │   f (1600-bit State)  │  │
                     │  └───────────────────────┘  │
                     │  ┌──── Absorbing ────────┐  │
                     │  │ XOR Input Block → f   │  │
                     │  └───────────────────────┘  │
                     │  ┌──── Squeezing ────────┐  │
                     │  │ Output Block ← f     │  │
                     │  └───────────────────────┘  │
                     └─────────────────────────────┘
                              │
                              ▼
                          Output (Hash)
```

**ข้อดีของ Sponge Construction:**
- **ทนต่อ Length Extension Attack** — SHA-2 เสี่ยง (HMAC แก้ปัญหานี้), SHA-3 ทนโดยธรรมชาติ
- **ยืดหยุ่น** — Output Size ปรับได้ตามต้องการ
- **แตกต่างจาก SHA-2** — ถ้า SHA-2 ถูกโจมตี SHA-3 ยังปลอดภัย (Diversity)

### 4.5 HMAC (Hash-based Message Authentication Code)

HMAC ใช้ฟังก์ชัน Hash ร่วมกับ Secret Key เพื่อให้ทั้ง **Authentication** (ยืนยันตัวตนผู้ส่ง) และ **Integrity** (ตรวจสอบว่าข้อมูลไม่ถูกเปลี่ยนแปลง):

```
HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))

โดยที่:
H   = Hash Function (SHA-256)
K   = Secret Key
K'  = Key ที่ถูกปรับขนาดให้เท่ากับ Block Size
opad = 0x5c5c5c... (Outer Padding)
ipad = 0x363636... (Inner Padding)
m   = Message
||  = Concatenation
⊕   = XOR
```

**ข้อดีของ HMAC:**
- **ทนต่อ Length Extension Attack** — ไม่เหมือน Hash-only MAC
- **Proof of Security** — พิสูจน์ทางคณิตศาสตร์แล้วว่าปลอดภัยถ้า Hash ปลอดภัย
- **ใช้งานได้กับ Hash Function ทุกประเภท**

**การใช้งาน HMAC:**
| โพรโทคอล | HMAC Variant |
|-----------|-------------|
| **TLS 1.2** | HMAC-SHA256 (สำหรับ Record Layer Integrity) |
| **TLS 1.3** | AEAD (HMAC ไม่ได้ใช้แยก — AEAD รวม Encryption + Auth ไว้ด้วยกัน) |
| **IPsec** | HMAC-SHA256-128 |
| **SSH** | HMAC-SHA256 |
| **API Authentication** | HMAC-SHA256 (AWS Signature V4) |

### 4.6 Cryptographic Hash vs Password Hashing

**สำคัญ:** การ Hash Password **ไม่ควรใช้ SHA-256 เพียงอย่างเดียว** — ต้องใช้ Algorithm ที่ออกแบบมาเฉพาะ:

| คุณสมบัติ | Cryptographic Hash (SHA-256) | Password Hashing (bcrypt, argon2) |
|-----------|---------------------------|----------------------------------|
| **ความเร็ว** | **เร็วมาก** — ออกแบบให้เร็ว | **ช้า** — ออกแบบให้ช้าโดยตั้งใจ |
| **Parallel** | GPU/ASIC Friendly — เร็วเป็นล้านเท่า | ยากต่อการทำ Parallel (Memory Hard) |
| **Salt** | ไม่จำเป็น (แต่ใช้ได้) | **จำเป็น** — ป้องกัน Rainbow Table |
| **การปรับความเร็ว** | ไม่มี | **Adjustable Work Factor** — ทำให้ช้าตาม Hardware ในอนาคต |
| **ตัวอย่าง** | SHA-256, SHA-3 | bcrypt (Blowfish-based), PBKDF2, **argon2** (แนะนำล่าสุด) |
| **การใช้งาน** | Integrity, Signature, HMAC | Password Storage |

---

## 5. Digital Signature

### 5.1 หลักการทำงาน

Digital Signature ใช้ Asymmetric Encryption **แบบกลับด้าน** — ลงนามด้วย Private Key ตรวจสอบด้วย Public Key:

**การลงนาม (Signing):**

```
1. Hash(Message) → Digest                         (ย่อขนาดข้อความ)
2. Digest + Private Key → Signature               (เข้ารหัส Digest ด้วย Private Key)
```

**การตรวจสอบ (Verification):**

```
1. Signature + Public Key → Digest1               (ถอดรหัส Signature)
2. Hash(Message) → Digest2                          (Hash ข้อความใหม่)
3. เปรียบเทียบ Digest1 == Digest2?                  (ถ้าเท่ากัน → Signature ถูกต้อง)
```

### 5.2 ทำไมต้อง Hash ก่อนเซ็น?

- **ประหยัดเวลา** — การเซ็นข้อมูลขนาดใหญ่ด้วย Asymmetric ช้ามาก — Hash ทำให้ข้อมูลเล็กลง (256 บิต)
- **เพิ่มความปลอดภัย** — Hash Function ทำลายโครงสร้างของข้อมูล — ป้องกันการโจมตีทางคณิตศาสตร์
- **Signing คือการเข้ารหัส Digest ด้วย Private Key** — "Encrypt with Private Key, Decrypt with Public Key"

### 5.3 สิ่งที่ Digital Signature ให้

| คุณสมบัติ | คำอธิบาย |
|-----------|----------|
| **Authentication** | ยืนยันว่าผู้ส่งคือเจ้าของ Private Key จริง — ตรวจสอบด้วย Public Key |
| **Integrity** | ตรวจสอบว่าข้อมูลไม่ถูกเปลี่ยนแปลง — ถ้าข้อมูลเปลี่ยน Hash จะเปลี่ยน → Signature ไม่ตรง |
| **Non-repudiation** | ผู้ส่งไม่สามารถปฏิเสธได้ว่าตนเป็นผู้ส่ง — Private Key มีเจ้าของคนเดียว |

### 5.4 อัลกอริทึม Digital Signature

| อัลกอริทึม | Key Type | ขนาด Signature | ความเร็ว | การใช้งานหลัก |
|-----------|---------|---------------|---------|-------------|
| **RSA Signature** | RSA (2048-4096) | ~256-512 ไบต์ | ปานกลาง | PKI, TLS, Code Signing, Document Signing |
| **ECDSA (P-256)** | ECC (256) | ~64 ไบต์ | เร็ว | TLS, Bitcoin (ECDSA/secp256k1) |
| **ECDSA (P-384)** | ECC (384) | ~96 ไบต์ | ปานกลาง | US Government |
| **EdDSA (Ed25519)** | Twisted Edwards Curve (256) | **~64 ไบต์** | **เร็วที่สุด** | SSH, OpenPGP, TLS 1.3 |
| **EdDSA (Ed448)** | Goldilocks Curve (448) | ~114 ไบต์ | เร็ว | High Security |
| **DSA** | DSA (1024-3072) | ~40-56 ไบต์ | ช้า | **Legacy** — เลิกใช้ |

**EdDSA (Ed25519):**
- พัฒนาโดย Daniel J. Bernstein (2011) — ทีมเดียวกับ ChaCha20
- **เร็วมาก** — เร็วกว่า ECDSA หลายเท่า
- **ปลอดภัย** — ออกแบบให้ทนต่อ Side-Channel โดยธรรมชาติ
- **Key เล็ก** — Public Key 32 ไบต์, Signature 64 ไบต์
- **Constant-Time** — ไม่รั่วไหลข้อมูลผ่าน Timing
- **การใช้งานที่เพิ่มขึ้น:** SSH default key type (OpenSSH 8.0+), TLS 1.3, OpenPGP

### 5.5 Sign then Encrypt (แนวทางปฏิบัติ)

ในการส่งข้อมูลที่ต้องการทั้ง Authentication (เซ็น) และ Confidentiality (เข้ารหัส) ต้องทำ **Sign แล้ว Encrypt**:

```
ส่งข้อมูลที่ปลอดภัย:
1. ผู้ส่ง: Sign ข้อความด้วย Private Key
2. ผู้ส่ง: Encrypt (ข้อความ + Signature) ด้วย Public Key ของผู้รับ
3. ผู้รับ: Decrypt ด้วย Private Key ของตนเอง — ได้ข้อความ + Signature
4. ผู้รับ: Verify Signature ด้วย Public Key ของผู้ส่ง

ส่ง → Alice Sign → Alice Encrypt → Bob Decrypt → Bob Verify → Bob
```

---

## 6. Perfect Forward Secrecy (PFS)

### 6.1 ปัญหาที่ PFS แก้ไข

ในการเข้ารหัสแบบดั้งเดิม (RSA Key Exchange):

```
บันทึก Session 1 (วันนี้)         Private Key เซิร์ฟเวอร์ถูกขโมย (พรุ่งนี้)
        │                                  │
        ▼                                  ▼
        ├── ใช้ RSA เข้ารหัส Session Key ──┤
        │   Session Key อยู่ใน Traffic     │
        │   ที่บันทึกไว้                     │
        └─────────────────────────────────→ สามารถถอดรหัส Session 1 ได้
                                           เพราะรู้ Private Key
```

**ถ้าไม่มี PFS:** การรั่วไหลของ Private Key ทำให้ **ทุก Session ในอดีต** ถูกถอดรหัสได้ทั้งหมด

### 6.2 แนวคิด PFS

PFS รับประกันว่า **Key การเข้ารหัสของแต่ละ Session (Session Key)** ไม่เกี่ยวข้องกับ Private Key ระยะยาว:

```
Session A (EDCHE):
├── เซิร์ฟเวอร์สร้าง Ephemeral Key Pair (a, aG) — ใช้เฉพาะ Session A
├── ไคลเอนต์สร้าง Ephemeral Key Pair (b, bG) — ใช้เฉพาะ Session A
└── Session Key = a × bG = b × aG

Session B (EDCHE):
├── สร้าง Ephemeral Key Pair ใหม่หมด — ไม่เกี่ยวข้องกับ Session A
└── Session Key ใหม่ — ถึงรู้ Session Key A ก็ถอดรหัส Session B ไม่ได้

เมื่อ Private Key ระยะยาวรั่ว:
├── Session A: 🔒 ปลอดภัย (Ephemeral Key ถูกทิ้งไปแล้ว)
├── Session B: 🔒 ปลอดภัย
└── เฉพาะ Session อนาคตที่อาจถูกโจมตี (แต่จะใช้ Ephemeral Key ใหม่)
```

### 6.3 DHE vs ECDHE

| ประเภท | Key Exchange | ความเร็ว | การใช้งาน |
|--------|-------------|---------|----------|
| **DHE** (Diffie-Hellman Ephemeral) | DH ปกติ แต่สร้าง Key Pair ใหม่ทุก Session | ช้า (FFDHE ขนาดใหญ่ 2048-4096) | TLS 1.2 (optional) |
| **ECDHE** (Elliptic Curve Diffie-Hellman Ephemeral) | ECDH แต่สร้าง Key Pair ใหม่ทุก Session | **เร็ว** (P-256) | **TLS 1.2 (recommended), TLS 1.3 (required)** |

### 6.4 PFS ใน TLS

| เวอร์ชัน TLS | PFS | รายละเอียด |
|-------------|-----|-----------|
| **TLS 1.0** | ❌ ไม่มี | ใช้ RSA Key Exchange — ถ้า Private Key รั่ว ถอดรหัสทุก Session ได้ |
| **TLS 1.1** | ❌ ไม่มี | เช่นเดียวกับ TLS 1.0 |
| **TLS 1.2** | ⚠️ Optional | สามารถใช้ ECDHE ได้ แต่ไม่บังคับ — Cipher Suite ขึ้นอยู่กับการ Config |
| **TLS 1.3** | ✅ **Required** | **ทุกระบบต้องใช้ ECDHE** — ไม่มี RSA Key Exchange อีกต่อไป |

---

## 7. การประยุกต์ใช้ Cryptography ใน Network Security

### 7.1 TLS Handshake (1.3)

TLS 1.3 Handshake (แบบย่อ — 1 Round Trip):

```
Client                          Server
  │                                │
  ├── ClientHello ────────────────→│
  │   Key Share (ECDHE Public Key) │
  │   Cipher Suites, Extensions    │
  │                                │
  │←── ServerHello ───────────────┤
  │   Key Share (ECDHE Public Key) │
  │   Cipher Suite ที่เลือก         │
  │   Certificate + Signature      │
  │   CertificateVerify            │
  │                                │
  │←── Finished ──────────────────┤
  │   (Server ใช้ Session Key      │
  │    เข้ารหัส Finished Message)  │
  │                                │
  ├── Finished ──────────────────→│
  │   (Client ใช้ Session Key      │
  │    เข้ารหัส Finished Message)  │
  │                                │
  ╞════════════════════════════════╡
  │   ● Authentication: Certificate (Asymmetric)  │
  │   ● Key Exchange: ECDHE (สร้าง Session Key)   │
  │   ● Bulk Encryption: AES-256-GCM (Symmetric)  │
  │   ● PFS: ✅ บังคับ                            │
  ╘════════════════════════════════╛
```

**Cipher Suite ใน TLS 1.3 (ตัวอย่าง):**
```
TLS_AES_256_GCM_SHA384
├── TLS = Protocol
├── AES_256_GCM = Symmetric Encryption (AES-256 ใน GCM Mode)
└── SHA384 = Key Derivation Function

TLS_CHACHA20_POLY1305_SHA256
├── TLS = Protocol
├── CHACHA20_POLY1305 = Stream Cipher + Authentication
└── SHA256 = Key Derivation Function
```

### 7.2 IPsec (IKEv2)

IPsec ใช้ Cryptography หลายรูปแบบใน IKEv2 (Internet Key Exchange):

| ขั้นตอน | Cryptography ที่ใช้ |
|---------|-------------------|
| **1. IKE_SA_INIT** | Diffie-Hellman (สร้าง Shared Secret), Nonce |
| **2. IKE_AUTH** | Digital Signature (RSA/ECDSA) หรือ PSK — ตรวจสอบตัวตน |
| **3. Create Child SA** | DH (อาจใช้ใหม่), สร้าง Key สำหรับ ESP |
| **4. ESP (Data)** | AES-256-GCM (Encryption + Authentication) |

**ESP Packet Structure:**
```
┌─────────────────────────────────────────────────────────────┐
│ SPI (Security Parameter Index) — 4 ไบต์                     │
├─────────────────────────────────────────────────────────────┤
│ Sequence Number — 4 ไบต์                                    │
├─────────────────────────────────────────────────────────────┤
│ Payload Data (เข้ารหัสด้วย AES-GCM)                         │
│  └── Original IP Packet หรือ IP Payload                     │
├─────────────────────────────────────────────────────────────┤
│ Padding (0-255 ไบต์)                                        │
├─────────────────────────────────────────────────────────────┤
│ ICV (Integrity Check Value) — HMAC-SHA256 หรือ GCM Auth Tag │
└─────────────────────────────────────────────────────────────┘
```

### 7.3 SSH

SSH ใช้ Cryptography ที่คล้ายกับ TLS แต่เน้น ChaCha20 และ Ed25519:

| ขั้นตอน | Cryptography ที่ใช้ |
|---------|-------------------|
| **Key Exchange** | ECDH (Curve25519) — สร้าง Shared Secret |
| **Server Authentication** | Ed25519 Signature — ตรวจสอบ Host Key |
| **User Authentication** | Ed25519 Signature (SSH Key), หรือ Password |
| **Session Encryption** | ChaCha20-Poly1305 หรือ AES-256-CTR + HMAC |
| **Integrity** | Poly1305 หรือ HMAC-SHA256 |

**ความแตกต่างสำคัญระหว่าง SSH กับ TLS:**
- SSH ไม่มี PKI — ใช้ Trust on First Use (TOFU): ครั้งแรกที่เชื่อมต่อ ระบบจะบันทึก Host Key และเตือนถ้าเปลี่ยน
- SSH Certificate Authority ก็มี — แต่ไม่บังคับ (OpenSSH CA)

### 7.4 สรุปการประยุกต์ใช้ Cryptography

| โพรโทคอล | Key Exchange | Authentication | Encryption (Bulk) | Integrity | PFS |
|-----------|-------------|---------------|-------------------|-----------|-----|
| **TLS 1.3** | ECDHE (X25519, P-256) | ECDSA, Ed25519, RSA | AES-256-GCM, ChaCha20-Poly1305 | AEAD (รวมใน Encryption) | ✅ **Required** |
| **TLS 1.2** | ECDHE, DHE, RSA | RSA, ECDSA | AES-GCM, AES-CBC, ChaCha20-Poly1305 | HMAC หรือ AEAD | ⚠️ Optional |
| **IPsec IKEv2** | DH (14-16, ECDH) | RSA, ECDSA, PSK | AES-256-GCM | HMAC-SHA256 หรือ GCM | ✅ |
| **SSH** | ECDH (Curve25519) | Ed25519, RSA | ChaCha20-Poly1305, AES-CTR | Poly1305, HMAC | ✅ |
| **WireGuard** | ECDH (Curve25519) | Ed25519 | ChaCha20-Poly1305 | Poly1305 | ✅ |

---

## 8. Post-Quantum Cryptography (PQC)

### 8.1 ทำไม Quantum Computer ถึงเป็นภัยคุกคาม?

| Algorithm | ปัญหาคณิตศาสตร์ | Quantum Algorithm | ผลกระทบ |
|-----------|----------------|-------------------|---------|
| **RSA** | Integer Factorization | **Shor's Algorithm** | ❌ **ถูกทำลาย — Polynomial Time** |
| **ECC (ECDSA, ECDH)** | ECDLP | **Shor's Algorithm** | ❌ **ถูกทำลาย — Polynomial Time** |
| **DH (Finite Field)** | Discrete Logarithm | **Shor's Algorithm** | ❌ **ถูกทำลาย — Polynomial Time** |
| **AES-256** | — | Grover's Search | ⚠️ ลดความปลอดภัยเหลือ 128 บิต (เพิ่ม Key Size เป็น 2x) |
| **SHA-256** | — | Grover's Search | ⚠️ ลด Collision Resistance (ใช้ Output 2x) |

**แนวโน้ม:** RSA-2048 ต้องใช้ ~4,000 Logical Qubits — ปัจจุบัน Quantum Computer มี ~1,000 Logical Qubits — ประมาณการว่า RSA จะถูกทำลายใน 10-20 ปี แต่ **"Harvest Now, Decrypt Later"** เป็นภัยคุกคามแล้ว

### 8.2 NIST Post-Quantum Cryptography Standardization

NIST เริ่มกระบวนการมาตรฐาน PQC ในปี 2016 — ในปี 2024 NIST ได้ประกาศมาตรฐานที่เลือกแล้ว:

| Algorithm | ประเภท | ใช้แทน | สถานะ |
|-----------|--------|--------|--------|
| **CRYSTALS-Kyber** | KEM (Key Encapsulation Mechanism) | RSA Key Exchange, ECDH | ✅ **Selected (FIPS 203)** |
| **CRYSTALS-Dilithium** | Digital Signature | RSA Sign, ECDSA, EdDSA | ✅ **Selected (FIPS 204)** |
| **FALCON** | Digital Signature | สำหรับกรณีที่ Signature Size เล็ก | ✅ **Selected (FIPS 205)** |
| **SPHINCS+** | Digital Signature | Stateless Hash-based (ไม่มี Trapdoor) | ✅ **Selected (FIPS 205)** |
| **Classic McEliece** | KEM | ปลอดภัยมากแต่ Key ใหญ่ | ⏳ Finalist (ยังพิจารณา) |

**การเปลี่ยนผ่าน (Migration Timeline):**
- ปัจจุบัน: Hybrid Mode (PQC + Traditional) — เช่น X25519Kyber768 ใน TLS 1.3
- Google เริ่มทดลอง X25519Kyber768 ใน Chrome 2023
- CNSA 2.0 (NSA) กำหนดให้ใช้ PQC สำหรับ US Government Systems ภายในปี 2030

---

## 9. การโจมตี Cryptography ที่สำคัญในประวัติศาสตร์

| การโจมตี | ปี | สิ่งที่ถูกโจมตี | วิธีการ | บทเรียน |
|-----------|-----|--------------|--------|---------|
| **Heartbleed (CVE-2014-0160)** | 2014 | OpenSSL (TLS) | Buffer Over-read — อ่าน Memory เซิร์ฟเวอร์ — ขโมย Private Key | Open Source Security, การ Review Code สำคัญ |
| **POODLE (CVE-2014-3566)** | 2014 | SSL 3.0 | Padding Oracle Attack — ถอดรหัส HTTP Cookies จาก TLS 1.0 | Protocol Downgrade อันตราย |
| **ROCA (CVE-2017-15361)** | 2017 | RSA Key (YubiKey, TPM, Smart Card) | ช่องโหว่ในการสร้าง Prime Number ของ Infineon — แยก Factor Key 768-bit ได้ | การสร้าง Key ที่ถูกต้องสำคัญ |
| **DROWN (CVE-2016-0800)** | 2016 | TLS + SSLv2 | ใช้ SSLv2 ที่เปิดอยู่เพื่อถอดรหัส TLS | Cross-Protocol Attack |
| **SHA-1 Collision (SHAttered)** | 2017 | SHA-1 | สร้าง Collision จริง — ใช้ GPU Cloud ~110,000 USD | Algorithm Deprecation |
| **CRIME/BEAST** | 2011-2012 | TLS Compression / CBC | Side-Channel ผ่าน Compression Ratio / IV Prediction | Information Leakage |

---

## 10. สรุปท้ายบท (Chapter Summary)

### 10.1 หลักการสำคัญ

| หัวข้อ | สรุป |
|-------|------|
| **Cryptography Basics** | 4 เป้าหมาย: Confidentiality, Integrity, Authentication, Non-repudiation — Kerckhoffs's Principle (Algorithm เปิดเผยได้, Key เท่านั้นที่เป็นความลับ) |
| **Symmetric Encryption** | Key เดียวกันทั้งเข้ารหัสและถอดรหัส — AES (FIPS 197, 128-256 bit, SPN, 10-14 Rounds), ChaCha20 (Stream, เร็วใน Software) — ต้องเลือก Block Cipher Mode ที่ปลอดภัย (GCM ➔ แนะนำ) |
| **Asymmetric Encryption** | Public/Private Key Pair — RSA (Integer Factorization, 2048-4096 bit), ECC (ECDLP, 256 bit ≈ RSA 3072), Diffie-Hellman (Key Exchange), ECDHE (PFS) |
| **Hash Functions** | One-Way, Fixed Output, Collision Resistant — SHA-256 (ปลอดภัย), SHA-3 (Sponge Construction), SHA-1/MD5 (ไม่ปลอดภัย) — HMAC เพิ่ม Authentication |
| **Digital Signature** | Sign (Private) → Verify (Public) — Authentication + Integrity + Non-repudiation — EdDSA/Ed25519 (แนะนำ), ECDSA, RSA |
| **PFS** | ECDHE — Session Key ไม่เกี่ยวข้องกับ Private Key ระยะยาว — TLS 1.3 Required — ป้องกัน "ถอดรหัสย้อนหลัง" |
| **Hybrid Cryptosystem** | Asymmetric (Key Exchange) + Symmetric (Data Encryption) — ใช้ใน TLS, IPsec, SSH |
| **Post-Quantum** | RSA, ECC ถูกทำลายด้วย Shor's Algorithm — CRYSTALS-Kyber (KEM), CRYSTALS-Dilithium (Signature) — NIST 2024 |

### 10.2 แนวทางเลือก Use Case

| Use Case | Encryption ที่แนะนำ | Key Exchange | Signature |
|----------|-------------------|-------------|-----------|
| **Web (HTTPS)** | AES-256-GCM หรือ ChaCha20-Poly1305 | ECDHE (X25519) | ECDSA (P-256) หรือ Ed25519 |
| **VPN (IPsec)** | AES-256-GCM | DH-14 หรือ ECDH | ECDSA หรือ PSK |
| **SSH (Remote Access)** | ChaCha20-Poly1305 | ECDH (Curve25519) | Ed25519 |
| **WireGuard** | ChaCha20-Poly1305 | Curve25519 | Ed25519 |
| **Code Signing** | — | — | ECDSA (P-384) หรือ Ed25519 |
| **Wi-Fi (WPA3)** | AES-256-GCM | SAE (Simultaneous Authentication of Equals) | ECDSA |

---

## คำถามทบทวน (Review Questions)

1. จงอธิบาย Kerckhoffs's Principle — เหตุใด Algorithm จึงควรเปิดเผยต่อสาธารณะ? เปรียบเทียบกับ Security through Obscurity
2. เปรียบเทียบข้อดีข้อเสียระหว่าง Symmetric (AES) และ Asymmetric (RSA, ECC) Encryption — อัลกอริทึมประเภทใดเหมาะกับข้อมูลปริมาณมาก? และใช้ใน Hybrid Cryptosystem อย่างไร?
3. AES มีสถาปัตยกรรมอย่างไร? จงอธิบายแต่ละขั้นตอนของ AES Round (SubBytes, ShiftRows, MixColumns, AddRoundKey) และความแตกต่างระหว่าง AES-128, AES-192, AES-256
4. ทำไม ECB Mode จึงไม่ปลอดภัย? จงอธิบายด้วยตัวอย่าง "ECB Penguin" — และเปรียบเทียบกับ GCM, CBC, CTR Mode
5. ECC ปลอดภัยกว่า RSA ใน Key Size ที่เล็กกว่าได้อย่างไร? จงอธิบายหลักการทางคณิตศาสตร์ (ECDLP) และเปรียบเทียบ Key Size RSA vs ECC ที่ความปลอดภัยเท่ากัน
6. Perfect Forward Secrecy (PFS) คืออะไร? ทำไม TLS 1.3 จึงบังคับใช้ ECDHE — อธิบายด้วยตัวอย่าง Private Key รั่วไหล
7. SHA-1 Collision (SHAttered 2017) สอนบทเรียนอะไรเกี่ยวกับการใช้ฟังก์ชัน Hash? ปัจจุบันควรใช้อัลกอริทึม Hash อะไร?
8. เปรียบเทียบ Cryptographic Hash (SHA-256) กับ Password Hashing (bcrypt, argon2) — ทำไมการ Hash Password ถึงไม่ควรใช้ SHA-256 เพียงอย่างเดียว?
9. TLS 1.3 Handshake ใช้ Cryptography กี่ประเภท — อะไรบ้าง — ในแต่ละขั้นตอน?
10. Post-Quantum Cryptography คืออะไร? อัลกอริทึมใดที่ถูกคัดเลือกโดย NIST และใช้แทน RSA/ECC ได้?

---

## เอกสารอ้างอิง (References)

### มาตรฐานและกรอบการทำงาน
1. NIST FIPS 197. (2001). *Advanced Encryption Standard (AES)*.
2. NIST FIPS 202. (2015). *SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions*.
3. NIST FIPS 186-5. (2023). *Digital Signature Standard (DSS)*.
4. NIST SP 800-38D. (2007). *Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)*.
5. NIST SP 800-56A Rev. 3. (2018). *Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography*.
6. NIST SP 800-57 Part 1 Rev. 5. (2020). *Recommendation for Key Management*.
7. NIST IR 8413. (2024). *Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process*.
8. Bernstein, D. J. (2008). *ChaCha, a variant of Salsa20*.

### ตำราหลัก
9. Stallings, W. (2022). *Cryptography and Network Security: Principles and Practice* (8th ed.). Pearson.
10. Ferguson, N., Schneier, B., & Kohno, T. (2010). *Cryptography Engineering*. Wiley.
11. Paar, C., & Pelzl, J. (2010). *Understanding Cryptography*. Springer.
12. Kaufman, C., Perlman, R., & Speciner, M. (2022). *Network Security: Private Communication in a Public World* (3rd ed.). Addison-Wesley.

### รายงานและกรณีศึกษา
13. Google & CWI. (2017). *SHAttered: The First SHA-1 Collision*. https://shattered.io/
14. RFC 8446. (2018). *The Transport Layer Security (TLS) Protocol Version 1.3*.
15. RFC 5246. (2008). *The Transport Layer Security (TLS) Protocol Version 1.2*.
16. RFC 7296. (2014). *Internet Key Exchange Protocol Version 2 (IKEv2)*.
17. RFC 4253. (2006). *The Secure Shell (SSH) Transport Layer Protocol*.
18. CVE-2014-0160 (Heartbleed). https://heartbleed.com/
19. CVE-2014-3566 (POODLE). *This POODLE Bites: Exploiting The SSL 3.0 Fallback*.

### แหล่งข้อมูลเพิ่มเติม
20. NIST Post-Quantum Cryptography. https://csrc.nist.gov/projects/post-quantum-cryptography
21. IETF Crypto Forum. https://datatracker.ietf.org/wg/cfrg/about/
22. ECRYPT CSA. *Algorithms, Key Size and Protocols Report (2024)*. https://www.ecrypt.eu.org/
23. Latacora. (2018). *The Newest Hope for Network Crypto: The Snowden-era Crypto That's Now Mainstream*.

---

*เอกสารนี้เป็นส่วนหนึ่งของรายวิชา Network Security | ภาคเรียนที่ 1 ปีการศึกษา 2569*
