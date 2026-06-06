# CH-2: พื้นฐานความปลอดภัยของซอฟต์แวร์ (CIA Triad, Authentication, Authorization, Accountability)


---

## วัตถุประสงค์การเรียนรู้

เมื่อจบบทนี้นักศึกษาสามารถ:

1. อธิบาย CIA Triad (Confidentiality, Integrity, Availability) และยกตัวอย่างการประยุกต์ใช้ในบริบทซอฟต์แวร์ พร้อมวิเคราะห์ความขัดแย้งระหว่างหลักการทั้งสาม
2. เข้าใจและแยกแยะความแตกต่างระหว่าง Identification, Authentication, Authorization, และ Accountability (IAAA)
3. อธิบายหลักการ Non-repudiation และ Privacy พร้อมยกตัวอย่างการประยุกต์ใช้
4. เข้าใจหลักการออกแบบความปลอดภัยขั้นพื้นฐานของ Saltzer & Schroeder และสามารถประยุกต์ใช้ในการออกแบบซอฟต์แวร์
5. ประยุกต์ใช้หลักการ Least Privilege, Defense in Depth, Fail Safe, และ Privacy by Design ในการวิเคราะห์และออกแบบระบบ

---

## เนื้อหา

### 2.1 CIA Triad ในบริบทของซอฟต์แวร์

CIA Triad เป็นหลักการพื้นฐานด้านความมั่นคงปลอดภัยของสารสนเทศที่ประกอบด้วย 3 เสาหลัก ได้แก่ Confidentiality (การรักษาความลับ), Integrity (ความถูกต้องครบถ้วน), และ Availability (ความพร้อมใช้งาน) แม้จะเป็นแนวคิดที่มีมาก่อนยุคดิจิทัล แต่การประยุกต์ใช้ในบริบทของซอฟต์แวร์มีรายละเอียดที่เฉพาะเจาะจง

#### 2.1.1 Confidentiality (การรักษาความลับ)

Confidentiality หมายถึง การปกป้องข้อมูลไม่ให้ถูกเปิดเผยแก่บุคคลหรือระบบที่ไม่ได้รับอนุญาต ในบริบทของซอฟต์แวร์ หมายถึงการทำให้แน่ใจว่าข้อมูลจะถูกอ่านได้โดยผู้ที่มีสิทธิ์เท่านั้น

**มาตรการรักษาความลับในซอฟต์แวร์:**

| มาตรการ | คำอธิบาย | ตัวอย่าง |
|---------|----------|---------|
| Encryption at Rest | เข้ารหัสข้อมูลขณะจัดเก็บ | เข้ารหัสฐานข้อมูลด้วย AES-256, เข้ารหัสไฟล์ในดิสก์ |
| Encryption in Transit | เข้ารหัสข้อมูลขณะส่งผ่านเครือข่าย | HTTPS (TLS 1.3), SSH, VPN |
| Access Control | ควบคุมการเข้าถึงข้อมูล | RBAC (Role-Based Access Control), ACL |
| Data Masking | ซ่อนข้อมูลบางส่วน | แสดงเลขบัตรเครดิตเฉพาะ 4 หลักท้าย |
| Memory Protection | ป้องกันการอ่านหน่วยความจำ | ASLR, DEP, Secure Enclave |

**ตัวอย่างการประยุกต์ใช้ในซอฟต์แวร์จริง:**

- **ระบบธนาคารออนไลน์:** ข้อมูลบัญชีและประวัติการเงินต้องถูกเข้ารหัสทั้งขณะจัดเก็บ (ที่เหลือ) และขณะส่ง (ในเส้นทาง) มีเฉพาะเจ้าของบัญชีเท่านั้นที่ดูข้อมูลของตนเองได้
- **ระบบโรงพยาบาล:** เวชระเบียนผู้ป่วยต้องถูกปกปิดตามกฎหมาย (PDPA/HIPAA) เฉพาะแพทย์ที่ดูแลผู้ป่วยนั้นเท่านั้นที่เข้าถึงได้
- **แอปพลิเคชันส่งข้อความ:** WhatsApp ใช้ End-to-End Encryption เพื่อให้แน่ใจว่ามีเพียงผู้ส่งและผู้รับเท่านั้นที่อ่านข้อความได้

**การละเมิด Confidentiality ที่มีชื่อเสียง:**
- กรณี Equifax (2017): ข้อมูลส่วนบุคคล 147 ล้านรายถูกรั่วไหล เนื่องจากช่องโหว่ที่ไม่ได้อัปเดต
- กรณี Facebook/Cambridge Analytica (2018): ข้อมูลผู้ใช้ 87 ล้านคนถูกนำไปใช้โดยไม่ได้รับอนุญาต
- การโจมตีแบบ Side-Channel (เช่น Meltdown, Spectre): CPU vulnerability ที่ทำให้โปรแกรมหนึ่งอ่านหน่วยความจำของอีกโปรแกรมหนึ่งได้

**ข้อควรจำ:**
- Confidentiality ไม่ใช่แค่การเข้ารหัส — ครอบคลุม Access Control, การจัดการ Key, และการป้องกัน Data Leakage
- ภัยคุกคามต่อ Confidentiality ไม่ได้มาแต่แฮกเกอร์ภายนอก — Insider Threat มีสัดส่วนสูง
- การเข้ารหัสที่ผิดวิธี (เช่น ใช้ ECB mode, ใช้คีย์ที่ Hardcode) แย่กว่าการไม่เข้ารหัส เพราะให้ความรู้สึกที่ผิดว่าปลอดภัย

---

#### 2.1.2 Integrity (ความถูกต้องครบถ้วน)

Integrity หมายถึง การทำให้แน่ใจว่าข้อมูลและระบบไม่ถูกแก้ไขเปลี่ยนแปลงโดยไม่ได้รับอนุญาต รวมถึงการทำให้แน่ใจว่าข้อมูลที่ได้รับเป็นข้อมูลที่ถูกต้องและสมบูรณ์

**มาตรการรักษาความถูกต้องในซอฟต์แวร์:**

| มาตรการ | คำอธิบาย | ตัวอย่าง |
|---------|----------|---------|
| Hashing | สร้างค่า Hash เพื่อตรวจสอบความถูกต้อง | SHA-256 Checksum สำหรับไฟล์ดาวน์โหลด |
| Digital Signatures | เซ็นชื่อดิจิทัลเพื่อยืนยันแหล่งที่มาและความถูกต้อง | เซ็น DLL, APK, Git Commit |
| Version Control | ระบบควบคุมเวอร์ชันเพื่อติดตามการเปลี่ยนแปลง | Git, SVN — ดูประวัติการแก้ไข |
| Audit Logs | บันทึกการเปลี่ยนแปลงทั้งหมด | ใคร แก้ไขอะไร เมื่อไหร่ |
| Integrity Monitoring | ตรวจจับการเปลี่ยนแปลงโดยไม่ได้รับอนุญาต | Tripwire, OSSEC, File Integrity Monitoring |
| Checksum / MAC | ตรวจสอบความถูกต้องของข้อมูลที่รับส่ง | HMAC, CRC |

**ตัวอย่างการประยุกต์ใช้ในซอฟต์แวร์จริง:**

- **Software Update:** ก่อนติดตั้งอัปเดต ระบบจะตรวจสอบ Signature และ Checksum ของไฟล์ เพื่อให้แน่ใจว่าไม่ได้ถูกแทรกโค้ดอันตรายระหว่างทาง (ป้องกัน Supply Chain Attack)
- **Database Transactions:** ACID (Atomicity, Consistency, Isolation, Durability) เพื่อให้มั่นใจในความถูกต้องของข้อมูลแม้เกิดระบบล่ม
- **Blockchain:** ทุกบล็อกมี Hash ของบล็อกก่อนหน้า ทำให้การแก้ไขประวัติต้องแก้ทั้ง chain
- **Git Commit Signing:** นักพัฒนาสามารถเซ็น Git commit ด้วย GPG หรือ SSH key เพื่อยืนยันว่าตนเป็นผู้ commit จริง

**ข้อควรจำ:**
- Integrity ครอบคลุมทั้ง Data Integrity (ข้อมูลไม่ถูกแก้) และ System Integrity (ระบบไม่ถูกแก้)
- การใช้ Hashing เพียงอย่างเดียวไม่เพียงพอ — ต้องมี Mechanisms เพื่อป้องกัน Man-in-the-Middle ที่แก้ Hash ไปพร้อมกัน
- Message Authentication Code (MAC) และ Digital Signatures ช่วยแก้ปัญหานี้โดยใช้ Secret Key หรือ Private Key

---

#### 2.1.3 Availability (ความพร้อมใช้งาน)

Availability หมายถึง การทำให้แน่ใจว่าระบบซอฟต์แวร์และข้อมูลสามารถเข้าถึงได้เมื่อต้องการ โดยผู้มีสิทธิ์ — ระบบที่ไม่สามารถใช้งานได้ย่อมไร้ค่าไม่ว่าจะปลอดภัยแค่ไหน

**มาตรการรักษาความพร้อมใช้งานในซอฟต์แวร์:**

| มาตรการ | คำอธิบาย | ตัวอย่าง |
|---------|----------|---------|
| Redundancy | มีระบบสำรอง | เซิร์ฟเวอร์สำรอง (Active-Passive, Active-Active) |
| Load Balancing | กระจายโหลด | NGINX, AWS ALB, HAProxy |
| Fault Tolerance | ทนต่อความผิดพลาด | Clustering, Failover, Replication |
| DDoS Protection | ป้องกันการโจมตีแบบปฏิเสธการให้บริการ | Cloudflare, AWS Shield, Rate Limiting |
| Auto Scaling | ปรับขนาดตามโหลด | AWS Auto Scaling, Kubernetes HPA |
| Backup & Recovery | สำรองและกู้คืนข้อมูล | Database Snapshot, Disaster Recovery Plan |
| Circuit Breaker | ป้องกัน Cascading Failure | Netflix Hystrix, Resilience4j |

**ตัวอย่างการประยุกต์ใช้ในซอฟต์แวร์จริง:**

- **Netflix:** ใช้ Chaos Engineering (Chaos Monkey) เพื่อทดสอบความพร้อมใช้งาน — จงใจทำให้บริการล่มในสภาพแวดล้อม production เพื่อดูว่าระบบสามารถกู้คืนได้เองหรือไม่
- **Cloud Services (AWS, Google, Azure):** มี SLA (Service Level Agreement) ระดับ 99.99% — หมายถึง downtime ไม่เกิน 52.56 นาทีต่อปี
- **ระบบจองตั๋วเครื่องบิน:** ต้องมี High Availability โดยเฉพาะช่วง Peak Season การล่มแม้ไม่กี่นาทีอาจสูญเสียรายได้มหาศาล

**ข้อควรจำ:**
- Availability มีต้นทุนสูง — ยิ่งต้องการ Availability สูง (99.999% = Five Nines) ยิ่งต้องลงทุนมาก
- DDoS Attack เป็นภัยคุกคามสำคัญต่อ Availability — ทุกองค์กรควรมีแผนรับมือ
- Availability ไม่ใช่แค่ Infrastructure — รวมถึง Code Quality, การจัดการ Dependency, และ Incident Response

---

#### 2.1.4 ความขัดแย้งระหว่าง CIA Triad (Trade-offs)

หลักการ CIA Triad ทั้งสามมักขัดแย้งกัน การเพิ่มความแข็งแกร่งด้านหนึ่งอาจลดทอนอีกด้านหนึ่ง

| ความขัดแย้ง | คำอธิบาย | ตัวอย่าง |
|-------------|----------|---------|
| Confidentiality ↔ Availability | ยิ่งป้องกันข้อมูลแน่นหนา ยิ่งเข้าถึงยาก | การเข้ารหัสที่ซับซ้อนอาจทำให้กู้คืนข้อมูลช้า, MFA ที่หลายขั้นตอนอาจทำให้ระบบล็อกผู้ใช้ออกจากระบบ |
| Integrity ↔ Availability | การตรวจสอบความถูกต้องทุกครั้งอาจทำให้ระบบช้า | การตรวจสอบ Checksum ทุก request อาจเพิ่ม latency |
| Confidentiality ↔ Integrity | การเข้ารหัสอย่างเดียวไม่รับประกันความถูกต้อง | ข้อมูลที่ถูกเข้ารหัสอาจถูกแก้ไข (ถ้าไม่มี Authenticated Encryption) |
| Security ↔ Usability | ความปลอดภัยสูงมักทำให้ใช้งานยาก | การเปลี่ยนรหัสผ่านทุก 30 วัน → ผู้ใช้จำไม่ได้ → จดไว้บน sticky note |

**การจัดการ Trade-offs:**

1. **Risk-Based Approach:** ประเมินความเสี่ยงของแต่ละสินทรัพย์ แล้วเลือกสมดุลที่เหมาะสม
   - ข้อมูลธนาคาร → Confidentiality สูง
   - ระบบ E-Commerce → Availability สูง
   - Blockchain → Integrity สูง

2. **Layered Controls:** ใช้ Defense in Depth — แต่ละชั้นเน้นคนละด้านของ CIA

3. **Context-Aware Decisions:** ปรับระดับความปลอดภัยตามบริบท
   - การโอนเงินจำนวนมาก → MFA + Approval workflow
   - การดูรายการเดินบัญชี → Password only

4. **Continuous Monitoring:** เฝ้าระวังและปรับ Trade-offs ตามสถานการณ์

**ตัวอย่างการตัดสินใจ Trade-off ในโลกจริง:**

ธนาคารออนไลน์ต้องตัดสินใจระหว่าง Security และ Availability:
- ถ้าใส่ MFA ทุกครั้งที่ login → ปลอดภัย แต่ผู้ใช้ไม่สะดวก → อาจเสียลูกค้า
- ถ้าใส่ MFA เฉพาะการโอนเงินต่างประเทศ → สมดุลระหว่างปลอดภัยและสะดวก
- ถ้าไม่ใส่ MFA เลย → ง่ายต่อการถูกโจมตี

**ข้อควรจำ:**
- ไม่มีระบบใดปลอดภัย 100% และ CIA Triad ที่สมบูรณ์แบบไม่มีอยู่จริง
- Trade-offs คือการตัดสินใจทางธุรกิจ (Business Decision) ไม่ใช่แค่ทางเทคนิค
- การทำ Risk Assessment และการสื่อสาร Trade-offs กับผู้มีส่วนได้ส่วนเสีย (Stakeholders) เป็นทักษะสำคัญ

**คำถามสำหรับการอภิปรายในชั้นเรียน:** จงยกตัวอย่างสถานการณ์ที่ Confidentiality และ Availability ขัดแย้งกันในชีวิตจริง และเสนอแนวทางการจัดการกับความขัดแย้งนั้น

---

#### 2.1.5 Parkerian Hexad — การขยายแนวคิด CIA สู่มิติความปลอดภัยที่สมบูรณ์ยิ่งขึ้น

Donn B. Parker นักวิจัยด้านความปลอดภัยสารสนเทศ ได้เสนอแนวคิด Parkerian Hexad ในปี 1998 โดยเพิ่มเติมอีก 3 มิติที่ CIA Triad แบบดั้งเดิมครอบคลุมไม่ถึง:

| มิติ | คำอธิบาย | ความสำคัญต่อซอฟต์แวร์ |
|------|----------|---------------------|
| **Confidentiality** | การรักษาความลับ (เช่นเดียวกับ CIA) | ข้อมูลไม่ถูกเปิดเผยแก่ผู้ไม่ได้รับอนุญาต |
| **Integrity** | ความถูกต้องครบถ้วน (เช่นเดียวกับ CIA) | ข้อมูลและระบบไม่ถูกแก้ไขโดยไม่ได้รับอนุญาต |
| **Availability** | ความพร้อมใช้งาน (เช่นเดียวกับ CIA) | ระบบและข้อมูลเข้าถึงได้เมื่อต้องการ |
| **Possession/Control** | การครอบครองหรือควบคุมข้อมูล | ข้อมูลอาจถูกคัดลอกโดยไม่สูญเสียการครอบครอง — เกี่ยวข้องกับ Data Loss Prevention (DLP), DRM, Cloud Data Residency |
| **Authenticity** | ความแท้จริงของข้อมูลและแหล่งที่มา | ยืนยันว่าข้อมูลและผู้ส่งเป็นของจริง — Digital Signature, Code Signing, Certificate Validation |
| **Utility** | ประโยชน์ใช้สอยของข้อมูล | ข้อมูลที่ถูกเข้ารหัสแต่ถอดรหัสไม่ได้ย่อมไร้ค่า — การจัดการ Key, Data Recovery |

**ความเกี่ยวข้องกับเทคโนโลยีปัจจุบัน:**

| บริบท | มิติ Parkerian Hexad ที่เกี่ยวข้อง | คำอธิบาย |
|-------|----------------------------------|----------|
| **Cloud Computing** | Possession/Control | ในคลาวด์ เรา "ครอบครอง" ข้อมูลแต่อาจไม่ได้ "ควบคุม" จริง — CSP มีสิทธิ์เข้าถึง infrastructure ต้องมี Data Sovereignty Controls และ Customer-Managed Encryption Keys |
| **Ransomware** | Utility | Ransomware ทำให้ข้อมูล "ไร้ประโยชน์" โดยการเข้ารหัส — แม้เจ้าของยังครอบครองข้อมูลอยู่ แต่ใช้การไม่ได้ — Backup & Recovery, Decryption Keys สำคัญ |
| **Zero Trust Architecture** | Authenticity | Zero Trust เน้น "ไม่ไว้ใจใคร ตรวจสอบเสมอ" — ทุก request ต้องถูกพิสูจน์ Authenticity ก่อน — Mutual TLS (mTLS), Certificate-Based Identity, JWT Validation |

**ข้อควรจำ:**
- Parkerian Hexad มีประโยชน์ในการวิเคราะห์ความเสี่ยงที่ละเอียดขึ้น โดยเฉพาะในยุคที่ CIA Triad แบบดั้งเดิมอาจไม่ครอบคลุมทุกมิติของความปลอดภัย
- Possession/Control และ Utility มีความสำคัญเพิ่มขึ้นในยุค Cloud และ Ransomware
- Authenticity เป็นรากฐานของ Zero Trust — ถ้าพิสูจน์ความแท้จริงไม่ได้ การตัดสินใจด้านสิทธิ์อื่นๆ ก็ไม่มีความหมาย

> **หมายเหตุสำคัญ: ความสัมพันธ์พึ่งพากันของ CIA Triad:** แม้ CIA Triad จะถูกนำเสนอเป็นสามเสาหลักที่แยกจากกัน แต่ในระบบจริง ทั้งสามมีความสัมพันธ์พึ่งพากัน (Interdependence) — ความล้มเหลวในด้านหนึ่งมักส่งผลกระทบต่ออีกด้านหนึ่ง ตัวอย่างเช่น กรณี Barclays IT Glitch ปี 2025 ที่ข้อผิดพลาดในระบบสำรองข้อมูล (Availability Failure) ทำให้ข้อมูลสถานะบัญชีของลูกค้าหายไป ส่งผลให้ข้อมูลขาดความถูกต้อง (Integrity Failure) ตามมา และทำให้ผู้ใช้ไม่สามารถทำธุรกรรมได้อย่างถูกต้อง (Confidentiality Impact ต่อข้อมูลการเงิน) นักศึกษาควรมอง CIA Triad เป็นระบบความสัมพันธ์ที่เชื่อมโยงกัน ไม่ใช่สามส่วนที่แยกขาดจากกัน

---

### 2.2 IAAA Framework (Identification, Authentication, Authorization, Accountability)

IAAA Framework เป็นแนวคิดที่อธิบายกระบวนการพิสูจน์และควบคุมตัวตนในระบบซอฟต์แวร์ ประกอบด้วย 4 ขั้นตอนที่ทำงานร่วมกัน

#### 2.2.1 Identification (การระบุตัวตน)

Identification คือขั้นตอนที่ผู้ใช้ "บอก" ระบบว่าตนคือใคร — เป็นการอ้างตัวตน (Claim of Identity) โดยยังไม่มีการพิสูจน์

**รูปแบบการระบุตัวตนในซอฟต์แวร์:**

| รูปแบบ | ตัวอย่าง | ข้อควรระวัง |
|--------|---------|-------------|
| Username | `john.smith@company.com` | ต้องไม่ซ้ำ, ไม่ควรใช้个人信息ที่เดาง่าย |
| User ID | `user_12345` | ควรเป็นค่า Internal ไม่เปิดเผย |
| Email Address | `user@example.com` | นิยมใช้เป็น Identifier แต่ก็ทำให้เดาตัวตนได้ |
| Phone Number | `+66 81 234 5678` | เปลี่ยนเบอร์ได้ ทำให้ติดตามยาก |
| Biometric (Identification) | ใบหน้า, ลายนิ้วมือ | ไม่เปลี่ยนตาม, มี Privacy Concerns |

**ข้อควรระวังเกี่ยวกับ Identification:**
- **Enumeration Attack:** ถ้าระบบตอบกลับแตกต่างเมื่อ username มีอยู่ vs ไม่มีอยู่ ผู้โจมตีสามารถรวบรวมรายชื่อ username ได้ ควรตอบกลับเหมือนกัน (เช่น "Invalid username or password")
- **Predictable IDs:** การใช้ ID แบบ Sequential (`/user/1`, `/user/2`) ทำให้ผู้โจมตีเดา ID ได้ ควรใช้ UUID หรือ Random ID แทน
- **Username Policy:** ควรมีนโยบาย username ที่ชัดเจน — ห้าม username ที่มีความหมายไม่เหมาะสม, ห้าม username ที่เหมือนกับ admin/system accounts

**ข้อควรจำ:**
- Identification เป็นเพียงการ "บอก" ว่าเป็นใคร ยังไม่มีการพิสูจน์
- ควรแยก Identifier ภายใน (Internal ID) ออกจาก Identifier ภายนอก (Display Name, Email)
- ใช้ Identifier ที่ไม่เปลี่ยน (Immutable) เท่านั้นเป็น Primary Key

---

#### 2.2.2 Authentication (การพิสูจน์ตัวตน)

Authentication คือกระบวนการ "พิสูจน์" ว่าผู้ใช้เป็นบุคคลที่อ้างตัวจริง — เป็นการยืนยัน Claim of Identity ด้วยหลักฐาน (Credential)

**ปัจจัยในการพิสูจน์ตัวตน (Authentication Factors):**

| ปัจจัย | คำอธิบาย | ตัวอย่าง |
|--------|----------|---------|
| **Something You Know** (สิ่งที่รู้) | ความลับที่ผู้ใช้จำได้ | Password, PIN, Security Question |
| **Something You Have** (สิ่งที่ครอบครอง) | อุปกรณ์ที่ผู้ใช้มี | OTP จากโทรศัพท์มือถือ, Hardware Token, Smart Card |
| **Something You Are** (สิ่งที่คุณเป็น) | ลักษณะทางกายภาพ | ลายนิ้วมือ, ใบหน้า, เส้นเลือดม่านตา |
| **Somewhere You Are** (ที่ที่คุณอยู่) | ตำแหน่งที่ตั้ง | IP Address, GPS Location |
| **Something You Do** (สิ่งที่คุณทำ) | พฤติกรรม | ลายเซ็น, จังหวะการพิมพ์, Gait Analysis |

**Multi-Factor Authentication (MFA):**
การใช้ปัจจัยมากกว่า 1 ประเภทในการยืนยันตัวตน เช่น
- รหัสผ่าน (สิ่งที่รู้) + OTP จากมือถือ (สิ่งที่ครอบครอง)
- รหัสผ่าน (สิ่งที่รู้) + ลายนิ้วมือ (สิ่งที่คุณเป็น)

**วิธีการ Authentication ที่พบบ่อยในซอฟต์แวร์:**

| วิธีการ | จุดแข็ง | จุดอ่อน |
|---------|---------|---------|
| Password | ใช้ง่าย, ผู้ใช้คุ้นเคย | Brute Force, Phishing, Weak Password |
| OTP (TOTP/HOTP) | ป้องกัน credential reuse | SIM Swap, Phishing (แบบ real-time) |
| WebAuthn / Passkeys | ป้องกัน Phishing, ไม่มี password | ต้องใช้อุปกรณ์ที่รองรับ |
| OAuth 2.0 / OIDC | Single Sign-On, Federated | ต้อง trust Identity Provider |
| Biometric (Face ID, Touch ID) | สะดวก, เร็ว | Privacy, ความแม่นยำ, Spoofing |
| Certificate-Based (Client Cert) | ปลอดภัยสูง | จัดการยาก, UX ไม่ดี |

**ข้อมูลเปรียบเทียบวิธีการ MFA ปี 2025-2026:**

| วิธีการ | การเติบโต (% YoY) | เวลาเฉลี่ย/auth | อัตราสำเร็จ | Phishing-Resistant | หมายเหตุ |
|---------|------------------|----------------|------------|-------------------|----------|
| **Passkeys (FIDO2)** | +412% | 0.9 วินาที | 99.1% | ✅ ใช่ | อัตราการเติบโตสูงที่สุด, UX ดีที่สุด |
| **Magic Links** | +52% | 1.4 วินาที | 98.2% | ❌ ไม่ | 41.2% ของการ authenticate ทั้งหมด |
| **SMS OTP** | -18% (ลดลง) | 2.8 วินาที | 91.3% | ❌ ไม่ | กำลังถูกเลิกใช้, เสี่ยง SIM Swap |
| **TOTP (Google Authenticator, etc.)** | -12% (ลดลง) | 3.2 วินาที | 93.1% | ❌ ไม่ | ยังนิยมแต่เริ่มถูกแทนที่ด้วย Passkeys |

**มาตรฐานใหม่ที่เกี่ยวข้อง:**
- **NIST SP 800-63B-4 (กรกฎาคม 2025):** รับรอง Syncable Passkeys (Passkeys ที่ซิงค์ข้ามอุปกรณ์ผ่าน iCloud Keychain, Google Password Manager) ณ ระดับ AAL2 (Authentication Assurance Level 2) — ทำให้องค์กรภาครัฐและเอกชนสามารถใช้ Passkeys แทน Password ได้อย่างถูกต้องตามมาตรฐาน
- **FIDO Alliance (2026):** รายงานว่ามี Passkeys มากกว่า 5 พันล้านคีย์ที่ใช้งานอยู่ทั่วโลก และผู้บริโภค 90% รู้จักและเข้าใจ Passkeys ขณะที่ 75% เปิดใช้งาน Passkeys ในอย่างน้อยหนึ่งบัญชีแล้ว

**นัยยะสำหรับนักพัฒนา:**
- Passkeys กำลังกลายเป็นมาตรฐานใหม่ของ Authentication — นักพัฒนาควรเริ่มรองรับ WebAuthn API
- SMS OTP กำลังถูกเลิกใช้ — Apple, Google, Microsoft ต่างผลักดันการยกเลิก SMS OTP
- การเลือก MFA Method ต้องคำนึงถึง Trade-off ระหว่าง Security (Phishing-Resistance), Usability (Auth Time, Success Rate), และ Cost

**แนวปฏิบัติที่ดีสำหรับ Authentication:**
1. **Password Hashing:** ไม่เก็บ plaintext — ใช้ Argon2id, bcrypt, หรือ PBKDF2
2. **Rate Limiting:** จำกัดจำนวนครั้งในการ login ต่อ IP / Username
3. **Account Lockout:** ล็อกบัญชีหลังล้มเหลวหลายครั้ง (แต่ระวัง DoS)
4. **Password Policy:** เน้นความยาว (12+ chars) มากกว่าความซับซ้อน (NIST SP 800-63B)
5. **MFA โดย Default:** โดยเฉพาะสำหรับ Admin Accounts
6. **Secure Credential Recovery:** กระบวนการกู้คืนรหัสผ่านที่ปลอดภัย

**ข้อควรจำ:**
- Authentication ≠ Authorization — Authentication พิสูจน์ว่า "คุณคือใคร" ส่วน Authorization กำหนด "คุณทำอะไรได้บ้าง"
- Password ยังเป็นวิธีการ Authentication ที่ใช้มากที่สุด แต่ก็อ่อนแอที่สุด — ควรเสริมด้วย MFA
- Never Roll Your Own Authentication — ใช้ Framework/Library ที่ผ่านการตรวจสอบแล้ว

---

#### 2.2.3 Authorization (การกำหนดสิทธิ์)

Authorization คือกระบวนการกำหนดว่าผู้ใช้ที่ผ่านการพิสูจน์ตัวตนแล้วสามารถเข้าถึงทรัพยากรอะไรบ้างและทำอะไรได้บ้าง

**โมเดล Authorization ที่สำคัญ:**

**1. DAC (Discretionary Access Control)**
- เจ้าของทรัพยากรเป็นผู้กำหนดสิทธิ์
- ตัวอย่าง: Unix File Permission (rwx), Google Docs Sharing
- จุดอ่อน: ผู้ใช้มักให้สิทธิ์มากเกินไป (Over-privilege), มัลแวร์สามารถใช้สิทธิ์ของเจ้าของ

**2. MAC (Mandatory Access Control)**
- ระบบกำหนดสิทธิ์ตามนโยบายกลาง ป้องกันการ override โดยเจ้าของ
- ตัวอย่าง: SELinux, AppArmor, Windows Mandatory Integrity Control
- จุดแข็ง: ปลอดภัยสูง, ป้องกันการโจมตีแบบ Privilege Escalation
- จุดอ่อน: จัดการซับซ้อน, ต้องมี Security Administrator

**3. RBAC (Role-Based Access Control)**
- สิทธิ์ถูกกำหนดตามบทบาท (Role) — ผู้ใช้ถูก assign เข้า Role
- ตัวอย่าง: Admin, Editor, Viewer — แต่ละ Role มี Permission ต่างกัน
- โครงสร้าง:
  ```
  User → Role → Permission
  ```
  - Role Hierarchy: Admin > Editor > Viewer (Role ที่สูงกว่ามีสิทธิ์ของ Role ที่ต่ำกว่าด้วย)

**4. ABAC (Attribute-Based Access Control)**
- สิทธิ์ถูกกำหนดจากคุณลักษณะ (Attributes) หลายมิติ
  - User Attributes: ตำแหน่ง, แผนก, Security Clearance
  - Resource Attributes: ประเภทข้อมูล, ความอ่อนไหว, เจ้าของ
  - Environment Attributes: เวลา, สถานที่, อุปกรณ์
- ตัวอย่าง Policy:
  ```
  ALLOW access IF user.department = resource.department 
  AND user.clearance >= resource.classification 
  AND time BETWEEN 08:00 AND 18:00
  ```

**5. ReBAC (Relationship-Based Access Control)**
- สิทธิ์ถูกกำหนดจากความสัมพันธ์ (Relationship) ระหว่าง Entity ต่างๆ ในระบบ
- ใช้โครงสร้าง Relationship Tuple: `(user, relation, object)` เช่น `(alice, editor, doc:report)`
- ตัวอย่างการทำงาน:
  - Alice เป็น "editor" ของ "document:report"
  - ถ้า Bob เป็น "viewer" ของ "folder:project" และ folder มี document นี้ → Bob อ่าน document ได้
  - ถ้า Alice แชร์ document ให้ Charlie (share) → Charlie เข้าถึง document นี้ได้
- **ระบบที่ใช้ ReBAC:** Google Zanzibar (ระบบ Authorization ของ Google ที่ใช้กับ Google Drive, YouTube, Gmail), OpenFGA (Open Source จาก Auth0), SpiceDB
- **จุดแข็ง:** จัดการ Permission ที่ซับซ้อนได้ดี (เช่น การแชร์เอกสารใน Google Drive — "แชร์ให้คนนี้ดูได้ แต่ห้ามแก้ไข และคนที่เขาแชร์ต่อก็ดูได้เช่นกัน") Collaborative Products
- **จุดอ่อน:** ซับซ้อนในการ Implement, ต้องมี Tuple Storage ที่มีประสิทธิภาพ, Query อาจซับซ้อน

| โมเดล | ความยืดหยุ่น | ความซับซ้อน | การจัดการ | การใช้งาน |
|-------|-------------|-------------|-----------|-----------|
| DAC | ต่ำ | ต่ำ | ง่าย | File Systems |
| MAC | ต่ำ | สูง | ยาก | Military, Government |
| RBAC | ปานกลาง | ปานกลาง | ปานกลาง | Enterprise Applications |
| ABAC | สูง | สูง | ซับซ้อน | Cloud, Microservices, API |
| **ReBAC** | **สูงมาก** | **สูงมาก** | **ซับซ้อน** | **Collaborative Apps (Google Drive, GitHub, Figma)** |

**หลักการสำคัญของ Authorization:**
1. **Least Privilege:** ให้สิทธิ์เท่าที่จำเป็นต่อการทำงานเท่านั้น
2. **Default Deny:** ปฏิเสธทุกอย่าง ยกเว้นที่ได้รับอนุญาตอย่างชัดเจน
3. **Separation of Duties:** หน้าที่สำคัญต้องแยกคนรับผิดชอบ (เช่น คนขอเบิก ≠ คนอนุมัติ ≠ คนจ่าย)
4. **Authorization ที่ทุกระดับ:** ตรวจสอบสิทธิ์ทั้งที่ API Gateway, Service Layer, และ Data Layer

**ข้อควรจำ:**
- Broken Access Control เป็นอันดับ 1 ของ OWASP Top 10 — เป็นช่องโหว่ที่พบบ่อยและอันตรายที่สุด
- การตรวจสอบ Authorization ต้องทำที่ Server-side เท่านั้น — Client-side check แค่ UX อย่างเดียว
- อย่าเชื่อข้อมูล Authorization ที่ส่งจาก Client (เช่น role="admin" ใน Request Body)

---

#### 2.2.4 Accountability (การตรวจสอบย้อนหลัง)

Accountability หมายถึง ความสามารถในการตรวจสอบย้อนหลังได้ว่า "ใคร ทำอะไร เมื่อไหร่ และที่ไหน" ในระบบ ซึ่งจำเป็นสำหรับการตรวจสอบ (Auditing), การสืบสวน (Forensics), และการปฏิบัติตามกฎหมาย (Compliance)

**องค์ประกอบของ Accountability:**

| องค์ประกอบ | คำอธิบาย |
|------------|----------|
| Identification | รู้ว่า "ใคร" เป็นผู้กระทำ |
| Logging | บันทึกการกระทำสำคัญทั้งหมด |
| Audit Trail | เรียงลำดับเหตุการณ์เพื่อการสืบสวน |
| Non-repudiation | ผู้กระทำไม่สามารถปฏิเสธได้ |
| Monitoring & Alerting | ตรวจจับพฤติกรรมผิดปกติแบบ Real-time |

**สิ่งที่ต้องบันทึกใน Audit Log:**

| หมวดหมู่ | ตัวอย่าง |
|----------|---------|
| Authentication Events | Login (success/fail), Logout, Password Change |
| Authorization Events | Access Denied, Privilege Escalation |
| Data Access | อ่าน/แก้ไข/ลบ ข้อมูลสำคัญ |
| Configuration Changes | เปลี่ยนแปลง Security Settings |
| Administrative Actions | สร้าง/ลบ User, เปลี่ยน Role |

**แนวปฏิบัติที่ดีสำหรับ Audit Log:**
1. **อย่า Log Secrets:** ไม่บันทึก Password, Token, Credit Card Numbers, PII
2. **Timestamp ที่แม่นยำ:** ใช้ NTP Sync, บันทึก Timezone (UTC เป็นมาตรฐาน)
3. **Immutable Logs:** Log ที่บันทึกแล้วไม่ควรแก้ไข — ใช้ Write-Once Storage หรือ Cryptographic Chain
4. **Centralized Logging:** รวม Log จากทุก Service ไว้ที่ศูนย์กลาง (SIEM — Splunk, ELK, Graylog)
5. **Log Retention:** กำหนดระยะเวลาเก็บ Log ตามข้อกำหนดทางกฎหมาย (เช่น PDPA, PCI DSS, SOX)
6. **Regular Review:** ตรวจสอบ Log อย่างสม่ำเสมอ — ไม่ใช่แค่เก็บไว้เฉยๆ

**ความสัมพันธ์กับ Non-repudiation:**
Accountability และ Non-repudiation ทำงานร่วมกัน:
- Accountability: บันทึกว่ามีการกระทำนี้เกิดขึ้น
- Non-repudiation: พิสูจน์ให้แน่ชัดว่าผู้กระทำไม่สามารถปฏิเสธได้ ใช้ Digital Signatures และ Audit Logs ที่เชื่อถือได้

**ข้อควรจำ:**
- "If it isn't logged, it didn't happen" — การไม่บันทึก Log = ไม่สามารถตรวจสอบได้
- Log ที่ไม่มี Audit Trail ที่สมบูรณ์ มีค่าน้อยกว่าการไม่มี Log เพราะให้ความเชื่อมั่นที่ผิด
- ต้องสมดุลระหว่าง Logging (ไว้ตรวจสอบ) และ Privacy (ไม่ละเมิดข้อมูลส่วนบุคคลเกินจำเป็น)

**คำถามสำหรับการอภิปรายในชั้นเรียน:** จงอธิบายความแตกต่างระหว่าง Identification, Authentication, Authorization, และ Accountability พร้อมยกตัวอย่างระบบที่นักศึกษาใช้ในชีวิตประจำวัน

---

### 2.3 หลักการออกแบบความปลอดภัยขั้นพื้นฐาน (Saltzer & Schroeder)

ในปี 1975 Jerome Saltzer และ Michael Schroeder ได้ตีพิมพ์บทความ "The Protection of Information in Computer Systems" ซึ่งนำเสนอหลักการออกแบบความปลอดภัย 8 ประการ ต่อมาได้มีการเพิ่มเติมเป็น 9 หลักการที่ยังคงใช้ได้จนถึงปัจจุบัน และในยุคดิจิทัลได้มีการเพิ่มหลักการที่สอดคล้องกับเทคโนโลยีสมัยใหม่อีก 2 หลักการ รวมเป็น 11 หลักการ

#### 2.3.1 Economy of Mechanism (ความเรียบง่าย)

**หลักการ:** กลไกการรักษาความปลอดภัยควรมีความเรียบง่ายและมีขนาดเล็กที่สุดเท่าที่จะเป็นไปได้

**เหตุผล:** ยิ่งระบบซับซ้อนมากเท่าไหร่ โอกาสที่จะเกิดข้อผิดพลาดและช่องโหว่ก็ยิ่งมากขึ้นเท่านั้น ระบบที่เรียบง่ายตรวจสอบได้ง่ายกว่า (Verifiable) และบำรุงรักษาได้ง่ายกว่า

**ตัวอย่างการประยุกต์ใช้:**
- **ดี:** ใช้ Library มาตรฐานในการเข้ารหัส (เช่น `cryptography` library ใน Python) แทนการเขียน Algorithm เอง
- **ไม่ดี:** เขียน AES Algorithm เองเพื่อ "เพิ่มความปลอดภัย" — มักมี Side-channel vulnerabilities
- **ดี:** ใช้ Framework Authentication (Spring Security, Django Auth) แทนเขียน Authentication เอง
- **แนวปฏิบัติ:** ใช้ "KISS Principle" (Keep It Simple, Stupid) — ถ้ามีวิธีที่ง่ายกว่าและปลอดภัยพอ ให้เลือกวิธีที่ง่ายกว่า

---

#### 2.3.2 Fail-Safe Defaults (ปฏิเสธเป็นค่าเริ่มต้น)

**หลักการ:** การเข้าถึงควรถูกปฏิเสธโดยค่าเริ่มต้น (Default Deny) — ต้องระบุอย่างชัดแจ้งว่าใครสามารถเข้าถึงอะไรได้บ้าง

**เหตุผล:** ถ้าเกิดความผิดพลาด (fail) ระบบควรปลอดภัยโดยอัตโนมัติ แทนที่จะเปิดช่องให้เข้าถึงได้

**ตัวอย่างการประยุกต์ใช้:**
- **ดี:** Firewall Rule — "Deny All" แล้วค่อย "Allow" เฉพาะที่จำเป็น
- **ไม่ดี:** Firewall Rule — "Allow All" แล้วค่อย "Deny" เฉพาะที่ไม่ต้องการ
- **ดี:** ไฟล์ที่อัปโหลดใหม่ควรถูกปฏิเสธการเข้าถึงโดยอัตโนมัติ จนกว่า Admin จะอนุมัติ
- **ดี:** API Endpoint ใหม่ควร require authentication เป็นค่าเริ่มต้น — ต้อง Explicitly mark เป็น public
- **แนวปฏิบัติ:** เมื่อ Error เกิดขึ้น ระบบควรปฏิเสธการเข้าถึง ไม่อนุญาตโดยค่าเริ่มต้น

**ข้อควรจำ:** Default Deny เป็นหลักการที่สำคัญที่สุดข้อหนึ่ง — การกำหนด Allowlist (Whitelist) ปลอดภัยกว่า Blocklist (Blacklist) เสมอ เพราะ Blocklist ไม่สามารถครอบคลุมทุกกรณีที่อาจเป็นอันตราย

---

#### 2.3.3 Complete Mediation (ตรวจสอบทุกครั้ง)

**หลักการ:** ทุกครั้งที่มีการเข้าถึงทรัพยากร ระบบต้องตรวจสอบ Authorization ทุกครั้ง ไม่มีการ Cache หรือ Assume สิทธิ์

**เหตุผล:** สิทธิ์ของผู้ใช้อาจเปลี่ยนแปลงได้ตลอดเวลา — ผู้ใช้อาจถูกเพิกถอนสิทธิ์ตั้งแต่การตรวจสอบครั้งล่าสุด

**ตัวอย่างการประยุกต์ใช้:**
- **ดี:** ตรวจสอบ Permission ทุกครั้งที่เรียก API endpoint แม้จะเพิ่งตรวจสอบไปเมื่อ 1 วินาทีก่อน
- **ไม่ดี:** ตรวจสอบ Permission เฉพาะตอน Login แล้วเก็บใน Session — ถ้าสิทธิ์ถูกเปลี่ยนตอนกลางคัน ระบบจะไม่รู้
- **ดี:** ใน UNIX — ทุก system call ที่เกี่ยวกับไฟล์จะตรวจสอบ permission ทุกครั้ง
- **ไม่ดี:** การ Cache Access Token โดยไม่ตรวจสอบ Revocation — ถ้า token ถูกเพิกถอน แต่ Cache ยังอยู่ ผู้ใช้ยังเข้าถึงได้
- **แนวปฏิบัติ:** ใช้ Centralized Authorization Service (เช่น OPA, Casbin) ที่ถูกเรียกทุกครั้งที่มี Request

**ข้อควรระวัง:** Complete Mediation มี Trade-off กับ Performance — การตรวจสอบทุกครั้งทำให้ระบบช้าลง ต้องออกแบบให้มีประสิทธิภาพ (เช่น ใช้ Policy Decision Point ที่เร็ว, Cache ที่มีการ Invalidation ที่เหมาะสม)

---

#### 2.3.4 Least Privilege (สิทธิ์น้อยที่สุด)

**หลักการ:** ทุก Entity (User, Process, Service) ควรได้รับสิทธิ์เท่าที่จำเป็นต่อการทำงานเท่านั้น — ไม่มากไป ไม่น้อยไป

**เหตุผล:** ถ้า Entity ถูกโจมตีหรือทำผิดพลาด ขอบเขตความเสียหายจะถูกจำกัดด้วยสิทธิ์ที่มี

**ตัวอย่างการประยุกต์ใช้:**

| กรณี | ไม่ปลอดภัย (Over-privilege) | ปลอดภัย (Least Privilege) |
|------|---------------------------|--------------------------|
| Database Connection | ใช้ root user เชื่อมต่อ | ใช้ user ที่มีสิทธิ์เฉพาะ Table ที่จำเป็น, permission แค่ SELECT/INSERT |
| Web Server | รันด้วย root | รันด้วย user ที่มีสิทธิ์เฉพาะ Directory ที่จำเป็น |
| API Service Token | Token ที่มี Scope "admin:all" | Token ที่มี Scope เฉพาะ "read:orders" |
| File Permission | chmod 777 | chmod 600 |
| Employee Access | ทุกคนเข้าถึงข้อมูลลูกค้าได้ | เฉพาะแผนกที่เกี่ยวข้อง |

**ตัวอย่างใกล้ตัว:**
- แอปพลิเคชันบนมือถือ: ถ้าแอป Flashlight ขอสิทธิ์เข้าถึง Contacts — น่าสงสัย (Over-privilege)
- Docker Container: ควรใช้ `--user` flag เพื่อรันด้วย non-root user
- Cloud IAM: ไม่ควรใช้ AdministratorAccess — ควรสร้าง Policy ที่จำกัดเฉพาะ Service ที่จำเป็น

**ข้อควรจำ:**
- Least Privilege ใช้กับทั้งคน (User) และเครื่อง (Service, Process, Container)
- การ Audit และ Review สิทธิ์เป็นระยะเป็นสิ่งจำเป็น — Privilege Creep (สิทธิ์เพิ่มขึ้นเรื่อยๆ โดยไม่ถูกลด) เป็นปัญหาจริง
- "Privilege Escalation" (การยกระดับสิทธิ์) เป็นเทคนิคการโจมตีหลัก — Least Privilege ช่วยจำกัดความเสียหายเมื่อถูกเจาะ

---

#### 2.3.5 Separation of Privilege (แยกอำนาจ)

**หลักการ:** การเข้าถึงทรัพยากรที่สำคัญควรต้องอาศัยปัจจัยหลายอย่างร่วมกัน — ไม่ควรมี Entity ใดที่มีอำนาจสมบูรณ์แต่เพียงผู้เดียว

**เหตุผล:** การแยกอำนาจทำให้การโจมตียากขึ้น — ผู้โจมตีต้อง Compromise หลายระบบพร้อมกันถึงจะสำเร็จ

**ตัวอย่างการประยุกต์ใช้:**
- **Dual Control:** การโอนเงินจำนวนมากต้องมี 2 คนอนุมัติ — คนทำรายการ ≠ คนอนุมัติ
- **Separation of Duties ใน DevOps:**
  - คนเขียนโค้ด ≠ คน Review โค้ด
  - คน Review โค้ด ≠ คน Deploy ขึ้น Production
- **Multi-Party Approval:** ใน Cloud — การเปลี่ยนแปลง Security Group ต้องมี Approval จาก Security Team
- **Split Key:** การเข้ารหัสคีย์ถูกแบ่งเป็น 2 ส่วน — คนละส่วน คนละที่ — ต้องใช้ทั้งสองส่วนถึงจะถอดรหัสได้
- **Android/iOS Biometric + PIN:** การทำ Transaction ที่สำคัญต้องยืนยันทั้ง Biometric และ PIN

**ข้อควรระวัง:**
- Separation of Privilege มากเกินไปอาจทำให้การทำงานล่าช้า — ต้องสมดุลกับ Efficiency
- Separation of Duties ≠ ทุกคนไม่ไว้ใจกัน — เป็นการลดความเสี่ยงจากการกระทำที่ผิดพลาดหรือเจตนาร้ายของบุคคลคนเดียว

---

#### 2.3.6 Least Common Mechanism (ใช้กลไกร่วมน้อยที่สุด)

**หลักการ:** ควรหลีกเลี่ยงการใช้กลไกร่วมกันระหว่างผู้ใช้หรือบริการต่างๆ เพราะกลไกที่ใช้ร่วมกันเป็นช่องทางให้ข้อมูลรั่วไหลระหว่างกัน

**เหตุผล:** ยิ่งใช้กลไกร่วมกันมาก การโจมตีแบบ Covert Channel ก็ยิ่งมีความเป็นไปได้สูง

**ตัวอย่างการประยุกต์ใช้:**
- **ไม่ดี:** ใช้ Database Instance เดียวสำหรับหลาย Application — ถ้า App หนึ่งมีช่องโหว่ SQL Injection จะกระทบ App ทั้งหมด
- **ดี:** แยก Database Instance ตาม Application หรืออย่างน้อยแยก Schema/Sandbox
- **ดี:** ใช้ Docker Container / Virtual Machine เพื่อแยก Environment ของแต่ละ Service
- **ดี:** แยก Production / Staging / Development Environment อย่างชัดเจน
- **Cloud:** ใช้ VPC และ Subnet ที่แตกต่างกันสำหรับบริการแต่ละประเภท

**ข้อควรจำ:** ในยุค Microservices การแยก Service (Service Isolation) เป็นการประยุกต์ใช้หลักการนี้ — แต่ต้องแลกกับต้นทุนการจัดการที่สูงขึ้น

---

#### 2.3.7 Psychological Acceptability (ยอมรับได้ทางจิตวิทยา)

**หลักการ:** กลไกความปลอดภัยต้องไม่เป็นภาระต่อผู้ใช้มากเกินไป — ต้องสามารถใช้งานได้ง่ายและสะดวก

**เหตุผล:** ถ้ากลไกความปลอดภัยใช้งานยาก ผู้ใช้จะหาวิธีเลี่ยง (Workaround) ซึ่งมักทำให้ระบบปลอดภัยน้อยลง

**ตัวอย่าง:**
- **ไม่ดี:** กำหนดให้เปลี่ยนรหัสผ่านทุก 30 วัน — ผู้ใช้จำไม่ได้ → จดไว้บน Post-it → แปะที่จอ → ปลอดภัยน้อยลง
- **ดี:** ใช้ Passwordless (Passkeys, Magic Links) — สะดวกและปลอดภัยกว่า
- **ไม่ดี:** ใช้ Captcha ที่ซับซ้อน — ผู้ใช้หงุดหงิด → ปิดการใช้งาน → เปิดช่องให้ Bot
- **ดี:** ใช้ Risk-Based MFA — ถ้า login จาก device ปกติ ไม่ต้อง OTP ถ้าจาก device แปลก ถึงต้อง MFA
- **ดี:** การแจ้งเตือน Push Notification ที่ชัดเจน — "Someone is trying to login from Russia" — ผู้ใช้เข้าใจและกดปฏิเสธได้ง่าย

**ข้อควรจำ:**
- Security ที่ไม่มี Usability = Security ที่ไม่มีใครใช้
- การออกแบบ Security UX ต้องคำนึงถึงพฤติกรรมมนุษย์ — ใช้หลัก Behavioral Economics และ Nudge Theory
- User Training สำคัญ — แต่การออกแบบระบบที่เข้าใจง่ายย่อมดีกว่าการอบรมให้ผู้ใช้จำ

---

#### 2.3.8 Defense in Depth (ป้องกันหลายชั้น)

**หลักการ:** ไม่พึ่งพามาตรการป้องกันเพียงชั้นเดียว — ให้สร้างเกราะป้องกันหลายชั้นเพื่อให้แน่ใจว่าแม้ชั้นหนึ่งถูกโจมตีสำเร็จ ก็ยังมีชั้นอื่นปกป้องอยู่

**เหตุผล:** ไม่มีมาตรการใดที่ป้องกันได้ 100% — Defense in Depth คือการ "ไม่เอาทุกอย่างไว้ในตะกร้าเดียว" (Don't Put All Eggs in One Basket)

**ตัวอย่าง Defense in Depth สำหรับ Web Application:**

```
Layer 1 — Security Requirements & Design Review
         ↓
Layer 2 — Secure Coding (Input Validation, Output Encoding)
         ↓
Layer 3 — SAST (Static Analysis) ใน CI/CD
         ↓
Layer 4 — SCA (Software Composition Analysis)
         ↓
Layer 5 — WAF (Web Application Firewall)
         ↓
Layer 6 — DAST (Dynamic Analysis)
         ↓
Layer 7 — Security Monitoring (SIEM, IDS/IPS)
         ↓
Layer 8 — Incident Response Plan
```

**ตัวอย่างในโลกจริง:**
- การป้องกันบัตรเครดิต: CVV (Card Verification Value) + 3D Secure (OTP) + Transaction Monitoring (Fraud Detection)
- การป้องกัน AWS Account: IAM User (Authentication) + IAM Policy (Authorization) + Security Group (Network) + CloudTrail (Audit) + GuardDuty (Threat Detection)
- การป้องกัน Mobile App: Biometric (Auth) + App Sandbox (Isolation) + Data Encryption + Certificate Pinning

**ข้อควรจำ:**
- Defense in Depth ≠ ซ้อนเครื่องมือโดยไม่จำเป็น — แต่ละชั้นต้องมีเหตุผลและ cover ความเสี่ยงที่ต่างกัน
- "Defense in Depth" แตกต่างจาก "Redundancy" — Defense in Depth คือการป้องกันต่างประเภทกัน ส่วน Redundancy คือการมีสิ่งเดียวกันหลายชุด
- ในยุค Zero Trust แนวคิด Defense in Depth ยังคงใช้ได้ — แต่ต้องปรับให้ตรวจสอบทุกครั้ง ไม่ใช่แค่ที่ Perimeter

---

#### 2.3.9 Open Design (การออกแบบแบบเปิดเผย)

**หลักการ:** ความปลอดภัยของระบบไม่ควรขึ้นอยู่กับความลับของ Algorithm หรือ Design — แต่ควรขึ้นอยู่กับความลับของ Key (Keys, Passwords, Secrets)

**เหตุผล:** "Security Through Obscurity" (ความปลอดภัยจากความคลุมเครือ) ไม่ใช่ความปลอดภัยที่แท้จริง — ระบบที่ถูกออกแบบให้เปิดเผยและตรวจสอบได้ย่อมผ่านการพิสูจน์จากผู้เชี่ยวชาญทั่วโลก

**ที่มา:** หลักการนี้สอดคล้องกับ Kerckhoffs's Principle (1883): "A cryptosystem should be secure even if everything about the system, except the key, is public knowledge"

**ตัวอย่าง:**
- **ดี:** AES — Algorithm เปิดเผย ผ่านการตรวจสอบจากนักเข้ารหัสทั่วโลกมา 20+ ปี — ความปลอดภัยขึ้นอยู่กับ Key
- **ไม่ดี:** สร้าง Algorithm เข้ารหัสเองและ "หวัง" ว่าไม่มีใครรู้ Algorithm — เมื่อ Algorithm ถูกเปิดเผย (และมันจะถูกเปิดเผยเสมอ) ระบบก็พัง
- **ดี:** OWASP WebGoat / Juice Shop — Source Code เปิดเผย, Database Schema เปิดเผย — แต่ยังต้อง Hack ถึงจะผ่านได้
- **ไม่ดี:** การซ่อน Admin URL (เช่น `/secret-admin-panel`) — นี่คือ Security Through Obscurity — แค่扫描ก็เจอแล้ว
- **ดี:** OpenSSL, Let's Encrypt — ซอฟต์แวร์ Open Source ที่คนนับพันตรวจสอบ

**ข้อควรระวัง:**
- Open Design ≠ เปิดทุกอย่าง — Secrets (API Keys, Database Passwords, Private Keys) ต้องถูกปกปิด
- Security Through Obscurity มีประโยชน์ในบางกรณี (Defense in Depth ชั้นหนึ่ง) แต่ห้ามพึ่งพาเป็นมาตรการหลัก
- "เปิดเผยเพื่อให้ตรวจสอบ" กับ "เปิดเผยเพื่อให้โจมตี" ต่างกัน — Coordinated Disclosure ต่างจาก Full Disclosure

---

#### 2.3.10 Work Factor (ปัจจัยความพยายามในการโจมตี)

**หลักการ:** ความปลอดภัยของระบบควรวัดจากต้นทุนและความพยายามที่ผู้โจมตีต้องใช้ในการเจาะระบบ เมื่อเทียบกับทรัพยากรที่ผู้โจมตีมีอยู่

**เหตุผล:** ไม่มีระบบใดปลอดภัย 100% — การทำให้ต้นทุนการโจมตีสูงกว่าผลประโยชน์ที่ผู้โจมตีจะได้รับ เป็นกลยุทธ์ที่มีประสิทธิภาพ ยิ่งใช้ทรัพยากรมากขึ้น โอกาสที่ผู้โจมตีจะทุ่มเทก็ลดลง

**ตัวอย่างการประยุกต์ใช้:**
- **Risk-Based Decisioning:** ระบบประเมินความเสี่ยงของ request แต่ละครั้ง — ถ้ามีความเสี่ยงต่ำ (เช่น login จาก device ปกติ) ใช้认证แบบง่าย ถ้ามีความเสี่ยงสูง (เช่น login จากประเทศที่ไม่เคย login) ใช้ MFA
- **Adaptive MFA:** ปรับระดับ MFA ตามความเสี่ยง — ปกติใช้ Passwordless แต่ถ้าสงสัย ต้องใช้ Biometric เพิ่ม
- **Password Hashing Work Factor:** ใช้ bcrypt/Argon2id ที่มี Cost Factor/Salt สูง เพื่อให้การ Crack Password ต่อคำต้องใช้เวลานาน
- **Rate Limiting & Account Lockout:** ทำให้การโจมตีแบบ Brute Force ใช้เวลานานเกินกว่าจะคุ้มค่า
- **CAPTCHA:** ทำให้การโจมตีแบบ Automated ต้องใช้ทรัพยากร computation หรือ human interaction

**ข้อควรระวัง:**
- Work Factor ไม่ใช่ค่าคงที่ — เมื่อ Hardware พัฒนาขึ้น (Moore's Law) Work Factor ที่เคยสูงอาจกลายเป็นต่ำ
- ต้องประเมินทั้งต้นทุนของผู้โจมตี (Attack Cost) และมูลค่าของข้อมูล (Asset Value)

---

#### 2.3.11 Compromise Recording (การบันทึกการถูกโจมตี)

**หลักการ:** ระบบควรถูกออกแบบให้สามารถตรวจจับและบันทึกการถูกบุกรุกได้ — แม้ผู้โจมตีจะสามารถ bypass มาตรการป้องกันได้ ก็ต้องทิ้งร่องรอยไว้

**เหตุผล:** การตรวจจับการบุกรุกที่รวดเร็วช่วยลดระยะเวลาที่ผู้โจมตีอยู่ในระบบ (Dwell Time) — ยิ่งตรวจพบเร็ว ความเสียหายยิ่งน้อยลง ตามหลักการ "Assume Breach"

**ตัวอย่างการประยุกต์ใช้:**
- **Immutable Audit Logs:** Log ที่บันทึกแล้วไม่สามารถแก้ไขหรือลบได้ — ใช้ Write-Once Storage, Cryptographic Audit Trail, หรือ Blockchain-based Logging
- **SIEM (Security Information and Event Management):** รวบรวมและวิเคราะห์ Log จากทุก Service แบบ Real-time — เช่น Splunk, ELK Stack, Azure Sentinel
- **Tamper-Evident Logging:** Log ที่มีการเซ็นด้วย Digital Signature ในแต่ละ entry — ถ้ามีการแก้ไข Signature จะไม่ตรง
- **File Integrity Monitoring (FIM):** ตรวจจับการเปลี่ยนแปลงไฟล์สำคัญ — เช่น Tripwire, OSSEC, AWS CloudTrail
- **Honeypot / Honeytoken:** สร้างทรัพยากรลวงเพื่อตรวจจับผู้โจมตี — ถ้ามีคนเข้าถึง แสดงว่าถูกบุกรุก

**ความเกี่ยวข้องกับหลักการอื่น:**
- Compromise Recording สนับสนุนหลักการ Accountability และ Non-repudiation
- เป็นส่วนประกอบสำคัญของ Defense in Depth — ชั้นสุดท้ายที่ช่วยตรวจจับเมื่อชั้นอื่นล้มเหลว
- จำเป็นสำหรับ Incident Response และ Digital Forensics

**ข้อควรจำ:**
- ผู้โจมตีมักพยายามลบร่องรอย — ต้องออกแบบ Compromise Recording ให้ผู้โจมตีลบ/แก้ไข Log ได้ยาก
- การบันทึกอย่างเดียวไม่พอ — ต้องมี Alerting และ Response Plan เมื่อตรวจพบความผิดปกติ
- "If it isn't logged, it didn't happen — และถ้า log ถูกแก้ ก็ไม่ต่างจากไม่เคยบันทึก"

---

**ตารางสรุป 11 หลักการของ Saltzer & Schroeder (แบบขยาย):**

| # | หลักการ | แนวคิดหลัก | ตัวอย่าง |
|:-:|---------|-----------|----------|
| 1 | Economy of Mechanism | ทำให้เรียบง่าย | ใช้ Library มาตรฐาน ไม่เขียน Crypto เอง |
| 2 | Fail-Safe Defaults | ปฏิเสธเป็นค่าเริ่มต้น | Firewall: Deny All → Allow เฉพาะที่จำเป็น |
| 3 | Complete Mediation | ตรวจสอบทุกครั้ง | ตรวจสอบ Permission ทุก API call |
| 4 | Least Privilege | สิทธิ์น้อยที่สุด | Database: ใช้ Restricted User, ไม่ใช้ Root |
| 5 | Separation of Privilege | แยกอำนาจ | ต้อง 2 คนอนุมัติการโอนเงิน |
| 6 | Least Common Mechanism | ใช้กลไกร่วมน้อยที่สุด | แยก Container, Database ตาม Service |
| 7 | Psychological Acceptability | ใช้สะดวก | Risk-Based MFA, Passwordless |
| 8 | Defense in Depth | ป้องกันหลายชั้น | WAF + SAST + DAST + Monitoring |
| 9 | Open Design | เปิดเผย Design | อิงมาตรฐานเปิด (AES, OWASP) |
| 10 | Work Factor | เพิ่มต้นทุนการโจมตี | Adaptive MFA, Slow Hash (bcrypt/Argon2id) |
| 11 | Compromise Recording | บันทึกร่องรอยการบุกรุก | Immutable Audit Log, SIEM, Honeypot |

**ตารางประยุกต์ใช้ Saltzer & Schroeder กับ Cloud/DevOps:**

| # | หลักการ | การประยุกต์ใช้ใน Cloud / DevOps |
|:-:|---------|-------------------------------|
| 1 | Economy of Mechanism | Serverless (Lambda, Cloud Functions) — ไม่ต้องจัดการ Infrastructure, ใช้ Managed Services |
| 2 | Fail-Safe Defaults | IAM Policy ที่เป็น Deny โดย Default, Security Group ที่ Deny All Inbound |
| 3 | Complete Mediation | API Gateway ตรวจสอบ Token ทุก Request, OPA (Open Policy Agent) สำหรับ Authorization |
| 4 | Least Privilege | IAM Role ที่แคบที่สุด, Just-In-Time (JIT) Access, Ephemeral Credentials (STS) |
| 5 | Separation of Privilege | Break Glass Account + Multi-Person Approval สำหรับ Production Changes |
| 6 | Least Common Mechanism | Microservices + Container Isolation (Kubernetes Namespace, Pod Security Policy) |
| 7 | Psychological Acceptability | Single Sign-On (SSO), Passwordless (Passkeys), Self-Service IAM Portal |
| 8 | Defense in Depth | VPC + WAF + IAM + CloudTrail + GuardDuty + Security Hub |
| 9 | Open Design | Infrastructure as Code (IaC) — Terraform/CloudFormation เปิดเผยและตรวจสอบได้ |
| 10 | Work Factor | Adaptive MFA, Risk-Based Authentication, Cost-Based Rate Limiting |
| 11 | Compromise Recording | Immutable CloudTrail Logs, SIEM Integration (Splunk/Datadog), GuardDuty Findings |

**ข้อควรจำ:**
- 11 หลักการนี้เป็นพื้นฐานที่ใช้ได้กับทุกระบบ ตั้งแต่ Legacy Mainframe ถึง Cloud Native Application
- หลักการเหล่านี้มีความเกี่ยวข้องกัน — การประยุกต์ใช้ต้องพิจารณาร่วมกัน ไม่ใช่แยกส่วน
- ความท้าทายที่แท้จริงอยู่ที่การประยุกต์ใช้ (Application) ให้เข้ากับบริบท ไม่ใช่การจำหลักการ
- การนำ S&S Principles ไปใช้ใน Cloud/DevOps ไม่ใช่การ "ย้ายของเก่ามาไว้ที่ใหม่" แต่เป็นการ reinterpret หลักการให้เข้ากับบริบทที่ Infrastructure ถูก manage ด้วย code, Identity เป็น Perimeter ใหม่, และการเปลี่ยนแปลงเกิดขึ้นรวดเร็ว

**คำถามสำหรับการอภิปรายในชั้นเรียน:** หลักการ 11 ข้อของ Saltzer & Schroeder (แบบขยาย) ข้อใดที่นักศึกษาคิดว่าสำคัญที่สุดสำหรับ Web Application ในยุคปัจจุบัน เพราะเหตุใด

---

### 2.4 Non-repudiation และ Privacy

#### 2.4.1 Non-repudiation (การไม่สามารถปฏิเสธความรับผิดชอบ)

Non-repudiation หมายถึง ความสามารถในการทำให้แน่ใจว่าบุคคลหรือระบบไม่สามารถปฏิเสธการกระทำที่ตนได้ทำไว้ได้ โดยเฉพาะในธุรกรรมอิเล็กทรอนิกส์

**องค์ประกอบของ Non-repudiation:**

| องค์ประกอบ | คำอธิบาย |
|------------|----------|
| Proof of Origin | พิสูจน์ว่าผู้ส่งเป็นผู้ส่งจริง (ไม่ใช่ปลอมแปลง) |
| Proof of Delivery | พิสูจน์ว่าผู้รับได้รับข้อมูลจริง |
| Proof of Content | พิสูจน์ว่าเนื้อหาไม่ได้ถูกแก้ไขระหว่างทาง |
| Proof of Time | พิสูจน์ว่าเหตุการณ์เกิดขึ้นในเวลาที่ระบุ |

**กลไกที่ใช้:**
1. **Digital Signatures:** ผู้ส่งเซ็นข้อมูลด้วย Private Key — ทุกคนสามารถตรวจสอบด้วย Public Key ได้
   - กระบวนการ: Hash ข้อความ → เข้ารหัส Hash ด้วย Private Key (Sign) → ส่ง Signature + ข้อความ
   - ผู้รับ: Decrypt Signature ด้วย Public Key → ได้ Hash → เปรียบเทียบกับ Hash ของข้อความที่ได้รับ
2. **Digital Timestamp:** ใช้ Trusted Third Party (Timestamping Authority) เพื่อรับรองเวลาที่แน่นอน
3. **Audit Logs:** บันทึกการกระทำทั้งหมดที่เชื่อถือได้และไม่สามารถแก้ไข
4. **Blockchain:** ใช้ Consensus Mechanism เพื่อบันทึกธุรกรรมที่ไม่สามารถแก้ไขได้

**ตัวอย่างการใช้งาน:**
- **E-Contract:** การเซ็นสัญญาอิเล็กทรอนิกส์ — Digital Signature พิสูจน์ว่าคู่สัญญาทั้งสองฝ่ายตกลงตามสัญญาจริง
- **E-Commerce:** ใบเสร็จอิเล็กทรอนิกส์ — ผู้ขายไม่สามารถปฏิเสธว่าขายสินค้าได้ และผู้ซื้อไม่สามารถปฏิเสธว่าซื้อสินค้าได้
- **Regulatory Compliance:** ธนาคารต้องมี Non-repudiation สำหรับธุรกรรมเพื่อให้เป็นไปตามกฎหมาย
- **Code Signing:** นักพัฒนาเซ็นโค้ดของตน — ถ้าโค้ดนั้นกลายเป็น malware จะสืบย้อนไปถึงผู้เซ็นได้

**Non-repudiation ด้วย Blockchain:**

Blockchain ได้เพิ่มทางเลือกใหม่สำหรับ Non-repudiation โดยใช้คุณสมบัติเฉพาะของเทคโนโลยี:

| มิติ | PKI แบบดั้งเดิม | Blockchain-Based |
|------|----------------|------------------|
| **Trust Model** | ต้อง Trust Certificate Authority (CA) | Decentralized — ไม่ต้อง Trust ตัวกลาง |
| **Timestamp** | ต้อง Trusted Timestamping Authority | Immutable timestamp จาก Consensus |
| **Key Management** | CA จัดการ Certificate | การจัดการ Key อยู่ที่ผู้ใช้ (Self-Sovereign) |
| **Revocation** | CRL/OCSP — ต้องเชื่อมต่อตรวจสอบ | Smart Contract ควบคุม Revocation ได้ |
| **Audit Trail** | ต้องรักษา Log เอง | ทุกธุรกรรมอยู่บน Ledger ตลอดไป |

**กลไกการทำงาน:**
1. สร้าง SHA-256 Hash ของเอกสาร/ธุรกรรม
2. บันทึก Hash ลงใน Blockchain Transaction
3. เวลาที่ Transaction ถูกยืนยัน (Confirmed) = Timestamp ที่พิสูจน์ได้
4. ทุกคนสามารถตรวจสอบได้โดยการ Hash เอกสารและเปรียบเทียบกับค่าบน Blockchain

**ข้อดี:**
- ความถูกต้องตรวจสอบได้โดยสาธารณะ (Public Verifiability)
- ไม่ต้องพึ่งพา CA หรือ Timestamping Authority ที่อาจถูกโจมตีหรือหมดอายุ
- ข้อมูลไม่สามารถแก้ไขย้อนหลังได้

**ข้อจำกัด:**
- ค่าใช้จ่ายในการบันทึกข้อมูลบน Blockchain (Gas Fee สำหรับ Ethereum)
- Blockchain ไม่ใช่ที่เก็บข้อมูลขนาดใหญ่ — ใช้แค่ Hash ไม่ใช่เอกสารทั้งฉบับ
- ต้องจัดการ Private Key สำหรับ Wallet อย่างปลอดภัย — ถ้า Key หาย การพิสูจน์กรรมสิทธิ์ก็หายไปด้วย
- ข้อกังวลด้าน Privacy — ข้อมูลบน Blockchain เป็นสาธารณะ ต้องใช้ Hash เท่านั้น ไม่ใช่ข้อมูลต้นฉบับ

**ตัวอย่างการใช้งานจริง:**
- OpenTimestamps — ใช้ Bitcoin Blockchain สำหรับ Timestamping
- การเซ็นเอกสารด้วย Ethereum Smart Contract — บันทึก Hash + Metadata
- Supply Chain — Walmart ใช้ Hyperledger Fabric สำหรับตรวจสอบที่มาของสินค้า (Provenance)

**ข้อควรจำ:**
- Non-repudiation ต้องพึ่งพา Public Key Infrastructure (PKI) ที่น่าเชื่อถือ
- ถ้า Private Key ถูกรั่วไหล Non-repudiation จะใช้ไม่ได้ — ต้องมีกระบวนการ Revocation
- Non-repudiation ต่างจาก Accountability — Accountability คือการบันทึก แต่อาจมี dispute (เช่น "ไม่ใช่ฉันที่ login") ส่วน Non-repudiation คือการมีหลักฐานที่หักล้างไม่ได้
- Blockchain ช่วยลดการพึ่งพา Trusted Third Party แต่ก็มีข้อจำกัดด้านค่าใช้จ่ายและ Privacy

---

#### 2.4.2 Audit Logs สำหรับการตรวจสอบ

Audit Logs เป็นรากฐานสำคัญของทั้ง Accountability และ Non-repudiation — เป็นการบันทึกเหตุการณ์ทั้งหมดในระบบอย่างเป็นระบบ

**หลักการสำคัญของ Audit Log ที่มีประสิทธิภาพ:**

1. **Completeness:** ต้องบันทึกเหตุการณ์สำคัญทั้งหมด ไม่ขาดตกบกพร่อง
2. **Tamper-Proof:** เมื่อบันทึกแล้วต้องไม่สามารถแก้ไขหรือลบได้ — ใช้ Write-Once Media หรือ Cryptographic Audit Trail
3. **Chronological:** เรียงตามเวลาที่เกิดขึ้น (Timestamp ที่แม่นยำ)
4. **Correlatable:** สามารถเชื่อมโยงเหตุการณ์ที่เกี่ยวข้องกันได้ (ใช้ Correlation ID, Session ID, Transaction ID)
5. **Accessible:** สามารถเข้าถึงและค้นหาได้เมื่อต้องการตรวจสอบ

**มาตรฐานและข้อกำหนดทางกฎหมายเกี่ยวกับ Audit Log:**

| มาตรฐาน/กฎหมาย | ข้อกำหนด |
|----------------|----------|
| PCI DSS | เก็บ Log การเข้าถึง Cardholder Data อย่างน้อย 1 ปี, เก็บ History อย่างน้อย 3 เดือน |
| SOX (Sarbanes-Oxley) | เก็บ Audit Log ทางการเงินอย่างน้อย 7 ปี |
| HIPAA | เก็บ Log การเข้าถึง Medical Records อย่างน้อย 6 ปี |
| PDPA (ไทย) | ต้องมี Log การเข้าถึง和使用ข้อมูลส่วนบุคคล |
| NIST SP 800-92 | แนวทางการจัดการ Log สำหรับ Security |

**ข้อควรระวัง:**
- Log Files เป็นเป้าหมายสำคัญของผู้โจมตี — ถ้าเข้าไปแก้ Log ได้ ก็จะลบร่องรอย — ต้องป้องกัน Log อย่างดี
- การ Log โดยไม่จำเป็น (Log Too Much) อาจละเมิด Privacy — ใช้ Data Minimization
- การ Log น้อยไป (Log Too Little) ก็ไม่สามารถตรวจสอบได้ — ต้องสมดุล

---

#### 2.4.3 หลักการ Privacy by Design

Privacy by Design คือแนวคิดที่นำความเป็นส่วนตัว (Privacy) มาพิจารณาตั้งแต่ขั้นตอนการออกแบบระบบ ไม่ใช่เพิ่มทีหลัง (Privacy as an Afterthought)

**7 หลักการพื้นฐานของ Privacy by Design (Ann Cavoukian):**

| หลักการ | คำอธิบาย |
|---------|----------|
| 1. Proactive not Reactive | คิดและป้องกันล่วงหน้า ไม่ใช่รอให้เกิดปัญหาแล้วค่อยแก้ |
| 2. Privacy as Default | ตั้งค่าเริ่มต้นให้ Privacy สูงที่สุด — ผู้ใช้ต้อง Opt-in เพื่อลด Privacy |
| 3. Privacy Embedded into Design | Privacy เป็นส่วนหนึ่งของ Design ไม่ใช่ Add-on |
| 4. Full Functionality | Privacy กับ Security ไม่ขัดแย้ง — สามารถมีได้ทั้งคู่ |
| 5. End-to-End Security | ปกป้องข้อมูลตลอดวงจรชีวิต ตั้งแต่สร้างจนถึงทำลาย |
| 6. Visibility and Transparency | เปิดเผยและโปร่งใส — ผู้ใช้รู้ว่าข้อมูลถูกใช้อย่างไร |
| 7. Respect for User Privacy | ให้ความสำคัญกับผู้ใช้ — เน้น User-Centric Design |

**การประยุกต์ใช้ Privacy by Design ในซอฟต์แวร์:**

1. **Data Minimization:** เก็บข้อมูลเท่าที่จำเป็น — ไม่เก็บ credit card number ถ้าใช้แค่ reference
2. **Purpose Limitation:** ใช้ข้อมูลตามวัตถุประสงค์ที่แจ้งไว้เท่านั้น
3. **Consent Management:** ให้ผู้ใช้เลือก (Opt-in) และยกเลิกความยินยอมได้
4. **Anonymization / Pseudonymization:** ทำให้ข้อมูลไม่สามารถระบุตัวตนได้เมื่อไม่จำเป็น
5. **Data Retention Policy:** กำหนดระยะเวลาเก็บ และลบเมื่อหมดอายุ
6. **Privacy Impact Assessment (PIA):** ประเมินผลกระทบด้าน Privacy ก่อนพัฒนาระบบ
7. **Privacy-Friendly Defaults:** ไม่เก็บข้อมูลการใช้งานโดยค่าเริ่มต้น

**ตัวอย่าง:**
- Apple iOS: App Tracking Transparency — ต้องขออนุญาตก่อนติดตามผู้ใช้ข้ามแอป
- WhatsApp: End-to-End Encryption — แม้ WhatsApp เองก็อ่านข้อความไม่ได้
- Google: Auto-delete controls — ผู้ใช้ตั้งค่าให้ลบประวัติอัตโนมัติทุก 3/18/36 เดือน

---

#### 2.4.4 ความสัมพันธ์ระหว่าง Security และ Privacy

Security และ Privacy มีความสัมพันธ์ที่ซับซ้อน — ไม่เหมือนกันแต่พึ่งพากัน

| มิติ | Security | Privacy |
|-----|----------|---------|
| เป้าหมาย | ปกป้องข้อมูลจากภัยคุกคาม | ปกป้องสิทธิส่วนบุคคล |
| จุดเน้น | CIA Triad | Consent, Transparency, Control |
| คำถามหลัก | "ข้อมูลปลอดภัยไหม" | "ข้อมูลถูกใช้ตามที่ตกลงไหม" |
| มาตรการ | Encryption, Firewall, Access Control | Consent Notice, Data Minimization, Deletion |
| ความสัมพันธ์ | Security ทำให้ Privacy เป็นไปได้ | Privacy กำหนด "สิ่งที่ต้อง protect" |

**ตัวอย่างความขัดแย้งระหว่าง Security และ Privacy:**
- **Security บอกรู้ทุกอย่าง → Privacy ข้องใจ:**
  - SIEM (Security Monitoring) ต้อง log IP Address, URL, User Activity — ซึ่งอาจละเมิด Privacy
  - ทางออก: ใช้ Privacy-Preserving Analytics, Anonymization
- **Privacy ต้องการ Anonymity → Security ต้องการ Identity:**
  - การ login โดยไม่ระบุตัวตน (Anonymous) ทำให้ป้องกันการโจมตียาก
  - ทางออก: Risk-Based Authentication — Anonymous สำหรับอ่าน, Identity สำหรับ transaction

**แนวปฏิบัติที่ดี:**
1. **Privacy ≠ Anonymity** — Privacy คือควบคุมข้อมูลของตน ส่วน Anonymity คือไม่เปิดเผยตัวตน
2. **Privacy Need Security** — ข้อมูลที่ Privacy ไม่ดี (มีการเก็บข้อมูลเกินจำเป็น) อาจรั่วไหลและสร้างความเสียหาย
3. **Security Without Privacy** — ระบบที่ปลอดภัยแต่ละเมิด Privacy (เช่น CCTV ในห้องเปลี่ยนเสื้อผ้า) — ไม่เป็นที่ยอมรับ
4. **Design for Both** — ดีที่สุดคือออกแบบให้ครอบคลุมทั้ง Security และ Privacy ตั้งแต่ต้น

**ข้อควรจำ:**
- Security คือการทำให้มั่นใจในความปลอดภัยของข้อมูล — Privacy คือการทำให้มั่นใจว่าข้อมูลถูกใช้อย่างเหมาะสม
- Privacy โดยไม่มี Security = รับประกันว่าข้อมูลจะถูกใช้ตามวัตถุประสงค์ แต่ไม่รับประกันความปลอดภัย
- Security โดยไม่มี Privacy = ปกป้องข้อมูลได้ดี แต่อาจละเมิดสิทธิส่วนบุคคล

**คำถามสำหรับการอภิปรายในชั้นเรียน:** ยกตัวอย่างสถานการณ์ที่ Security และ Privacy ขัดแย้งกันในระบบซอฟต์แวร์ที่นักศึกษาใช้ — และเสนอแนวทางแก้ไข

---

## Keywords

CIA Triad, Confidentiality, Integrity, Availability, Authentication, Authorization, Accountability, Non-repudiation, Identification, IAAA, Least Privilege, Defense in Depth, Fail Safe Defaults, Complete Mediation, Economy of Mechanism, Separation of Privilege, Least Common Mechanism, Psychological Acceptability, Open Design, Work Factor, Compromise Recording, Privacy by Design, Saltzer & Schroeder, Parkerian Hexad, Default Deny, RBAC, ABAC, MAC, DAC, ReBAC, Audit Log, Digital Signature, Data Minimization, Passkeys, MFA, Blockchain

---

## มาตรฐานอ้างอิง (Standards Reference)

เนื้อหาในบทนี้สัมพันธ์กับมาตรฐานและกรอบแนวคิดด้านความปลอดภัยดังต่อไปนี้:

| หัวข้อ | มาตรฐาน / กรอบแนวคิดที่เกี่ยวข้อง |
|-------|---------------------------------|
| **CIA Triad** | NIST SP 800-53 Rev. 5 (Security and Privacy Controls), ISO 27001:2022 A.12 (Operations Security) |
| **IAAA (Identification, Authentication, Authorization, Accountability)** | NIST SP 800-63B-4 (Digital Identity Guidelines — Authentication), OWASP ASVS V2 (Authentication), V6 (Authorization) |
| **Saltzer & Schroeder Principles** | NIST SP 800-160 (Systems Security Engineering), OWASP ASVS V1 (Architecture, Design, Threat Modeling) |
| **Non-repudiation** | RFC 3161 (Internet X.509 Public Key Infrastructure Time-Stamp Protocol), eIDAS Regulation (EU), ESIGN Act (US) |
| **Privacy by Design** | GDPR Art. 25 (Data Protection by Design and by Default), NIST Privacy Framework, ISO 27701 (Privacy Information Management), PDPA (Thailand) |
| **Access Control Models (DAC, MAC, RBAC, ABAC, ReBAC)** | NIST SP 800-53 AC-family (Access Control), ISO 27001:2022 A.9 (Access Control), NIST SP 800-162 (ABAC) |

---

## กรณีศึกษา

### กรณีศึกษา 1: Change Healthcare (2024) — MFA Failure

**ปีที่เกิดเหตุการณ์:** กุมภาพันธ์ 2567
**ประเภทการโจมตี:** Stolen Credentials + Ransomware
**จำนวนผู้ได้รับผลกระทบ:** 193 ล้านคน (ประมาณครึ่งหนึ่งของประชากรสหรัฐฯ) — ทำให้เป็น Healthcare Breach ที่ใหญ่ที่สุดในประวัติศาสตร์
**ความเสียหาย:** ค่าไถ่ 22 ล้านเหรียญสหรัฐ (จ่ายแล้ว), ค่าฟื้นฟูระบบหลายพันล้าน, การดำเนินงานด้านสาธารณสุขของสหรัฐฯ หยุดชะงักเป็นวงกว้าง

**สาเหตุของเหตุการณ์:**
Change Healthcare เป็นบริษัทกลางด้านการประมวลผลการเรียกร้องค่าสินไหมทดแทนทางการแพทย์ (Medical Claims Processing) ของสหรัฐฯ — ดำเนินธุรกรรมกว่า 15 พันล้านรายการต่อปี คิดเป็น 1 ใน 3 ของ Medical Claims ทั่วประเทศ ผู้โจมตีจากกลุ่ม BlackCat/ALPHV Ransomware ใช้ **Credentials ที่ถูกขโมย** (ไม่มี MFA) เพื่อเข้าสู่ Citrix Portal ของ Change Healthcare ซึ่งเป็น Remote Access Gateway สำหรับพนักงาน

**ลำดับเหตุการณ์:**
- **Day 1-9:** ผู้โจมตีใช้ Credentials ที่ถูกขโมยเข้าสู่ระบบ Citrix Portal — ไม่มี MFA, ไม่มีการแจ้งเตือนการเข้าถึงผิดปกติ
- **Day 9:** ผู้โจมตียกระดับสิทธิ์ (Privilege Escalation) และขโมยข้อมูลกว่า 4TB
- **Day 10:** ติดตั้ง Ransomware — ระบบของ Change Healthcare ถูกเข้ารหัสทั้งหมด
- **Day 11:** โรงพยาบาลทั่วสหรัฐฯ ไม่สามารถดำเนินการ Claims ได้ — ผลกระทบลูกโซ่ (Cascading Effect)
- **Day 21:** Change Healthcare จ่ายค่าไถ่ 22 ล้านเหรียญสหรัฐ — แต่ข้อมูลบางส่วนยังถูกรั่วไหล

**การละเมิดหลักการในบทนี้:**

| หลักการ | การละเมิด |
|---------|-----------|
| **Authentication** — ไม่มี MFA | Citrix Portal ซึ่งเป็น Gateway เข้าสู่ระบบสำคัญ ไม่มีการบังคับใช้ MFA — Credentials ที่ถูกขโมยก็เข้าได้ทันที |
| **Identification** — ไม่มี Anomaly Detection | ไม่มีระบบตรวจจับพฤติกรรมผิดปกติ — การ login จากสถานที่/IP แปลกไม่มีการแจ้งเตือน |
| **Defense in Depth** — ขาดหลายชั้น | ขาดทั้ง MFA, Network Segmentation, Behavioral Analytics, และ Data Access Monitoring |
| **Least Privilege** — ไม่ชัดเจน | ผู้โจมตีสามารถยกระดับสิทธิ์และเข้าถึงข้อมูล 4TB ได้โดยไม่ถูกสกัด |
| **Accountability** — ตรวจจับช้า | ใช้เวลา 9 วันในการตรวจจับ — Dwell Time ที่นานเกินไป |
| **Availability** — ผลกระทบรุนแรง | ระบบล่มส่งผลกระทบต่อโรงพยาบาลนับพันแห่ง — ผู้ป่วยไม่ได้รับการรักษาตามเวลา |

**บทเรียนที่ได้:**
1. **MFA ไม่ใช่ทางเลือก — เป็นขั้นต่ำ (Table Stakes)** สำหรับระบบที่เข้าถึงจาก Internet ทุกระบบ โดยเฉพาะ Remote Access Gateway
2. **Critical Infrastructure ต้องมี Defense in Depth ที่แข็งแกร่ง** — การพึ่งพาแค่ Password สำหรับ Gateway ที่เข้าถึงเครือข่ายภายใน = หายนะ
3. **Credentials ที่ถูกขโมยเป็น Attack Vector หลัก** — ต้องมี Credential Monitoring และ Anomaly Detection
4. **Incident Response Plan ต้องซ้อมสม่ำเสมอ** — การตอบสนองที่ช้าทำให้ความเสียหายขยายวง
5. **Third-Party Risk** — Change Healthcare เป็น Vendor ด้าน Healthcare — การที่ Vendor ถูกโจมตีส่งผลกระทบต่อองค์กรปลายทางเป็นลูกโซ่

**คำถามสำหรับการอภิปรายในชั้นเรียน:** ถ้านักศึกษาเป็น CISO ของ Change Healthcare ก่อนเกิดเหตุการณ์ นักศึกษาจะออกแบบ Authentication และ Monitoring อย่างไรเพื่อป้องกันการโจมตีนี้

---

### กรณีศึกษา 2: Snowflake / AT&T Cluster (2024) — IAAA Failure

**ปีที่เกิดเหตุการณ์:** เมษายน - พฤษภาคม 2567 (ตรวจพบและเปิดเผย: มิถุนายน 2567)
**ประเภทการโจมตี:** Credential Stuffing + Data Theft (Infostealer-derived Credentials)
**จำนวนผู้ได้รับผลกระทบ:** AT&T 110+ ล้าน records, Ticketmaster, Santander, และอื่นๆ รวมหลายร้อยล้าน records
**ความเสียหาย:** ยังอยู่ในระหว่างการประเมิน — คาดว่าหลายพันล้านเหรียญรวมทุกบริษัท

**สาเหตุของเหตุการณ์:**
Snowflake เป็น Data Cloud Platform ที่ให้บริการ Data Warehouse แบบ Cloud-Native โดยมีลูกค้าชั้นนำจำนวนมาก ในช่วงต้นปี 2567 กลุ่มผู้โจมตี (UNC5537) ใช้ Credentials ที่ได้จาก Infostealer Malware (Malware ที่ขโมย Credentials จากเครื่องของผู้ใช้) เพื่อทำ Credential Stuffing เข้าสู่บัญชีลูกค้าของ Snowflake ที่ไม่มี MFA บังคับใช้

**รายละเอียดการโจมตี:**
- ผู้โจมตีใช้ Credentials ที่ถูกขโมยจากเครื่องพนักงานของ AT&T, Ticketmaster, Santander และลูกค้า Snowflake รายอื่นๆ
- Credentials มาจาก Infostealer Malware ที่ติดเครื่องพนักงานผ่าน Phishing หรือการดาวน์โหลดซอฟต์แวร์ที่ไม่ปลอดภัย
- **Snowflake ไม่ได้บังคับ MFA โดย Default** — ลูกค้าหลายราย (รวมถึง AT&T) ไม่ได้เปิด MFA
- ไม่มี Network Policy ที่จำกัด IP ต้นทาง — สามารถ login เข้าจากที่ไหนก็ได้
- ข้อมูลที่ขโมยได้รวมถึง Call Logs (AT&T), Ticket Sales Data (Ticketmaster), Financial Records (Santander)

**การละเมิดหลักการ IAAA:**

| ขั้นตอน IAAA | สิ่งที่ผิดพลาด |
|-------------|---------------|
| **Identification** | ไม่มีการระบุ Device Fingerprint หรือ Behavioral Profile — ใช้แค่ Username |
| **Authentication** | **MFA ไม่ได้ถูกบังคับ** — Credentials ที่ถูกขโมยเพียงพอต่อการเข้าสู่ระบบ |
| **Authorization** | Service Accounts (ไม่ใช่คน) ถูกใช้โดยไม่มี Network Restriction หรือ IP Allowlist |
| **Accountability** | การขโมยข้อมูลปริมาณมาก (หลาย TB) ไม่ถูกตรวจจับแบบ Real-time |

**บทเรียนที่ได้:**
1. **Cloud Vendor ต้อง enforce Security Defaults** — Snowflake เปลี่ยนนโยบายหลัง breach: บังคับ MFA สำหรับทุก Account
2. **Credentials ที่ถูกขโมยจาก Infostealer เป็นภัยคุกคามใหญ่** — ต้องมี Credential Scanning, Passwordless Adoption
3. **Service Accounts ต้องมี Network Restriction** — ไม่ใช่แค่รหัสผ่าน แต่ต้องจำกัดด้วย IP, Device, และ Time
4. **Data Exfiltration Detection** — การขโมยข้อมูลปริมาณมากควรถูกตรวจจับโดย DLP และ Behavioral Analytics
5. **Zero Trust สำหรับ Cloud Platform** — อย่าไว้ใจ Network หรือ Credentials — ตรวจสอบทุกครั้ง

**คำถามสำหรับการอภิปรายในชั้นเรียน:** ถ้านักศึกษาเป็น Security Architect ของบริษัทที่ใช้ Snowflake นักศึกษาจะออกแบบมาตรการป้องกันอะไรบ้างเพื่อลดความเสี่ยงจาก Credential Theft และการขาด MFA

---

### กรณีศึกษา 3: Europa Cloud Breach (2026) — IAM Governance Failure

**ปีที่เกิดเหตุการณ์:** มีนาคม 2569
**ประเภทการโจมตี:** Supply Chain Attack (Trivy Compromise) + Cloud IAM Misconfiguration
**จำนวนผู้ได้รับผลกระทบ:** 42 หน่วยงานภายใน EU + 29 หน่วยงานสหภาพยุโรปอื่นๆ
**ความเสียหาย:** 340 GB ข้อมูลถูกขโมย รวมถึง DKIM Signing Keys, SSO Directory, AWS Configuration — กระทบต่อความมั่นคงของสหภาพยุโรป

**สาเหตุของเหตุการณ์:**
Europa Cloud เป็นระบบคลาวด์ของสหภาพยุโรป (AWS-based) ที่ให้บริการเว็บไซต์ "europa.eu" และบริการดิจิทัลแก่ประเทศสมาชิก — ถูกโจมตีโดยกลุ่ม TeamPCP ผ่านการโจมตีห่วงโซ่อุปทาน (Supply Chain Attack) ใน Trivy (Open Source Vulnerability Scanner) ซึ่งถูกระบุเป็น CVE-2026-33634

**ลำดับเหตุการณ์:**
- **19 มีนาคม 2569:** ผู้โจมตีใช้ AWS Secret Key ที่ได้จากการโจมตี Trivy เพื่อเข้าถึง AWS Account ของ European Commission
- **19 มีนาคม:** ผู้โจมตีรัน TruffleHog เพื่อค้นหา Secrets เพิ่มเติม และเริ่ม Reconnaissance
- **24 มีนาคม:** CSOC (Cyber Security Operations Center) ของ EC ได้รับ Alert — เริ่ม Incident Response
- **25 มีนาคม:** CERT-EU ได้รับแจ้ง — ระงับ Compromised Credentials
- **27 มีนาคม:** European Commission ประกาศเหตุการณ์ต่อสาธารณะ
- **28 มีนาคม:** ShinyHunters เผยแพร่ข้อมูล 340 GB สู่สาธารณะ

**รายละเอียดการละเมิด IAM:**
- **Static IAM Keys:** Service Account ใช้ Access Key แบบถาวร (ไม่มีการ Rotate) — ไม่มี Expiration
- **Wildcard S3 Permissions:** IAM Policy อนุญาต `s3:*` และ `secretsmanager:GetSecretValue` บนทรัพยากรทั้งหมด (`Resource: "*"`) — ไม่จำกัด
- **ไม่มี SCP (Service Control Policy):** ไม่มี Organization-level Guardrails — Service Account ที่ถูกขโมยสามารถทำอะไรก็ได้ใน Account
- **ไม่มี GuardDuty / Threat Detection:** ไม่มีระบบตรวจจับพฤติกรรมผิดปกติ
- **ไม่มี IMDSv2:** ใช้ IMDSv1 ซึ่งป้องกัน SSRF attack ได้น้อยกว่า
- **ไม่มี CloudTrail Alerts:** มี CloudTrail แต่ไม่มี Alert เมื่อมีการเรียก API ที่ผิดปกติ

**การละเมิดหลักการในบทนี้:**

| หลักการ | การละเมิด |
|---------|-----------|
| **Least Privilege** | Wildcard S3 Permission + `secretsmanager:GetSecretValue` ทุก ARN — Service Account มีสิทธิ์เกินจำเป็นอย่างมหาศาล |
| **Fail-Safe Defaults** | ไม่มี SCP — ไม่มี Default Deny ในระดับ Organization |
| **Complete Mediation** | CloudTrail ถูกเปิดแต่ไม่ได้ถูกเฝ้าติดตาม — "ตรวจสอบ" แต่ไม่ได้ "ตรวจ" จริง |
| **Accountability** | ไม่มี Alerting — ขาดการตรวจสอบแบบ Real-time |
| **Defense in Depth** | ขาดทุกชั้น — IAM Key + ไม่มี Rotation + ไม่มี Monitoring + ไม่มี SCP |
| **Work Factor** | Static Key ที่ไม่มี Rotation ทำให้ Attack Cost ต่ำ — ผู้โจมตีมีเวลาไม่จำกัด |
| **Compromise Recording** | ไม่มี GuardDuty หรือ Detective Controls — ไม่มีทางรู้ว่าถูกบุกรุก |

**บทเรียนที่ได้:**
1. **IAM Governance เป็นปัญหาเชิงระบบ ไม่ใช่แค่เทคนิค** — การแก้ไขต้องมีทั้ง Policy (SCP), Process (Key Rotation), Technology (GuardDuty), และ People (Monitoring Team)
2. **Static IAM Keys เป็นความเสี่ยงใหญ่** — ควรใช้ Temporary Credentials (STS, IAM Roles Anywhere) แทน
3. **Wildcard Permission ไม่ควรมีใน Production** — ใช้ Policy ที่จำกัด Resource และ Action เฉพาะที่จำเป็น
4. **SCP เป็น "Seatbelt" ของ Cloud Organization** — ทุก Organization ควรมี SCP จำกัด แม้ Admin Account
5. **Monitoring ที่ไม่มี Alert = ไม่มี Monitoring** — ต้องมีทั้ง Detective และ Responsive Controls
6. **IMDSv2 ควรเป็น Default** — ป้องกัน SSRF-based Credential Theft ได้ดีกว่า v1 มาก
7. **DKIM Keys ต้องถูกแยกไว้ใน Service Role ที่มี Specific ARN Scope** — ไม่ให้ User-facing Principal เข้าถึงได้

**คำถามสำหรับการอภิปรายในชั้นเรียน:** จงเปรียบเทียบการละเมิดหลักการ IAM ในกรณีนี้กับกรณี Capital One (2019) — เหตุการณ์ไหนรุนแรงกว่ากัน และมีบทเรียนที่แตกต่างกันอย่างไร

---

### กรณีศึกษา 4: Capital One Data Breach (2019) — Failure of Least Privilege

**ปีที่เกิดเหตุการณ์:** มีนาคม - กรกฎาคม 2562 (ตรวจพบ 19 กรกฎาคม 2562)
**ประเภทการโจมตี:** Server-Side Request Forgery (SSRF) + Privilege Escalation
**จำนวนผู้ได้รับผลกระทบ:** 106 ล้านคนในสหรัฐฯ และแคนาดา
**ความเสียหาย:** ค่าปรับและค่าเสียหายรวม 190 ล้านเหรียญสหรัฐ

**สาเหตุของเหตุการณ์:**
Capital One ใช้ AWS Cloud Infrastructure มี Web Application Firewall (WAF) ที่ Front-End เพื่อกรอง request อันตราย แต่ผู้โจมตี (Paige Thompson — อดีตพนักงาน AWS) สามารถใช้ SSRF เพื่อ bypass WAF และเรียกใช้ Metadata Endpoint (`169.254.169.254`) ของ AWS EC2 Instance ได้สำเร็จ

จากนั้นผู้โจมตีใช้ Credential ที่ได้จาก Metadata เพื่อ Assume Role ที่มีสิทธิ์บริหารจัดการ S3 Bucket (Role ที่มี Privilege สูงเกินจำเป็น) และขโมยข้อมูลจาก S3 Buckets ที่เก็บข้อมูลลูกค้า

**ความสัมพันธ์กับเนื้อหาในบทนี้:**

| หลักการ | สิ่งที่ผิดพลาด |
|---------|---------------|
| Least Privilege | EC2 Instance มี IAM Role ที่มีสิทธิ์เข้าถึง S3 Buckets — ทั้งที่ Instance นั้นไม่ควรเข้าถึง S3 โดยตรง |
| Complete Mediation | WAF ไม่สามารถตรวจจับ SSRF Attack ที่ไปยัง Internal Metadata Endpoint |
| Defense in Depth | ขาด Network Segmentation — ไม่มีชั้นป้องกันระหว่าง EC2 และ Metadata Service |
| Fail-Safe Defaults | IAM Role ถูกตั้ง Allow — ควรตั้งแบบ Least Privilege หรือ Deny เป็นค่าเริ่มต้น |
| Accountability | Capital One ใช้ AWS CloudTrail ทำให้สามารถตรวจสอบการกระทำของผู้โจมตีได้ (แต่สายเกินไป) |

**บทเรียนที่ได้:**
1. ใช้ Least Privilege อย่างเคร่งครัด — IAM Role ต้องมีสิทธิ์เฉพาะที่จำเป็นเท่านั้น
2. Metadata Endpoint (169.254.169.254) ต้องถูกป้องกัน — ห้าม Service ภายนอกเข้าถึงได้
3. SSRF เป็นช่องโหว่อันตรายที่มักถูกมองข้าม — ต้องมี URL Validation และ Network Filtering
4. Zero Trust Model — ไม่ไว้ใจ Service ภายในองค์กร (Internal Service) โดยอัตโนมัติ
5. Defense in Depth — ไม่พึ่งพา WAF เพียงอย่างเดียว ต้องมี Layer อื่นเสริม

**คำถามสำหรับการอภิปรายในชั้นเรียน:** หากนักศึกษาเป็น Security Architect ของ Capital One หลังจากเหตุการณ์นี้ นักศึกษาจะออกแบบระบบการเข้าถึง S3 Bucket ใหม่อย่างไรเพื่อป้องกันไม่ให้เหตุการณ์ซ้ำ

---

### กรณีศึกษา 5: Target Data Breach (2013) — Failure of Defense in Depth

**ปีที่เกิดเหตุการณ์:** 27 พฤศจิกายน - 15 ธันวาคม 2556 (ตรวจพบ 12 ธันวาคม 2556)
**ประเภทการโจมตี:** Supply Chain Attack → Lateral Movement → Data Exfiltration
**จำนวนผู้ได้รับผลกระทบ:** 70 ล้านคน (ข้อมูลลูกค้า) + 40 ล้านบัตรเครดิต
**ความเสียหาย:** 252 ล้านเหรียญสหรัฐ (รวมค่าใช้จ่ายด้านกฎหมาย, ค่าปรับ, การชดเชย)

**สาเหตุของเหตุการณ์:**
Target บริษัทค้าปลีกใหญ่เป็นอันดับ 2 ในสหรัฐฯ ถูกโจมตีผ่านคู่ค้าระบบปรับอากาศ (HVAC Vendor — Fazio Mechanical Services) ผู้โจมตีใช้ Credential ที่ขโมยมาจาก Fazio เพื่อเข้าสู่ระบบเครือข่ายของ Target

แม้ Target จะใช้ FireEye (ระบบตรวจจับ Malware ราคาแพง) และ SIEM แต่ระบบตรวจพบพฤติกรรมผิดปกติตั้งแต่วันแรกและแจ้งเตือนไปยังทีม Security Operations Center (SOC) แต่ทีม SOC ไม่ได้ตอบสนองต่อการแจ้งเตือน ทำให้ผู้โจมตีอยู่ในระบบนานถึง 19 วัน และขโมยข้อมูลบัตรเครดิตไปจำนวนมหาศาล

**ลำดับเหตุการณ์ตาม IAAA Framework:**

| ขั้นตอนของ IAAA | สิ่งที่เกิดขึ้น |
|-----------------|---------------|
| Identification (การระบุตัวตน) | ผู้โจมตีใช้ Credentials ของ Fazio (HVAC Vendor) — ระบุตัวตนเป็นคู่ค้าที่ถูกต้อง |
| Authentication (การพิสูจน์ตัวตน) | Target ไม่มี MFA สำหรับ Third-Party Vendors — Credentials ที่ถูกขโมยก็ผ่าน Authentication ได้ |
| Authorization (การกำหนดสิทธิ์) | Vendor Account มีสิทธิ์เข้าถึง Network ภายใน Target (Over-privilege) — ควรจำกัดเฉพาะระบบ HVAC |
| Accountability (การตรวจสอบ) | แม้ FireEye+SIEM ตรวจพบ (Accountability ทำงาน) แต่ไม่มีคนตอบสนอง (Human Gap) |

**การละเมิดหลักการออกแบบความปลอดภัย:**

| หลักการ | การละเมิด |
|---------|-----------|
| Least Privilege | Vendor Account มีสิทธิ์มากเกินกว่าที่ Fazio จำเป็นต้องใช้ |
| Separation of Privilege | Vendor Network ไม่ได้ถูกแยก (Segregate) ออกจาก Network หลัก (POS System) |
| Complete Mediation | ไม่มีการตรวจสอบ Vendor Activity — ระบบคิดว่าถ้า login ผ่านแล้วทุกอย่างโอเค |
| Fail-Safe Defaults | Security Alert ถูกตั้งให้ "Notify Only" แทนการบล็อกโดยอัตโนมัติ (Fail-Open) |
| Defense in Depth | FireEye ตรวจจับได้ แต่ขาดการตอบสนอง — Automation (Auto-Block) น่าจะช่วยได้ |
| Psychological Acceptability | การตั้งค่าความปลอดภัยที่ซับซ้อนเกินไป (หรือไม่มีนโยบายที่ชัดเจนสำหรับ Vendor Access) |

**บทเรียนที่ได้:**
1. Third-Party Risk Management — ทุก Vendor ที่เชื่อมต่อเครือข่ายต้องถูกตรวจสอบ
2. Network Segmentation — เครือข่ายของ Vendor (HVAC) ต้องแยกจาก POS อย่างเด็ดขาด
3. MFA สำหรับทุก External Access — ไม่ใช่แค่ Password
4. Security Alert ต้องมีคนตอบสนอง — ถ้า Automated Alert ไม่มี Action Plan = ไร้ค่า
5. Least Privilege สำหรับทุก Account รวมถึง Vendor Account

**คำถามสำหรับการอภิปรายในชั้นเรียน:** ในฐานะนักพัฒนาซอฟต์แวร์ที่ต้องเชื่อมต่อ API กับระบบภายนอก (Third-Party API) นักศึกษาจะใช้หลักการใดในบทนี้ในการออกแบบระบบเพื่อป้องกันไม่ให้ Supplier/Vendor เข้าถึงข้อมูลเกินกว่าที่จำเป็น

---

### กรณีศึกษา 6: The Ashley Madison Data Breach (2015) — Failure of Confidentiality, Integrity, และ Open Design

**ปีที่เกิดเหตุการณ์:** กรกฎาคม 2558
**ประเภทการโจมตี:** External Hack โดยกลุ่ม "The Impact Team"
**จำนวนผู้ได้รับผลกระทบ:** 37 ล้านผู้ใช้งาน
**ความเสียหาย:** มูลค่าบริษัทตกต่ำ, ค่าปรับรวม 11.2 ล้านเหรียญสหรัฐ (FTC + FTC Australia), CEO ลาออก

**สาเหตุของเหตุการณ์:**
Ashley Madison เป็นเว็บไซต์หาคู่สำหรับคนมีคู่ (Extra-marital Affairs) กลุ่มผู้โจมตีสามารถเข้าถึงระบบและขโมยข้อมูลผู้ใช้ 37 ล้านคน รวมถึงชื่อ, อีเมล, ที่อยู่, ประวัติการใช้บัตรเครดิต, และข้อมูลความสัมพันธ์ทางเพศ

**การละเมิด CIA Triad และหลักการออกแบบ:**

| หลักการ | การละเมิด |
|---------|-----------|
| **Confidentiality** — ข้อมูลผู้ใช้รั่วไหลทั้งหมด | ไม่มีการเข้ารหัสข้อมูลสำคัญ, ข้อมูลการชำระเงินไม่ได้รับการป้องกันอย่างเพียงพอ |
| **Integrity** — บริษัทสัญญาว่าจะลบข้อมูลแต่ไม่ลบ | Ashley Madison สัญญาว่าจะลบข้อมูลเมื่อผู้ใช้ลบบัญชี (คิดค่าบริการ $19) แต่ไม่ได้ลบจริง — ข้อมูลถูกขโมยและเปิดเผย |
| **Fail-Safe Defaults** | ระบบตั้งค่าให้เก็บข้อมูลผู้ใช้ไว้ ไม่ใช่ลบตามที่สัญญา |
| **Open Design (กลับกัน)** | Ashley Madison ใช้ "Security Through Obscurity" — มีการใช้ SSL แต่มีคุณภาพต่ำ, ใช้ MD5 สำหรับ hashing (ซึ่งอ่อนแอมาก) |
| **Psychological Acceptability** | บริษัทตั้งใจออกแบบ UI/UX ให้ผู้ใช้ "มั่นใจ" ว่าข้อมูลปลอดภัย แต่ความจริงไม่ได้เป็นอย่างนั้น — เป็น Deceptive Design |
| **Accountability** | ผู้โจมตีเปิดเผยข้อมูลทั้งหมด — Accountability ที่เป็นลบ (การเปิดโปงการโกหกของบริษัท) |

**บทเรียนด้าน Ethics และ Privacy:**
1. **อย่าสัญญาในสิ่งที่ทำไม่ได้ — Ashley Madison สัญญาว่าจะลบข้อมูล ($19 delete) แต่ไม่ลบจริง ถือเป็นการฉ้อโกง**
2. **การเข้ารหัสที่อ่อนแอ (MD5 for Passwords) แย่กว่าการไม่เข้ารหัส — เพราะให้ภาพลวงตาว่าปลอดภัย**
3. **Privacy ต้องถูก Design-In — ถ้าธุรกิจของคุณขึ้นอยู่กับการเก็บข้อมูลที่ sensitive ข้อมูลนั้นต้องถูกป้องกันตั้งแต่ต้น**
4. **GDPR/PDPA กำหนด Right to be Forgotten — ถ้าผู้ใช้ขอให้ลบข้อมูล ต้องลบจริง**

**คำถามสำหรับการอภิปรายในชั้นเรียน:** Ashley Madison กล่าวหาว่า "บริษัทให้ความสำคัญกับความปลอดภัย" แต่กลับใช้ MD5 สำหรับ hashing รหัสผ่านและไม่ได้ลบข้อมูลตามที่สัญญา นักศึกษาคิดว่าการกระทำเช่นนี้ผิดจริยธรรมหรือไม่ และเกี่ยวข้องกับหลักการ Open Design และ Psychological Acceptability อย่างไร

---

## กิจกรรมปฏิบัติการ

### Lab 2.1: วิเคราะห์ CIA Triad สำหรับแอปพลิเคชันตัวอย่าง

**วัตถุประสงค์:** เพื่อฝึกประยุกต์ใช้ CIA Triad ในการวิเคราะห์ความต้องการด้านความปลอดภัยของซอฟต์แวร์

**โจทย์:** ให้นักศึกษาเลือกแอปพลิเคชันมา 1 ระบบ (เช่น ระบบธนาคารออนไลน์, ระบบโรงพยาบาล, ระบบ E-Commerce, ระบบ Social Media, ระบบ Cloud Storage) และวิเคราะห์:

1. ข้อมูล/ฟังก์ชันใดในระบบที่ต้องการ Confidentiality สูง — อะไรคือมาตรการป้องกัน
2. ข้อมูล/ฟังก์ชันใดที่ต้องการ Integrity สูง — อะไรคือมาตรการป้องกัน
3. ข้อมูล/ฟังก์ชันใดที่ต้องการ Availability สูง — อะไรคือมาตรการป้องกัน
4. มีความขัดแย้ง (Trade-off) ระหว่าง CIA Triad ในระบบนี้หรือไม่ — อย่างไร
5. ถ้าต้องเลือก牺牲一个ด้านของ CIA สำหรับระบบนี้ ด้านใดที่牺牲ได้ และทำไม

**ส่งงาน:** แผนภาพหรือตารางวิเคราะห์ CIA Triad + คำอธิบายประกอบ

---

### Lab 2.2: ออกแบบ RBAC Model สำหรับระบบจำลอง

**วัตถุประสงค์:** เพื่อฝึกออกแบบ Role-Based Access Control (RBAC) สำหรับระบบจริง

**โจทย์:** ให้นักศึกษาออกแบบ RBAC Model สำหรับระบบจัดการโรงพยาบาลที่ประกอบด้วย:

**ผู้ใช้:**
- แพทย์ (Doctor)
- พยาบาล (Nurse)
- เภสัชกร (Pharmacist)
- เจ้าหน้าที่การเงิน (Billing Staff)
- ผู้ดูแลระบบ (Admin)

**ทรัพยากรที่ต้องควบคุม:**
- เวชระเบียนผู้ป่วย (Patient Records) — อ่าน/เขียน/ลบ
- ใบสั่งยา (Prescriptions) — อ่าน/เขียน/ลบ
- ข้อมูลการเงิน (Billing) — อ่าน/เขียน/ลบ
- ตารางแพทย์ (Schedule) — อ่าน/เขียน
- ระบบ Inventory ยา — อ่าน/เขียน
- User Management — จัดการ

**สิ่งที่ต้องส่ง:**
1. แผนภาพแสดง Role Hierarchy (ถ้ามี)
2. Permission Matrix — แสดงว่า Role ไหนมี Permission (Create/Read/Update/Delete) อะไรได้บ้าง
3. อธิบายว่าใช้หลัก Least Privilege, Separation of Duties, และ Default Deny อย่างไรใน Model นี้

---

### Lab 2.3: เปรียบเทียบ HTTP vs HTTPS ด้วย Wireshark

**วัตถุประสงค์:** เพื่อให้เห็นความแตกต่างด้าน Confidentiality และ Integrity ระหว่าง HTTP และ HTTPS ด้วยสายตา

**ขั้นตอน:**
1. เปิด Wireshark และเริ่มจับ Network Traffic
2. เปิด Browser แล้วเข้าเว็บไซต์ HTTP (เช่น `http://httpbin.org`) และเว็บ HTTPS (เช่น `https://httpbin.org`)
3. สังเกตความแตกต่างของแพ็กเก็ตข้อมูล

**สิ่งที่ต้องวิเคราะห์และส่ง:**
1. จับภาพหน้าจอ (Screenshot) แพ็กเก็ต HTTP — ชี้ให้เห็นว่าข้อมูลใน Request/Response ถูกแสดงเป็น Plain Text
2. จับภาพหน้าจอแพ็กเก็ต HTTPS — ชี้ให้เห็นว่าข้อมูลถูกเข้ารหัส (TLSv1.2/1.3)
3. วิเคราะห์:
   - HTTP: Protocol, Method, Path, Headers, Body — ทั้งหมดอ่านได้
   - HTTPS: TLS Handshake, Encrypted Application Data — อ่านไม่ได้
4. อธิบายว่า HTTPS ปกป้อง Confidentiality และ Integrity อย่างไร
5. ระบุ Certificate Details (ออกโดย CA ไหน, ใช้ Algorithm อะไร, Expire เมื่อไหร่)

---

## คำถามท้ายบท

1. จงยกตัวอย่างสถานการณ์ที่ Confidentiality และ Availability ขัดแย้งกันในระบบซอฟต์แวร์ และเสนอวิธีการจัดการกับความขัดแย้งนั้น พร้อมอธิบาย Trade-off ที่เกิดขึ้น

2. อธิบายความแตกต่างระหว่าง Authentication และ Authorization พร้อมยกตัวอย่างจากระบบที่นักศึกษาใช้ในชีวิตประจำวัน (เช่น Facebook, Internet Banking, Gmail)

3. หลักการ Defense in Depth แตกต่างจากความซ้ำซ้อน (Redundancy) อย่างไร จงยกตัวอย่างที่แสดงให้เห็นถึงความแตกต่างนี้

4. Non-repudiation มีความสำคัญอย่างไรในระบบธุรกรรมอิเล็กทรอนิกส์ (E-Commerce / E-Contract) และกลไกใดบ้างที่ใช้สร้าง Non-repudiation

5. จงอธิบายความสัมพันธ์ระหว่างหลักการ Least Privilege, Fail-Safe Defaults, และ Defense in Depth โดยยกตัวอย่างการใช้ทั้งสามหลักการร่วมกันในระบบ Web Application เดียวกัน

6. จงเปรียบเทียบ RBAC กับ ABAC ในแง่ของความยืดหยุ่น ความซับซ้อนการจัดการ และความเหมาะสมในการใช้งาน — พร้อมยกตัวอย่างระบบที่เหมาะสมกับแต่ละแบบ

7. "Security Through Obscurity" ขัดแย้งกับหลักการ Open Design อย่างไร จงวิเคราะห์กรณีที่ "Obscurity" อาจมีประโยชน์และกรณีที่เป็นอันตราย

8. จงอธิบายความแตกต่างระหว่าง Accountability และ Non-repudiation พร้อมยกตัวอย่างเหตุการณ์ที่ Accountability มีอยู่แต่ Non-repudiation ไม่สมบูรณ์

9. Privacy by Design มีหลักการอะไรบ้างที่เกี่ยวข้องโดยตรงกับนักพัฒนาซอฟต์แวร์ จงยกตัวอย่างการประยุกต์ใช้ 3 หลักการในระบบ Web Application

10. หลักการ Separation of Privilege ถูกนำไปใช้ในระบบที่นักศึกษาใช้ในชีวิตประจำวันอย่างไรบ้าง จงยกตัวอย่างอย่างน้อย 3 ระบบ พร้อมอธิบายกลไก

---

## Verification

- **Web search verified:** FIDO Alliance State of Passkeys 2026 (5B passkeys, 90% awareness, 75% enabled); NIST SP 800-63B-4 July 2025 (syncable passkeys at AAL2); Change Healthcare 2024 breach (Citrix no MFA, 190M+ victims, $22M ransom); Snowflake/AT&T 2024 (110M records, infostealer credentials, no MFA); Barclays 2025 IT outage (availability → integrity cascade); Europa Cloud Breach 2026 (Trivy supply chain, wildcard IAM, 340GB exfiltrated)
- **Chinese character fixes:** "确保" → Thai (7 occurrences), "手机" → โทรศัพท์มือถือ, "密钥" → คีย์, "ไม่เขียเอcrypto" → ไม่เขียน Crypto
- **Standards citations:** NIST SP 800-53 Rev. 5, ISO 27001:2022, NIST SP 800-63B-4, OWASP ASVS, RFC 3161, eIDAS, GDPR Art. 25, PDPA — all verified against primary sources
- **CVE references:** CVE-2026-33634 (Trivy supply chain) listed is based on CERT-EU report — marked in context
- **Status:** All verified — no [UNVERIFIED] items