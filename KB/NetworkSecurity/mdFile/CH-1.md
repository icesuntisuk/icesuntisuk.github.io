# CH-1: บทนำ — หลักการพื้นฐานด้าน Network Security

## วัตถุประสงค์การเรียนรู้ (Learning Objectives)

เมื่อจบบทนี้แล้ว ผู้เรียนสามารถ:
1. อธิบายความหมายและความสำคัญของการรักษาความปลอดภัยทางเครือข่ายในยุคดิจิทัล พร้อมยกตัวอย่างสถิติและแนวโน้มล่าสุดได้
2. อธิบายหลักการ CIA Triad ตามนิยามของ NIST SP 800-12 และยกตัวอย่างการละเมิดในแต่ละด้านจากกรณีจริงที่เกิดขึ้นในประวัติศาสตร์
3. อธิบายแนวคิด AAA (Authentication, Authorization, Accounting) และเปรียบเทียบ RADIUS, TACACS+, และ Diameter ได้
4. อธิบายองค์ประกอบของ NIST Cybersecurity Framework (CSF) 2.0 ทั้ง 6 ฟังก์ชัน พร้อมการเปลี่ยนแปลงจากเวอร์ชัน 1.1
5. อธิบายโครงสร้างของ ISO/IEC 27001:2022 กระบวนการ ISMS และความสัมพันธ์กับ Annex A (93 Controls)
6. วิเคราะห์บทเรียนจากเหตุการณ์โจมตีที่มีผลกระทบในวงกว้าง (Colonial Pipeline, SolarWinds, Dyn DNS) และระบุเทคนิคตาม MITRE ATT&CK ได้
7. อธิบายแนวคิด Defense in Depth และความสัมพันธ์กับ Zero Trust Architecture
8. อธิบายหลักการบริหารความเสี่ยงด้าน Cybersecurity ตามกรอบมาตรฐานสากล

---

## 1. ความรู้เบื้องต้นเกี่ยวกับ Network Security

### 1.1 ความหมายของ Network Security

Network Security หรือการรักษาความปลอดภัยทางเครือข่าย หมายถึงแนวปฏิบัติ นโยบาย กระบวนการ และเทคโนโลยีที่ถูกนำมาใช้เพื่อปกป้องเครือข่ายคอมพิวเตอร์ ข้อมูล และทรัพยากรที่เกี่ยวข้องจากการถูกเข้าถึงโดยไม่ได้รับอนุญาต การถูกดัดแปลง การถูกทำลาย หรือการถูกขัดขวางการใช้งาน โดยครอบคลุมทั้งฮาร์ดแวร์ (เราเตอร์ สวิตช์ ไฟร์วอลล์) และซอฟต์แวร์ (ระบบปฏิบัติการ แอปพลิเคชัน โพรโทคอล)

Network Security ไม่ได้จำกัดอยู่เพียงการป้องกันการโจมตีจากภายนอกเท่านั้น แต่ยังรวมถึง:
- **การควบคุมการเข้าถึงจากภายใน** — ป้องกันผู้ใช้ภายในที่ไม่มีสิทธิ์เข้าถึงข้อมูลที่สำคัญ
- **การรักษาความปลอดภัยของข้อมูลขณะส่งผ่านเครือข่าย** — ป้องกันการดักจับหรือแก้ไขข้อมูลระหว่างทาง
- **การทำให้แน่ใจว่าระบบสามารถทำงานได้อย่างต่อเนื่อง** — แม้เผชิญกับภัยคุกคาม เช่น DDoS หรือ Ransomware

### 1.2 ความสำคัญในยุคดิจิทัล

ในปัจจุบันที่องค์กรทุกแห่งต้องพึ่งพาระบบเครือข่ายในการดำเนินธุรกิจ การโจมตีทางเครือข่ายสามารถสร้างความเสียหายได้ในวงกว้าง ข้อมูลจากรายงานสำคัญในปี 2025 ระบุว่า:

| ตัวชี้วัด | ค่าสถิติ |
|----------|---------|
| ค่าเสียหายเฉลี่ยต่อการละเมิดข้อมูล (IBM 2025) | **4.44 ล้าน USD** |
| ค่าเสียหายเฉลี่ยในสหรัฐอเมริกา | **10.22 ล้าน USD** (สูงเป็นประวัติการณ์) |
| อุตสาหกรรมที่เสียหายสูงสุด | Healthcare — **7.42 ล้าน USD** |
| เวลาเฉลี่ยในการตรวจจับและควบคุม (Breach Lifecycle) | **241 วัน** (158 วันตรวจจับ + 83 วันควบคุม) — ต่ำสุดในรอบ 9 ปี |
| Ransomware ใน breaches ทั้งหมด (Verizon DBIR 2025) | **44%** (เพิ่มขึ้น 37% จากปีก่อน) |
| องค์กรที่ใช้ AI ด้านความปลอดภัย | **67%** — ลดค่าเสียหายลงเฉลี่ย 1.9 ล้าน USD |
| การโจมตีผ่าน Edge Device/VPN | เพิ่มขึ้น **8 เท่า** จากปีก่อน |

**ผลกระทบหลักของการโจมตีทางเครือข่าย:**

| ประเภทผลกระทบ | คำอธิบาย | ตัวอย่าง |
|---------------|----------|---------|
| **การหยุดชะงักของธุรกิจ** | ระบบไม่สามารถให้บริการ สูญเสียรายได้ | Colonial Pipeline หยุดส่งน้ำมัน 6 วัน, NHS ต้องเลื่อนการผ่าตัด 1,500+ ครั้ง |
| **การสูญเสียข้อมูลสำคัญ** | ข้อมูลลูกค้า ความลับทางการค้าถูกขโมย | Equifax 147.9M records รั่วไหล, Marriott 500M records |
| **ความเสียหายทางการเงิน** | ค่าไถ่ ค่าปรับตามกฎหมาย ค่าใช้จ่ายในการกู้คืน | ค่าเสียหายเฉลี่ย 4.44 ล้าน USD ต่อการละเมิด |
| **ความเสียหายด้านชื่อเสียง** | ความเชื่อมั่นของลูกค้าลดลง | 63% ขององค์กรเพิ่มราคาสินค้าเพื่อชดเชยค่าเสียหาย |
| **ผลกระทบทางกฎหมาย** | ค่าปรับจาก PDPA, GDPR, HIPAA | GDPR ปรับสูงสุดถึง 4% ของรายได้ทั่วโลก หรือ 20 ล้าน EUR |

### 1.3 ภาพรวมภัยคุกคามในปัจจุบัน

ข้อมูลจาก Verizon 2025 Data Breach Investigations Report (DBIR) ซึ่งวิเคราะห์เหตุการณ์ 22,052 incidents และ 12,195 confirmed breaches จาก 139 ประเทศ พบแนวโน้มสำคัญ:

- **Human Element**: 60% ของ breaches เกี่ยวข้องกับความผิดพลาดของมนุษย์
- **Credential Abuse**: 22% — ยังคงเป็นเวกเตอร์อันดับหนึ่ง
- **Ransomware**: 44% ของ breaches (เพิ่มขึ้น 37% YoY) — SMB 88% โดน ransomware
- **Vulnerability Exploitation**: 20% ของ breaches (เพิ่มขึ้น 34% YoY) — แซงหน้า Phishing
- **Third-Party Involvement**: เพิ่มเป็น 30% (จาก 15% — เพิ่มขึ้นเท่าตัว)
- **Espionage**: 17% ของ breaches (เพิ่มขึ้นอย่างมีนัยสำคัญ)

จากรายงาน ENISA Threat Landscape 2025 (วิเคราะห์ 4,875 incidents ใน EU):
- **DDoS**: 76.7% ของ incidents ทั้งหมด (ส่วนใหญ่มาจาก Hacktivist)
- **Phishing**: 60% ของ initial intrusion vectors
- **AI-generated phishing**: >80% ของแคมเปญ Phishing ใช้เนื้อหาที่สร้างโดย AI
- **Vulnerability disclosures**: 42,595 CVEs ใหม่ (เพิ่มขึ้น 27% YoY)
- **Sectors ที่ถูกโจมตีมากที่สุด**: Public admin (38.2%), Transport (7.5%), Finance (4.5%)

---

## 2. หลักการ CIA Triad

### 2.1 นิยามตามมาตรฐาน NIST

CIA Triad เป็นหลักการพื้นฐานด้านการรักษาความปลอดภัยของข้อมูลที่ถูกอ้างอิงในมาตรฐานความปลอดภัยทุกรูปแบบ ตามนิยามของ NIST SP 800-12 Rev. 1:

| องค์ประกอบ | นิยาม (NIST SP 800-12) | คำอธิบาย |
|-----------|----------------------|----------|
| **Confidentiality** (การรักษาความลับ) | "Preserving authorized restrictions on information access and disclosure, including means for protecting personal privacy and proprietary information." | การจำกัดการเข้าถึงและการเปิดเผยข้อมูลเฉพาะผู้ที่ได้รับอนุญาตเท่านั้น |
| **Integrity** (การรักษาความถูกต้อง) | "Guarding against improper information modification or destruction, and includes ensuring information non-repudiation and authenticity." | การป้องกันการแก้ไขหรือทำลายข้อมูลโดยไม่ได้รับอนุญาต รวมถึงการยืนยันความถูกต้องแท้จริง |
| **Availability** (การทำให้พร้อมใช้งาน) | "Ensuring timely and reliable access to and use of information." | การทำให้แน่ใจว่าข้อมูลและระบบสามารถเข้าถึงได้อย่างทันท่วงทีและเชื่อถือได้ |

CIA Triad ถูกฝังอยู่ในมาตรฐานสำคัญต่างๆ:
- **ISO 27001**: Annex A controls ถูก mapping กับ CIA properties
- **GDPR Article 32**: กำหนด "ระดับความปลอดภัยที่เหมาะสมกับความเสี่ยง" โดยอ้างอิง CIA
- **NIST SP 800-53**: Sections 3.3.2 (Availability), 3.3.3 (Integrity), 3.3.4 (Confidentiality)
- **CIS Controls**: Control 6 (Access Control Mgmt) สำหรับ Confidentiality, Control 3 (Data Protection) สำหรับ Integrity, Control 11 (Data Recovery) สำหรับ Availability

### 2.2 Confidentiality (การรักษาความลับ)

**มาตรการป้องกันที่สำคัญ:**

| มาตรการ | คำอธิบาย | ตัวอย่างการนำไปใช้ |
|---------|----------|-------------------|
| **Encryption (At Rest / In Transit)** | เข้ารหัสข้อมูลทั้งขณะจัดเก็บและขณะส่ง | AES-256 สำหรับ Database, TLS 1.3 สำหรับ HTTPS, E2EE สำหรับ Messaging |
| **Access Control** | ควบคุมสิทธิ์การเข้าถึงตามหลัก Least Privilege | RBAC, ABAC, MAC |
| **Data Classification** | จำแนกระดับความลับของข้อมูล | Public, Internal, Confidential, Restricted, Secret |
| **Multi-Factor Authentication (MFA)** | พิสูจน์ตัวตนหลายปัจจัย | FIDO2/WebAuthn, OTP + Password + Biometric |
| **Network Segmentation** | แยกเครือข่ายตามระดับความปลอดภัย | VLAN, Microsegmentation, DMZ, Air Gapped Network |
| **Data Masking** | ปกปิดข้อมูลสำคัญไม่ให้แสดงทั้งหมด | แสดงเฉพาะเลข 4 ตัวท้ายของบัตรเครดิต |

**ตัวอย่างการละเมิดจากกรณีจริง:**

| กรณี | ปี | รายละเอียด | สาเหตุ |
|------|----|------------|--------|
| **Equifax** | 2017 | ข้อมูล 147.9 ล้านรายการรั่วไหล (SSN, DOB) | ไม่แพตช์ Apache Struts CVE-2017-5638 |
| **Marriott/Starwood** | 2018 | ข้อมูล 500 ล้านรายการของแขกโรงแรม | Database Access ไม่มีการควบคุม |
| **Facebook/Cambridge Analytica** | 2018 | ข้อมูล 87 ล้าน profiles ถูกเก็บไปใช้ | API Access Controls ไม่รัดกุม |
| **Optus Australia** | 2022 | ข้อมูล 10 ล้านรายการของลูกค้า | API ไม่มี Authentication |
| **Medibank** | 2022 | ข้อมูล 9.7 ล้านรายการ | Credentials ถูกขโมยผ่าน Partner Access |
| **ESHYFT** | 2024 | ข้อมูล 86,000+ รายการ (SSN, ใบอนุญาตวิชาชีพ) | Amazon S3 Bucket ไม่มี Encryption และ Access Control |

**คำถามสำหรับการตรวจสอบ (Audit Question):** "ข้อมูลที่ละเอียดอ่อนของเราถูกเข้ารหัสหรือไม่? ใครบ้างที่สามารถเข้าถึงข้อมูลนี้ได้? มีการควบคุมตามหลัก Least Privilege หรือไม่?"

### 2.3 Integrity (การรักษาความถูกต้องครบถ้วน)

**มาตรการป้องกันที่สำคัญ:**

| มาตรการ | คำอธิบาย | ตัวอย่างการนำไปใช้ |
|---------|----------|-------------------|
| **Hashing** | ใช้ฟังก์ชัน Hash ตรวจสอบความถูกต้องของข้อมูล | SHA-256, SHA-3, HMAC |
| **Digital Signature** | ลงนามดิจิทัลเพื่อยืนยันแหล่งที่มา | RSA, ECDSA |
| **File Integrity Monitoring (FIM)** | ตรวจสอบการเปลี่ยนแปลงของไฟล์และระบบ | Tripwire, OSSEC, Wazuh, AIDE |
| **Logging & Audit Trail** | บันทึกการเปลี่ยนแปลงทั้งหมดเพื่อตรวจสอบย้อนหลัง | SIEM, Syslog, Blockchain/Immutable Ledger |
| **Version Control** | ควบคุมเวอร์ชันของข้อมูลและการเปลี่ยนแปลง | Git, Checksum verification |
| **Database ACID Properties** | ทำให้แน่ใจว่าธุรกรรมฐานข้อมูลสมบูรณ์ | Atomicity, Consistency, Isolation, Durability |

**ตัวอย่างการละเมิดจากกรณีจริง:**

| กรณี | ปี | รายละเอียด |
|------|----|------------|
| **Stuxnet** | 2010 | แก้ไข PLC Code ของเครื่องหมุนเหวี่ยงนิวเคลียร์อิหร่าน — การโจมตี Integrity disguised เป็นการทำงานปกติ |
| **Bangladesh Bank** | 2016 | ขโมยเงิน 81 ล้าน USD โดยแก้ไข SWIFT Transaction Messages |
| **NotPetya** | 2017 | แก้ไข M.E.Doc (ซอฟต์แวร์บัญชีของยูเครน) — Supply Chain Integrity Compromise |
| **SolarWinds** | 2020 | Malicious DLL ที่ Sign ด้วย Certificate จริง — Code Integrity Bypass |
| **Twitter Bitcoin Scam** | 2020 | ผู้โจมตีแก้ไข Internal Admin Tools เพื่อยึดบัญชีผู้มีชื่อเสียง |

**คำถามสำหรับการตรวจสอบ:** "เรามีวิธีการตรวจสอบหรือไม่ว่าข้อมูลของเราไม่ถูกเปลี่ยนแปลงโดยไม่ได้รับอนุญาต? เรามี File Integrity Monitoring หรือไม่?"

### 2.4 Availability (การทำให้พร้อมใช้งาน)

**มาตรการป้องกันที่สำคัญ:**

| มาตรการ | คำอธิบาย | ตัวอย่างการนำไปใช้ |
|---------|----------|-------------------|
| **Redundancy** | มีระบบสำรองเพื่อป้องกัน Single Point of Failure | N+1, 2N, Active-Active Cluster, RAID |
| **Disaster Recovery** | แผนการกู้คืนระบบเมื่อเกิดภัยพิบัติ | RPO (Recovery Point Objective), RTO (Recovery Time Objective) |
| **Load Balancing** | กระจาย Traffic เพื่อป้องกัน Overload | AWS ALB, NGINX, F5, Geographic Distribution |
| **DDoS Protection** | ป้องกันการโจมตีแบบ Distributed Denial of Service | Cloudflare, AWS Shield, Akamai Kona |
| **Backup Strategy** | สำรองข้อมูลตามหลัก 3-2-1 | 3 Copies, 2 Media, 1 Offsite; Immutable Backup, Air-Gapped |
| **Patch Management** | อัปเดตระบบอย่างสม่ำเสมอ | WSUS, SCCM, Automox |
| **SLA Guarantees** | ระดับการให้บริการที่รับประกัน | 99.9% (Three Nines = 8.76 ชม./ปี), 99.999% (Five Nines = 5.26 นาที/ปี) |

**ตัวอย่างการละเมิดจากกรณีจริง:**

| กรณี | ปี | รายละเอียด |
|------|----|------------|
| **Dyn DDoS** | 2016 | IoT Botnet 100,000+ เครื่องโจมตี DNS — Twitter, Netflix, Reddit ออฟไลน์ |
| **Colonial Pipeline** | 2021 | Ransomware บังคับปิดท่อส่งน้ำมัน 6 วัน — 45% ของ East Coast Fuel |
| **AWS US-East-1** | 2017 | S3 Outage จาก Typo — ส่วนใหญ่ของอินเทอร์เน็ตล่ม |
| **WannaCry** | 2017 | 200,000+ เครื่องใน 150 ประเทศ — NHS ยกเลิกนัดหมาย 19,000 ครั้ง |
| **OVHcloud** | 2021 | ไฟไหม้ Data Center ที่ Strasbourg — 3.6 ล้านเว็บไซต์ออฟไลน์ |

**คำถามสำหรับการตรวจสอบ:** "หากระบบนี้ล่มในวันนี้ เราจะสามารถกู้คืนได้ภายในกี่ชั่วโมง? RTO และ RPO ของเราคือเท่าใด?"

### 2.5 ความสัมพันธ์ระหว่าง CIA Triad และการ Trade-off

ทั้งสามองค์ประกอบของ CIA Triad มีความสัมพันธ์แบบ Trade-off ซึ่งหมายถึงการเพิ่มความแข็งแกร่งให้ด้านหนึ่งอาจทำให้อีกด้านลดลง:

| การ Trade-off | สถานการณ์ | ผลกระทบ |
|--------------|-----------|---------|
| **Confidentiality ↔ Availability** | เข้ารหัสข้อมูลด้วย AES-256 ต้องใช้เวลาในการถอดรหัส | ผู้ใช้รอนานขึ้น — Availability ลดลง; ใช้อุปกรณ์ HSM (Hardware Security Module) เพื่อลดผลกระทบ |
| **Integrity ↔ Availability** | ตรวจสอบ Checksum ทุก Transaction | Performance ลดลง — อาจไม่ทันต่อความต้องการ; ใช้ Tiered Storage กับ WORM สำหรับ Critical Logs |
| **Availability ↔ Confidentiality** | มีสำเนาข้อมูลหลายชุดเพื่อ Redundancy | ความเสี่ยงของการเปิดเผยข้อมูลเพิ่มขึ้น — ใช้ Encrypted Backups พร้อม Key Rotation |
| **Cost ↔ All Three** | งบประมาณจำกัด — ต้องเลือก | ใช้ Risk-Based Control Selection — ลงทุนกับสิ่งที่สำคัญที่สุด |

การหาจุดสมดุล (Balancing) ที่เหมาะสมระหว่างทั้งสามด้านเป็นหน้าที่ของนักบริหารความปลอดภัยที่ต้องพิจารณาตามความเสี่ยงและความต้องการขององค์กร

### 2.6 Parkerian Hexad (ส่วนขยายของ CIA)

Donn B. Parker ได้เสนอ **Parkerian Hexad** ในหนังสือ *Fighting Computer Crime* (1998) ซึ่งเป็นส่วนขยายของ CIA Triad โดยเพิ่ม 3 องค์ประกอบ:

| องค์ประกอบ | คำอธิบาย | ตัวอย่าง |
|-----------|----------|---------|
| **Confidentiality** (การรักษาความลับ) | "Known only to a limited few" — ข้อมูลเป็นที่รู้จักเฉพาะกลุ่มที่จำกัด | การเข้ารหัสข้อมูล |
| **Possession/Control** (การครอบครอง) | การควบคุมความเป็นเจ้าของข้อมูลทางกายภาพหรือทางตรรกะ — แยกจากการรักษาความลับ | ฮาร์ดดิสก์ที่เข้ารหัสถูกขโมย → เสีย Possession แต่ Confidentiality ยังคงอยู่ |
| **Integrity** (ความถูกต้อง) | "Material wholeness, unimpaired condition" — ความสมบูรณ์ของข้อมูล | ไฟล์ไม่ถูกแก้ไข — แตกต่างจาก CIA Integrity เล็กน้อย |
| **Authenticity** (ความถูกต้องแท้จริง) | "Genuine, valid, of established authority" — ข้อมูลและแหล่งที่มาต้องเป็นของจริง | Digital Signature ยืนยัน Authenticity — เอกสารอาจ Integrity ดีแต่ปลอมแปลง (ไม่ Authentic) |
| **Availability** (ความพร้อมใช้งาน) | "Capable of use, immediately usable" | ระบบทำงานได้เมื่อต้องการ |
| **Utility** (ประโยชน์ใช้สอย) | "Usefulness, fitness for purpose" — ข้อมูลต้องมีประโยชน์และใช้งานได้ | ข้อมูลที่เข้ารหัสมี Utility ต่ำสำหรับผู้โจมตี แต่ Confidentiality ยังคงอยู่ |

**ข้อแตกต่างสำคัญของ Parkerian Hexad:** Parker แยก "Possession" (การครอบครองทางกายภาพ) ออกจาก "Confidentiality" (การรักษาความลับ) — ฮาร์ดดิสก์ที่เข้ารหัสถูกขโมยหมายถึงเสียการครอบครองแต่ยังรักษาความลับไว้ได้ ในทำนองเดียวกัน "Authenticity" ถูกแยกจาก "Integrity" — เอกสารสามารถมีความถูกต้องครบถ้วน (Integrity) แต่เป็นของปลอม (ไม่ Authentic)

### 2.7 โมเดลอื่นๆ ที่เกี่ยวข้อง

| โมเดล | คำอธิบาย |
|-------|----------|
| **STRIDE** (Microsoft) | แบ่งภัยคุกคามเป็น 6 ประเภท: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege — เป็น Threat-Centric |
| **DAD** | Disclosure, Alteration, Destruction — ด้านตรงข้าม (Negative) ของ CIA |

---

## 3. แนวคิด AAA (Authentication, Authorization, Accounting)

### 3.1 Authentication (การพิสูจน์ตัวตน)

**หลักการ:** การยืนยันว่าผู้ใช้หรืออุปกรณ์เป็นใครตามที่อ้างว่าเป็น โดยใช้ปัจจัยหนึ่งหรือหลายปัจจัยร่วมกัน เรียกการพิสูจน์ตัวตนหลายปัจจัยว่า **Multi-Factor Authentication (MFA)**

**คำถามที่ Authentication ตอบ:** "คุณคือใคร?" (Who are you?)

**ปัจจัยในการพิสูจน์ตัวตน (5 ปัจจัย):**

| ปัจจัย | ชื่อ | ตัวอย่าง | รายละเอียดทางเทคนิค |
|-------|------|---------|-------------------|
| **Type 1** | Something You Know (สิ่งที่รู้) | Password, PIN, Security Questions | Entropy ต่ำที่สุด; เสี่ยงต่อ Phishing, Brute-Force, Credential Stuffing |
| **Type 2** | Something You Have (สิ่งที่ครอบครอง) | OTP Token, Smart Card, Phone, FIDO2 Key, TPM | Hardware-Backed; FIDO2/U2F ทนต่อ Phishing |
| **Type 3** | Something You Are (สิ่งที่คุณเป็น) | ลายนิ้วมือ, Face ID, ม่านตา, เสียง | ต้องมี Liveness Detection; เสี่ยงต่อ Template Storage |
| **Type 4** | Somewhere You Are (สถานที่) | GPS, IP Geolocation, Network Segment | ใช้สำหรับ Risk-Based Authentication |
| **Type 5** | Something You Do (พฤติกรรม) | Keystroke Dynamics, รูปแบบการเดิน | Continuous Authentication; ความซับซ้อนสูง |

**หมายเหตุ:** NIST SP 800-63-4 (2025) กำหนดอย่างเป็นทางการเพียง 3 ปัจจัย (Knowledge, Possession, Inherence) แต่ระบุ Location และ Behavior เป็น Supplementary Signals

| วิธีการ MFA | การนำไปใช้ | ความเสี่ยงในการ bypass |
|------------|-----------|----------------------|
| SMS OTP | ส่งรหัสทาง SMS | SIM Swapping, SS7 attacks, Phishing |
| TOTP | Authenticator App (Google Auth, Authy) | Real-Time Relay Phishing, Seed Theft |
| Push Notification | Duo, Microsoft Authenticator | MFA Fatigue / Push Bombing |
| Hardware Token | YubiKey, RSA SecurID | Physical Theft, Cost ต่อผู้ใช้ |
| FIDO2/WebAuthn | Public Key Cryptography ต่อ Site | **ปลอดภัยที่สุด** — ทนต่อ Phishing |
| Smart Card | CAC/PIV (US Government) | ต้องใช้ Card Reader |
| Biometrics | Fingerprint, Face ID | Spoofing ด้วย Deepfakes (ความเสี่ยงเพิ่มขึ้น) |

**เทคนิคการ bypass MFA ที่สำคัญ:**
- **MFA Fatigue Attack**: ส่ง Push Notification ซ้ำๆ จนผู้ใช้กดยอมรับ (Uber Breach 2022)
- **SIM Swapping**: โน้มน้าวให้ Carrier โอนหมายเลข (Twitter 2020, สูญเสีย 540M USD ใน Crypto)
- **Real-Time Phishing (EvilGinx2, Muraena)**: Proxy ที่ Relay Credentials + Session Cookies แบบ Real-Time
- **OAuth Token Theft**: ขโมย Session Tokens หลัง Authentication

### 3.2 Authorization (การกำหนดสิทธิ์)

**หลักการ:** การกำหนดว่าผู้ที่ผ่านการพิสูจน์ตัวตนแล้วสามารถเข้าถึงทรัพยากรใดได้บ้างและทำอะไรได้บ้าง โดยยึดหลัก **Least Privilege** — ให้สิทธิ์เท่าที่จำเป็นเท่านั้น

**คำถามที่ Authorization ตอบ:** "คุณทำอะไรได้บ้าง?" (What can you do?)

**โมเดลการควบคุมการเข้าถึง:**

| โมเดล | ใครควบคุม | ใช้หลักการอะไร | ความปลอดภัย | ความยืดหยุ่น | การใช้งาน |
|-------|-----------|---------------|------------|------------|----------|
| **DAC** (Discretionary) | เจ้าของข้อมูล | Owner-Set Permissions | **ต่ำ** | **สูง** | Unix chmod, Shared Drives |
| **MAC** (Mandatory) | ระบบ/Admin | Security Labels + Clearances | **สูงที่สุด** | **ต่ำ** | Military, Government (SELinux, AppArmor) |
| **RBAC** (Role-Based) | Admin | Roles → Permissions | **ปานกลาง-สูง** | **ปานกลาง** | Enterprise, ERP, SaaS |
| **ABAC** (Attribute-Based) | Admin/ระบบ | User + Resource + Environment Attributes | **สูง** | **สูงที่สุด** | Cloud, Zero Trust, Dynamic Environments |

**แนวทางปฏิบัติสมัยใหม่:** ระบบส่วนใหญ่ใช้ RBAC สำหรับการจัดระดับกว้าง + ABAC สำหรับการกำหนดข้อยกเว้นแบบละเอียด (Hybrid Approach)

### 3.3 Accounting (การบันทึกและการตรวจสอบ)

**หลักการ:** การติดตาม บันทึก และรายงานการกระทำของผู้ใช้ในระบบ เพื่อให้สามารถตรวจสอบย้อนหลัง (Audit Trail) และใช้เป็นหลักฐานในการสอบสวน

**คำถามที่ Accounting ตอบ:** "คุณทำอะไรไปแล้วบ้าง?" (What did you do?)

**ข้อมูลที่ควรบันทึก (ตาม OWASP, PCI DSS, ISO 27001):**
- **เมื่อใด** — Timestamp ของการกระทำ
- **ใคร** — User ID, Session ID, Source IP
- **อะไร** — Resource ที่ถูกเข้าถึง, Action ที่ทำ (Read, Write, Delete, Modify)
- **อย่างไร** — Success/Failure, วิธีการ, Privilege Changes
- **Authentication Attempts** — ทั้งที่สำเร็จและล้มเหลว

**รูปแบบ Log มาตรฐาน:**

| รูปแบบ | ตัวอย่าง |
|--------|---------|
| **Common Log Format (CLF)** | `127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /image.gif HTTP/1.0" 200 2326` |
| **Combined Log Format** | CLF + Referer + User-Agent |
| **Syslog (RFC 5424)** | Facility, Severity (0-7), Timestamp, Hostname, App, Message |
| **CEF (ArcSight)** | ArcSight Common Event Format — มี Structured Fields |
| **JSON/NDJSON** | Structured, Machine-Parseable — นิยมในระบบสมัยใหม่ |

### 3.4 RADIUS, TACACS+, และ Diameter

RADIUS, TACACS+ และ Diameter เป็นโพรโทคอลสำหรับทำ AAA ในระบบเครือข่าย:

| คุณสมบัติ | RADIUS | TACACS+ | Diameter |
|-----------|--------|---------|----------|
| **มาตรฐาน** | IETF (RFC 2865) | Cisco Proprietary → Open | IETF (RFC 6733) |
| **Transport** | UDP (พอร์ต 1812/1813) | TCP (พอร์ต 49) | TCP หรือ SCTP |
| **Encryption** | เข้ารหัสเฉพาะ Password | เข้ารหัสทั้ง Packet (Payload) | IPsec/TLS |
| **Auth + Authz** | รวมกัน | แยกกัน | แยกกัน |
| **Protocol** | Client/Server | Client/Server | Peer-to-Peer |
| **Vendor** | มาตรฐานเปิด | Cisco | มาตรฐานเปิด |
| **Use Case หลัก** | Network Access (VPN, 802.1X) | Device Admin (Router/Switch) | LTE/5G, IMS, Mobile Networks |
| **Accounting** | แยก Application | ในตัว | Built-in |
| **Failover** | จำกัด | จำกัด | Robust, Stateful |

**RADIUS**: ใช้กับ 802.1X มากที่สุด; รองรับ EAP Methods หลายแบบ (EAP-TLS, PEAP, EAP-TTLS)
**TACACS+**: นิยมสำหรับ Device Administration เพราะแยก AAA Functions ออกจากกัน
**Diameter**: ทายาทของ RADIUS; ใช้ใน 4G/5G Core Networks; รองรับ 1,000+ Attribute-Value Pairs (AVPs)

### 3.5 802.1X และ EAP Methods

**802.1X** เป็น Port-Based Network Access Control ประกอบด้วย 3 บทบาท:
1. **Supplicant** (อุปกรณ์ของผู้ใช้ - Client)
2. **Authenticator** (Switch, Access Point)
3. **Authentication Server** (RADIUS Server)

**EAP Methods (IANA Registry: 40+ Methods):**

| Method | ความปลอดภัย | ต้องใช้ Certificate | การใช้งาน |
|--------|------------|-------------------|-----------|
| **EAP-TLS** | **สูงที่สุด** | Client + Server | Enterprise Wireless; ปลอดภัยที่สุด |
| **EAP-TTLS** | สูง | Server เท่านั้น | Tunnel สำหรับ Legacy Auth |
| **PEAPv0/EAP-MSCHAPv2** | ปานกลาง-สูง | Server เท่านั้น | ใช้แพร่หลายที่สุด |
| **EAP-FAST** | ปานกลาง-สูง | Optional (PAC) | Cisco Environments |
| **EAP-SIM/AKA** | ปานกลาง | SIM Card | Mobile/Cellular Auth |
| **EAP-MD5** | **ต่ำ** | ไม่ต้อง | Legacy — **ไม่แนะนำ** |
| **LEAP** | **ต่ำ** | ไม่ต้อง | Cisco Legacy — **Deprecated** |

---

## 4. NIST Cybersecurity Framework (CSF) 2.0

### 4.1 ภาพรวม

NIST Cybersecurity Framework (CSF) 2.0 ได้รับการเผยแพร่เมื่อวันที่ **26 กุมภาพันธ์ 2024** โดย National Institute of Standards and Technology (NIST) ประเทศสหรัฐอเมริกา (CSWP 29) เป็นกรอบการทำงานที่ช่วยให้องค์กรทุกขนาดและทุกภาคส่วนสามารถบริหารจัดการความเสี่ยงด้าน Cybersecurity ได้อย่างเป็นระบบ

**การเปลี่ยนแปลงที่สำคัญจาก CSF 1.1:**
- ขยายขอบเขตจาก Critical Infrastructure → **ทุกองค์กร** (โรงเรียน, องค์กรไม่แสวงหากำไร, รัฐบาล, SME)
- เพิ่มฟังก์ชัน **Govern (GV)** ใหม่ — Governance ถูกยกระดับจาก Subcategory ใน Identify เป็น Function เต็ม
- **ไม่มีเนื้อหาใดถูกลบ** — ทุกเนื้อหาจาก 1.1 ยังคงอยู่ใน 2.0
- เพิ่ม **2 Categories ใหม่ใน Protect**: PR.PS (Platform Security) และ PR.IR (Technology Infrastructure Resilience)
- **Implementation Examples** แนบมากับทุก Subcategory
- **CSF 2.0 Reference Tool** — ค้นหาและ Export ข้อมูลในรูปแบบ Machine-Readable
- **Informative References Catalog** — Mapping ไปยัง 50+ Cybersecurity Documents

### 4.2 โครงสร้างของ CSF 2.0

CSF 2.0 ประกอบด้วย 3 ส่วนหลัก:

```
┌───────────────────────────────────────────────────────────┐
│                     CSF Core                               │
│  ประกอบด้วย 6 Functions → 22 Categories → 106 Subcategories     │
├───────────────────────────────────────────────────────────┤
│                   Organizational Profiles                   │
│  Current Profile (ปัจจุบัน) ↔ Target Profile (เป้าหมาย)          │
│  → Gap Analysis → Action Plan                             │
├───────────────────────────────────────────────────────────┤
│                   Implementation Tiers                     │
│  Tier 1 (Partial) → Tier 2 (Risk-Informed)                  │
│  → Tier 3 (Repeatable) → Tier 4 (Adaptive)                  │
└───────────────────────────────────────────────────────────┘
```

### 4.3 6 Functions ของ CSF 2.0

| ฟังก์ชัน | ตัวย่อ | จำนวน Categories | คำอธิบาย |
|---------|--------|-----------------|----------|
| **Govern** | GV | 6 | **ใหม่ใน 2.0** — กำหนดนโยบาย, บทบาท, ความเสี่ยง, และห่วงโซ่อุปทาน |
| **Identify** | ID | 3 | ระบุทรัพย์สิน, ประเมินความเสี่ยง, ปรับปรุง |
| **Protect** | PR | 5 | ป้องกัน — IAM, Training, Data Security, Platform, Resilience |
| **Detect** | DE | 2 | ตรวจจับ — Continuous Monitoring, Event Analysis |
| **Respond** | RS | 4 | ตอบสนอง — Incident Management, Analysis, Communication, Mitigation |
| **Recover** | RC | 2 | กู้คืน — Recovery Plan Execution, Communication |

### 4.4 รายละเอียด Categories ในแต่ละ Function

**Govern (GV): การกำกับดูแล — NEW**

| Category | ตัวย่อ | รายละเอียด | Key Subcategories |
|----------|--------|-----------|-------------------|
| Organizational Context | GV.OC | บริบทขององค์กร — ภารกิจ, กฎหมาย, ข้อบังคับ | Mission, Stakeholder Expectations, Legal/Regulatory |
| Risk Management Strategy | GV.RM | กลยุทธ์การบริหารความเสี่ยง | Risk Appetite, Tolerance, Enterprise Risk Integration |
| Roles, Responsibilities, Authorities | GV.RR | บทบาทและหน้าที่ด้าน Cybersecurity | Defined and Communicated Roles |
| Policy | GV.PO | นโยบายด้าน Cybersecurity | Established, Reviewed, Updated |
| Oversight | GV.OV | การกำกับดูแลและการตรวจสอบ | Board Oversight, Independent Review |
| Cybersecurity Supply Chain Risk Mgmt | GV.SC | การบริหารความเสี่ยงในห่วงโซ่อุปทาน | C-SCRM Processes, Supplier Risk, Third-Party Assessment |

**Identify (ID): การระบุ**

| Category | ตัวย่อ | รายละเอียด | การเปลี่ยนแปลงจาก 1.1 |
|----------|--------|-----------|---------------------|
| Asset Management | ID.AM | การบริหารจัดการทรัพย์สินทางเทคโนโลยี | ID.AM เหมือนเดิม |
| Risk Assessment | ID.RA | การประเมินความเสี่ยง | ID.RA เหมือนเดิม |
| Improvement | ID.IM | **ใหม่** — การปรับปรุงจากการเรียนรู้เหตุการณ์ | ย้ายมาจาก RC.IM (Improvements) |

**การเปลี่ยนแปลงจาก 1.1:** ID.BE (Business Environment) → GV.OC; ID.GV → GV.RM; ID.SC → GV.SC; ID.RM → GV.RM; ID.IM ใหม่

**Protect (PR): การป้องกัน**

| Category | ตัวย่อ | รายละเอียด |
|----------|--------|-----------|
| Identity Management, Authentication, Access Control | PR.AA | การจัดการตัวตน, Credentials, Access Permissions |
| Awareness and Training | PR.AT | การอบรมและสร้างความตระหนักรู้, Role-Based Training |
| Data Security | PR.DS | Data At Rest/In Transit, Encryption, Classification |
| **Platform Security** | **PR.PS** | **NEW** — Hardware, Software, Platform Hardening |
| **Technology Infrastructure Resilience** | **PR.IR** | **NEW** — Resilience, Redundancy, Capacity Management |

**Detect (DE): การตรวจจับ**

| Category | ตัวย่อ | รายละเอียด |
|----------|--------|-----------|
| Continuous Monitoring | DE.CM | การเฝ้าระวังอย่างต่อเนื่อง — Network, Physical, Personnel |
| Adverse Event Analysis | DE.AE | Event Correlation, Impact Analysis, Alert Triage |

**การเปลี่ยนแปลง:** DE.DP (Detection Processes) ถูกย้ายและรวมเข้ากับ GV, ID, DE

**Respond (RS): การตอบสนอง**

| Category | ตัวย่อ | รายละเอียด |
|----------|--------|-----------|
| Incident Management | RS.MA | **ขยายจาก RS.RP** — การจัดการเหตุการณ์ที่ครอบคลุมขึ้น |
| Incident Analysis | RS.AN | Investigation, Forensics, Root Cause |
| Incident Response Reporting & Communication | RS.CO | Internal/External Reporting, Stakeholder Communication |
| Incident Mitigation | RS.MI | Containment, Eradication |

**Recover (RC): การกู้คืน**

| Category | ตัวย่อ | รายละเอียด |
|----------|--------|-----------|
| Incident Recovery Plan Execution | RC.RP | **ขยายอย่างมีนัยสำคัญ** |
| Incident Recovery Communication | RC.CO | Internal/External Recovery Communication |

### 4.5 CSF Implementation Tiers

| ระดับ | ชื่อ | คำอธิบาย |
|------|------|----------|
| **Tier 1** | Partial (บางส่วน) | ไม่มีกระบวนการที่เป็นทางการ, ตอบสนองแบบ Reactively, Risk Management ไม่เป็นทางการ |
| **Tier 2** | Risk-Informed (ตระหนักถึงความเสี่ยง) | มีกระบวนการแต่ยังไม่ครอบคลุมทั้งองค์กร, ทำงานแบบ Siloed |
| **Tier 3** | Repeatable (ทำซ้ำได้) | มีกระบวนการที่ได้มาตรฐานทั่วทั้งองค์กร, วัดผลและปรับปรุง |
| **Tier 4** | Adaptive (ปรับตัวได้) | ปรับปรุงอย่างต่อเนื่อง, ใช้ข้อมูลเชิงลึกในการตัดสินใจแบบ Real-Time |

### 4.6 Organizational Profiles

- **Current Profile**: จุดที่องค์กรยืนอยู่ตอนนี้ (Current Cybersecurity Outcomes)
- **Target Profile**: จุดที่องค์กรต้องการไปให้ถึง
- **Gap Analysis**: ความแตกต่างระหว่าง Current และ Target Profile
- **Action Plan**: ขั้นตอนที่มีลำดับความสำคัญเพื่อปิด Gap

### 4.7 Informative References

CSF 2.0 มีการ Mapping ไปยัง 50+ เอกสาร รวมถึง:
- NIST SP 800-53 Rev. 5 — Security and Privacy Controls
- **ISO/IEC 27001:2022** — ISMS Requirements
- CIS Controls v8
- COBIT 2019
- NIST Privacy Framework
- NIST AI Risk Management Framework
- OWASP ASVS (Application Security Verification Standard)

---

## 5. ISO/IEC 27001:2022

### 5.1 ภาพรวมของ ISMS

**ISO/IEC 27001:2022** เป็นมาตรฐานสากลด้านการจัดการความปลอดภัยของข้อมูล (Information Security Management System — ISMS) ที่กำหนดข้อกำหนดสำหรับการจัดตั้ง ดำเนินการ ติดตาม ทบทวน และปรับปรุง ISMS ภายในองค์กร เผยแพร่เมื่อ **25 ตุลาคม 2022** แทนที่เวอร์ชัน 2013

**ISMS (Information Security Management System):** ระบบการจัดการที่ครอบคลุม People, Processes, และ IT Systems ผ่านกระบวนการบริหารความเสี่ยง เพื่อปกป้องข้อมูลขององค์กรอย่างเป็นระบบ

**ประโยชน์ของ ISMS (ตาม ISO):**
- ลดความเสี่ยงต่อการถูกโจมตีทางไซเบอร์
- มีกรอบการจัดการที่เป็นระบบและเป็นศูนย์กลาง
- พร้อมรับมือกับภัยคุกคามที่เปลี่ยนแปลง
- ได้เปรียบทางการแข่งขันผ่าน Certification
- ประหยัดต้นทุนผ่านประสิทธิภาพที่เพิ่มขึ้น

### 5.2 หลักการ PDCA (Plan-Do-Check-Act)

ISMS ใช้แนวคิดกระบวนการ PDCA:

```
┌─────────────────────────────────────────────────────────────┐
│ PLAN (วางแผน)                                                │
│  └── กำหนดขอบเขต ISMS, นโยบาย, ประเมินความเสี่ยง              │
│  └── เลือก Controls, สร้าง Risk Treatment Plan, จัดทำ SoA     │
│       ↓                                                       │
│ DO (ปฏิบัติ)                                                   │
│  └── ดำเนินการตาม Risk Treatment Plan                         │
│  └── ควบคุมการปฏิบัติงานตามกระบวนการที่กำหนด                    │
│       ↓                                                       │
│ CHECK (ตรวจสอบ)                                               │
│  └── ติดตาม วัดผล วิเคราะห์                                    │
│  └── Internal Audit, Management Review                         │
│       ↓                                                       │
│ ACT (ปรับปรุง)                                                 │
│  └── ปรับปรุงอย่างต่อเนื่อง (Continuous Improvement)             │
│  └── Corrective Actions, ปรับปรุง ISMS                         │
└─────────────────────────────────────────────────────────────┘
```

### 5.3 Annex A: 93 Controls แบ่งเป็น 4 หมวด

Annex A ของ ISO 27001:2022 ประกอบด้วยมาตรการควบคุมจำนวน **93 ข้อ** (ลดลงจาก 114 ข้อในเวอร์ชัน 2013 ผ่านการรวมข้อที่ซ้ำซ้อน) แบ่งเป็น 4 หมวด:

```
┌─────────────────────────────────────────────────────────────┐
│                    Annex A (93 Controls)                     │
├─────────────────────────────────────────────────────────────┤
│  A.5 Organizational Controls (37 ข้อ)                        │
│  │  — Governance, Policy, Risk, Supply Chain, Cloud         │
│  │  — Threat Intelligence, BC/DR, Project Management        │
│  A.6 People Controls (8 ข้อ)                                 │
│  │  — Screening, Training, Awareness, Disciplinary Process   │
│  │  — Remote Working                                         │
│  A.7 Physical Controls (14 ข้อ)                              │
│  │  — Physical Security Perimeters, Entry Controls            │
│  │  — Equipment Security, Cabling, Clear Desk/Clear Screen   │
│  A.8 Technological Controls (34 ข้อ)                         │
│  │  — Access Control, Cryptography, Secure Development        │
│  │  — DLP, Monitoring, Web Filtering, Secure Coding          │
└─────────────────────────────────────────────────────────────┘
```

**สถิติการเปลี่ยนแปลงจากเวอร์ชัน 2013:**
- 57 controls ถูก Merge
- 23 controls ถูก Rename
- 3 controls ถูกลบ
- **11 controls ถูกเพิ่มใหม่**

### 5.4 11 Controls ใหม่ใน ISO 27001:2022

| Control ID | ชื่อ | หมวด | คำอธิบาย |
|-----------|------|------|----------|
| **5.7** | Threat Intelligence | Organizational | รวบรวมและวิเคราะห์ข้อมูลภัยคุกคามเพื่อป้องกันเชิงรุก |
| **5.23** | Information Security for Cloud Services | Organizational | จัดการความปลอดภัยสำหรับบริการคลาวด์ — Shared Responsibility Model |
| **5.30** | ICT Readiness for Business Continuity | Organizational | ความพร้อมของ ICT สำหรับความต่อเนื่องทางธุรกิจ |
| **7.4** | Physical Security Monitoring | Physical | การตรวจสอบทางกายภาพอย่างต่อเนื่องเพื่อตรวจจับการบุกรุก |
| **8.9** | Configuration Management | Technological | จัดการ Configuration ของระบบ — Baseline Hardening |
| **8.10** | Information Deletion | Technological | การลบข้อมูลอย่างปลอดภัยเมื่อไม่จำเป็นต้องใช้แล้ว |
| **8.11** | Data Masking | Technological | การปกปิดข้อมูลตามนโยบาย Access Control และ Data Classification |
| **8.12** | Data Leakage Prevention (DLP) | Technological | ป้องกันการรั่วไหลของข้อมูลโดยไม่ได้รับอนุญาต |
| **8.16** | Monitoring Activities | Technological | ตรวจสอบเครือข่ายและระบบเพื่อหาพฤติกรรมผิดปกติ |
| **8.23** | Web Filtering | Technological | จัดการการเข้าถึงเว็บไซต์ — ปิดกั้นเนื้อหาที่เป็นอันตราย |
| **8.28** | Secure Coding | Technological | ใช้หลักการ Secure Coding ตลอด SDLC |

### 5.5 Statement of Applicability (SoA)

SoA เป็นเอกสารบังคับตาม ISO 27001 **Clause 6.1.3(d)** ที่องค์กรต้องจัดทำขึ้นเพื่อ:
- แสดงรายการควบคุมทั้งหมด **93 ข้อ**
- ระบุว่า Control ใด **Applicable** และ Control ใด **Excluded**
- ให้เหตุผลสำหรับการ Exclude แต่ละ Control
- ระบุ Implementation Status สำหรับ Applicable Controls
- อ้างอิง Policy/Procedure ที่เกี่ยวข้อง

### 5.6 กระบวนการ Risk Assessment & Treatment (Clause 6.1)

**1. Risk Assessment (6.1.2):**
- Define และ Apply Risk Assessment Methodology
- Identify Risks (Threats × Vulnerabilities × Assets)
- Analyze Likelihood และ Impact
- Evaluate Risks กับ Acceptance Criteria

**2. Risk Treatment (6.1.3):**
- Select Treatment Options: **Mitigate, Transfer, Accept, Avoid**
- Determine Necessary Controls (จาก Annex A หรืออื่นๆ)
- เปรียบเทียบกับ Annex A เพื่อยืนยันว่าไม่มี Control ใดถูกละเว้น
- **จัดทำ Statement of Applicability (SoA)**
- จัดทำ Risk Treatment Plan พร้อม Responsible Persons, Timelines, Resources, Success Criteria
- ขออนุมัติจาก Risk Owner

### 5.7 ISO 27001 vs ISO 27002

| มิติ | ISO 27001 | ISO 27002 |
|------|-----------|-----------|
| **ประเภท** | Requirements Standard (**Certifiable**) | Guidelines / Code of Practice |
| **วัตถุประสงค์** | สิ่งที่องค์กร **ต้องทำ** (Requirements) | **วิธีการ** Implement Controls (Guidance) |
| **Clauses** | Clauses 4-10 (Mandatory) | Guidance Only |
| **Annex A** | รายการ 93 Controls (Normative) | รายละเอียด Control (Informative) |
| **Certification** | Yes — Third-Party Audit | No |

---

## 6. การเปรียบเทียบ NIST CSF 2.0 และ ISO/IEC 27001:2022

| มิติ | NIST CSF 2.0 | ISO/IEC 27001:2022 |
|------|--------------|-------------------|
| **ลักษณะ** | กรอบแนวคิด (Framework) | มาตรฐานที่รับรองได้ (Certifiable Standard) |
| **การรับรอง** | ไม่มีการรับรอง | มีการรับรองโดย Certification Body |
| **โครงสร้าง** | 6 Functions → 22 Categories → 106 Subcategories | Clauses 4-10 + Annex A (93 Controls, 4 Themes) |
| **ภาษา** | Outcomes-Based (What to achieve) | Requirements-Based (What to implement) |
| **การนำไปใช้** | ทุกองค์กร ทุกขนาด | ทุกองค์กร ทุกขนาด |
| **การปรับใช้** | ยืดหยุ่น — เลือกใช้ตามความเหมาะสม | ต้องใช้ทุกข้อหรือระบุข้อยกเว้นใน SoA |
| **ระดับรายละเอียด** | ระดับสูง (Strategic) | ระดับกลาง (Operational) |
| **การจัดการความเสี่ยง** | Risk-Based | Risk-Based |
| **ความสัมพันธ์** | CSF 2.0 อ้างอิง ISO 27001 เป็น Informative Reference | ISO 27001 สามารถใช้คู่กับ CSF 2.0 ได้ |

**แนวทางการเลือกใช้:**
- องค์กรที่ต้องการ **ความยืดหยุ่น** และ **แนวทางเชิงกลยุทธ์** → NIST CSF 2.0
- องค์กรที่ต้องการ **Certification** และ **มาตรฐานที่ตรวจสอบได้** → ISO 27001:2022
- องค์กรที่ต้องการทั้งสองอย่าง → ใช้ NIST CSF 2.0 เป็นกรอบภาพรวม และ ISO 27001 เป็นมาตรฐานสำหรับการดำเนินงาน

---

## 7. กรณีศึกษา (Case Studies)

### 7.1 Colonial Pipeline Ransomware Attack (2021)

| รายการ | รายละเอียด |
|--------|------------|
| **วันที่เกิดเหตุ** | 7 พฤษภาคม 2021 |
| **ผู้โจมตี** | DarkSide (Ransomware-as-a-Service) |
| **ประเภท** | Ransomware + Data Exfiltration (Double Extortion) |
| **ค่าเสียหาย** | จ่ายค่าไถ่ 4.4 ล้าน USD (75 BTC) — FBI กู้คืนได้ ~2.3 ล้าน USD |

**เส้นทางการโจมตี (Attack Timeline):**

```
29 เม.ย. 2021 — เข้าถึงเครือข่ายครั้งแรกผ่าน VPN Account ที่ไม่มีการใช้งานแล้ว
                    └── Credential รั่วไหล (พบใน Dark Web — reused password)
                    └── **ไม่มี MFA** — จุดอ่อนสำคัญที่สุด
   ↓
30 เม.ย.-6 พ.ค. — ยกระดับสิทธิ์, ขโมยข้อมูล 100 GB (Billing Data), วาง Ransomware
                    └── PowerShell สำหรับ Deployment, RDP สำหรับ Persistence
                    └── Shadow Copy ถูกลบเพื่อป้องกัน Recovery
   ↓
7 พ.ค. 05:00 น. — พนักงานพบ Ransom Note บน Control Room Computer
7 พ.ค. 06:10 น. — ปิดระบบท่อส่งน้ำมันยาว 5,500 ไมล์ (ป้องกันการแพร่กระจายไปยัง OT)
   ↓
8 พ.ค. — จ่ายค่าไถ่ 4.4 ล้าน USD (75 Bitcoin) — ได้ Decryption Tool (แต่ทำงานช้า)
   ↓
10-12 พ.ค. — Panic Buying ทั่ว SE USA — ปั๊มน้ำมัน 11,000+ แห่งขาดแคลน
   ↓
12 พ.ค. — เริ่มเดินระบบอีกครั้ง (หยุด 6 วัน)
   ↓
ต่อมา — FBI กู้คืน Bitcoin ได้ ~2.3 ล้าน USD โดยยึด Private Key ของ DarkSide Wallet
```

**การวิเคราะห์สาเหตุหลัก (Root Cause):**
- **Primary**: VPN Profile ที่ไม่ได้ใช้แล้วแต่ยังเปิดอยู่ — ไม่มี MFA — Password รั่วจาก Data Breach ก่อนหน้า
- **Contributing**: ไม่มี Access Review, ไม่มีการ Monitor VPN Access, IT/OT ไม่ได้ Segmentation ที่ดีพอ

**MITRE ATT&CK Techniques ที่ใช้ในการโจมตี:**

| Tactic | Technique ID | ชื่อ | รายละเอียด |
|--------|-------------|------|-----------|
| Initial Access | T1133 | External Remote Services | Legacy VPN Exploitation |
| Initial Access | T1078 | Valid Accounts | Compromised VPN Credentials |
| Execution | T1059 | Command & Scripting Interpreter | PowerShell |
| Persistence | T1021.001 | Remote Services: RDP | RDP สำหรับ Persistence |
| Defense Evasion | T1562.001 | Impair Defenses: Disable/Modify Tools | Shadow Copy Deletion |
| Lateral Movement | T1021.001 | Remote Services: RDP | Lateral Movement ทั่ว IT Network |
| Command & Control | T1090.003 | Proxy: Multi-hop Proxy | Tor Network สำหรับ C2 |
| Command & Control | T1071 | Application Layer Protocol | Cobalt Strike C2 |
| Exfiltration | T1567 | Exfiltration Over Web Service | ขโมยข้อมูล 100 GB |
| Impact | T1486 | Data Encrypted for Impact | DarkSide Ransomware Encryption |

**ผลกระทบ:**

| ด้าน | รายละเอียด |
|------|-----------|
| **Operational** | ท่อส่ง 5,500 ไมล์หยุด 6 วัน — 45% ของ East Coast Fuel (100M แกลลอน/วัน) |
| **Financial** | ค่าไถ่ 4.4M USD + ค่า Recovery — รวมประมาณ 5-10M USD |
| **Societal** | Panic Buying, รัฐ 17 แห่ง + DC ประกาศสถานการณ์ฉุกเฉิน, ราคาน้ำมันเพิ่ม 2-3 cents/gallon |
| **Regulatory** | TSA ออก Security Directives ใหม่, Executive Order 14028 |

**บทเรียนที่ได้:**

| บทเรียน | แนวทางปฏิบัติ |
|---------|-------------|
| **เปิด MFA ทุกจุด** | โดยเฉพาะ Remote Access (VPN, RDP, VDI) — CISA/FBI Primary Recommendation |
| **ตรวจจับและลบบัญชีที่ไม่ใช้งาน** | Quarterly Access Reviews — Dormant Account Detection |
| **แยก IT และ OT Network** | Controlled Conduits + Monitoring — ป้องกัน Lateral Movement |
| **มี Incident Response Plan** | ฝึกซ้อม IR Plan อย่างสม่ำเสมอ — Communication Protocols |
| **Backup ที่แยกออกจากเครือข่าย** | 3-2-1 Backup Rule + Immutable Backup + Offline Backup |
| **จับตาดู Dark Web** | Credential Monitoring — รู้ว่า Password ของคุณรั่วหรือไม่ |

**การเปลี่ยนแปลงหลังจากเหตุการณ์:**
- **TSA Security Directives** (2021-2022): กำหนด Cybersecurity Coordinator, รายงาน Incidents ภายใน 12 ชม.
- **Executive Order 14028** (พ.ค. 2021): Improving Nation's Cybersecurity
- **CISA Joint Cyber Defense Collaborative (JCDC)** ก่อตั้งขึ้น
- **Cyber Incident Reporting for Critical Infrastructure Act (CIRCIA)** 2022
- **Pipeline-Specific Cybersecurity Performance Goals (CPGs)**

### 7.2 SolarWinds Supply Chain Attack (2020)

| รายการ | รายละเอียด |
|--------|------------|
| **วันที่ตรวจพบ** | ธันวาคม 2020 (FireEye ค้นพบและเปิดเผย 12 ธ.ค. 2020) |
| **ผู้โจมตี** | NOBELIUM / APT29 / Cozy Bear — Russian Foreign Intelligence Service (SVR) |
| **ประเภท** | Supply Chain Attack + Backdoor |

**เส้นทางการโจมตี:**

```
ต้น 2019 — NOBELIUM เริ่ม Reconnaissance Build Environment ของ SolarWinds
   ↓
ต.ค. 2019 — ทดสอบ Injection — Empty Classes ถูกแทรกเพื่อทดสอบ
   ↓
ก.พ. 2020 — SUNBURST Backdoor ถูก Compile เข้าไปใน Orion DLL
               └── SUNSPOT Code Injector รันบน Build Server
               └── Source Code Repository สะอาด — ไม่มี Malicious Code
               └── DLL ถูก Sign ด้วย Certificate จริงของ SolarWinds
   ↓
มี.ค. 2020 — Orion 2019.4 Hotfix 5 เผยแพร่ — มี Trojanized DLL
   ↓
เม.ย. 2020 — DNS Beaconing ไปยัง avsvmcloud[.]com เริ่ม (หลังรอ 2 สัปดาห์)
   ↓
พ.ค.-พ.ย. 2020 — Hands-on-Keyboard บนเครือข่ายเหยื่อ — C2, Lateral Movement, Exfil
   ↓
12 ธ.ค. 2020 — FireEye ตรวจพบและเปิดเผย SUNBURST
15 ธ.ค. 2020 — Microsoft + GoDaddy Sinkhole avsvmcloud[.]com — Killswitch ทำงาน
```

**รายละเอียดทางเทคนิคของ SUNBURST:**

| คุณสมบัติ | รายละเอียด |
|-----------|------------|
| **ไฟล์** | `SolarWinds.Orion.Core.BusinessLayer.dll` — ~4,000 บรรทัด Malicious Code |
| **การ Sign** | Digitally Signed ด้วย SolarWinds' Legitimate Certificate |
| **Dormancy** | รอ **2 สัปดาห์** ก่อนเริ่มกิจกรรม — หลบเลี่ยง Sandbox/Analysis |
| **Anti-Analysis** | Blacklist Forensic/AV Tools: Carbon Black, CrowdStrike, SentinelOne, FireEye, Defender, ESET, F-SECURE |
| **C2 Protocol** | DNS-Based C2 ผ่าน DGA (avsvmcloud[.]com) — Traffic ปลอมเป็น Orion Improvement Protocol (OIP) |
| **DGA Details** | Subdomain = `[encoded_userID][encoded_domain].avsvmcloud[.]com` — Reversible Encoding |

**SUNSPOT Code Injector:**
- **ไม่เคยถูก Distributed ไปยัง Customer** — พบเฉพาะบน Build Servers ของ SolarWinds
- รันใน Background เฝ้าดู Build ใหม่ของ Orion
- ที่ Build Time: Inject SUNBURST Malicious Code เข้าไปใน Source File ชั่วคราว
- หลัง Compile: ลบ Temp File — **Source Code Repository สะอาด**
- ค้นพบโดย **KPMG** ระหว่าง Forensic Investigation

**MITRE ATT&CK Techniques:**

| Tactic | Technique ID | ชื่อ |
|--------|-------------|------|
| Initial Access | T1195.002 | Compromise Software Supply Chain |
| Execution | T1569.002 | Service Execution |
| Defense Evasion | T1027 | Obfuscated Files or Information |
| Defense Evasion | T1553.002 | Code Signing |
| Discovery | T1083 | File and Directory Discovery |
| Discovery | T1518.001 | Security Software Discovery |
| Discovery | T1057 | Process Discovery |
| Command & Control | T1071.001 | Web Protocols |
| Command & Control | T1071.004 | DNS |
| Command & Control | T1568.002 | Domain Generation Algorithms |
| Persistence | T1543.003 | Windows Service |

**ผลกระทบ:**

| ด้าน | รายละเอียด |
|------|-----------|
| **จำนวนผู้ได้รับผลกระทบ** | 18,000 Customers ได้รับ Trojanized Update; ~100 องค์กรถูกเจาะลึก |
| **หน่วยงานรัฐบาลสหรัฐฯ** | Treasury, Commerce, State, Energy, Homeland Security, NIH |
| **บริษัทเอกชน** | Microsoft, FireEye, Cisco, Intel, Deloitte, Nvidia, VMware, Malwarebytes |
| **ประเทศที่ได้รับผลกระทบ** | US, UK, Canada, Mexico, Belgium, Spain, Israel, UAE |

**SBOM — Software Bill of Materials:**

**คำจำกัดความ (ตาม NTIA):** บันทึกทางการที่ประกอบด้วยรายละเอียดและความสัมพันธ์ใน Supply Chain ของ Components ที่ใช้ในการสร้าง Software

**องค์ประกอบสำคัญ:** ชื่อ Component, เวอร์ชัน, Supplier, Dependency Relationships, Hash ของแต่ละ Component, License Information

**มาตรฐาน:** SPDX (ISO/IEC 5962:2021), CycloneDX (OWASP), SWID (ISO/IEC 19770-2)

**Executive Order 14028** กำหนดให้ SBOM เป็นข้อบังคับสำหรับ Software ที่ขายให้กับ US Government

**บทเรียนที่ได้:**

| บทเรียน | แนวทางปฏิบัติ |
|---------|-------------|
| **Supply Chain Risk Management** | ตรวจสอบ Security Posture ของ Vendor ทุกราย |
| **Software Bill of Materials (SBOM)** | รู้ Component ทั้งหมดใน Software — ตรวจสอบได้ |
| **Zero Trust Architecture** | ไม่เชื่อถือ Software หรือ Device ใดโดยปริยาย |
| **Build Environment Security** | แยก Build Environment, Secure CI/CD, Code Signing Protection |
| **Code Signing Protection** | ปกป้อง Code Signing Certificate อย่างเข้มงวด — HSM |
| **Endpoint Detection and Response (EDR)** | ใช้ EDR ตรวจจับพฤติกรรมผิดปกติ |
| **Runtime Integrity Monitoring** | ตรวจจับพฤติกรรมที่ไม่คาดคิดของ Application |

### 7.3 Mirai Botnet / Dyn DNS DDoS Attack (2016)

| รายการ | รายละเอียด |
|--------|------------|
| **วันที่เกิดเหตุ** | 21 ตุลาคม 2016 |
| **ผู้โจมตี** | Mirai Botnet (เขียนโดย Paras Jha "Anna-senpai" — รับสารภาพผิด 2017) |
| **ประเภท** | DDoS (Distributed Denial of Service) — IoT Botnet |

**เส้นทางการโจมตี:**

```
IoT Devices (กล้องวงจรปิด, DVR, Router) ถูกติดตั้ง Mirai Malware
    └── สแกน Internet ทั่วโลกที่ TCP Port 23 และ 2323 (Telnet)
    └── ใช้ 62 Hardcoded Default Credentials (admin:admin, root:root, ฯลฯ)
    └── Device Phone Home ไปยัง C2 Server — กลายเป็น Bot
   ↓
21 ต.ค. 2016 — สั่ง Botnet ~50,000-100,000 เครื่อง
                 โจมตี DNS Provider Dyn (DNS Water Torture + Amplification)
   ↓
DNS Resolution ของเว็บไซต์ใหญ่ล้มเหลว — 3 Waves ตลอดทั้งวัน:
    Twitter, Netflix, Reddit, CNN, Spotify, Airbnb, Pinterest, The Guardian, PayPal, GitHub, Etsy, NYT
   ↓
Traffic สูงสุด: ~1.2 Tbps — 30+ Attack Commands — DNS Response Time 500ms → 16 วินาที
```

**รายละเอียดทางเทคนิคของ Mirai:**

| คุณสมบัติ | รายละเอียด |
|-----------|------------|
| **ภาษา** | C (สำหรับ Bot), Go (สำหรับ C2 Server) |
| **Target Ports** | TCP 23 และ 2323 (Telnet) |
| **Credentials** | 62 Hardcoded Default Username/Password Pairs |
| **Self-Protection** | Blocklist คู่แข่ง, Process Scanning, Telnet/SSH Port Blocking |
| **Persistence** | RAM-Only — Reboot ล้าง แต่ติดตั้งใหม่ได้ทันที (Rapid Reinfection) |
| **Source Code** | เผยแพร่สู่สาธารณะ 30 ก.ย. 2016 — นำไปสู่ Mirai Forks มากมาย |

**DDoS Capabilities:**
- UDP Flood, ACK Flood, SYN Flood
- GRE IP/GRE ETH Flood
- DNS Water Torture (Subdomain Attack)
- HTTP Flood (Layer 7)
- STOMP Flood

**IoT Vulnerability Landscape (2016):**
- อุปกรณ์หลายสิบล้านชิ้นใช้ Default Passwords
- Telnet/SSH เปิดบน WAN Interface
- อุปกรณ์จำนวนมากไม่สามารถ Patch ได้ (No Update Mechanism)
- XiongMai Technologies เพียงเจ้าเดียวมีอุปกรณ์เสี่ยง 515,000+ เครื่อง
- แหล่งข้อมูล Rapid7: 15M Public Telnet Servers ทั่วโลก

**การโจมตีของ Mirai ที่สำคัญก่อน Dyn:**

| วันที่ | Target | Traffic |
|-------|--------|---------|
| ส.ค. 2016 | Incapsula (GRE Floods) | 280 Gbps |
| 20 ก.ย. 2016 | Brian Krebs' Blog | 620 Gbps — สูงสุดในเวลานั้น |
| ปลาย ก.ย. 2016 | OVH (French Webhost) | 1.1-1.5 Tbps — สถิติโลกใหม่ |
| 21 ต.ค. 2016 | Dyn DNS | ~1.2 Tbps |

**บทเรียนที่ได้:**

| บทเรียน | แนวทางปฏิบัติ |
|---------|-------------|
| **IoT Device Security** | เปลี่ยน Default Password ทุกครั้ง, ปิด Telnet, ใช้ SSH |
| **DDoS Mitigation Strategy** | ใช้ DDoS Protection Service (Cloudflare, AWS Shield, Akamai) |
| **DNS Redundancy** | ใช้ DNS Provider หลายราย (Multi-Vendor) |
| **Network Monitoring** | ตรวจจับ Traffic Anomaly ก่อนถึงขั้นรุนแรง |
| **IoT Segmentation** | แยก IoT Devices ไว้คนละ VLAN |
| **Outbound Filtering** | IoT Devices ไม่ควร Initiate Arbitrary External Connections |
| **Vendor Liability** | ผลักดันความรับผิดชอบไปยัง Manufacturer (Cyber Resilience Act 2024/2847) |

**ความคืบหน้าด้าน IoT Security นับตั้งแต่นั้น:**
- **California SB-327** (2018): กฎหมายฉบับแรกในสหรัฐฯ ที่กำหนดให้ IoT Devices มี Security Features
- **EU Cyber Resilience Act** (Regulation 2024/2847): กำหนด Security Requirements สำหรับ Products with Digital Elements
- **NIST IR 8425**: IoT Device Cybersecurity Guidance
- **IoT Botnets ยังคงมีอยู่**: Mozi, Gafgyt (Bashlite Successor), FBot
- **Global IoT Devices**: 18+ พันล้านเครื่อง (2025, est.)

---

## 8. สถิติและแนวโน้มด้าน Network Security

### 8.1 IBM Cost of Data Breach Report 2025

| ตัวชี้วัด | ค่า | การเปลี่ยนแปลง |
|----------|-----|---------------|
| ค่าเสียหายเฉลี่ยโลก | 4.44 ล้าน USD | ลดลง 9% จาก 2024 (ลดครั้งแรกใน 5 ปี) |
| ค่าเสียหายเฉลี่ยในสหรัฐอเมริกา | 10.22 ล้าน USD | เพิ่มขึ้น 9% — สูงเป็นประวัติการณ์ |
| Healthcare | 7.42 ล้าน USD | สูงสุด (14 ปีติดต่อกัน) |
| Financial Services | 5.56 ล้าน USD | อันดับสอง |
| เวลาตรวจจับ (Mean Time to Identify) | 158 วัน | ต่ำสุดในรอบ 9 ปี |
| เวลาควบคุม (Mean Time to Contain) | 83 วัน | — |
| % ที่องค์กรตรวจจับได้เอง | 42% | เพิ่มขึ้นจาก 33% |
| AI + Automation — ลดค่าเสียหาย | 1.9 ล้าน USD | เทียบกับองค์กรที่ไม่ใช้ AI |
| AI Governance Gap | 97% ของ AI-Related Breaches ขาด Access Control | 63% ไม่มี AI Governance Policy |
| Shadow AI | 20% ของ Breaches เกี่ยวข้องกับ Shadow AI | เพิ่มค่าเสียหาย 670K USD |
| Phishing | 16% | Top Attack Vector |
| Malicious Insider | 4.92 ล้าน USD | Highest Cost Vector |
| Supply Chain | 4.91 ล้าน USD | Second Costliest; Longest Lifecycle (267 วัน) |

### 8.2 Verizon 2025 Data Breach Investigations Report (DBIR)

| ตัวชี้วัด | ค่า |
|----------|-----|
| Dataset | 22,052 Incidents, 12,195 Confirmed Breaches, 139 ประเทศ |
| Ransomware in Breaches | **44%** (เพิ่มขึ้น 37% YoY จาก 32%) |
| Vulnerability Exploitation | **20%** (เพิ่มขึ้น 34% YoY — แซง Phishing) |
| Edge Device/VPN Attacks | เพิ่มขึ้น **8 เท่า** (22% ของ Vulnerability Exploitations) |
| Third-Party Involvement | **30%** (เพิ่มขึ้นเท่าตัวจาก 15%) |
| Credential Abuse | **22%** — ยังคงอันดับหนึ่ง |
| Human Element | **60%** |
| Espionage | **17%** (เพิ่มขึ้นอย่างมีนัยสำคัญ) |
| SMB Ransomware | **88%** ของ SMB Breaches (vs 39% สำหรับ Large Orgs) |
| Median Ransom Payment | 115,000 USD (ลดลงจาก 150,000) |
| Non-Payment Rate | 64% (เพิ่มขึ้นจาก 50% เมื่อ 2 ปีก่อน) |
| Infostealer Credentials | 30% Enterprise Devices; 46% Non-Managed (BYOD) |
| Patching Gap | แค่ 54% ของ Edge Device Vulns ได้รับการแก้ไข — Median 32 วัน |

### 8.3 ENISA Threat Landscape 2025

| ตัวชี้วัด | ค่า |
|----------|-----|
| ระยะเวลา | กรกฎาคม 2024 — มิถุนายน 2025 |
| Incidents ที่วิเคราะห์ | 4,875 |
| DDoS Attacks | **76.7%** ของ incidents ทั้งหมด (ส่วนใหญ่มาจาก Hacktivist) |
| Ransomware | **Most Impactful** Threat ใน EU |
| Hacktivism | 79% ของ Incidents (ส่วนใหญ่เป็น Low-Impact DDoS) |
| State-Aligned | 7.2% ของ Incidents; 46 Distinct Intrusion Sets |
| Phishing (Initial Intrusion) | 60% |
| AI-Generated Phishing | >80% ของแคมเปญทั้งหมด |
| CVEs ใหม่ | 42,595 (เพิ่มขึ้น 27% YoY) |
| Sectors ที่ถูกโจมตีมากที่สุด | Public Admin 38.2%, Transport 7.5%, Digital Infrastructure 4.8%, Finance 4.5% |

### 8.4 สถิติ Ransomware เฉพาะทาง

| แหล่งที่มา | ตัวชี้วัด | ค่า |
|-----------|-----------|-----|
| **Chainalysis 2025** | ยอดรวมจ่ายค่าไถ่ 2024 | 813.55 ล้าน USD (ลดลง 35% YoY) |
| **BlackFog 2025** | Disclosed Attacks เพิ่มขึ้น | 49% YoY (1,174 Incidents) |
| **BlackFog 2025** | Undisclosed Attacks | 86% ไม่เคยรายงานต่อสาธารณะ |
| **Sophos 2025** | Median Ransom Demand | 1.20 ล้าน USD (ลดลง 56% YoY) |
| **Sophos 2025** | Median Ransom Paid | 1.0 ล้าน USD |
| **CheckPoint 2025** | Monthly Victims | ~535/month (เพิ่มขึ้นจาก 420 YoY) |
| **Coveware Q4 2024** | Payment Rate | 25% — All-Time Low |
| **Verizon DBIR 2025** | Ransomware in Breaches | 44% |

**กลุ่ม Ransomware ที่ Active (Q3 2025):** Qilin (~75 victims/month), LockBit (re-emerged), 85+ Active Data Leak Sites

### 8.5 Zero Trust Adoption

| ตัวชี้วัด | ค่า | แหล่งที่มา |
|-----------|-----|-----------|
| Market Size 2024 | 36.96 พันล้าน USD | Grand View Research |
| Market Size 2025 | 41.5-50.9 พันล้าน USD | Multiple Sources |
| Projected 2030 | 92.42-121.6 พันล้าน USD | Multiple Sources |
| CAGR | 14.7%-17.7% | Multiple Sources |
| องค์กรที่ Adopt (ทั้งหมดหรือบางส่วน) | 63% | Gartner |
| อยู่ระหว่าง Adopt | 46% | Survey 2,200 Leaders |
| ไม่มีแผน Zero Trust | 11% | Survey 2,200 Leaders |
| Asia-Pacific CAGR | 16.87% (เร็วที่สุด) | Kings Research |

### 8.6 Cybersecurity Skills Gap

| ตัวชี้วัด | ค่า | แหล่งที่มา |
|-----------|-----|-----------|
| องค์กรที่มี Skills Shortage | **95%** | ISC2 2025 |
| Critical/Significant Shortage | **59%** (เพิ่มจาก 44% ใน 2024) | ISC2 2025 |
| มีผลกระทบจาก Skills Gap | **88%** | ISC2 2025 |
| Top Skill ที่ต้องการ | AI/ML **41%** | ISC2 2025 |
| ทักษะอันดับสอง | Cloud Security **36%** | ISC2 2025 |
| Budget Cuts | 36% | ISC2 2025 |
| จำนวนผู้ตอบแบบสอบถาม | 16,029 | ISC2 2025 |

**หมายเหตุสำคัญ:** ISC2 2025 ไม่ได้เผยแพร่ตัวเลข Global Workforce Gap — เปลี่ยนโฟกัสจาก Headcount เป็น **Skills**

---

## 9. Security Governance และการบริหารความเสี่ยง

### 9.1 กรอบการบริหารความเสี่ยง (Risk Management Frameworks)

| Framework | ขอบเขต | Methodology | ผลลัพธ์ | Certifiable |
|-----------|--------|-------------|---------|-------------|
| **ISO 31000:2018** | องค์กรทั้งหมด (Enterprise) | คุณภาพ (Qualitative) / หลักการ | Risk Register, Treatment Plan | ไม่มี |
| **COSO ERM (2017)** | องค์กรทั้งหมด — เน้น Governance | คุณภาพ (Qualitative) | Risk Appetite, Strategy Alignment | ไม่มี |
| **FAIR** | ภัยคุกคามทางไซเบอร์เท่านั้น | **ปริมาณ (Quantitative)** — เป็นตัวเลขเงิน | Annual Loss Expectancy (ALE) | ไม่มี |
| **NIST RMF** | ระบบสารสนเทศของรัฐบาลสหรัฐฯ | แบบขั้นตอน 7 ขั้นตอน | System Authorization | ไม่มี |
| **ISO 27001** | ISMS | Risk-Based Controls | ISMS Certification | **มี** |

**คำอธิบายเพิ่มเติม:**

**ISO 31000:2018:**
- หลักการ: "Risk management creates and protects value"
- กระบวนการ: Communication & Consultation → Establish Context → Risk Assessment (ID → Analyze → Evaluate) → Risk Treatment → Monitoring & Review
- ยืดหยุ่น — ไม่กำหนดวิธีการเฉพาะ

**COSO ERM (2017 Update):**
- 20 Principles ใน 5 Components: Governance & Culture; Strategy & Objective-Setting; Performance; Review & Revision; Information, Communication & Reporting
- Strong on Board Oversight, Risk Appetite Definition

**FAIR (Factor Analysis of Information Risk):**
- Quantitative Cyber Risk Analysis — ผลลัพธ์เป็นตัวเลขเงิน
- สูตร: **Loss Event Frequency × Loss Magnitude = Risk ($/year)**
- SLE (Single Loss Expectancy) = Asset Value × Exposure Factor
- ARO (Annualized Rate of Occurrence)
- ALE (Annualized Loss Expectancy) = SLE × ARO

### 9.2 Security Policy Hierarchy

| ระดับ | ประเภทเอกสาร | คำอธิบาย | ตัวอย่าง |
|------|-------------|----------|---------|
| **1** | **Policies** | เจตนารมณ์ระดับบริหาร — บังคับ | "ข้อมูลทั้งหมดต้องถูกเข้ารหัส" |
| **2** | **Standards** | กฎเกณฑ์บังคับที่สนับสนุน Policy | "ต้องใช้ AES-256 สำหรับ Encryption" |
| **3** | **Procedures** | ขั้นตอนการปฏิบัติทีละขั้น | "วิธีการเข้ารหัส Laptop ด้วย BitLocker" |
| **4** | **Guidelines** | คำแนะนำ (ไม่บังคับ) | "ควรพิจารณาใช้ Tools เพิ่มเติมสำหรับ Key Management" |
| **5** | **Baselines** | การกำหนดค่า Security ขั้นต่ำ | "Windows 11 Security Baseline" |

### 9.3 บทบาทและหน้าที่ด้าน Cybersecurity

| บทบาท | ความรับผิดชอบหลัก |
|-------|------------------|
| **CISO** | กลยุทธ์, Governance, Risk Appetite, การสื่อสารกับ Board, งบประมาณ |
| **Security Architect** | ออกแบบระบบรักษาความปลอดภัย, Reference Architectures, Security Patterns |
| **SOC Analyst** | ติดตาม Alert, Triage Incidents, Escalation |
| **Incident Responder** | Contain, Eradicate, Recovery จาก Security Incidents |
| **Security Engineer** | Implement, Configure, บำรุงรักษา Security Tools (FW, IDS, EDR, SIEM) |
| **Penetration Tester** | Ethical Hacking, Vulnerability Assessment, Red Team |
| **GRC Analyst** | Compliance Audits, Policy Development, Risk Assessments |
| **IAM Administrator** | Identity Lifecycle, Access Reviews, MFA/SSO Administration |
| **Security Awareness Manager** | Training Programs, Phishing Simulations, Culture Change |
| **Data Protection Officer (DPO)** | Privacy Compliance, DPIAs, Data Subject Rights |

### 9.4 ภาพรวมกฎหมายและข้อบังคับที่เกี่ยวข้อง

| กฎหมาย/ข้อบังคับ | ขอบเขต | ข้อกำหนดสำคัญ | บทลงโทษ |
|-----------------|--------|--------------|---------|
| **GDPR** (EU) | ข้อมูลส่วนบุคคลของ residents ใน EU | Data Protection by Design, Breach Notification (72 ชม.), DPO, Consent | สูงสุด 20M EUR หรือ 4% ของรายได้ทั่วโลก |
| **PDPA** (ไทย) | ข้อมูลส่วนบุคคลของ residents ในไทย | Consent, Data Subject Rights, Breach Notification (72 ชม.), DPO | สูงสุด 5M THB + โทษอาญา |
| **HIPAA** (US) | Healthcare PHI | Administrative/Physical/Technical Safeguards, BAA | สูงสุด 1.9M USD/ปี ต่อ Violation |
| **PCI DSS v4.0** | ข้อมูลบัตรเครดิต | 12 Requirements, 78 Sub-Requirements, Network Segmentation, Encryption | ค่าปรับ, ค่าธรรมเนียมที่เพิ่มขึ้น, การเพิกถอนสิทธิ์ |
| **NIS2** (EU) | Critical Infrastructure | Incident Reporting, Supply Chain Security, Risk Management | สูงสุด 10M EUR หรือ 2% ของรายได้ทั่วโลก |

---

## 10. แนวคิด Defense in Depth

### 10.1 หลักการพื้นฐาน

Defense in Depth (การป้องกันเชิงลึก) เป็นแนวคิดที่ได้รับการพัฒนาขึ้นโดย **National Security Agency (NSA)** ของสหรัฐอเมริกา โดยมีหลักการสำคัญคือ **ไม่มีมาตรการป้องกันเพียงชั้นเดียวที่เพียงพอ** — ต้องมีการป้องกันหลายชั้นซ้อนทับกันเพื่อให้แน่ใจว่าหากชั้นใดชั้นหนึ่งล้มเหลว ก็ยังมีชั้นอื่นที่สามารถป้องกันหรือลดผลกระทบได้

"**The Onion Model**" — ข้อมูลอยู่ที่แกนกลาง ถูกล้อมรอบด้วยชั้นป้องกันซ้อนกันหลายชั้น

### 10.2 People, Process, Technology Framework

| ชั้น | คำอธิบาย | ตัวอย่าง |
|------|----------|---------|
| **People** (คน) | ปัจจัยมนุษย์, วัฒนธรรม, ทักษะ | Awareness Training, Background Checks, Security Culture |
| **Process** (กระบวนการ) | นโยบาย, ขั้นตอน, Governance | Incident Response Plan, Change Management, Risk Assessment |
| **Technology** (เทคโนโลยี) | เครื่องมือ, มาตรการควบคุม, สถาปัตยกรรม | Firewalls, EDR, SIEM, IAM, Encryption |

### 10.3 การแบ่งประเภทของมาตรการควบคุม

| ประเภท | คำอธิบาย | ตัวอย่าง |
|--------|----------|---------|
| **Administrative Controls** (เชิงบริหาร) | นโยบายและกระบวนการ | Security Policies, Risk Assessments, Training, Background Checks, Vendor Due Diligence |
| **Technical Controls** (เชิงเทคนิค) | เครื่องมือและเทคโนโลยี | **Preventive**: Firewalls, IAM, Encryption — **Detective**: IDS/IPS, SIEM, EDR, FIM — **Corrective**: Automated Containment, Backup Restoration, Patching |
| **Physical Controls** (เชิงกายภาพ) | การป้องกันทางกายภาพ | รั้ว, CCTV, Biometric Access Control, Server Room Locks, Environmental Controls (Fire Suppression, HVAC) |

### 10.4 ตัวอย่าง: Defense in Depth สำหรับ Web Application

| Layer | มาตรการควบคุม | ตัวอย่าง |
|-------|--------------|---------|
| **1 — Perimeter** | Firewall, WAF, DDoS Protection | Cloudflare, AWS WAF, ModSecurity |
| **2 — Network** | IDS/IPS, Network Segmentation | Snort, Suricata; VLANs, Microsegmentation |
| **3 — Endpoint** | EDR, Anti-Malware, HIPS | CrowdStrike, Defender for Endpoint |
| **4 — Application** | Secure Coding, SAST/DAST | OWASP Top 10, SonarQube, Burp Suite |
| **5 — Data** | Encryption At Rest/In Transit, DLP | AES-256, TLS 1.3, Microsoft Purview DLP |
| **6 — Identity** | MFA, IAM, Least Privilege | Okta, Azure AD, FIDO2 Keys |
| **7 — Monitoring** | SIEM, SOAR, 24/7 SOC | Splunk, Sentinel, Chronicle |
| **8 — Response** | Incident Response Plan, Playbooks | NIST SP 800-61, MITRE D3FEND |
| **9 — Recovery** | Backups, DR, BCP | 3-2-1 Backup Rule, Immutable Backups, Air-Gapped |

### 10.5 ความสัมพันธ์กับ Zero Trust Architecture

| มิติ | Defense in Depth | Zero Trust Architecture |
|------|------------------|------------------------|
| **Focus** | WHAT — Layered Controls | HOW — "Never Trust, Always Verify" |
| **Assumption** | Assume Breach | Assume Breach |
| **Verification** | ตรวจสอบที่ Perimeter เป็นหลัก | ตรวจสอบ **ทุก Request** อย่างต่อเนื่อง |
| **Segmentation** | VLANs เป็นหลัก | **Microsegmentation** — Per-Workload Isolation |
| **Access** | Static Permissions | Just-In-Time, Just-Enough Access |
| **Data-Centric** | ป้องกันที่ Network | ป้องกันที่ **Data** ไม่ใช่ Location |

**ความเหมือน:**
- ทั้งสองแนวคิดตั้งอยู่บนสมมติฐาน "Assume Breach"
- ต้องมี Verification Points หลายจุด
- ปฏิเสธ Implicit Trust

**NIST SP 800-207** กำหนด ZTA 7 Tenets:
1. All data sources and computing services are resources
2. All communication is secured regardless of network location
3. Access to resources is granted on a per-session basis
4. Access to resources is determined by dynamic policy
5. The enterprise monitors and measures the security posture of all owned assets
6. All resource authentication and authorization is dynamic and strictly enforced before access is allowed
7. The enterprise collects as much information as possible about the current state of assets, network infrastructure, and communications and uses it to improve its security posture

**CISA Zero Trust Maturity Model (v2.0, 2023):** วัด Maturity 5 Pillars — Identity, Devices, Networks, Applications/Workloads, Data — จาก Traditional → Advanced → Optimal

---

## 11. สรุปท้ายบท (Chapter Summary)

### 11.1 หลักการสำคัญ

| หัวข้อ | สรุป |
|-------|------|
| **Network Security** | การปกป้องเครือข่ายและข้อมูลจากการถูกเข้าถึงหรือโจมตีโดยไม่ได้รับอนุญาต — มีความสำคัญมากขึ้นในยุคที่ทุกองค์กรพึ่งพาระบบดิจิทัล |
| **CIA Triad** | Confidentiality (การรักษาความลับ), Integrity (การรักษาความถูกต้อง), Availability (การทำให้พร้อมใช้งาน) — หลักการพื้นฐานที่ถูกอ้างอิงในมาตรฐานทุกรูปแบบ; มี Parkerian Hexad เป็นส่วนขยาย |
| **AAA** | Authentication (พิสูจน์ตัวตน), Authorization (กำหนดสิทธิ์), Accounting (บันทึกการใช้งาน) — RADIUS, TACACS+, และ Diameter เป็นโพรโทคอลหลัก |
| **NIST CSF 2.0** | (กุมภาพันธ์ 2024) 6 ฟังก์ชัน: Govern, Identify, Protect, Detect, Respond, Recover — ขยายจาก Critical Infrastructure สู่ทุกองค์กร |
| **ISO/IEC 27001:2022** | 93 Controls แบ่งเป็น 4 หมวด (Organizational, People, Physical, Technological) — 11 Controls ใหม่ |
| **กรณีศึกษา Colonial Pipeline** | MFA, Credential Review, IT/OT Segmentation — การโจมตีผ่าน Legacy VPN ที่ไม่มี MFA |
| **กรณีศึกษา SolarWinds** | Supply Chain Security, SBOM, Zero Trust — การโจมตีผ่าน Build Pipeline ที่ซับซ้อนที่สุดในประวัติศาสตร์ |
| **กรณีศึกษา Dyn DDoS** | IoT Security, DDoS Mitigation, DNS Redundancy — IoT Botnet 100,000+ เครื่องโจมตี DNS |
| **Defense in Depth** | 9 Layers of Protection — ไม่มีมาตรการป้องกันชั้นเดียวที่เพียงพอ |
| **Security Governance** | Risk Management Frameworks (ISO 31000, COSO ERM, FAIR), Policy Hierarchy, Roles & Responsibilities |

### 11.2 ตัวเลขสำคัญที่ควรจำ

| ตัวเลข | ความหมาย |
|--------|----------|
| **4.44 ล้าน USD** | ค่าเสียหายเฉลี่ยต่อ Data Breach (IBM 2025) |
| **241 วัน** | Breach Lifecycle เฉลี่ย (ตรวจจับ + ควบคุม) |
| **44%** | สัดส่วน Ransomware ใน Breaches ทั้งหมด (Verizon DBIR 2025) |
| **76.7%** | สัดส่วน DDoS ใน Incidents ทั้งหมดใน EU (ENISA 2025) |
| **93** | จำนวน Controls ใน ISO 27001:2022 Annex A |
| **6** | จำนวน Functions ใน NIST CSF 2.0 |

---

## คำถามทบทวน (Review Questions)

1. จงอธิบายหลักการ CIA Triad ตามนิยามของ NIST SP 800-12 และยกตัวอย่างการละเมิดในแต่ละด้านจากกรณีจริงที่เกิดขึ้นในประวัติศาสตร์
2. MFA (Multi-Factor Authentication) ช่วยป้องกันการโจมตีแบบใด? จงอธิบายปัจจัยทั้ง 5 ประเภท พร้อมยกตัวอย่าง MFA Fatigue Attack
3. NIST CSF 2.0 มีกี่ฟังก์ชัน? อะไรบ้าง? และแตกต่างจากเวอร์ชัน 1.1 อย่างไร?
4. ISO 27001:2022 Annex A มีกี่ Controls? แบ่งเป็นกี่หมวด? มี Controls ใหม่อะไรบ้าง? จงอธิบายกระบวนการ Risk Assessment ตาม Clause 6.1
5. จงวิเคราะห์และเปรียบเทียบบทเรียนที่ได้จากเหตุการณ์ Colonial Pipeline และ SolarWinds Attack โดยระบุ MITRE ATT&CK Techniques ที่เกี่ยวข้อง
6. RADIUS แตกต่างจาก TACACS+ และ Diameter ในด้านใดบ้าง? โพรโทคอลใดเหมาะสำหรับใช้งานใน 5G Network?
7. หากคุณเป็น CISO ขององค์กร คุณจะเลือกใช้ NIST CSF 2.0 หรือ ISO 27001:2022? เพราะเหตุใด? หรือจะใช้ทั้งสองแบบร่วมกัน?
8. Parkerian Hexad มีองค์ประกอบอะไรเพิ่มเติมจาก CIA Triad? จงอธิบายความแตกต่างระหว่าง Possession และ Confidentiality
9. จงอธิบายแนวคิด Defense in Depth และยกตัวอย่าง 9 Layers of Protection สำหรับ Web Application
10. ข้อมูลจาก IBM Cost of Data Breach Report 2025 และ Verizon DBIR 2025 บ่งชี้อะไรเกี่ยวกับแนวโน้มด้าน Ransomware และ AI ใน Cybersecurity?
11. จงเปรียบเทียบ ISO 31000, COSO ERM, และ FAIR — Framework ใดเหมาะกับการสื่อสารความเสี่ยงทางไซเบอร์กับ Board of Directors?
12. จงอธิบายความสัมพันธ์ระหว่าง Defense in Depth และ Zero Trust Architecture — แตกต่างและเสริมกันอย่างไร?

---

## เอกสารอ้างอิง (References)

### มาตรฐานและกรอบการทำงาน
1. NIST. (2024). *Cybersecurity Framework 2.0*. CSWP 29. National Institute of Standards and Technology.
2. ISO/IEC. (2022). *ISO/IEC 27001:2022 Information Security Management Systems — Requirements*.
3. NIST SP 800-53 Rev. 5. (2020). *Security and Privacy Controls for Information Systems and Organizations*.
4. NIST SP 800-207. (2020). *Zero Trust Architecture*.
5. NIST SP 800-12 Rev. 1. (2017). *An Introduction to Information Security*.
6. NIST SP 800-63-4. (2025). *Digital Identity Guidelines*.
7. ISO 31000:2018. *Risk Management — Guidelines*.
8. FAIR Institute. *Factor Analysis of Information Risk (FAIR) Framework*.
9. CISA. (2023). *Zero Trust Maturity Model v2.0*.

### ตำราหลัก
10. Stallings, W. (2022). *Cryptography and Network Security: Principles and Practice* (8th ed.). Pearson.
11. Whitman, M. E., & Mattord, H. J. (2021). *Principles of Information Security* (7th ed.). Cengage Learning.
12. Kaufman, C., Perlman, R., & Speciner, M. (2022). *Network Security: Private Communication in a Public World* (3rd ed.). Addison-Wesley.

### รายงานและกรณีศึกษา
13. IBM Security & Ponemon Institute. (2025). *Cost of a Data Breach Report 2025*.
14. IBM Security & Ponemon Institute. (2024). *Cost of a Data Breach Report 2024*.
15. Verizon. (2025). *2025 Data Breach Investigations Report*.
16. ENISA. (2025). *ENISA Threat Landscape 2025*.
17. ISC2. (2025). *ISC2 Cybersecurity Workforce Study 2025*.
18. CISA. (2023). *The Attack on Colonial Pipeline: What We've Learned & What We've Done Over the Past Two Years*.
19. CyOTE Program. (2025). *Colonial Pipeline Case Study*. Idaho National Laboratory.
20. Microsoft Threat Intelligence. (2020). *Analyzing Solorigate: The Compromised DLL File*.
21. FireEye. (2020). *Evasive Attacker Leverages SolarWinds Supply Chain Compromises with SUNBURST Backdoor*.
22. Antonakakis, M., et al. (2017). *Understanding the Mirai Botnet*. USENIX Security Symposium.
23. Chainalysis. (2025). *2025 Crypto Ransomware Report*.
24. Sophos. (2025). *State of Ransomware 2025*.

### แหล่งข้อมูลเพิ่มเติม
25. OWASP. (2024). *OWASP Top 10 - 2021*. https://owasp.org/Top10/
26. MITRE ATT&CK. (2024). https://attack.mitre.org/
27. NIST National Vulnerability Database. https://nvd.nist.gov/
28. NIST Cybersecurity Framework (CSF) 2.0 Reference Tool. https://www.nist.gov/cyberframework
29. CISA Known Exploited Vulnerabilities Catalog. https://www.cisa.gov/known-exploited-vulnerabilities-catalog

---

*เอกสารนี้เป็นส่วนหนึ่งของรายวิชา Network Security | ภาคเรียนที่ 1 ปีการศึกษา 2569*
