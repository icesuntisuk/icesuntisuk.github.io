# CH-4: Threat Modeling และการวิเคราะห์ความเสี่ยงด้านความปลอดภัยของซอฟต์แวร์


---

## วัตถุประสงค์การเรียนรู้

เมื่อจบบทนี้นักศึกษาสามารถ:

1. อธิบายความแตกต่างระหว่าง Threat, Vulnerability, Risk, Threat Modeling, Risk Assessment และ Vulnerability Scoring ได้อย่างถูกต้อง
2. กำหนดขอบเขตระบบ สินทรัพย์สำคัญ ผู้มีส่วนเกี่ยวข้อง สมมติฐาน และข้อจำกัดของการทำ Threat Modeling ได้
3. สร้าง Data Flow Diagram (DFD) เพื่อใช้วิเคราะห์ภัยคุกคาม พร้อมระบุ Trust Boundary และจุดที่ข้อมูลข้ามเขตความไว้วางใจ
4. วิเคราะห์ภัยคุกคามด้วย STRIDE Framework และเชื่อมโยงภัยคุกคามแต่ละประเภทกับมาตรการควบคุมด้านความปลอดภัยที่เหมาะสม
5. ประเมินความเสี่ยงโดยใช้ Likelihood, Impact, Risk Matrix, Risk Register และแนวคิด Residual Risk ตามหลักการของ NIST SP 800-30 Rev.1 และ ISO/IEC 27005:2022
6. ใช้ CVSS v4.0 เพื่อสื่อสารระดับความรุนแรงของช่องโหว่ และอธิบายได้ว่าคะแนน CVSS ไม่ใช่คะแนนความเสี่ยงทางธุรกิจทั้งหมด
7. เปรียบเทียบแนวทาง Threat Modeling ที่สำคัญ เช่น STRIDE, PASTA, LINDDUN, Trike และ VAST พร้อมเลือกใช้ให้เหมาะกับบริบท
8. สร้าง Attack Tree และจัดทำแผนลดความเสี่ยงที่มีเจ้าของงาน กำหนดเวลา และวิธีตรวจสอบผลลัพธ์

---

## เนื้อหา

### 4.1 ภาพรวมของ Threat Modeling และ Risk Analysis

Threat Modeling เป็นหนึ่งในกิจกรรมสำคัญของ Secure SDLC ที่เชื่อมโยงบทที่ 3 โดยตรง เพราะเป็นกิจกรรมด้านความปลอดภัยที่ควรเกิดตั้งแต่ขั้นตอน Requirements และ Design ไม่ใช่รอให้ระบบพัฒนาเสร็จแล้วค่อยทดสอบ การทำ Threat Modeling ที่ดีช่วยให้ทีมพัฒนามองเห็นปัญหาเชิงสถาปัตยกรรมตั้งแต่ต้น เช่น การไม่มีการตรวจสิทธิ์ระหว่างบริการ การส่งข้อมูลสำคัญผ่านช่องทางที่ไม่เข้ารหัส หรือการออกแบบระบบที่ทำให้ผู้ใช้ทั่วไปเข้าถึงฟังก์ชันของผู้ดูแลระบบได้

OWASP อธิบาย Threat Modeling ผ่านคำถามหลัก 4 ข้อ ซึ่งเหมาะมากสำหรับใช้ในชั้นเรียนและในทีมพัฒนาจริง:

1. เรากำลังสร้างอะไร (What are we building?)
2. อะไรอาจผิดพลาดได้ (What can go wrong?)
3. เราจะจัดการกับสิ่งที่ผิดพลาดอย่างไร (What are we going to do about it?)
4. เราตรวจสอบได้อย่างไรว่าทำงานถูกต้อง (Did we do a good job?)

คำถามทั้ง 4 ข้อนี้ทำให้ Threat Modeling ไม่ใช่แค่การวาดแผนภาพ แต่เป็นกระบวนการคิดอย่างเป็นระบบ ตั้งแต่การเข้าใจระบบ การค้นหาภัยคุกคาม การตัดสินใจลดความเสี่ยง และการตรวจสอบว่ามาตรการที่เลือกใช้ได้ผลจริง

#### 4.1.1 ทำไม Threat Modeling จึงสำคัญต่อ Software Security

ซอฟต์แวร์จำนวนมากไม่ได้ล้มเหลวเพราะเขียนโค้ดผิดเพียงอย่างเดียว แต่ล้มเหลวเพราะออกแบบผิดตั้งแต่แรก ตัวอย่างเช่น:

- ระบบ API ออกแบบให้ Client ส่ง `user_id` มาเองโดยไม่ตรวจสอบว่าผู้ใช้เป็นเจ้าของข้อมูลนั้นจริงหรือไม่
- ระบบ Microservices เชื่อใจกันเองภายในเครือข่าย โดยไม่มี Service-to-Service Authentication
- ระบบอัปโหลดไฟล์ไม่มีการจำกัดชนิดไฟล์ ขนาดไฟล์ หรือพื้นที่จัดเก็บ ทำให้เกิดทั้ง Malware Upload และ Denial of Service
- ระบบ Payment Callback เชื่อข้อมูลจาก Third-party โดยไม่ตรวจ Digital Signature ทำให้ผู้โจมตีปลอมสถานะชำระเงินสำเร็จได้

ปัญหาเหล่านี้มักไม่ถูกพบด้วย Unit Test ทั่วไป เพราะ Unit Test ตรวจว่าโค้ดทำงานตามที่เขียนไว้ แต่ไม่ได้ถามว่า “สิ่งที่ออกแบบไว้นั้นปลอดภัยหรือไม่” Threat Modeling จึงเป็นวิธีคิดที่เติมช่องว่างระหว่างการออกแบบระบบกับการทดสอบความปลอดภัย

#### 4.1.2 ผลลัพธ์ที่ควรได้จาก Threat Modeling

Threat Modeling ที่สมบูรณ์ควรมีผลลัพธ์อย่างน้อยดังนี้:

| ผลลัพธ์ | คำอธิบาย | ใช้ทำอะไรต่อ |
|---------|----------|--------------|
| System Scope | ขอบเขตระบบที่วิเคราะห์ | ป้องกันการวิเคราะห์กว้างเกินไปหรือแคบเกินไป |
| Asset List | รายการสินทรัพย์สำคัญ | ใช้จัดลำดับความสำคัญของการป้องกัน |
| DFD | แผนภาพการไหลของข้อมูล | ใช้ค้นหาจุดโจมตีและ Trust Boundary |
| Threat List | รายการภัยคุกคาม | ใช้สร้าง Risk Register และ Security Requirements |
| Control Recommendations | มาตรการควบคุมที่เสนอ | ส่งต่อให้ทีมพัฒนาออกแบบและแก้ไข |
| Risk Register | ทะเบียนความเสี่ยง | ใช้ติดตามเจ้าของงาน สถานะ และ Residual Risk |
| Verification Plan | แผนตรวจสอบ | ใช้กำหนด Test Case, Security Review, SAST/DAST/Pen Test |

**ข้อควรจำ:** Threat Model ที่ดีต้องนำไปปฏิบัติได้ ไม่ใช่เอกสารที่ทำเพื่อให้ครบขั้นตอนเท่านั้น ถ้า Threat Model ไม่ทำให้เกิด Security Requirements, Design Changes, Test Cases หรือ Risk Decisions แสดงว่ายังไม่เกิดคุณค่าจริง

---

### 4.2 แยกคำสำคัญ: Threat, Vulnerability, Risk, Severity

ก่อนเริ่มวิเคราะห์ นักศึกษาต้องแยกคำสำคัญให้ชัด เพราะความสับสนเรื่องคำศัพท์ทำให้การจัดลำดับความสำคัญผิดพลาดได้

| คำศัพท์ | ความหมาย | ตัวอย่างในระบบ E-Commerce |
|---------|----------|-----------------------------|
| Asset | สิ่งที่มีคุณค่าต่อองค์กร | ข้อมูลลูกค้า, คำสั่งซื้อ, Token ชำระเงิน |
| Threat | เหตุการณ์หรือผู้กระทำที่อาจสร้างความเสียหาย | ผู้โจมตีพยายามขโมยข้อมูลลูกค้า |
| Vulnerability | จุดอ่อนที่อาจถูกใช้โจมตี | API ไม่มี Authorization Check |
| Impact | ผลกระทบเมื่อเหตุการณ์เกิดขึ้น | ข้อมูลลูกค้ารั่วไหล, ค่าปรับ, เสียชื่อเสียง |
| Likelihood | โอกาสที่เหตุการณ์จะเกิดขึ้น | สูง ถ้า API เปิดบนอินเทอร์เน็ตและเดา ID ได้ |
| Risk | การรวม Threat, Vulnerability, Likelihood และ Impact | ความเสี่ยงที่ผู้ใช้คนหนึ่งอ่านคำสั่งซื้อของผู้อื่นได้ |
| Severity | ความรุนแรงเชิงเทคนิคของช่องโหว่ | CVSS 8.1 High |

#### 4.2.1 ตัวอย่างการแยกคำศัพท์

สถานการณ์: ระบบจองตั๋วภาพยนตร์มี endpoint `/api/bookings/{booking_id}` และใช้หมายเลขการจองแบบเรียงลำดับ เช่น 1001, 1002, 1003

- **Asset:** ข้อมูลการจองและข้อมูลผู้ใช้
- **Threat:** ผู้ใช้ทั่วไปพยายามเดาหมายเลขการจองของผู้อื่น
- **Vulnerability:** ไม่มี Object-level Authorization Check
- **Impact:** ข้อมูลส่วนบุคคลและประวัติการจองรั่วไหล
- **Likelihood:** สูง เพราะเดา ID ได้ง่ายและ endpoint เปิดให้ผู้ใช้ทั่วไปเรียก
- **Risk:** ผู้ใช้หนึ่งสามารถอ่านข้อมูลการจองของผู้ใช้อื่นได้
- **Control:** ตรวจว่า `booking_id` เป็นของผู้ใช้ที่เข้าสู่ระบบจริง, ใช้ UUID ที่เดายาก, เพิ่ม Audit Log

#### 4.2.2 ความแตกต่างระหว่าง Threat Modeling, Risk Assessment และ Vulnerability Scoring

| กิจกรรม | คำถามหลัก | ผลลัพธ์ | ตัวอย่างเครื่องมือ/กรอบ |
|---------|-----------|--------|---------------------------|
| Threat Modeling | อะไรอาจผิดพลาดได้ | รายการภัยคุกคามและมาตรการควบคุม | STRIDE, PASTA, Attack Tree |
| Risk Assessment | ความเสี่ยงสำคัญแค่ไหน | Risk Register, Risk Rating, Risk Treatment | NIST SP 800-30, ISO/IEC 27005 |
| Vulnerability Scoring | ช่องโหว่รุนแรงแค่ไหน | Severity Score | CVSS v4.0 |

**ข้อควรจำ:** CVSS เป็นคะแนนความรุนแรงของช่องโหว่ ไม่ใช่คะแนนความเสี่ยงทางธุรกิจทั้งหมด ช่องโหว่ CVSS สูงในระบบภายในที่แยกเครือข่ายดีมาก อาจมีความเสี่ยงทางธุรกิจต่ำกว่าช่องโหว่ CVSS กลางในระบบที่เปิดสู่อินเทอร์เน็ตและเก็บข้อมูลส่วนบุคคลจำนวนมาก

---

### 4.3 ขั้นตอนการทำ Threat Modeling แบบใช้งานจริง

บทนี้ใช้กระบวนการ 7 ขั้นที่เหมาะกับทีมพัฒนาซอฟต์แวร์และงานในห้องเรียน:

1. กำหนด Scope และ Business Context
2. ระบุ Asset และ Security Objective
3. สร้าง Data Flow Diagram
4. ระบุ Trust Boundary และ Attack Surface
5. วิเคราะห์ภัยคุกคามด้วย STRIDE
6. ประเมินและจัดลำดับความเสี่ยง
7. กำหนด Control, Owner, Verification และติดตาม Residual Risk

#### 4.3.1 กำหนด Scope และ Business Context

Scope คือขอบเขตว่าการวิเคราะห์นี้ครอบคลุมอะไรและไม่ครอบคลุมอะไร การกำหนด Scope ที่ดีช่วยให้ Threat Modeling ไม่หลุดประเด็น

ตัวอย่าง Scope สำหรับระบบ E-Commerce:

- ครอบคลุม: สมัครสมาชิก, เข้าสู่ระบบ, ตะกร้าสินค้า, ชำระเงิน, ประวัติคำสั่งซื้อ
- ไม่ครอบคลุม: ระบบคลังสินค้าภายใน, ระบบบัญชีหลังบ้าน, ระบบ CRM
- ผู้ใช้หลัก: ลูกค้า, ผู้ดูแลร้าน, Payment Gateway, Email Service
- ข้อมูลสำคัญ: ข้อมูลส่วนบุคคล, ที่อยู่จัดส่ง, Order History, Payment Token
- ข้อจำกัด: ระบบไม่เก็บเลขบัตรเครดิตเต็ม ใช้ Token จาก Payment Gateway เท่านั้น

#### 4.3.2 ระบุ Asset และ Security Objective

Asset ไม่ได้มีแค่ Database แต่รวมถึงข้อมูล กระบวนการ บริการ และความน่าเชื่อถือของระบบ

| Asset | Security Objective | ตัวอย่างภัยคุกคาม |
|-------|--------------------|-------------------|
| ข้อมูลบัญชีผู้ใช้ | Confidentiality, Integrity | Account Takeover, Data Leakage |
| Order Record | Integrity, Accountability | แก้ไขยอดคำสั่งซื้อ, ปฏิเสธว่าไม่ได้สั่งซื้อ |
| Payment Token | Confidentiality | Token Leakage, Replay Attack |
| Admin Function | Authorization, Accountability | Privilege Escalation |
| Service Availability | Availability | DDoS, Resource Exhaustion |
| Audit Log | Integrity, Non-repudiation | ลบหรือแก้ Log เพื่อปิดบังการกระทำ |

#### 4.3.3 ระบุ Assumption และ Constraint

Assumption คือสิ่งที่ทีมเชื่อว่าเป็นจริง แต่ต้องบันทึกไว้เพื่อทบทวน เช่น:

- Payment Gateway ตรวจสอบบัตรเครดิตแทนระบบเรา
- ข้อมูลระหว่าง Frontend กับ Backend ใช้ HTTPS เสมอ
- Admin ต้องใช้ MFA
- Database ไม่เปิดให้เข้าจากอินเทอร์เน็ตโดยตรง

Constraint คือข้อจำกัดที่มีผลต่อการเลือก Control เช่น:

- ทีมมีเวลาพัฒนา 2 Sprint
- ระบบต้องรองรับผู้ใช้ 10,000 คนพร้อมกัน
- ต้องปฏิบัติตาม PDPA
- ต้องรองรับ Mobile App รุ่นเก่าอีก 6 เดือน

Assumption ที่ไม่ถูกตรวจสอบอาจกลายเป็นช่องโหว่ร้ายแรง ตัวอย่างเช่น ทีมเชื่อว่า API ถูกเรียกผ่าน Frontend เท่านั้น จึงไม่ตรวจ Authorization ที่ Backend แต่ผู้โจมตีสามารถเรียก API โดยตรงได้

---

### 4.4 Data Flow Diagram และ Trust Boundary

DFD เป็นหัวใจของ Threat Modeling เพราะช่วยให้ทีมเห็นภาพเดียวกันว่าใครส่งข้อมูลอะไร ไปที่ไหน ผ่านกระบวนการใด และข้อมูลถูกเก็บตรงไหน

#### 4.4.1 องค์ประกอบของ DFD

| องค์ประกอบ | คำอธิบาย | ตัวอย่าง |
|-------------|----------|----------|
| External Entity | ผู้ใช้หรือระบบภายนอกที่ติดต่อระบบ | Customer, Admin, Payment Gateway |
| Process | ส่วนที่ประมวลผลข้อมูล | Auth Service, Order Service, Payment Service |
| Data Store | ที่เก็บข้อมูล | User DB, Order DB, Object Storage |
| Data Flow | เส้นทางการส่งข้อมูล | Login Request, Payment Callback, Order Query |
| Trust Boundary | เส้นแบ่งระดับความเชื่อถือ | Internet ↔ Backend, App ↔ Database, Company ↔ Third-party |

#### 4.4.2 ตัวอย่าง DFD เชิงข้อความ: ระบบ E-Commerce

```
[Customer Browser]
    -> Login Request -> [Web Frontend]
    -> API Request -> [Backend API]
    -> Query User -> [User Database]
    -> Create Order -> [Order Service]
    -> Payment Request -> [Payment Gateway]
    <- Payment Callback <- [Payment Gateway]
    -> Send Email -> [Email Service]
```

Trust Boundary ที่ควรระบุ:

1. Customer Browser ↔ Web Frontend: ข้ามจากอุปกรณ์ผู้ใช้เข้าสู่ระบบองค์กร
2. Web Frontend ↔ Backend API: ข้ามจาก Presentation Layer ไป Application Layer
3. Backend API ↔ Database: ข้ามจาก Application Layer ไป Data Layer
4. Backend API ↔ Payment Gateway: ข้ามจากองค์กรไป Third-party
5. Backend API ↔ Email Service: ข้ามจากองค์กรไป Third-party

#### 4.4.3 วิธีอ่าน DFD เพื่อหาภัยคุกคาม

ให้ถามคำถามซ้ำในทุกจุดที่ข้อมูลไหล:

- ผู้ส่งเป็นใคร และระบบพิสูจน์ตัวตนอย่างไร
- ผู้ส่งมีสิทธิ์ทำ action นี้หรือไม่
- ข้อมูลถูกแก้ไขระหว่างทางได้หรือไม่
- ข้อมูลสำคัญถูกเปิดเผยระหว่างทางหรือใน log หรือไม่
- ปลายทางตรวจสอบ input หรือ trust ข้อมูลทันที
- ถ้า request จำนวนมากเข้ามาพร้อมกัน ระบบล่มหรือไม่
- มีหลักฐานตรวจสอบย้อนหลังหรือไม่ว่าใครทำอะไรเมื่อไหร่

#### 4.4.4 ข้อผิดพลาดที่พบบ่อยในการวาด DFD

| ข้อผิดพลาด | ผลกระทบ | วิธีแก้ |
|------------|---------|--------|
| วาดเฉพาะ UI ไม่วาด Backend | มองไม่เห็นภัยคุกคามที่ API และ Database | วาด Process และ Data Store ให้ครบ |
| ไม่ใส่ Third-party | มองข้าม Supply Chain และ Callback Risk | ใส่ Payment, Email, Analytics, CDN |
| ไม่ระบุ Trust Boundary | ไม่รู้ว่าจุดไหนต้องตรวจสิทธิ์หรือเข้ารหัส | วาดเส้นแบ่งระหว่างระดับความไว้วางใจ |
| ไม่ระบุทิศทางข้อมูล | วิเคราะห์ Tampering และ Disclosure ยาก | ใส่ลูกศรและชื่อข้อมูลทุกเส้น |
| วาดละเอียดเกินไปตั้งแต่แรก | ใช้เวลามากและหลุดจากเป้าหมาย | เริ่มจาก Context Diagram แล้วค่อยแตก Level 1 |

---

### 4.5 STRIDE Framework

STRIDE เป็นวิธีวิเคราะห์ภัยคุกคามที่นิยมมาก เพราะเข้าใจง่ายและผูกกับคุณสมบัติด้านความปลอดภัยพื้นฐาน

| ตัวอักษร | ภัยคุกคาม | กระทบต่อ | คำถามสำคัญ |
|----------|-----------|----------|-------------|
| S | Spoofing | Authentication | ใครสามารถปลอมตัวเป็นผู้ใช้หรือบริการอื่นได้หรือไม่ |
| T | Tampering | Integrity | ข้อมูลหรือคำสั่งถูกแก้ไขโดยไม่ได้รับอนุญาตได้หรือไม่ |
| R | Repudiation | Non-repudiation, Accountability | ผู้ใช้ปฏิเสธการกระทำได้หรือไม่ เพราะไม่มีหลักฐาน |
| I | Information Disclosure | Confidentiality | ข้อมูลสำคัญรั่วไหลสู่ผู้ไม่มีสิทธิ์ได้หรือไม่ |
| D | Denial of Service | Availability | ผู้โจมตีทำให้ระบบใช้งานไม่ได้ได้หรือไม่ |
| E | Elevation of Privilege | Authorization | ผู้ใช้ได้สิทธิ์สูงกว่าที่ควรได้หรือไม่ |

#### 4.5.1 Spoofing: การปลอมตัวตน

Spoofing เกิดเมื่อผู้โจมตีสามารถสวมรอยเป็นผู้ใช้ ระบบ หรือบริการอื่นได้

ตัวอย่าง:

- ขโมย Session Token แล้วใช้แทนผู้ใช้จริง
- ปลอม API Key ของ Third-party
- ใช้ Email Phishing เพื่อหลอกให้ผู้ใช้เข้าสู่ระบบปลอม
- Service หนึ่งเรียกอีก Service โดยไม่มี mTLS หรือ Token Validation

มาตรการควบคุม:

- MFA สำหรับบัญชีสำคัญ
- Session Token ที่สุ่มเพียงพอ หมดอายุเหมาะสม และถูกป้องกันด้วย Secure Cookie
- Mutual TLS หรือ Signed JWT สำหรับ Service-to-Service
- Certificate Pinning ในบางบริบทที่มีความเสี่ยงสูง
- Credential Rotation และ Secret Management

#### 4.5.2 Tampering: การแก้ไขข้อมูลโดยมิชอบ

Tampering เกิดเมื่อข้อมูล คำสั่ง หรือ configuration ถูกแก้ไขโดยไม่ได้รับอนุญาต

ตัวอย่าง:

- ผู้ใช้แก้ราคาใน request ก่อนส่งไป Backend
- ผู้โจมตีแก้ Payment Callback ให้สถานะเป็นชำระเงินสำเร็จ
- แก้ไฟล์ JavaScript ที่โหลดจาก Third-party CDN
- แก้ Log เพื่อปิดบังร่องรอย

มาตรการควบคุม:

- Server-side Validation
- Digital Signature หรือ HMAC สำหรับ Callback
- Subresource Integrity สำหรับไฟล์จาก CDN
- Immutable Log หรือ Append-only Log
- Database Constraint และ Transaction Integrity

#### 4.5.3 Repudiation: การปฏิเสธความรับผิดชอบ

Repudiation เกิดเมื่อระบบไม่มีหลักฐานเพียงพอที่จะพิสูจน์ว่าใครทำอะไร เมื่อไหร่ จากที่ใด

ตัวอย่าง:

- ผู้ใช้ปฏิเสธว่าไม่ได้ยกเลิกคำสั่งซื้อ
- Admin ปฏิเสธว่าไม่ได้เปลี่ยนสิทธิ์ผู้ใช้
- ระบบไม่มี Audit Log หรือ Log ถูกแก้ไขได้

มาตรการควบคุม:

- Audit Log ที่มี User ID, Timestamp, Source IP, Action, Resource ID
- Log Integrity Protection
- Time Synchronization ด้วย NTP
- Digital Signature สำหรับธุรกรรมสำคัญ
- Separation of Duties สำหรับ action ที่มีผลกระทบสูง

#### 4.5.4 Information Disclosure: การเปิดเผยข้อมูล

Information Disclosure เกิดเมื่อข้อมูลที่ควรถูกจำกัดถูกเปิดเผยต่อผู้ไม่มีสิทธิ์

ตัวอย่าง:

- API ส่งข้อมูลเกินจำเป็น เช่น ส่ง `password_hash` กลับไปที่ Frontend
- Error Message แสดง SQL Query หรือ Stack Trace
- Log บันทึก Access Token หรือเลขบัตรประชาชนเต็ม
- Object Storage ตั้งค่า Public โดยไม่ได้ตั้งใจ

มาตรการควบคุม:

- Data Minimization
- Field-level Access Control
- Encryption at Rest และ Encryption in Transit
- Secret Redaction ใน Log
- Secure Error Handling
- Object Storage Policy Review

#### 4.5.5 Denial of Service: การปฏิเสธการให้บริการ

Denial of Service เกิดเมื่อผู้โจมตีทำให้ระบบช้า ล่ม หรือไม่สามารถให้บริการผู้ใช้จริงได้

ตัวอย่าง:

- ส่ง request จำนวนมากไปยัง endpoint ที่ใช้ CPU สูง
- อัปโหลดไฟล์ขนาดใหญ่มากจนพื้นที่เต็ม
- สร้าง Order จำนวนมากโดยไม่จ่ายเงินจนระบบ Inventory ทำงานผิดปกติ
- ใช้ query ที่ทำให้ Database Full Table Scan

มาตรการควบคุม:

- Rate Limiting และ Quota
- Request Size Limit
- Timeout และ Circuit Breaker
- Queue-based Processing
- Caching และ Backpressure
- DDoS Protection และ Autoscaling

#### 4.5.6 Elevation of Privilege: การยกระดับสิทธิ์

Elevation of Privilege เกิดเมื่อผู้ใช้หรือกระบวนการได้สิทธิ์มากกว่าที่ควรได้รับ

ตัวอย่าง:

- ผู้ใช้ทั่วไปเรียก Admin API ได้
- JWT มี claim `role=admin` แล้ว Backend เชื่อโดยไม่ตรวจลายเซ็น
- Container รันด้วย root และ escape ไปยัง host
- Service Account มีสิทธิ์อ่านทุก bucket ทั้งที่ต้องอ่านเพียง bucket เดียว

มาตรการควบคุม:

- Least Privilege
- Role-Based Access Control หรือ Attribute-Based Access Control
- Authorization Check ที่ Backend ทุกครั้ง
- Token Signature Validation
- Privilege Review เป็นรอบ
- Container Hardening และไม่รันด้วย root

---

### 4.6 STRIDE ตามองค์ประกอบของ DFD

Microsoft Threat Modeling Tool ใช้แนวคิดการจับคู่ STRIDE กับองค์ประกอบของ DFD เพื่อช่วยให้ทีมไม่ลืมภัยคุกคามสำคัญ

| องค์ประกอบ DFD | STRIDE ที่ควรพิจารณา | ตัวอย่างคำถาม |
|----------------|----------------------|----------------|
| External Entity | Spoofing, Repudiation | ผู้ใช้ปลอมตัวได้หรือไม่, มีหลักฐานยืนยัน action หรือไม่ |
| Process | Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege | Process ตรวจ input และสิทธิ์ครบหรือไม่ |
| Data Store | Tampering, Information Disclosure, Denial of Service | ข้อมูลถูกแก้ อ่าน หรือลบโดยไม่มีสิทธิ์ได้หรือไม่ |
| Data Flow | Tampering, Information Disclosure, Denial of Service | ข้อมูลถูกดักอ่าน แก้ไข หรือ flood ระหว่างทางได้หรือไม่ |
| Trust Boundary | ใช้เป็นจุดบังคับตรวจ | มี Authentication, Authorization, Validation และ Encryption หรือไม่ |

#### 4.6.1 ตัวอย่าง STRIDE สำหรับระบบจองตั๋วภาพยนตร์

| จุดใน DFD | STRIDE | ภัยคุกคาม | Control ที่แนะนำ |
|-----------|--------|-----------|------------------|
| Login API | Spoofing | Credential Stuffing | MFA, Rate Limit, Password Breach Check |
| Booking API | Tampering | ผู้ใช้แก้ราคาตั๋วใน request | คำนวณราคาที่ Server เท่านั้น |
| Cancel Booking | Repudiation | ผู้ใช้ปฏิเสธว่าไม่ได้ยกเลิก | Audit Log และ Confirmation Step |
| Booking History API | Information Disclosure | ดู booking ของผู้อื่นผ่าน IDOR | Object-level Authorization |
| Seat Selection | Denial of Service | Lock ที่นั่งจำนวนมากโดยไม่จ่ายเงิน | Seat Hold Timeout และ Quota |
| Admin Panel | Elevation of Privilege | ผู้ใช้ทั่วไปเข้าถึงหน้า Admin | RBAC, Backend Authorization, MFA |

#### 4.6.2 Threat Statement ที่ดีควรเขียนอย่างไร

รูปแบบที่แนะนำ:

```
ผู้โจมตี [ประเภทผู้โจมตี] อาจ [การกระทำ] ผ่าน [ช่องทาง/จุดในระบบ] เนื่องจาก [ช่องโหว่/สมมติฐานที่ผิด] ส่งผลให้ [ผลกระทบต่อ Asset]
```

ตัวอย่าง:

```
ผู้ใช้ทั่วไปอาจอ่านข้อมูลการจองของผู้ใช้อื่นผ่าน Booking History API เนื่องจากระบบตรวจเพียงว่าผู้ใช้เข้าสู่ระบบแล้ว แต่ไม่ตรวจว่า booking_id เป็นของผู้ใช้นั้นจริง ส่งผลให้ข้อมูลส่วนบุคคลและประวัติการจองรั่วไหล
```

Threat Statement ที่ดีต้องระบุผู้โจมตี ช่องทาง สาเหตุ และผลกระทบ ไม่ควรเขียนสั้นเกินไป เช่น “API ไม่ปลอดภัย” เพราะนำไปแก้ไขต่อไม่ได้

---

### 4.7 Attack Surface และ Attack Tree

Attack Surface คือพื้นที่หรือช่องทางทั้งหมดที่ผู้โจมตีสามารถใช้โต้ตอบกับระบบได้ ยิ่ง Attack Surface มาก ความเป็นไปได้ของช่องโหว่ก็ยิ่งสูงขึ้น

#### 4.7.1 ตัวอย่าง Attack Surface ของ Web Application

| Attack Surface | ตัวอย่าง | ภัยคุกคามที่เกี่ยวข้อง |
|----------------|----------|--------------------------|
| Public API | `/login`, `/orders`, `/payments` | Injection, Broken Access Control, DoS |
| File Upload | รูปสินค้า, เอกสารยืนยันตัวตน | Malware Upload, Storage Exhaustion |
| Admin Portal | Dashboard, User Management | Privilege Escalation, Account Takeover |
| Third-party Callback | Payment, Webhook | Spoofing, Tampering, Replay Attack |
| Mobile App API | Token-based API | Token Theft, API Abuse |
| CI/CD Pipeline | Build Script, Secrets | Supply Chain Attack |
| Logging/Monitoring | Log Collector, Dashboard | Information Disclosure, Tampering |

#### 4.7.2 Attack Tree

Attack Tree เป็นการแตกเป้าหมายการโจมตีออกเป็นวิธีการย่อยแบบลำดับชั้น โดย Root Node คือเป้าหมายหลัก และ Child Nodes คือวิธีการที่ทำให้บรรลุเป้าหมายนั้น

ตัวอย่าง Attack Tree: “ขโมยข้อมูลลูกค้า”

```
เป้าหมาย: ขโมยข้อมูลลูกค้า
OR
  1. เข้าถึงฐานข้อมูลโดยตรง
     AND
       - ได้ credential ของ database
       - เข้าถึง network ภายในได้
  2. ใช้ช่องโหว่ API เพื่ออ่านข้อมูล
     OR
       - IDOR ใน endpoint /customers/{id}
       - SQL Injection ใน search API
  3. ขโมยบัญชี Admin
     AND
       - หลอก phishing รหัสผ่าน
       - ไม่มี MFA
  4. ขโมย backup file
     AND
       - Object Storage ตั้งค่า public
       - Backup ไม่เข้ารหัส
```

ประโยชน์ของ Attack Tree:

- ช่วยให้เห็นเส้นทางโจมตีหลายทางพร้อมกัน
- ใช้หาจุดควบคุมที่ลดความเสี่ยงได้หลายเส้นทาง
- ช่วยสื่อสารกับผู้บริหาร เพราะแสดงภาพว่าเป้าหมายหนึ่งอาจเกิดจากหลายสาเหตุ

---

### 4.8 Risk Assessment ตาม NIST SP 800-30 Rev.1

NIST SP 800-30 Rev.1 ชื่อ *Guide for Conducting Risk Assessments* เผยแพร่เดือนกันยายน 2012 เป็นเอกสารสำคัญสำหรับการประเมินความเสี่ยงด้านความมั่นคงปลอดภัยสารสนเทศ โดยมองความเสี่ยงผ่านองค์ประกอบ เช่น Threat Source, Threat Event, Vulnerability, Predisposing Condition, Likelihood, Impact และ Risk

#### 4.8.1 องค์ประกอบหลักของ Risk Assessment

| องค์ประกอบ | ความหมาย | ตัวอย่าง |
|-------------|----------|----------|
| Threat Source | แหล่งที่มาของภัยคุกคาม | External Attacker, Insider, Malware, Natural Event |
| Threat Event | เหตุการณ์ที่อาจเกิด | ผู้โจมตีใช้ Credential ที่รั่วไหลเข้าสู่ระบบ |
| Vulnerability | จุดอ่อน | ไม่มี MFA, Password Reuse |
| Predisposing Condition | เงื่อนไขที่ทำให้เสี่ยงขึ้น | ระบบเปิดบนอินเทอร์เน็ต, ไม่มี Rate Limit |
| Likelihood | โอกาสเกิด | สูง ถ้ามี credential stuffing บ่อยและไม่มี MFA |
| Impact | ผลกระทบ | ข้อมูลลูกค้ารั่วไหล, ระบบหยุดทำงาน |
| Risk | ระดับความเสี่ยง | High หรือ Critical |

#### 4.8.2 Likelihood และ Impact

Likelihood ไม่ใช่การเดาแบบไม่มีหลักฐาน แต่ควรพิจารณาจากข้อมูล เช่น:

- ระบบเปิดสู่อินเทอร์เน็ตหรืออยู่ภายใน
- มีช่องโหว่ที่ exploit ง่ายหรือไม่
- มี exploit code สาธารณะหรือไม่
- มีการโจมตีจริงในอุตสาหกรรมหรือไม่
- มี control ป้องกันอยู่แล้วหรือไม่
- ผู้โจมตีต้องใช้สิทธิ์หรือเงื่อนไขพิเศษหรือไม่

Impact ควรพิจารณาหลายมิติ:

- ความลับของข้อมูล (Confidentiality)
- ความถูกต้องของข้อมูล (Integrity)
- ความพร้อมใช้งาน (Availability)
- ผลกระทบทางการเงิน
- ผลกระทบทางกฎหมายและการปฏิบัติตามข้อกำหนด
- ผลกระทบต่อชื่อเสียงและความเชื่อมั่น

#### 4.8.3 Risk Matrix

ตัวอย่าง Risk Matrix แบบ 3x3 สำหรับการเรียน:

| Impact \ Likelihood | Low | Medium | High |
|---------------------|-----|--------|------|
| Low | Low | Low | Medium |
| Medium | Low | Medium | High |
| High | Medium | High | Critical |

ตัวอย่างการใช้งาน:

- IDOR ในระบบที่เปิดสาธารณะและมีข้อมูลส่วนบุคคลจำนวนมาก: Likelihood = High, Impact = High, Risk = Critical
- Stack Trace แสดงในระบบภายในที่ไม่มีข้อมูลสำคัญ: Likelihood = Medium, Impact = Low, Risk = Low
- ไม่มี Rate Limit ที่ Login API: Likelihood = High, Impact = Medium, Risk = High

**ข้อควรจำ:** Risk Matrix เป็นเครื่องมือช่วยตัดสินใจ ไม่ใช่ความจริงทางคณิตศาสตร์ที่สมบูรณ์ ต้องใช้ร่วมกับบริบทและการตัดสินใจของผู้รับผิดชอบความเสี่ยง

---

### 4.9 ISO/IEC 27005:2022 และ Risk Treatment

ISO/IEC 27005:2022 เป็น Edition 4 ของมาตรฐานแนวทางการจัดการความเสี่ยงด้านความมั่นคงปลอดภัยสารสนเทศ เผยแพร่ปี 2022 และสนับสนุนการทำงานร่วมกับระบบบริหารความมั่นคงปลอดภัยสารสนเทศตาม ISO/IEC 27001

#### 4.9.1 วงจรการจัดการความเสี่ยง

แนวคิดหลักประกอบด้วย:

1. Establish Context: กำหนดบริบทองค์กร ขอบเขต และเกณฑ์ความเสี่ยง
2. Risk Assessment: ระบุ วิเคราะห์ และประเมินความเสี่ยง
3. Risk Treatment: เลือกวิธีจัดการความเสี่ยง
4. Risk Acceptance: ผู้มีอำนาจยอมรับความเสี่ยงคงเหลือ
5. Risk Communication and Consultation: สื่อสารกับผู้มีส่วนเกี่ยวข้อง
6. Risk Monitoring and Review: ติดตามและทบทวนต่อเนื่อง

#### 4.9.2 ทางเลือก Risk Treatment

| ทางเลือก | ความหมาย | ตัวอย่าง |
|----------|----------|----------|
| Mitigate | ลดโอกาสเกิดหรือลดผลกระทบ | เพิ่ม MFA, แก้ Authorization, เข้ารหัสข้อมูล |
| Transfer | โอนความเสี่ยงบางส่วน | Cyber Insurance, ใช้ผู้ให้บริการที่รับผิดชอบบางส่วน |
| Accept | ยอมรับความเสี่ยง | ยอมรับ Low Risk ที่ต้นทุนแก้สูงกว่าผลกระทบ |
| Avoid | หลีกเลี่ยงความเสี่ยง | ยกเลิกฟีเจอร์ที่เก็บข้อมูลอ่อนไหวโดยไม่จำเป็น |

#### 4.9.3 Residual Risk

Residual Risk คือความเสี่ยงที่เหลืออยู่หลังใช้มาตรการควบคุมแล้ว ไม่มี Control ใดลดความเสี่ยงเป็นศูนย์ได้ทั้งหมด

ตัวอย่าง:

- ความเสี่ยงเดิม: Account Takeover จาก Credential Stuffing = High
- Control: MFA, Rate Limit, Breached Password Detection
- Residual Risk: Medium เพราะยังอาจเกิด Social Engineering หรือ Session Theft
- Risk Owner: Product Owner ของระบบบัญชีผู้ใช้
- Decision: Accept Residual Risk ระดับ Medium พร้อม Monitoring เพิ่มเติม

---

### 4.10 Risk Register

Risk Register คือเอกสารหลักสำหรับติดตามความเสี่ยงจาก Threat Modeling ให้กลายเป็นงานที่มีเจ้าของและสถานะชัดเจน

| Field | คำอธิบาย |
|-------|----------|
| Risk ID | รหัสความเสี่ยง เช่น R-001 |
| Threat Statement | ข้อความอธิบายภัยคุกคาม |
| Asset | สินทรัพย์ที่ได้รับผลกระทบ |
| Vulnerability | จุดอ่อนหรือสาเหตุ |
| Likelihood | Low/Medium/High |
| Impact | Low/Medium/High |
| Risk Level | Low/Medium/High/Critical |
| Treatment | Mitigate/Transfer/Accept/Avoid |
| Control | มาตรการที่เลือกใช้ |
| Owner | ผู้รับผิดชอบ |
| Due Date | กำหนดแล้วเสร็จ |
| Status | Open/In Progress/Done/Accepted |
| Residual Risk | ความเสี่ยงหลังควบคุม |

#### 4.10.1 ตัวอย่าง Risk Register สำหรับระบบจองตั๋ว

| ID | Threat | Asset | Likelihood | Impact | Level | Treatment | Control | Owner | Status |
|----|--------|-------|------------|--------|-------|-----------|---------|-------|--------|
| R-001 | ผู้ใช้ดู booking ของผู้อื่นผ่าน IDOR | Booking Data | High | High | Critical | Mitigate | Object-level Authorization, UUID | Backend Lead | Open |
| R-002 | ผู้โจมตี brute force login | User Account | High | Medium | High | Mitigate | Rate Limit, MFA, Lockout | Auth Team | In Progress |
| R-003 | Payment Callback ถูกปลอม | Payment Status | Medium | High | High | Mitigate | HMAC Signature, Replay Protection | Payment Team | Open |
| R-004 | ผู้ใช้ lock ที่นั่งจำนวนมาก | Availability | Medium | Medium | Medium | Mitigate | Seat Hold Timeout, Quota | Product Team | Open |
| R-005 | Log เก็บข้อมูลส่วนบุคคลเกินจำเป็น | Personal Data | Medium | High | High | Mitigate | Log Redaction, Retention Policy | Platform Team | Open |

---

### 4.11 CVSS v4.0: ใช้ให้ถูกบริบท

CVSS หรือ Common Vulnerability Scoring System เป็นมาตรฐานเปิดของ FIRST สำหรับให้คะแนนความรุนแรงของช่องโหว่ เวอร์ชัน v4.0 เผยแพร่ในปี 2023 และใช้คะแนนช่วง 0.0 ถึง 10.0

#### 4.11.1 กลุ่ม Metric ของ CVSS v4.0

| Metric Group | ความหมาย | ใช้ตอบคำถาม |
|--------------|----------|--------------|
| Base Metrics | คุณลักษณะพื้นฐานของช่องโหว่ที่ค่อนข้างคงที่ | ช่องโหว่นี้โจมตียากแค่ไหนและกระทบอะไร |
| Threat Metrics | สถานะภัยคุกคามที่เปลี่ยนตามเวลา | มี exploit หรือถูกโจมตีจริงหรือไม่ |
| Environmental Metrics | บริบทเฉพาะขององค์กร | ระบบนี้สำคัญกับองค์กรแค่ไหน |
| Supplemental Metrics | ข้อมูลเสริม | มี Automatable, Safety, Provider Urgency หรือบริบทอื่นหรือไม่ |

#### 4.11.2 ระดับความรุนแรง

| ระดับ | คะแนน |
|-------|-------|
| None | 0.0 |
| Low | 0.1 - 3.9 |
| Medium | 4.0 - 6.9 |
| High | 7.0 - 8.9 |
| Critical | 9.0 - 10.0 |

#### 4.11.3 CVSS กับ Risk ต่างกันอย่างไร

ตัวอย่างเปรียบเทียบ:

| ช่องโหว่ | CVSS | บริบท | Risk จริง |
|----------|------|-------|-----------|
| Remote Code Execution ในระบบทดสอบที่แยกเครือข่าย | Critical | ไม่มีข้อมูลจริงและปิดจากอินเทอร์เน็ต | Medium |
| Broken Access Control ในระบบลูกค้า | High | เปิดสาธารณะและมีข้อมูลส่วนบุคคลจำนวนมาก | Critical |
| Information Disclosure ใน Debug Endpoint | Medium | แสดง Secret และ Token จริง | High |

สรุป: CVSS ช่วยบอกความรุนแรงทางเทคนิค แต่ Risk ต้องรวมบริบทของ Asset, Exposure, Business Impact และ Existing Controls

---

### 4.12 DREAD: ประโยชน์และข้อจำกัด

DREAD เป็นกรอบให้คะแนนภัยคุกคามที่ประกอบด้วย 5 ปัจจัย:

- Damage: ความเสียหายหากเกิดขึ้น
- Reproducibility: ทำซ้ำได้ง่ายแค่ไหน
- Exploitability: โจมตีได้ง่ายแค่ไหน
- Affected Users: กระทบผู้ใช้จำนวนเท่าใด
- Discoverability: ค้นพบช่องโหว่ได้ง่ายแค่ไหน

#### 4.12.1 ตัวอย่างการใช้ DREAD ในชั้นเรียน

| Threat | Damage | Reproducibility | Exploitability | Affected Users | Discoverability | รวม |
|--------|--------|-----------------|----------------|----------------|-----------------|-----|
| IDOR อ่าน booking ผู้อื่น | 8 | 9 | 8 | 7 | 8 | 40 |
| ไม่มี Rate Limit หน้า Login | 6 | 9 | 7 | 8 | 9 | 39 |
| Stack Trace แสดงรายละเอียด | 4 | 6 | 3 | 3 | 7 | 23 |

#### 4.12.2 ข้อจำกัดของ DREAD

DREAD มีประโยชน์ในการฝึกคิด แต่ไม่ควรนำเสนอเป็นมาตรฐานหลักสมัยใหม่ เพราะ:

- คะแนนขึ้นกับผู้ประเมินสูง
- ทีมต่างกันอาจให้คะแนนต่างกันมาก
- Discoverability มักทำให้เกิดความสับสน เพราะช่องโหว่ที่ค้นพบยากไม่ได้แปลว่าไม่ร้ายแรง
- ไม่เชื่อมโยงบริบทธุรกิจอย่างชัดเท่า Risk Register

แนวทางในบทนี้: ใช้ DREAD เพื่อฝึกการอภิปราย แต่ใช้ Risk Matrix และ Risk Register เป็นผลลัพธ์หลักของการจัดลำดับความเสี่ยง

---

### 4.13 เปรียบเทียบวิธี Threat Modeling ที่สำคัญ

| วิธี | จุดเด่น | เหมาะกับ | ข้อควรระวัง |
|------|--------|----------|-------------|
| STRIDE | เข้าใจง่าย ผูกกับ DFD | ทีมพัฒนาและผู้เริ่มต้น | ต้องมี DFD ที่ดี ไม่เช่นนั้นตกหล่นง่าย |
| PASTA | Risk-centric และเชื่อมธุรกิจ | ระบบสำคัญระดับองค์กร | ใช้เวลาและข้อมูลมาก |
| LINDDUN | เน้น Privacy Threat | ระบบที่ประมวลผลข้อมูลส่วนบุคคล | ไม่ครอบคลุมภัยคุกคามด้าน Availability หรือ Privilege ทั้งหมด |
| Trike | เน้นข้อกำหนดและสิทธิ์ | ระบบที่ต้องควบคุมสิทธิ์ละเอียด | ซับซ้อนสำหรับชั้นเรียนพื้นฐาน |
| VAST | รองรับองค์กรขนาดใหญ่และ Agile | หลายทีม หลายระบบ | ต้องมีเครื่องมือและกระบวนการรองรับ |

#### 4.13.1 PASTA 7 ขั้นตอน

PASTA หรือ Process for Attack Simulation and Threat Analysis เป็นแนวทางที่เน้นการจำลองการโจมตีและความเสี่ยงทางธุรกิจ มี 7 ขั้นตอน:

1. Define Business Objectives
2. Define Technical Scope
3. Decompose the Application
4. Threat Analysis
5. Vulnerability Analysis
6. Attack Modeling and Simulation
7. Risk and Impact Analysis

PASTA เหมาะกับระบบที่ต้องการเชื่อมความเสี่ยงทางเทคนิคกับผลกระทบทางธุรกิจ เช่น ระบบธนาคาร ระบบชำระเงิน ระบบสุขภาพ หรือระบบโครงสร้างพื้นฐานสำคัญ

#### 4.13.2 LINDDUN สำหรับ Privacy Threat Modeling

LINDDUN เหมาะกับระบบที่ประมวลผลข้อมูลส่วนบุคคล โดยพิจารณาภัยคุกคามด้านความเป็นส่วนตัว เช่น Linkability, Identifiability, Non-repudiation, Detectability, Disclosure of Information, Unawareness และ Non-compliance

ตัวอย่างการใช้งาน:

- แอปสุขภาพที่เก็บข้อมูลอาการและตำแหน่ง
- ระบบวิเคราะห์พฤติกรรมลูกค้า
- ระบบนักศึกษาออนไลน์ที่เก็บข้อมูลการเรียนรู้

---

### 4.14 เครื่องมือสำหรับ Threat Modeling

เครื่องมือช่วยให้ทำงานเป็นระบบ แต่ไม่สามารถแทนการคิดวิเคราะห์ของทีมได้

| เครื่องมือ | จุดเด่น | เหมาะกับ |
|------------|--------|----------|
| Microsoft Threat Modeling Tool | ใช้ STRIDE และสร้างรายงานจาก DFD | ทีมที่ต้องการเริ่มต้นแบบมีโครง |
| OWASP Threat Dragon | Open Source, ใช้งานกับ DFD ได้ | ชั้นเรียนและทีมพัฒนา |
| draw.io / diagrams.net | วาด DFD ได้ยืดหยุ่น | ทีมที่ต้องการเริ่มเร็ว |
| Miro / FigJam | Collaboration ดี | Workshop หลายคน |
| Jira / GitHub Issues | ติดตาม Risk และ Control เป็นงาน | เชื่อม Threat Model กับ Sprint |

#### 4.14.1 ข้อควรระวังในการใช้เครื่องมือ

- เครื่องมือช่วยจัดรูปแบบ แต่ไม่รับประกันว่าภัยคุกคามครบ
- ถ้า DFD ผิด ผลการวิเคราะห์ก็ผิด
- Threat Model ต้องอัปเดตเมื่อระบบเปลี่ยน
- ควรเชื่อมผลลัพธ์กับ Backlog, Security Requirement และ Test Case

---

### 4.15 กรณีศึกษาจริง

#### 4.15.1 Equifax 2017

Equifax ถูกโจมตีในปี 2017 ผ่านช่องโหว่ Apache Struts และคณะกรรมาธิการการค้าแห่งสหรัฐระบุว่ามีผู้ได้รับผลกระทบประมาณ 147 ล้านคน ข้อตกลงปี 2019 มีมูลค่าอย่างน้อย 575 ล้านดอลลาร์สหรัฐ และอาจสูงถึง 700 ล้านดอลลาร์สหรัฐ

ประเด็นที่เกี่ยวข้องกับบทนี้:

- Patch Management เป็นส่วนหนึ่งของ Risk Treatment
- การไม่แบ่งส่วนเครือข่ายทำให้ผลกระทบขยายวง
- การตรวจจับล่าช้าทำให้ Impact สูงขึ้น
- Threat Modeling ควรมองเส้นทางโจมตีจากระบบที่เปิดสาธารณะไปยังข้อมูลสำคัญ

บทเรียน:

- ช่องโหว่ที่มี Patch แล้วแต่ไม่แก้ไข อาจกลายเป็นความเสี่ยงระดับองค์กร
- Risk Register ต้องมีเจ้าของและกำหนดเวลา ไม่ใช่แค่รายการช่องโหว่
- ต้องตรวจสอบว่า Control ทำงานจริง เช่น Certificate Monitoring, Network Segmentation, Logging

#### 4.15.2 Capital One Cloud Breach 2019/2020

สำนักงานผู้ควบคุมเงินตราสหรัฐปรับ Capital One จำนวน 80 ล้านดอลลาร์สหรัฐในปี 2020 โดยระบุปัญหาเกี่ยวกับกระบวนการประเมินความเสี่ยงก่อนย้ายงานสำคัญขึ้นคลาวด์และการควบคุมความเสี่ยงที่ไม่มีประสิทธิผลเพียงพอ

ประเด็นที่เกี่ยวข้องกับบทนี้:

- Cloud Architecture ต้องทำ Threat Modeling เฉพาะบริบท
- Metadata Service, IAM Role และ Network Exposure เป็นจุดสำคัญ
- การให้สิทธิ์เกินจำเป็นเพิ่มผลกระทบเมื่อเกิดการเจาะระบบ

บทเรียน:

- Least Privilege ต้องตรวจจริง ไม่ใช่แค่เขียนในนโยบาย
- ต้องทดสอบสมมติฐานด้านสถาปัตยกรรม เช่น “ระบบภายในปลอดภัย” หรือ “WAF ป้องกันได้ทั้งหมด”
- Risk Assessment ก่อนย้ายระบบขึ้น Cloud ต้องมีหลักฐานและการตรวจสอบต่อเนื่อง

#### 4.15.3 SolarWinds 2020

การโจมตี SolarWinds SUNBURST ในปี 2020 เป็นกรณีสำคัญของ Software Supply Chain Attack ผู้โจมตีแทรกโค้ดอันตรายในกระบวนการอัปเดตซอฟต์แวร์ ทำให้ลูกค้าจำนวนมากได้รับผลกระทบผ่านซอฟต์แวร์ที่เชื่อถือ

ประเด็นที่เกี่ยวข้องกับบทนี้:

- Threat Modeling ต้องรวม CI/CD Pipeline และ Build System
- Software Update เป็น Trust Boundary ที่สำคัญ
- Code Signing ไม่เพียงพอถ้า Build Pipeline ถูก compromise ก่อนเซ็น

บทเรียน:

- Attack Surface ของซอฟต์แวร์รวมถึงกระบวนการ build, dependency, signing key และ release pipeline
- ต้องมี Build Integrity, Separation of Duties, Monitoring และ Reproducible Build ในระบบสำคัญ
- Risk Communication ต่อผู้บริหารและผู้ใช้เป็นส่วนหนึ่งของการบริหารความเสี่ยง

#### 4.15.4 MOVEit Transfer 2023

CISA ระบุว่ากลุ่ม Cl0p ใช้ช่องโหว่ SQL Injection ใน MOVEit Transfer โดยเริ่มโจมตีตั้งแต่วันที่ 27 พฤษภาคม 2023 และ CISA เผยแพร่คำแนะนำวันที่ 7 มิถุนายน 2023

ประเด็นที่เกี่ยวข้องกับบทนี้:

- ระบบถ่ายโอนไฟล์มักเปิดสู่อินเทอร์เน็ตและถือข้อมูลสำคัญ
- ช่องโหว่ Injection ในระบบที่มีข้อมูลจำนวนมากมี Impact สูง
- การจัดลำดับแพตช์ต้องพิจารณา Exposure และการถูกโจมตีจริง ไม่ใช่คะแนนอย่างเดียว

บทเรียน:

- Internet-facing File Transfer System ต้องอยู่ใน Risk Register ระดับสูง
- ต้องมี Monitoring สำหรับพฤติกรรมการดาวน์โหลดผิดปกติ
- Threat Modeling ควรถามว่า “ถ้าระบบนี้ถูกเจาะ ผู้โจมตีจะเข้าถึงข้อมูลใดได้บ้าง”

#### 4.15.5 Log4Shell 2021

Log4Shell หรือ CVE-2021-44228 เป็นช่องโหว่ร้ายแรงใน Log4j ที่ส่งผลกระทบกว้างขวางต่อระบบ Java จำนวนมากทั่วโลก

ประเด็นที่เกี่ยวข้องกับบทนี้:

- Dependency เป็นส่วนหนึ่งของ Attack Surface
- SBOM ช่วยระบุว่าระบบใดใช้ component ที่ได้รับผลกระทบ
- CVSS สูงต้องนำมาประกอบกับ Asset Criticality และ Exposure

บทเรียน:

- Risk Analysis ต้องครอบคลุม Third-party Dependency
- ต้องมี Inventory ของระบบและ Library
- การตอบสนองต่อช่องโหว่ต้องวัดจากเวลาค้นพบระบบที่ได้รับผลกระทบและเวลาปิดความเสี่ยง

---

### 4.16 ตัวอย่าง End-to-End: Threat Modeling ระบบจองตั๋วภาพยนตร์

ส่วนนี้แสดงตัวอย่างการทำ Threat Modeling ตั้งแต่ต้นจนจบ เพื่อให้นักศึกษาเห็นว่าขั้นตอนต่างๆ เชื่อมกันอย่างไร

#### 4.16.1 System Scope

ระบบ CineTicket เป็นระบบจองตั๋วภาพยนตร์ออนไลน์ ผู้ใช้สามารถสมัครสมาชิก เข้าสู่ระบบ เลือกรอบภาพยนตร์ เลือกที่นั่ง ชำระเงิน และดูประวัติการจองได้ ผู้ดูแลระบบสามารถจัดการภาพยนตร์ รอบฉาย ราคา และคำสั่งซื้อได้

**อยู่ในขอบเขต:**

- ระบบสมัครสมาชิกและเข้าสู่ระบบ
- ระบบเลือกที่นั่งและสร้าง booking
- ระบบชำระเงินผ่าน Payment Gateway
- ระบบประวัติการจอง
- ระบบผู้ดูแลสำหรับจัดการรอบฉาย

**อยู่นอกขอบเขต:**

- ระบบบัญชีภายในบริษัท
- ระบบบริหารพนักงานโรงภาพยนตร์
- ระบบของ Payment Gateway ภายใน

#### 4.16.2 Asset และ Security Objective

| Asset | คำอธิบาย | Security Objective |
|-------|----------|--------------------|
| User Account | ข้อมูลบัญชีผู้ใช้และ credential | Confidentiality, Integrity |
| Booking Record | ประวัติการจอง รอบฉาย ที่นั่ง ราคา | Integrity, Accountability |
| Seat Inventory | สถานะที่นั่งว่าง/ถูกจอง | Integrity, Availability |
| Payment Status | สถานะการชำระเงินจาก Gateway | Integrity, Non-repudiation |
| Admin Function | ฟังก์ชันเพิ่มรอบฉายและแก้ราคา | Authorization, Accountability |
| Audit Log | หลักฐานการทำธุรกรรม | Integrity, Non-repudiation |

#### 4.16.3 DFD แบบย่อ

```
[Customer]
  -> Login/Register -> [Auth Service] -> [User DB]
  -> Search Movie -> [Movie Service] -> [Movie DB]
  -> Select Seat -> [Booking Service] -> [Seat DB]
  -> Pay -> [Payment Service] -> [Payment Gateway]
  <- Payment Callback <- [Payment Gateway]
  -> View Booking -> [Booking Service] -> [Booking DB]

[Admin]
  -> Manage Movie/Showtime -> [Admin API] -> [Movie DB]
```

**Trust Boundary:**

1. Customer ↔ Web/API: ผู้ใช้ภายนอกเข้าสู่ระบบองค์กร
2. Admin ↔ Admin API: ผู้ดูแลเข้าสู่ฟังก์ชันสิทธิ์สูง
3. API ↔ Database: Application Layer ติดต่อ Data Layer
4. Payment Service ↔ Payment Gateway: ระบบองค์กรติดต่อ Third-party
5. Internal Services ↔ Logging System: ข้อมูลเหตุการณ์ถูกส่งไปเก็บเพื่อ audit

#### 4.16.4 Threat List ด้วย STRIDE

| ID | DFD Element | STRIDE | Threat Statement | Proposed Control |
|----|-------------|--------|------------------|------------------|
| T-001 | Auth Service | Spoofing | ผู้โจมตีใช้ credential ที่รั่วไหลเพื่อเข้าสู่บัญชีผู้ใช้ | MFA, Rate Limit, Breached Password Check |
| T-002 | Booking API | Tampering | ผู้ใช้แก้ราคาใน request ก่อนยืนยันการจอง | คำนวณราคาที่ Server และตรวจ Promotion Rule |
| T-003 | Cancel Booking | Repudiation | ผู้ใช้ปฏิเสธว่าไม่ได้ยกเลิก booking | Audit Log, Confirmation Step |
| T-004 | Booking History | Information Disclosure | ผู้ใช้เดา booking_id เพื่อดูข้อมูลของผู้อื่น | Object-level Authorization, UUID |
| T-005 | Seat Hold | Denial of Service | ผู้โจมตี hold ที่นั่งจำนวนมากโดยไม่จ่ายเงิน | Seat Hold Timeout, User Quota |
| T-006 | Admin API | Elevation of Privilege | ผู้ใช้ทั่วไปเรียก Admin API โดยตรง | Backend RBAC, MFA, Admin Network Policy |
| T-007 | Payment Callback | Tampering | ผู้โจมตีปลอม callback ว่าชำระเงินสำเร็จ | HMAC Signature, Replay Protection |
| T-008 | Log Pipeline | Information Disclosure | ระบบบันทึก Token หรือข้อมูลส่วนบุคคลใน log | Log Redaction, Data Classification |

#### 4.16.5 Risk Register จาก Threat List

| Risk ID | Threat | Likelihood | Impact | Level | Treatment | Owner | Residual Risk |
|---------|--------|------------|--------|-------|-----------|-------|---------------|
| R-001 | IDOR ใน Booking History | High | High | Critical | Mitigate | Backend Lead | Low หลังเพิ่ม Object-level Authorization |
| R-002 | Payment Callback ปลอม | Medium | High | High | Mitigate | Payment Lead | Low หลังใช้ HMAC และ nonce |
| R-003 | Credential Stuffing | High | Medium | High | Mitigate | Auth Team | Medium หลัง MFA และ Rate Limit |
| R-004 | Seat Hold Abuse | Medium | Medium | Medium | Mitigate | Product Team | Low หลังใช้ quota และ timeout |
| R-005 | Admin API ถูกเรียกโดยไม่มีสิทธิ์ | Medium | High | High | Mitigate | Platform Team | Low หลัง RBAC และ MFA |

#### 4.16.6 Security Requirements ที่ได้จาก Threat Model

Threat Modeling ต้องแปลงเป็น Requirements ที่ทดสอบได้ ตัวอย่าง:

| Requirement ID | Security Requirement | Threat ที่เกี่ยวข้อง | Acceptance Criteria |
|----------------|----------------------|----------------------|---------------------|
| SR-001 | ระบบต้องตรวจว่า booking_id เป็นของผู้ใช้ที่เข้าสู่ระบบก่อนแสดงข้อมูล | T-004 | ผู้ใช้ A ไม่สามารถเรียก booking ของผู้ใช้ B ได้ แม้รู้ booking_id |
| SR-002 | Payment Callback ต้องมี HMAC Signature และ timestamp | T-007 | Callback ที่ signature ผิดหรือ timestamp เกิน 5 นาทีต้องถูกปฏิเสธ |
| SR-003 | Admin API ต้องใช้ MFA และ RBAC | T-006 | ผู้ใช้ role customer เรียก endpoint admin แล้วต้องได้ 403 |
| SR-004 | Seat Hold ต้องหมดอายุภายในเวลาที่กำหนด | T-005 | ที่นั่งที่ hold แล้วไม่ชำระเงินต้องกลับสู่ว่างอัตโนมัติ |
| SR-005 | Log ต้องไม่เก็บ Access Token หรือเลขบัตรประชาชนเต็ม | T-008 | Automated log scan ไม่พบ token pattern หรือ personal identifier แบบเต็ม |

#### 4.16.7 Security Test Cases ที่ได้จาก Threat Model

| Test ID | Test Case | Expected Result | Tool/Method |
|---------|-----------|-----------------|-------------|
| ST-001 | Login ผิดซ้ำเกิน threshold | ถูก rate limit หรือ lock ชั่วคราว | Manual/API Test |
| ST-002 | User A เรียก `/bookings/{id}` ของ User B | HTTP 403 หรือ 404 | API Test |
| ST-003 | ส่ง Payment Callback โดยไม่มี signature | ถูกปฏิเสธและบันทึก log | Integration Test |
| ST-004 | แก้ราคาใน request | Server ใช้ราคาจากฐานข้อมูล ไม่ใช้ราคาจาก client | Integration Test |
| ST-005 | อัปโหลด request จำนวนมากเพื่อ hold seat | ถูกจำกัด quota | Load/Abuse Test |
| ST-006 | ตรวจ log หลังทำธุรกรรม | ไม่พบ token หรือข้อมูลส่วนบุคคลเกินจำเป็น | Log Review / DLP Rule |

**ข้อควรจำ:** Threat Model ที่ดีควรสร้างเส้นทางจาก Threat → Requirement → Implementation → Test → Monitoring ได้ครบ หากขาดขั้นใดขั้นหนึ่ง ความเสี่ยงอาจไม่ถูกปิดจริง

---

### 4.17 การเชื่อม Threat Modeling เข้ากับ Secure SDLC และ DevSecOps

Threat Modeling ไม่ควรถูกทำเป็น workshop ครั้งเดียวแล้วเก็บไฟล์ไว้ แต่ควรฝังเข้าไปใน SDLC และ DevSecOps Pipeline

#### 4.17.1 Mapping กับ SDLC

| SDLC Phase | Threat Modeling Activity | Output |
|------------|--------------------------|--------|
| Requirements | ระบุ Asset, Abuse Case, Security Objective | Security Requirements |
| Design | วาด DFD, ระบุ Trust Boundary, วิเคราะห์ STRIDE | Threat Model, Design Controls |
| Implementation | แปลง Threat เป็น Secure Coding Task | Code Changes, Secure Defaults |
| Testing | สร้าง Security Test Cases จาก Threat | API Security Test, DAST, Abuse Test |
| Deployment | ตรวจ Configuration และ Secret | Deployment Gate, IaC Scan |
| Operations | Monitor Threat และ Residual Risk | Alert, Incident Playbook, Risk Review |

#### 4.17.2 การใช้ Threat Model ใน Agile

ใน Agile ทีมไม่จำเป็นต้องทำ Threat Modeling ขนาดใหญ่ทุก Sprint แต่ควรใช้แนวทาง incremental:

- ทำ Threat Modeling เต็มเมื่อเริ่มระบบหรือเปลี่ยนสถาปัตยกรรมใหญ่
- ทำ Mini Threat Modeling เมื่อเพิ่มฟีเจอร์ที่แตะข้อมูลสำคัญหรือ Trust Boundary ใหม่
- เพิ่ม Security Story ใน Backlog
- ใส่ Security Acceptance Criteria ใน User Story
- ทบทวน Threat Model ใน Sprint Review หากมี design เปลี่ยน

ตัวอย่าง Security Story:

```
ในฐานะผู้ใช้ระบบจองตั๋ว
ฉันต้องการให้ข้อมูล booking ของฉันถูกแสดงเฉพาะกับบัญชีของฉันเท่านั้น
เพื่อป้องกันไม่ให้ผู้ใช้คนอื่นเข้าถึงข้อมูลส่วนบุคคลและประวัติการจองของฉัน

Acceptance Criteria:
1. API ต้องตรวจ owner ของ booking ทุกครั้ง
2. ผู้ใช้ที่ไม่ใช่เจ้าของ booking ต้องได้รับ 403 หรือ 404
3. ทุกความพยายามเข้าถึง booking ที่ไม่มีสิทธิ์ต้องถูกบันทึกใน audit log
```

#### 4.17.3 การใช้ Threat Model เป็น Security Gate

องค์กรสามารถกำหนด Security Gate เช่น:

- ฟีเจอร์ที่เพิ่ม endpoint สาธารณะใหม่ต้องมี Threat Review
- ฟีเจอร์ที่ประมวลผลข้อมูลส่วนบุคคลต้องมี Privacy Threat Review
- ฟีเจอร์ที่เชื่อม Third-party ต้องมี Trust Boundary Review
- Critical/High Threat ต้องมีเจ้าของและแผนแก้ก่อน production
- Residual Risk ระดับ High ต้องมีผู้บริหารหรือ Risk Owner อนุมัติ

---

### 4.18 Checklist สำหรับ Threat Modeling Review

ใช้ Checklist นี้ก่อนปิดงาน Threat Modeling

#### 4.18.1 Scope Checklist

- ระบุระบบและฟีเจอร์ที่อยู่ในขอบเขตแล้ว
- ระบุสิ่งที่อยู่นอกขอบเขตแล้ว
- ระบุผู้ใช้และระบบภายนอกครบถ้วน
- ระบุข้อมูลสำคัญและ Asset สำคัญแล้ว
- ระบุ Assumption และ Constraint แล้ว

#### 4.18.2 DFD Checklist

- มี External Entity ครบ
- มี Process หลักครบ
- มี Data Store ครบ
- Data Flow มีทิศทางและชื่อข้อมูล
- Trust Boundary ถูกระบุชัดเจน
- Third-party และ callback ถูกแสดงใน DFD
- ระบบ logging, monitoring และ admin function ไม่ถูกลืม

#### 4.18.3 Threat Checklist

- วิเคราะห์ STRIDE ครบตามองค์ประกอบที่เกี่ยวข้อง
- Threat Statement ระบุผู้โจมตี ช่องทาง สาเหตุ และผลกระทบ
- ภัยคุกคามสำคัญมี Control ที่ชัดเจน
- ไม่มี Threat ที่คลุมเครือเกินไป เช่น “ระบบไม่ปลอดภัย”
- มีการพิจารณา Abuse Case และ Business Logic Abuse

#### 4.18.4 Risk Checklist

- ทุก High/Critical Threat ถูกบันทึกใน Risk Register
- มี Owner และ Due Date
- มี Risk Treatment ชัดเจน
- มี Residual Risk หลัง Control
- Risk ที่ Accept มีผู้อนุมัติและเหตุผล
- Control ถูกแปลงเป็น Requirement หรือ Backlog Item

#### 4.18.5 Verification Checklist

- Control สำคัญมี Test Case
- Authorization Test ครอบคลุม object-level access
- Logging และ alert ถูกทดสอบ
- Security Test ถูกผูกกับ CI/CD หรือ release gate เท่าที่เหมาะสม
- Threat Model ถูกเก็บในที่ที่ทีมเข้าถึงและอัปเดตได้

---

### 4.19 ข้อผิดพลาดที่พบบ่อยและแนวทางแก้ไข

| ข้อผิดพลาด | ผลที่เกิด | แนวทางแก้ |
|------------|----------|-----------|
| ทำ Threat Modeling หลังระบบเสร็จแล้ว | แก้ design ยากและต้นทุนสูง | ทำตั้งแต่ Requirements/Design และทบทวนเมื่อเปลี่ยนแปลง |
| ให้ Security Team ทำฝ่ายเดียว | ทีมพัฒนาไม่เข้าใจและไม่แก้จริง | ทำ workshop ร่วมระหว่าง Dev, QA, DevOps, Product, Security |
| สนใจเฉพาะเทคนิค ไม่ดูธุรกิจ | จัดลำดับผิด | ระบุ Asset, Business Impact และ Risk Owner |
| ไม่มี Risk Register | ภัยคุกคามไม่ถูกติดตาม | แปลง Threat เป็น Risk และ Backlog Item |
| ใช้ CVSS เป็นคำตอบสุดท้าย | มองข้ามบริบทธุรกิจ | ใช้ CVSS คู่กับ Exposure, Asset Criticality และ Existing Controls |
| ลืม Third-party | มองข้าม Supply Chain Risk | ใส่ทุก Third-party ใน DFD และระบุ Trust Boundary |
| ไม่ทดสอบ Control | คิดว่าปลอดภัยแต่ control อาจไม่ทำงาน | สร้าง Test Case และ Monitoring จาก Threat Model |

**คำถามสำหรับการอภิปรายในชั้นเรียน:** หากทีมมีเวลาจำกัดมาก ควรทำ Threat Modeling แบบย่ออย่างไรให้ยังเกิดคุณค่า นักศึกษาควรเสนอขั้นตอนที่ใช้เวลาไม่เกิน 30 นาที และระบุว่าขั้นตอนใดห้ามตัดออกเด็ดขาด

---

## Keywords

Threat Modeling, Risk Assessment, Risk Analysis, STRIDE, DFD, Trust Boundary, Attack Surface, Attack Tree, Risk Register, Residual Risk, CVSS v4.0, DREAD, PASTA, LINDDUN, ISO/IEC 27005, NIST SP 800-30

---

## กิจกรรมปฏิบัติการ

### Lab 4.1: สร้าง DFD และระบุ Trust Boundary

**วัตถุประสงค์:** เพื่อฝึกแปลงระบบซอฟต์แวร์ให้เป็นแผนภาพที่ใช้วิเคราะห์ภัยคุกคามได้

**เวลาที่ใช้:** 45-60 นาที

**ระบบตัวอย่าง:** เลือก 1 ระบบ

- ระบบ E-Commerce
- ระบบจองตั๋วภาพยนตร์
- ระบบ Mobile Banking
- ระบบรับส่งไฟล์ภายในองค์กร

**ขั้นตอน:**

1. ระบุผู้ใช้งานและระบบภายนอกอย่างน้อย 3 รายการ
2. ระบุ Process หลักอย่างน้อย 4 รายการ
3. ระบุ Data Store อย่างน้อย 2 รายการ
4. วาด Data Flow พร้อมชื่อข้อมูลบนเส้นทุกเส้น
5. ระบุ Trust Boundary อย่างน้อย 3 จุด
6. เขียน Assumption อย่างน้อย 5 ข้อ
7. เขียน Asset List อย่างน้อย 5 รายการ พร้อม Security Objective

**สิ่งที่ต้องส่ง:**

1. DFD 1 ภาพ
2. ตาราง Asset List
3. รายการ Trust Boundary พร้อมคำอธิบาย
4. Assumption และ Constraint ของระบบ

---

### Lab 4.2: วิเคราะห์ภัยคุกคามด้วย STRIDE

**วัตถุประสงค์:** เพื่อฝึกใช้ STRIDE วิเคราะห์ DFD อย่างเป็นระบบ

**เวลาที่ใช้:** 60 นาที

**ขั้นตอน:**

1. ใช้ DFD จาก Lab 4.1
2. เลือกองค์ประกอบอย่างน้อย 8 จุดจาก DFD
3. วิเคราะห์ STRIDE ที่เกี่ยวข้องกับแต่ละจุด
4. เขียน Threat Statement อย่างน้อย 12 รายการ
5. ระบุ Asset ที่ได้รับผลกระทบ
6. เสนอ Control อย่างน้อย 1 รายการต่อ Threat
7. ตรวจว่ามี Threat ซ้ำ คลุมเครือ หรือไม่มีผลกระทบชัดเจนหรือไม่

**Template ที่ใช้ส่ง:**

| ID | DFD Element | STRIDE | Threat Statement | Asset | Proposed Control |
|----|-------------|--------|------------------|-------|------------------|
| T-001 | Login API | Spoofing | ... | User Account | MFA, Rate Limit |

**สิ่งที่ต้องส่ง:**

1. ตาราง STRIDE Threat อย่างน้อย 12 รายการ
2. Control ที่สอดคล้องกับภัยคุกคาม
3. สรุป 3 ภัยคุกคามที่สำคัญที่สุดพร้อมเหตุผล

---

### Lab 4.3: ทำ Risk Register และเลือก Risk Treatment

**วัตถุประสงค์:** เพื่อฝึกเปลี่ยน Threat List ให้เป็น Risk Register ที่ติดตามได้จริง

**เวลาที่ใช้:** 60 นาที

**ขั้นตอน:**

1. เลือกภัยคุกคาม 8 รายการจาก Lab 4.2
2. ประเมิน Likelihood เป็น Low/Medium/High
3. ประเมิน Impact เป็น Low/Medium/High
4. ใช้ Risk Matrix เพื่อกำหนด Risk Level
5. เลือก Risk Treatment: Mitigate, Transfer, Accept หรือ Avoid
6. ระบุ Control, Owner, Due Date และ Status
7. ประเมิน Residual Risk หลังมี Control

**Template ที่ใช้ส่ง:**

| Risk ID | Threat | Asset | Likelihood | Impact | Level | Treatment | Control | Owner | Due Date | Residual Risk |
|---------|--------|-------|------------|--------|-------|-----------|---------|-------|----------|---------------|

**สิ่งที่ต้องส่ง:**

1. Risk Register อย่างน้อย 8 รายการ
2. คำอธิบายเหตุผลของ Risk Level อย่างน้อย 3 รายการ
3. รายการ Risk ที่ยอมรับได้ พร้อมเหตุผลและผู้อนุมัติสมมติ

---

### Lab 4.4: CVSS v4.0 เทียบกับความเสี่ยงทางธุรกิจ

**วัตถุประสงค์:** เพื่อให้นักศึกษาเข้าใจว่า Severity ไม่เท่ากับ Risk

**เวลาที่ใช้:** 45-60 นาที

**ขั้นตอน:**

1. เลือกช่องโหว่ตัวอย่าง 3 รายการ เช่น IDOR, SQL Injection, Missing Rate Limit
2. ประเมินหรือค้นหาคะแนน CVSS โดยใช้แนวคิด CVSS v4.0
3. ระบุบริบทธุรกิจของแต่ละช่องโหว่ เช่น ระบบเปิดอินเทอร์เน็ตหรือระบบภายใน
4. ระบุ Asset ที่เกี่ยวข้องและข้อมูลที่อาจได้รับผลกระทบ
5. จัดลำดับการแก้ไขตาม CVSS อย่างเดียว
6. จัดลำดับใหม่โดยใช้ Business Risk
7. อธิบายว่าลำดับเปลี่ยนหรือไม่ เพราะเหตุใด

**สิ่งที่ต้องส่ง:**

1. ตารางเปรียบเทียบ CVSS กับ Business Risk
2. ลำดับการแก้ไขแบบ Severity-based
3. ลำดับการแก้ไขแบบ Risk-based
4. บทสรุป 1 หน้าเรื่อง “ทำไม CVSS จึงไม่ใช่ Risk ทั้งหมด”

---

## คำถามท้ายบท

1. Threat Modeling แตกต่างจาก Risk Assessment และ Vulnerability Scoring อย่างไร จงอธิบายพร้อมตัวอย่างในระบบ Web Application
2. เหตุใด DFD และ Trust Boundary จึงเป็นพื้นฐานสำคัญของ Threat Modeling จงยกตัวอย่าง Trust Boundary อย่างน้อย 3 จุดในระบบ E-Commerce
3. อธิบาย STRIDE ทั้ง 6 หมวด พร้อมยกตัวอย่างภัยคุกคามและมาตรการควบคุมสำหรับแต่ละหมวด
4. จงเขียน Threat Statement สำหรับกรณี “ผู้ใช้สามารถดูข้อมูลคำสั่งซื้อของผู้อื่นได้” โดยระบุผู้โจมตี ช่องทาง ช่องโหว่ และผลกระทบ
5. Risk Matrix มีข้อดีและข้อจำกัดอย่างไร เหตุใดจึงไม่ควรใช้เป็นสูตรคณิตศาสตร์ตายตัว
6. CVSS v4.0 มี Metric Group ใดบ้าง และเพราะเหตุใด CVSS จึงไม่เท่ากับความเสี่ยงทางธุรกิจทั้งหมด
7. DREAD มีประโยชน์อย่างไรในการเรียน Threat Modeling และมีข้อจำกัดอะไรเมื่อนำไปใช้จริง
8. เปรียบเทียบ STRIDE กับ PASTA ในด้านจุดประสงค์ ขั้นตอน ข้อมูลที่ต้องใช้ และความเหมาะสมกับองค์กร
9. จากกรณี Equifax 2017 จงอธิบายว่าการทำ Threat Modeling และ Risk Register ที่ดีควรช่วยลดความเสี่ยงใดได้บ้าง
10. จากกรณี SolarWinds 2020 จงอธิบายว่า Attack Surface ของซอฟต์แวร์ไม่ได้มีแค่ตัวแอปพลิเคชัน แต่รวมถึงส่วนใดบ้างของ Supply Chain

---

## สรุปท้ายบท

Threat Modeling เป็นกระบวนการคิดเชิงระบบเพื่อค้นหาว่า “อะไรอาจผิดพลาดได้” ในการออกแบบและพัฒนาซอฟต์แวร์ โดยเริ่มจากการเข้าใจระบบ กำหนดขอบเขต ระบุสินทรัพย์ สร้าง DFD ระบุ Trust Boundary และวิเคราะห์ภัยคุกคามด้วยกรอบ เช่น STRIDE ผลลัพธ์ที่ดีต้องไม่หยุดแค่รายการภัยคุกคาม แต่ต้องเชื่อมต่อไปยัง Security Requirements, Controls, Test Cases และ Risk Register

STRIDE ช่วยให้ทีมพัฒนาวิเคราะห์ภัยคุกคามอย่างเป็นระบบผ่าน 6 หมวด ได้แก่ Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service และ Elevation of Privilege เมื่อนำ STRIDE ไปจับคู่กับองค์ประกอบของ DFD จะช่วยลดโอกาสตกหล่นและทำให้การวิเคราะห์สอดคล้องกับสถาปัตยกรรมจริงของระบบ

Risk Assessment ช่วยจัดลำดับว่าภัยคุกคามใดสำคัญที่สุด โดยพิจารณา Likelihood และ Impact ตามแนวคิดของ NIST SP 800-30 Rev.1 และการจัดการความเสี่ยงตาม ISO/IEC 27005:2022 ผลลัพธ์ควรถูกบันทึกใน Risk Register ที่มีเจ้าของงาน สถานะ กำหนดเวลา มาตรการควบคุม และ Residual Risk ชัดเจน

CVSS v4.0 เป็นเครื่องมือสำคัญในการสื่อสารความรุนแรงของช่องโหว่ แต่ไม่ใช่คะแนนความเสี่ยงทางธุรกิจทั้งหมด การตัดสินใจจริงต้องรวมบริบทขององค์กร เช่น ระบบเปิดสู่อินเทอร์เน็ตหรือไม่ มีข้อมูลสำคัญมากแค่ไหน มีการโจมตีจริงหรือไม่ และมี Control ใดอยู่แล้ว

กรณีศึกษา Equifax, Capital One, SolarWinds, MOVEit และ Log4Shell แสดงให้เห็นว่า Threat Modeling และ Risk Analysis ไม่ใช่กิจกรรมเชิงเอกสาร แต่เป็นการป้องกันความเสียหายจริง หากองค์กรไม่เข้าใจ Attack Surface, Supply Chain, Cloud Permission, Patch Priority และ Data Exposure ความเสี่ยงทางเทคนิคอาจกลายเป็นความเสียหายระดับธุรกิจได้อย่างรวดเร็ว

สุดท้าย Threat Modeling ไม่ใช่งานของ Security Team เท่านั้น แต่เป็นกิจกรรมร่วมกันของ Developer, Architect, QA, DevOps, Product Owner และผู้บริหาร เพราะการยอมรับหรือจัดการความเสี่ยงเป็นทั้งการตัดสินใจทางเทคนิคและการตัดสินใจทางธุรกิจ

---

## Verification

- **Research process:** ใช้ researcher ตรวจสอบข้อมูลประกอบผ่านแหล่งอ้างอิงทางการและ NotebookLM-assisted research ก่อนปรับปรุงเนื้อหา
- **OWASP Threat Modeling:** ยืนยันกรอบคำถาม 4 ข้อและแนวคิด Threat Modeling เป็นกระบวนการต่อเนื่อง
- **Microsoft Threat Modeling Tool:** ยืนยันการใช้ STRIDE กับองค์ประกอบ DFD และแนวทางวิเคราะห์ภัยคุกคามจากการออกแบบระบบ
- **NIST SP 800-30 Rev.1:** ยืนยันชื่อเอกสาร *Guide for Conducting Risk Assessments* และเดือนเผยแพร่กันยายน 2012
- **ISO/IEC 27005:2022:** ยืนยันว่าเป็น Edition 4 และเป็นแนวทางการจัดการความเสี่ยงด้านความมั่นคงปลอดภัยสารสนเทศที่เชื่อมโยงกับ ISMS
- **FIRST CVSS v4.0:** ยืนยันช่วงคะแนน 0.0 ถึง 10.0, Metric Groups ได้แก่ Base, Threat, Environmental และ Supplemental, และระดับ None/Low/Medium/High/Critical
- **DREAD:** ตรวจสอบข้อจำกัดด้านความเป็นอัตวิสัย และนำเสนอเป็นเครื่องมือฝึกอภิปราย ไม่ใช่มาตรฐานหลักสมัยใหม่
- **PASTA:** ยืนยันว่าเป็น Process for Attack Simulation and Threat Analysis และมี 7 ขั้นตอน
- **Equifax 2017:** ยืนยันตัวเลขผู้ได้รับผลกระทบประมาณ 147 ล้านคน และข้อตกลงปี 2019 อย่างน้อย 575 ล้านดอลลาร์สหรัฐ อาจสูงถึง 700 ล้านดอลลาร์สหรัฐ จากแหล่งทางการของสหรัฐ
- **Capital One 2020:** ยืนยันค่าปรับ 80 ล้านดอลลาร์สหรัฐจากสำนักงานผู้ควบคุมเงินตราสหรัฐ และประเด็นเรื่องกระบวนการประเมินความเสี่ยงก่อนย้ายงานสำคัญขึ้นคลาวด์
- **MOVEit 2023:** ยืนยันข้อมูลจาก CISA เกี่ยวกับการโจมตีของกลุ่ม Cl0p ช่องโหว่ SQL Injection วันที่เริ่มโจมตี 27 พฤษภาคม 2023 และคำแนะนำวันที่ 7 มิถุนายน 2023
- **Status:** ตรวจสอบข้อมูลหลักแล้ว ไม่มีรายการที่ตั้งใจปล่อยไว้เป็น [UNVERIFIED]

## เอกสารอ้างอิงหลัก

1. OWASP Threat Modeling: https://owasp.org/www-community/Threat_Modeling
2. OWASP Threat Modeling Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html
3. Microsoft SDL Threat Modeling: https://www.microsoft.com/en-us/securityengineering/sdl/threatmodeling
4. Microsoft Threat Modeling Tool Threats: https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats
5. NIST SP 800-30 Rev.1, *Guide for Conducting Risk Assessments*: https://csrc.nist.gov/pubs/sp/800/30/r1/final
6. NIST SP 800-39, *Managing Information Security Risk*: https://csrc.nist.gov/publications/detail/sp/800-39/final
7. ISO/IEC 27005:2022: https://www.iso.org/standard/80585.html
8. FIRST CVSS v4.0 Specification: https://www.first.org/cvss/v4.0/specification-document
9. FIRST CVSS v4.0 Project: https://www.first.org/cvss/v4.0/
10. FTC Equifax Data Breach Settlement: https://www.ftc.gov/enforcement/refunds/equifax-data-breach-settlement
11. OCC Capital One Civil Money Penalty 2020: https://www.occ.gov/news-issuances/news-releases/2020/nr-occ-2020-101.html
12. CISA MOVEit Transfer Advisory: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a
