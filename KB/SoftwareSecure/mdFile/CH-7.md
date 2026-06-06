# CH-7: Access Control และ Authorization


---

## วัตถุประสงค์การเรียนรู้

เมื่อจบบทนี้นักศึกษาสามารถ:

1. อธิบายและเปรียบเทียบโมเดล Access Control ทั้ง 5 ประเภท (DAC, MAC, RBAC, ABAC, Rule-Based) ในแง่การบริหารจัดการ ความยืดหยุ่น ระดับความปลอดภัย และกรณีการใช้งาน
2. ออกแบบ Role Hierarchy และ Permission Matrix ตามโมเดล RBAC ของ NIST โดยใช้หลักการ Core RBAC และ Role Hierarchy พร้อมระบุข้อกำหนด Separation of Duty
3. ประยุกต์ใช้หลักการออกแบบ Authorization (Least Privilege, Separation of Duties, Default Deny, Permission Review) ในการออกแบบระบบควบคุมการเข้าถึง
4. ระบุและอธิบาย Broken Access Control แต่ละประเภท (IDOR, Missing Function Level Access Control, Path Traversal, Privilege Escalation, Mass Assignment) พร้อมแนวทางป้องกันและการเขียนโค้ดที่ปลอดภัย
5. วิเคราะห์และตรวจสอบ IDOR Vulnerability ในเว็บแอปพลิเคชัน และแก้ไขโดยใช้ Indirect Reference Map ร่วมกับ Authorization Check
6. อธิบายแนวคิด API Authorization รวมถึง OAuth 2.0 Scopes, ความแตกต่างระหว่าง API Keys และ Access Tokens, และสถาปัตยกรรม Policy-Based Access Control (OPA / Casbin)
7. ออกแบบนโยบาย (Policy) ของ Policy-Based Access Control โดยใช้ Rego Language ของ Open Policy Agent
8. วิเคราะห์กรณีศึกษา Broken Access Control ในโลกจริง (Cambridge Analytica, Capital One, GitHub) และสรุปบทเรียนด้านการออกแบบสิทธิ์
9. ตรวจสอบตนเองโดยใช้ OWASP ASVS V4 Access Control Checklist และ OWASP Top 10 2025 A01 Checklist
10. แปลงความรู้ด้าน Authorization Security เป็น Security Requirements และ Test Cases ในกระบวนการพัฒนาซอฟต์แวร์

---

## ขอบเขตและข้อกำหนดด้านจริยธรรมของบทนี้

บทนี้ครอบคลุมหลักการออกแบบ Access Control และ Authorization ที่ปลอดภัย เนื้อหามีตัวอย่างช่องโหว่ Broken Access Control เพื่อการเรียนรู้เชิงป้องกันเท่านั้น กิจกรรมปฏิบัติการทั้งหมดต้องทำในสภาพแวดล้อมที่ได้รับอนุญาต เช่น เครื่องของนักศึกษาเอง เซิร์ฟเวอร์ทดลอง หรือแอปพลิเคชันตัวอย่างที่อาจารย์จัดให้เท่านั้น

**ข้อควรจำ:** Broken Access Control เป็นอันดับ 1 ใน OWASP Top 10 2025 โดย 100% ของแอปพลิเคชันที่ทดสอบพบช่องโหว่ด้านนี้บางรูปแบบ ห้ามนำเทคนิคในบทนี้ไปใช้กับระบบของบุคคลอื่นหรือระบบที่ไม่ได้รับอนุญาตเป็นลายลักษณ์อักษรโดยเด็ดขาด

---

## แผนการเรียนรู้สำหรับ 4 ชั่วโมง

| ช่วงเวลา | หัวข้อ | เป้าหมายการเรียนรู้ | กิจกรรมในชั้นเรียน |
|----------|--------|----------------------|----------------------|
| ชั่วโมงที่ 1 | พื้นฐาน Access Control และหลักการออกแบบ | เข้าใจ DAC, MAC, RBAC, ABAC, Rule-Based และหลัก Least Privilege, Separation of Duties, Default Deny | เปรียบเทียบโมเดล Access Control และวิเคราะห์ตัวอย่าง Policy |
| ชั่วโมงที่ 2 | OWASP A01 Broken Access Control และ API Authorization | เข้าใจ IDOR, Missing Function Level, Path Traversal, Privilege Escalation, Mass Assignment และ OAuth Scopes, OPA | วิเคราะห์โค้ดที่มีช่องโหว่ IDOR และออกแบบ Authorization Policy |
| ชั่วโมงที่ 3 | Lab 7.1 และ Lab 7.2 | ฝึกวิเคราะห์และแก้ไข IDOR และออกแบบ RBAC Model สำหรับระบบ EHR | แก้ไขช่องโหว่ IDOR และออกแบบ Role Hierarchy + Permission Matrix |
| ชั่วโมงที่ 4 | Lab 7.3 และ Lab 7.4 | ฝึก Implement Policy-Based Access Control และตรวจจับ Broken Access Control | เขียน Rego Policy และทดสอบด้วย Burp Suite/ZAP |

---

## เนื้อหา

### 7.1 พื้นฐานและประเภทของ Access Control

Access Control (การควบคุมการเข้าถึง) เป็นกลไกที่กำหนดว่าใคร (Who) สามารถทำอะไร (What) กับทรัพยากรใด (Which Resource) ได้บ้างภายใต้เงื่อนไขใด (Under What Conditions) การเลือกโมเดล Access Control ที่เหมาะสมส่งผลโดยตรงต่อความปลอดภัยและประสิทธิภาพการบริหารจัดการของระบบ

#### 7.1.1 DAC (Discretionary Access Control)

DAC เป็นโมเดลที่ให้ **เจ้าของทรัพยากร (Owner)** เป็นผู้กำหนดสิทธิ์การเข้าถึงทรัพยากรของตนเอง เจ้าของสามารถให้สิทธิ์ แก้ไข หรือเพิกถอนสิทธิ์แก่ผู้ใช้อื่นได้ตามดุลยพินิจ

**ตัวอย่างที่คุ้นเคย: UNIX File Permissions**

ระบบ UNIX/Linux ใช้ DAC ในรูปแบบ permission bits 3 กลุ่ม ได้แก่ Owner, Group, Others และ 3 สิทธิ์ ได้แก่ Read (r), Write (w), Execute (x)

```bash
# ตัวอย่าง: แสดงสิทธิ์ไฟล์ใน UNIX
$ ls -l /etc/passwd
-rw-r--r--  1 root  wheel  1234 Jan 15 10:30 /etc/passwd
# เจ้าของ (root): rw- (อ่าน+เขียน)
# กลุ่ม (wheel): r-- (อ่านอย่างเดียว)
# อื่นๆ (others): r-- (อ่านอย่างเดียว)

# เปลี่ยนสิทธิ์
$ chmod 600 secret.txt      # เจ้าของอ่าน+เขียนได้เท่านั้น
$ chown alice:devteam file   # เปลี่ยนเจ้าของและกลุ่ม
```

**ข้อดีของ DAC:**
- ยืดหยุ่นสูง — เจ้าของทรัพยากรตัดสินใจเองได้
- ใช้งานง่าย — ผู้ใช้ทั่วไปเข้าใจแนวคิดเจ้าของและสิทธิ์
- ไม่ต้องมีผู้ดูแลระบบส่วนกลางตลอดเวลา

**ข้อเสียของ DAC:**
- เสี่ยงข้อมูลรั่ว — ผู้ใช้ที่ไม่ระมัดระวังอาจให้สิทธิ์กว้างเกินจำเป็น
- ควบคุมยากในองค์กรใหญ่ — ไม่มีนโยบายกลางที่บังคับใช้ทั่วทั้งระบบ
- Malware ที่รันในบริบทของผู้ใช้สามารถเข้าถึงไฟล์ที่ผู้ใช้เป็นเจ้าของได้
- ไม่สามารถป้องกันการโอนสิทธิ์ (Trojan Horse) — โปรแกรมที่ผู้ใช้รันสามารถอ่านข้อมูลและส่งออกได้

#### 7.1.2 MAC (Mandatory Access Control)

MAC เป็นโมเดลที่ **ระบบหรือนโยบายกลาง** เป็นผู้กำหนดสิทธิ์การเข้าถึง ผู้ใช้และเจ้าของทรัพยากรไม่สามารถเปลี่ยนแปลงสิทธิ์ได้ด้วยตนเอง ตรงข้ามกับ DAC โดยสิ้นเชิง

**หลักการทำงาน:**
- ทุก Entity (Subject และ Object) ถูกติด Label ความปลอดภัย (Security Label / Classification)
- ระบบเปรียบเทียบ Label ของ Subject (เช่น clearance level) กับ Label ของ Object (เช่น classification level)
- Subject สามารถอ่าน Object ได้เมื่อ clearance >= classification (ใน Bell-LaPadula Model)

**ตัวอย่างระบบที่ใช้ MAC:**

| ระบบ | รายละเอียด |
|------|-----------|
| **SELinux** (Security-Enhanced Linux) | พัฒนาโดย NSA, บังคับใช้นโยบาย (Policy) ทั่วทั้งระบบปฏิบัติการ |
| **AppArmor** | ใช้ Profile จำกัดความสามารถของแต่ละโปรแกรม |
| **Windows Mandatory Integrity Control** | ใช้ Integrity Level (Low, Medium, High, System) |

**ตัวอย่างการใช้งาน SELinux:**

```bash
# ดู SELinux context ของไฟล์
$ ls -Z /var/www/html/index.html
system_u:object_r:httpd_sys_content_t:s0 /var/www/html/index.html

# ดู SELinux mode
$ getenforce
Enforcing

# ดู SELinux boolean
$ getsebool httpd_enable_homedirs
httpd_enable_homedirs --> off
```

**ข้อดีของ MAC:**
- ปลอดภัยสูง — ผู้ใช้ไม่สามารถ bypass นโยบายกลางได้
- ป้องกันการโจมตีแบบ privilege escalation ได้ดี
- บังคับใช้นโยบายทั่วทั้งระบบอย่างสม่ำเสมอ
- ลดความเสี่ยงจาก insider threat ที่เจตนารั่วไหลข้อมูล

**ข้อเสียของ MAC:**
- ซับซ้อนในการบริหารจัดการ — ต้องมีผู้เชี่ยวชาญในการออกแบบนโยบาย
- ยืดหยุ่นต่ำ — ผู้ใช้ไม่สามารถแชร์ทรัพยากรได้สะดวก
- ค่าใช้จ่ายในการดูแลสูง
- อาจมีปัญหา compatibility กับซอฟต์แวร์บางประเภท

**กรณีการใช้งานที่เหมาะสม:** หน่วยงาน military, government intelligence, ระบบที่ต้องปฏิบัติตามมาตรฐานความปลอดภัยสูง

#### 7.1.3 RBAC (Role-Based Access Control)

RBAC เป็นโมเดลที่ **กำหนดสิทธิ์ตามบทบาท (Role)** ของผู้ใช้ในองค์กร แทนที่จะกำหนดสิทธิ์ให้กับผู้ใช้โดยตรง ผู้ใช้จะได้รับสิทธิ์ผ่านบทบาทที่ได้รับมอบหมาย

**NIST RBAC Reference Model (ANSI INCITS 359-2012):**

โมเดล RBAC ประกอบด้วย 4 ระดับ (RBAC0 - RBAC3):

| ระดับ | ชื่อ | คุณสมบัติ |
|-------|------|-----------|
| RBAC0 | Core RBAC | User, Role, Permission, Session |
| RBAC1 | Hierarchical RBAC | RBAC0 + Role Hierarchy (สืบทอดสิทธิ์) |
| RBAC2 | Constrained RBAC | RBAC0 + Separation of Duty (SSD/DSD) |
| RBAC3 | Consolidated RBAC | RBAC1 + RBAC2 รวม Hierarchy และ Constraints |

**Core RBAC Components:**

- **User** — บุคคลที่เข้าถึงระบบ (อาจแทนด้วย human user หรือ service account)
- **Role** — หน้าที่หรืองานในองค์กร เช่น "พยาบาล", "แพทย์", "ผู้ดูแลระบบ"
- **Permission** — การอนุญาตให้ดำเนินการกับ resource ใด resource หนึ่ง (operation + object)
- **Session** — ความสัมพันธ์ชั่วคราวระหว่าง user กับ subset ของ roles ที่ได้รับมอบหมาย
- **User-Role Assignment** — การมอบหมายบทบาทให้ผู้ใช้
- **Role-Permission Assignment** — การกำหนดสิทธิ์ให้บทบาท

**Role Hierarchy:**

Role Hierarchy ช่วยให้สิทธิ์ถูกสืบทอดผ่านโครงสร้างบทบาท

```text
Manager
  ├── Senior Engineer    (สืบทอด: Reviewer, Developer)
  │     ├── Reviewer     (สืบทอด: Developer)
  │     └── Developer    (สืบทอด: Tester)
  └── Tester
```

ในตัวอย่างนี้ Senior Engineer มีสิทธิ์ทุกอย่างของ Reviewer และ Developer โดยอัตโนมัติ ส่วน Manager มีสิทธิ์ทุกอย่างของทั้ง Senior Engineer และ Tester

**Separation of Duty (SoD):**

SoD ป้องกันไม่ให้บุคคลคนเดียวมีสิทธิ์ที่ขัดแย้งกัน ซึ่งอาจนำไปสู่การทุจริต

| ประเภท | คำอธิบาย | ตัวอย่าง |
|---------|----------|---------|
| **Static Separation of Duty (SSD)** | ห้ามมอบหมายบทบาทที่ขัดแย้งให้ผู้ใช้คนเดียวกัน | บุคคลคนเดียวไม่สามารถเป็นทั้ง "ผู้ขอซื้อ" และ "ผู้อนุมัติซื้อ" ได้พร้อมกัน |
| **Dynamic Separation of Duty (DSD)** | ภายใน session เดียวกัน ห้าม activate บทบาทที่ขัดแย้งพร้อมกัน | คนเดียวกันสามารถเป็นทั้ง "พนักงานขาย" และ "ผู้จัดการ" ได้ แต่ activate พร้อมกันใน session เดียวไม่ได้ |

**ตัวอย่างการออกแบบ RBAC สำหรับระบบธนาคาร:**

```python
# ตัวอย่างโครงสร้าง RBAC ใน Python
roles_permissions = {
    "teller": [
        "transaction:create",
        "account:view_own_branch",
        "customer:view_basic"
    ],
    "loan_officer": [
        "loan:create",
        "loan:approve_up_to_100k",
        "customer:view_full_profile",
        "account:view_customer_accounts"
    ],
    "branch_manager": [
        "loan:approve_up_to_1m",
        "employee:manage",
        "report:view_branch",
        "audit:initiate"
    ],
    "compliance_officer": [
        "audit:view_all",
        "transaction:investigate",
        "report:view_enterprise"
    ]
}

# SSD: teller และ compliance_officer ต้องไม่ใช่คนเดียวกัน
# DSD: loan_officer และ loan_approver เป็นบทบาทที่ activate พร้อมกันไม่ได้
```

**ข้อดีของ RBAC:**
- ลดความซับซ้อนในการจัดการสิทธิ์ — เปลี่ยน role แทนการแก้ permission ทีละคน
- สอดคล้องกับโครงสร้างองค์กร
- รองรับการตรวจสอบ (audit) — รู้ว่าบทบาทใดมีสิทธิ์อะไร
- สนับสนุนการสืบทอดสิทธิ์ผ่าน Role Hierarchy

**ข้อเสียของ RBAC:**
- Role Explosion — เมื่อองค์กรใหญ่ขึ้น จำนวน role อาจเพิ่มขึ้นมาก (role creep)
- ไม่ยืดหยุ่นพอสำหรับเงื่อนไขละเอียด — เช่น "ให้สิทธิ์เฉพาะวันจันทร์-ศุกร์"
- การปรับ role ทุกครั้งต้องแก้ code หรือ configuration

#### 7.1.4 ABAC (Attribute-Based Access Control)

ABAC ตามนิยามของ **NIST SP 800-162** คือโมเดลที่ตัดสินใจให้สิทธิ์โดยการ **ประเมินคุณลักษณะ (Attributes)** ของ Subject, Object, Environment และ Policy Rules

**องค์ประกอบของ ABAC:**

| ประเภท Attribute | ตัวอย่าง |
|------------------|---------|
| **Subject Attributes** | ตำแหน่ง, แผนก, clearance level, สัญชาติ, อายุงาน |
| **Object Attributes** | ระดับความลับ (classification), เจ้าของ, แผนกเจ้าของ, ประเภทข้อมูล |
| **Environment Attributes** | เวลา, สถานที่, อุปกรณ์, เครือข่าย, ระดับความเสี่ยงปัจจุบัน |
| **Action Attributes** | ประเภท operation (read/write/delete/export) |

**ตัวอย่าง Policy Rule ใน ABAC:**

```text
Rule: "พนักงานสามารถดูเอกสารของแผนกตนเองได้เฉพาะในเวลาทำงาน"
IF
  subject.department == object.department
  AND subject.employment_status == "active"
  AND environment.time BETWEEN "09:00" AND "17:00"
  AND environment.day_of_week IN ["Monday","Tuesday","Wednesday","Thursday","Friday"]
THEN
  PERMIT action.read
```

**ข้อดีของ ABAC:**
- ยืดหยุ่นสูง — สามารถกำหนดเงื่อนไขละเอียดได้ตามบริบท
- ไม่เกิด Role Explosion — ใช้ attribute แทนการสร้าง role ใหม่ทุกครั้ง
- รองรับการเปลี่ยนแปลงแบบ real-time — เช่น ตัดสิทธิ์ทันทีเมื่อพนักงานลาออก
- สามารถ implement DAC และ MAC ได้ภายใต้กรอบ ABAC เดียวกัน

**ข้อเสียของ ABAC:**
- ซับซ้อนในการออกแบบ — ต้องเข้าใจ business logic อย่างลึกซึ้ง
- ประสิทธิภาพ — การประเมินหลาย attribute ทุก request อาจช้า
- ต้องมี Attribute Management ที่ robust
- ทดสอบยาก — จำนวน combinations ของ attributes มีมหาศาล

**เมื่อไรควรใช้ ABAC:**
- ระบบที่มีเงื่อนไขการเข้าถึงหลากหลายและเปลี่ยนแปลงบ่อย
- ระบบที่ต้องควบคุมการเข้าถึงตามบริบท (เวลา สถานที่ อุปกรณ์)
- องค์กรขนาดใหญ่ที่มีโครงสร้างซับซ้อน
- ระบบคลาวด์ที่ต้องการ fine-grained access control

#### 7.1.5 Rule-Based Access Control

Rule-Based Access Control กำหนดการเข้าถึงโดยใช้ **กฎเงื่อนไข (Rules)** ที่ตายตัว เช่น ACLs (Access Control Lists) ในไฟร์วอลล์หรือเราเตอร์

**ความแตกต่างจาก ABAC:** Rule-Based ใช้กฎที่ตายตัวและไม่พิจารณา context attributes เปลี่ยนแปลงยาก ABAC ใช้ attributes ที่ยืดหยุ่นและ dynamic กว่า

**ตัวอย่าง Rule-Based:**

```bash
# iptables Rule (Linux Firewall)
iptables -A INPUT -p tcp --dport 22 -s 192.168.1.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j DROP

# AWS S3 Bucket Policy (Rule-Based)
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::public-bucket/*",
      "Condition": {
        "IpAddress": {
          "aws:SourceIp": "203.0.113.0/24"
        }
      }
    }
  ]
}
```

#### 7.1.6 การเปรียบเทียบ DAC/MAC/RBAC/ABAC

| มิติการเปรียบเทียบ | DAC | MAC | RBAC | ABAC |
|-------------------|-----|-----|------|------|
| **ผู้ควบคุมสิทธิ์** | เจ้าของทรัพยากร | ระบบ / นโยบายกลาง | ผู้ดูแลระบบตาม role | Policy Engine ตาม attributes |
| **ความซับซ้อนในการบริหารจัดการ** | ต่ำ | สูงมาก | ปานกลาง | สูง |
| **ความยืดหยุ่น** | สูง | ต่ำมาก | ปานกลาง | สูงมาก |
| **ระดับความปลอดภัย** | ต่ำ-ปานกลาง | สูงมาก | ปานกลาง-สูง | สูง |
| **การปรับขนาด (Scalability)** | ไม่เหมาะกับองค์กรใหญ่ | ปานกลาง | ดี | ดีมาก |
| **การรองรับเงื่อนไขบริบท** | ไม่มี | ไม่มี | ไม่มีโดยตรง | มี (Environment Attributes) |
| **การตรวจสอบ (Audit)** | ยาก | ง่าย | ง่าย | ปานกลาง |
| **กรณีใช้งานที่เหมาะสม** | เครื่องส่วนตัว, ไฟล์ส่วนตัว | Military, Government | องค์กรทั่วไป, ERP, HR | คลาวด์, ระบบที่มีเงื่อนไขซับซ้อน |
| **ตัวอย่างเทคโนโลยี** | UNIX permissions, NTFS | SELinux, AppArmor | Keycloak Roles, Spring Security | OPA, AWS IAM, Azure RBAC |

---

### 7.2 หลักการออกแบบ Authorization

#### 7.2.1 Principle of Least Privilege (สิทธิ์น้อยที่สุด)

**หลักการ:** ผู้ใช้ โปรแกรม หรือกระบวนการ ควรได้รับสิทธิ์เท่าที่จำเป็นต่อการปฏิบัติหน้าที่เท่านั้น และต้องถูกเพิกถอนเมื่อไม่จำเป็นอีกต่อไป

**แนวทางการ Implement:**

1. **เริ่มจาก Zero แล้วค่อยเพิ่ม:** ตั้งค่า Default Deny แล้วเพิ่มสิทธิ์ทีละน้อยตามความจำเป็น
2. **แยกบัญชีตามหน้าที่:** ไม่ใช้บัญชีเดียวกับทุกบทบาท
3. **จำกัดเวลาและขอบเขต:** สิทธิ์ชั่วคราว (Just-In-Time Privilege)

**ตัวอย่าง: การสร้าง Database User ด้วย Least Privilege**

```sql
-- ไม่ปลอดภัย: ให้สิทธิ์ admin ทั้งหมด
GRANT ALL PRIVILEGES ON *.* TO 'app_user'@'%';

-- ปลอดภัย: ให้สิทธิ์เฉพาะ table และ operation ที่จำเป็น
CREATE USER 'app_readonly'@'10.0.0.0/255.255.255.0' 
  IDENTIFIED BY 'strong_password';
GRANT SELECT ON orders_db.orders TO 'app_readonly'@'10.0.0.0/255.255.255.0';
GRANT SELECT, INSERT, UPDATE ON orders_db.order_items 
  TO 'app_readonly'@'10.0.0.0/255.255.255.0';
-- ไม่ให้ DELETE หรือ DROP
```

**ตัวอย่าง: Service Account ที่ปลอดภัย**

```python
# ไม่ปลอดภัย: ใช้ Admin Credentials ทุกอย่าง
aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
# คีย์นี้มีสิทธิ์ Admin — ถ้ารั่วหายนะ!

# ปลอดภัย: ใช้ IAM Role ที่มีสิทธิ์จำกัด
# Policy ที่แนบกับ EC2 Role:
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::my-app-bucket/uploads/*"
    }
  ]
}
# EC2 instance นี้ upload/download ได้เฉพาะ bucket/uploads/ เท่านั้น
```

#### 7.2.2 Principle of Separation of Duties (การแยกหน้าที่)

**หลักการ:** หน้าที่ที่สำคัญและมีความขัดแย้งทางผลประโยชน์ต้องแยกให้บุคคลหลายคนรับผิดชอบ เพื่อป้องกันการทุจริต (Fraud) โดยบุคคลเดียว

**ตัวอย่างในระบบ Payment:**

| บทบาท | หน้าที่ | ข้อห้าม |
|--------|--------|---------|
| **Requestor** | ขอจัดซื้อ/เบิกจ่าย | ไม่อนุมัติคำขอของตนเอง |
| **Approver** | อนุมัติคำขอ | ไม่ใช่คนเดียวกับ Requestor |
| **Processor** | ดำเนินการจ่ายเงิน | ไม่อนุมัติหรือขอเบิก |
| **Auditor** | ตรวจสอบธุรกรรม | ไม่มีสิทธิ์สร้าง/แก้ไข/ลบธุรกรรม |

**ตัวอย่างการ Implement ใน Code:**

```python
# Separation of Duty Check
def can_approve_payment(approver_id, payment_request):
    """ตรวจสอบว่า approver ไม่ใช่คนเดียวกับ requestor"""
    if approver_id == payment_request.requestor_id:
        raise AuthorizationError(
            "ผู้ขอและผู้อนุมัติต้องไม่ใช่บุคคลเดียวกัน (SoD violation)"
        )
    
    # ตรวจสอบว่าบุคคลนี้มีบทบาท Approver
    if not user_has_role(approver_id, "payment_approver"):
        raise AuthorizationError(
            "เฉพาะผู้ที่มีบทบาท payment_approver เท่านั้นที่อนุมัติได้"
        )
    
    # ตรวจสอบ SSD constraint
    if roles_conflict(approver_id, "payment_approver", "payment_processor"):
        raise AuthorizationError(
            "บุคคลนี้มีบทบาทที่ขัดแย้ง (SSD violation)"
        )
    
    return True
```

#### 7.2.3 Default Deny (Fail Safe Defaults)

**หลักการ:** การเข้าถึงทุกอย่างถูก **ปฏิเสธเป็นค่าเริ่มต้น** เว้นแต่จะได้รับอนุญาตอย่างชัดแจ้ง (Explicit Grant)

**แนวปฏิบัติ:**

```python
# ไม่ปลอดภัย: อนุญาตโดยปริยาย
def view_document(user, document_id):
    document = get_document(document_id)
    # ถ้าไม่มี check ใดๆ — ผู้ใช้ทุกคนเห็นเอกสารทั้งหมด!
    return document

# ปลอดภัย: Default Deny + Explicit Grant
def view_document(user, document_id):
    # ขั้นตอนที่ 1: ตรวจสอบ Authentication
    if not user.is_authenticated:
        raise AuthenticationError("โปรดล็อกอินก่อน")
    
    # ขั้นตอนที่ 2: Default Deny — เริ่มต้นด้วยการปฏิเสธ
    authorized = False
    
    # ขั้นตอนที่ 3: Explicit Grant — ตรวจสอบสิทธิ์ทีละกรณี
    if user.has_permission("document:view_all"):
        authorized = True
    elif user.has_permission("document:view_own") and \
         document.owner_id == user.id:
        authorized = True
    elif user.has_role("manager") and \
         document.department == user.department:
        authorized = True
    
    # ขั้นตอนที่ 4: ถ้าไม่ได้รับอนุญาต — ปฏิเสธ
    if not authorized:
        log_access_denied(user, document_id)
        raise AuthorizationError("คุณไม่มีสิทธิ์เข้าถึงเอกสารนี้")
    
    return document
```

**ข้อควรจำ:** ถ้าลืมเขียน authorization check — Default Deny จะปกป้องระบบ ตรงข้ามกับ Default Allow ที่จะเปิดช่องโหว่ทันที

#### 7.2.4 Permission Creep และการทบทวนสิทธิ์

**Permission Creep** คือปรากฏการณ์ที่พนักงานสะสมสิทธิ์เพิ่มขึ้นเรื่อยๆ เมื่อเปลี่ยนบทบาทหรือหน้าที่ โดยสิทธิ์เก่าไม่ถูกเพิกถอน ทำให้พนักงานมีสิทธิ์เกินความจำเป็น

**ตัวอย่างปัญหา:**

```text
Alice เริ่มงานเป็น Developer (มีสิทธิ์: read code, commit to dev branch)
Alice เลื่อนเป็น Senior Developer (เพิ่มสิทธิ์: merge to staging, access CI/CD)
Alice เลื่อนเป็น Tech Lead (เพิ่มสิทธิ์: merge to production, manage secrets)
Alice โอนย้ายเป็น Product Manager (เพิ่มสิทธิ์: view roadmap, manage backlog)
---
สิทธิ์สะสมของ Alice ณ ปัจจุบัน = ALL (Developer + Senior + Tech Lead + PM)
Alice มีสิทธิ์ merge code สู่ production แม้ไม่ใช่หน้าที่แล้ว!
```

**แนวทางจัดการ Permission Creep:**

| มาตรการ | รายละเอียด |
|---------|-----------|
| **Periodic Access Review** | ทุก 3-6 เดือน ทบทวนสิทธิ์ของพนักงานทุกคน |
| **Role-Based Cleanup** | เปลี่ยนบทบาท — เพิกถอนสิทธิ์ของบทบาทเก่าโดยอัตโนมัติ |
| **Just-In-Time Privilege** | ให้สิทธิ์ชั่วคราวเมื่อจำเป็นเท่านั้น (PIM/PAM) |
| **Separation of Duties Review** | ตรวจสอบว่าไม่มี SoD violation |
| **Access Certification** | ผู้จัดการต้อง certify สิทธิ์ของลูกน้องทุกปี |

**ตัวอย่าง Identity Governance Process:**

1. พนักงานย้ายแผนก — HR System แจ้ง IAM
2. IAM System เพิกถอนบทบาทเก่าทั้งหมดอัตโนมัติ
3. IAM System มอบหมายบทบาทใหม่ตามโครงสร้างองค์กร
4. ผู้จัดการใหม่ได้รับการแจ้งเตือนให้ certify สิทธิ์ภายใน 30 วัน
5. ถ้าไม่ certify ภายใน 30 วัน — สิทธิ์ถูกระงับอัตโนมัติ

#### 7.2.5 Authorization ที่ระดับ API Endpoint และระดับ Data

การตรวจสอบ Authorization ต้องทำ **ทุกระดับ** ไม่ใช่แค่หน้า Login

**แนวคิด: Two-Level Authorization**

```python
# Level 1: API Endpoint Authorization (ใครสามารถเรียก endpoint นี้ได้)
@app.route("/api/orders/<order_id>", methods=["GET"])
@jwt_required
@requires_permission("orders:view")  # มีสิทธิ์ดู orders หรือไม่?
def get_order(order_id):
    
    # Level 2: Data-Level Authorization (คนนี้มีสิทธิ์ดู order นี้ไหม?)
    order = Order.query.get(order_id)
    
    # ตรวจสอบ Data Ownership
    if not can_access_order(current_user.id, order):
        log_unauthorized_access(current_user.id, order_id)
        return {"error": "Forbidden"}, 403
    
    return order.to_dict()

def can_access_order(user_id, order):
    """ตรวจสอบว่าผู้ใช้มีสิทธิ์เข้าถึง order นี้หรือไม่"""
    # Case 1: เจ้าของ order
    if order.customer_id == user_id:
        return True
    
    # Case 2: พนักงานที่รับผิดชอบ
    if order.assignee_id == user_id:
        return True
    
    # Case 3: Admin/Supervisor
    if user_has_role(user_id, "order_admin"):
        return True
    
    # Case 4: ผู้จัดการแผนก
    if user_has_role(user_id, "department_manager") and \
       order.department == get_user_department(user_id):
        return True
    
    # Default: Deny
    return False
```

**ข้อควรระวัง:** Data-Level Authorization มักถูกลืมในการพัฒนา — นักพัฒนามักตรวจสอบแค่ว่า "ผู้ใช้ล็อกอินหรือไม่" และ "มีสิทธิ์เรียก endpoint หรือไม่" แต่ลืมตรวจว่า "มีสิทธิ์เข้าถึง resource นี้หรือไม่"

---

### 7.3 OWASP A01: Broken Access Control

Broken Access Control เป็นอันดับ 1 ใน OWASP Top 10 ทั้งปี 2021 และ 2025 โดย 100% ของแอปพลิเคชันที่ถูกทดสอบพบช่องโหว่ด้านนี้บางรูปแบบ มี CWE ที่เกี่ยวข้อง 40 รายการ และมีจำนวน occurrences มากที่สุด 1,839,701 ครั้งจากข้อมูลที่รวบรวม

#### 7.3.1 Insecure Direct Object Reference (IDOR)

IDOR (CWE-639) เกิดเมื่อแอปพลิเคชันเปิดเผย reference โดยตรงของ internal object (เช่น ID, คีย์, filename) และไม่ตรวจสอบว่าผู้ใช้มีสิทธิ์เข้าถึง object นั้นหรือไม่

**ตัวอย่างช่องโหว่:**

```python
# ไม่ปลอดภัย: IDOR Vulnerability
@app.route("/api/user/profile/<user_id>")
@jwt_required
def get_user_profile(user_id):
    # ปัญหา: ไม่ตรวจสอบว่า current_user มีสิทธิ์ดู profile ของ user_id นี้หรือไม่
    user = User.query.get(user_id)
    return user.to_dict()

# ผู้โจมตีเปลี่ยน user_id ใน URL:
# GET /api/user/profile/102 — ดูข้อมูล user 102 (ของตัวเอง)
# GET /api/user/profile/103 — ดูข้อมูล user 103 (ของคนอื่น!)
# GET /api/user/profile/999 — ดูข้อมูล user 999
```

**แนวทางแก้ไข 1: Authorization Check ก่อนเข้าถึง object**

```python
# ปลอดภัย: ตรวจสอบว่าผู้ใช้มีสิทธิ์เข้าถึง object
@app.route("/api/user/profile/<user_id>")
@jwt_required
def get_user_profile(user_id):
    # ตรวจสอบ Authorization
    if current_user.id != int(user_id) and \
       not current_user.has_role("admin"):
        log_unauthorized_access(current_user.id, "view_profile", user_id)
        return {"error": "Forbidden"}, 403
    
    user = User.query.get(user_id)
    return user.to_dict()
```

**แนวทางแก้ไข 2: Indirect Reference Map**

```python
# ปลอดภัย: ใช้ Indirect Reference Map
import uuid

# สร้าง mapping จาก ID จริง ไปยัง UUID ที่สุ่ม
user_reference_map = {}  # ในระบบจริงใช้ database หรือ cache

def get_user_by_ref(ref_id):
    """แปลง indirect reference เป็น user ID"""
    user_id = user_reference_map.get(ref_id)
    if not user_id:
        return None
    return User.query.get(user_id)

@app.route("/api/user/profile/<ref_id>")
@jwt_required
def get_user_profile(ref_id):
    user = get_user_by_ref(ref_id)
    if not user:
        return {"error": "Not found"}, 404
    
    # ตรวจสอบ Authorization (ยังต้องมี!)
    if current_user.id != user.id and \
       not current_user.has_role("admin"):
        return {"error": "Forbidden"}, 403
    
    return user.to_dict()
```

#### 7.3.2 Missing Function Level Access Control

ช่องโหว่นี้เกิดเมื่อแอปพลิเคชันมีฟังก์ชันที่ sensitive (เช่น admin panel, user management, system configuration) แต่ไม่ได้ตรวจสอบระดับสิทธิ์ก่อนให้เข้าถึง

**ตัวอย่างช่องโหว่:**

```python
# ไม่ปลอดภัย: Admin Function ที่ไม่มี Access Control
@app.route("/admin/delete-user/<user_id>", methods=["DELETE"])
@jwt_required
def admin_delete_user(user_id):
    # ปัญหา: ไม่มีการตรวจสอบว่า current_user เป็น admin หรือไม่
    user = User.query.get(user_id)
    db.session.delete(user)
    db.session.commit()
    return {"message": "User deleted"}

# ผู้โจมตีเรียก:
# DELETE /admin/delete-user/42
# ถ้ามี JWT token ใดๆ ก็สามารถลบผู้ใช้คนอื่นได้!
```

**แนวทางแก้ไข:**

```python
# ปลอดภัย: Role Check ทุก Function
from functools import wraps

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.has_role("admin"):
            log_unauthorized_access(current_user.id, "admin_function")
            return {"error": "Forbidden"}, 403
        return f(*args, **kwargs)
    return decorated

@app.route("/admin/delete-user/<user_id>", methods=["DELETE"])
@jwt_required
@admin_required  # <-- เพิ่ม Authorization Check
def admin_delete_user(user_id):
    user = User.query.get(user_id)
    db.session.delete(user)
    db.session.commit()
    log_admin_action(current_user.id, "delete_user", user_id)
    return {"message": "User deleted"}
```

**หลักการสำคัญ:** Function-Level Access Control ต้องตรวจสอบทุกรายการ ไม่ใช่เฉพาะที่ "มองเห็น" ใน UI ผู้โจมตีสามารถ force browse หรือ guess URL ได้เสมอ

#### 7.3.3 Path Traversal

Path Traversal (CWE-22) เกิดเมื่อแอปพลิเคชันใช้ข้อมูลผู้ใช้เพื่อสร้าง path ไปยังไฟล์โดยไม่ตรวจสอบอย่างปลอดภัย ทำให้ผู้โจมตีสามารถเข้าถึงไฟล์นอก directory ที่อนุญาต

**ตัวอย่างช่องโหว่:**

```python
# ไม่ปลอดภัย: Path Traversal
@app.route("/files/<filename>")
@jwt_required
def get_file(filename):
    # ปัญหา: ใช้ filename จากผู้ใช้โดยตรง
    file_path = os.path.join(UPLOAD_DIR, filename)
    return send_file(file_path)

# ผู้โจมตีส่ง:
# GET /files/../../../etc/passwd
# — file_path = /var/uploads/../../../etc/passwd = /etc/passwd
```

**แนวทางแก้ไข: Canonicalization + Allowlist**

```python
import os.path

# ปลอดภัย: Canonicalization + Path Validation
UPLOAD_DIR = "/var/www/app/uploads/"

@app.route("/files/<filename>")
@jwt_required
def get_file(filename):
    # ขั้นตอนที่ 1: สร้าง absolute path
    requested_path = os.path.normpath(
        os.path.join(UPLOAD_DIR, filename)
    )
    
    # ขั้นตอนที่ 2: Canonicalization
    real_path = os.path.realpath(requested_path)
    
    # ขั้นตอนที่ 3: ตรวจสอบว่า path อยู่ใน allowed directory
    if not real_path.startswith(os.path.realpath(UPLOAD_DIR)):
        log_unauthorized_access(current_user.id, "path_traversal", filename)
        return {"error": "Forbidden"}, 403
    
    # ขั้นตอนที่ 4: ตรวจสอบว่าไฟล์มีอยู่
    if not os.path.isfile(real_path):
        return {"error": "Not found"}, 404
    
    return send_file(real_path)
```

**Allowlist Approach (ปลอดภัยกว่า):**

```python
# ใช้ allowlist ของชื่อไฟล์ที่อนุญาต
ALLOWED_FILES = {
    "report-q1-2025.pdf",
    "report-q2-2025.pdf",
    "user-guide-v3.pdf"
}

@app.route("/files/<filename>")
@jwt_required
def get_file(filename):
    if filename not in ALLOWED_FILES:
        return {"error": "File not found"}, 404
    return send_file(os.path.join(UPLOAD_DIR, filename))
```

#### 7.3.4 Privilege Escalation

Privilege Escalation คือการที่ผู้ใช้ได้รับสิทธิ์ที่สูงกว่าหรือแตกต่างจากที่ควรจะเป็น มี 2 ประเภท:

| ประเภท | คำอธิบาย | ตัวอย่าง |
|--------|----------|---------|
| **Horizontal Privilege Escalation** | เข้าถึง resource ของผู้ใช้ระดับเดียวกันแต่ต่างคน | ผู้ใช้ A เห็นข้อมูลบัตรเครดิตของผู้ใช้ B |
| **Vertical Privilege Escalation** | เข้าถึงฟังก์ชันหรือข้อมูลที่ต้องใช้สิทธิ์สูงกว่า | ผู้ใช้ทั่วไปเข้าถึง Admin Panel |

**ตัวอย่าง Horizontal Privilege Escalation:**

```python
# ไม่ปลอดภัย: Horizontal PE
@app.route("/api/orders/<order_id>")
@jwt_required
def get_order(order_id):
    # ผู้ใช้คนใดก็ได้ที่ล็อกอินสามารถดู order ใดก็ได้
    order = Order.query.get(order_id)
    return order.to_dict()

# ผู้ใช้ A ส่ง: GET /api/orders/ORDER-1001 — เห็น order ของผู้ใช้ B
```

**ตัวอย่าง Vertical Privilege Escalation:**

```javascript
// ไม่ปลอดภัย: แสดง Admin Button เฉพาะเมื่อ user.role == "admin"
// แต่ backend ไม่ตรวจสอบ!
if (user.role === "admin") {
    document.getElementById('adminPanel').style.display = 'block';
}

// ผู้โจมตีส่ง request โดยตรง:
// POST /api/admin/deleteUser
// Backend ไม่ได้ตรวจสอบ role — คำสั่งสำเร็จ!
```

**แนวทางป้องกัน:**

```python
# 1. ตรวจสอบ Data Ownership (ป้องกัน Horizontal PE)
def get_order(order_id):
    order = Order.query.get(order_id)
    
    # ตรวจสอบ: ผู้ใช้ต้องเป็นเจ้าของ order หรือมี role เฉพาะ
    if order.user_id != current_user.id and \
       not current_user.has_permission("orders:view_all"):
        return {"error": "Forbidden"}, 403
    
    return order.to_dict()

# 2. ตรวจสอบ Role/Permission ทุกครั้ง (ป้องกัน Vertical PE)
def delete_user(user_id):
    if not current_user.has_role("admin"):
        return {"error": "Forbidden"}, 403
    
    # Admin function logic here
    pass
```

#### 7.3.5 Mass Assignment / Object Injection

Mass Assignment (หรือที่เรียกว่า Object Injection, Autobinding) เกิดเมื่อ framework อัตโนมัติ map parameters จาก request ไปยัง object fields โดยไม่จำกัดเฉพาะ fields ที่ควรจะแก้ไขได้

**แนวทางแก้ไข: DTO Pattern (Data Transfer Object)**

```python
from pydantic import BaseModel

class UserUpdateDTO(BaseModel):
    """DTO: กำหนดเฉพาะ fields ที่ผู้ใช้แก้ไขได้"""
    display_name: str
    email: str
    phone_number: str | None = None
    # ไม่มี field: role, is_admin, account_balance

@app.route("/api/users/<user_id>", methods=["PATCH"])
@jwt_required
def update_user(user_id):
    # ตรวจสอบสิทธิ์
    if current_user.id != int(user_id):
        return {"error": "Forbidden"}, 403
    
    # รับเฉพาะ fields ที่ DTO กำหนด
    data = UserUpdateDTO(**request.json)
    
    # อัปเดตเฉพาะ fields ที่ได้รับอนุญาต
    user = User.query.get(user_id)
    user.display_name = data.display_name
    user.email = data.email
    user.phone_number = data.phone_number
    db.session.commit()
    
    return user.to_dict()
```

---

### 7.4 API และ Microservices Authorization

#### 7.4.1 OAuth 2.0 Scopes

ใน OAuth 2.0, **Scope** เป็นกลไกที่ใช้จำกัดขอบเขตการทำงานของ Access Token แทนการให้สิทธิ์แบบ all-or-nothing

**ตัวอย่าง Scopes:**

| Scope | ความหมาย | การใช้งาน |
|-------|----------|---------|
| `read:users` | อ่านข้อมูลผู้ใช้ | GET /api/users |
| `write:users` | สร้าง/แก้ไขข้อมูลผู้ใช้ | POST/PUT /api/users |
| `delete:users` | ลบผู้ใช้ | DELETE /api/users |
| `read:orders` | อ่านข้อมูลคำสั่งซื้อ | GET /api/orders |
| `write:orders` | สร้าง/แก้ไขคำสั่งซื้อ | POST/PUT /api/orders |
| `email` | อ่านอีเมลผู้ใช้ | UserInfo Endpoint |

**การ Validate Scope ที่ Resource Server:**

```python
from functools import wraps

def requires_scope(required_scope):
    """Decorator: ตรวจสอบ scope ใน Access Token"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = get_jwt_token()
            
            # ตรวจสอบ scope
            token_scopes = token.get("scope", "").split()
            if required_scope not in token_scopes:
                log_insufficient_scope(
                    token.get("sub"), 
                    required_scope
                )
                return {
                    "error": "insufficient_scope",
                    "message": f"ต้องการ scope: {required_scope}"
                }, 403
            
            return f(*args, **kwargs)
        return decorated
    return decorator

# การใช้งาน
@app.route("/api/users/<user_id>")
@jwt_required
@requires_scope("read:users")
def get_user(user_id):
    user = User.query.get(user_id)
    return user.to_dict()

@app.route("/api/users/<user_id>", methods=["DELETE"])
@jwt_required
@requires_scope("delete:users")
def delete_user(user_id):
    user = User.query.get(user_id)
    db.session.delete(user)
    db.session.commit()
    return {"message": "Deleted"}
```

#### 7.4.2 API Keys vs Access Tokens

| ประเด็น | API Keys | Access Tokens |
|---------|----------|---------------|
| **วัตถุประสงค์หลัก** | ระบุ client (identification) | แทน authorization grant |
| **รูปแบบ** | String คงที่ อายุยาว | มักเป็น JWT มีอายุสั้น |
| **อายุ** | ไม่หมดอายุ (หรือนานเป็นปี) | สั้น (5-60 นาที) |
| **Revocation** | ยาก — ต้อง regenerate | ง่าย — short expiry + refresh token |
| **Scope Limitation** | จำกัดยาก มัก all-or-nothing | รองรับ fine-grained scopes |
| **Who** | ระบุ client/application | ระบุ user + authorization |
| **ความเสี่ยง** | ถ้ารั่ว — ใช้ได้นาน | ถ้ารั่ว — หมดอายุเร็ว |

**API Keys เหมาะกับ:**
- Service-to-service communication ที่ไม่เกี่ยวข้องกับ user context
- Public API สำหรับ third-party developers (เช่น Stripe, Twilio)
- Rate limiting และ usage tracking

**Access Tokens เหมาะกับ:**
- การดำเนินการในนามของผู้ใช้ (delegated authorization)
- ระบบที่ต้องการ fine-grained scope control
- ระบบที่ต้องการ short-lived credentials

**ข้อควรระวัง:**

```python
# ไม่ปลอดภัย: ใช้ API key แทนการตรวจสอบสิทธิ์ผู้ใช้
@app.route("/api/orders")
def get_orders():
    api_key = request.headers.get("X-API-Key")
    client = validate_api_key(api_key)
    if not client:
        return {"error": "Invalid API Key"}, 401
    
    # ปัญหา: API key ใช้ระบุ client เท่านั้น
    # แต่ไม่ได้บอกว่าเป็น order ของใคร!
    orders = Order.query.all()  # สั่ง order ทั้งหมด!
    return orders

# ปลอดภัย: Access Token + Scope Check
@app.route("/api/orders")
@jwt_required
@requires_scope("read:orders")
def get_orders():
    # รู้ว่าเป็นคำขอของผู้ใช้คนใด (จาก JWT sub claim)
    user_id = get_jwt_identity()
    orders = Order.query.filter_by(customer_id=user_id).all()
    return [o.to_dict() for o in orders]
```

#### 7.4.3 Policy-Based Access Control (OPA — Open Policy Agent)

OPA (Open Policy Agent) เป็น Open Source Policy Engine ที่แยก authorization logic ออกจาก application code ใช้ภาษา **Rego** ในการเขียน policy

**แนวคิด:**
- Application ส่ง request data (input) ไปยัง OPA
- OPA ประเมิน policy และตอบว่า allow หรือ deny
- Application บังคับตามคำตอบของ OPA

**ตัวอย่าง Rego Policy:**

```rego
package app.authz

# ค่าเริ่มต้น: ปฏิเสธทุกอย่าง
default allow = false

# อนุญาตให้ admin ทำอะไรก็ได้
allow {
    input.user.roles[_] == "admin"
}

# อนุญาตให้เจ้าของเอกสารดูเอกสารของตนเอง
allow {
    input.action == "read"
    input.resource.type == "document"
    input.resource.owner == input.user.id
}

# อนุญาตให้พนักงานแผนกเดียวกันดูเอกสารของกันและกัน
allow {
    input.action == "read"
    input.resource.type == "document"
    input.resource.department == input.user.department
    input.user.employment_status == "active"
}

# อนุญาตให้ผู้จัดการดูเอกสารทุกฉบับในแผนกที่ดูแล
allow {
    input.action == "read"
    input.resource.type == "document"
    input.resource.department == input.user.managed_departments[_]
    input.user.roles[_] == "manager"
}
```

**การ Integrate OPA ใน Python:**

```python
import requests
import json

OPA_URL = "http://localhost:8181/v1/data/app/authz/allow"

def check_authorization(user, action, resource):
    """ส่ง request ไปยัง OPA เพื่อตรวจสอบ authorization"""
    input_data = {
        "input": {
            "user": {
                "id": user.id,
                "roles": user.roles,
                "department": user.department,
                "employment_status": user.employment_status,
                "managed_departments": user.managed_departments
            },
            "action": action,
            "resource": {
                "type": resource.type,
                "id": resource.id,
                "owner": resource.owner_id,
                "department": resource.department
            }
        }
    }
    
    response = requests.post(OPA_URL, json=input_data)
    result = response.json()
    
    return result.get("result", False)

# การใช้งาน
@app.route("/api/documents/<doc_id>")
@jwt_required
def get_document(doc_id):
    doc = Document.query.get(doc_id)
    
    # ถาม OPA
    if not check_authorization(current_user, "read", doc):
        return {"error": "Forbidden"}, 403
    
    return doc.to_dict()
```

**ข้อดีของ OPA:**
- แยก Policy ออกจาก Code — เปลี่ยน policy โดยไม่ต้อง deploy application ใหม่
- Policy ตรวจสอบได้ (auditable) — Rego policy เป็น declarative
- ใช้ร่วมกันหลาย service — centralized policy engine
- รองรับ context-aware decisions

#### 7.4.4 Centralized Authorization Service

ในสถาปัตยกรรม Microservices, การมี Authorization กระจายอยู่ทุก service ทำให้ยากต่อการบริหารและตรวจสอบ แนวทางที่ดีคือการมี **Centralized Authorization Service** ตามโมเดลของ NIST และ XACML:

| Component | ชื่อเต็ม | หน้าที่ |
|-----------|---------|--------|
| **PEP** | Policy Enforcement Point | จุดที่ request เข้ามา — ส่ง request ไปยัง PDP และบังคับผล |
| **PDP** | Policy Decision Point | จุดตัดสินใจ — ประเมิน policy และตอบ allow/deny |
| **PAP** | Policy Administration Point | จุดจัดการ policy — สร้าง แก้ไข ลบ policy |
| **PIP** | Policy Information Point | จุดดึง attribute — ดึงข้อมูลจาก external sources |
| **PRP** | Policy Retrieval Point | จัดเก็บและ retrieve policies |

**สถาปัตยกรรม:**

```text
Client Request
     │
     ▼
┌─────────────────┐
│  PEP (Gateway)  │  ← Policy Enforcement Point: รับ request และบังคับใช้ policy
└────────┬────────┘
         │ ส่ง request attributes
         ▼
┌─────────────────┐     ┌─────────────────┐
│  PDP (Policy    │────→│  PAP (Policy    │
│   Decision)     │     │   Admin)        │
└────────┬────────┘     └─────────────────┘
         │ ถาม attribute                     ┌─────────────────┐
         ▼                                   │  PIP (Info)     │
┌─────────────────┐                           │  - LDAP/AD      │
│  Response       │                           │  - Database     │
│  Allow / Deny   │                           │  - APIs         │
└─────────────────┘                           └─────────────────┘
```

**ตัวอย่าง PEP/PDP ใน Python Microservice:**

```python
# PEP — Policy Enforcement Point (ใน API Gateway)
class AuthorizationMiddleware:
    def __init__(self, pdp_url="http://authz-service:8181"):
        self.pdp_url = pdp_url
    
    def authorize(self, request):
        """PEP: ส่ง request ไปยัง PDP เพื่อตัดสิน"""
        # สร้าง decision request
        decision_request = {
            "subject": {
                "id": request.user_id,
                "roles": request.user_roles
            },
            "resource": {
                "type": request.resource_type,
                "id": request.resource_id
            },
            "action": request.method,
            "environment": {
                "ip": request.remote_addr,
                "time": datetime.utcnow().isoformat()
            }
        }
        
        # ส่งไปยัง PDP
        response = requests.post(
            f"{self.pdp_url}/v1/data/authz/allow",
            json={"input": decision_request}
        )
        
        result = response.json()
        
        # PEP: บังคับตามการตัดสินใจของ PDP
        if not result.get("result", False):
            raise AuthorizationError("Forbidden")
        
        return True
```

#### 7.4.5 Gateway Level Authorization

API Gateway เป็นจุดที่เหมาะสมที่สุดในการตรวจสอบ Authorization ระดับต้น (coarse-grained) ก่อนที่ request จะถึง backend service

**ตัวอย่าง: Kong API Gateway Authorization Plugin:**

```yaml
# Kong Gateway Configuration
plugins:
  - name: oauth2
    config:
      scopes:
        - read:users
        - write:users
        - delete:users
      mandatory_scope: true
      token_expiration: 3600
      provision_key: "your_provision_key"
      enable_authorization_code: true
      enable_client_credentials: true

  - name: rate-limiting
    config:
      minute: 100
      hour: 1000
      policy: local
```

**ข้อควรระวัง:** Gateway-Level Authorization ควรทำ coarse-grained check (เช่น scope, role) เท่านั้น Fine-grained authorization (เช่น data ownership) ต้องทำที่ service level ด้วยเสมอ

---

### 7.5 กรณีศึกษา (Case Studies)

#### 7.5.1 Facebook / Cambridge Analytica (2018)

**รายละเอียดเหตุการณ์:**
- Cambridge Analytica เป็นบริษัทที่ปรึกษาทางการเมืองของสหราชอาณาจักร
- ได้รับข้อมูลของ Facebook users ผ่าน app ที่ชื่อ "thisisyourdigitallife" (แบบทดสอบบุคลิกภาพ)
- ข้อมูลที่ถูกเก็บ: Facebook User ID, เพศ, วันเกิด, ที่ตั้ง, friends list, likes
- **จำนวนผู้ได้รับผลกระทบ:** สูงถึง 87 ล้าน users
- FTC ปรับ Facebook เป็นจำนวน **5,000 ล้านดอลลาร์สหรัฐ** ในเดือนกรกฎาคม 2019

**สาเหตุด้าน Broken Access Control:**
1. **OAuth Scope Misconfiguration:** Facebook Graph API v1 อนุญาตให้ developer app เก็บข้อมูลของ friends ของผู้ใช้ที่ติดตั้ง app ได้ โดยไม่ต้องขออนุญาตจาก friends เหล่านั้น
2. **Missing Data-Level Access Control:** เมื่อ Facebook เปลี่ยนเป็น Graph API v2 ในเดือนเมษายน 2014 ที่ปิดช่องนี้ แต่ app เดิมมีเวลา 1 ปี (ถึงเมษายน 2015) ก่อนที่ข้อจำกัดจะมีผล
3. **Insufficient Enforcement:** Facebook ไม่ได้บังคับใช้นโยบายการตรวจสอบ app developers อย่างสม่ำเสมอ

**บทเรียน:**
- OAuth scopes ต้องถูกออกแบบอย่างรัดกุม — ไม่อนุญาตให้ app เข้าถึงข้อมูลของ third-party โดยไม่ได้รับ consent ที่ชัดเจน
- API version upgrade ต้องพิจารณาผลกระทบด้าน access control
- การตรวจสอบและบังคับใช้นโยบาย access control ต้องทำอย่างต่อเนื่อง

#### 7.5.2 Capital One Breach (2019)

**รายละเอียดเหตุการณ์:**
- เหตุการณ์เกิดขึ้นระหว่างเดือนมีนาคมถึงกรกฎาคม 2019 (ตรวจพบในเดือนกรกฎาคม 2019)
- ผู้โจมตีคือ Paige Thompson (AKA "Erratic") อดีตพนักงาน AWS
- **จำนวนผู้ได้รับผลกระทบ:** ประมาณ 100 ล้าน customers
- ข้อมูลที่ถูกขโมย: ชื่อ, ที่อยู่, รหัสไปรษณีย์, เบอร์โทร, อีเมล, วันเกิด, รายงานเครดิต
- Capital One ถูกปรับ 80 ล้านดอลลาร์สหรัฐจาก federal bank regulators

**สาเหตุด้าน Broken Access Control:**
1. **SSRF Vulnerability (CWE-918):** ผู้โจมตีใช้ SSRF ผ่าน Web Application Firewall (ModSecurity) ที่มีช่องโหว่ เพื่อเข้าถึง AWS EC2 Metadata Service ที่ IP `169.254.169.254`
2. **Over-Provisioned IAM Role:** IAM Role ที่ใช้กับ WAF instance ("WAF-Role") มีสิทธิ์เกินความจำเป็น — สามารถ list S3 buckets และอ่านข้อมูลจาก S3 ได้
3. **Missing Condition in IAM Policy:** IAM role ไม่มี Condition ที่จำกัดการใช้ credentials จาก network ของ Capital One เท่านั้น ทำให้ attacker ใช้ credentials จากนอกเครือข่ายได้

**เส้นทางการโจมตี:**

```text
1. SSRF — เข้าถึง Metadata Service (http://169.254.169.254)
2. ขโมย IAM Credentials ของ WAF-Role
3. ใช้ AWS CLI: aws s3 ls (list 700+ S3 buckets)
4. aws s3 cp s3://capitalone-bucket (ขโมยข้อมูล 30GB)
5. อัปโหลดข้อมูลบางส่วนขึ้น GitHub
```

**บทเรียน:**
- Least Privilege สำหรับ IAM Roles สำคัญที่สุด — WAF ไม่จำเป็นต้องมีสิทธิ์อ่าน S3
- ใช้ Condition key ใน IAM Policy เพื่อจำกัด source IP หรือ VPC endpoint
- IMDSv2 (session-oriented) ปลอดภัยกว่า IMDSv1
- CloudTrail monitoring ต้องมีการแจ้งเตือนเมื่อ credentials ถูกใช้จากนอกเครือข่าย

#### 7.5.3 GitHub OAuth Token Theft (2022)

**รายละเอียดเหตุการณ์:**
- ตรวจพบเมื่อวันที่ 12 เมษายน 2022 โดย GitHub Security
- ผู้โจมตีขโมย OAuth user tokens ที่ออกให้ Heroku และ Travis CI
- เป็นการโจมตีแบบเจาะจง (targeted attack) ต่อหลายองค์กร รวมถึง npm
- ผู้โจมตี clone private repositories และขโมย secrets (รวมถึง AWS access keys)

**สาเหตุด้าน Broken Access Control:**
1. **OAuth Token Theft:** ผู้โจมตีเจาะ Heroku database และขโมย OAuth tokens ที่ Heroku เก็บไว้
2. **OAuth Scope ที่กว้างเกินไป:** OAuth tokens ที่ Heroku และ Travis CI ถือครองมี scope ที่ให้สิทธิ์เข้าถึง private repositories
3. **Token Reuse:** OAuth tokens ที่ถูกขโมยไปใช้ได้จนกว่าจะถูก revoke

**เส้นทางการโจมตี:**

```text
1. Heroku database ถูกเจาะ — OAuth tokens ถูกขโมย
2. ใช้ tokens เพื่อ authenticate ผ่าน GitHub API
3. List organizations — เลือกเป้าหมาย
4. List private repositories — Clone repositories
5. ขุด secrets จากโค้ดที่ cloned — Pivot ไปยังระบบอื่น (รวมถึง npm)
```

**บทเรียน:**
- OAuth tokens ต้องมี scope ที่แคบที่สุดเท่าที่จำเป็น (principle of least privilege)
- ต้องเข้ารหัส OAuth tokens ที่เก็บใน database
- ใช้ short-lived tokens + refresh token rotation
- GitHub App (installation token) ปลอดภัยกว่า OAuth App (user token) เนื่องจาก scope จำกัดกว่า

#### 7.5.4 Parler Data Scraping (2021)

**รายละเอียดเหตุการณ์:**
- หลังการจลาจลที่ Capitol Hill ในสหรัฐ เมื่อวันที่ 6 มกราคม 2021
- นักวิจัย scraping ข้อมูลจาก Parler social network ผ่าน API ที่มี IDOR
- แม้ content จะเป็น public แต่ผู้ใช้ตั้งใจให้เป็น private — API ไม่มี authorization check
- ข้อมูลกว่า 99 TB ถูกดึงออกมา รวมถึงวิดีโอและ metadata ที่ผู้ใช้ลบไปแล้ว

**บทเรียน:** API endpoint ที่เปิดเผยข้อมูลต้องมี data-level access control แม้ users จะยินยอมให้ app เข้าถึงก็ตาม

---

### 7.6 สรุปและแนวทางปฏิบัติ

#### 7.6.1 OWASP ASVS V4 — V4 Access Control

**ASVS Version 4.0.3 — V4: Access Control Verification Requirements:**

**V4.1 General Access Control Design:**

| ข้อ | รายการ | L1 | L2 | L3 | CWE |
|-----|--------|:--:|:--:|:--:|:---:|
| 4.1.1 | บังคับ access control rules ที่ trusted service layer (server-side) — อย่าเชื่อ client-side control | ✓ | ✓ | ✓ | 602 |
| 4.1.2 | ตรวจสอบว่า user และ data attributes ที่ใช้ใน access control ไม่ถูกปลอมแปลงโดยผู้ใช้ | ✓ | ✓ | ✓ | 639 |
| 4.1.3 | ใช้ Principle of Least Privilege — ผู้ใช้เข้าถึงได้เฉพาะ functions/data ที่ได้รับอนุญาต | ✓ | ✓ | ✓ | 285 |
| 4.1.5 | Access controls fail securely — เมื่อเกิด exception ต้อง deny access | ✓ | ✓ | ✓ | 285 |

**V4.2 Operation Level Access Control:**

| ข้อ | รายการ | L1 | L2 | L3 | CWE |
|-----|--------|:--:|:--:|:--:|:---:|
| 4.2.1 | ป้องกัน IDOR ทั้ง CRUD operations | ✓ | ✓ | ✓ | 639 |
| 4.2.2 | บังคับ anti-CSRF สำหรับ authenticated functionality | ✓ | ✓ | ✓ | 352 |

**V4.3 Other Access Control Considerations:**

| ข้อ | รายการ | L1 | L2 | L3 | CWE |
|-----|--------|:--:|:--:|:--:|:---:|
| 4.3.1 | Admin interfaces ต้องมี MFA | ✓ | ✓ | ✓ | 419 |
| 4.3.2 | ปิด directory browsing และไม่เปิดเผย metadata (.git, .DS_Store, .svn) | ✓ | ✓ | ✓ | 548 |
| 4.3.3 | มี additional authorization หรือ step-up auth สำหรับ high-value applications | | ✓ | ✓ | 732 |

#### 7.6.2 OWASP Top 10 2025 — A01 Broken Access Control Checklist

**รายการตรวจสอบสำหรับ A01:**

- [ ] ใช้ Principle of Least Privilege — ทุกคนได้สิทธิ์เท่าที่จำเป็นเท่านั้น
- [ ] ใช้ Default Deny — ปฏิเสธทุกอย่างยกเว้นที่ได้รับอนุญาตอย่างชัดแจ้ง
- [ ] สร้าง access control mechanism แบบ centralized และ reuse ข้าม application
- [ ] ทุก API endpoint (GET, POST, PUT, DELETE) มี authorization check
- [ ] Data-level access control — ตรวจสอบ record ownership และ scope
- [ ] Indirect reference map — ไม่ใช้ ID จริง (auto-increment) ใน URL
- [ ] ป้องกัน Mass Assignment — ใช้ DTO pattern หรือ allowlist binding
- [ ] ป้องกัน Path Traversal — ใช้ canonicalization + allowlist
- [ ] Log access control failures และแจ้ง admin เมื่อมี repeated failures
- [ ] Rate limiting สำหรับ API endpoints
- [ ] ปิด directory listing และลบ metadata files ออกจาก web root
- [ ] ใช้ short-lived JWT และ refresh token rotation
- [ ] CORS ถูกต้อง — ไม่เปิดกว้างเกินจำเป็น
- [ ] SSRF protection — ตรวจสอบ URL จากผู้ใช้ จำกัด internal IP ranges

#### 7.6.3 การแปลงความรู้เป็น Security Requirements และ Test Cases

**ตัวอย่าง Security Requirements สำหรับ Authorization:**

| Requirement ID | Security Requirement | ช่องโหว่ที่เกี่ยวข้อง | Acceptance Criteria |
|----------------|----------------------|------------------------|---------------------|
| SR-AC-001 | ทุก API endpoint ต้องมี authorization check ที่ server-side ก่อนเข้าถึง resource | IDOR, Missing Function Level | request ที่ไม่มี token หรือมี token ไม่มีสิทธิ์ถูกปฏิเสธ 401/403 |
| SR-AC-002 | ใช้ Indirect Reference Map (UUID) แทน auto-increment ID ใน URL | IDOR | URL ใช้ UUID ไม่ใช่ ID ที่เดาหรือคาดเดาได้ |
| SR-AC-003 | ใช้ DTO pattern — รับเฉพาะ fields ที่ผู้ใช้แก้ไขได้เท่านั้น | Mass Assignment | field ที่ sensitive (role, is_admin) ไม่ถูก bind จาก request |
| SR-AC-004 | ใช้ Default Deny — access control ต้อง fail อย่างปลอดภัยเมื่อเกิด exception | Missing Function Level | endpoint ที่ไม่มี explicit rule ต้อง deny |
| SR-AC-005 | แยกหน้าที่ตาม Separation of Duties — บุคคลเดียวมีสิทธิ์ขัดแย้งกันไม่ได้ | Fraud, Insider Threat | ระบบตรวจสอบ SSD/DSD constraints ก่อน assign role |
| SR-AC-006 | ทุก admin interface ต้องมี MFA | Vertical Privilege Escalation | admin login ที่ไม่มี MFA ถูกปฏิเสธ |

**ตัวอย่าง Security Test Cases:**

| Test ID | Test Case | Expected Result | วิธีทดสอบ |
|---------|-----------|-----------------|-----------|
| ST-AC-001 | เปลี่ยน user_id ใน URL เป็นของคนอื่นโดยไม่ได้รับอนุญาต | 403 Forbidden | Manual test / Automation |
| ST-AC-002 | เรียก admin endpoint ด้วย user token ที่ไม่มี role admin | 403 Forbidden | API test |
| ST-AC-003 | ส่ง field role ใน request body ตอน update profile | ไม่ถูกอัปเดต (role คงเดิม) | Integration test |
| ST-AC-004 | ลอง path traversal ใน filename parameter | 403 Forbidden หรือ 404 | Security test |
| ST-AC-005 | ตรวจสอบว่า user ที่เปลี่ยน role เก่า ถูกลบ role เก่า (permission creep) | role เก่าถูกเพิกถอน | Integration test |
| ST-AC-006 | ส่ง request ไปยัง endpoint ที่ไม่มี explicit access control | 403 Forbidden (default deny) | API test |
| ST-AC-007 | ตรวจสอบว่าผู้ใช้ที่ถูกลบ session หมดอายุ (logout) แล้วยังใช้ token เดิมได้ | 401 Unauthorized | Security test |

#### 7.6.4 Pull Request Checklist สำหรับ Access Control

ใช้ checklist นี้ในการ review pull request ที่เกี่ยวข้องกับการเข้าถึงข้อมูลหรือฟังก์ชัน:

- [ ] มี authorization check ที่ server-side ทุก endpoint หรือไม่ (อย่าเชื่อ client-side control)
- [ ] ใช้ Default Deny หรือไม่ (ไม่ใช่ Default Allow)
- [ ] มี data-level access control หรือไม่ (ไม่ใช่แค่ endpoint check)
- [ ] ใช้ Indirect Reference Map หรือ UUID แทน auto-increment ID หรือไม่
- [ ] มีการป้องกัน Mass Assignment — ใช้ DTO หรือ allowlist binding หรือไม่
- [ ] มีการป้องกัน Path Traversal — ใช้ canonicalization / allowlist หรือไม่
- [ ] มี Rate Limiting สำหรับ API endpoints หรือไม่
- [ ] มีการ Log access control failures หรือไม่
- [ ] CORS configuration ถูกต้องหรือไม่
- [ ] JWT validation ตรวจสอบ exp, iss, aud claims หรือไม่
- [ ] Role/Permission checks ถูก implement เป็น centralized mechanism หรือไม่
- [ ] มี test cases ที่ครอบคลุม authorization scenarios หรือไม่
- [ ] มี Separation of Duties review หรือไม่

---

## Keywords

Authorization, Access Control, DAC, MAC, RBAC, ABAC, Rule-Based Access Control, Least Privilege, Separation of Duties, Default Deny, Fail Safe Defaults, Permission Creep, Identity Governance, IDOR, Insecure Direct Object Reference, Missing Function Level Access Control, Path Traversal, CWE-22, CWE-639, Privilege Escalation, Horizontal Privilege Escalation, Vertical Privilege Escalation, Mass Assignment, Object Injection, DTO Pattern, OAuth 2.0 Scopes, API Keys, Access Tokens, Open Policy Agent, OPA, Rego, Policy-Based Access Control, PDP, PEP, PAP, PIP, Centralized Authorization Service, API Gateway Authorization, OWASP ASVS V4, OWASP Top 10 A01, Broken Access Control, Cambridge Analytica, Capital One Breach, GitHub OAuth Token Theft, Parler Data Scraping, RBAC0, RBAC1, RBAC2, RBAC3, Role Hierarchy, Static Separation of Duty, Dynamic Separation of Duty, Permission Matrix, NIST SP 800-162, NIST RBAC Model, CWE-285, CWE-352, CWE-918, SSRF, Indirect Reference Map, Canonicalization, Allowlist

---

## กิจกรรมปฏิบัติการ

> กิจกรรมทั้งหมดต้องทำในเครื่องของนักศึกษาเองหรือในสภาพแวดล้อมที่ได้รับอนุญาตเท่านั้น ห้ามทดสอบกับระบบจริงของบุคคลอื่นโดยไม่ได้รับอนุญาต

### Lab 7.1: IDOR Vulnerability — วิเคราะห์และแก้ไขใน Web Application

**วัตถุประสงค์:** เข้าใจและสามารถระบุ IDOR Vulnerability ใน Web Application และแก้ไขด้วย Authorization Check + Indirect Reference Map

**เวลาที่ใช้:** 45-60 นาที

**เครื่องมือ:** Python + Flask, Postman หรือ curl, Web Browser

**ขั้นตอน:**

1. สร้าง Flask app ที่มีช่องโหว่ IDOR:
   ```python
   from flask import Flask, jsonify
   
   app = Flask(__name__)
   
   users = {
       1: {"id": 1, "username": "alice", "email": "alice@example.com", "role": "user"},
       2: {"id": 2, "username": "bob", "email": "bob@example.com", "role": "user"},
       3: {"id": 3, "username": "admin", "email": "admin@example.com", "role": "admin"}
   }
   
   @app.route("/api/users/<int:user_id>")
   def get_user(user_id):
       # ช่องโหว่: ไม่มีการตรวจสอบสิทธิ์
       user = users.get(user_id)
       if not user:
           return jsonify({"error": "Not found"}), 404
       return jsonify(user)
   ```

2. ทดสอบ IDOR ด้วย curl:
   ```bash
   curl http://localhost:5000/api/users/1
   curl http://localhost:5000/api/users/2
   curl http://localhost:5000/api/users/3
   ```

3. แก้ไขช่องโหว่ด้วย Authorization Check + Indirect Reference Map
4. ทดสอบอีกครั้ง — เปลี่ยน ref_id เป็นของคนอื่นต้องถูกปฏิเสธ

**สิ่งที่ต้องส่ง:**
1. โค้ดที่มีช่องโหว่และโค้ดที่แก้ไขแล้ว
2. ภาพหรือ log การทดสอบที่แสดง IDOR (ก่อนแก้) และการถูกปฏิเสธ (หลังแก้)
3. คำอธิบายว่าเหตุใด Indirect Reference Map + Authorization Check จึงปลอดภัยกว่าใช้ ID โดยตรง

---

### Lab 7.2: RBAC Model Design — Role Hierarchy และ Permission Matrix สำหรับระบบ EHR

**วัตถุประสงค์:** ออกแบบ Role-Based Access Control สำหรับระบบ Electronic Health Record (EHR) ของโรงพยาบาล โดยใช้ Role Hierarchy, Permission Matrix และ Separation of Duties

**เวลาที่ใช้:** 45-60 นาที

**เครื่องมือ:** เอกสารหรือตาราง, draw.io (optional), Python (optional)

**ขั้นตอน:**

1. กำหนดบทบาท (Roles) ในระบบ EHR: Doctor, Nurse, Pharmacist, Lab Technician, Medical Records Clerk, Billing Staff, Hospital Administrator, Compliance Officer
2. กำหนด Resource Types: Patient Demographics, Medical History, Lab Results, Prescriptions, Medication Administration Records, Billing Records, Audit Logs
3. สร้าง Permission Matrix (8 roles x 7 resource types)
4. ออกแบบ Role Hierarchy
5. กำหนด Separation of Duties Constraints (SSD/DSD)
6. Implement ใน Python (ถ้ามีเวลา)

**สิ่งที่ต้องส่ง:**
1. Role Definitions (8 roles) พร้อมคำอธิบายหน้าที่
2. Permission Matrix (8 roles x 7 resource types)
3. Role Hierarchy Diagram
4. SSD/DSD Constraints พร้อมเหตุผล
5. โค้ด RBAC Implementation (ถ้ามี)

---

### Lab 7.3: Policy-Based Access Control — Implement OPA

**วัตถุประสงค์:** เรียนรู้การเขียน Policy ในรูปแบบ Declarative (Rego) และ Integrate กับ Web Application

**เวลาที่ใช้:** 45-60 นาที

**เครื่องมือ:** OPA (Open Policy Agent) Docker, Python + Flask, curl

**ขั้นตอน:**

1. รัน OPA ด้วย Docker:
   ```bash
   docker run -d --name opa -p 8181:8181 openpolicyagent/opa run --server
   ```

2. สร้าง Rego Policy File (`authz.rego`) ที่มีเงื่อนไข: admin ทำได้ทุกอย่าง, user อ่าน profile ตัวเองได้, พนักงานแผนกเดียวกันดูเอกสารกันได้, manager อนุมัติ purchase request ไม่เกิน $10,000
3. อัปโหลด Policy ไปยัง OPA:
   ```bash
   curl -X PUT --data-binary @authz.rego http://localhost:8181/v1/policies/app/authz
   ```
4. ทดสอบ Policy ด้วย curl อย่างน้อย 4 กรณี
5. Integrate กับ Flask Application

**สิ่งที่ต้องส่ง:**
1. Rego Policy File ที่สมบูรณ์
2. ผลลัพธ์จากการทดสอบ Policy (อย่างน้อย 4 test cases)
3. โค้ด Integration กับ Flask
4. คำอธิบายว่า OPA แยก authorization logic ออกจาก application code อย่างไร

---

### Lab 7.4: Broken Access Control Detection ด้วย Burp Suite / ZAP

**วัตถุประสงค์:** ฝึกตรวจจับ Broken Access Control vulnerabilities ด้วยเครื่องมือ Proxy และเขียน Authorization Test

**เวลาที่ใช้:** 45-60 นาที

**เครื่องมือ:** Burp Suite Community Edition หรือ OWASP ZAP, Web Browser, Toy Application

**ขั้นตอน:**

1. ตั้งค่า Proxy และให้ Browser ส่ง traffic ผ่าน Proxy
2. เปิด Toy Application ที่มีช่องโหว่ (WebGoat หรือที่อาจารย์จัดให้)
3. ทดสอบ IDOR: เปลี่ยน parameter (user_id, order_id) แล้วสังเกต response
4. ทดสอบ Missing Function Level: เรียก admin endpoint โดยตรง (force browsing)
5. ทดสอบ Mass Assignment: ส่ง field พิเศษใน request body เช่น "role": "admin"
6. บันทึก Findings ในรูปแบบ Report

**สิ่งที่ต้องส่ง:**
1. ภาพหรือ log การทดสอบที่พบช่องโหว่
2. Finding Report อย่างน้อย 2 รายการ (IDOR + Missing Function Level)
3. คำอธิบายแนวทางแก้ไขสำหรับแต่ละ finding
4. Authorization Test Cases (อย่างน้อย 3 test cases)

---

## คำถามท้ายบท

1. จงเปรียบเทียบ DAC, MAC, RBAC และ ABAC ในแง่ผู้ควบคุมสิทธิ์ ความยืดหยุ่น ระดับความปลอดภัย และกรณีการใช้งานที่เหมาะสม
2. Core RBAC Components ประกอบด้วยอะไรบ้าง และ RBAC0, RBAC1, RBAC2, RBAC3 แตกต่างกันอย่างไร
3. Static Separation of Duty (SSD) และ Dynamic Separation of Duty (DSD) แตกต่างกันอย่างไร จงยกตัวอย่าง
4. Principle of Least Privilege คืออะไร และมีแนวทางการ Implement ในระบบฐานข้อมูลอย่างไร
5. Permission Creep คืออะไร เกิดขึ้นได้อย่างไร และมีแนวทางป้องกันอย่างไรบ้าง
6. IDOR (Insecure Direct Object Reference) คืออะไร จงยกตัวอย่างโค้ดที่มีช่องโหว่และวิธีการแก้ไข 2 วิธี
7. Missing Function Level Access Control แตกต่างจาก IDOR อย่างไร
8. Path Traversal (CWE-22) ป้องกันอย่างไร จงอธิบายบทบาทของ Canonicalization ในการป้องกัน
9. Horizontal Privilege Escalation แตกต่างจาก Vertical Privilege Escalation อย่างไร จงยกตัวอย่าง
10. Mass Assignment / Object Injection คืออะไร และ DTO Pattern ช่วยป้องกันได้อย่างไร
11. จงอธิบายความแตกต่างระหว่าง API Keys และ Access Tokens พร้อมข้อควรระวังในการใช้งานแต่ละแบบ
12. OAuth 2.0 Scopes คืออะไร และมีวิธีการ Validate Scope ที่ Resource Server อย่างไร
13. Open Policy Agent (OPA) ทำงานอย่างไร และ Rego Policy แตกต่างจาก Authorization Logic ใน Code อย่างไร
14. Policy Enforcement Point (PEP) และ Policy Decision Point (PDP) แตกต่างกันอย่างไรใน Centralized Authorization Service
15. จากกรณีศึกษา Capital One Breach 2019 จงอธิบายว่าช่องโหว่ SSRF และ IAM Role Over-Provisioning ส่งผลต่อกันอย่างไร
16. จากกรณีศึกษา Cambridge Analytica 2018 จงอธิบายว่า OAuth Scope Misconfiguration ทำให้ข้อมูล 87 ล้าน users รั่วไหลได้อย่างไร
17. จากกรณีศึกษา GitHub 2022 จงอธิบายว่าเหตุใด OAuth Token Scope ที่กว้างเกินไปจึงเป็นความเสี่ยง และแนวทางป้องกันคืออะไร
18. OWASP ASVS V4 ข้อ 4.1.1 และ 4.2.1 กำหนดอะไรบ้าง และเกี่ยวข้องกับการป้องกัน Broken Access Control อย่างไร
19. จงออกแบบ Security Requirement สำหรับระบบที่ป้องกัน IDOR และ Mass Assignment พร้อม Acceptance Criteria
20. จงออกแบบ Test Case สำหรับตรวจสอบว่า Vertical Privilege Escalation เกิดขึ้นได้หรือไม่ในระบบที่กำหนด
21. Default Deny (Fail Safe Defaults) สำคัญอย่างไร และทำไมการตั้ง Default Allow จึงเป็นอันตราย
22. Role Explosion คืออะไร และ ABAC ช่วยแก้ปัญหานี้ได้อย่างไร
23. Gateway-Level Authorization มีข้อจำกัดอะไรบ้าง และทำไมยังต้องมี Data-Level Authorization ที่ Service Level
24. จากกรณี Parler Data Scraping 2021 จงอธิบายว่า IDOR ใน API ทำให้ข้อมูลส่วนตัวรั่วไหลได้อย่างไรทั้งที่ข้อมูลถูกตั้งเป็น private
25. Pull Request Checklist สำหรับ Access Control ควรมีรายการตรวจสอบอะไรบ้าง (อย่างน้อย 10 ข้อ)

---

## สรุปท้ายบท

Access Control และ Authorization เป็นรากฐานสำคัญของความปลอดภัยซอฟต์แวร์ Broken Access Control ยังคงเป็นอันดับ 1 ใน OWASP Top 10 2025 โดย 100% ของแอปพลิเคชันที่ทดสอบพบช่องโหว่ด้านนี้บางรูปแบบ

โมเดล Access Control มี 5 ประเภทหลัก ได้แก่ DAC (เจ้าของกำหนดสิทธิ์), MAC (ระบบกำหนดตาม Label), RBAC (สิทธิ์ตามบทบาท), ABAC (สิทธิ์ตามคุณลักษณะ) และ Rule-Based Access Control การเลือกโมเดลที่เหมาะสมขึ้นอยู่กับขนาดองค์กร ระดับความปลอดภัยที่ต้องการ และความยืดหยุ่นในการบริหารจัดการ

หลักการออกแบบ Authorization ที่สำคัญ ได้แก่ Least Privilege (ให้สิทธิ์เท่าที่จำเป็น), Separation of Duties (แยกหน้าที่ที่ขัดแย้งกัน), Default Deny (ปฏิเสธเป็นค่าเริ่มต้น) และการจัดการ Permission Creep (สิทธิ์สะสม) การตรวจสอบ Authorization ต้องทำทุกระดับตั้งแต่ API Endpoint จนถึงระดับ Data

OWASP A01 Broken Access Control ครอบคลุมช่องโหว่ 5 ประเภทหลัก ได้แก่ IDOR, Missing Function Level Access Control, Path Traversal, Privilege Escalation (แนวนอนและแนวตั้ง) และ Mass Assignment/Object Injection การป้องกันแต่ละประเภทต้องใช้เทคนิคเฉพาะ เช่น Authorization Check ทุก request, Indirect Reference Map, Canonicalization, DTO Pattern และ Role/Permission Check ทุก function

ในสถาปัตยกรรม API และ Microservices, การจัดการ Authorization ที่ดีต้องใช้ OAuth 2.0 Scopes เพื่อจำกัดขอบเขต Access Token, เข้าใจความแตกต่างระหว่าง API Keys และ Access Tokens, และใช้ Policy-Based Access Control (OPA/Casbin) เพื่อแยก Authorization Logic ออกจาก Application Code โมเดล PEP/PDP/PAP/PIP ช่วยให้การจัดการ Authorization เป็น centralized และตรวจสอบได้

กรณีศึกษา Cambridge Analytica (2018), Capital One (2019), GitHub (2022) และ Parler (2021) แสดงให้เห็นว่าช่องโหว่ด้าน Access Control สร้างความเสียหายระดับโลกได้ — ตั้งแต่ข้อมูล 87 ล้าน users รั่วไหล ค่าปรับ 5,000 ล้านดอลลาร์สหรัฐ ไปจนถึงข้อมูลทางการเงิน 100 ล้าน customers ถูกขโมย

OWASP ASVS V4 (V4 Access Control) และ OWASP Top 10 2025 A01 Checklist เป็นเครื่องมือสำคัญในการตรวจสอบตนเอง การแปลงความรู้เป็น Security Requirements และ Test Cases ที่วัดผลได้ช่วยให้องค์กรสามารถป้องกัน Broken Access Control ได้อย่างเป็นระบบ

---

## Verification

- **Research process:** ใช้ websearch ตรวจสอบข้อมูลประกอบจากแหล่งอ้างอิงหลักก่อนปรับปรุงเนื้อหา
- **OWASP Top 10 2025 A01 Broken Access Control:** ยืนยันอันดับ 1, 100% ของแอปพลิเคชันพบช่องโหว่, 40 CWEs, 1,839,701 occurrences, 32,654 CVEs
- **OWASP ASVS v4.0.3 V4 Access Control:** ยืนยัน V4.1 General Access Control Design, V4.2 Operation Level Access Control, V4.3 Other Access Control Considerations
- **NIST SP 800-162:** ยืนยันนิยาม ABAC, องค์ประกอบ Subject/Object/Environment Attributes, Policy Rules
- **NIST RBAC Model (ANSI INCITS 359-2012):** ยืนยัน RBAC0-RBAC3, Core RBAC Components, Role Hierarchy, SSD/DSD
- **Facebook/Cambridge Analytica 2018:** ยืนยัน 87 ล้าน users, FTC fine $5 billion (July 2019)
- **Capital One Breach 2019:** ยืนยัน SSRF (CWE-918), IAM Role Over-Provisioning, 100 ล้าน customers, $80 million fine, Paige Thompson (Erratic), IMDSv1
- **GitHub OAuth Token Theft April 2022:** ยืนยัน OAuth tokens from Heroku + Travis CI, targeted attack, npm, private repositories cloned
- **Parler Data Scraping January 2021:** ยืนยัน 99 TB data scraped, API IDOR, Capitol Hill riot context
- **OWASP Top 10 2021/2025 A01:** ยืนยัน Broken Access Control ยังคงอันดับ 1
- **CWE Mappings:** ยืนยัน CWE-22 (Path Traversal), CWE-285 (Improper Authorization), CWE-352 (CSRF), CWE-602 (Client-Side Enforcement), CWE-639 (IDOR), CWE-918 (SSRF)
- **Safety boundary:** Labs ระบุให้ทำในเครื่องของนักศึกษาเองหรือสภาพแวดล้อมที่ได้รับอนุญาตเท่านั้น
- **Status:** ตรวจสอบข้อมูลหลักแล้ว ไม่มีรายการที่ตั้งใจปล่อยไว้เป็น [UNVERIFIED]

---

## เอกสารอ้างอิงหลัก

1. OWASP Top 10 2025 — A01 Broken Access Control: https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/
2. OWASP ASVS v4.0.3 — V4 Access Control: https://asvs.dev/v4.0.3/V4-Access-Control/
3. OWASP Access Control Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html
4. OWASP Authorization Testing: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/
5. NIST SP 800-162 — Guide to ABAC Definition and Considerations: https://nvlpubs.nist.gov/nistpubs/specialpublications/NIST.sp.800-162.pdf
6. NIST RBAC Model (ANSI INCITS 359-2012): https://csrc.nist.gov/projects/role-based-access-control
7. OWASP Mass Assignment Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
8. OWASP IDOR Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html
9. Open Policy Agent (OPA) Documentation: https://www.openpolicyagent.org/docs/latest/
10. OPA Rego Language Reference: https://www.openpolicyagent.org/docs/latest/policy-language/
11. OAuth 2.0 Scopes — RFC 6749 Section 3.3: https://datatracker.ietf.org/doc/html/rfc6749#section-3.3
12. FTC — Cambridge Analytica Settlement (July 2019): https://www.ftc.gov/news-events/news/press-releases/2019/07/ftc-imposes-5-billion-penalty-sweeping-new-privacy-restrictions-facebook
13. Capital One Indictment — DOJ (July 2019): https://www.justice.gov/usao-wdwa/pr/former-aws-employee-charged-data-theft-capital-one
14. GitHub Security Alert (April 2022): https://github.blog/2022-04-15-security-alert-stolen-oauth-user-tokens/
15. Heroku Incident Review (June 2022): https://heroku.com/blog/april-2022-incident-review
16. CWE-22 — Path Traversal: https://cwe.mitre.org/data/definitions/22.html
17. CWE-639 — Insecure Direct Object Reference: https://cwe.mitre.org/data/definitions/639.html
18. CWE-285 — Improper Authorization: https://cwe.mitre.org/data/definitions/285.html
19. CWE-918 — Server-Side Request Forgery: https://cwe.mitre.org/data/definitions/918.html
20. MITRE ATT&CK — T1068 Exploitation for Privilege Escalation: https://attack.mitre.org/techniques/T1068/
21. AWS IAM Best Practices: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
22. Kong API Gateway — OAuth 2.0 Authentication: https://docs.konghq.com/hub/kong-inc/oauth2/
23. OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org/
24. NVD — CVE Details Search: https://nvd.nist.gov/vuln/search
