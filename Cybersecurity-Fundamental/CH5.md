# สรุปเนื้อหา
## บทที่  5: Security Operations
## Module 1: Data Security

Data Security 

กระบวนการจัดการข้อมูลมีดังนี้ 
Create > Store > Share > Use > Modify > Archrive > Destroy

Data Sensitivity Levels 
- High Restriced
- Moderately Restriced
- Low sensitivity
- Unrestriced public data

Ingress Monitoring Tools (Logging)
- Firewall
- Gateways
- Remote Authentication server
- IDS/IPS 
- SIEM
- Anti malware 

EGress Monitoring Tools (Logging)
- Email
- การคัดลอกข้อมูลไปยังอุปกรณ์พกพา
- FTP
- การโพสบน Web Pages
- การใช้งาน API

รูปแบบการเข้ารหัสมี 2 รูปแบบดังนี้ 
- Symetric - ใช้ Key เดียวกันสำหรับเข้ารหัสและถอดรหัส
- Asymetric - ใช้ Public and Private Key สำหรับการเข้าและถอดรหัส

็คุณสมบัติของ HASH Function มีดังต่อไปนี้
1. ข้อมูลแต่ละตัวเมื่อผ่านฟังก์ชันแฮชแล้วจะต้องมีค่าไม่เท่ากัน มีลักษณะที่จำเพาะแต่ล่ะข้อมูล
2. หาค่าแฮชจากข้อมูลควรทำได้ง่ายและรวดเร็ว
3. เมื่อข้อมูลผ่านฟังก์ชันแฮชแล้วไม่ควรทำย้อนกลับได้
4. การบวนการแฮชควรมีการกระจายตัวสูง กล่าวคือ ข้อมูลใดๆที่ผ่านฟังก์ชันแฮชควรมีขนาดเท่ากัน แต่ไม่เหมือนกัน

ชนิดของฟังก์ชันแฮชแต่ละประเภทสามารถแจกแจงได้ดังนี้
- MD2 (128bits) คิดค้นโดย Ronald Rivests
- MD4 (128bits) คิดค้นโดย Ronald Rivests
- MD5 (128bits) คิดค้นโดย Ronald Rivests
- MD6 (0~512 bits) คิดค้นโดย Ronald Rivests Team
- SHA0 (160bits) คิดค้นโดย National Security Agency : NSA
- SHA1 (160bits) คิดค้นโดย National Security Agency : NSA
- SHA2 (SHA-224, SHA-256, SHA-384, SHA-512) คิดค้นโดย National Security Agency : NSA

---

## Module 2: System Hardening

กระบวนการทำ Configulation Managemnent ประกอบด้วย
- Identification 
- Baseline
- Change Control
- Verification & Audit

ส่วนประกอบของ Configuration Management ประกอบด้วย
- Inventory 
- Baselines
- Updates 
- Patches

---

## Module 3: Best Practice Security Policies

Base Practice Security Policy มีดังนี้
- Data Handling - ควรมีการจัดการข้อมูลขององค์กรอย่างมีประสิทธิภาพ
- Password - ความใช้รหัสผ่านที่มีความยาก และจะต้องมีการจัดทำนโยบายการเปลี่ยนแปลงรหัสผ่านให้มีความเหมาะสม เช่น การเปลี่ยนรหัสทุก 30 วัน เป็นต้น
- Acceptable Use - การอนุญาตใช้สินทรัพย์หรืออุปกรณ์หรือข้อมูล ควรได้รับการอนุญาตจากผู้มีสิทธิเข้าถึง เช่น
  - Data Access
  - System Access
  - Passwords 
  - Data Retention
  - Internet Usage 
  - Company Device Usages
- BYOD - นโยบายการนำอุปกรณ์ส่วนตัวมาใช้ในองค์กร
  - Smartphone
  - Tablet 
  - Laptop
  - Smartwatch 
  - Bluetooth Devices
- Privavy - การป้องกันความเป็นส่วนตัว
  - PII
  - ePHI
  - Bank/Credit card information
  - GDPR
  - PIPEDA - Personal Information Protection and Electronic Documents Act
  - PDPA
- Change Management - การจัดการการเปลี่ยนแปลงในแต่ละขั้นตอน

นโยบายและขั้นตอนการจัดการข้อมูล มีดังนี้
- Classify
- Categorize 
- Label 
- Store 
- Encrypt 
- Backup
- Destroy

--- 

## Module 4: Security Awareness Training

รูปแบบของการสร้างความตระหนักรู้สามารถแบ่งได้ดังนี้
- Education
- Training 
- Awareness

Social Engineering Techniques
- Baiting
- Phone phishging or vishong
- Pretexting 
- Quid pro qui
- Tailgating
- False flag or false front operations

---