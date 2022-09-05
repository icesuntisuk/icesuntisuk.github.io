# สรุปเนื้อหาหลักสูตร Incident Response

## The CIA Triad
* C - Confidentiality rการรักษาไว้ซึ่งความลับของข้อมูล โดยเป็นการปกป้องข้อมูลและไม่เปิดเผยข้อมูลไปยังผู้ที่ไม่ได้รับอนุญาต 
    - Personally Identifiable Information (PII) อยู่ภายใต้ขอบเขตของ confidentiality ซึ่งกล่าวถึงข้อมูลของแต่ละบุคคลที่จะต้องมีการรักษาไว้ซึ่งความลับและไม่ถูกเปิดเผยให้กับผู้ที่ไม่ได้รับอนุญาต ยกตัวอย่างเช่น protected health information (PHI) เป็นการป้องกันข้อมูลทางการแพทย์ของผู้ป่วย จะต้องได้รับการปกป้องให้สามารถเข้าถึงได้เฉพาะบุคคลที่มีได้รับอนุญาตเข้าถึงข้อมูลดังกล่าว เป็นต้น 
* I - Integrity ข้อมูลต้องมีความถูกต้องครบถ้วนสมบูรณ์ไม่มีการเปลี่ยนแปลง ดัดแปลง หรือแก้ไขใด ๆ โดยไม่ได้รับอนุญาต
    - Data integrity เป็นการบ่งบอกว่าข้อมูลดังกล่าวจะต้องไม่ถูกเปลี่ยนแปลงใดๆ จากผู้ที่ไม่มีสิทธิ โดยจะต้องมีการป้องกันข้อมูลภายในระบบ เพื่อให้สามารถมั่นใจได้ว่าข้อมูลต่าง ๆ จะไม่ถูกเปลี่ยนแปลงไปในขั้นตอน เช่น ระหว่างจัดเก็บข้อมูล, ระหว่างการประมวลผลข้อมูล และระหว่างการส่งต่อข้อมูลได้ 
    - System integrity เป็นรูปแบบการจัดทำ Baseline สำหรับระบบ เพื่อให้มั่นใจได้ว่าระบบมีการตั้งค่าไว้อย่างถูกต้องสมบูรณ์โดยที่ไม่ถูกเปลี่ยนแปลงหรือแก้ไขการตั้งค่าแต่อย่างใด 
* A - ข้อมูลต้องมีความพร้อมใช้งานเมื่อถูกเรียกใช้ กล่าวคือข้อมูลจะต้องสามารถเข้าถึงได้และสามารถใช้งานได้จากผู้ที่มีสิทธิการเข้าถึงข้อมูลดังกล่าวเมื่อมีการร้องขอ

___ 
## คำศัพท์ที่เกี่ยวข้องกับ IR
**Event** - เป็นเหตุการณ์ที่เกิดขึ้น 

**Alert** - เป็นส่วนที่เกิดจากการป้องกันหรือการแจ้งเตือนต่าง ๆ ที่เกิดขึ้นการ Monitor ของระบบ

**Incident** - เป็นเหตุการณ์ที่เกิดขึ้น และเกิดผลกระทบต่อ C-I-A ต่อองค์กร 

**Incident Response Team** 
มีหน้าที่ประสานงานร่วมกับกลุ่มผู้ปฏิบัติทั้งจากภายในและภายนอก โดยมีเป้าหมายให้ระบบสามารถกลับมาทำงานได้ตามปกติเมื่อเกิด Incident กับระบบที่เกี่ยวข้อง และอ้างอิงการดำเนินการจาก [NIST Cyber Security Framework](https://www.nist.gov/cyberframework) ดังนี้ 
- Preparation phase เป็นขั้นตอนในการเตรียมทุกอย่างให้พร้อมสำหรับการรับมือเหตุการณ์ภัยคุกคาม เช่น​ ช่องทางการสื่อสาร,​ Hardware, Software, Baseline เป็นต้น 
- Detection and Analysis phase เป็นขั้นตอนการตรวจจับการโจมตีที่เกิดขึ้น ได้แก่ 
  - Attack Vectors (Web, Services, USB, People, Email)
  - Sign of an incident (Know and Unknown)
  - Source of Precursors and Indicators (IPS/IDS, SIEMs, Antivirus, Firewall, Endpoint Detection, Logs, IOC, People)
  - Incident Analysis (Profiling, Normal Behaviors, Log Correction, Knownledge Base, Research, Packet Sniffer)
    - ในการตรวจสอบ Normal Behaviors ของผู้ใช้งานนั้น เป็นเรื่องยากต่อการตรวจสอบของแต่ละองค์กร ฉะนั้น องค์กรจำเป็นจะต้องมี Baseline ของผู้ใช้งานของผู้ใช้งาน
  - Incident Document (Details of Incident)
  - Incident Prioritization (Functional Impact, Information Impact, Recoverability)
  - Incident Notification (Personal, Channel)
- Containment, Eradication & Remediation phase - เป็นขั้นตอนสำหรับพิจารณาวิธีการในการควบคุมความเสียหาย การควบคุมความเสียหายมีความจำเป็นอย่างยิ่งที่จะป้องกันไม่ให้ความเสียหายกระจายออกไปเป็นวงกว้าง สร้างผลกระทบต่อทรัพยากรในการดำเนินธุรกิจอื่นๆและยังเป็นการเปิดพื้นที่ เพิ่มระยะเวลาให้ทีมที่รับมือ Incident มีเวลาในการคิดหาสาเหตุ และวิธีการแก้ปัญหาที่ถาวรได้ ข้อสำคัญของการควบคุมความเสียหาย คือการตัดสินใจเลือกใช้วิธีการที่เหมาะสม โดยวิธีการทั่วไปมี
  - Containment Strategy - เป็นรูปแบบการควบคุมความเสียหาย ไม่ให้เกิดการรุกรามไปสู่ระบบอื่น เช่น การทำ Isolate เครื่องออกจากระบบ เป็นต้น
  - Evidence Gathering and Handling - เป็นการเก็บหลักฐานที่มีความน่าสงสัยและตรวจสอบเพื่มเติม
  - Identifying the Attacking Hosts 
  - Eradication - เป็นการกำจัดสาเหตุของภัยคุกคามจาก **Root Course** แล้วทำการแก้ไขปัญหาดังกล่าว
  - Remediation - เป็นการนำระบบกลับมาให้สามารถใช้งานได้ตามปกติ โดยอยู่บนพื้นฐานของความสมบูรณ์ของระบบหลังจากการแก้ไขและความเร็วในการดำเนินการแก้ไข
- Post Incident Activities เป็นรูปแบบของการดำเนินการหลังจากเกิดเหตุการณ์ โดยจะต้องนำ Lesson Learn มาศึกษา เพื่อนำข้อมูลไปปรับปรุงในการดำเนินการให้เกิดประสิทธิภาพสูงสุดในครั้งถัดไป 
  - Lesson Learned 
  - Stratistic of incident 
  - Evidece Retention
  - Incident Handling Checklist 
  - Recommendations 
  - Law Enforcement 

___ 

## SOC - Security Operation Center 
เป็นสถานที่สำหรับรับมือเหตุการณ์หรือภัยคุกคามทางไซเบอร์ โดยมี SOC Team เป็นผู้ปฏิบัติภายใน SOC โดยประกอบไปด้วย Tier 1, Tier 2 และ Tier 3 โดยมีหน้าที่ดังนี้
- Tier 1 ทำหน้าที่เป็น Operation Team และตรวจสอบการทำงานต่าง ๆ ให้เป็นไปตาม Playbook ที่ได้กำหนดไว้ 
  - Notify from SIEM
  - Analysys in Playbook 
- Tier 2 ทำหน้าที่วิเคราะห์ข้อมูลหรือ Security Analyst ในเหตุการณ์ใหม่ๆ
- Tier 3 ทำหน้าที่เป็น Therat Hunter Team 

**Usecase หรือ คู่มือการปฏิบัติ**
- Login with multiple country
- Bruteforce Attack - ใน [CIS](https://www.cisecurity.org/cis-benchmarks/) ได้ระบุให้หลีกเลี่ยงการใช้ Default Admin users 
- Internal Threat - สามารถตรวจจับได้จาก EDR หรือการจัดทำ User Baseline
- Hacking with VPN
- Zero-day Attack

**Skill, Ability and Knowledge**
- สามารถดูข้อมูลกว้างๆ ได้จากตัวอย่าง [Link](https://cyberindustry.org/workrole)
- [Security Certification Roadmap](https://pauljerimy.com/security-certification-roadmap/)

**SOC Measurement** - เป็นการวัดประสิทธิภาพอง SOC สามารถประเมิน โดยอาศัยการวัดจากข้อมูลดังนี้
- Data Feed Health - การตรวจสอบสถานะภาพของข้อมูลที่เข้ามาในระบบ สามารถนำมาใช้เป็นตัวชี้วัดภายใน SOC ได้ 
- Coverage - มีความครอบคลุมการตรวจสอบมากแค่ไหน 
- Moniroring SLAs/SLOs 
  - SLA: Service Level Agreement
  - SLO: Service Level Objective
- Scanning and Sweeping 
  - เป็นรูปแบบการแสกนของระบบ เพื่อตรวจสอบ Asset ของระบบตามวงรอบ ซึ่งจะสามารถทราบถึงความเสี่ยงและช่องโหว่ที่เกิดขึ้นกับระบบ
  - สามารถตรวจสอบโดยอาศัยการแสกนช่องโหว่ได้ทั้งจาก On-Prem และ On-Cloud 
- Analysis Performance - เป็นการเจาะจงไปยังการวัดผลจากการวิเคระห์
  - % True Positive rate for escalation
  - % Response rate for customer escalation
  - Number of escalated case handled in last 30 days 
  - Mean Time to close a case 
- Masument with action
  - Tabletop exercise
  - Puple team exercise
  - Surprise exercise 

**Indicator of Compromise (IOC)**
- Hash 
- IP Address
- Name of exed used 

**Pyramid of Pain** จะถูกเรียงลำดับจากง่ายสุดไปยากสุด (Hash --> TTPs)
- Hash Value
- IP Addresses
- Domain Name 
  - Unicode
  - Legitimate Domain
  - Punycode
  - Malicious Homograph - เป็นการ Rander Domain name ออกมาเป็นตัวอักษร โดยเป็นรูปแบบการหลอกให้ Browser แปลความของข้อความผิดไป ทั้งนี้ บน Browser ใหม่ๆ จะมีการป้องกันข้อมูลดังกล่าวไว้แล้ว
- Network/Host Artifacets 
  - Network Artifacts 
    - Rare User-Agents String
    - Traffic on non-traditional Ports 
  - Host Artifacets 
    - Specific Registry Key เช่น
      - SOFTWARE\Microst\Windows\CurrentVersion\Run
      - SOFTWARE\Microst\Windows\CurrentVersion\RunOne
      - HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
      - HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
    - Process Connected on Port 80 that is not a browser 
- Tools 
  - psexec.exe
  - cmd.exe - exe command 
  - reg.exe - Create registry file 
  - wce.exe - Drump password on memory
  - wmi.exe - query and exe 
  - minikatz - Dump Credential 
  - powershell empire - backdoor 
  - certutil - สร้าง Certificate และมักถูกใช้สำหรับ Download file ได้ ซึ่งอยู่ภายใต้ระบบปฏิบัติการ Windows 
  - LOLBAS หรือ Living Off The Land Binaries, Scripts and Libraries เป็นตัวอย่างคำสั่งสำหรับใช้ทำ Threat Hunting เพื่อหลบเลี่ยงการตรวจจับ รายละเอียดตาม [link](https://lolbas-project.github.io)
- TTPs (Tactics, Techniques, Procedure)
  - [MITRE](https://attack.mitre.org) ได้ทำการแบ่งและขยายความเพิ่มเติมจาก Cyber Kill Chain โดยอ้างอิงตาม Tactic, Technique และ Procedure ขอแต่ละการโจมตี โดยอ้างอิงตาม ID ซึ่งจะมีข้อมูลของการทำ Mitigation และ การ Detection ให้สามารถนำไปปรับใช้กับองค์กรได้ 

___

## Threat Intelligence Platform
TI Platform เป็นเครื่องมือที่ใช้สำหรับรวมรวมข้อมูลจากแหล่งข้อมูลข่าวทางไซเบอร์ ประกอบด้วย
- Opensource Intelligence Feeds
- Security Vendor Feeds
- Commercial Threat Feeds/Report
- Community 

**IOC Checker tools URL**
- https://otx.alienvault.com/preview
- https://exchange.xforce.ibmcloud.com
- https://www.virustotal.com 
- https://www.hybrid-analysis.com 

**Suspicious Events** สามารถตรวจสอบได้จาก
- Suspicious activities in PC/Laptop
- Username/Account was unauthorized used/logged in to the system
- Username/Account was lockedd
- System down/ System Change without approval
- Get/Sent suspicioud email/Phishing 
- Anomaly behaviors at unusal time

**Log Correlation** เป็นรูปแบบการหาความสัมพันธ์ของข้อมูล Log มาประกอบการพิจารณาเหตุการณ์ที่เกิดขึ้นในระบบ​ เช่น การส่ง Alets จาก Hardware หรือ Application failed หรือ การจัดทำ User-Defined rules สำหรับการจัดทำความสัมพันธ์ที่ต้องการ

___

### ตัวอย่าง UseCases 

**RDP Bruteforce สามารถตรวจสอบได้จาก Log ดังนี้**

Microsoft-Windows-Security-Auditing
- Event 4624: Success authentication with an account
- Event 4625: Failed authentication
  
Microsoft-Windows-TerminalServices-LocalSessionManager
- Event 21: Remote Desktop Services: Session logon succeeded
- Event 22: Remote Desktop Services: Shell start notification received
- Event 23: Remote Desktop Services: Session logoff succeeded
- Event 24: Remote Desktop Services: Session has been disconnected
- Event 25: Remote Desktop Services: Session reconnection succeeded
- Event 39: Session X has been disconnected by session Y
- Event 40: Session X has been disconnected, reason code Z
- 
Mitigation
- Change admin name to another name
- Allow RDP only from internal network
- Lock account after login fail with threshold 

**Powershell สามารถตรวจสอบได้จาก Log ดังนี้**

Sysmon
- Event 1: Process Create
- Event 3: Network Connection detected 

Mitigation
- Uninstall powershell
- Monitor powershell usage

**Web Application สามารถตรวจสอบได้จาก Log ดังนี้**

Web Server Log
- Access.log
- Error.log

Inspect 
- Huge number of requests from client
- User-Agent จากเครื่องมือต่าง ๆ เช่น Nmap, Acunetic, Nikto, ZAP 
- Attack โดยสามารถตรวจจับได้จาก Sinature based

Mitigation
- Secure Codeing (Secure Code Development life cycle)
- Pentration Test 
- Secure Cod Review
- WAF

**Linux Command สำหรับการวิเคราะห์ข้อมูล Log**
- ตัวอย่างคำสั่งจะอยู่ในรูปแบบ Command1 arg1 | Command2 arg2 | ...
- 


Powered by Icesuntisuk