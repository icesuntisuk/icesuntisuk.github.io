# Incident Response
## SOC - Security Operation Center 


**Event** - เป็นเหตุการณ์ที่เกิดขึ้น 

**Alert** - เป็นส่วนที่เกิดจากการป้องกันหรือการแจ้งเตือนต่าง ๆ ที่เกิดขึ้นการ Monitor ของระบบ

**Incident** - เป็นเหตุการณ์ที่เกิดขึ้น และเกิดผลกระทบต่อ C-I-A ต่อองค์กร 

**Incident Response Team** 
มีหน้าที่ประสานงานร่วมกับกลุ่มผู้ปฏิบัติทั้งจากภายในและภายนอก โดยมีเป้าหมายให้ระบบสามารถกลับมาทำงานได้ตามปกติเมื่อเกิด Incident กับระบบที่เกี่ยวข้อง และอ้างอิงการดำเนินการจาก NIST Framework ได้แก่ 
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
- 
