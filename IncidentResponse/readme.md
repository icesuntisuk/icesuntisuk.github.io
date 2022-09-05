# สรุปเนื้อหาหลักสูตร Incident Response

## The CIA Triad
* C - Confidentiality rการรักษาไว้ซึ่งความลับของข้อมูล โดยเป็นการปกป้องข้อมูลและไม่เปิดเผยข้อมูลไปยังผู้ที่ไม่ได้รับอนุญาต 
    - Personally Identifiable Information (PII) อยู่ภายใต้ขอบเขตของ confidentiality ซึ่งกล่าวถึงข้อมูลของแต่ละบุคคลที่จะต้องมีการรักษาไว้ซึ่งความลับและไม่ถูกเปิดเผยให้กับผู้ที่ไม่ได้รับอนุญาต ยกตัวอย่างเช่น protected health information (PHI) เป็นการป้องกันข้อมูลทางการแพทย์ของผู้ป่วย จะต้องได้รับการปกป้องให้สามารถเข้าถึงได้เฉพาะบุคคลที่มีได้รับอนุญาตเข้าถึงข้อมูลดังกล่าว เป็นต้น 
* I - Integrity ข้อมูลต้องมีความถูกต้องครบถ้วนสมบูรณ์ไม่มีการเปลี่ยนแปลง ดัดแปลง หรือแก้ไขใด ๆ โดยไม่ได้รับอนุญาต
    - Data integrity เป็นการบ่งบอกว่าข้อมูลดังกล่าวจะต้องไม่ถูกเปลี่ยนแปลงใดๆ จากผู้ที่ไม่มีสิทธิ โดยจะต้องมีการป้องกันข้อมูลภายในระบบ เพื่อให้สามารถมั่นใจได้ว่าข้อมูลต่าง ๆ จะไม่ถูกเปลี่ยนแปลงไปในขั้นตอน เช่น ระหว่างจัดเก็บข้อมูล, ระหว่างการประมวลผลข้อมูล และระหว่างการส่งต่อข้อมูลได้ 
    - System integrity เป็นรูปแบบการจัดทำ Baseline สำหรับระบบ เพื่อให้มั่นใจได้ว่าระบบมีการตั้งค่าไว้อย่างถูกต้องสมบูรณ์โดยที่ไม่ถูกเปลี่ยนแปลงหรือแก้ไขการตั้งค่าแต่อย่างใด 
* A - ข้อมูลต้องมีความพร้อมใช้งานเมื่อถูกเรียกใช้ กล่าวคือข้อมูลจะต้องสามารถเข้าถึงได้และสามารถใช้งานได้จากผู้ที่มีสิทธิการเข้าถึงข้อมูลดังกล่าวเมื่อมีการร้องขอ

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
- Containment, Eradication & Remediation phase
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

