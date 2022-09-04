Chapter 1: Security Principles
 Module 1: Security Concept 
**The CIA Triad**
* C - Confidentiality rการรักษาไว้ซึ่งความลับของข้อมูล โดยเป็นการปกป้องข้อมูลและไม่เปิดเผยข้อมูลไปยังผู้ที่ไม่ได้รับอนุญาต 
    - Personally Identifiable Information (PII) อยู่ภายใต้ขอบเขตของ confidentiality ซึ่งกล่าวถึงข้อมูลของแต่ละบุคคลที่จะต้องมีการรักษาไว้ซึ่งความลับและไม่ถูกเปิดเผยให้กับผู้ที่ไม่ได้รับอนุญาต ยกตัวอย่างเช่น protected health information (PHI) เป็นการป้องกันข้อมูลทางการแพทย์ของผู้ป่วย จะต้องได้รับการปกป้องให้สามารถเข้าถึงได้เฉพาะบุคคลที่มีได้รับอนุญาตเข้าถึงข้อมูลดังกล่าว เป็นต้น 
* I - Integrity ข้อมูลต้องมีความถูกต้องครบถ้วนสมบูรณ์ไม่มีการเปลี่ยนแปลง ดัดแปลง หรือแก้ไขใด ๆ โดยไม่ได้รับอนุญาต
    - Data integrity is the assurance that data has not been altered in an unauthorized manner. This requires the protection of the data in systems and during processing to ensure that it is free from improper modification, errors or loss of information and is recorded, used and maintained in a way that ensures its completeness. Data integrity covers data in storage, during processing and while in transit.
    - System integrity refers to the maintenance of a known good configuration and expected operational function as the system processes the information. Ensuring integrity begins with an awareness of state, which is the current condition of the system. Specifically, this awareness concerns the ability to document and understand the state of data or a system at a certain point, creating a baseline. For example, a baseline can refer to the current state of the information—whether it is protected. Then, to preserve that state, the information must always continue to be protected through a transaction.
* A - ข้อมูลต้องมีความพร้อมใช้งานเมื่อถูกเรียกใช้ กล่าวคือข้อมูลจะต้องสามารถเข้าถึงได้และสามารถใช้งานได้จากผู้ที่มีสิทธิการเข้าถึงข้อมูลดังกล่าวเมื่อมีการร้องขอ

**Authentication** - When users have stated their identity, it is necessary to validate that they are the rightful owners of that identity. This process of verifying or proving the user’s identification is known as authentication. Simply put, authentication is a process to prove the identity of the requestor.
* Something you know: Passwords or paraphrases
* Something you have: Tokens, memory cards, smart cards
* Something you are: Biometrics , measurable characteristics

**Method of Authentication**
* single-factor authentication (SFA) 
* multi-factor authentication (MFA)
สำหรับขั้นตอนการปฏิบัติที่ดีควรมีส่วนประกอบด้านล่างนี้อย่างน้อย 2 ส่วน สำหรับดำเนินการทำ Authentication ของผู้ใช้งาน ได้แก่:
*  Knowledge-based  - personal identification number (PIN), password 
* Token-based  
* Characteristic-based  
ตัวอย่าง MFA เช่น การกดเงินสดด้วยบัตร ATM เราจะมี (HAVE) บัตร ATM และรู้ (KNOW) รหัสสำหรับกดหรือ PIN จึงจะสามารถกดเงินได้ โดยหากมีเพียงบัตรเพียงอย่างเดียวก็จะไม่สามารถกดเงินออกมาได้ เป็นต้น

**Non-Repudiation** เป็นข้อกำหนดทางกฎหมายและเป็นข้อกำหนดที่กำหนดไว้เพื่อให้บุคคลจะต้องไม่ปฏิเสธความรับผิดชอบในการดำเนินการใดๆทางอิเล็กทรอนิกส์ที่ได้ระบุถึงตัวผู้ใช้ของบุคคลดังกล่าว เช่น การดำเนินการสร้างบัญชีผู้ใช้, การอนุมัติ หรือการส่งข้อความ เป็นต้น ในปัจจุบันจะเห็นได้ว่าระบบ E-Commerce และการทำธุรกรรม มักมีการแอบอ้างการใช้งานจากบุคคลที่ไม่ใช่เจ้าของบัญชีที่ถูกต้อง เช่น เกิดการสั่งซื้อสินค้าออนไลน์ที่ไม่ถูกต้องและมีการแจ้งปฏิเสธในภายหลัง เป็นต้น จากตัวอย่างดังกล่าวจะเห็นได้ว่า บัญชีผู้ใช้จะต้องสามามารถเชื่อถือได้และตามหลักการของ Non-Repudiation จะต้องไม่ปฏิเสธความรับผิดชอบต่อการดำเนินธุรกรรมใดๆ ที่เกิดขึ้นจากบัญชีผู้ใช้ของตน 

**Privacy**
ความเป็นส่วนตัวของแต่ละบุคคลเป็นสิ่งสำคัญเพื่อป้องกันและควบคุมการเข้าถึงข้อมูลสารสนเทศของแต่ละบุคคล อีกทั้งปริมาณข้อมูลในปัจจุบันมีอัตราการเจริญเติบโตที่สูงขึ้นอย่างต่อเนื่อง ซึ่งส่งผลกระทบโดยตรวจต่อนโยบายความเป็นส่วนบุคคลและการปกป้องข้อมูลส่วนบุคคลอย่างชัดเจน ซึ่งจะเห็นได้จากการผลักดันกฎหมายของแต่ละประเทศที่ออกมาสำหรับปกป้องข้อมูลของประชาชนหรือเจ้าของช้อมูล เช่น GDPA (General Data Protection Regulation) ของฝั่ง EU หรือ PDPA (Personal Data protection Act) ของไทย เป็นต้น โดยการออกกฎหมายดังกล่าวเป็นสิ่งที่ทำให้ภาคธุรกิจและประชาชนมีความตระหนักรู้และตื่นตัวกับความเป็นส่วนตัวของข้อมูลมากขึ้นอย่างเห็นได้ชัด 

 Module 2: Risk Management Process
 Risk = Impact x Likelihood