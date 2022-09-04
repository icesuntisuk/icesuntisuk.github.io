Chapter 1: Security Principles
 
**The CIA Triad**
* C - Confidentiality relates to permitting authorized access to information, while at the same time protecting information from improper disclosure.
    - Personally Identifiable Information (PII) is a term related to the area of confidentiality. It pertains to any data about an individual that could be used to identify them. Other terms related to confidentiality are protected health information (PHI) , which is information regarding one’s health status, and classified or sensitive information, which includes trade secrets, research, business plans and intellectual property.
* I - Integrity is the property of information whereby it is recorded, used and maintained in a way that ensures its completeness, accuracy, internal consistency and usefulness for a stated purpose.
    - Data integrity is the assurance that data has not been altered in an unauthorized manner. This requires the protection of the data in systems and during processing to ensure that it is free from improper modification, errors or loss of information and is recorded, used and maintained in a way that ensures its completeness. Data integrity covers data in storage, during processing and while in transit.
    - System integrity refers to the maintenance of a known good configuration and expected operational function as the system processes the information. Ensuring integrity begins with an awareness of state, which is the current condition of the system. Specifically, this awareness concerns the ability to document and understand the state of data or a system at a certain point, creating a baseline. For example, a baseline can refer to the current state of the information—whether it is protected. Then, to preserve that state, the information must always continue to be protected through a transaction.
* A - Availability means that systems and data are accessible at the time users need them.

**Authentication** - When users have stated their identity, it is necessary to validate that they are the rightful owners of that identity. This process of verifying or proving the user’s identification is known as authentication. Simply put, authentication is a process to prove the identity of the requestor.
* Something you know: Passwords or paraphrases
* Something you have: Tokens, memory cards, smart cards
* Something you are: Biometrics , measurable characteristics

**Method of Authentication**
* single-factor authentication (SFA) 
* multi-factor authentication (MFA)
Beat Practice is to implement at least two of the three common techniques for authentication:*  Knowledge-based  - personal identification number (PIN), password 
* Token-based  
* Characteristic-based  
ตัวอย่าง MFA เช่น การกดเงินสดด้วยบัตร ATM เราจะมี (HAVE) บัตร ATM และรู้ (KNOW) รหัสสำหรับกดหรือ PIN จึงจะสามารถกดเงินได้ โดยหากมีเพียงบัตรเพียงอย่างเดียวก็จะไม่สามารถกดเงินออกมาได้ เป็นต้น

**Non-Repudiation** เป็นข้อกำหนดทางกฎหมายและเป็นข้อกำหนดที่กำหนดไว้เพื่อให้บุคคลจะต้องไม่ปฏิเสธความรับผิดชอบในการดำเนินการใดๆทางอิเล็กทรอนิกส์ที่ได้ระบุถึงตัวผู้ใช้ของบุคคลดังกล่าว เช่น การดำเนินการสร้างบัญชีผู้ใช้, การอนุมัติ หรือการส่งข้อความ เป็นต้น ในปัจจุบันจะเห็นได้ว่าระบบ E-Commerce และการทำธุรกรรม มักมีการแอบอ้างการใช้งานจากบุคคลที่ไม่ใช่เจ้าของบัญชีที่ถูกต้อง เช่น เกิดการสั่งซื้อสินค้าออนไลน์ที่ไม่ถูกต้องและมีการแจ้งปฏิเสธในภายหลัง เป็นต้น จากตัวอย่างดังกล่าวจะเห็นได้ว่า บัญชีผู้ใช้จะต้องสามามารถเชื่อถือได้และตามหลักการของ Non-Repudiation จะต้องไม่ปฏิเสธความรับผิดชอบต่อการดำเนินธุรกรรมใดๆ ที่เกิดขึ้นจากบัญชีผู้ใช้ของตน 

**Privacy**
