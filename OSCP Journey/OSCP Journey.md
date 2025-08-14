# OSCP Journey: บันทึกการเดินทาง ความทุ่มเท และการ "Try Harder"

สวัสดีครับทุกคน!

ผมเขียนบทความนี้ขึ้นมาเพื่อแชร์ประสบการณ์การเดินทางทั้งหมดของผมในการคว้าใบรับรอง **Offensive Security Certified Professional (OSCP)** ซึ่งเป็นหนึ่งในใบรับรองที่ท้าทายและได้รับการยอมรับมากที่สุดในสายงาน Cybersecurity ผมหวังเป็นอย่างยิ่งว่าเรื่องราวของผม ตั้งแต่จุดเริ่มต้นที่ไม่คาดฝัน ความทุ่มเทตลอดครึ่งปี ไปจนถึงช่วงเวลา 24 ชั่วโมงในห้องสอบ จะสามารถสร้างแรงบันดาลใจและเป็นแนวทางให้กับทุกคนที่กำลังมุ่งมั่นในเส้นทางนี้ได้นะครับ

## จุดเริ่มต้นที่ไม่คาดฝัน: จากสนามแข่ง CTF สู่เส้นทาง OSCP

เรื่องราวทั้งหมดเริ่มต้นจากการที่ผมตัดสินใจเข้าร่วมการแข่งขัน CTF (Capture The Flag) ที่จัดโดย **สำนักข่าวกรองแห่งชาติ (สขช.)** ครับ ในตอนนั้นผมมองว่าเป็นโอกาสอันดีที่จะได้ทดสอบฝีมือ วัดความรู้ และหาประสบการณ์ใหม่ๆ ในบรรยากาศการแข่งขันที่เข้มข้น แต่ผมไม่เคยคาดคิดเลยว่าการตัดสินใจครั้งนี้จะเป็นจุดเปลี่ยนครั้งสำคัญในชีวิตของผม

ความท้าทายมันอยู่ตรงที่รางวัลสำหรับผู้ที่ทำคะแนนติด 1 ใน 15 อันดับแรก คือ **Voucher สำหรับการสอบ OSCP** พอได้ยินแบบนั้น ไฟในตัวผมก็ลุกโชนขึ้นมาทันที! ผมทุ่มเทสมาธิและความสามารถทั้งหมดที่มี และด้วยความพยายามบวกกับโชคอีกนิดหน่อย ผมก็สามารถคว้า **อันดับที่ 2** มาครองได้สำเร็จ มันเป็นความรู้สึกที่ยอดเยี่ยมมาก และเป็นเหมือนประตูบานแรกที่เปิดให้ผมได้ก้าวสู่โลกของ Offensive Security อย่างเต็มตัว

## ก้าวแรกกับ OffSec: 3 เดือนแห่งการเรียนรู้และเปลี่ยน Mindset

หลังจากได้รับรางวัล ผมได้สิทธิ์เข้าเรียนในหลักสูตร **PEN-200 (Penetration Testing with Kali Linux)** ซึ่งเป็นคอร์สบังคับของ OffSec ก่อนจะไปสอบ OSCP ครับ

ช่วงเวลา 3 เดือนนี้เป็นการเรียนรู้ที่เข้มข้นมากครับ ผมได้ดำดิ่งสู่โลกของ Penetration Testing อย่างแท้จริง ตั้งแต่การทำ Information Gathering, Enumeration, การหาช่องโหว่, การทำ Privilege Escalation ไปจนถึงการเขียนรายงานอย่างมืออาชีพ แต่สิ่งที่สำคัญที่สุดที่ผมได้เรียนรู้จากที่นี่ ไม่ใช่แค่เทคนิคหรือเครื่องมือ แต่คือการเปลี่ยน **Mindset** ไปสู่ปรัชญา **"Try Harder"**

"Try Harder" ไม่ใช่แค่คำขวัญเท่ๆ แต่มันคือหัวใจของการเป็น Pentester คือการไม่ยอมแพ้เมื่อเจอกับทางตัน คือการกลับไปเริ่มต้นใหม่ (Enumeration is key!) เมื่อรู้สึกว่ามาผิดทาง คือการอดทน ค้นคว้า และทดลองซ้ำแล้วซ้ำเล่าจนกว่าจะเจอแสงสว่างที่ปลายอุโมงค์ ซึ่ง Lab ของ OffSec ได้สอนบทเรียนนี้ให้ผมเป็นอย่างดี

## ฝึกฝน ฝึกฝน และฝึกฝน: สมรภูมิ Hack The Box และ Proving Grounds

เมื่อจบ 3 เดือนจากคอร์สของ OffSec ผมรู้ดีว่าตัวเองยังต้องเสริมกระดูกอีกเยอะมาก ประสบการณ์เท่านั้นที่จะสร้างความแข็งแกร่งได้ ผมจึงมองหาแนวทางการฝึกฝนเพิ่มเติม และก็ได้เจอกับ "คัมภีร์" ที่ชาว OSCP ทุกคนรู้จักกันดี นั่นก็คือ **TJNull's List**

TJNull's List คือรายการเครื่องเซิร์ฟเวอร์เป้าหมายบนแพลตฟอร์มต่างๆ ที่มีแนวทางและเทคนิคใกล้เคียงกับข้อสอบ OSCP จริงๆ ซึ่งส่วนใหญ่จะอยู่บน **Hack The Box (HTB)** และ **Proving Grounds (PG)** ของ OffSec เอง ผมใช้เวลาอีกกว่า 3 เดือนในการไล่เก็บเครื่องในลิสต์นี้อย่างจริงจัง มันคือช่วงเวลาที่ผมได้เจอกับโจทย์ที่หลากหลาย ได้ฝึกแก้ปัญหาเฉพาะหน้า และที่สำคัญคือการจดบันทึกและสร้าง Playbook ของตัวเองขึ้นมา ซึ่งเป็นที่มาของ Write-up ต่างๆ ที่ผมได้ทำเก็บไว้นั่นเองครับ

## วันพิพากษา: 24 ชั่วโมงแห่งความท้าทายสุดขีด

และแล้วก็มาถึงวันที่ 10 สิงหาคม พ.ศ. 2568 วันที่ผมต้องลงสนามสอบจริง การสอบ OSCP ขึ้นชื่อเรื่องความโหด เพราะเป็นการสอบปฏิบัติที่ยาวนานถึง **23 ชั่วโมง 45 นาที** เราต้องเจาะระบบให้ได้ตามเป้าหมายที่กำหนด และเขียนรายงานสรุปผล (Professional Report) ที่ละเอียดและชัดเจนส่งภายใน 24 ชั่วโมงถัดไป

มันเป็น 24 ชั่วโมงที่ทั้งกดดัน เครียด และตื่นเต้นที่สุดในชีวิต มีทั้งช่วงที่ติดគាំងจนอยากจะทุบคอมทิ้ง และช่วงเวลาที่ "Eureka!" เมื่อเจอทางไปต่อ แต่ด้วยทุกสิ่งที่เตรียมตัวมาตลอดครึ่งปี ทั้งความรู้, Mindset, และ Playbook ที่สร้างมากับมือ ทำให้ผมสามารถบริหารเวลาและทำข้อสอบได้สำเร็จตามเป้าหมาย

## ความสำเร็จและความภูมิใจ: ก้าวต่อไปในเส้นทางสาย Cyber

หลังจากส่งรายงานไป ผมใช้เวลารอผลอย่างใจจดใจจ่อ และในที่สุดอีเมลที่รอคอยก็มาถึง... **ผมสอบผ่าน!**

วินาทีที่เห็นคำว่า "PASSED" มันโล่งใจและภูมิใจอย่างบอกไม่ถูกครับ การเดินทางครั้งนี้สอนให้ผมรู้ว่าไม่มีอะไรที่เป็นไปไม่ได้ถ้าเรามีความพยายาม ความอดทน และความมุ่งมั่นที่มากพอ หรืออย่างที่ OffSec บอกไว้เสมอว่า **"Try Harder!"**

---

## บันทึกการฝึกฝน (My Write-ups)

ด้านล่างนี้คือรายการ Write-up บางส่วนที่ผมได้ทำไว้ระหว่างการฝึกฝนบน Hack The Box และ Proving Grounds ครับ ผมหวังว่ามันจะเป็นประโยชน์สำหรับเพื่อนๆ ที่กำลังฝึกฝนอยู่นะครับ

### Hack The Box (HTB)

*   [Access](./WiteUp/HTB%20Challenge/Access/Access.md)
*   [Administrator](./WiteUp/HTB%20Challenge/AdministratorHTB/Administrator.md)
*   [APT](./WiteUp/HTB%20Challenge/APT/APT.md)
*   [ATOM](./WiteUp/HTB%20Challenge/ATOM%20HTB/ATOM.md)
*   [Blackfield](./WiteUp/HTB%20Challenge/Blackfield/Blackfield.md)
*   [Builder](./WiteUp/HTB%20Challenge/Builder/Builder.md)
*   [Cerberus](./WiteUp/HTB%20Challenge/Cerberus/Cerberus.md)
*   [Clicker](./WiteUp/HTB%20Challenge/Clicker/Clicker.md)
*   [Dog](./WiteUp/HTB%20Challenge/Dog/Dog.md)
*   [Editorial](./WiteUp/HTB%20Challenge/Editorial/Editorial.md)
*   [Magic](./WiteUp/HTB%20Challenge/Magic/Magic.md)
*   [Manager](./WiteUp/HTB%20Challenge/Manager/Manager.md)
*   [Mentro](./WiteUp/HTB%20Challenge/Mentro/Mentro.md)
*   [Monteverde](./WiteUp/HTB%20Challenge/Monteverde/Monteverde.md)
*   [Networked](./WiteUp/HTB%20Challenge/Networked/Networked.md)
*   [Pandora](./WiteUp/HTB%20Challenge/Pandora/Pandora.md)
*   [Rebound](./WiteUp/HTB%20Challenge/Rebound/Rebound.md)
*   [Soccer](./WiteUp/HTB%20Challenge/Soccer/Soccer.md)
*   [StreamIO](./WiteUp/HTB%20Challenge/StreamIO/StreamIO.md)
*   [Support](./WiteUp/HTB%20Challenge/Support/Support.md)
*   [Updown](./WiteUp/HTB%20Challenge/UpDown/Updown.md)
*   [Usage](./WiteUp/HTB%20Challenge/Usage/Usage.md)

### Proving Grounds (PG)

*   [Access](./WiteUp/ProvingGround/Access/Access.md)
*   [Billyboss](./WiteUp/ProvingGround/Billyboss/Billyboss.md)
*   [bullyBox](./WiteUp/ProvingGround/bullyBox/bullyBox.md)
*   [carryover](./WiteUp/ProvingGround/carryover/carryover.md)
*   [CVE-2023-6019](./WiteUp/ProvingGround/CVE-2023-6019/CVE-2023-6019.md)
*   [dev_working](./WiteUp/ProvingGround/dev_working/dev_working.md)
*   [Exfiltrated](./WiteUp/ProvingGround/Exfiltrated/Exfiltrated.md)
*   [Extplorer](./WiteUp/ProvingGround/Extplorer/Extplorer.md)
*   [Fikklish](./WiteUp/ProvingGround/Fikklish/Fikklish.md)
*   [Fish](./WiteUp/ProvingGround/Fish/Fish.md)
*   [Forward](./WiteUp/ProvingGround/Forward/Forward.md)
*   [Groove](./WiteUp/ProvingGround/Groove/Groove.md)
*   [Jordak](./WiteUp/ProvingGround/Jordak/Jordak.md)
*   [Lavita](./WiteUp/ProvingGround/Lavita/Lavita.md)
*   [Levram](./WiteUp/ProvingGround/Levram/Levram.md)
*   [vmdak](./WiteUp/ProvingGround/vmdak/vmdak.md)
*   [WallpaperHub](./WiteUp/ProvingGround/WallpaperHub/WallpaperHub.md)

---

## แหล่งข้อมูลอ้างอิง (References)

สำหรับใครที่สนใจ ผมขอแนบลิงก์ที่เป็นประโยชน์มากๆ ในการเตรียมตัวมาไว้ตรงนี้ครับ:

*   **Offensive Security Certified Professional (OSCP):** [https://www.offsec.com/courses/pen-200/](https://www.offsec.com/courses/pen-200/)
*   **TJNull's OSCP-Like VM List:** [https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=183940215](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=183940215)
*   **Hack The Box:** [https://www.hackthebox.com/](https://www.hackthebox.com/)
*   **OffSec Proving Grounds:** [https://www.offsec.com/labs/proving-grounds/](https://www.offsec.com/labs/proving-grounds/)
