# การดึงค่าเวลาจาก NTP Server ด้วย Python

เวลาเป็นสิ่งสำคัญสำหรับระบบทุกระบบ หากเวลาในระบบมีความไม่ถูกต้องหรือไม่เหมือนกันก็จะส่งผลให้การตรวจสอบปัญหาหรือ Transaction ผิดพลาดได้ ฉะนั้นการดึงค่าเวลาจึงเป็นเรื่องที่สำคัญในงานด้าน Security สำหรับวันนี้ผมจะมากล่าวถึง Library ชื่อ ntplib ซึ่งจะสามารถดึงค่าเวลาจาก NTP Server ที่เรา Trust ได้ 

สำหรับการใช้งาน ntplib สามารถใช้คำสั่ง import ntplib เพื่อมาใช้โดยเราสามารถระบุ URL ของ NTP Server ได้ เพื่อไปดึงข้อมูลเวลาตามที่เราต้องการ โดยในตัวอย่างจะทำการเปรียบเทียบการดึงข้อมูลจากเครื่องคอมพิวเตอร์กับการดึงข้อมูลจาก NTP Server โดยจะใช้ของกองทัพเรือเป็น Server อ้างอิงค่าเวลา

``` python
import ntplib
from time import ctime
from datetime import datetime

now = datetime.now()
print("Date from machine:", now)

c = ntplib.NTPClient()
response = c.request('time2.navy.mi.th')
print("Date from NTP:"+str(ctime(response.tx_time)))
```
**ผลการทดสอบ**

![](/KB/img/ntp.png)

สังเกตดูว่าเวลาที่ได้จะแตกต่างกันในหลักวินาที แต่ข้อดึของการดึงค่าของ NTP คือเวลาเราจะเป็นสากล อีกทั้งมีโอกาสที่เครื่องเซิฟเวอร์หรือเครื่องคอมพิวเตอร์จะมีปัญหาและส่งผลให้เวลาของระบบผิดพลาดได้

**Powered By** : 
Icesuntisuk 
๔ ธ.ค.๖๔