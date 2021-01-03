## Library requests_safe ทำงานอย่างไร

โดยปกติแล้วเวลาเราทำการเรียกหน้า Web Site ใดๆ บนภาษา Python เราจะใช้ library ตัวหนึ่งชื่อ [Request](https://2.python-requests.org/en/master/) ซึ่งเป็นตัวยอดนิยมที่ Developer มักใช้กันสำหรับส่งค่า HTTP ไปยัง Server ซึ่งสามารถดูรายละเอียดได้ตาม Link ทั้งนี้การเรียกใช้งาน HTTP ไปยังเว็บไซต์ที่ต้องการนั้นเราไม่สามารถทราบได้ว่ามีความปลอดภัยมากน้อยขนาดไหน จึงทำให้มีการพัฒนา library สำหรับการ GET ข้อมุล HTTP ที่มีความปลอดภัยมากยิ่งขึ้นด้วย **requests_safe** ซึ่งจะสามารถตรวจสอบข้อมุล Connection ที่เชื่อมต่อไปหา Server ว่ามีความปลอดภัยหรือไม่ 

วิธีการใช้งานก็ไม่ใช่เรื่องยาก โดยผู้ใช้สามารถ import library ได้เลย 

``` python
import requests_safe
from requests import Session,request
import requests

# การเรียกใช้งานผ่าน : Requests
x = requests.get('https://icesuntisuk.github.io')
print("Response from unsafe > Code "+str(x.status_code))

# การเรียกใช้งานผ่าน : Requests-Safe
with Session() as s:
    requests_safe.apply(s)
    print(s.get("https://icesuntisuk.github.io"))
``` 
ทดสอบ run ด้วย PyCharm จะเห็นว่ามีการ Response  Code 200 เหมือนกัน

![](/KB/img/requests_safe01.png)

จากตัวอย่างด้านบนจะเป็นการทดสอบเรียกไปหาเว็บไซต์เดียวกันด้วยการเรียกผ่าน Method GET เหมือนกัน แต่แตกต่างกันที่วิธีการเรียก โดยบรรทัดด้านบนจะเป็นการเรียกด้วยวิธีปกติ และด้านล่างจะเป็นการเรียกผ่าน **requests_safe** โดยสิ่งที่แตกต่างกันคือ การเรียกผ่าน **requests_safe** จะมีการตรวจสอบ Connection ที่เรียกว่ามีความปลอดภัยหรือไม่ โดยจะตรวจสอบว่า IP ที่เชื่อมต่อด้วยนั้นเป็นหมายเลข IP ที่เป็น Private หรือไม่ โดยสามารถดูรายละเอียดได้ตามลิงค์ด้านล่าง

Reference : [https://pypi.org/project/requests-safe/](https://pypi.org/project/requests-safe)

**Powered By** : 
Icesuntisuk 
๓ ธ.ค.๖๔
