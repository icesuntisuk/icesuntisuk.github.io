## Function requests_safe ทำงานอย่างไร

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

จากตัวอย่างด้านบนจะเป็นการทดสอบเรียกไปหาเว็บไซต์เดียวกันด้วยการเรียกผ่าน Method GET เหมือนกัน แต่แตกต่างกันที่วิธีการเรียก โดยบรรทัด บนจะเป็นการเรียกด้วยวิธีปกติ และด้านล่างจะเป็นการเรียกผ่าน requests_safe โดยสิ่งที่แตกต่างกันคือ การเรียกผ่าน requests_safe จะมีการตรวจสอบ Connection ที่เรียกว่ามีความปลอดภัยหรือไม่ โดยจะตรวจสอบว่า IP ที่เชื่อมต่อด้วยนั้นเป็นหมายเลข IP ที่เป็น Private หรือไม่ ดังตารางต่อไปนี้

## IPv4 unsage network 
|Name |Network (CIDR)|
| ------------------------ |:-------------:|
|RFC1918 (private network) |10.0.0.0/8|
|RFC1918 |172.16.0.0/12|
|RFC1918 |192.168.0.0/16|
|Link-Local |169.254.0.0/16|
|CG-NAT address space |100.64.0.0/10|
|Localhost/loopback |127.0.0.0/8|
|Wildcard IP |0.0.0.0/32|
|IETF Protocol Assignments |192.0.0.0/24|
|TEST-NET-1 |192.0.2.0/24|
|RESERVED |192.88.99.0/24|
|Benchmark testing |198.18.0.0/15|
|TEST-NET-2 |198.51.100.0/24|
|TEST-NET-3 |203.0.113.0/24|
|IP Multicast |224.0.0.0/4|
|RESERVED |240.0.0.0/4|
|Limited broadcast |255.255.255.255/32|

## IPv6 unsage network 
|Name |Network (CIDR)|
| ------------------------ |:-------------:|
|Localhost/unspecified address|::/128|
|Loopback |::1/128|
|IPv4 mapped address |::ffff:0:0/96|
|IPv4 translated addresses |::ffff:0:0:0/96|
|IPv4/IPv6 translation |64:ff9b::/96|
|Discard prefix |100::/64|
|Teredo tunneling |2001::/32|
|Orchid v2 (abondoned)|2001:20::/28|
|Documentation |2001:db8::/32|
|6to4 addressing scheme|2002::/16|
|ULA address space |fc00::/7|
|Link-local address space|fe80::/10|
|Global multicast |ff00::/8|

Reference : [https://pypi.org/project/requests-safe/](https://pypi.org/project/requests-safe)

**Powered By** : 
Icesuntisuk 
๓ ธ.ค.๖๔
