# การ Encode/Decode Base64 ด้วย Python

Base64 เป็นรูปแบบการแปลงค่าข้อมูลจาก Binary เป็น Text ซึ่งเป็นการทำงานเบื้องหลังของคอมพิวเตอร์ เนื่องจากคอมพิวเตอร์นั้นไม่สามารถอ่านค่า Text ได้จึงจำเป็นต้องแปลงค่าจาก Text ให้เป็นข้อมูล Binary หรือตัวเลข 0,1 เพื่อสามารถนำข้อมูลไปประมวลผลต่อไป โดยในบางครั้งเราจะพบกับ Payload การโจมตีทาง Cyber ในรูแแบบของการแปลงข้อมูลเป็น Base64 อยู่บ่อยๆ ซึ่งผู้ไม่ประสงค์ดีอาจจะแทรกข้อมูลที่ผิดปกติบนไฟล์ที่เราส่งอยู่ในเครือข่าย ฉะนั้นการแกะข้อมูลไฟล์หรือข้อมูลการจราจรบนเครือข่ายในบางครั้งจะอยู่ในรูปแบบ Base64 ซึ่งผู้ดูแลระบบหรือทีม CSIRT จะต้องสามารถตรวจสอบข้อมูลได้อย่างทันถ้วงที

บทความนี้จะเป็นวิธีการแปลงข้อมูลไปมาระหว่าง Text ไปเป็น Binary เพื่อให้ทราบถึงวิธีการแปลงข้อมูลบนภาษา Python 

``` python
import base64
data = "icesuntisuk.github.io"
# Encode
encodedBytes = base64.b64encode(data.encode("utf-8"))
encodedStr = str(encodedBytes, "utf-8")
print("Encode text: " + encodedStr)
# Decode
print("Decode text: "+str(base64.b64decode(encodedStr),"utf-8"))
```

**ผลการทดสอบ**

![](/KB/img/base64.png)

สำหรับการ Encode/Decode นั้นยังมีเครื่องมืออื่นๆ ที่สามารถใช้ได้อีกมากมาย ผมขอยกตัวอย่างเช่น [CyberChef](https://gchq.github.io/CyberChef/) เป็นต้น


**Powered By** : 
Icesuntisuk 
๖ ธ.ค.๖๔