# การสร้าง UUID บน Python

สำหรับการพัฒนาซอฟต์แวร์ปัจจุบันจะต้องคำนึงถึงการ Identify ผู้ใช้งานด้วยวิธีการต่างๆ ซึ่งเราจะเห็นได้ว่าผู้ใช้งานแต่ละคนจะมีอุปกรณ์ที่แตกต่างกันออกไป ทำให้ยากต่อการระบุตัวตนผู้ใช้สำหรับเข้าใช้งานระบบที่นักพัฒนาได้สร้างขึ้น จึงมีแนวคิดในการสร้าง Unique Identify ขึ้นมาบนระบบเพื่อตอบสนองการใช้งานที่คล่องตัวมากยิ่งขึ้น กล่าวคือเมื่อผู้ใช้งานใช้ระบบจากอุปกรณ์ใดๆก็ตามระบบจะสร้างสิ่งที่เรียกว่า UUID (Universally Unique Identifier) ซึ่งมีไว้เพื่อสร้างตัวเลขประจำตัวให้กับข้อมูล, อุปกรณ์, หรือสิ่งใดๆ ก็ตามที่ต้องการการอ้างอิง ซึ่งจากตัวอย่างด้านบนจะเป็นการอ้างอิงถึงอุปกรณ์ของผู้ใช้แต่ละอุปกรณ์นั่นเอง ซึ่งผู้ออกแบบระบบสามารถออกแบบให้ผู้ใช้มี UUID เดียวในแต่ละอุปกรณ์หรืออาจจะมีหลาย UUID โดยแยก UUID ในแต่ละอุปกรณ์ก็ได้ ซึ่งจะขึ้นอยู่กับการออกแบบของผู้พัฒนา

## UUID - Universally Unique Identifier
เป็นหมายเลขขนาด 128 bit ซึ่งปัจจุบันมีด้วยกันทั้งสิ้น 5 version ซึ่งจะมี Format 

xxxxxxxx-xxxx-**M**xxx-**N**xxx-xxxxxxxxxxxx

สังเกตตัว **M** จะเป็นหมายเลขของ Version ของ UUID ที่ใช้ และ **N** จะเป็น Variant หรือตัวเลขระบุการอิมพลีเมนต์ที่ต่างกัน

สำหรับ Version จะมีรายละเอียดดังต่อไปนี้ (Reference : [blognone](https://www.blognone.com/node/51679) )

**version 1**: ใช้หมายเลข MAC ของเครื่องมาเติมลงใน 6 หลักแรกของหมายเลข UUID และที่เหลือให้เติมด้วยตัวเลขเวลาของเครื่อง ปัญหาของ UUID เวอร์ชั่นนี้คือการเปิดเผยหมายเลขเครื่อง ซึ่งหลายครั้งกลายเป็นปัญหาความปลอดภัย ข้อดีสำคัญของการสร้างหมายเลขรูปแบบนี้คือในเครื่องเดียวกันจะไม่มีทางซ้ำกันได้แน่นอน (เพราะสร้างคนละเวลากัน)
**version 2**: เพิ่มฟิลด์ที่สองเป็นหมายเลขโปรเซสขณะที่สร้างหมายเลขอยู่การออกแบบต้องการให้หมายเลขที่สร้างขึ้นไม่ซ้ำกันในทุกครั้งที่รันโปรเซสแต่ในโลกความเป็นจริงหมายเลขโปรเซสนั้นซ้ำกันได้ง่ายมากทำให้รูปแบบนี้ไม่ได้รับความนิยมอีกต่อไป
**version 3**: เป็นค่า MD5 ของค่าประจำเครื่องนั้นๆ ค่าที่เป็นไปได้ ได้แก่ URL, โดเมนเนมแบบเต็ม, ค่า distinguished name ของ LDAP, หรือชื่อเฉพาะของระบบในระบบการตั้งชื่อใดๆ ค่า MD5 นั้นปกติจะให้ค่ายาว 128 บิตพอดี มาตรฐาน UUID ระบุให้ใช้ค่า M และ N แทนลงไปใน MD5 เลย การใช้ MD5 สามารถใช้เพื่อปกปิดชื่อที่แท้จริงของระบบได้ในกรณีที่ไม่ต้องการเปิดเผยชื่อที่แท้จริง แต่การใช้งานโดยมากถูกแทนที่โดย version 5 แล้ว
**version 4**: ค่าสุ่มอย่างสมบูรณ์ ทุกบิตยกเว้น M และ N จะถูกสุ่มมา การสร้างหมายเลขแต่ละครั้งไม่มีการรับประกันว่าจะซ้ำกับตัวสร้างอื่นๆ หรือไม่ แต่ความน่าจะเป็นที่จะซ้ำก็ต่ำมาก
**version 5**: เหมือน version 3 แต่เนื่องจาก MD5 อ่อนแอลงมากในช่วงหลัง ทำให้แฮกเกอร์อาจจะเปิดเผยชื่อที่แท้จริงได้ จึงให้ใช้ SHA-1 แทนที่ เนื่องจาก SHA-1 ให้ค่าแฮช 160 บิต จึงได้ตัดออกเหลือ 128 บิต

ในการทดสอบเราจะใช้ Python สำหรับสร้าง UUID บนเครื่องคอมพิวเตอร์ ทั้งนี้บน Python จะรองรับ version 1, 3, 4 และ 5 เท่านั้น
``` python
import uuid
print("UUID Ver 1 : " + str(uuid.uuid1()))
print("UUID Ver 3 : " + str(uuid.uuid3(uuid.NAMESPACE_DNS, 'icesuntisuk.github.io')))
print("UUID Ver 4 : " + str(uuid.uuid4()))
print("UUID Ver 5 : " + str(uuid.uuid5(uuid.NAMESPACE_DNS, 'icesuntisuk.github.io')))
``` 
ผลการทดสอบ 
![](/KB/img/uuid.png)

จะเห็นได้ว่าตัวเลขในแต่ละ Version จะมีความแตกต่างกันไป ทั้งนี้นักพัฒนาสามารถนำ UUID ไป Identify อุปกรณ์หรือระบุถึงตัวผู้ใช้ในระบบได้ตามความเหมาะสม ซึ่ง UUID เป็นเพียงหนึ่งวิธีที่จะช่วยใช้ชีวิตของนักพัฒนามีความง่ายยิ่งขึ้น 

**Powered By** : 
Icesuntisuk 
๓ ธ.ค.๖๔