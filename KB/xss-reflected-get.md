# XSS-Reflected(GET)

สำหรับบทความนี้จะเป็นการ POC XSS-Reflected(GET) บน bWAPP 

Step 1: Go to Cross-site-Scripting-Reflected(GET) จาก Drop-Down จากนั้นเลือก Hack
![](/KB/img/xss-get-01.jpg)

Step 2: ภายใน XSS-Reflected(GET) จะมีช่องให้ใส่ Firstname และ Lastname ซึ่งเมื่อทดสอบใส่ค่าชื่อ foo/bar ก็จะขึ้นข้อความด้านล่างเป็น Welcome foo bar
![](/KB/img/xss-get-02.jpg)

Step 3: ถ้าสังเกตดีๆ จะเห็นในช่อง URL มีค่าของ Firstname และ Lastname ที่เราได้กรอกไปก่อนหน้า
![](/KB/img/xss-get-03.jpg)

Step 4: แล้วถ้าหากเราใส่ Tag ไว้ในช่องละจะเกิดอะไรขึ้น 
``` html
Firstname = <font size='50'>Hack</font>
Lastname  = <font size='50' color='#f00'>XXS</font>
```
![](/KB/img/xss-get-04.jpg)

จากภาพแสดงให้เห็นว่าเราสามารถแทรกบางสิ่งบางอย่างลงไปได้

Step 5: คราวนี้เราลองใส่ 
``` html
Firstname = <script>alert('HACK')</script>
Lastname  = bar
```
![](/KB/img/xss-get-05.jpg)
จะเห็นได้ว่าเราสามารถยัด Script อะไรก็ได้เข้าไปในช่องใส่ ซึ่งรวมถึง Shell ด้วย


Step 6: ในขั้นตอนนี้เราต้องเข้าไปดูที่ไฟล์ xss_get.php ของเราเพื่อไปดูว่า Code ของเรามีส่วนไหนที่ผิดปกติ โดยเราสามารถใช้ WinSCP เพื่อเข้าไปดู Path ของ Code เรา
![](/KB/img/xss-get-06.jpg)


Step 7: เมื่อได้ Path ของ Code เราก็สามารถตรวจสอบด้วย rips เพื่อหา Vulnerability ภายใน Code จากโปรแกรม rips ซึ่งเป็น Static Web Scan ซึ่งสามารถกด **Scan** ได้เลยเมื่อใส่ข้อมุล Path ถูกต้อง
![](/KB/img/xss-get-07.jpg)

Step 8: เมื่อ Scan เสร็จเรียบร้อยเราสามารถเห็นได้ว่า Code มีช่องโหว่อะไรบ้าง ซึ่งเราสามารถเลือก Help เพื่อตรวจสอบวิธีการแก้ไข Code
![](/KB/img/xss-get-08.jpg)

Step 9: จากนั้นทำการแก้ไข Code โดยในที่นี้ให้ใส่ Function เพิ่มเติมไปในส่วนที่โปรแกรม Rips ได้แจ้งให้เราทราบ ในที่นี้เราจะใช้ Function **htmlentities**
![](/KB/img/xss-get-09.jpg)

Step 10: เข้าไปแก้ไข Code ของเราตาม Help ได้เลยครับ

**ก่อนใส่**
![](/KB/img/xss-get-10.jpg)

**หลังใส่**
![](/KB/img/xss-get-11.jpg)

Step 11: ลอง Scan ด้วย Rips อีกครั้ง จะเห็นได้ว่าช่องโหว่ของเราได้หายไปแล้ว 
![](/KB/img/xss-get-12.jpg)

**Powered By** : 
Icesuntisuk and Sakarin
๒๗ ธ.ค.๖๓