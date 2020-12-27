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
Firstname = <script>alert('hello world')</script>
Lastname  = bar
```

