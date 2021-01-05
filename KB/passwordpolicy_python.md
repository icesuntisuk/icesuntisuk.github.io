## การทำ Password Policy สำหรับการตั้ง Password ด้วย Python

ปัจจุบันการตั้งค่า Password เป็นปัญหาค่อนข้างมากในงานด้าน Security เนื่องจากผู้ใช้งานส่วนใหญ่มักไม่นึกถึงความปลอดภัยในการตั้งค่ารหัสผ่านเท่าที่ควร ซึ่งจะเห็นได้จาก Report ต่างๆ บนโลก Internet ที่มักจะรายงาน Password ที่อ่อนแอออกมาให้เราได้เห็นอยู่บ่อยๆ ยกตัวอย่างเช่น 
* 123456
* 123456789
* password
* 12345678
* 111111
 
 จะเห็นได้ว่าการตั้งค่า Password ให้กับระบบจึงมักเป็นเรื่องที่ผู้พัฒนาจำเป็นต้องคำนึงถึงเป็นลำดับต้นๆ ฉะนั้นในบทความนี้ผมจะพาไปดูวิธีการเขียนโปรแกรมในภาษา Python โดยใช้ Library ชื่อ **Password-Strength** ซึ่งจะช่วยให้เราสามารถตั้งค่านโยบายการตั้ง Password ให้มีความปลอดภัยมากยิ่งขึั้น 

``` python
from password_strength import PasswordPolicy

policy = PasswordPolicy.from_names(
    length=8,  # min length: 8
    uppercase=2,  # need min. 2 uppercase letters
    numbers=2,  # need min. 2 digits
    special=2,  # need min. 2 special characters
    nonletters=2,  # need min. 2 non-letter characters (digits, specials, anything)
)
print("Bad Password[123456]: " + str(policy.test('123456')))
print("Good Password[]: " + str(policy.test('Ic3Sunt1suk.github.io')))
```

**ผลการทดสอบ**

 ![](/KB/img/passwordpolicy.png)

 จะสังเกตได้ว่าเมื่อเราใส่ค่า Password ที่มีความง่ายตัวของ Library จะคืนค่าที่เป็น List ออกมาให้ตามเงี่อนไขที่เราได้กำหนด แต่หากเรากำหนดรหัสผ่านที่มีความปลอดภัยก็จะส่ง List ที่ไม่มีข้อมูลใดๆ กลับมา ซึ่งผู้พัฒนาสามารถนำไปต่อยอดเพื่อให้โปรแกรมของตนมีความปลอดภัยได้ตามที่ต้องการ

Reference : 
* [Password-strength](https://pypi.org/project/password-strength/)
* [List of the most common passwords@wiki](https://en.wikipedia.org/wiki/List_of_the_most_common_passwords)