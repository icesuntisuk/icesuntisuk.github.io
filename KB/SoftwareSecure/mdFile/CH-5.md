# CH-5: Input Validation และ Injection Attacks



---

## วัตถุประสงค์การเรียนรู้

เมื่อจบบทนี้นักศึกษาสามารถ:

1. อธิบายหลักการของ Input Validation, Sanitization, Output Encoding และ Parameterization รวมถึงความแตกต่างของแต่ละแนวทางได้อย่างถูกต้อง
2. วิเคราะห์ได้ว่าข้อมูลนำเข้าจากผู้ใช้ ไฟล์ คุกกี้ HTTP Header API ภายนอก และฐานข้อมูลเดิมล้วนต้องถือว่าไม่น่าเชื่อถือจนกว่าจะตรวจสอบ
3. อธิบายกลไกของ Injection Attacks ที่เกิดจากการปะปนระหว่าง “ข้อมูล” กับ “คำสั่ง” ในบริบท SQL, NoSQL, OS Command, LDAP, XPath, Template และ Browser Script
4. อธิบายและจำแนก SQL Injection ประเภท In-band, Blind และ Out-of-band รวมถึง Second-order SQL Injection และ NoSQL Injection
5. ใช้ Parameterized Query, Prepared Statement, Safe ORM Usage และ Least Privilege เพื่อลดความเสี่ยง SQL Injection ได้
6. อธิบาย Cross-Site Scripting (XSS) ประเภท Reflected, Stored และ DOM-based พร้อมเลือกใช้ Context-aware Output Encoding, Safe DOM API และ Content Security Policy ได้เหมาะสม
7. อธิบาย Command Injection, Server-side Template Injection, File Upload Vulnerability และ CSRF พร้อมแนวทางป้องกันแบบ Defense in Depth
8. ใช้ WebGoat, OWASP Juice Shop, DVWA หรือ toy application ภายในเครื่องเพื่อเรียนรู้ วิเคราะห์ และแก้ไขช่องโหว่อย่างถูกต้องตามจริยธรรม
9. แปลงผลการค้นพบช่องโหว่เป็น Security Requirement, Secure Coding Guideline, Test Case และ Checklist ก่อนส่งมอบซอฟต์แวร์ได้

---

## ขอบเขตและข้อกำหนดด้านจริยธรรมของบทนี้

บทนี้มีตัวอย่างเกี่ยวกับช่องโหว่ Injection และ XSS เพื่อการเรียนรู้เชิงป้องกันเท่านั้น กิจกรรมปฏิบัติการทั้งหมดต้องทำในสภาพแวดล้อมที่ได้รับอนุญาต เช่น WebGoat, OWASP Juice Shop, DVWA หรือ toy application ที่รันในเครื่องของนักศึกษาเอง ห้ามนำเทคนิคในบทนี้ไปทดสอบกับเว็บไซต์ ระบบ API ฐานข้อมูล หรือระบบของบุคคลอื่นโดยไม่ได้รับอนุญาตเป็นลายลักษณ์อักษร

**ข้อควรจำ:** เป้าหมายของบทนี้คือให้นักศึกษารู้ว่าช่องโหว่เกิดขึ้นอย่างไร เพื่อออกแบบ เขียน ทดสอบ และรีวิวโค้ดให้ปลอดภัย ไม่ใช่เพื่อฝึกโจมตีระบบจริง

---

## แผนการเรียนรู้สำหรับบท 6 ชั่วโมง

| ช่วงเวลา | หัวข้อ | เป้าหมายการเรียนรู้ | กิจกรรมในชั้นเรียน |
|----------|--------|----------------------|----------------------|
| ชั่วโมงที่ 1 | Input Validation และภาพรวม Injection | เข้าใจ trust boundary, untrusted input และการแยกข้อมูลออกจากคำสั่ง | วิเคราะห์ตัวอย่าง request ที่มาจาก form, header, cookie, file และ webhook |
| ชั่วโมงที่ 2 | SQL Injection และ NoSQL Injection | เข้าใจสาเหตุ การจำแนกประเภท และการป้องกันด้วย parameterization | เปรียบเทียบ vulnerable query กับ prepared statement |
| ชั่วโมงที่ 3 | XSS และ Output Encoding | แยก Reflected, Stored, DOM-based XSS และเลือก encoding ตามบริบท | วิเคราะห์ source/sink และ output context |
| ชั่วโมงที่ 4 | Command, LDAP, XPath, Template Injection | เข้าใจ injection นอกบริบทฐานข้อมูลและ browser | วิเคราะห์ command execution และ template rendering ใน toy app |
| ชั่วโมงที่ 5 | File Upload, CSRF, CSP และ Defense in Depth | เข้าใจการป้องกันหลายชั้นและข้อจำกัดของแต่ละมาตรการ | ทำ checklist ก่อน deploy และออกแบบ CSP เบื้องต้น |
| ชั่วโมงที่ 6 | Lab และ Secure Code Review | แก้โค้ดและสร้าง test case จากช่องโหว่ | ทำ lab, สรุป finding และเสนอ remediation |

---

## เนื้อหา

### 5.1 ภาพรวม Input Validation และ Injection Attacks

Input Validation คือกระบวนการตรวจสอบข้อมูลที่เข้าระบบว่ามีชนิด รูปแบบ ความยาว ช่วงค่า โครงสร้าง และความหมายตรงตามที่ระบบคาดหวังหรือไม่ ในบริบท Software Security ข้อมูลนำเข้าทุกชนิดต้องถือว่าไม่น่าเชื่อถือ แม้ข้อมูลนั้นจะไม่ได้มาจากช่องกรอกฟอร์มโดยตรงก็ตาม

#### 5.1.1 ข้อมูลนำเข้ามาจากที่ใดบ้าง

ข้อมูลที่ต้องตรวจสอบไม่ได้มีเฉพาะข้อมูลจากผู้ใช้หน้าเว็บ แต่รวมถึง:

- Query string เช่น `?id=123`
- Request body เช่น JSON, XML, form data
- HTTP Header เช่น `User-Agent`, `Referer`, `X-Forwarded-For`
- Cookie และ session-related value
- File upload และ metadata ของไฟล์
- URL path parameter เช่น `/users/123`
- Webhook และ callback จาก third-party
- Message queue และ event stream
- ข้อมูลจากฐานข้อมูลเดิมที่อาจถูกป้อนเข้ามาในอดีต
- ข้อมูลจาก log, cache, CSV, spreadsheet หรือ configuration file

**หลักสำคัญ:** ข้อมูลที่ “เคยถูกบันทึกไว้แล้ว” ไม่ได้แปลว่าปลอดภัย เพราะอาจเกิด Second-order Injection เมื่อข้อมูลอันตรายถูกบันทึกไว้ก่อน แล้วถูกนำไปใช้ในบริบทอันตรายในภายหลัง

#### 5.1.2 Injection เกิดขึ้นได้อย่างไร

Injection Attack เกิดเมื่อระบบนำข้อมูลที่ไม่น่าเชื่อถือไปประกอบเข้ากับคำสั่งหรือภาษาที่มีตัวแปลความหมาย เช่น SQL, shell command, HTML, JavaScript, LDAP filter, XPath query หรือ template expression โดยไม่แยก “ข้อมูล” ออกจาก “คำสั่ง” ให้ชัดเจน

ตัวอย่างแนวคิด:

```
ข้อมูลผู้ใช้ + คำสั่งของระบบ = คำสั่งใหม่ที่ผู้โจมตีควบคุมบางส่วน
```

ใน SQL Injection ผู้โจมตีพยายามทำให้ข้อมูลที่ส่งเข้ามาถูกตีความเป็นส่วนหนึ่งของ SQL statement ใน XSS ผู้โจมตีพยายามทำให้ข้อมูลที่แสดงในหน้าเว็บถูกตีความเป็น script ใน Command Injection ผู้โจมตีพยายามทำให้ข้อมูลที่ควรเป็น argument กลายเป็น shell command เพิ่มเติม

#### 5.1.3 Injection ใน OWASP Top 10 2021

OWASP Top 10 2021 จัด Injection อยู่ในหมวด **A03: Injection** และรวม Cross-Site Scripting (XSS) ไว้ในหมวดนี้ด้วย เนื่องจาก XSS เป็นการฉีด script เข้าไปในบริบทของ browser เพื่อให้ browser ของเหยื่อรันคำสั่งที่ผู้โจมตีควบคุม

**ตัวอย่างชนิด Injection ที่ควรรู้จัก:**

| ประเภท | บริบทที่ถูกฉีด | ผลกระทบทั่วไป |
|--------|----------------|----------------|
| SQL Injection | คำสั่ง SQL | อ่าน/แก้ข้อมูล, bypass login, ทำลายข้อมูล |
| NoSQL Injection | Query object หรือ operator | bypass query, อ่านข้อมูลเกินสิทธิ์ |
| XSS | HTML/JavaScript ใน browser | ขโมย session, สวมรอยผู้ใช้, แก้หน้าเว็บ |
| OS Command Injection | Shell หรือคำสั่งระบบปฏิบัติการ | รันคำสั่งบน server |
| LDAP Injection | LDAP filter | bypass authentication, อ่าน directory |
| XPath Injection | XPath query | อ่าน XML data เกินสิทธิ์ |
| Server-side Template Injection | Template engine | อ่านข้อมูลหรือรันโค้ดบน server |
| Header Injection | Email/HTTP header | เพิ่ม header, ส่ง email ปลอม, response splitting |

---

### 5.2 Validation, Sanitization, Encoding และ Parameterization

คำสี่คำนี้มักถูกใช้ปะปนกัน แต่มีหน้าที่ต่างกันอย่างชัดเจน

| เทคนิค | ใช้เมื่อใด | เป้าหมาย | ตัวอย่าง | ข้อจำกัด |
|--------|-----------|----------|----------|----------|
| Validation | ตอนรับข้อมูล | ตรวจว่าข้อมูลตรงรูปแบบที่อนุญาต | ตรวจว่า age เป็นเลข 0-120 | ไม่พอสำหรับ SQL Injection และ XSS หากนำข้อมูลไปใช้ผิดบริบท |
| Sanitization | เมื่อต้องยอมรับข้อมูลบางส่วน | ลบหรือปรับส่วนที่ไม่ปลอดภัย | ล้าง HTML ที่ผู้ใช้ใส่ใน comment | เสี่ยงหากกฎไม่ครบหรือ parser ไม่ถูกต้อง |
| Output Encoding | ก่อนแสดงผล | ทำให้ข้อมูลไม่ถูกตีความเป็นโค้ด | แปลง `<` เป็น entity ใน HTML context | ต้องตรงบริบทเสมอ |
| Parameterization | ก่อนส่งคำสั่งไปยัง interpreter | แยกข้อมูลออกจากคำสั่ง | Prepared statement ใน SQL | ใช้ไม่ได้กับทุกตำแหน่ง เช่น ชื่อตารางหรือชื่อ column |

#### 5.2.1 Allowlist vs Blocklist

| ประเด็น | Allowlist | Blocklist |
|---------|-----------|-----------|
| หลักคิด | ระบุสิ่งที่อนุญาต | ระบุสิ่งที่ห้าม |
| เหมาะกับ | ข้อมูลที่รูปแบบชัดเจน เช่น รหัสนักศึกษา วันที่ เบอร์โทร | ใช้เสริมสำหรับ pattern ที่รู้จัก |
| ตัวอย่าง | อนุญาตเฉพาะตัวเลข 10 หลัก | ห้าม `'`, `--`, `<script>` |
| จุดแข็ง | ควบคุมได้ชัดเจนกว่า | ใช้เร็วกับเคสง่าย |
| จุดอ่อน | ต้องนิยามรูปแบบให้ครบ | ถูก bypass ง่ายด้วย encoding, case, unicode, alternative syntax |
| คำแนะนำ | ใช้เป็นหลัก | ไม่ควรเป็นแนวป้องกันหลัก |

#### 5.2.2 Client-side Validation และ Server-side Validation

Client-side validation ช่วยให้ผู้ใช้เห็นข้อผิดพลาดเร็วและลด request ที่ไม่จำเป็น แต่ไม่ถือเป็นมาตรการความปลอดภัยหลัก เพราะผู้โจมตีสามารถแก้ JavaScript, ใช้ proxy, ส่ง API request โดยตรง หรือเขียน client เองได้

Server-side validation เป็นสิ่งจำเป็นเสมอ เพราะเป็นจุดที่องค์กรควบคุมได้จริง ข้อมูลทุกอย่างที่เข้าสู่ backend ต้องถูกตรวจสอบตาม schema และ business rule

**ตัวอย่าง:**

| ข้อมูล | Client-side Validation | Server-side Validation ที่ต้องมี |
|--------|------------------------|----------------------------------|
| จำนวนสินค้า | ห้ามใส่ค่าติดลบใน UI | ตรวจว่าเป็นจำนวนเต็ม 1-99 และ stock เพียงพอ |
| ราคา | ไม่ควรให้ผู้ใช้แก้ราคา | คำนวณราคาที่ server จาก product catalog เท่านั้น |
| อีเมล | ตรวจรูปแบบเบื้องต้น | ตรวจความยาว รูปแบบ normalization และ uniqueness |
| ไฟล์อัปโหลด | จำกัด extension ในหน้าเว็บ | ตรวจชนิดไฟล์จริง ขนาด ชื่อ ตำแหน่งจัดเก็บ และสิทธิ์ |

#### 5.2.3 Canonicalization และปัญหา Encoding

Canonicalization คือการแปลงข้อมูลให้อยู่ในรูปแบบมาตรฐานก่อนตรวจสอบ เช่น แปลง path, URL encoding, unicode normalization หรือการตัด whitespace ที่ไม่จำเป็น หากตรวจสอบก่อน canonicalization ผู้โจมตีอาจใช้ encoding หลบกฎตรวจจับได้

ตัวอย่างปัญหา:

- URL encoded character ทำให้ blocklist ตรวจไม่เจอ
- Unicode character ที่ดูคล้ายกันทำให้เกิด homograph confusion
- Path traversal ที่ใช้รูปแบบ path หลายแบบเพื่อหลบ validation
- ข้อมูลที่ถูก decode หลายรอบทำให้ผลลัพธ์หลัง decode เป็นอันตราย

**แนวทาง:** แปลงเป็นรูปแบบมาตรฐานก่อน validation และต้องระวังไม่ decode ซ้ำโดยไม่จำเป็น เพราะอาจสร้างช่องโหว่ใหม่

---

### 5.3 SQL Injection

SQL Injection เป็นช่องโหว่ที่เกิดเมื่อระบบสร้าง SQL statement โดยนำข้อมูลผู้ใช้ไปต่อเป็น string แล้วส่งให้ฐานข้อมูลตีความ ทำให้ผู้โจมตีสามารถเปลี่ยนความหมายของ query ได้

#### 5.3.1 ตัวอย่างโค้ดที่มีช่องโหว่

ตัวอย่างนี้ใช้เพื่อการเรียนใน toy application เท่านั้น:

```python
# ไม่ปลอดภัย: อย่าใช้ในระบบจริง
username = request.form["username"]
password = request.form["password"]

sql = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
cursor.execute(sql)
```

ปัญหาคือ `username` และ `password` ถูกนำไปเป็นส่วนหนึ่งของ SQL โดยตรง หากข้อมูลผู้ใช้มี syntax ที่ database ตีความเป็นคำสั่ง ความหมายของ query จะเปลี่ยนไป

#### 5.3.2 โค้ดที่ปลอดภัยด้วย Parameterized Query

```python
# ปลอดภัยกว่า: แยกข้อมูลออกจากคำสั่ง
username = request.form["username"]
password = request.form["password"]

sql = "SELECT * FROM users WHERE username = ? AND password_hash = ?"
cursor.execute(sql, (username, password_hash))
```

Prepared statement ทำให้ database รู้ว่าโครงสร้างคำสั่งคืออะไร และ parameter เป็นข้อมูล ไม่ใช่ SQL syntax เพิ่มเติม นี่คือเหตุผลหลักที่ parameterized query ป้องกัน SQL Injection ได้ดีกว่าการต่อ string

#### 5.3.3 ประเภทของ SQL Injection

| ประเภท | ลักษณะ | สิ่งที่ควรสอน |
|--------|--------|----------------|
| In-band SQLi | ผลลัพธ์กลับมาทาง response เดียวกัน | เห็นผลชัด เหมาะกับ demo ใน lab |
| Error-based SQLi | ใช้ error message เพื่อเรียนรู้โครงสร้างฐานข้อมูล | ห้ามแสดง error ภายในต่อผู้ใช้ |
| Union-based SQLi | ใช้ `UNION` รวมผลลัพธ์จาก query อื่น | แสดงความเสี่ยงของข้อมูลรั่ว |
| Blind Boolean-based SQLi | อนุมานจาก true/false ของ response | สอนการคิดเชิงตรรกะของผู้โจมตี |
| Blind Time-based SQLi | อนุมานจากเวลาตอบสนอง | แสดงว่าช่องโหว่อาจมีแม้ไม่เห็น error |
| Out-of-band SQLi | ใช้ช่องทางอื่นส่งข้อมูลออก | อธิบายเชิงแนวคิด ไม่จำเป็นต้องทำ lab อันตราย |
| Second-order SQLi | payload ถูกบันทึกก่อน แล้วเกิดผลเมื่อถูกใช้ภายหลัง | ย้ำว่าข้อมูลจาก database ก็ต้องถือว่าไม่น่าเชื่อถือ |

#### 5.3.4 Stored Procedure และ ORM ปลอดภัยเสมอหรือไม่

Stored Procedure ปลอดภัยเมื่อใช้ parameter อย่างถูกต้อง แต่ยังเสี่ยงหากภายใน stored procedure สร้าง dynamic SQL จากข้อมูลผู้ใช้

ORM ช่วยลดความเสี่ยงเพราะมักสร้าง parameterized query ให้โดยอัตโนมัติ แต่ยังเกิดช่องโหว่ได้เมื่อใช้ raw query หรือ string interpolation อย่างไม่ปลอดภัย

| วิธี | ปลอดภัยเมื่อ | ยังเสี่ยงเมื่อ |
|------|--------------|---------------|
| Prepared Statement | ใช้ parameter จริง ไม่ต่อ string | ใช้ string interpolation สร้าง SQL ก่อนส่ง |
| Stored Procedure | ใช้ parameter และไม่สร้าง dynamic SQL | ต่อ string ภายใน procedure |
| ORM Query Builder | ใช้ API ของ ORM ตามปกติ | ใช้ raw SQL จากข้อมูลผู้ใช้ |
| Escaping | ใช้เป็น fallback ตาม library ที่ถูกต้อง | ใช้ manual escaping หรือไม่ครอบคลุม encoding |

#### 5.3.5 Least Privilege สำหรับฐานข้อมูล

แม้จะใช้ parameterized query แล้ว ก็ยังควรลดผลกระทบด้วย database least privilege:

- บัญชีของ application ไม่ควรใช้สิทธิ์ database admin
- แยกบัญชีสำหรับ read-only และ write operation หากทำได้
- จำกัดสิทธิ์เฉพาะ table หรือ view ที่จำเป็น
- ห้าม application account มีสิทธิ์ `DROP`, `ALTER` หรือสิทธิ์จัดการ user หากไม่จำเป็น
- ใช้ view หรือ stored procedure เพื่อลดการเข้าถึงข้อมูลดิบในบางกรณี
- เปิด audit log สำหรับ query ที่ผิดปกติหรือ action สำคัญ

---

### 5.4 NoSQL Injection

NoSQL Injection เกิดเมื่อระบบให้ผู้ใช้ควบคุมโครงสร้าง query หรือ operator ของ NoSQL database เช่น MongoDB โดยไม่ตรวจ schema และชนิดข้อมูลอย่างเข้มงวด

#### 5.4.1 ตัวอย่างแนวคิด

ระบบคาดหวัง JSON แบบนี้:

```json
{
  "username": "alice",
  "password": "secret"
}
```

แต่ถ้า backend นำ object จากผู้ใช้ไปใช้เป็น query โดยตรง ผู้โจมตีอาจส่ง object ที่มี operator ของฐานข้อมูลเข้ามาแทน string ธรรมดาได้

#### 5.4.2 แนวทางป้องกัน NoSQL Injection

- ตรวจ schema ของ request body อย่างเข้มงวด
- บังคับ type เช่น `username` ต้องเป็น string ไม่ใช่ object
- ไม่ส่ง object จากผู้ใช้เข้า query โดยตรง
- จำกัด operator ที่ application อนุญาตให้ใช้
- ใช้ query builder หรือ API ที่แยกข้อมูลออกจาก query structure
- ใช้ least privilege กับ database account
- log query pattern ที่ผิดปกติ

---

### 5.5 Cross-Site Scripting (XSS)

XSS คือช่องโหว่ที่ทำให้ browser ของผู้ใช้รัน script ที่ผู้โจมตีควบคุมในบริบทของเว็บไซต์ที่เหยื่อเชื่อถือ ผลกระทบอาจรวมถึงขโมย session, สวมรอยผู้ใช้, แก้เนื้อหาหน้าเว็บ, อ่านข้อมูลที่หน้าเว็บเข้าถึงได้ หรือทำลายกลไกป้องกัน CSRF

#### 5.5.1 ประเภทของ XSS

| ประเภท | ลักษณะ | ตัวอย่าง |
|--------|--------|----------|
| Reflected XSS | payload มาจาก request แล้วสะท้อนใน response ทันที | ช่องค้นหาแสดงคำค้นโดยไม่ encode |
| Stored XSS | payload ถูกบันทึกในระบบแล้วแสดงให้ผู้ใช้คนอื่น | comment, profile, review |
| DOM-based XSS | ช่องโหว่เกิดจาก JavaScript ฝั่ง browser ใช้ข้อมูลไม่ปลอดภัยกับ dangerous sink | ใช้ `innerHTML` กับค่าจาก URL fragment |

#### 5.5.2 Output Encoding ต้องตรงบริบท

XSS ป้องกันด้วยการ encode output ให้ตรงกับบริบทที่ข้อมูลถูกนำไปแสดง ไม่ใช่ใช้ function กลางตัวเดียวกับทุกกรณี

| บริบท | ความเสี่ยง | แนวป้องกัน |
|--------|------------|-------------|
| HTML Content | แทรก tag หรือ script | HTML entity encoding |
| HTML Attribute | หลุดออกจาก attribute value | Attribute encoding และใส่ quote เสมอ |
| JavaScript Context | กลายเป็น code รันได้ | หลีกเลี่ยงฝังข้อมูลดิบใน script ใช้ JSON encoding อย่างปลอดภัย |
| CSS Context | ควบคุม style หรือ URL | จำกัดค่าและใช้ CSS encoding เฉพาะบริบท |
| URL Context | ใช้ scheme อันตรายหรือ redirect | ตรวจ allowlist ของ scheme และ domain |

#### 5.5.3 DOM-based XSS: Source และ Sink

DOM-based XSS มักเกิดจากการนำข้อมูลจาก source ที่ไม่น่าเชื่อถือไปใส่ใน sink ที่ตีความเป็น HTML หรือ script

| Source | ตัวอย่าง |
|--------|----------|
| `location.href` | URL ปัจจุบัน |
| `location.search` | Query string |
| `location.hash` | Fragment หลัง `#` |
| `document.referrer` | หน้าก่อนหน้า |
| `postMessage` | ข้อความจาก window อื่น |

| Dangerous Sink | ทางเลือกที่ปลอดภัยกว่า |
|----------------|----------------------|
| `innerHTML` | `textContent` เมื่อไม่ต้องการ HTML |
| `document.write` | DOM API ที่สร้าง element อย่างชัดเจน |
| `eval` | หลีกเลี่ยงการประเมิน string เป็น code |
| `setTimeout(string)` | ส่ง function แทน string |
| `insertAdjacentHTML` | sanitize HTML ด้วย library ที่เชื่อถือได้หากจำเป็นต้องรับ HTML |

#### 5.5.4 Framework ช่วยป้องกัน XSS แค่ไหน

Framework เช่น React, Angular และ Vue มัก escape output ตามค่าเริ่มต้นในหลายกรณี แต่ไม่ได้หมายความว่าปลอดภัยเสมอไป เพราะยังมี escape hatch หรือ API ที่ตั้งใจให้แทรก HTML ได้

| Framework/Pattern | ช่วยอะไร | จุดที่ต้องระวัง |
|-------------------|----------|-----------------|
| React JSX | escape text content ตามปกติ | `dangerouslySetInnerHTML` |
| Angular Template | context-aware escaping หลายกรณี | bypass security trust API |
| Vue Template | escape interpolation | `v-html` |
| Server-side Template | escape ได้ถ้าเปิด autoescape | ปิด autoescape หรือใช้ raw output |

#### 5.5.5 Content Security Policy (CSP)

CSP เป็น HTTP response header ที่ช่วยจำกัดแหล่งโหลด script, style, image และ resource อื่นๆ ใช้เป็น defense in depth เพื่อลดผลกระทบจาก XSS แต่ไม่ควรใช้แทน output encoding หรือการแก้ช่องโหว่ต้นเหตุ

| Directive | หน้าที่ | คำแนะนำ |
|-----------|--------|---------|
| `default-src` | ค่าเริ่มต้นของแหล่ง resource | ตั้งให้แคบ เช่น `'self'` |
| `script-src` | จำกัดแหล่ง script | หลีกเลี่ยง `unsafe-inline` และ `unsafe-eval` |
| `object-src` | จำกัด plugin/object | มักตั้งเป็น `'none'` |
| `base-uri` | จำกัด base URL | ลดความเสี่ยงจาก base tag injection |
| `frame-ancestors` | ควบคุมการถูกฝังใน frame | ช่วยกัน clickjacking |
| `report-uri` หรือ `report-to` | รายงานการละเมิด policy | ใช้ตรวจและปรับ policy |

ตัวอย่าง CSP แบบเริ่มต้นที่เข้มงวดขึ้น:

```http
Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'
```

**ข้อควรจำ:** CSP ที่มี `unsafe-inline` หรือ `unsafe-eval` มักลดประสิทธิภาพในการป้องกัน XSS อย่างมาก

---

### 5.6 Command Injection และ OS Injection

Command Injection เกิดเมื่อ application ส่งข้อมูลผู้ใช้เข้า shell หรือ system command โดยไม่แยก command กับ argument อย่างปลอดภัย ทำให้ผู้โจมตีอาจเพิ่มคำสั่งอื่นหรือเปลี่ยนความหมายของ command ได้

#### 5.6.1 ตัวอย่างโค้ดที่มีช่องโหว่

```python
# ไม่ปลอดภัย: อย่าใช้ในระบบจริง
host = request.args.get("host")
os.system("ping -c 1 " + host)
```

ปัญหาคือ `host` ถูกนำไปต่อกับ shell command โดยตรง หากมี shell metacharacter อาจทำให้เกิดคำสั่งเพิ่มเติม

#### 5.6.2 แนวทางที่ปลอดภัยกว่า

```python
# ปลอดภัยกว่า: ไม่ใช้ shell และส่ง argument แยกกัน
import subprocess
import ipaddress

host = request.args.get("host")
ipaddress.ip_address(host)
subprocess.run(["ping", "-c", "1", host], shell=False, check=False)
```

แนวทางป้องกัน:

- หลีกเลี่ยงการเรียก shell หากไม่จำเป็น
- ใช้ API ของภาษาแทน shell command
- ส่ง command และ argument เป็น list แยกกัน
- ใช้ allowlist สำหรับ command หรือ argument ที่อนุญาต
- ตรวจชนิดและรูปแบบข้อมูล เช่น IP address, filename, enum
- รัน process ด้วยสิทธิ์ต่ำสุด
- จำกัด timeout และ resource usage

---

### 5.7 LDAP Injection, XPath Injection และ Template Injection

#### 5.7.1 LDAP Injection

LDAP Injection เกิดเมื่อข้อมูลผู้ใช้ถูกนำไปประกอบ LDAP filter โดยไม่ escape ตามบริบท ทำให้ผู้โจมตีเปลี่ยนเงื่อนไขค้นหา directory ได้

แนวป้องกัน:

- ใช้ LDAP API ที่รองรับ parameter หรือ escaping ที่ถูกต้อง
- ใช้ allowlist สำหรับ username หรือ attribute ที่อนุญาต
- จำกัดสิทธิ์บัญชีที่ใช้ query directory
- ห้ามใช้ข้อมูลผู้ใช้สร้าง filter แบบ string concatenation

#### 5.7.2 XPath Injection

XPath Injection คล้าย SQL Injection แต่เกิดกับ XPath query ที่ใช้ค้น XML document หากระบบต่อ string จากข้อมูลผู้ใช้ลงใน XPath expression ผู้โจมตีอาจเปลี่ยนเงื่อนไข query ได้

แนวป้องกัน:

- ใช้ variable binding หรือ API ที่ปลอดภัย
- ตรวจ input ด้วย allowlist
- ลดการใช้ XML query จากข้อมูลผู้ใช้โดยตรง
- จำกัดข้อมูลที่ query สามารถเข้าถึงได้

#### 5.7.3 Server-side Template Injection (SSTI)

SSTI เกิดเมื่อผู้ใช้ควบคุม template หรือ expression ที่ template engine ประมวลผลฝั่ง server ช่องโหว่นี้อันตรายเพราะในบาง engine อาจนำไปสู่การอ่านข้อมูลภายในหรือรันโค้ดบน server ได้

แนวป้องกัน:

- ห้ามให้ผู้ใช้ควบคุม template source โดยตรง
- แยก user content ออกจาก template syntax
- เปิด sandbox หาก template engine รองรับ
- จำกัด object/function ที่ template เข้าถึงได้
- ใช้ least privilege กับ process ที่รัน template

---

### 5.8 File Upload Vulnerabilities

File Upload เป็นพื้นที่เสี่ยงสูง เพราะไฟล์มีทั้ง content, metadata, filename, MIME type, extension และอาจถูกนำไปเปิด แสดง ประมวลผล หรือรันในภายหลัง

#### 5.8.1 ความเสี่ยงของ File Upload

| ความเสี่ยง | ตัวอย่าง | ผลกระทบ |
|------------|----------|---------|
| อัปโหลดไฟล์ executable | ไฟล์ script ถูกวางใน web root | รันโค้ดบน server |
| MIME spoofing | ไฟล์อันตรายปลอมเป็น image | bypass validation |
| ขนาดไฟล์ใหญ่เกิน | อัปโหลดไฟล์จำนวนมาก | storage exhaustion หรือ DoS |
| Filename injection | ใช้ path หรือชื่อไฟล์พิเศษ | overwrite file หรือ path traversal |
| Malware upload | อัปโหลดไฟล์ที่มี malware | กระทบผู้ใช้ที่ดาวน์โหลด |
| Image processing exploit | ใช้ parser/library ที่มีช่องโหว่ | compromise service |

#### 5.8.2 Checklist การป้องกัน File Upload

- ใช้ allowlist ของชนิดไฟล์ที่อนุญาต
- ตรวจ extension และ MIME type แต่ไม่พึ่งเพียงอย่างเดียว
- ตรวจ magic bytes หรือ file signature เท่าที่เหมาะสม
- จำกัดขนาดไฟล์และจำนวนไฟล์
- เปลี่ยนชื่อไฟล์เป็นชื่อที่ระบบสร้างเอง
- เก็บไฟล์นอก web root หรือใน object storage ที่ไม่รันโค้ด
- ตั้ง permission ให้ต่ำที่สุด
- สแกน malware หากใช้ในระบบจริง
- แยก domain สำหรับไฟล์ผู้ใช้หากต้องแสดงต่อ browser
- ห้ามแสดงไฟล์ HTML/SVG จากผู้ใช้ใน origin เดียวกับ application หลักโดยไม่ควบคุม

---

### 5.9 Cross-Site Request Forgery (CSRF)

CSRF คือการโจมตีที่หลอกให้ browser ของผู้ใช้ที่ล็อกอินอยู่ส่ง request ไปยังเว็บไซต์เป้าหมายโดยอาศัย cookie session ที่ browser แนบให้อัตโนมัติ แตกต่างจาก XSS ตรงที่ CSRF ไม่จำเป็นต้องรัน script ในเว็บไซต์เป้าหมาย แต่หลอกให้เกิด request จาก browser ของเหยื่อ

#### 5.9.1 CSRF ต่างจาก XSS อย่างไร

| ประเด็น | CSRF | XSS |
|---------|------|-----|
| กลไก | หลอก browser ให้ส่ง request พร้อม cookie | ทำให้ browser รัน script ที่ผู้โจมตีควบคุม |
| สิ่งที่โจมตี | State-changing request | Trust ของผู้ใช้ต่อเว็บไซต์ |
| ตัวอย่าง | เปลี่ยนอีเมล โอนเงิน กด action สำคัญ | ขโมย token, แก้ DOM, ส่ง request แทนผู้ใช้ |
| แนวป้องกัน | CSRF token, SameSite, Origin check | Output encoding, safe DOM API, CSP |
| ความสัมพันธ์ | XSS อาจทำให้ CSRF token ถูกอ่านหรือใช้แทนได้ | XSS มักร้ายแรงกว่าในบริบท browser |

#### 5.9.2 แนวทางป้องกัน CSRF

- ใช้ CSRF token ที่ผูกกับ session และตรวจทุก state-changing request
- ตั้งค่า cookie `SameSite=Lax` หรือ `SameSite=Strict` ตามบริบท
- ตรวจ `Origin` หรือ `Referer` สำหรับ request สำคัญ
- ใช้ Fetch Metadata headers เป็น defense in depth
- หลีกเลี่ยง state-changing operation ผ่าน GET
- ยืนยันซ้ำสำหรับ action ที่มีผลกระทบสูง
- ป้องกัน XSS เพราะ XSS สามารถทำให้การป้องกัน CSRF ล้มเหลวได้

---

### 5.10 Defense in Depth สำหรับ Injection

การป้องกัน Injection ไม่ควรพึ่งมาตรการเดียว แต่ควรใช้หลายชั้นร่วมกัน

| ช่องโหว่ | ป้องกันหลัก | ป้องกันเสริม |
|----------|--------------|---------------|
| SQL Injection | Parameterized query | Least privilege, input validation, monitoring |
| XSS | Context-aware output encoding | CSP, safe framework usage, HttpOnly cookie |
| Command Injection | ไม่เรียก shell หรือแยก argument | Allowlist, low privilege, timeout |
| NoSQL Injection | Schema validation และ safe query API | จำกัด operator, least privilege |
| LDAP/XPath Injection | API ที่รองรับ parameter/escaping | Allowlist, low privilege |
| SSTI | ไม่ให้ผู้ใช้ควบคุม template | Sandbox, low privilege |
| File Upload | Allowlist, safe storage | Malware scan, separate domain, size limit |
| CSRF | Token และ SameSite | Origin check, Fetch Metadata, re-authentication |

#### 5.10.1 Secure Coding Checklist

ก่อนส่งโค้ดที่รับข้อมูลจากผู้ใช้ ให้ตรวจอย่างน้อย:

- มี server-side validation ตาม schema หรือไม่
- ใช้ allowlist เมื่อข้อมูลมีรูปแบบชัดเจนหรือไม่
- SQL ใช้ parameterized query หรือไม่
- ไม่มีการต่อ string เพื่อสร้าง command, SQL, LDAP, XPath หรือ template จากข้อมูลผู้ใช้
- Output encoding ตรงบริบทหรือไม่
- DOM code หลีกเลี่ยง dangerous sink หรือไม่
- File upload ตรวจชนิด ขนาด ชื่อ และตำแหน่งจัดเก็บหรือไม่
- API สำคัญมี authorization check ที่ backend หรือไม่
- State-changing request มี CSRF protection หรือไม่
- Error message ไม่เปิดเผย stack trace หรือ query ภายในหรือไม่
- Log ไม่เก็บ secret, token หรือข้อมูลส่วนบุคคลเกินจำเป็นหรือไม่

---

### 5.11 กรณีศึกษาจริง

#### 5.11.1 Equifax 2017

Equifax ถูกโจมตีในปี 2017 ผ่านช่องโหว่ Apache Struts CVE-2017-5638 ซึ่งเกี่ยวข้องกับการประมวลผลข้อมูลนำเข้าที่นำไปสู่ remote code execution มีผู้ได้รับผลกระทบประมาณ 147 ล้านคน และ FTC ระบุข้อตกลงชดเชยปี 2019 มูลค่าสูงสุด 700 ล้านดอลลาร์สหรัฐ

บทเรียนสำหรับบทนี้:

- Input processing bug ใน framework สามารถกระทบระบบใหญ่ได้
- Patch management และ asset inventory สำคัญพอๆ กับ secure coding
- ต้องมี defense in depth เช่น segmentation, monitoring และ least privilege

#### 5.11.2 TalkTalk 2015

TalkTalk ในสหราชอาณาจักรถูกโจมตีในปี 2015 โดยเหตุการณ์เกี่ยวข้องกับ SQL Injection สำนักงานคณะกรรมาธิการสารสนเทศสหราชอาณาจักรระบุว่ามีลูกค้าได้รับผลกระทบ 156,959 ราย และถูกปรับ 400,000 ปอนด์

บทเรียนสำหรับบทนี้:

- SQL Injection เป็นช่องโหว่พื้นฐานแต่ยังสร้างความเสียหายระดับองค์กรได้
- ระบบเก่าต้องได้รับการทดสอบและแก้ไข ไม่ใช่สนใจเฉพาะระบบใหม่
- Error handling และ vulnerability management มีผลต่อความเสียหายจริง

#### 5.11.3 Heartland Payment Systems 2008

Heartland Payment Systems ถูกโจมตีในปี 2008 โดยเหตุการณ์เริ่มจาก SQL Injection และนำไปสู่การฝัง malware ในระบบประมวลผลบัตร กระทรวงยุติธรรมสหรัฐอเมริการะบุว่ามีหมายเลขบัตรมากกว่า 130 ล้านรายการถูกขโมย

บทเรียนสำหรับบทนี้:

- SQL Injection อาจเป็นจุดเริ่มต้นของการบุกรุกหลายขั้น
- การป้องกันต้องรวม database least privilege, network segmentation และ monitoring
- ระบบ payment ต้องมีการควบคุมข้อมูลและ logging ที่เข้มงวด

#### 5.11.4 British Airways 2018

British Airways ถูกโจมตีในปี 2018 ผ่านการโจมตีฝั่งเว็บที่ดักข้อมูลผู้ใช้ระหว่างทำธุรกรรม สำนักงานคณะกรรมาธิการสารสนเทศสหราชอาณาจักรระบุว่าลูกค้าได้รับผลกระทบมากกว่า 429,000 ราย และค่าปรับสุดท้ายคือ 20 ล้านปอนด์

บทเรียนสำหรับบทนี้:

- ความปลอดภัยฝั่ง browser และ third-party script เป็นส่วนหนึ่งของ software security
- CSP, Subresource Integrity, script inventory และ monitoring ฝั่ง client ช่วยลดความเสี่ยง
- การป้องกัน XSS ต้องทำร่วมกับ supply chain control

#### 5.11.5 MOVEit Transfer 2023

MOVEit Transfer มีช่องโหว่ CVE-2023-34362 ซึ่งเป็น SQL Injection ที่ถูกใช้โจมตีจริงในปี 2023 CISA เผยแพร่คำแนะนำเมื่อวันที่ 7 มิถุนายน 2023 และรายงานสาธารณะจาก Emsisoft ระบุว่ามีองค์กรมากกว่า 2,700 แห่ง และบุคคลมากกว่า 93 ล้านคนได้รับผลกระทบ

บทเรียนสำหรับบทนี้:

- Internet-facing file transfer system เป็นเป้าหมายมูลค่าสูง
- ต้องมี patch process ที่รวดเร็วสำหรับช่องโหว่ที่ถูกใช้โจมตีจริง
- Monitoring และ log review สำคัญมากหลังพบช่องโหว่ injection ในระบบที่ถือข้อมูลจำนวนมาก

#### 5.11.6 Log4Shell 2021

Log4Shell หรือ CVE-2021-44228 ใน Apache Log4j เป็นช่องโหว่ร้ายแรงที่ NVD ให้คะแนน CVSS 10.0 ข้อมูลที่ดูเหมือนเป็นข้อความ log สามารถนำไปสู่การประมวลผลที่อันตรายใน library ได้

บทเรียนสำหรับบทนี้:

- ข้อมูลนำเข้าอาจอันตรายเมื่อถูก log หรือส่งต่อให้ library อื่น
- Dependency และ logging pipeline เป็นส่วนหนึ่งของ attack surface
- SBOM และ dependency inventory ช่วยให้องค์กรค้นหาระบบที่ได้รับผลกระทบได้เร็วขึ้น

---

### 5.12 จากช่องโหว่สู่ Security Requirement และ Test Case

บทนี้ไม่ควรจบที่การรู้ชื่อช่องโหว่ แต่ต้องแปลงความเข้าใจเป็นข้อกำหนด โค้ดที่ปลอดภัย และการทดสอบที่ทำซ้ำได้ในกระบวนการพัฒนา

#### 5.12.1 ตัวอย่าง Security Requirements

| Requirement ID | Security Requirement | ช่องโหว่ที่เกี่ยวข้อง | Acceptance Criteria |
|----------------|----------------------|------------------------|---------------------|
| SR-INPUT-001 | ทุก API ต้องตรวจ request body ตาม schema ที่กำหนด | Injection, Business Logic Abuse | request ที่มี field เกิน type ผิด หรือค่าผิดช่วงต้องถูกปฏิเสธ |
| SR-SQL-001 | ทุก database query ที่รับข้อมูลผู้ใช้ต้องใช้ parameterized query | SQL Injection | code review ไม่พบ string concatenation ใน SQL ที่มีข้อมูลผู้ใช้ |
| SR-XSS-001 | ทุกข้อมูลที่แสดงในหน้าเว็บต้องผ่าน output encoding ตามบริบท | XSS | ข้อมูลผู้ใช้ถูกแสดงเป็นข้อความ ไม่ถูกตีความเป็น HTML/JavaScript |
| SR-DOM-001 | JavaScript ฝั่ง client ห้ามใช้ dangerous sink กับข้อมูลจาก URL โดยตรง | DOM XSS | ไม่พบการใช้ `innerHTML` กับ `location.search` หรือ `location.hash` โดยไม่ sanitize |
| SR-CMD-001 | ห้ามเรียก shell ด้วยข้อมูลผู้ใช้ หากจำเป็นต้องแยก argument และตรวจ allowlist | Command Injection | ไม่พบ `shell=True` หรือ command concatenation จากข้อมูลผู้ใช้ |
| SR-FILE-001 | ไฟล์อัปโหลดต้องตรวจชนิด ขนาด เปลี่ยนชื่อ และเก็บในพื้นที่ที่รันโค้ดไม่ได้ | File Upload | ไฟล์ที่ไม่ตรง allowlist ถูกปฏิเสธและชื่อไฟล์จากผู้ใช้ไม่ถูกใช้ตรงๆ |
| SR-CSRF-001 | ทุก state-changing request ต้องมี CSRF protection | CSRF | request ที่ไม่มี token หรือ origin ไม่ถูกต้องต้องถูกปฏิเสธ |

#### 5.12.2 ตัวอย่าง Security Test Cases

| Test ID | Test Case | Expected Result | วิธีทดสอบ |
|---------|-----------|-----------------|-----------|
| ST-SQL-001 | ส่งค่าที่มี SQL metacharacter ไปยัง login form ใน toy app | ไม่ bypass login และไม่มี database error | Automated integration test หรือ manual lab |
| ST-XSS-001 | บันทึกข้อความที่มี HTML tag ใน comment | แสดงเป็นข้อความ ไม่รัน script | Browser test |
| ST-DOM-001 | ใส่ HTML fragment ใน URL hash | DOM ไม่สร้าง HTML จากข้อมูลนั้น | Unit test สำหรับ client script |
| ST-CMD-001 | ส่ง hostname ที่มีตัวคั่นคำสั่งใน lab | ถูก reject หรือถูก treat เป็น argument ไม่ใช่ command | Unit/integration test |
| ST-FILE-001 | อัปโหลดไฟล์ที่ extension ไม่ตรง allowlist | ถูกปฏิเสธและมี log เหตุการณ์ | API test |
| ST-CSRF-001 | ส่ง POST request โดยไม่มี CSRF token | ได้ 403 หรือ error ที่กำหนด | Integration test |

#### 5.12.3 Pull Request Checklist สำหรับ Injection และ XSS

ใช้ checklist นี้ในการ review pull request ที่เกี่ยวข้องกับ input, output, query, command, file หรือ browser DOM:

- มี schema validation สำหรับ request body และ parameter หรือไม่
- SQL, NoSQL, LDAP, XPath หรือ query อื่นๆ ใช้ API ที่แยกข้อมูลออกจากคำสั่งหรือไม่
- มีการต่อ string เพื่อสร้าง query หรือ command จากข้อมูลผู้ใช้หรือไม่
- Output ที่แสดงข้อมูลผู้ใช้ถูก encode ตามบริบทหรือไม่
- JavaScript ใช้ dangerous sink เช่น `innerHTML`, `eval`, `document.write` หรือไม่
- ถ้าต้องรับ rich text มี HTML sanitizer ที่เชื่อถือได้และกำหนด allowlist ชัดเจนหรือไม่
- File upload ตรวจ extension, MIME type, magic bytes, size, filename และ storage location หรือไม่
- State-changing request มี CSRF token และ SameSite cookie หรือไม่
- Error message ไม่เปิดเผย stack trace, SQL query, file path หรือ secret หรือไม่
- Log ไม่บันทึก access token, session ID, password, API key หรือข้อมูลส่วนบุคคลเกินจำเป็นหรือไม่
- มี test case ที่พิสูจน์ว่าช่องโหว่เดิมถูกแก้แล้วหรือไม่

#### 5.12.4 ตัวอย่าง Finding Report แบบย่อ

```text
Finding ID: CH5-SQL-001
Title: SQL query constructed with string concatenation in login endpoint
Severity: High
Affected Component: /login
Root Cause: User input is concatenated into SQL statement
Impact: Attacker may bypass authentication or access unauthorized data
Recommendation: Replace dynamic SQL construction with parameterized query and add regression test
Verification: Login injection test no longer bypasses authentication and no SQL error is returned
```

**ข้อควรจำ:** Finding ที่ดีต้องมี root cause และวิธีแก้ที่ตรวจสอบได้ ไม่ใช่เพียงบอกว่า “มี SQL Injection” หรือ “มี XSS” เท่านั้น

---

## Keywords

Input Validation, Injection, SQL Injection, NoSQL Injection, Cross-Site Scripting, XSS, DOM XSS, Command Injection, OS Injection, Parameterized Query, Prepared Statement, Output Encoding, Context-aware Encoding, Content Security Policy, CSP, Sanitization, Canonicalization, CSRF, File Upload, Server-side Template Injection, SSTI, LDAP Injection, XPath Injection, Allowlist, Defense in Depth

---

## กิจกรรมปฏิบัติการ

> กิจกรรมทั้งหมดต้องทำใน WebGoat, OWASP Juice Shop, DVWA หรือ toy application ภายในเครื่องเท่านั้น ห้ามทดสอบกับระบบจริงหรือระบบของผู้อื่นโดยไม่ได้รับอนุญาต

### Lab 5.1: SQL Injection และการแก้ด้วย Parameterized Query

**วัตถุประสงค์:** เข้าใจผลของการต่อ string สร้าง SQL และแก้ด้วย parameterized query

**เวลาที่ใช้:** 45-60 นาที

**เครื่องมือ:** WebGoat หรือ DVWA และ toy app ที่อาจารย์เตรียมไว้

**ขั้นตอน:**

1. เปิด WebGoat หรือ DVWA ในเครื่อง
2. เข้าแบบฝึกหัด SQL Injection ที่ออกแบบเพื่อการศึกษา
3. ทดลอง input ตามคำแนะนำใน lab ของเครื่องมือนั้นเท่านั้น
4. สังเกตว่าระบบคืนข้อมูลหรือ bypass logic ได้อย่างไร
5. เปิด toy app ที่มีโค้ดต่อ string สร้าง SQL
6. แก้เป็น prepared statement หรือ parameterized query
7. ทดลอง input เดิมอีกครั้ง
8. บันทึกผลก่อนและหลังแก้

**สิ่งที่ต้องส่ง:**

1. ภาพหรือ log ก่อนแก้และหลังแก้
2. โค้ดส่วนที่มีช่องโหว่และโค้ดที่แก้แล้ว
3. คำอธิบายว่าทำไม parameterized query จึงแยกข้อมูลออกจากคำสั่ง
4. ข้อเสนอ least privilege สำหรับบัญชี database ของ toy app

---

### Lab 5.2: Reflected XSS, Stored XSS และ Context-aware Encoding

**วัตถุประสงค์:** เข้าใจความต่างของ XSS แต่ละประเภทและการแก้ด้วย output encoding

**เวลาที่ใช้:** 45-60 นาที

**เครื่องมือ:** OWASP Juice Shop หรือ WebGoat

**ขั้นตอน:**

1. เปิด lab XSS ในเครื่องมือที่กำหนด
2. ทดลองเฉพาะ payload ตัวอย่างที่ lab ให้มาและไม่ทำอันตราย
3. แยกประเภทว่าเป็น reflected หรือ stored XSS
4. ระบุว่าข้อมูลถูกแสดงในบริบทใด เช่น HTML content หรือ attribute
5. แก้ toy app ด้วย output encoding ที่ตรงบริบท
6. ทดลองซ้ำและตรวจว่าข้อมูลถูกแสดงเป็นข้อมูล ไม่ใช่ code
7. เพิ่ม CSP แบบเริ่มต้นและสังเกตว่า CSP ช่วยเสริมแต่ไม่แทนการ encoding

**สิ่งที่ต้องส่ง:**

1. ตารางแยก Reflected, Stored และ DOM-based XSS
2. ระบุ output context ของแต่ละช่องโหว่
3. อธิบายว่า encoding ที่ใช้เหมาะกับบริบทใด
4. ตัวอย่าง CSP ที่ใช้เป็น defense in depth

---

### Lab 5.3: DOM-based XSS และ Safe DOM API

**วัตถุประสงค์:** เห็นว่าช่องโหว่เกิดฝั่ง browser ได้แม้ server ไม่เปลี่ยนข้อมูล

**เวลาที่ใช้:** 30-45 นาที

**เครื่องมือ:** Toy HTML/JavaScript page ภายในเครื่อง

**ขั้นตอน:**

1. สร้างหน้า HTML ที่อ่านค่าจาก `location.hash` หรือ `location.search`
2. แสดงค่าด้วย `innerHTML` เพื่อดูพฤติกรรมที่ไม่ปลอดภัยใน lab
3. ระบุ source และ sink
4. เปลี่ยนจาก `innerHTML` เป็น `textContent` เมื่อไม่ต้องการแสดง HTML
5. ทดลองซ้ำและเปรียบเทียบผล
6. อภิปรายว่า Trusted Types และ CSP ช่วยเสริมได้อย่างไร

**สิ่งที่ต้องส่ง:**

1. Source และ sink ของช่องโหว่
2. โค้ดก่อนและหลังแก้
3. คำอธิบายความต่างระหว่าง `innerHTML` และ `textContent`

---

### Lab 5.4: Command Injection ในสภาพแวดล้อมจำลอง

**วัตถุประสงค์:** เข้าใจอันตรายของการส่งข้อมูลผู้ใช้เข้า shell และแก้ด้วยการแยก argument

**เวลาที่ใช้:** 45 นาที

**เครื่องมือ:** DVWA หรือ toy app ฟังก์ชัน ping ที่รันภายในเครื่อง

**ขั้นตอน:**

1. เปิด lab command injection ในเครื่องของตนเอง
2. ทดลอง input ปกติ เช่น IP address ภายในเครื่อง
3. ทดลองเฉพาะ input ที่ lab กำหนดเพื่อแสดงผลของ shell metacharacter
4. แก้ toy app โดยไม่ใช้ shell หรือส่ง argument เป็น list แยกกัน
5. เพิ่ม allowlist สำหรับ IP address หรือ hostname ที่อนุญาต
6. เพิ่ม timeout และจำกัดสิทธิ์ process

**สิ่งที่ต้องส่ง:**

1. คำอธิบายว่าความเสี่ยงเกิดจาก shell metacharacter อย่างไร
2. โค้ดก่อนและหลังแก้
3. เหตุผลว่าทำไมการส่ง argument แยกกันปลอดภัยกว่า

---

### Lab 5.5: File Upload และ CSRF Defense

**วัตถุประสงค์:** ฝึกตรวจ file upload และป้องกัน CSRF ด้วย token และ cookie setting

**เวลาที่ใช้:** 60 นาที

**เครื่องมือ:** DVWA, WebGoat หรือ toy app ภายในเครื่อง

**ขั้นตอนส่วน File Upload:**

1. ทดลองอัปโหลดไฟล์ที่ lab กำหนด
2. ตรวจว่าระบบพึ่ง extension อย่างเดียวหรือไม่
3. เพิ่ม validation: extension allowlist, size limit, MIME check และ filename randomization
4. ย้ายที่เก็บไฟล์ออกจากตำแหน่งที่รันโค้ดได้
5. ตรวจ permission ของไฟล์ที่อัปโหลด

**ขั้นตอนส่วน CSRF:**

1. ใช้ toy app ที่มีฟอร์มเปลี่ยนข้อมูล
2. ทดลองส่ง request โดยไม่มี CSRF token ใน lab
3. เพิ่ม CSRF token ที่ผูกกับ session
4. ตั้งค่า SameSite cookie
5. ตรวจ Origin สำหรับ state-changing request
6. ทดลองซ้ำและบันทึกผล

**สิ่งที่ต้องส่ง:**

1. File upload security checklist ที่ใช้กับ toy app
2. ภาพหรือ log การป้องกัน CSRF ก่อนและหลังแก้
3. คำอธิบายว่า XSS สามารถทำให้ CSRF protection ล้มเหลวได้อย่างไร

---

## คำถามท้ายบท

1. Input Validation, Sanitization, Output Encoding และ Parameterization ต่างกันอย่างไร จงยกตัวอย่างสถานการณ์ที่ควรใช้แต่ละแบบ
2. เหตุใด Allowlist จึงเหมาะกว่า Blocklist ในการตรวจข้อมูลนำเข้าส่วนใหญ่ และ Blocklist มีข้อจำกัดอะไร
3. อธิบายว่าทำไม Parameterized Query จึงป้องกัน SQL Injection ได้ดีกว่าการต่อ string และ manual escaping
4. Stored Procedure และ ORM ป้องกัน SQL Injection ได้เสมอหรือไม่ จงอธิบายพร้อมตัวอย่างสถานการณ์ที่ยังเสี่ยง
5. Blind SQL Injection แตกต่างจาก In-band SQL Injection อย่างไร และเหตุใดระบบที่ไม่แสดง error ก็ยังอาจมีช่องโหว่ SQL Injection ได้
6. Reflected XSS, Stored XSS และ DOM-based XSS ต่างกันอย่างไร จงยกตัวอย่าง source และ sink สำหรับ DOM-based XSS
7. ทำไม Output Encoding ต้องเป็น Context-aware Encoding และเหตุใดการใช้ฟังก์ชัน escape ตัวเดียวกับทุกบริบทจึงไม่พอ
8. CSP ช่วยลดความเสี่ยง XSS ได้อย่างไร และมีข้อจำกัดอะไรเมื่อเทียบกับการแก้ output encoding ที่ต้นเหตุ
9. Command Injection แตกต่างจาก Argument Injection อย่างไร และทำไมการหลีกเลี่ยง shell จึงเป็นแนวทางที่ปลอดภัยกว่า
10. File Upload ที่ปลอดภัยควรตรวจอะไรบ้างนอกจากนามสกุลไฟล์
11. CSRF แตกต่างจาก XSS อย่างไร และเหตุใด XSS สามารถทำให้ CSRF token ไม่เพียงพอได้
12. จากกรณี MOVEit Transfer 2023 จงอธิบายว่าทำไมระบบถ่ายโอนไฟล์ที่เปิดสู่อินเทอร์เน็ตจึงเป็น asset ความเสี่ยงสูง
13. จากกรณี Log4Shell จงอธิบายว่าทำไมข้อมูลนำเข้าที่ถูกนำไป log จึงยังอาจก่อให้เกิดความเสี่ยงได้
14. จงออกแบบ checklist สำหรับ code review ที่ใช้ตรวจ Injection และ XSS ใน pull request ของทีมพัฒนา

---

## สรุปท้ายบท

Input Validation เป็นด่านแรกของการป้องกัน แต่ไม่ใช่คำตอบทั้งหมดของ Injection Attacks หลักสำคัญคือข้อมูลทุกชนิดจากผู้ใช้ เครือข่าย ไฟล์ cookie header API ภายนอก และข้อมูลที่เคยบันทึกไว้ ต้องถือว่าไม่น่าเชื่อถือจนกว่าจะผ่านการตรวจสอบในบริบทที่ถูกต้อง

Injection เกิดจากการปะปนระหว่าง “ข้อมูล” กับ “คำสั่ง” วิธีป้องกันที่แข็งแรงจึงต้องแยกข้อมูลออกจากคำสั่ง เช่น ใช้ parameterized query สำหรับ SQL ใช้ safe API แทน shell command ใช้ schema validation สำหรับ NoSQL และหลีกเลี่ยงการให้ผู้ใช้ควบคุม template หรือ query structure

XSS เป็น Injection ในบริบทของ browser การป้องกันต้องใช้ context-aware output encoding และ safe DOM API เป็นหลัก CSP, HttpOnly cookie และ framework auto-escaping เป็นมาตรการเสริมที่มีประโยชน์ แต่ไม่ควรใช้แทนการแก้ต้นเหตุ

Command Injection, File Upload Vulnerability, SSTI และ CSRF แสดงให้เห็นว่าช่องโหว่จาก input ไม่ได้อยู่เฉพาะฐานข้อมูลหรือหน้าเว็บเท่านั้น แต่ครอบคลุม shell, template engine, file system, browser behavior และ third-party integration การป้องกันจึงต้องใช้ defense in depth, least privilege, secure defaults, monitoring และ secure code review อย่างต่อเนื่อง

กรณี Equifax, TalkTalk, Heartland, British Airways, MOVEit และ Log4Shell แสดงให้เห็นว่าช่องโหว่ injection และ input processing bug ที่ดูเป็น “เรื่องพื้นฐาน” สามารถสร้างความเสียหายระดับองค์กรได้ หากไม่มี secure coding, patch management, asset inventory และ risk-based prioritization ที่ดี

---

## Verification

- **Research process:** ใช้ researcher ตรวจสอบข้อมูลประกอบผ่านแหล่งอ้างอิงหลักก่อนปรับปรุงเนื้อหา
- **OWASP Top 10 2021:** ยืนยันว่า Injection อยู่ในหมวด A03 และรวม XSS อยู่ในหมวดนี้
- **OWASP Cheat Sheet Series:** ใช้ยืนยันแนวทาง Input Validation, SQL Injection Prevention, XSS Prevention, DOM XSS Prevention, CSP, CSRF, File Upload และ OS Command Injection Defense
- **MITRE CWE:** ใช้ยืนยันนิยาม CWE-89 (SQL Injection) และ CWE-79 (XSS)
- **MITRE CWE Top 25 2024:** ใช้ประกอบความสำคัญของช่องโหว่ซอฟต์แวร์ที่พบบ่อย
- **Equifax 2017:** ยืนยันผู้ได้รับผลกระทบประมาณ 147 ล้านคน และข้อตกลงสูงสุด 700 ล้านดอลลาร์สหรัฐ
- **TalkTalk 2015:** ยืนยันผู้ได้รับผลกระทบ 156,959 ราย และค่าปรับ 400,000 ปอนด์จาก ICO
- **Heartland 2008:** ยืนยันหมายเลขบัตรมากกว่า 130 ล้านรายการจาก DOJ
- **British Airways 2018:** ยืนยันผู้ได้รับผลกระทบมากกว่า 429,000 ราย และค่าปรับ 20 ล้านปอนด์จาก ICO
- **MOVEit Transfer 2023:** ยืนยัน CVE-2023-34362, คำแนะนำ CISA วันที่ 7 มิถุนายน 2023 และข้อมูลผลกระทบจากรายงานสาธารณะ
- **Log4Shell 2021:** ยืนยัน CVE-2021-44228 และ CVSS 10.0 จาก NVD
- **Safety boundary:** Labs ระบุให้ทำเฉพาะใน WebGoat, OWASP Juice Shop, DVWA หรือ toy application ภายในเครื่องเท่านั้น
- **Status:** ตรวจสอบข้อมูลหลักแล้ว ไม่มีรายการที่ตั้งใจปล่อยไว้เป็น [UNVERIFIED]

## เอกสารอ้างอิงหลัก

1. OWASP Top 10 2021 — A03: Injection: https://owasp.org/Top10/2021/A03_2021-Injection/
2. OWASP Input Validation Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html
3. OWASP SQL Injection Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
4. OWASP Query Parameterization Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html
5. OWASP Cross Site Scripting Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
6. OWASP DOM based XSS Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html
7. OWASP Content Security Policy Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
8. OWASP Cross-Site Request Forgery Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
9. OWASP File Upload Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
10. OWASP OS Command Injection Defense Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
11. MITRE CWE-89: https://cwe.mitre.org/data/definitions/89.html
12. MITRE CWE-79: https://cwe.mitre.org/data/definitions/79.html
13. MITRE CWE Top 25 2024: https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html
14. OWASP WebGoat: https://owasp.org/www-project-webgoat/
15. OWASP Juice Shop: https://owasp.org/www-project-juice-shop/
16. CISA MOVEit Transfer Advisory: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a
17. NVD CVE-2021-44228: https://nvd.nist.gov/vuln/detail/CVE-2021-44228
