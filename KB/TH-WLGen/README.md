# Thai keyboard Wordlist Generator

โค้ดด้านล่างนี้เป็นการสร้างรายการรหัสผ่านสำหรับการทดสอบการเข้าถึงระบบ (Bruteforce) โดยส่วนใหญ่คนไทยมักจะใช้คำภาษาไทยที่พิมพ์ผ่านแป้นพิมพ์ภาษาอังกฤษเป็นรหัสผ่าน ทั้งนี้ โปรแกรมนี้จะทำการแปลงคำที่ป้อนเป็นภาษาไทยเป็นภาษาอังกฤษ หรือแปลงคำภาษาอังกฤษเป็นภาษาไทยตามแป้นพิมพ์คีย์บอร์ด โดยการใส่ Input เข้าไปใน input.txt จากนั้นรันโปแกรมก็จะสามารถได้ Wordlist สำหรับโจมตีต่อไปได้ 

``` python
import re

mapping = {
    "q": "ๆ", "w": "ไ", "e": "ำ", "r": "พ", "t": "ะ", "y": "ั", "u": "ี", "i": "ร", "o": "น", "p": "ย",
    "[": "บ", "]": "ล", "\\": "ฃ",
    "a": "ฟ", "s": "ห", "d": "ก", "f": "ด", "g": "เ", "h": "้", "j": "่", "k": "า", "l": "ส", ";": "ว", "'": "ง",
    ",": "ฟ",
    "z": "ผ", "x": "ป", "c": "แ", "v": "อ", "b": "ิ", "n": "ื", "m": "ท", ",": "ม", ".": "ใ", "/": "ฝ",
    "Q": "๐", "W": "\"", "E": "ฎ", "R": "ฑ", "T": "ธ", "Y": "ํ", "U": "๊", "I": "ณ", "O": "ฯ", "P": "ญ",
    "{": "ฐ", "}": ",", "|": "ฅ",
    "A": "ฤ", "S": "ฆ", "D": "ฏ", "F": "โ", "G": "ฌ", "H": "็", "J": "๋", "K": "ษ", "L": "ศ", ":": "ซ", "\"": ".",
    "<": "ฉ", ">": "ฮ", "?": "์",
    "1": "ๅ", "2": "/", "3": "-", "4": "ภ", "5": "ถ", "6": "ุ", "7": "ึ", "8": "ค", "9": "ต", "0": "จ", "-": "ข", "=": "ช",
    "!": "+", "@": "๑", "#": "๒", "$": "๓", "%": "๔", "^": "ู", "&": "฿", "*": "๕", "(": "๖", ")": "๗", "_": "๘", "+": "๙",
}

def map_to_thai(input_text):
    thai_text = ""
    for char in input_text:
        if char in mapping:
            thai_text += mapping[char]
        else:
            thai_text += char

    return thai_text

def map_to_english(input_text):
    reverse_mapping = {value: key for key, value in mapping.items()}
    english_text = ""
    for char in input_text:
        if char in reverse_mapping:
            english_text += reverse_mapping[char]
        else:
            english_text += char

    return english_text

def is_thai(text):
    thai_characters = "ๅ/-ภถุึคตจขช'ฝพะัีรนยบลฃฟหกดเ้่าสวงผปแอิืทมใฝ๐\"ฎฑธํ๊ณฯญฐ,ฅฤฆฏโฌ็๋ษศซ.()ฉฮฺ์?ฒฬฦ"
    for char in text:
        if char in thai_characters:
            return True
    return False

def translate_text(input_text):
    if is_thai(input_text):
        translated_text = map_to_english(input_text)
        print(translated_text)
        #print(is_valid_password(str(translated_text)))

    else:
        translated_text = map_to_thai(input_text)
        print(translated_text)
        #print(is_valid_password(str(translated_text)))


def is_valid_password(password):
    # Define the regular expression patterns for each criterion
    criteria = {
        "lowercase": r"(?=.*[a-zก-๙])",  # At least one lowercase letter (English and Thai)
        "uppercase": r"(?=.*[A-Zก-๙])",  # At least one uppercase letter (English and Thai)
        "digit": r"(?=.*\d)",            # At least one digit
        "special": r"(?=.*[@$!%*?&;])",   # At least one special character (excluding ' and ")    }
    }
    
    # Check each criterion and store the failed criteria
    failed_criteria = [criterion for criterion, pattern in criteria.items() if not re.search(pattern, password)]
    
    # If there are failed criteria, return them. Otherwise, return True
    if failed_criteria:
        return failed_criteria
    else:
        return True

# Open the file in read mode
file_path = "input.txt"
with open(file_path, "r", encoding="utf-8") as file:
    # Read the file line by line
    for line in file:
        # Translate each line and output the translation
        translate_text(line.strip())

```

**Powered By** : 
Icesuntisuk & Supavit
๒๙ มี.ค.๖๗