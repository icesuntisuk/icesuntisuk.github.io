import re
import argparse

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
        if translated_text:
            return translated_text
        else:
            return ""
    else:
        translated_text = map_to_thai(input_text)
        if translated_text:
            return translated_text
        else:
            return ""



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

def main(input_file, output_file):
    with open(input_file, "r", encoding="utf-8") as file:
        with open(output_file, "w", encoding="utf-8") as output:
            for line in file:
                translated_text = translate_text(line.strip())
                output.write(translated_text + "\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Translate text between English and Thai and check password strength.")
    parser.add_argument("-i", "--input", help="Input file path")
    parser.add_argument("-o", "--output", help="Output file path")
    args = parser.parse_args()

    if not args.input or not args.output:
        parser.error("Please specify both input and output file paths.")

    main(args.input, args.output)
