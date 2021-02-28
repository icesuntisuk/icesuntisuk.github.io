# File Integrity Monitoring (FIM) and notify to Line in python 

โปรแกรมนี้ใช้สำหรับการตรวจสอบการเปลี่ยนแปลงไฟล์ที่ต้องการ Monitor ใน Path นั้นๆ ที่ Run โปรแกรม โดยจะทำการแจ้งเตือนไปยังผู้ดูแลกรณีมีการเปลี่ยนแปลงค่า Hash ของไฟล์

``` python
import os, hashlib, time, requests
def lineNotify(msg):
    url = 'https://notify-api.line.me/api/notify'
    token = 'token ID'
    headers = {'content-type': 'application/x-www-form-urlencoded', 'Authorization': 'Bearer ' + token}
    r = requests.post(url,headers=headers,data={'message':msg})

files={}
while True:
    for file in [item for item in os.listdir('.') if os.path.isfile(item)]:
        hash = hashlib.md5()
        with open(file,'rb') as f:
            for chunk in iter (lambda : f.read(4096), b""):
                hash.update(chunk)
        md5 = hash.hexdigest()
        if file in files and md5 != files[file]:
            msg = str(time.strftime('%Y-%m-%d %H:%M:%S')) + str(file) + "has been changed"
            print(msg)
            lineNotify(msg)
        files[file] = md5
    time.sleep(1)
```

Powered by Icesuntisuk and Thanakorn