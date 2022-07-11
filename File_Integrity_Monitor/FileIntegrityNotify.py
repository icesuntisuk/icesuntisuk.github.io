# v.1 FIM in current directory
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
            #lineNotify(msg)
        files[file] = md5
    time.sleep(1)
