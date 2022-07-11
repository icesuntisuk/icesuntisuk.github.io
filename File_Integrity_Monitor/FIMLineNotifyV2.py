# Indeph directory traversal upgrade from v1 
import glob
import os, hashlib, time, requests

def lineNotify(msg):
    url = 'https://notify-api.line.me/api/notify'
    token = 'token ID'
    headers = {'content-type': 'application/x-www-form-urlencoded', 'Authorization': 'Bearer ' + token}
    r = requests.post(url,headers=headers,data={'message':msg})

files={}
result = []
while True:
    for x in os.walk('.'):
        for file in glob.glob(os.path.join(x[0], '*')):
            if os.path.isfile(file):
                result.append(file)
                # print(file)
                #Integrity Checking
                hash = hashlib.md5()
                with open(file,'rb') as f:
                    for chunk in iter (lambda : f.read(4096), b""):
                        hash.update(chunk)
                md5 = hash.hexdigest()
                if file in files and md5 != files[file]:
                    msg = str(time.strftime('%Y-%m-%d %H:%M:%S')) + " \nFile name = [" +str(file) + "] has been changed"
                    print(msg)
                    lineNotify(msg)
                files[file] = md5
    time.sleep(1)