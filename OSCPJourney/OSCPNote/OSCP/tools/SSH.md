if you have Private KEY or id_rsa
Copy it to local 
```
copy home/offsec/.ssh/id_rsa to local 


cp id_rsa id2 
chmod 400 id2
sudo ssh -i id2 -p2222 offsec@mountaindesserts.com 
```