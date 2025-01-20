#[[host]]

```
#host -t $RECORD_TYPE $TARGET 
host -t A megacorpone.com
```

```
#Manual bruteforcing dns
cat list.txt
www
ftp
mail
owa
proxy
router
# Bruteforce dns
for ip in $(cat list.txt); do host $ip.megacorpone.com; done

# Bruteforce IP 200 - 254 
for ip in $(seq 200 254); do host 51.222.169.$ip; done | grep -v "not found"
```

#[[dnsrecon]]
```
# DNS recon Scan 
# -t to specify the type of enumeration to perform (in this case, a standard scan).
dnsrecon -d megacorpone.com -t std

# DNS Bruteforce
dnsrecon -d megacorpone.com -D ~/list.txt -t brt 
```

#dnsenum

```
#DNS bruteforce 
dnsenum megacorpone.com
```

#[[nslookup]]

```
nslookup -type=TXT info.megacorptwo.com 192.168.50.151 
```
