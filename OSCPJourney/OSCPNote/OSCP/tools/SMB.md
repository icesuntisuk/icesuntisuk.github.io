
#[[SMB]]

```
# SCA SMB
sudo nmap -Pn -p139,445 -sCV 192.168.222.0/24 

# Windows view file share Command 
net view \\dc01 //all

# Crackmap 
netexec smb 192.168.222.0/24 -u '' -p '' --shares 
netexec smb 192.168.222.0/24 -u 'alfred' -p '' --shares 

# enum4linux 
enum4linux -a 192.168.22.13 
```