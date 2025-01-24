
#[[SMTP]]

```
rustscan -a 192.168.222.0/24 -p 25 --ulimit 5000 
nc -nv 192.168.50.8 25
```

```python
#!/usr/bin/python

import socket
import sys

if len(sys.argv) != 3:
        print("Usage: vrfy.py <username> <target_ip>")
        sys.exit(0)

# Create a Socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the Server
ip = sys.argv[2]
connect = s.connect((ip,25))

# Receive the banner
banner = s.recv(1024)

print(banner)

# VRFY a user
user = (sys.argv[1]).encode()
s.send(b'VRFY ' + user + b'\r\n')
result = s.recv(1024)

print(result)

# Close the socket
s.close()
```

```
python3 smtp.py root 192.168.50.8
python3 smtp.py johndoe 192.168.50.8

# Windows SMTP
Test-NetConnection -Port 25 192.168.50.8 
# Enable Telnet client 
dism /online /Enable-Feature /FeatureName:TelnetClient
telnet 192.168.50.8
```