```
# nmap -Pn -iL <outputFile> -p<portNumber> <target> -oG nmap/smtp_exercise

nmap --script http-* 192.168.50.6 

# Search CVE 
nmap -sV -p- 192.168.222.0/24 

# Scan CVE on target IP 
sudo -sCV -p 443 --script "vuln" 192.168.222.222 

```