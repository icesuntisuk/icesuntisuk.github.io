Check Services on Ubuntu
```bash
service --status-all
sudo lsof -i -n -P | more
# TCP Connection
sudo lsof -i -n -P | grep TCP | more
sudo netstat -ant 
# UDP Connection 
sudo lsof -i -n -P | grep UDP | more
sudo netstat -anu
```

UFW
```bash
sudo ufw enable
# Syntax UFW
# sudo ufw allow <port>
sudo ufw allow 22
sudo ufw allow 80/tcp
sudo ufw allow 1025/udp
sudo ufw allow from 127.0.0.1/8 to any port 21

# sudo ufw deny <Port>
sudo ufw deny 22

# Check status 
ufw status 
ufw status verbose
sudo ufw app list
sudo ufw status numbered

# Delete Rules 
sudo ufw delete {num}
sudo ufw delete 5
ufw delete deny 25/tcp comment 'Block access to smptd by default'

```