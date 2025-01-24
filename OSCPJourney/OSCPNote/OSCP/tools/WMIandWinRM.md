```
$user='jen';
$pass='Nexus1231';
$secureString = ConvertTo-SecureString $pass  -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $user, $secureString;

New-PSSession -ComputerName 192.168.152.72 -Credential $credential
```

