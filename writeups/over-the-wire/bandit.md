---
description: This is a collection of challenges built around common Linux utilities.
---

# Bandit

## Level 0

To start off we follow the instructions found here [https://overthewire.org/wargames/bandit/bandit0.html](https://overthewire.org/wargames/bandit/bandit0.html) and ssh to bandit.labs.overthewire.org on port 2220 as the user bandit0. To do this I will be using the Debian Windows Subsystem for Linux \(mostly because putty can be annoying to work with\). Just as a note, I will not be explaining these solutions, simply showing what commands can be used to find the flag. That being said, I am also using this an an exercise to test my bash-fu a little.

## Level 1

> The password for the next level is stored in a file called **readme** located in the home directory. Use this password to log into bandit1 using SSH. Whenever you find a password for a level, use SSH \(on port 2220\) to log into that level and continue the game.

{% tabs %}
{% tab title="Solution" %}
```bash
cat readme
```
{% endtab %}

{% tab title="Flag" %}
```
boJ9jbbUNNfktd78OOpsqOltutMc3MY1
```
{% endtab %}
{% endtabs %}

## Level 2

> The password for the next level is stored in a file called **-** located in the home directory

{% tabs %}
{% tab title="Solution" %}
```bash
cat /home/bandit1/-
```
{% endtab %}

{% tab title="Flag" %}
```
CV1DtqXWVFXTvM2F0k09SHz0YwRINYA9
```
{% endtab %}
{% endtabs %}

## Level 3

> The password for the next level is stored in a file called **spaces in this filename** located in the home directory

{% tabs %}
{% tab title="Solution" %}
```bash
cat ./spaces\ in\ this\ filename
```
{% endtab %}

{% tab title="Flag" %}
```
UmHadQclWmgdLOKQ3YNgjWxGoRMb5luK
```
{% endtab %}
{% endtabs %}

## Level 4

> The password for the next level is stored in a hidden file in the **inhere** directory.

{% tabs %}
{% tab title="Solution" %}
```bash
cat inhere/.hidden
```
{% endtab %}

{% tab title="Flag" %}
```
pIwrPrtPN36QITSp3EQaw936yaFoFgAB
```
{% endtab %}
{% endtabs %}

## Level 5

> The password for the next level is stored in the only human-readable file in the **inhere** directory. Tip: if your terminal is messed up, try the “reset” command.

{% tabs %}
{% tab title="Solution" %}
```bash
file inhere/* | grep ASCII | cat $(awk 'BEGIN { FS = ":"} ; { print $1}')
```
{% endtab %}

{% tab title="Flag" %}
```
koReBOKuIDDepwhWk7jZC0RTdopnAYKh
```
{% endtab %}
{% endtabs %}

## Level 6

> The password for the next level is stored in a file somewhere under the **inhere** directory and has all of the following properties:

> * human-readable
> * 1033 bytes in size
> * not executable

{% tabs %}
{% tab title="Solution" %}
```bash
cat $(find inhere -size 1033c)
```
{% endtab %}

{% tab title="Flag" %}
```
DXjZPULLxYr17uwoI01bNLQbtFemEgo7
```
{% endtab %}
{% endtabs %}

## Level 7

> The password for the next level is stored **somewhere on the server** and has all of the following properties:

> * owned by user bandit7
> * owned by group bandit6
> * 33 bytes in size

{% tabs %}
{% tab title="Solution" %}
```bash
cat $(find / -size 33c -user bandit7 -group bandit6 2> /dev/null)
```
{% endtab %}

{% tab title="Flag" %}
```
HKBPTKQnIay4Fw76bEy8PVxKEDQRKTzs
```
{% endtab %}
{% endtabs %}

## Level 8

> The password for the next level is stored in the file **data.txt** next to the word **millionth**

{% tabs %}
{% tab title="Solution" %}
```bash
grep millionth data.txt | awk ' {print $2} '
```
{% endtab %}

{% tab title="Flag" %}
```
cvX2JJa4CFALtqS87jk27qwqGhBM9plV
```
{% endtab %}
{% endtabs %}

## Level 9

> The password for the next level is stored in the file **data.txt** and is the only line of text that occurs only once

{% tabs %}
{% tab title="Solution" %}
```bash
cat data.txt | sort | uniq -u
```
{% endtab %}

{% tab title="Flag" %}
```
UsvVyFSfZZWbi6wgC7dAFyFuR6jQQUhR
```
{% endtab %}
{% endtabs %}

## Level 10

> The password for the next level is stored in the file **data.txt** in one of the few human-readable strings, beginning with several ‘=’ characters.

{% hint style="info" %}
Note that for this challenge there are multiple lines that match the regular expression `^=+` so we must use the knowledge that the flag is 32 characters long.
{% endhint %}

{% tabs %}
{% tab title="Solution" %}
```bash
strings data.txt | grep -E '^=+[[:space:]]{1}[[:alnum:]]{32}' | awk '{print $2}'
```
{% endtab %}

{% tab title="Flag" %}
```
truKLdjsbJ5g7yyJ2X2R0o3a5HQJFuLk
```
{% endtab %}
{% endtabs %}

## Level 11

> The password for the next level is stored in the file **data.txt**, which contains base64 encoded data

{% tabs %}
{% tab title="Solution" %}
```bash
base64 -d data.txt | awk '{print $4}'
```
{% endtab %}

{% tab title="Flag" %}
```
IFukwKGsFW8MOq3IRFqrxE1hxTNEbUPR
```
{% endtab %}
{% endtabs %}

## Level 12

> The password for the next level is stored in the file **data.txt**, where all lowercase \(a-z\) and uppercase \(A-Z\) letters have been rotated by 13 positions

{% tabs %}
{% tab title="Solution" %}
```bash
cat data.txt | tr A-Za-z N-ZA-Mn-za-m | awk '{print $4}'
```
{% endtab %}

{% tab title="Flag" %}
```
5Te8Y4drgCRfCx8ugdwuEX8KFC6k2EUu
```
{% endtab %}
{% endtabs %}

## Level **13**

> The password for the next level is stored in the file **data.txt**, which is a hexdump of a file that has been repeatedly compressed. For this level it may be useful to create a directory under /tmp in which you can work using mkdir. For example: mkdir /tmp/myname123. Then copy the datafile using cp, and rename it using mv \(read the manpages!\)

{% tabs %}
{% tab title="Solution" %}
```bash
xxd -r ~/data.txt - | gzip -d | bzip2 -d | gzip -d | tar xOf - | tar xOf - | bzip2 -d | tar xOf - | gunzip -d | awk '{print $4}'
```
{% endtab %}

{% tab title="Flag" %}
```
8ZjyCRiBWFYkneahHwxCv3wb2a1ORpYL
```
{% endtab %}
{% endtabs %}

## Level 14

> The password for the next level is stored in **/etc/bandit\_pass/bandit14 and can only be read by user bandit14**. For this level, you don’t get the next password, but you get a private SSH key that can be used to log into the next level. **Note:** **localhost** is a hostname that refers to the machine you are working on

{% tabs %}
{% tab title="Solution" %}
```bash
ssh -i sshkey.private bandit14@localhost cat /etc/bandit_pass/bandit14
```
{% endtab %}

{% tab title="Flag" %}
```
4wcYUJFw0k0XLShlDzztnTBHiqxU3b3e
```
{% endtab %}
{% endtabs %}



## Level 15

> The password for the next level can be retrieved by submitting the password of the current level to **port 30000 on localhost**.

{% tabs %}
{% tab title="Solution" %}
```bash
nc -nv 127.0.0.1 30000 < /etc/bandit_pass/bandit14
```
{% endtab %}

{% tab title="Flag" %}
```
BfMYroe26WYalil77FoDi9qh59eK5xNr
```
{% endtab %}
{% endtabs %}

## Level 16

> The password for the next level can be retrieved by submitting the password of the current level to **port 30001 on localhost** using SSL encryption.
>
> **Helpful note: Getting “HEARTBEATING” and “Read R BLOCK”? Use -ign\_eof and read the “CONNECTED COMMANDS” section in the manpage. Next to ‘R’ and ‘Q’, the ‘B’ command also works in this version of that command…**

{% tabs %}
{% tab title="Solution" %}
```bash
openssl s_client -ign_eof -connect 127.0.0.1:30001 < /etc/bandit_pass/bandit15
```
{% endtab %}

{% tab title="Flag" %}
```
cluFn7wTiGryunymYOu4RcffSxQluehd
```
{% endtab %}
{% endtabs %}

## Level 17

> The credentials for the next level can be retrieved by submitting the password of the current level to **a port on localhost in the range 31000 to 32000**. First find out which of these ports have a server listening on them. Then find out which of those speak SSL and which don’t. There is only 1 server that will give the next credentials, the others will simply send back to you whatever you send to it.

Okay, I have to admit that my solution here is **ugly**, but was able to get it into a form that you could copy and paste. The basic flow of this solution goes:

1. Do an nmap scan for open ports  between 31000-32000 on 127.0.0.1, enumerate the service versions on each open port, then output in grepable formate to stdout
2. ignore all lines starting with `#` or containing `Status`
3. grab the portion of the output with the open ports results
4. Cut the remaining strings off at the work `Ignored`
5. change all commas to new lines \(this will make it so each port's results are on it's own line\)
6. trim all spaces and tabs
7. ignore all lines that contain the word `echo` \(We want to avoid the echo servers\)
8. grab the first field, which is the port number of the valid port
9. Put this value into an environment variable named `PORT`
10. Use `$PORT` to connect to the correct port and pipe in the correct password from `/etc/bandit_pass/bandit16` to get the flag

While technically two commands, I'd say it is pretty compact. This page was super helpful in working with the nmap output: [https://github.com/leonjza/awesome-nmap-grep\#print-the-top-10-ports](https://github.com/leonjza/awesome-nmap-grep#print-the-top-10-ports) 

{% tabs %}
{% tab title="Solution" %}
```bash
PORT=$(nmap -sV -p 31000-32000 -oG - 127.0.0.1 | egrep -v "^#|Status" | cut -d ' ' -f4- | sed -n -e 's/Ignored.*//p' | tr ',' '\n' | sed -e 's/^[ \t]*//' | egrep -v "unknown" | cut -d '/' -f1); openssl s_client -ign_eof -connect 127.0.0.1:$PORT < /etc/bandit_pass/bandit16
```
{% endtab %}

{% tab title="Flag" %}
```
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAvmOkuifmMg6HL2YPIOjon6iWfbp7c3jx34YkYWqUH57SUdyJ
imZzeyGC0gtZPGujUSxiJSWI/oTqexh+cAMTSMlOJf7+BrJObArnxd9Y7YT2bRPQ
Ja6Lzb558YW3FZl87ORiO+rW4LCDCNd2lUvLE/GL2GWyuKN0K5iCd5TbtJzEkQTu
DSt2mcNn4rhAL+JFr56o4T6z8WWAW18BR6yGrMq7Q/kALHYW3OekePQAzL0VUYbW
JGTi65CxbCnzc/w4+mqQyvmzpWtMAzJTzAzQxNbkR2MBGySxDLrjg0LWN6sK7wNX
x0YVztz/zbIkPjfkU1jHS+9EbVNj+D1XFOJuaQIDAQABAoIBABagpxpM1aoLWfvD
KHcj10nqcoBc4oE11aFYQwik7xfW+24pRNuDE6SFthOar69jp5RlLwD1NhPx3iBl
J9nOM8OJ0VToum43UOS8YxF8WwhXriYGnc1sskbwpXOUDc9uX4+UESzH22P29ovd
d8WErY0gPxun8pbJLmxkAtWNhpMvfe0050vk9TL5wqbu9AlbssgTcCXkMQnPw9nC
YNN6DDP2lbcBrvgT9YCNL6C+ZKufD52yOQ9qOkwFTEQpjtF4uNtJom+asvlpmS8A
vLY9r60wYSvmZhNqBUrj7lyCtXMIu1kkd4w7F77k+DjHoAXyxcUp1DGL51sOmama
+TOWWgECgYEA8JtPxP0GRJ+IQkX262jM3dEIkza8ky5moIwUqYdsx0NxHgRRhORT
8c8hAuRBb2G82so8vUHk/fur85OEfc9TncnCY2crpoqsghifKLxrLgtT+qDpfZnx
SatLdt8GfQ85yA7hnWWJ2MxF3NaeSDm75Lsm+tBbAiyc9P2jGRNtMSkCgYEAypHd
HCctNi/FwjulhttFx/rHYKhLidZDFYeiE/v45bN4yFm8x7R/b0iE7KaszX+Exdvt
SghaTdcG0Knyw1bpJVyusavPzpaJMjdJ6tcFhVAbAjm7enCIvGCSx+X3l5SiWg0A
R57hJglezIiVjv3aGwHwvlZvtszK6zV6oXFAu0ECgYAbjo46T4hyP5tJi93V5HDi
Ttiek7xRVxUl+iU7rWkGAXFpMLFteQEsRr7PJ/lemmEY5eTDAFMLy9FL2m9oQWCg
R8VdwSk8r9FGLS+9aKcV5PI/WEKlwgXinB3OhYimtiG2Cg5JCqIZFHxD6MjEGOiu
L8ktHMPvodBwNsSBULpG0QKBgBAplTfC1HOnWiMGOU3KPwYWt0O6CdTkmJOmL8Ni
blh9elyZ9FsGxsgtRBXRsqXuz7wtsQAgLHxbdLq/ZJQ7YfzOKU4ZxEnabvXnvWkU
YOdjHdSOoKvDQNWu6ucyLRAWFuISeXw9a/9p7ftpxm0TSgyvmfLF2MIAEwyzRqaM
77pBAoGAMmjmIJdjp+Ez8duyn3ieo36yrttF5NSsJLAbxFpdlc1gvtGCWW+9Cq0b
dxviW8+TFVEBl1O4f7HVm6EpTscdDxU+bCXWkfjuRb7Dy9GOtt9JPsX8MBTakzh3
vBgsyi/sN3RqRBcGU40fOoZyfAMT8s1m/uYv52O6IgeuZ/ujbjY=
-----END RSA PRIVATE KEY-----
```
{% endtab %}
{% endtabs %}



## Level 18

> There are 2 files in the homedirectory: **passwords.old and passwords.new**. The password for the next level is in **passwords.new** and is the only line that has been changed between **passwords.old and passwords.new**
>
> **NOTE: if you have solved this level and see ‘Byebye!’ when trying to log into bandit18, this is related to the next level, bandit19**

{% tabs %}
{% tab title="Solution" %}
```bash
diff passwords.old passwords.new | grep '>' | cut -d ' ' -f2
```
{% endtab %}

{% tab title="Flag" %}
```
kfBf3eYk5BPBRzwjqutbbfE887SVc5Yd
```
{% endtab %}
{% endtabs %}

## Level 19

> The password for the next level is stored in a file **readme** in the homedirectory. Unfortunately, someone has modified **.bashrc** to log you out when you log in with SSH.

Because the `.bashrc` for this user automatically kicks you, we simply run the command via ssh instead of logging in.

{% tabs %}
{% tab title="Solution" %}
```bash
ssh bandit18@bandit.labs.overthewire.org -p 2220 cat /home/bandit18/readme
```
{% endtab %}

{% tab title="Flag" %}
```
IueksS7Ubh8G3DCwVzrTd8rAVOwq3M5x
```
{% endtab %}
{% endtabs %}

## Level 20

> To gain access to the next level, you should use the setuid binary in the homedirectory. Execute it without arguments to find out how to use it. The password for this level can be found in the usual place \(/etc/bandit\_pass\), after you have used the setuid binary.

{% tabs %}
{% tab title="Solution" %}
```bash
./bandit20-do /bin/cat /etc/bandit_pass/bandit20
```
{% endtab %}

{% tab title="Flag" %}
```
GbKksEFF4yrVs6il55v6gwY5aVje5f0j
```
{% endtab %}
{% endtabs %}

## Level 21

> There is a setuid binary in the homedirectory that does the following: it makes a connection to localhost on the port you specify as a commandline argument. It then reads a line of text from the connection and compares it to the password in the previous level \(bandit20\). If the password is correct, it will transmit the password for the next level \(bandit21\)

{% tabs %}
{% tab title="Solution" %}
```bash
# In tmux pane 1:
nc -nvlp 31337 < /etc/bandit_pass/bandit20

# In tmux pane 2:
./suconnect 31337
```
{% endtab %}

{% tab title="Flag" %}
```
gE269g2h3mw3pwgrj0Ha9Uoqen1c9DGr
```
{% endtab %}
{% endtabs %}

## Level 22

> A program is running automatically at regular intervals from **cron**, the time-based job scheduler. Look in **/etc/cron.d/** for the configuration and see what command is being executed.

The cronjob in this challenge is simply writing to the following file:

{% tabs %}
{% tab title="Solution" %}
```bash
cat /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
```
{% endtab %}

{% tab title="Flag" %}
```
Yk7owGAcWjwMVRwrTesJEwB7WVOiILLI
```
{% endtab %}
{% endtabs %}

## Level 23

> A program is running automatically at regular intervals from **cron**, the time-based job scheduler. Look in **/etc/cron.d/** for the configuration and see what command is being executed.
>
> **NOTE:** Looking at shell scripts written by other people is a very useful skill. The script for this level is intentionally made easy to read. If you are having problems understanding what it does, try executing it to see the debug information it prints.

{% tabs %}
{% tab title="Solution" %}
```bash
cat /tmp/$(echo I am user bandit23 | md5sum | cut -d ' ' -f1)
```
{% endtab %}

{% tab title="Flag" %}
```
jc1udXuA1tiHqjIsL8yaapX5XIAI6i0n
```
{% endtab %}
{% endtabs %}

## Level 24

> A program is running automatically at regular intervals from **cron**, the time-based job scheduler. Look in **/etc/cron.d/** for the configuration and see what command is being executed.
>
> **NOTE:** This level requires you to create your own first shell-script. This is a very big step and you should be proud of yourself when you beat this level!
>
> **NOTE 2:** Keep in mind that your shell script is removed once executed, so you may want to keep a copy around…

{% tabs %}
{% tab title="Solution" %}
```bash
mkdir /tmp/bandit24_results
cd /tmp/bandit24_results
touch password.txt
chmod 666 password.txt
echo <<EOF > ./get_password.sh
#!/bin/bash
cat /etc/bandit_pass/bandit24 > /tmp/bandit24_results/password.txt
EOF
chmod 777 ./get_password.sh
cp ./get_password.sh /var/spool/bandit24
watch cat password.txt
```
{% endtab %}

{% tab title="Flag" %}
```
UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ
```
{% endtab %}
{% endtabs %}

## Level 25

> A daemon is listening on port 30002 and will give you the password for bandit25 if given the password for bandit24 and a secret numeric 4-digit pincode. There is no way to retrieve the pincode except by going through all of the 10000 combinations, called brute-forcing.

This could certainly be sped up quite a bit with multithreading, but I didn't feel it was necessary.

{% tabs %}
{% tab title="Solution" %}
```bash
python ./solution.py
```
{% endtab %}

{% tab title="solution.py" %}
```python
import socket

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
bandit24 = open('/etc/bandit_pass/bandit24','r').read().replace('\n','')
print "initiating brute force..."
connect = s.connect(('127.0.0.1',30002))
s.recv(1024)
for x in range(0,10000):
    print('attempting:{} {:04d}'.format(bandit24,x))
    s.send('{} {:04d}\n'.format(bandit24 , x))
    message = s.recv(1024)
    if 'Wrong!' not in message:
        print(message)
        break
s.close()
```
{% endtab %}

{% tab title="Flag" %}
```
uNG9O58gUE7snukf3bvZ0rxhtnjzSGzG
```
{% endtab %}
{% endtabs %}

