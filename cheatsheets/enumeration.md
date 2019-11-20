# Enumeration
## Nmap

  - Quick TCP Scan

```bash
nmap -sC -sV -vv -oN quick 10.10.10.10
```

  - Quick TCP Scan

```bash
nmap -sU -sV -vv -oN quick_udp 10.10.10.10
```

  - Full TCP Scan

```bash
nmap -sC -cV -p- -vv -oN full 10.10.10.10
```

## Banner Grabbing

  - Netcat Banner Grab

```bash
nc -v 10.10.10.10 <port>
```

  - Telnet Banner Grab

```bash
telnet 10.10.10.10 <port>
```

## SMB

  - Nmap Vulnerability Scan

```bash 
nmap -p 139,445 -vv --script=smb-vuln* 10.10.10.10
```

  - Nmap User and Share Scan

```bash
nmap -p 139,445 -vv --script=smb-enum-shares.nse,smb-enum-users.nse 10.10.10.10
```

  - Enum4linux

```bash
enum4linux -a 10.10.10.10
```

  - Null Connection Test

```bash
rpcclient -U "" 10.10.10.10
```

  - Connecting to a client

```bash
smbclient //MOUNT/share
```
  - Getting the version of Samba:
  
```bash
# Originally from: https://0xdf.gitlab.io/2018/12/02/pwk-notes-smb-enumeration-checklist-update1.html#enum4linux
#!/bin/sh
#Author: rewardone
#Description:
# Requires root or enough permissions to use tcpdump
# Will listen for the first 7 packets of a null login
# and grab the SMB Version
#Notes:
# Will sometimes not capture or will print multiple
# lines. May need to run a second time for success.
if [ -z $1 ]; then echo "Usage: ./smbver.sh RHOST {RPORT}" && exit; else rhost=$1; fi
if [ ! -z $2 ]; then rport=$2; else rport=139; fi
tcpdump -s0 -n -i tap0 src $rhost and port $rport -A -c 7 2>/dev/null | grep -i "samba\|s.a.m" | tr -d '.' | grep -oP 'UnixSamba.*[0-9a-z]' | tr -d '\n' & echo -n "$rhost: " &
echo "exit" | smbclient -L $rhost 1>/dev/null 2>/dev/null
sleep 0.5 && echo ""
```
## SNMP

  - snmp-check

```bash
snmp-check 10.10.10.10
```

## Web Scanning
  - quick directory busting scan with gobuster

```bash
gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.10:<port> -s 200,204,301,302,307,403,500 -e -k -t 50 -np -o gobuster_quick_scan.txt 
```
  - targeting specific extensions with gobuster

```bash
gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.10:<port> -s 200,204,301,302,307,403,500 -e -k -t 50 -np -o gobuster_quick_scan.txt -x .txt,.php
```
  
  - Nikto

```bash
nikto -h http://10.10.10.10:<port>
```

  - WordPress Scan

```bash
wpscan -u 10.10.10.10 port
```

## Oracle Databases

  - Oscanner
  
```bash
oscanner -s 10.10.10.10. -p 1521
```
