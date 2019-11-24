# Password Cracking

## Hashcat

Hashcat is going to work best when running on your host machine rather than inside of a VM, especially if your host machine has a video card installed. When utilizing a graphics card, hashcat cat be _much_ faster than john the ripper. Below will just be a collection of commands I've used for different kinds of hashes.

 - Cracking Unix MD5 Hashes:
 ```bash
 echo '$1$cVbu7POZ$WB/V36i/G00QKzHkkqWig/' > hashes.txt
 .\hashcat64.exe -o cracked -m 500 .\hashes.txt .\rockyou.txt
 ```
