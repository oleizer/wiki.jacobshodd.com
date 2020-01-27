# Hash Cracking \(with Hashcat\)

Hashcat is going to work best when running on your host machine rather than inside of a VM, especially if your host machine has a video card installed. When utilizing a graphics card, hashcat cat be _much_ faster than john the ripper. Below will just be a collection of commands I've used for different kinds of hashes.

## Cracking Unix MD5 Hashes:

```bash
 echo '$1$cVbu7POZ$WB/V36i/G00QKzHkkqWig/' > hashes.txt
 .\hashcat64.exe -o cracked.txt -m 500 .\hashes.txt .\rockyou.txt
 cat cracked.txt
```

## Cracking Windows NTLM Hashes:

```bash
echo C5E0002FDE3F5EB2CF5730FFEE58EBCC > hashes.txt
.\hashcat64.exe -o cracked.txt -m 1000 .\hashes.txt .\rockyou.txt
cat cracked.txt
```



