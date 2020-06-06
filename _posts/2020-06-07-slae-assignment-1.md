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
