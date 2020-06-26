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
Let's start off with something simple: This payload adds a new user to the ```/etc/passwd``` file. Let's have a look at the configurable options:
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
