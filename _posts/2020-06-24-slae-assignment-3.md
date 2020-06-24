---
title:  "SLAE x86 Assignment 3: Egghunter Shellcode"
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

Hey guys! Welcome back! In this post, we will write an egghunter shellcode for
assignment 3 of the SLAE x86 certification. Let's begin!

## Understanding The Objective ##
So what is an egghunter shellcode? An egghunter shellcode is used in situations where buffer size in a particular location is significantly small, which restricts an attacker to store large shellcodes in said location, in order for it to be executed.

To work around this, the shellcode is placed in another location of the process' VAS (Virtual Address Space) which has adequate space, and a smaller egghunter shellcode is placed in place of where the original shellcode would ideally go. The main purpose of this egghunter shellcode is to locate the original shellcode in memory, and pass execution to it.

So how does the egghunter locate the shellcode? It basically looks for an EGG, which is a unique string used as a sort of marker. So how this works is, we prepend the larger shellcode with the EGG twice, which is what the egghunter will look for in memory. Why twice? This is to prevent the egghunter from running into itself in memory, as the egghunter shellcode will also have those same 4 bytes stored in its code.

Alright, let's have a quick look at how this should work:

```
For eg, this is our shellcode here:

EGGEGGshellcodeshellcodeshellcodeshellcodeshellcode....

Our egghuter:

egghunter(address)
{
  if(val at address == EGGEGG)
    jump address
  else
    address + 1
}
```

This is a very simple representation of how it should work. However, there are a few things that we must understand before we proceed:

- In the VAS of a process, there are multiple branches of memory, which means that if we are searching through the whole VAS, we are bound to run into branches that we do not have the permission to access, which will trigger a segmentation fault (SIGSEGV signal). This will cause our executable to crash. Hence, we will need a process that looks for a particular flag that is triggered when trying to access a restricted memory location, and move on to the next branch in the case that it is in fact restricted. This will prevent us from trying to access locations that we cannot.

- There are three (mainly two) methods that we can use to do this, each of which impact the size of the shellcode. [Skape's paper](http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf) is a great read for understanding each method in depth.
