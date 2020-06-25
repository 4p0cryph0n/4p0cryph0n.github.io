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

- There are three (mainly two functions) methods that we can use to do this, each of which impact the size of the shellcode. [Skape's paper](http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf) is a great read for understanding each method in depth.

Alright, now that we have a fair idea of how things should work, let's dive in!

## Using sigaction() ##
This method of writing an egghunter involves using the ```sigaction()``` function to scan through multiple address in memory at the same time, in order to determine which addresses are accessible and which are not. This method is by far the fastest and most efficient implementation of an x86 egghunter. It is the smallest in size too.

```c
#include <signal.h>

      int sigaction(int signum, const struct sigaction *act,
                    struct sigaction *oldact);
```

So when a group of addresses is restricted, a flag is returned. This flag is the ```EFAULT``` flag, and this is what our ```sigaction()``` function will look for. However, we will need to pass an argument through this function directly, which is the ```PAGE_SIZE``` variable, which helps us in setting the location of memory regions, in order to search through the VAS. This basically sets up the page alignment.

This variable will be incremented after each search, in order to switch memory regions when they are restricted. Keep in mind that this function searches through multiple addresses at the same time, looking for 16 bytes of continuous data at each region. This is what makes this method faster than its predecessor, which involves using the ```access()``` function.

So what goes in ```ebx``` and ```edx``` does not concern us. ```ecx``` will take the address to search through. I don't feel the need to write a c prototype for this method, so I will be directly jumping to the assembly code.

### Aseembly time!
We start off by gathering our syscall numbers:
```
#define __NR_sigaction 67
```
Now, we will need the value of our ```PAGE_SIZE``` variable. This is what we will store in ```ecx```, and keep incrementing:
```
$ getconf PAGE_SIZE
4096
```
The ```EFAULT``` flag in hex is ```0xf2```.

Alright, let's start off by setting up our page alignment:
```nasm
global _start:

section .text
_start:

page_size:

 or cx, 0xfff     ;4096
```
 Now, let's write a piece of code that checks for the ```EFAULT``` flag, and changes memory regions if that flag is returned:
 ```nasm
 efault_check:

	xor eax, eax    ;clearing eax
	inc ecx         ;memory region
	mov al, 0x43    ;67 --> sigaction
	int 0x80        ;syscall

	cmp al, 0xf2    ;compare the flag returned to EFAULT
	jz page_size    ;If it matches, set page alignment again and search through next region
```
