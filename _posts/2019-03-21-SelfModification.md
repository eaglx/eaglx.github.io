---
layout: post
title:  "Selfmodification"
date:   2019-03-21 00:00:00 +0000
categories: Dev
---

A function calling convention is a set of rules that determine how functions are called at the machine level. It is defined by the application's binary interface. The most popular are _CDECL_, _STDCALL_ and _FASTCALL_.

* CDECL - stacking parameters from right to left; the calling function must clear the stack after calling another function. Return value saved in EAX.
* STDCALL - stacking parameters from right to left; the stack should clean up the called function. Return value saved in EAX.
* FASTCALL - the first two parameters are stored in ECX and EDX, the others are stacked. Return value saved in EAX.

Is it possible to write a program that modifies itself on the fly? YES! But you must first prepare the appropriate permissions, because self-modification is blocked. The program being executed is loaded into memory. Regarding addresses, Windows divides the virtual address space into two parts:

* part for the kernel;
* part intended for the user.

In x86 architecture, the upper 2GB are reserved for the kernel and the lower 2GB for user processes. So virtual addresses from 0 to 0x7FFFFFFF are in user space, and addresses above in kernel space. For x64, user processes have access to 0x000007FFFFFFFFFF, and the kernel from 0xFFFF080000000000 (this address is a separator, the kernel cannot use it!). The file header is read from the disk when the system loads the program into the process address space. After loading, the program is located in a virtual address space managed by the system kernel. All this space is appropriately divided into different segments (see figure below). By default, a program compiled using Visual Studio allocates 1MB of space for the stack.

![mem_segments](/img/samomodyf/mem_segments.png)

We will focus only on the segment _TEXT_, where the program code resides. Behind _storage_ we have memory pages managed by the kernel (this is mapping to physical addresses). Here, the permissions are managed by the system and by default the TEXT segment is _read / execute_. This can be changed using the _VirtualProtect_ function. The code is compiled using Visual Studio 2013, running under Windows 7 (x86_64). The _VirtualProtect_ function has the following arguments:

* LPVOID lpAddress - the address of the region of the start page that will be subject to changing permissions;
* SIZE_T dwSize - region size;
* DWORD flNewProtect - target permissions;
* PDWORD lpflOldProtect - variable address to get outdated permissions.

The function returns a non-zero value if successful. We will consider a simple case. We have a function that prints the value of some variable. We want to change this value to another one.

{% highlight c++ %}
#include <cstdio>

void funToModify(void)
{
    int i = 0;
    ++i;
    printf("i = %d\n", i);
}

int main()
{

    funToModify();

    return 0;
}
{% endhighlight %}

To make a change on the fly, we need to see the machine code of our function _funToModify_. *ATTENTION* for the example to work, we must disable build optimization. We don't care about effective code ;).

![machinecode](/img/samomodyf/machinecode.png)

Our goal is to modify the selected item during the _runtime_. Machine code:
* 010E100E - location in the memory of the desired instruction;
* 83C0 01 - machine code for instructions that the CPU reads and executes;
* ADD EAX, 1 - human readable :)

We need to modify items 01. Okay, but how to do it? There are two methods:
* manual distance counting;
* writing a function that prints the address of our function.

We'll start by manually calculating the distance. The function starts at address 010E1000, and the target is under 010E1010 (because 010E100E + 3). Distance = 16 ;). Now the second method. Hmmm .... after modification the address of our function has changed. Current Code:

{% highlight c++ %}
#include <cstdio>

void funToModify(void);
void bar(void);
void printFunctionAddress(void *func_ptr, size_t func_len);

int main()
{
    void *foo_addr = (void*) funToModify;
    void *bar_addr = (void*) bar;

    printFunctionAddress(funToModify, (intptr_t)bar_addr - (intptr_t)foo_addr);

    return 0;
}

void funToModify(void)
{
    int i = 0;
    ++i;
    printf("i = %d\n", i);
}

void bar(void){ ; }

void printFunctionAddress(void *func_ptr, size_t func_len)
{
    for (unsigned char i = 0; i < func_len; i++)
    {
        unsigned char *instr = (unsigned char*)func_ptr + i;
        printf("%p (%2u): %x\n", (size_t)func_ptr + i, i, *instr);
    }
}
{% endhighlight %}

![newaddr](/img/samomodyf/newaddr.png)

The address will always change - this is a form of protection against modifications. So we will use the second method. On the right, in the photo, we have the addresses displayed. We are interested in item _013A1040_. Fortunately, we can see that this is the 16th position! So as much as we came from the calculation.

![out](/img/samomodyf/out.png)

Correct modification in _runtime_! Full code below.

{% highlight c++ %}
#include <cstdio>
#include <windows.h>

void funToModify(void);
void bar(void);
void printFunctionAddress(void *func_ptr, size_t func_len);
int changePagePermissionsOfAddress(void *addr);

int TargetValue;

int main()
{
    void *foo_addr = (void*) funToModify;
    void *bar_addr = (void*) bar;

    printFunctionAddress(funToModify, (intptr_t)bar_addr - (intptr_t)foo_addr);

    if (changePagePermissionsOfAddress(foo_addr) == -1)
    {
        printf("Error while changing page permissions!\n");
        return 1;
    }
    else {
        printf("Changing page permissions SUCCESS!\n");
    }

    printf("Before modify:\n");
    funToModify();
    // Change value
    unsigned char *instr = (unsigned char*)foo_addr + 16;
    *instr = 2;
    printf("After modify:\n");
    funToModify();

    return 0;
}

void funToModify(void)
{
    int i = 0;
    ++i;
    printf("i = %d\n", i);
}

void bar(void){ ; }

void printFunctionAddress(void *func_ptr, size_t func_len)
{
    for (unsigned char i = 0; i < func_len; i++)
    {
        unsigned char *instr = (unsigned char*)func_ptr + i;
        printf("%p (%2u): %x\n", (size_t)func_ptr + i, i, *instr);
        if (i == 16) {
            printf("TARGET\n");
            TargetValue = i;
            return;
        }
    }
}

int changePagePermissionsOfAddress(void *addr)
{
    DWORD oldPerm;

    if (VirtualProtect(addr, sizeof(addr), PAGE_EXECUTE_READWRITE, &oldPerm) == 0)
    {
        return -1;
    }

    return 0;
}
{% endhighlight %}

#### A little theory
he physical memory of the computer is divided into units of 4kB (or pages, ofc can be larger; the size is determined by the PAGE_SIZE constant in the page.h file <= Linux). The addresses are divided into physical and virtual. Physical are the actual addresses of the memory cells used by the CPU. Virtual addresses are used by running programs (with paging enabled). The virtual address can have any numeric value. Addresses have a structure by which they are processed by the memory management processor unit. On x86 systems that support physical address extension (PAE), virtual memory addresses can be divided into three table iset up per-function exception handler
* PTE - a element.

The code is compiled using Visual Studio 2013 (optimization disabled), running under Windows 7 (x86_64). As a side note, before calling the main function _main_ we have something like  *__SEH_prolog4* , which can be seen in the figure below. This is an auxiliary function for the compiler that is used to set the exception handling for each function (_set up per-function exception handler_).

![prolog](/img/samomodyfshell/prolog.png)

e want to invoke some system command, e.g. _echo_, instead of the built-in function. Normally, a console command can be invoked in C using the following function.

{% highlight c++ %}
system("cmd.exe /c echo Hello World!");
{% endhighlight %}

As we look at what the above function looks like at assembly level, it's not too big. In the figure below we can see that it takes seven lines.

![normalcall](/img/samomodyfshell/normalcall.png)

The function that will be modified has the following form. It was deliberately chosen because of the size of the area we need for the injected code.

{% highlight c++ %}
void funToModify(void)
{
    int i = 0;
    ++i;
    i *= 5;
    printf("	i = %d\n", i);
    i -= 100;
    printf("	i = %d\n", i);
}
{% endhighlight %}

The above function normally at assembly level looks no more like the following figure.

![funbef](/img/samomodyfshell/funbef.png)

So what should the code look like be injected? We know that the argument for the system function is a string. In our case it is "cmd.exe / c echo Hello World!" Which will be sent to the stack. Important, we have to throw it in from the end!

{% highlight bash %}
echo -ne 'cmd.exe /c echo Hello World!' | xxd -ps | fold -w8 | tac
726c6421
6f20576f
48656c6c
63686f20
2f632065
65786520
636d642e
{% endhighlight %}

Above we see the generated hex form of our argument. Now we need to build our function using opcodes. Below is the complete code of our function with comments.

{% highlight c++ %}
"\x55"                 // PUSH EBP
"\x8b\xec"             // MOV EPB, ESP
"\x33\xc0"             // XOR EAX, EAX
"\x68\x00\x00\x00\x00" // PUSH
"\x68\x72\x6c\x64\x21" // PUSH
"\x68\x6f\x20\x57\x6f" // PUSH
"\x68\x48\x65\x6c\x6c" // PUSH
"\x68\x63\x68\x6f\x20" // PUSH
"\x68\x2f\x63\x20\x65" // PUSH
"\x68\x65\x78\x65\x20" // PUSH
"\x68\x63\x6d\x64\x2e" // PUSH
"\x8b\xfc"             // MOV EDI, ESP - adding a pointer to the stack
"\x57"                 // PUSH EDI
"\xb8\x2d\x0b\xa7\x74" // MOVE EAx, msvcrt.74a70b2d - using the hardcoded address
"\xff\xd0"             // CALL EAX
"\x83\xc4\x08"         // ADD ESP, 8
"\x8b\xe5"             // MOV ESP, EBP
"\x5d"                 // POP EBP
"\xc3";                // RET
{% endhighlight %}

NOTE, the address of the _msvcrt.74a70b2d_ function, i.e. _system_, may be different after restarting. This is because the _msvcrt_ library has been loaded at a different address. The main function looks like below at assembly level. From 01261044 to 01261055 addresses we see the process of modifying the code.

![main](/img/samomodyfshell/main.png)

As we can see in the figure below, our new function occupies the area 01261080 to 012610BD. It is shorter than the original function, you can see the last commands of the previous one. An important element is that we use the EAX register to call the system function.

![funaft](/img/samomodyfshell/funaft.png)

The result of our program :).

![fin](/img/samomodyfshell/fin.png)

{% highlight c++ %}
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#define _CRT_SECURE_DEPRECATE_MEMORY
#include <memory.h>

char shellcode[] =     // == system("cmd.exe /c echo Hello World!")
"\x55"                 // PUSH EBP
"\x8b\xec"             // MOV EPB, ESP
"\x33\xc0"             // XOR EAX, EAX
"\x68\x00\x00\x00\x00" // PUSH
"\x68\x72\x6c\x64\x21" // PUSH
"\x68\x6f\x20\x57\x6f" // PUSH
"\x68\x48\x65\x6c\x6c" // PUSH
"\x68\x63\x68\x6f\x20" // PUSH
"\x68\x2f\x63\x20\x65" // PUSH
"\x68\x65\x78\x65\x20" // PUSH
"\x68\x63\x6d\x64\x2e" // PUSH
"\x8b\xfc"             // MOV EDI, ESP - adding a pointer to the stack
"\x57"                 // PUSH EDI
"\xb8\x2d\x0b\xa7\x74" // MOVE EAx, msvcrt.74a70b2d - using the hardcoded address
"\xff\xd0"             // CALL EAX
"\x83\xc4\x08"         // ADD ESP, 8
"\x8b\xe5"             // MOV ESP, EBP
"\x5d"                 // POP EBP
"\xc3";                // RET

void funToModify(void);
int changePagePermissionsOfAddress(void *addr);

int main(int argc, char **argv)
{

    printf("************ BUILD IN, call FUN\n");
    funToModify();
    void *foo_addr = (void*)funToModify;
    if (changePagePermissionsOfAddress(foo_addr) == -1)
    {
        printf("Error while changing page permissions!\n");
        return 1;
    }
    memcpy(foo_addr, shellcode, sizeof(shellcode)-1);
    printf("************ SHELL INJECT, call FUN\n");
    funToModify();
    return 0;
}

void funToModify(void)
{
    int i = 0;
    ++i;
    i *= 5;
    printf("	i = %d\n", i);
    i -= 100;
    printf("	i = %d\n", i);
}

int changePagePermissionsOfAddress(void *addr)
{
    DWORD oldPerm;

    if (VirtualProtect(addr, sizeof(addr), PAGE_EXECUTE_READWRITE, &oldPerm) == 0)
    {
        return -1;
    }

    return 0;
}
{% endhighlight %}