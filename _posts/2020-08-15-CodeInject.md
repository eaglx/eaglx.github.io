---
layout: post
title:  "Five code injection techniques"
date:   2020-08-15 00:00:00 +0000
categories: Sec
---

Code injection techniques can be a way to bypass security mechanisms. They allow to execute any code in the space of another process that is currently running and has specific privilages. Because the code is executed in a different process, this software is not visible.

#### DLL injection
The method of injecting code into antoher program based on the use of a dynamic library is often used by malware authors. It comes down to the fact that he malware enters locations in its dynamic library into another process. It is important that after modification the program loads the malicious library into memory in a separate thread.

All operations will be based on Windows handlers. A handler is a reference to an object, process or thread. Thanks to this mechanism it is possible to get information about the process, e.g. what file reads or writes or what changes are made to the operating system. Moreover, the program can capture information from e.g. the keyboard.

![1](/img/inj/1.png)

The first step is to locate any program that is running. This is done using functions such as CreateToolHelp32Snapshot or Process32First. The first function is used to obtain information about the status of a given program in memory, while the second one acquires information about the process. Once the selected process is found, a handle is created for it through OpenProcess. Then the location is entered into dynamic library in the process under attack. For this purpose functions such as VirtualAllocEX and WriteProcessMemory are used. The first one creates free space for information about library's location and the second one makes modifications. After an correct modification a function such as CreateRemoteThread is called, which creates a new process of an attacked program. It is important that the starting point of the new process is located in the dynamic malware library. The disadvantage of this technique is that a large part of the protective software detects it because it monitors calls of the CreateRemoteThread function.

#### PE injection
The method of copying the code directly to the process is similar to the above mentioned method with a dynamic library, but in contrast to it the whole malware code is copied. The advantage of this technique is that no other files are needed.

![2](/img/inj/2.png)

The first step is to create with the VirtualAllocEx function a space in the attacked program, but much bigger than the technique with a library. Then using WriteProcessMemory it copies malicious code. The last step is to start execution of the injected code by creating a new thread with CreateRemoteThread. An important problem is locating the location of the malicious code in the attacked process. This is related to the ASLR mechanism problem. This problem is solved by using information from PE file section table.

#### Process Hollowing
The technique of overwriting the code in the memory of the process is connected with overwriting the contents of the attacked program in the memory of a malicious code.

![3](/img/inj/3.png)

The first step is to create a new process of a given program, which will be created and run in a pasue state, i.e. the program will be loaded in memory, but not executed. This is achived by using the CreateProcess function with the option CREATE_SUSPENDED and will remain on hold until the ResumeThread function is called. The next step is to transform the code content of the attacked process by malware. To do this first, the ZwUnmapViewOfSection function releases the memory of the attacked process, so that the malware can copy the malicious code. The next step is to overwrite the contents of the program with the malware code and then start the attacked process.

#### Thread execution hijacking
A similar technique to the analyzed method of overwriting the code of the attacked process it to take over the process of the thread of the attakced process. This way it can avoid re-creating the process or the thread. The first step of the attack is to stop the thread using SuspendThread. The first stage of the attack is to stop the thread using the SuspendThread function and then overwrite it with malicious code using the WriteProcessMemory function. The last step is to resume the attacked process thread.

![4](/img/inj/4.png)

It is important to modify the EIP register of the thread to execute malicious code. This is possible by using SetThreadContext function. From the malware author's point of view, the method of attacking the process thread can be problematic, because suspending and resuming the thread during a system call can cause system crashes.

#### Early bird code injection
The method of copying the code before starting the program (early bird code injection) uses the Asynchronous Procedure Calls (APC) mechanism. The first step is to create a new process which is in suspended mode. Then there is some free space created in the attacked process. The next step is to copy the malicious code to the created space using the WriteProcessMemory function. Next, an APC queue is created for the attacked process to run the malicious code. This is achived by using NtQueueApcThread function. The last step is to run the stopped process using the NtResumeThread function. After the APC queue result is set, the attacked process starts functions in the malicious code.

![5](/img/inj/5.png)