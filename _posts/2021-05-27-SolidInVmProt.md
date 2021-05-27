---
layout: post
title:  "Looking for SOLID in VMPROTECT"
date:   2021-05-27 19:40:00 +0000
categories: Dev
---

### About VMPROTECT
A virtual machine that simulates a CPU along with a few other hardware components, allows to perform arithmetic operations, reads and writes to memory and interacts with I/O devices. It can understand a machine language which can be used to program it. Virtual machines used in code obfuscation are completely different than common virtual machnines. They are very specific to the task of executing a few set of instructions. Each instruction is given a custom opcode (often generated at random) [Repository](https://github.com/eaglx/VMPROTECT).

### What is SOLID
It is a mnemonic acronym for five design principles [source](https://en.wikipedia.org/wiki/SOLID):
* The Single-responsibility,
* The Open-closed,
* The Liskov substitution,
* The Interface segregation,
* The Dependency inversion.

### The Single-responsibility
_"There should never be more than one reason for a class to change." In other words, every class should have only one responsibility. [source](https://en.wikipedia.org/wiki/SOLID)_

According to this principle, we create a class/structure object that will only perform a specific task. If at a later time you need to add additional responsibility then move it to a separate object. Let's first check out what structures in the project look like. The first structure ADDRESS_SPACE (*PADDRESS_SPACE) satisfies this rule because it only deals with memory consisting of three elements:
* codeData
* stack
* dataBuffer

When it comes to REGISTERSS (*PREGISTERSS) which only deals with records, will also meet this rule.

{% highlight c++ %}
typedef struct {
    /* Here will be a code to execute and other data - 50KB*/
    VBYTE codeData[CODE_DATA_SIZE];

    /* Size of one element is VDWORD 
    in order to be able to push addresses. */
    VDWORD stack[STACK_SIZE];

    /* Here will be a user input*/
    VBYTE dataBuffer[INPUT_BUFFER_SIZE];
} ADDRESS_SPACE, *PADDRESS_SPACE;

typedef struct {
    /* General Purpose Registers R0 -> R7 */
    VDWORD R[8];
    struct {
        /* Zero Flag 
            value 1 - flag is set if the result of the last comparison was zero
            value 0 - flag is not set
        */
        unsigned char ZF : 1;
        /* Carry Flag 
            value 1 - flag is set the results of the last comparison was moving
            value 0 - flag is not set
        */
        unsigned char CF : 1;
    };
    /* Program Counter */
    VDWORD PC;
    /* Stack Pointer */
    VDWORD SP;
} REGISTERSS, *PREGISTERSS;
{% endhighlight %}

As for the VMCPU class that describes the processor, it does not follow this rule. The class can be seen below.

{% highlight c++ %}
class VMCPU {
    public:
        bool areFramesNeeded;
        std::map<int, int> frameMap;

    private:
        PADDRESS_SPACE AS;
        PREGISTERSS REGS;
        #ifdef _WIN32_DEV_ENVIRONMENT
            WIN32 *sysBus;
        #else //_LINUX_DEV_ENVIRONMENT
            UNIX *sysBus;
        #endif

        int currentFrameNumber;
        bool isError;

    private:
        int executer(VBYTE);
        void getDataFromCodeData(std::string &, int);
        void vmPrint(VBYTE s);
        void vmPrintHX(VDWORD);
        void vmPrintN(VBYTE s);
        void vmPrintHXN(VDWORD);
        void writeByteIntoFrame(int, int, std::vector<VBYTE>);
        std::vector<VBYTE> getByteFromFrame(int, int);
        int loadFrame(int);
        void restoreFrame();

    public:
        VMCPU();
        ~VMCPU();
        void run();
        void debug();
        bool loadCode(VBYTE *, int);
        void memoryManager();
};
{% endhighlight %}

The functionality of the class is complex and performs various tasks such as:
* writing characters to the screen,
* executing virtual instructions,
* memory handling,
* handling of memory frames.

The functionality of the VMCPU class should be broken down as shown below.

{% highlight c++ %}
class VMMEMORY {
    public:
        bool areFramesNeeded;
        std::map<int, int> frameMap;
        void getDataFromCodeData(std::string &, int);
        void writeByteIntoFrame(int, int, std::vector<VBYTE>);
        bool loadCode(VBYTE *, int);
        void memoryManager();
    private:
        PADDRESS_SPACE AS;
        PREGISTERSS REGS;
        int currentFrameNumber;
        int loadFrame(int);
        void restoreFrame();
}; 

class VMSCREEN {
    public:
        void vmPrint(VBYTE s);
        void vmPrintHX(VDWORD);
        void vmPrintN(VBYTE s);
        void vmPrintHXN(VDWORD);
}; 

class VMCPU {
    private:
        bool isError;
    private:
        int executer(VBYTE);
    public:
        VMCPU();
        ~VMCPU();
        void run();
        void debug();
};
{% endhighlight %}

### The Open-closed
_"Software entities ... should be open for extension, but closed for modification." [source](https://en.wikipedia.org/wiki/SOLID)_

The principle assumes that a module should be open for extension of functionality but modification of existing code is blocked. Openness means the possibility to change the behavior of a module without changing the source code. Extending the capabilities of a component can be done, for example, by using inheritance. The _executer(VBYTE)_ function deals with the execution of a virtual instruction. In the giant switch the appropriate case for the instruction is selected. If there will be another instruction to handle, we must modify the current _executer(VBYTE)_ function by adding another case.

{% highlight c++ %}
int VMCPU::executer(VBYTE opcode)
{
    int valToReturn = 0;

    VBYTE bTmp_0, bTmp_1, bTmp_2;
    VWORD wTmp_0, wTmp_1;
    VDWORD dTmp_0, dTmp_1, dTmp_2;

    switch(opcode)
    {
        /* NOP */
        case 0x56:
        case 0x6d:
        case NOP:
            #ifdef V_DEBUG
                std::cout << "[DEBUG] NOP" << std::endl;
            #endif
            opcode+=20;
            break;
        /* EE - end of code */
        case EE:
            #ifdef V_DEBUG
                std::cout << "[DEBUG] EE" << std::endl;
            #endif
            valToReturn = 1;
            break;
...
        /* 
            MOVMRD - move double word from memory to register
                    get addr from register
            0D 02 01 => MOVMRW R2, R1
        */
        case MOVMRD:
            #ifdef V_DEBUG
                std::cout << "[DEBUG] MOVMRD" << std::endl;
            #endif
            bTmp_0 = AS->codeData[REGS->PC++];
            if(bTmp_0 > 8) goto EXCEPTION;
            bTmp_1 = AS->codeData[REGS->PC++];
            if(bTmp_1 > 8) goto EXCEPTION;
            //if(REGS->R[bTmp_1] >= sizeof(AS->codeData)) goto EXCEPTION;
            if(areFramesNeeded && (REGS->R[bTmp_1] >= frameMap[currentFrameNumber]))
            {
                std::vector<VBYTE> bytes = getByteFromFrame(REGS->R[bTmp_1], 4);
                if(isError) goto EXCEPTION;
                VBYTE hb3 = bytes[0];
                VBYTE hb2 = bytes[1];
                VBYTE hb1 = bytes[2];
                VBYTE lb = bytes[3];
                VDWORD dw = ((VDWORD) hb3 << 24) | ((VDWORD) hb2 << 16) | ((VDWORD) hb1 << 8) | lb;
                REGS->R[bTmp_0] = dw;
            }
            else REGS->R[bTmp_0] = *(VDWORD*) &AS->codeData[REGS->R[bTmp_1]];
            break;
        /*  ********************************
                        JUMP
            ********************************
        */
        /*
            JMP - unconditional jump
            20 15 00 => JMP 0015
        */
        case JMP:
            #ifdef V_DEBUG
                std::cout << "[DEBUG] JMP" << std::endl;
            #endif
            wTmp_0 = *(VWORD*) &AS->codeData[REGS->PC];
            REGS->PC += 2;
            // if(wTmp_0 > sizeof(AS->codeData)) goto EXCEPTION;
            REGS->PC = wTmp_0;
            break; 
{% endhighlight %}

The best approach to replacing this switch statement with a dictionary that is mapping values to functions that get called in response to them. A dictionary will take a constant time and there will be extra memory wasted. But a large switch statement is a nightmare.

{% highlight c++ %}
#include <map>

class VMCPU {
    private:
        void opFuncEE();
        void opFuncMOV();
        void opFuncMOVMB();
        void opFuncMOVMW();
        void opFuncJMP();
        void opFuncJNZ();
        ...

        std::map<int, void*> mapOpcodesFunction= {
            { MOV, &opFuncMOV }
            ...
        };
        int executer(VBYTE);
...
};

int VMCPU::executer(VBYTE opcode)
{
    ...
    (*mapOpcodesFunction[opcode])();
}
{% endhighlight %}

### The Liskov substitution
_"Functions that use pointers or references to base classes must be able to use objects of derived classes without knowing it." [source](https://en.wikipedia.org/wiki/SOLID)_

A case like this is not in this project.

### The Interface segregation
_"Many client-specific interfaces are better than one general-purpose interface." [source](https://en.wikipedia.org/wiki/SOLID)_

A case like this is not in this project.

### The Dependency inversion
_"Depend upon abstractions, [not] concretions." [source](https://en.wikipedia.org/wiki/SOLID)_

Yes, the project violates this principle.

{% highlight c++ %}
typedef struct {                    // <<<<<<--------- LOW-LEVEL
    VBYTE codeData[CODE_DATA_SIZE];
    VDWORD stack[STACK_SIZE];
    VBYTE dataBuffer[INPUT_BUFFER_SIZE];
} ADDRESS_SPACE, *PADDRESS_SPACE;

typedef struct {                    // <<<<<<--------- LOW-LEVEL
    VDWORD R[8];
    VDWORD PC;
    VDWORD SP;
} REGISTERSS, *PREGISTERSS;

class VMCPU {                      // <<<<<<--------- HIGH-LEVEL
    private:
        PADDRESS_SPACE AS;
        PREGISTERSS REGS;
};
{% endhighlight %}

When for example we change stack from _array_ to _list_ or any other container, we need to change in many places which violates this principle. The high-level _VMCPU_ module depend on low-level modules ADDRESS_SPACE (*PADDRESS_SPACE) and REGISTERSS (*PREGISTERSS). An example solution is below.

{% highlight c++ %}
class VMMEMORYCONTROLLER {
    ... 
};

class VMMEMORY: VMMEMORYCONTROLLER {
    ...
}; 

class VMCPU {
    private:
        VMCONTROLLER memController;
};
{% endhighlight %}