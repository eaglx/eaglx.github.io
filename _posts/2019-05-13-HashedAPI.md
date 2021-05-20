---
layout: post
title:  "HashedAPI-Carberp"
date:   2019-05-13 00:00:00 +0000
categories: Malw
---

Recently, I had the pleasure to analyze a Carberp (good whitepaper [HERE](https://www.fireeye.com/blog/threat-research/2019/04/carbanak-week-part-one-a-rare-occurrence.html)) that called Windows API functions, but hid them and it wasn't quite clear what was happening. Everything was based on the values returned by the hash function. But before I go on to the next description, I will present an interesting function that I discovered in C++, from libraries _STD_. Specifically, it's about the method _std::hash_. The usage is as follows.

{% highlight c++ %}
std::hash < std::string > hashString;
std::cout << ( hashString( "Get hash from text" ) ) << std::endl;
{% endhighlight %}

It is worth to notice that the algorithms for generating hash values may change in the future. In the above code the compiler g++ 7.4.0 will return the output _14534471473516538966_. At the beginning by generating the aforementioned function, _std::hash_, hashes of function names from the Windows API we can have something like the following.

{% highlight c++ %}
#define hashGetKeyboardLayout 0x059e7754
#define hashToAsciiEx 0x0899a6f8
#define hashGetCommandLineA 0x0c348a51
#define hashGetCurrentProcess 0x0b601193
#define hashSleep 0x005a2bc0
#define hashLoadLibraryA 0x0aadf0f1
#define hashLoadLibraryW 0x0aadf0c7
#define hashFreeLibrary 0x02b40339
#define hashGetProcAddress 0x0b3c1d03  // <<<<<<<<<<<<-------------------
#define hashOpenSCManagerA 0x0284af31
#define hashOpenSCManagerW 0x0284af27
#define hashOpenServiceA 0x09fa3a01
#define hashOpenServiceW 0x09fa3a37
#define hashChangeServiceConfig2A 0x05ce83a1
#define hashCloseServiceHandle 0x048eed15
#define hashMoveFileA 0x0c9cb6f1
#define hashRtlAdjustPrivilege 0x049fbb95
{% endhighlight %}

All of these functions (or most) are in the library _kernel32.dll_. So we're doing something like this.

{% highlight c++ %}
HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
if (kernel32 == NULL) {
    std::cout << "NULL VALUE" << std::endl;
    return -1;
}
GetApiAddr(kernel32, hashGetProcAddress);
{% endhighlight %}

The first thing is to download the handler to the library _kernel32.dll_, then we need to write a function that will find in the given library the address of the function which hash we have already calculated. Below the entire code of function _GetApiAddr_ is given. In short, the function retrieves the entire export table from the library. Then it loops the function name from the array and calculates the hash. If the hash value is the same as the searched value (calculated previously), then the function address is calculated and returned. Even after calculating the address, it is checked whether the function address is in the library address space. If it's not, the function address is searched by calling _GetProcAddress_.

{% highlight c++ %}
#define RVATOVA( base, offset ) ( (SIZE_T)base + (SIZE_T)offset )
typedef unsigned int uint;

void* GetApiAddr(HMODULE module, DWORD hashFunc)
{
    if (module == nullptr) return nullptr;

    PIMAGE_OPTIONAL_HEADER poh = (PIMAGE_OPTIONAL_HEADER)((LPVOID)((SIZE_T)module +
    ((PIMAGE_DOS_HEADER)(module))->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)));;
    PIMAGE_EXPORT_DIRECTORY exportDir = (IMAGE_EXPORT_DIRECTORY*)RVATOVA(module,
    poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    int exportSize = poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    int ordinal = -1;

    DWORD * namesTable = (DWORD*)RVATOVA(module, exportDir->AddressOfNames);
    WORD * ordinalTable = (WORD*)RVATOVA(module, exportDir->AddressOfNameOrdinals);


    for (uint i = 0; i < exportDir->NumberOfNames; i++)
    {
        //std::cout << (char*)RVATOVA(module, *namesTable) << std::endl;
        //getchar();

        char* name = (char*)RVATOVA(module, *namesTable);

        if (strcmp(name, "GetProcAddress") == 0) {
        std::cout << "GET NEW HASH" << std::endl;
        std::hash<char*> ptr_hash;
        std::stringstream strValue;
        strValue << ptr_hash(name);
        unsigned int intValue;
        strValue >> intValue;
        hashFunc = intValue;
    }

    std::hash<char*> ptr_hash;
    std::stringstream strValue;
    strValue << ptr_hash(name);
    unsigned int intValue;
    strValue >> intValue;

    std::cout << "Calc: " << intValue << " Search: " << hashFunc << std::endl;
    if (intValue == hashFunc)
    {
        ordinal = *ordinalTable;
        break;
    }

    namesTable++;
    ordinalTable++;
    }

    if (ordinal < 0)
        return nullptr;

    DWORD* addrTable = (DWORD*)RVATOVA(module, exportDir->AddressOfFunctions);
    SIZE_T rva = addrTable[ordinal];

    SIZE_T addr = (SIZE_T)RVATOVA(module, rva);
    if (addr > (SIZE_T)exportDir && addr < (SIZE_T)exportDir + exportSize)
    //(NameDll.NameFunc)
    {
        char* s = (char*)addr;
        char nameDll[32];
        int i = 0;
        while (s[i] != '.')
        {
            nameDll[i] = s[i];
            i++;
        }
        s += i + 1;
        nameDll[i++] = '.';
        nameDll[i++] = 'd';
        nameDll[i++] = 'l';
        nameDll[i++] = 'l';
        nameDll[i] = 0;
        int num = 0;
        if (*s == '#')
        {
            while (*++s) num = num * 10 + *s - '0';
            s = (char*)& num;
        }
        HMODULE hdll = LoadLibraryA(nameDll);
        return GetProcAddress(hdll, s);
    }
    else
        return (void*)addr;
}
{% endhighlight %}