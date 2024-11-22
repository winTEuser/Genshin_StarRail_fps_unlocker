#pragma once

#ifndef __NT_SYSAPI_H__
#define __NT_SYSAPI_H__

#include <Windows.h>

#ifndef _WIN64
#error this API define only work for Win64
#endif

#define DirectCall

extern "C" NTSTATUS NTAPI asm_syscall();
extern "C" void NTAPI asm_initpsc(DWORD* scnum);

DWORD sc_number = 0;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES* POBJECT_ATTRIBUTES;


typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;


typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation
} MEMORY_INFORMATION_CLASS, * PMEMORY_INFORMATION_CLASS;

typedef struct CLIENT_ID
{
    HANDLE UniqueProc;
    HANDLE UniqueThread;
}CLIENT_ID, * PCLIENT_ID;


typedef NTSTATUS(NTAPI* _ZwCreateThreadEx_Win64)(
    PHANDLE ThreadHandle,//out
    ACCESS_MASK DesiredAccess,//in
    LPVOID ObjectAttributes,//in
    HANDLE ProcessHandle,//in
    LPTHREAD_START_ROUTINE lpStartAddress,//in
    LPVOID lpParameter,//in
    DWORD  CreateThreadFlags,//in
    SIZE_T ZeroBits,//in
    SIZE_T StackSize,//in
    SIZE_T MaximumStackSize,//in
    PPROC_THREAD_ATTRIBUTE_LIST AttributeList//in
    );

typedef NTSTATUS(NTAPI* _NtCreateThread_Win64)(
    PHANDLE     ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE      ProcessHandle,
    PCLIENT_ID  ClientId,
    PCONTEXT    ThreadContext,
    LPVOID      InitialTeb,
    BOOLEAN     CreateSuspended
    );

typedef NTSTATUS(NTAPI* _ZwAllocateVirtualMemory_Win64)(
    HANDLE    ProcessHandle,
    PVOID*    BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
    );

typedef NTSTATUS(NTAPI* _ZwWriteVirtualMemory_Win64)(
    HANDLE    ProcessHandle,
    LPVOID    TargetAddress,
    LPVOID    SrcBuffer,
    SIZE_T    RegionSize,
    PSIZE_T   lpNumberOfBytesWritten
    );


typedef NTSTATUS(NTAPI* _NtCreateSection_Win64)(
    PHANDLE SectionHandle, 
    ACCESS_MASK DesiredAccess, 
    POBJECT_ATTRIBUTES ObjectAttributes, 
    PLARGE_INTEGER MaximumSize, 
    ULONG SectionPageProtection, 
    ULONG AllocationAttributes, 
    HANDLE FileHandle
    );

typedef NTSTATUS(NTAPI* _NtProtectVirtualMemory_Win64)(
    HANDLE  ProcesssHandle, 
    LPVOID* BaseAddress, 
    PSIZE_T Size, 
    DWORD   NewProtect, 
    PDWORD  OldProtect
    );

typedef NTSTATUS(NTAPI* _NtQueryVirtualMemory_Win64)(
    HANDLE ProcessHandle, 
    PVOID BaseAddress, 
    MEMORY_INFORMATION_CLASS MemoryInformationClass, 
    PVOID MemoryInformation, 
    SIZE_T MemoryInformationLength, 
    PSIZE_T ReturnLength
    );

typedef NTSTATUS(NTAPI* _NtOpenSection_Win64)(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSTATUS(NTAPI* _NtUnmapViewOfSection_Win64)(HANDLE ProcessHandle, PVOID BaseAddress);
typedef NTSTATUS(NTAPI* _NtMapViewOfSection_Win64)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    SECTION_INHERIT InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
    );

typedef DWORD(NTAPI* _RtlNtStatusToDosError_Win64)(DWORD Status);


_ZwCreateThreadEx_Win64 ZwCreateThreadEx = 0;
//_NtCreateThread_Win64 NtCreateThread = 0;
_ZwAllocateVirtualMemory_Win64 ZwAllocateVirtualMemory = 0;
_ZwWriteVirtualMemory_Win64 ZwWriteVirtualMemory = 0;
_NtProtectVirtualMemory_Win64 NtProtectVirtualMemory = 0;
_RtlNtStatusToDosError_Win64 RtlNtStatusToDosError = 0;

DWORD scNum_CreateThreadEx = 0;
//DWORD scNum_CreateThread = 0;
DWORD scNum_AllocMem = 0;
DWORD scNum_WriteMem = 0;
DWORD scNum_ProtectMem = 0;


static NTSTATUS NTAPI ZwCreateThreadEx_internel()
{
    sc_number = scNum_CreateThreadEx;
    return asm_syscall();
}

//static NTSTATUS NTAPI NtCreateThread_internel()
//{
//    sc_number = scNum_CreateThread;
//    return asm_syscall();
//}

static NTSTATUS NTAPI ZwAllocateVirtualMemory_internel()
{
    sc_number = scNum_AllocMem;
    return asm_syscall();
}

static NTSTATUS NTAPI ZwWriteVirtualMemory_internel()
{
    sc_number = scNum_WriteMem;
    return asm_syscall();
}

static NTSTATUS NTAPI NtProtectVirtualMemory_internel()
{
    sc_number = scNum_ProtectMem;
    return asm_syscall();
}

//copy from vmp
enum {
    WINDOWS_XP = 2600,
    WINDOWS_2003 = 3790,
    WINDOWS_VISTA = 6000,
    WINDOWS_VISTA_SP1 = 6001,
    WINDOWS_VISTA_SP2 = 6002,
    WINDOWS_7 = 7600,
    WINDOWS_7_SP1 = 7601,
    WINDOWS_8 = 9200,
    WINDOWS_8_1 = 9600,
    WINDOWS_10_TH1 = 10240,
    WINDOWS_10_TH2 = 10586,
    WINDOWS_10_RS1 = 14393,
    WINDOWS_10_RS2 = 15063,
    WINDOWS_10_RS3 = 16299,
    WINDOWS_10_RS4 = 17134,
    WINDOWS_10_RS5 = 17763,
    WINDOWS_10_19H1 = 18362,
    WINDOWS_10_19H2 = 18363,
    WINDOWS_10_20H1 = 19041,
    WINDOWS_10_20H2 = 19042,
    WINDOWS_10_21H1 = 19043,
    WINDOWS_10_21H2 = 19044,
    WINDOWS_10_22H2 = 19045,
    WINDOWS_11_21H2 = 22000,
    WINDOWS_11_22H2 = 22621,
    WINDOWS_11_23H2 = 22631,
    WINDOWS_11_24H2 = 26100,
};

#define IS_KNOWN_WINDOWS_BUILD(b) ( \
	(b) == WINDOWS_XP || \
	(b) == WINDOWS_2003 || \
	(b) == WINDOWS_VISTA || \
	(b) == WINDOWS_VISTA_SP1 || \
	(b) == WINDOWS_VISTA_SP2 || \
	(b) == WINDOWS_7 || \
	(b) == WINDOWS_7_SP1 || \
	(b) == WINDOWS_8 || \
	(b) == WINDOWS_8_1 || \
	(b) == WINDOWS_10_TH1 || \
	(b) == WINDOWS_10_TH2 || \
	(b) == WINDOWS_10_RS1 || \
	(b) == WINDOWS_10_RS2 || \
	(b) == WINDOWS_10_RS3 || \
	(b) == WINDOWS_10_RS4 || \
	(b) == WINDOWS_10_RS5 || \
	(b) == WINDOWS_10_19H1 || \
	(b) == WINDOWS_10_19H2 || \
	(b) == WINDOWS_10_20H1 || \
	(b) == WINDOWS_10_20H2 || \
	(b) == WINDOWS_10_21H1 || \
	(b) == WINDOWS_10_21H2 || \
	(b) == WINDOWS_10_22H2 || \
    (b) == WINDOWS_11_21H2 || \
    (b) == WINDOWS_11_22H2 || \
    (b) == WINDOWS_11_23H2 || \
    (b) == WINDOWS_11_24H2 \
)

typedef struct _PEB64 {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[0x115];
    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
} PEB64;

__declspec(noinline) const wchar_t* FindFileVersion(const BYTE* ptr, size_t data_size) {
    const wchar_t* data = reinterpret_cast<const wchar_t*>(ptr);
    data_size /= sizeof(wchar_t);

    for (size_t i = 0; i < data_size; i++) {
        if (data_size >= 13) {
            if (data[i + 0] == L'F' && data[i + 1] == L'i' && data[i + 2] == L'l' && data[i + 3] == L'e' && data[i + 4] == L'V' && data[i + 5] == L'e' && data[i + 6] == L'r' &&
                data[i + 7] == L's' && data[i + 8] == L'i' && data[i + 9] == L'o' && data[i + 10] == L'n' && data[i + 11] == 0 && data[i + 12] == 0)
                return data + i + 13;
        }
        if (data_size >= 15) {
            if (data[i + 0] == L'P' && data[i + 1] == L'r' && data[i + 2] == L'o' && data[i + 3] == L'd' && data[i + 4] == L'u' && data[i + 5] == L'c' && data[i + 6] == L't' &&
                data[i + 7] == L'V' && data[i + 8] == L'e' && data[i + 9] == L'r' && data[i + 10] == L's' && data[i + 11] == L'i' && data[i + 12] == L'o' && data[i + 13] == L'n' && data[i + 14] == 0)
                return data + i + 15;
        }
    }
    return NULL;
}

//need fix
WORD ParseOSBuildBumber(HMODULE ntdll)
{
    WORD os_build_number = 0;
    IMAGE_DOS_HEADER* dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(ntdll);
    if (dos_header->e_magic == IMAGE_DOS_SIGNATURE) 
    {
        IMAGE_NT_HEADERS* pe_header = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<BYTE*>(ntdll) + dos_header->e_lfanew);
        if (pe_header->Signature == IMAGE_NT_SIGNATURE) 
        {
            DWORD resource_adress = pe_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
            if (resource_adress) 
            {
                const BYTE* resource_start = reinterpret_cast<const BYTE*>(ntdll) + resource_adress;
                const BYTE* resource_end = resource_start + pe_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
                while (const wchar_t* file_version = FindFileVersion(resource_start, resource_end - resource_start)) 
                {
                    os_build_number = 0;
                    for (size_t i = 0; *file_version; file_version++) 
                    {
                        if (*file_version == L'.')
                            i++;
                        else if (i == 2) 
                        {
                            while (wchar_t c = *file_version++) 
                            {
                                if (c >= L'0' && c <= L'9') 
                                {
                                    os_build_number *= 10;
                                    os_build_number += c - L'0';
                                }
                                else
                                    break;
                            }
                            break;
                        }
                    }

                    if (IS_KNOWN_WINDOWS_BUILD(os_build_number))
                        break;

                    resource_start = reinterpret_cast<const BYTE*>(file_version);
                }
            }
        }
    }
    return os_build_number;
}



static void BaseSetLastNTError_inter(DWORD Status)
{
    return SetLastError(RtlNtStatusToDosError(Status));
}

static BOOLEAN WINAPI VirtualProtect_Internal(HANDLE procHandle, LPVOID baseAddr, size_t size, DWORD protect, DWORD* oldp)
{
    DWORD oldpt = 0;
    if (!oldp)
    {
        oldp = &oldpt;
    }
    if (size & 0xFFF)
    {
        size += 0x1000;
        size &= 0xFFFFFFFFF000;
    }
    NTSTATUS ret = NtProtectVirtualMemory(procHandle, &baseAddr, &size, protect, oldp);
    if (ret)
    {
        BaseSetLastNTError_inter(ret);
        return 0;
    }
    return 1;
}


static PVOID WINAPI VirtualAllocEx_Internal(HANDLE procHandle, PVOID* dst_baseaddr, size_t size, DWORD protect)
{
    void* baseaddr = 0;
    if (!dst_baseaddr)
        dst_baseaddr = &baseaddr;
    NTSTATUS ret = ZwAllocateVirtualMemory(procHandle, dst_baseaddr, 0, &size, MEM_COMMIT | MEM_RESERVE, protect);
    if (ret)
    {
        BaseSetLastNTError_inter(ret);
        return 0;
    }
    return baseaddr;
}

static PVOID WINAPI VirtualAlloc_Internal(PVOID* dst_baseaddr, size_t size, DWORD protect)
{
    void* baseaddr = 0;
    if (!dst_baseaddr)
        dst_baseaddr = &baseaddr;
    NTSTATUS ret = ZwAllocateVirtualMemory((HANDLE)-1, dst_baseaddr, 0, &size, MEM_COMMIT | MEM_RESERVE, protect);
    if (ret)
    {
        BaseSetLastNTError_inter(ret);
        return 0;
    }
    return baseaddr;
}


static BOOLEAN WINAPI WriteProcessMemoryInternal(HANDLE procHandle, LPVOID dst_baseaddr, LPVOID src_buffer, size_t size, size_t* writenum)
{
    size_t tsize = 0;
    NTSTATUS ret = ZwWriteVirtualMemory(procHandle, dst_baseaddr, src_buffer, size, &tsize);
    if (ret)
    {
        BaseSetLastNTError_inter(ret);
        return 0;
    }
    if (writenum)
    {
        *writenum = tsize;
    }
    return 1;
}


static HANDLE WINAPI CreateThread_Internal(HANDLE procHandle, LPSECURITY_ATTRIBUTES lpThreadAttributes, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter)
{
    HANDLE retHandle = 0;

    NTSTATUS status = ZwCreateThreadEx(&retHandle, 0x1FFFF, 0, procHandle, lpStartAddress, lpParameter, 0, 0, 0xC000, 0x30000, 0);
    if (status)
    {
        BaseSetLastNTError_inter(status);
        return 0;
    }
    return retHandle;
}


static void writebyte(void* dst, BYTE num)
{
    size_t i = 0;
    while (*((BYTE*)dst + i) != 0)
    {
        i++;
    }
    *((BYTE*)dst + i) = num;
}


static void init_syscall_buff(void* buffer)
{
    memset(buffer, 0xCC, 0x400);
    BYTE* startaddr = (BYTE*)buffer + 0x100;
    for(int i = 0; i != 0x5; i++)
    {
        *(DWORD64*)(startaddr + (i * 0x20)) = 0xFFFFFFFFB8CA8949;
        *(DWORD64*)(startaddr + (i * 0x20) + 0x8) = 0xFBEB050FC3401F0F;
    }
    *(DWORD*)(startaddr + 0x4) = scNum_CreateThreadEx;
    ZwCreateThreadEx = (_ZwCreateThreadEx_Win64)startaddr;
    startaddr += 0x20;
    *(DWORD*)(startaddr + 0x4) = scNum_AllocMem;
    ZwAllocateVirtualMemory = (_ZwAllocateVirtualMemory_Win64)startaddr;
    startaddr += 0x20;
    *(DWORD*)(startaddr + 0x4) = scNum_ProtectMem;
    NtProtectVirtualMemory = (_NtProtectVirtualMemory_Win64)startaddr;
    startaddr += 0x20;
    *(DWORD*)(startaddr + 0x4) = scNum_WriteMem;
    ZwWriteVirtualMemory = (_ZwWriteVirtualMemory_Win64)startaddr;
}

static NTSTATUS init_NTAPI()
{
    HMODULE ntdll = 0;
    {
        char str_ntdll[16] = { 0 };
        writebyte(str_ntdll, 'n');
        writebyte(str_ntdll, 't');
        writebyte(str_ntdll, 'd');
        writebyte(str_ntdll, 'l');
        writebyte(str_ntdll, 'l');
        writebyte(str_ntdll, '.');
        writebyte(str_ntdll, 'd');
        writebyte(str_ntdll, 'l');
        writebyte(str_ntdll, 'l');
        ntdll = GetModuleHandleA(str_ntdll);
    }
    if (!ntdll)
        return STATUS_DLL_NOT_FOUND;
#ifdef DirectCall
    PEB64* peb = reinterpret_cast<PEB64*>(__readgsqword(0x60));  
    //uint16_t OSver = ParseOSBuildBumber(ntdll);
    WORD OSver = peb->OSBuildNumber;
    bool init_OSver = 0;
    if (IS_KNOWN_WINDOWS_BUILD(OSver))
    {
        DWORD sc_CreateThreadEx = 0;
        //DWORD sc_CreateThread = 0;
        DWORD sc_AllocMem = 0;
        DWORD sc_WriteMem = 0;
        DWORD sc_ProtectMem = 0;
        if (OSver == WINDOWS_11_24H2)
        {
            sc_CreateThreadEx = 0xc9;
            sc_AllocMem = 0x18;
            sc_WriteMem = 0x3a;
            sc_ProtectMem = 0x50;
            init_OSver = 1;
        }
        else if (OSver == WINDOWS_11_22H2 || OSver == WINDOWS_11_23H2)
        {
            sc_CreateThreadEx = 0xc7;
            sc_AllocMem = 0x18;
            sc_WriteMem = 0x3a;
            sc_ProtectMem = 0x50;
            init_OSver = 1;
        }
        else if (OSver == WINDOWS_11_21H2)
        {
            sc_CreateThreadEx = 0xc6;
            sc_AllocMem = 0x18;
            sc_WriteMem = 0x3a;
            sc_ProtectMem = 0x50;
            init_OSver = 1;
        }
        else if (OSver == WINDOWS_10_22H2 || OSver == WINDOWS_10_21H2)
        {
            sc_CreateThreadEx = 0xc2;
            sc_AllocMem = 0x18;
            sc_WriteMem = 0x3a;
            sc_ProtectMem = 0x50;
            init_OSver = 1;
        }
        else if (OSver == WINDOWS_10_20H2 || OSver == WINDOWS_10_20H1 || OSver == WINDOWS_10_21H1)
        {
            sc_CreateThreadEx = 0xc1;
            sc_AllocMem = 0x18;
            sc_WriteMem = 0x3a;
            sc_ProtectMem = 0x50;
            init_OSver = 1;
        }
        else if (OSver == WINDOWS_10_19H2 || OSver == WINDOWS_10_19H1)
        {
            sc_CreateThreadEx = 0xbd;
            sc_AllocMem = 0x18;
            sc_WriteMem = 0x3a;
            sc_ProtectMem = 0x50;
            init_OSver = 1;
        }
        else if (OSver == WINDOWS_10_RS5)
        {
            sc_CreateThreadEx = 0xbc;
            sc_AllocMem = 0x18;
            sc_WriteMem = 0x3a;
            sc_ProtectMem = 0x50;
            init_OSver = 1;
        }
        else if (OSver == WINDOWS_10_RS4)
        {
            sc_CreateThreadEx = 0xbb;
            sc_AllocMem = 0x18;
            sc_WriteMem = 0x3a;
            sc_ProtectMem = 0x50;
            init_OSver = 1;
        }
        else if (OSver == WINDOWS_10_RS3)
        {
            sc_CreateThreadEx = 0xba;
            sc_AllocMem = 0x18;
            sc_WriteMem = 0x3a;
            sc_ProtectMem = 0x50;
            init_OSver = 1;
        }
        else if (OSver == WINDOWS_10_RS2)
        {
            sc_CreateThreadEx = 0xb9;
            sc_AllocMem = 0x18;
            sc_WriteMem = 0x3a;
            sc_ProtectMem = 0x50;
            init_OSver = 1;
        }
        else if (OSver == WINDOWS_10_RS1)
        {
            sc_CreateThreadEx = 0xb6;
            sc_AllocMem = 0x18;
            sc_WriteMem = 0x3a;
            sc_ProtectMem = 0x50;
            init_OSver = 1;
        }
        else if (OSver == WINDOWS_10_TH2)
        {
            sc_CreateThreadEx = 0xb4;
            sc_AllocMem = 0x18;
            sc_WriteMem = 0x3a;
            sc_ProtectMem = 0x50;
            init_OSver = 1;
        }
        else if (OSver == WINDOWS_10_TH1)
        {
            sc_CreateThreadEx = 0xb3;
            sc_AllocMem = 0x18;
            sc_WriteMem = 0x3a;
            sc_ProtectMem = 0x50;
            init_OSver = 1;
        }
        else if (OSver == WINDOWS_8_1)
        {
            sc_CreateThreadEx = 0xb0;
            //sc_CreateThread = 0x4d;
            sc_AllocMem = 0x17;
            sc_WriteMem = 0x39;
            sc_ProtectMem = 0x4f;
            init_OSver = 1;
        }
        else if (OSver == WINDOWS_8)
        {
            sc_CreateThreadEx = 0xaf;
            //sc_CreateThread = 0x4c;
            sc_AllocMem = 0x16;
            sc_WriteMem = 0x38;
            sc_ProtectMem = 0x4e;
            init_OSver = 1;
        }
        else if (OSver == WINDOWS_7_SP1)
        {
            sc_CreateThreadEx = 0xa5;
            //sc_CreateThread = 0x4b;
            sc_AllocMem = 0x15;
            sc_WriteMem = 0x37;
            sc_ProtectMem = 0x4d;
            init_OSver = 1;
        }
        else if (OSver == WINDOWS_7)
        {
            sc_CreateThreadEx = 0xa5;
            //sc_CreateThread = 0x4b;
            sc_AllocMem = 0x15;
            sc_WriteMem = 0x37;
            sc_ProtectMem = 0x4d;
            init_OSver = 1;
        }
        else if (OSver == WINDOWS_VISTA_SP2)
        {
            sc_CreateThreadEx = 0xa5;
            //sc_CreateThread = 0x4b;
            sc_AllocMem = 0x15;
            sc_WriteMem = 0x37;
            sc_ProtectMem = 0x4d;
            init_OSver = 1;
        }
        else if (OSver == WINDOWS_VISTA_SP1)
        {
            sc_CreateThreadEx = 0xa5;
            //sc_CreateThread = 0x4b;
            sc_AllocMem = 0x15;
            sc_WriteMem = 0x37;
            sc_ProtectMem = 0x4d;
            init_OSver = 1;
        }
        else if (OSver == WINDOWS_VISTA)
        {
            sc_CreateThreadEx = 0xa7;
            //sc_CreateThread = 0x4b;
            sc_AllocMem = 0x15;
            sc_WriteMem = 0x37;
            sc_ProtectMem = 0x4d;
            init_OSver = 1;
        }
        if (init_OSver)
        {
            scNum_CreateThreadEx = sc_CreateThreadEx;
            scNum_AllocMem = sc_AllocMem;
            scNum_WriteMem = sc_WriteMem;
            scNum_ProtectMem = sc_ProtectMem;
            //ZwCreateThreadEx = (_ZwCreateThreadEx_Win64)&ZwCreateThreadEx_internel;
            _ZwAllocateVirtualMemory_Win64 allocEr = (_ZwAllocateVirtualMemory_Win64)&ZwAllocateVirtualMemory_internel;
            //ZwWriteVirtualMemory = (_ZwWriteVirtualMemory_Win64)&ZwWriteVirtualMemory_internel;
            //NtProtectVirtualMemory = (_NtProtectVirtualMemory_Win64)&NtProtectVirtualMemory_internel;
            RtlNtStatusToDosError = (_RtlNtStatusToDosError_Win64)GetProcAddress(ntdll, "RtlNtStatusToDosError");
            if (!RtlNtStatusToDosError)
            {
                return GetLastError();
            }
            asm_initpsc(&sc_number);
            size_t i = 0x1000;
            void* buff = 0;
            allocEr((HANDLE)-1, &buff, 0, &i, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (buff)
            {
                init_syscall_buff(buff);
                DWORD oldp;
                return NtProtectVirtualMemory((HANDLE)-1, &buff, &i, PAGE_EXECUTE_READ, &oldp);
            }
            return ERROR_SUCCESS;
        }
    }
    else
#endif
    {
        {
            char str_zct[24] = { 0 };
            writebyte(str_zct, 'N');
            writebyte(str_zct, 't');
            writebyte(str_zct, 'C');
            writebyte(str_zct, 'r');
            writebyte(str_zct, 'e');
            writebyte(str_zct, 'a');
            writebyte(str_zct, 't');
            writebyte(str_zct, 'e');
            writebyte(str_zct, 'T');
            writebyte(str_zct, 'h');
            writebyte(str_zct, 'r');
            writebyte(str_zct, 'e');
            writebyte(str_zct, 'a');
            writebyte(str_zct, 'd');
            writebyte(str_zct, 'E');
            writebyte(str_zct, 'x');
            ZwCreateThreadEx = (_ZwCreateThreadEx_Win64)GetProcAddress(ntdll, str_zct);
        }
        if (!ZwCreateThreadEx)
        {
            return GetLastError();
        }
        {
            char str_alloc[32] = { 0 };
            writebyte(str_alloc, 'N');
            writebyte(str_alloc, 't');
            writebyte(str_alloc, 'A');
            writebyte(str_alloc, 'l');
            writebyte(str_alloc, 'l');
            writebyte(str_alloc, 'o');
            writebyte(str_alloc, 'c');
            writebyte(str_alloc, 'a');
            writebyte(str_alloc, 't');
            writebyte(str_alloc, 'e');
            writebyte(str_alloc, 'V');
            writebyte(str_alloc, 'i');
            writebyte(str_alloc, 'r');
            writebyte(str_alloc, 't');
            writebyte(str_alloc, 'u');
            writebyte(str_alloc, 'a');
            writebyte(str_alloc, 'l');
            writebyte(str_alloc, 'M');
            writebyte(str_alloc, 'e');
            writebyte(str_alloc, 'm');
            writebyte(str_alloc, 'o');
            writebyte(str_alloc, 'r');
            writebyte(str_alloc, 'y');
            ZwAllocateVirtualMemory = (_ZwAllocateVirtualMemory_Win64)GetProcAddress(ntdll, str_alloc);
        }
        if (!ZwAllocateVirtualMemory)
        {
            return GetLastError();
        }
        {
            char str_wrtMem[32] = { 0 };
            writebyte(str_wrtMem, 'N');
            writebyte(str_wrtMem, 't');
            writebyte(str_wrtMem, 'W');
            writebyte(str_wrtMem, 'r');
            writebyte(str_wrtMem, 'i');
            writebyte(str_wrtMem, 't');
            writebyte(str_wrtMem, 'e');
            writebyte(str_wrtMem, 'V');
            writebyte(str_wrtMem, 'i');
            writebyte(str_wrtMem, 'r');
            writebyte(str_wrtMem, 't');
            writebyte(str_wrtMem, 'u');
            writebyte(str_wrtMem, 'a');
            writebyte(str_wrtMem, 'l');
            writebyte(str_wrtMem, 'M');
            writebyte(str_wrtMem, 'e');
            writebyte(str_wrtMem, 'm');
            writebyte(str_wrtMem, 'o');
            writebyte(str_wrtMem, 'r');
            writebyte(str_wrtMem, 'y');
            ZwWriteVirtualMemory = (_ZwWriteVirtualMemory_Win64)GetProcAddress(ntdll, str_wrtMem);
        }
        if (!ZwWriteVirtualMemory)
        {
            return GetLastError();
        }
        {
            char str_protectMem[32] = { 0 };
            writebyte(str_protectMem, 'N');
            writebyte(str_protectMem, 't');
            writebyte(str_protectMem, 'P');
            writebyte(str_protectMem, 'r');
            writebyte(str_protectMem, 'o');
            writebyte(str_protectMem, 't');
            writebyte(str_protectMem, 'e');
            writebyte(str_protectMem, 'c');
            writebyte(str_protectMem, 't');
            writebyte(str_protectMem, 'V');
            writebyte(str_protectMem, 'i');
            writebyte(str_protectMem, 'r');
            writebyte(str_protectMem, 't');
            writebyte(str_protectMem, 'u');
            writebyte(str_protectMem, 'a');
            writebyte(str_protectMem, 'l');
            writebyte(str_protectMem, 'M');
            writebyte(str_protectMem, 'e');
            writebyte(str_protectMem, 'm');
            writebyte(str_protectMem, 'o');
            writebyte(str_protectMem, 'r');
            writebyte(str_protectMem, 'y');
            NtProtectVirtualMemory = (_NtProtectVirtualMemory_Win64)GetProcAddress(ntdll, str_protectMem);
        }
        if (!NtProtectVirtualMemory)
        {
            return GetLastError();
        }
    }
    RtlNtStatusToDosError = (_RtlNtStatusToDosError_Win64)GetProcAddress(ntdll, "RtlNtStatusToDosError");
    if (!RtlNtStatusToDosError)
    {
        return GetLastError();
    }
    return ERROR_SUCCESS;
}



#endif