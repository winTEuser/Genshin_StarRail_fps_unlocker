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

const BYTE buffer_call[0x400] = { 0 };


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
    HANDLE  ProcessHandle, 
    PVOID   BaseAddress, 
    MEMORY_INFORMATION_CLASS MemoryInformationClass, 
    PVOID   MemoryInformation, 
    SIZE_T  MemoryInformationLength, 
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

typedef NTSTATUS(NTAPI* _NtOpenProcess_Win64)(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId
    );

typedef BOOL(WINAPI* CreateProcessW_pWin64)(
    _In_opt_ LPCWSTR lpApplicationName,
    _Inout_opt_ LPWSTR lpCommandLine,
    _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
    _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
    _In_ BOOL bInheritHandles,
    _In_ DWORD dwCreationFlags,
    _In_opt_ LPVOID lpEnvironment,
    _In_opt_ LPCWSTR lpCurrentDirectory,
    _In_ LPSTARTUPINFOW lpStartupInfo,
    _Out_ LPPROCESS_INFORMATION lpProcessInformation
);

typedef DWORD(WINAPI* _RtlNtStatusToDosError_Win64)(DWORD Status);



enum 
{
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


typedef struct _LIST_MOD {
    struct MODULE_TABLE_ENTRY* Flink;
    struct MODULE_TABLE_ENTRY* Blink;
} _LIST_MOD, * P_LIST_MOD;

typedef struct MODULE_TABLE_ENTRY 
{
    MODULE_TABLE_ENTRY* Next;
    MODULE_TABLE_ENTRY* Last;
    PVOID Reserved[2];
    HMODULE ModBase;
    PVOID EntryPoint;
    PVOID Reserved3;
    UNICODE_STRING FullDllName;
    BYTE Reserved4[8];
    PVOID Reserved5[3];
    union 
    {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG TimeDateStamp;
} MODULE_TABLE_ENTRY, * PMODULE_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA64
{
    ULONG Length;                                      //0x0
    UCHAR Initialized;                                 //0x4
    PVOID SsHandle;                                    //0x8
    _LIST_ENTRY InLoadOrderModuleList;                 //0x10
    _LIST_MOD InMemoryOrderModuleList;                 //0x20
    _LIST_ENTRY InInitializationOrderModuleList;       //0x30
    PVOID EntryInProgress;                             //0x40
    UCHAR ShutdownInProgress;                          //0x48
    PVOID ShutdownThreadId;                            //0x50
}PEB_LDR_DATA64, * PPEB_LDR_DATA64;

typedef struct PEB64
{
    UCHAR InheritedAddressSpace;                       //0x0
    UCHAR ReadImageFileExecOptions;                    //0x1
    UCHAR BeingDebugged;                               //0x2
    union
    {
        UCHAR BitField;                                //0x3
        struct
        {
            UCHAR ImageUsesLargePages : 1;             //0x3
            UCHAR IsProtectedProcess : 1;              //0x3
            UCHAR IsImageDynamicallyRelocated : 1;     //0x3
            UCHAR SkipPatchingUser32Forwarders : 1;    //0x3
            UCHAR IsPackagedProcess : 1;               //0x3
            UCHAR IsAppContainer : 1;                  //0x3
            UCHAR IsProtectedProcessLight : 1;         //0x3
            UCHAR IsLongPathAwareProcess : 1;          //0x3
        };
    };
    UCHAR Padding0[4];                                 //0x4
    ULONGLONG Mutant;                                  //0x8
    ULONGLONG ImageBaseAddress;                        //0x10
    PEB_LDR_DATA64* Ldr;                               //0x18
    ULONGLONG ProcessParameters;                       //0x20
    ULONGLONG SubSystemData;                           //0x28
    ULONGLONG ProcessHeap;                             //0x30
    ULONGLONG FastPebLock;                             //0x38
    ULONGLONG AtlThunkSListPtr;                        //0x40
    ULONGLONG IFEOKey;                                 //0x48
    BYTE Resevered[0xC8];
    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    WORD OSBuildNumber;
    BYTE Resevered1[14];
}PEB64, * PPEB64;


_ZwCreateThreadEx_Win64 ZwCreateThreadEx = 0;
//_NtCreateThread_Win64 NtCreateThread = 0;
_ZwAllocateVirtualMemory_Win64 ZwAllocateVirtualMemory = 0;
_ZwWriteVirtualMemory_Win64 ZwWriteVirtualMemory = 0;
_NtProtectVirtualMemory_Win64 NtProtectVirtualMemory = 0;
_NtQueryVirtualMemory_Win64 NtQueryVirtualMemory = 0;
_NtOpenProcess_Win64 NtOpenProcess = 0;

_RtlNtStatusToDosError_Win64 RtlNtStatusToDosError = 0;
CreateProcessW_pWin64 CreateProcessW_internal = 0;
DWORD64 p_OpenProcess = 0;

static void writebyte(void* dst, BYTE num)
{
    size_t i = 0;
    while (*((BYTE*)dst + i) != 0)
    {
        i++;
    }
    *((BYTE*)dst + i) = ~num;
}

//copy from vmp
__declspec(noinline) const wchar_t* FindFileVersion(const BYTE* ptr, size_t data_size) {
    const wchar_t* data = reinterpret_cast<const wchar_t*>(ptr);
    data_size /= sizeof(wchar_t);

    for (size_t i = 0; i < data_size; i++) 
    {
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

//ntdll filever
WORD ParseOSBuildBumber()
{
    PEB64* peb = reinterpret_cast<PEB64*>(__readgsqword(0x60));
    PMODULE_TABLE_ENTRY list = peb->Ldr->InMemoryOrderModuleList.Flink->Next;//跳过第一个用户程序模块
    HMODULE ntdll = list->ModBase;
    if (!ntdll)
    {
        char str_ntdll[16] = { 0 };
        writebyte(str_ntdll, (~'n'));
        writebyte(str_ntdll, (~'t'));
        writebyte(str_ntdll, (~'d'));
        writebyte(str_ntdll, (~'l'));
        writebyte(str_ntdll, (~'l'));
        writebyte(str_ntdll, (~'.'));
        writebyte(str_ntdll, (~'d'));
        writebyte(str_ntdll, (~'l'));
        writebyte(str_ntdll, (~'l'));
        ntdll = LoadLibraryA(str_ntdll);
    }
    if (!ntdll)
        return 0;
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
                    resource_start = reinterpret_cast<const BYTE*>(file_version);
                }
            }
        }
    }
    return os_build_number;
}

int vm_strcmp(const char* str1, const char* str2)
{
    unsigned char c1;
    unsigned char c2;
    size_t pos = 0;
    do {
        c1 = *(str1++);
        c2 = *(str2++);
        /*
        if (is_enc) {
            c1 ^= (_rotl32(FACE_STRING_DECRYPT_KEY, static_cast<int>(pos)) + pos);
            pos++;
        }*/
        if (!c1)
            break;
    } while (c1 == c2);

    if (c1 < c2)
        return -1;
    else if (c1 > c2)
        return 1;
    return 0;
}

void* GetProcAddress_Internal(HMODULE module, const char* proc_name)
{
    // check input
    if (!module || !proc_name)
        return NULL;

    // check module's header
    IMAGE_DOS_HEADER* dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(module);
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    // check NT header
    IMAGE_NT_HEADERS* pe_header = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<uint8_t*>(module) + dos_header->e_lfanew);
    if (pe_header->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    // get the export directory
    uint32_t export_adress = pe_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!export_adress)
        return NULL;

    uint32_t export_size = pe_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    uint32_t address;
    uint32_t ordinal_index = -1;
    IMAGE_EXPORT_DIRECTORY* export_directory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(reinterpret_cast<uint8_t*>(module) + export_adress);

    if (proc_name <= reinterpret_cast<const char*>(0xFFFF)) 
    {
        // ordinal
        ordinal_index = static_cast<uint32_t>(INT_PTR(proc_name)) - export_directory->Base;
        // index is either less than base or bigger than number of functions
        if (ordinal_index >= export_directory->NumberOfFunctions)
            return NULL;
        // get the function offset by the ordinal
        address = (reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(module) + export_directory->AddressOfFunctions))[ordinal_index];
        // check for empty offset
        if (!address)
            return NULL;
    }
    else 
    {
        // name of function
        if (export_directory->NumberOfNames) 
        {
            // start binary search
            int left_index = 0;
            int right_index = export_directory->NumberOfNames - 1;
            uint32_t* names = reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(module) + export_directory->AddressOfNames);
            while (left_index <= right_index) 
            {
                uint32_t cur_index = (left_index + right_index) >> 1;
                switch (vm_strcmp(proc_name, (const char*)(reinterpret_cast<uint8_t*>(module) + names[cur_index]))) 
                {
                case 0:
                    ordinal_index = (reinterpret_cast<WORD*>(reinterpret_cast<uint8_t*>(module) + export_directory->AddressOfNameOrdinals))[cur_index];
                    left_index = right_index + 1;
                    break;
                case -1:
                    right_index = cur_index - 1;
                    break;
                case 1:
                    left_index = cur_index + 1;
                    break;
                }
            }
        }
        // if nothing has been found
        if (ordinal_index >= export_directory->NumberOfFunctions)
            return NULL;
        // get the function offset by the ordinal
        address = (reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(module) + export_directory->AddressOfFunctions))[ordinal_index];
        if (!address)
            return NULL;
    }

    // if it is just a pointer - return it
    if (address < export_adress || address >= export_adress + export_size)
        return reinterpret_cast<FARPROC>(reinterpret_cast<uint8_t*>(module) + address);

    return 0;
}


static void BaseSetLastNTError_inter(DWORD Status)
{
    return SetLastError(RtlNtStatusToDosError(Status));
}

static BOOLEAN WINAPI VirtualProtect_Internal(HANDLE procHandle, LPVOID baseAddr, size_t size, DWORD protect, DWORD* oldp)
{
    if(!NtProtectVirtualMemory)
    {
        BaseSetLastNTError_inter(STATUS_ACCESS_VIOLATION);
        return 0;
    }
    DWORD oldpt = 0;
    if (!oldp)
    {
        oldp = &oldpt;
    }
    DWORD64 addr = (DWORD64)baseAddr;
    addr &= 0xFFFFFFFFFFFFF000;
    NTSTATUS ret = NtProtectVirtualMemory(procHandle, (void**)(&addr), &size, protect, oldp);
    if (ret)
    {
        BaseSetLastNTError_inter(ret);
        return 0;
    }
    return 1;
}


static PVOID WINAPI VirtualAllocEx_Internal(HANDLE procHandle, PVOID* dst_baseaddr, size_t size, DWORD protect)
{
    if (!ZwAllocateVirtualMemory)
    {
        BaseSetLastNTError_inter(STATUS_ACCESS_VIOLATION);
        return 0;
    }
    void* baseaddr = dst_baseaddr;
    NTSTATUS ret = ZwAllocateVirtualMemory(procHandle, &baseaddr, 0, &size, MEM_COMMIT | MEM_RESERVE, protect);
    if (ret)
    {
        BaseSetLastNTError_inter(ret);
        return 0;
    }
    return baseaddr;
}

static PVOID WINAPI VirtualAlloc_Internal(PVOID* dst_baseaddr, size_t size, DWORD protect)
{
    if (!ZwAllocateVirtualMemory)
    {
        BaseSetLastNTError_inter(STATUS_ACCESS_VIOLATION);
        return 0;
    }
    void* baseaddr = dst_baseaddr;
    NTSTATUS ret = ZwAllocateVirtualMemory((HANDLE)-1, &baseaddr, 0, &size, MEM_COMMIT | MEM_RESERVE, protect);
    if (ret)
    {
        BaseSetLastNTError_inter(ret);
        return 0;
    }
    return baseaddr;
}


static BOOLEAN WINAPI WriteProcessMemoryInternal(HANDLE procHandle, LPVOID dst_baseaddr, LPVOID src_buffer, size_t size, size_t* writenum)
{
    if (!ZwWriteVirtualMemory)
    {
        BaseSetLastNTError_inter(STATUS_ACCESS_VIOLATION);
        return 0;
    }
    size_t tsize = 0;
    DWORD oldp = 0;
    NTSTATUS ret = STATUS_ACCESS_VIOLATION;
    MEMORY_BASIC_INFORMATION temp = { 0 };
    ret = NtQueryVirtualMemory(procHandle, dst_baseaddr, MemoryBasicInformation, &temp, sizeof(temp), &tsize);
    if (ret)
        goto __failed;
    if (temp.Protect & 0xCC)
    {
        ret = ZwWriteVirtualMemory(procHandle, dst_baseaddr, src_buffer, size, &tsize);
        if (ret)
            goto __failed;

        if (writenum)
            *writenum = tsize;
        return 1;
    }
    else if (VirtualProtect_Internal(procHandle, dst_baseaddr, size, 0x60000040, &oldp))
    {
        ret = ZwWriteVirtualMemory(procHandle, dst_baseaddr, src_buffer, size, &tsize);
        if (ret)
            goto __failed;
        
        if (writenum)
            *writenum = tsize;
        return VirtualProtect_Internal(procHandle, dst_baseaddr, size, oldp, 0);
    }
__failed:
    BaseSetLastNTError_inter(ret);
    return 0;
}


static HANDLE WINAPI CreateThread_Internal(HANDLE procHandle, LPSECURITY_ATTRIBUTES lpThreadAttributes, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter)
{
    if (!ZwCreateThreadEx)
    {
        BaseSetLastNTError_inter(STATUS_ACCESS_VIOLATION);
        return 0;
    }
    HANDLE retHandle = 0;
    NTSTATUS status = ZwCreateThreadEx(&retHandle, 0x1FFFF, 0, procHandle, lpStartAddress, lpParameter, 0, 0, 0xC000, 0x30000, 0);
    if (status)
    {
        BaseSetLastNTError_inter(status);
        return 0;
    }
    return retHandle;
}


static HANDLE WINAPI OpenProcess_Internal(DWORD dwDesiredAccess, DWORD dwProcessId)
{
    if (!NtOpenProcess)
    {
        BaseSetLastNTError_inter(STATUS_ACCESS_VIOLATION);
        return 0;
    }
    HANDLE opHandle = 0;
    OBJECT_ATTRIBUTES tempOb = { 0 };
    CLIENT_ID tempID = { 0 };
    tempOb.Length = 0x30;
    tempOb.Attributes = 0x2;
    tempID.UniqueProc = (HANDLE)dwProcessId;
    NTSTATUS ret = NtOpenProcess(&opHandle, dwDesiredAccess, &tempOb, &tempID);
    if (ret)
    {
        BaseSetLastNTError_inter(ret);
        return 0;
    }
    return opHandle;
}


static __forceinline void init_syscall_buff(void* buff, DWORD sc_CTEx, DWORD sc_alloc, DWORD sc_ptm, DWORD sc_writemem, DWORD sc_querymem, DWORD sc_openproc)
{
    DWORD64 va = __rdtsc();
    va &= 0x00000000000001F0;
    BYTE* startaddr = (BYTE*)buff + va;
    DWORD64 fir = 0xFFFFFFFFB8CA8949;
    DWORD64 sec = 0xFBEB050FC3401F0F;
    for(int i = 0; i != 0x6; i++)
    {
        *(DWORD64*)(startaddr + (i * 0x20)) = fir;
        *(DWORD64*)(startaddr + (i * 0x20) + 0x8) = sec;
    }
    *(DWORD*)(startaddr + 0x4) = sc_CTEx;
    ZwCreateThreadEx = (_ZwCreateThreadEx_Win64)startaddr;
    startaddr += 0x20;
    *(DWORD*)(startaddr + 0x4) = sc_alloc;
    ZwAllocateVirtualMemory = (_ZwAllocateVirtualMemory_Win64)startaddr;
    startaddr += 0x20;
    *(DWORD*)(startaddr + 0x4) = sc_ptm;
    NtProtectVirtualMemory = (_NtProtectVirtualMemory_Win64)startaddr;
    startaddr += 0x20;
    *(DWORD*)(startaddr + 0x4) = sc_writemem;
    ZwWriteVirtualMemory = (_ZwWriteVirtualMemory_Win64)startaddr;
    startaddr += 0x20;
    *(DWORD*)(startaddr + 0x4) = sc_querymem;
    NtQueryVirtualMemory = (_NtQueryVirtualMemory_Win64)startaddr;
    startaddr += 0x20;
    *(DWORD*)(startaddr + 0x4) = sc_openproc;
    NtOpenProcess = (_NtOpenProcess_Win64)startaddr;
}

static NTSTATUS init_NTAPI()
{
    PEB64* peb = reinterpret_cast<PEB64*>(__readgsqword(0x60));
    PMODULE_TABLE_ENTRY list = peb->Ldr->InMemoryOrderModuleList.Flink->Next;//跳过第一个用户程序模块
    HMODULE ntdll = list->ModBase;
    HMODULE kernel32 = list->Next->ModBase;
    if (!ntdll)
    {
        char str_ntdll[16] = { 0 };
        writebyte(str_ntdll, (~'n'));
        writebyte(str_ntdll, (~'t'));
        writebyte(str_ntdll, (~'d'));
        writebyte(str_ntdll, (~'l'));
        writebyte(str_ntdll, (~'l'));
        writebyte(str_ntdll, (~'.'));
        writebyte(str_ntdll, (~'d'));
        writebyte(str_ntdll, (~'l'));
        writebyte(str_ntdll, (~'l'));
        ntdll = LoadLibraryA(str_ntdll);
    }
    if (!ntdll)
        return STATUS_DLL_NOT_FOUND;
    if(!kernel32)
    {
        char str_kerneldll[16] = { 0 };
        writebyte(str_kerneldll, (~'k'));
        writebyte(str_kerneldll, (~'e'));
        writebyte(str_kerneldll, (~'r'));
        writebyte(str_kerneldll, (~'n'));
        writebyte(str_kerneldll, (~'e'));
        writebyte(str_kerneldll, (~'l'));
        writebyte(str_kerneldll, (~'b'));
        writebyte(str_kerneldll, (~'a'));
        writebyte(str_kerneldll, (~'s'));
        writebyte(str_kerneldll, (~'e'));
        writebyte(str_kerneldll, (~'.'));
        writebyte(str_kerneldll, (~'d'));
        writebyte(str_kerneldll, (~'l'));
        writebyte(str_kerneldll, (~'l'));
        kernel32 = LoadLibraryA(str_kerneldll);
    }
    if (!kernel32)
        return STATUS_DLL_NOT_FOUND;


#ifdef DirectCall
    //uint16_t OSver = ParseOSBuildBumber(ntdll);以peb版本为准
    WORD OSver = peb->OSBuildNumber;
    bool init_OSver = 0;
    if (OSver)
    {
        DWORD sc_CreateThreadEx = 0;
        DWORD sc_AllocMem = 0;
        DWORD sc_WriteMem = 0;
        DWORD sc_ProtectMem = 0;
        DWORD sc_VirtualQuery = 0;
        DWORD sc_OpenProc = 0;
        if (OSver == WINDOWS_11_24H2)
        {
            sc_CreateThreadEx = 0xc9;
            sc_AllocMem = 0x18;
            sc_WriteMem = 0x3a;
            sc_ProtectMem = 0x50;
            sc_VirtualQuery = 0x23;
            sc_OpenProc = 0x26;
            init_OSver = 1;
        }
        else if (OSver == WINDOWS_11_22H2 || OSver == WINDOWS_11_23H2)
        {
            sc_CreateThreadEx = 0xc7;
            sc_AllocMem = 0x18;
            sc_WriteMem = 0x3a;
            sc_ProtectMem = 0x50;
            sc_VirtualQuery = 0x23;
            sc_OpenProc = 0x26;
            init_OSver = 1;
        }
        else if (OSver == WINDOWS_11_21H2)
        {
            sc_CreateThreadEx = 0xc6;
            sc_AllocMem = 0x18;
            sc_WriteMem = 0x3a;
            sc_ProtectMem = 0x50;
            sc_VirtualQuery = 0x23;
            sc_OpenProc = 0x26;
            init_OSver = 1;
        }
        else if (OSver == WINDOWS_10_22H2 || OSver == WINDOWS_10_21H2)
        {
            sc_CreateThreadEx = 0xc2;
            sc_AllocMem = 0x18;
            sc_WriteMem = 0x3a;
            sc_ProtectMem = 0x50;
            sc_VirtualQuery = 0x23;
            sc_OpenProc = 0x26;
            init_OSver = 1;
        }
        else if (OSver == WINDOWS_10_20H2 || OSver == WINDOWS_10_20H1 || OSver == WINDOWS_10_21H1)
        {
            sc_CreateThreadEx = 0xc1;
            sc_AllocMem = 0x18;
            sc_WriteMem = 0x3a;
            sc_ProtectMem = 0x50;
            sc_VirtualQuery = 0x23;
            sc_OpenProc = 0x26;
            init_OSver = 1;
        }
        else if (OSver == WINDOWS_10_19H2 || OSver == WINDOWS_10_19H1)
        {
            sc_CreateThreadEx = 0xbd;
            sc_AllocMem = 0x18;
            sc_WriteMem = 0x3a;
            sc_ProtectMem = 0x50;
            sc_VirtualQuery = 0x23;
            sc_OpenProc = 0x26;
            init_OSver = 1;
        }
        else if (OSver == WINDOWS_10_RS5)
        {
            sc_CreateThreadEx = 0xbc;
            sc_AllocMem = 0x18;
            sc_WriteMem = 0x3a;
            sc_ProtectMem = 0x50;
            sc_VirtualQuery = 0x23;
            sc_OpenProc = 0x26;
            init_OSver = 1;
        }
        else if (OSver == WINDOWS_10_RS4)
        {
            sc_CreateThreadEx = 0xbb;
            sc_AllocMem = 0x18;
            sc_WriteMem = 0x3a;
            sc_ProtectMem = 0x50;
            sc_VirtualQuery = 0x23;
            sc_OpenProc = 0x26;
            init_OSver = 1;
        }
        else if (OSver == WINDOWS_10_RS3)
        {
            sc_CreateThreadEx = 0xba;
            sc_AllocMem = 0x18;
            sc_WriteMem = 0x3a;
            sc_ProtectMem = 0x50;
            sc_VirtualQuery = 0x23;
            sc_OpenProc = 0x26;
            init_OSver = 1;
        }
        else if (OSver == WINDOWS_10_RS2)
        {
            sc_CreateThreadEx = 0xb9;
            sc_AllocMem = 0x18;
            sc_WriteMem = 0x3a;
            sc_ProtectMem = 0x50;
            sc_VirtualQuery = 0x23;
            sc_OpenProc = 0x26;
            init_OSver = 1;
        }
        else if (OSver == WINDOWS_10_RS1)
        {
            sc_CreateThreadEx = 0xb6;
            sc_AllocMem = 0x18;
            sc_WriteMem = 0x3a;
            sc_ProtectMem = 0x50;
            sc_VirtualQuery = 0x23;
            sc_OpenProc = 0x26;
            init_OSver = 1;
        }
        else if (OSver == WINDOWS_10_TH2)
        {
            sc_CreateThreadEx = 0xb4;
            sc_AllocMem = 0x18;
            sc_WriteMem = 0x3a;
            sc_ProtectMem = 0x50;
            sc_VirtualQuery = 0x23;
            sc_OpenProc = 0x26;
            init_OSver = 1;
        }
        else if (OSver == WINDOWS_10_TH1)
        {
            sc_CreateThreadEx = 0xb3;
            sc_AllocMem = 0x18;
            sc_WriteMem = 0x3a;
            sc_ProtectMem = 0x50;
            sc_VirtualQuery = 0x23;
            sc_OpenProc = 0x26;
            init_OSver = 1;
        }
        else if (OSver == WINDOWS_8_1)
        {
            sc_CreateThreadEx = 0xb0;
            sc_AllocMem = 0x17;
            sc_WriteMem = 0x39;
            sc_ProtectMem = 0x4f;
            sc_VirtualQuery = 0x22;
            sc_OpenProc = 0x25;
            init_OSver = 1;
        }
        else if (OSver == WINDOWS_8)
        {
            sc_CreateThreadEx = 0xaf;
            sc_AllocMem = 0x16;
            sc_WriteMem = 0x38;
            sc_ProtectMem = 0x4e;
            sc_VirtualQuery = 0x21;
            sc_OpenProc = 0x24;
            init_OSver = 1;
        }
        else if (OSver == WINDOWS_7_SP1 || OSver == WINDOWS_7)
        {
            sc_CreateThreadEx = 0xa5;
            sc_AllocMem = 0x15;
            sc_WriteMem = 0x37;
            sc_ProtectMem = 0x4d;
            sc_VirtualQuery = 0x20;
            sc_OpenProc = 0x23;
            init_OSver = 1;
        }
        else if (OSver == WINDOWS_VISTA_SP2)
        {
            sc_CreateThreadEx = 0xa5;
            sc_AllocMem = 0x15;
            sc_WriteMem = 0x37;
            sc_ProtectMem = 0x4d;
            sc_VirtualQuery = 0x20;
            sc_OpenProc = 0x23;
            init_OSver = 1;
        }
        else if (OSver == WINDOWS_VISTA_SP1)
        {
            sc_CreateThreadEx = 0xa5;
            sc_AllocMem = 0x15;
            sc_WriteMem = 0x37;
            sc_ProtectMem = 0x4d;
            sc_VirtualQuery = 0x20;
            sc_OpenProc = 0x23;
            init_OSver = 1;
        }
        else if (OSver == WINDOWS_VISTA)
        {
            sc_CreateThreadEx = 0xa7;
            sc_AllocMem = 0x15;
            sc_WriteMem = 0x37;
            sc_ProtectMem = 0x4d;
            sc_VirtualQuery = 0x20;
            sc_OpenProc = 0x23;
            init_OSver = 1;
        }
        if (init_OSver)
        {
            
            asm_initpsc(&sc_ProtectMem);

            size_t i = 0x1000;
            DWORD old = 0;
            uintptr_t addr = (uintptr_t)(&buffer_call);
            addr &= 0xFFFFFFFFFFFFF000;
            NTSTATUS ret = ((_NtProtectVirtualMemory_Win64)&asm_syscall)((HANDLE)-1, (void**)(&addr), &i, PAGE_EXECUTE_READWRITE, &old);
            if (!ret)
            {
                init_syscall_buff((void*)(&buffer_call), sc_CreateThreadEx, sc_AllocMem, sc_ProtectMem, sc_WriteMem, sc_VirtualQuery, sc_OpenProc);
                ret = ((_NtProtectVirtualMemory_Win64)&asm_syscall)((HANDLE)-1, (void**)(&addr), &i, PAGE_EXECUTE_READ, &old);
                
            }
            if (ret)
            {
                return ret;
            }
            asm_initpsc(0);
            
            goto __other_init;
        }
    }
#endif
    if(1)
    {
        char str_zct[24] = { 0 };
        writebyte(str_zct, (~'N'));
        writebyte(str_zct, (~'t'));
        writebyte(str_zct, (~'C'));
        writebyte(str_zct, (~'r'));
        writebyte(str_zct, (~'e'));
        writebyte(str_zct, (~'a'));
        writebyte(str_zct, (~'t'));
        writebyte(str_zct, (~'e'));
        writebyte(str_zct, (~'T'));
        writebyte(str_zct, (~'h'));
        writebyte(str_zct, (~'r'));
        writebyte(str_zct, (~'e'));
        writebyte(str_zct, (~'a'));
        writebyte(str_zct, (~'d'));
        writebyte(str_zct, (~'E'));
        writebyte(str_zct, (~'x'));
        ZwCreateThreadEx = (_ZwCreateThreadEx_Win64)GetProcAddress_Internal(ntdll, str_zct);
    }
    if (!ZwCreateThreadEx)
    {
        return 0xC1;
    }
    {
        char str_alloc[32] = { 0 };
        writebyte(str_alloc, (~'N'));
        writebyte(str_alloc, (~'t'));
        writebyte(str_alloc, (~'A'));
        writebyte(str_alloc, (~'l'));
        writebyte(str_alloc, (~'l'));
        writebyte(str_alloc, (~'o'));
        writebyte(str_alloc, (~'c'));
        writebyte(str_alloc, (~'a'));
        writebyte(str_alloc, (~'t'));
        writebyte(str_alloc, (~'e'));
        writebyte(str_alloc, (~'V'));
        writebyte(str_alloc, (~'i'));
        writebyte(str_alloc, (~'r'));
        writebyte(str_alloc, (~'t'));
        writebyte(str_alloc, (~'u'));
        writebyte(str_alloc, (~'a'));
        writebyte(str_alloc, (~'l'));
        writebyte(str_alloc, (~'M'));
        writebyte(str_alloc, (~'e'));
        writebyte(str_alloc, (~'m'));
        writebyte(str_alloc, (~'o'));
        writebyte(str_alloc, (~'r'));
        writebyte(str_alloc, (~'y'));
        ZwAllocateVirtualMemory = (_ZwAllocateVirtualMemory_Win64)GetProcAddress_Internal(ntdll, str_alloc);
    }
    if (!ZwAllocateVirtualMemory)
    {
        return 0xC2;
    }
    {
        char str_wrtMem[32] = { 0 };
        writebyte(str_wrtMem, (~'N'));
        writebyte(str_wrtMem, (~'t'));
        writebyte(str_wrtMem, (~'W'));
        writebyte(str_wrtMem, (~'r'));
        writebyte(str_wrtMem, (~'i'));
        writebyte(str_wrtMem, (~'t'));
        writebyte(str_wrtMem, (~'e'));
        writebyte(str_wrtMem, (~'V'));
        writebyte(str_wrtMem, (~'i'));
        writebyte(str_wrtMem, (~'r'));
        writebyte(str_wrtMem, (~'t'));
        writebyte(str_wrtMem, (~'u'));
        writebyte(str_wrtMem, (~'a'));
        writebyte(str_wrtMem, (~'l'));
        writebyte(str_wrtMem, (~'M'));
        writebyte(str_wrtMem, (~'e'));
        writebyte(str_wrtMem, (~'m'));
        writebyte(str_wrtMem, (~'o'));
        writebyte(str_wrtMem, (~'r'));
        writebyte(str_wrtMem, (~'y'));
        ZwWriteVirtualMemory = (_ZwWriteVirtualMemory_Win64)GetProcAddress_Internal(ntdll, str_wrtMem);
    }
    if (!ZwWriteVirtualMemory)
    {
        return 0xC3;
    }
    {
        char str_protectMem[32] = { 0 };
        writebyte(str_protectMem, (~'N'));
        writebyte(str_protectMem, (~'t'));
        writebyte(str_protectMem, (~'P'));
        writebyte(str_protectMem, (~'r'));
        writebyte(str_protectMem, (~'o'));
        writebyte(str_protectMem, (~'t'));
        writebyte(str_protectMem, (~'e'));
        writebyte(str_protectMem, (~'c'));
        writebyte(str_protectMem, (~'t'));
        writebyte(str_protectMem, (~'V'));
        writebyte(str_protectMem, (~'i'));
        writebyte(str_protectMem, (~'r'));
        writebyte(str_protectMem, (~'t'));
        writebyte(str_protectMem, (~'u'));
        writebyte(str_protectMem, (~'a'));
        writebyte(str_protectMem, (~'l'));
        writebyte(str_protectMem, (~'M'));
        writebyte(str_protectMem, (~'e'));
        writebyte(str_protectMem, (~'m'));
        writebyte(str_protectMem, (~'o'));
        writebyte(str_protectMem, (~'r'));
        writebyte(str_protectMem, (~'y'));
        NtProtectVirtualMemory = (_NtProtectVirtualMemory_Win64)GetProcAddress_Internal(ntdll, str_protectMem);
    }
    if (!NtProtectVirtualMemory)
    {
        return 0xC4;
    }
    {
        char str_QueryMem[32] = { 0 };
        writebyte(str_QueryMem, (~'N'));
        writebyte(str_QueryMem, (~'t'));
        writebyte(str_QueryMem, (~'Q'));
        writebyte(str_QueryMem, (~'u'));
        writebyte(str_QueryMem, (~'e'));
        writebyte(str_QueryMem, (~'r'));
        writebyte(str_QueryMem, (~'y'));
        writebyte(str_QueryMem, (~'V'));
        writebyte(str_QueryMem, (~'i'));
        writebyte(str_QueryMem, (~'r'));
        writebyte(str_QueryMem, (~'t'));
        writebyte(str_QueryMem, (~'u'));
        writebyte(str_QueryMem, (~'a'));
        writebyte(str_QueryMem, (~'l'));
        writebyte(str_QueryMem, (~'M'));
        writebyte(str_QueryMem, (~'e'));
        writebyte(str_QueryMem, (~'m'));
        writebyte(str_QueryMem, (~'o'));
        writebyte(str_QueryMem, (~'r'));
        writebyte(str_QueryMem, (~'y'));
        NtQueryVirtualMemory = (_NtQueryVirtualMemory_Win64)GetProcAddress_Internal(ntdll, str_QueryMem);
    }
    if (!NtQueryVirtualMemory)
    {
        return 0xC5;
    }
    {
        char str_openproc[16] = { 0 };
        writebyte(str_openproc, (~'N'));
        writebyte(str_openproc, (~'t'));
        writebyte(str_openproc, (~'O'));
        writebyte(str_openproc, (~'p'));
        writebyte(str_openproc, (~'e'));
        writebyte(str_openproc, (~'n'));
        writebyte(str_openproc, (~'P'));
        writebyte(str_openproc, (~'r'));
        writebyte(str_openproc, (~'o'));
        writebyte(str_openproc, (~'c'));
        writebyte(str_openproc, (~'e'));
        writebyte(str_openproc, (~'s'));
        writebyte(str_openproc, (~'s'));
        NtOpenProcess = (_NtOpenProcess_Win64)GetProcAddress_Internal(ntdll, str_openproc);
    }
    if (!NtOpenProcess)
    {
        return 0xC6;
    }

    
__other_init:
    RtlNtStatusToDosError = (_RtlNtStatusToDosError_Win64)GetProcAddress_Internal(ntdll, "RtlNtStatusToDosError");
    if (!RtlNtStatusToDosError)
    {
        return 0xF1;
    }
    {
        char str_createproc[16] = { 0 };
        writebyte(str_createproc, (~'C'));
        writebyte(str_createproc, (~'r'));
        writebyte(str_createproc, (~'e'));
        writebyte(str_createproc, (~'a'));
        writebyte(str_createproc, (~'t'));
        writebyte(str_createproc, (~'e'));
        writebyte(str_createproc, (~'P'));
        writebyte(str_createproc, (~'r'));
        writebyte(str_createproc, (~'o'));
        writebyte(str_createproc, (~'c'));
        writebyte(str_createproc, (~'e'));
        writebyte(str_createproc, (~'s'));
        writebyte(str_createproc, (~'s'));
        writebyte(str_createproc, (~'W'));
        CreateProcessW_internal = (CreateProcessW_pWin64)GetProcAddress_Internal(kernel32, str_createproc);
    }
    if (!CreateProcessW_internal)
    {
        return 0xF2;
    }
    {
        char str_openproc[16] = { 0 };
        writebyte(str_openproc, (~'O'));
        writebyte(str_openproc, (~'p'));
        writebyte(str_openproc, (~'e'));
        writebyte(str_openproc, (~'n'));
        writebyte(str_openproc, (~'P'));
        writebyte(str_openproc, (~'r'));
        writebyte(str_openproc, (~'o'));
        writebyte(str_openproc, (~'c'));
        writebyte(str_openproc, (~'e'));
        writebyte(str_openproc, (~'s'));
        writebyte(str_openproc, (~'s'));
        p_OpenProcess = (DWORD64)GetProcAddress_Internal(kernel32, str_openproc);
    }
    if (!p_OpenProcess)
    {
        return 0xF3;
    }

    return ERROR_SUCCESS;
}



#endif