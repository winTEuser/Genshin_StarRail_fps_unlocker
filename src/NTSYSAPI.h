#pragma once

#ifndef __NT_SYSAPI_H__
#define __NT_SYSAPI_H__

#include <Windows.h>
#include <immintrin.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:pTLS_CALLBACKs")

#ifndef _WIN64
#error this API define only work for Win64
#endif


#define CREATE_THREAD_INITFAILED        (0xC001)
#define VIRTUAL_ALLOC_INITFAILED        (0xC002)
#define VIRTUAL_FREE_INITFAILED         (0xC003)
#define READ_VIRTUAL_MEM_INITFAILED     (0xC004)
#define WRITE_VIRTUAL_MEM_INITFAILED    (0xC005)
#define VIRTUAL_PROTECT_INITFAILED      (0xC006)
#define VIRTUAL_QUERY_INITFAILED        (0xC007)
#define OPEN_PROCESS_INITFAILED         (0xC008)
#define CREATE_SECTION_INITFAILED       (0xC009)
#define MAP_SECTION_INITFAILED          (0xC00A)
#define UNMAP_SECTION_INITFAILED        (0xC00B)
#define QUERY_SYS_INFO_INITFAILED       (0xC00C)
#define TERMINATE_INITFAILED            (0xC00D)
#define SUSPEND_INITFAILED              (0xC00E)
#define RESUME_INITFAILED               (0xC00F)
#define CLOSE_HANDLE_INITFAILED         (0xC010)




NTSTATUS init_API(void);

void NTAPI TLS_CALLBACK(PVOID DllHandle, DWORD Reason, PVOID Reserved)
{
    if (Reason == DLL_PROCESS_ATTACH)
    {
        if (NTSTATUS r = init_API())
        {
            return ExitProcess(r);
        }
    }
}

#pragma const_seg(".CRT$XLB")
EXTERN_C const PIMAGE_TLS_CALLBACK pTLS_CALLBACKs[] = { TLS_CALLBACK, 0 };
#pragma const_seg()


EXTERN_C NTSTATUS NTAPI asm_syscall();

EXTERN_C NTSYSAPI DWORD NTAPI RtlSetLastWin32ErrorAndNtStatusFromNtStatus(NTSTATUS Status);

EXTERN_C NTSYSAPI DWORD NTAPI NtRaiseHardError(
    NTSTATUS    ErrorStatus,
    DWORD       NumberOfParameters,
    DWORD       UnicodeStringParameterMask,
    PULONG_PTR  Parameters,
    DWORD       ValidResponseOptions,
    PDWORD      Response
    );

static DWORD init_Status = -1;


#if(1)

typedef struct SYSCALLSTRUCT {
    DWORD64 calladdr;
    DWORD64 scnumber;
    DWORD64 rcx;
}SYSCALLSTRUCT, *PSYSCALLSTRUCT;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
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

typedef enum _MEMORY_INFORMATION_CLASS 
{
    MemoryBasicInformation
} MEMORY_INFORMATION_CLASS, * PMEMORY_INFORMATION_CLASS;

typedef enum HardErrorResponseButton {
    ResponseButtonOK,
    ResponseButtonOKCancel,
    ResponseButtonAbortRetryIgnore,
    ResponseButtonYesNoCancel,
    ResponseButtonYesNo,
    ResponseButtonRetryCancel,
    ResponseButtonCancelTryAgainContinue
} HardErrorResponseButton;

typedef enum HardErrorResponseIcon {
    IconAsterisk = 0x40,
    IconError = 0x10,
    IconExclamation = 0x30,
    IconHand = 0x10,
    IconInformation = 0x40,
    IconNone = 0,
    IconQuestion = 0x20,
    IconStop = 0x10,
    IconWarning = 0x30,
    IconUserIcon = 0x80
} HardErrorResponseIcon;

typedef enum HardErrorResponse {
    ResponseReturnToCaller,
    ResponseNotHandled,
    ResponseAbort, ResponseCancel,
    ResponseIgnore,
    ResponseNo,
    ResponseOk,
    ResponseRetry,
    ResponseYes
} HardErrorResponse;

#define STATUS_SERVICE_NOTIFICATION ((NTSTATUS)0x40000018L)
#define HARDERROR_OVERRIDE_ERRORMODE (0x10000000)

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation, 
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation,
    SystemLocksInformation,
    SystemStackTraceInformation,
    SystemPagedPoolInformation,
    SystemNonPagedPoolInformation,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPageFileInformation,
    SystemVdmInstemulInformation,
    SystemVdmBopInformation,
    SystemFileCacheInformation,
    SystemPoolTagInformation,
    SystemInterruptInformation,
    SystemDpcBehaviorInformation,
    SystemFullMemoryInformation,
    SystemLoadGdiDriverInformation,
    SystemUnloadGdiDriverInformation,
    SystemTimeAdjustmentInformation,
    SystemSummaryMemoryInformation,
    SystemMirrorMemoryInformation,
    SystemPerformanceTraceInformation,
    SystemObsolete0,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemExtendServiceTableInformation,
    SystemPrioritySeperation,
    SystemVerifierAddDriverInformation,
    SystemVerifierRemoveDriverInformation,
    SystemProcessorIdleInformation,
    SystemLegacyDriverInformation,
    SystemCurrentTimeZoneInformation,
    SystemLookasideInformation,
    SystemTimeSlipNotification,
    SystemSessionCreate,
    SystemSessionDetach,
    SystemSessionInformation,
    SystemRangeStartInformation,
    SystemVerifierInformation,
    SystemVerifierThunkExtend,
    SystemSessionProcessInformation,
    SystemLoadGdiDriverInSystemSpace,
    SystemNumaProcessorMap,
    SystemPrefetcherInformation,
    SystemExtendedProcessInformation,
    SystemRecommendedSharedDataAlignment,
    SystemComPlusPackage,
    SystemNumaAvailableMemory,
    SystemProcessorPowerInformation,
    SystemEmulationBasicInformation,
    SystemEmulationProcessorInformation,
    SystemExtendedHandleInformation,
    SystemLostDelayedWriteInformation,
    SystemBigPoolInformation,
    SystemSessionPoolTagInformation,
    SystemSessionMappedViewInformation,
    SystemHotpatchInformation,
    SystemObjectSecurityMode,
    SystemWatchdogTimerHandler,
    SystemWatchdogTimerInformation,
    SystemLogicalProcessorInformation,
    SystemWow64SharedInformation,
    SystemRegisterFirmwareTableInformationHandler,
    SystemFirmwareTableInformation,
    SystemModuleInformationEx,
    SystemVerifierTriageInformation,
    SystemSuperfetchInformation,
    SystemMemoryListInformation,
    SystemFileCacheInformationEx,
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
    UNICODE_STRING ImageName;
    SIZE_T BasePriority;
    HANDLE UniqueProcessId;
    PVOID Reserved2;
    ULONG HandleCount;
    ULONG SessionId;
    PVOID Reserved3;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG Reserved4;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    PVOID Reserved5;
    SIZE_T QuotaPagedPoolUsage;
    PVOID Reserved6;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef struct CLIENT_ID
{
    HANDLE UniqueProc;
    HANDLE UniqueThread;
}CLIENT_ID, * PCLIENT_ID;


typedef NTSTATUS(NTAPI* _NtCreateThreadEx_Win64)(
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

typedef NTSTATUS(NTAPI* _NtAllocateVirtualMemory_Win64)(
    HANDLE    ProcessHandle,
    PVOID     BaseAddress,
    PVOID     ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
    );

typedef NTSTATUS(NTAPI* _NtFreeVirtualMemory_Win64)(
    HANDLE  ProcessHandle,
    PVOID*  BaseAddress,
    PSIZE_T RegionSize,
    ULONG   FreeType
    );

typedef NTSTATUS(NTAPI* _NtWriteVirtualMemory_Win64)(
    HANDLE    ProcessHandle,
    LPVOID    TargetAddress,
    LPVOID    SrcBuffer,
    SIZE_T    RegionSize,
    PSIZE_T   lpNumberOfBytesWritten
    );

typedef NTSTATUS(NTAPI* _NtReadVirtualMemory_Win64)(
    HANDLE      hProcess,
    LPCVOID     lpBaseAddress,
    LPVOID      lpBuffer,
    SIZE_T      nSize,
    SIZE_T*     lpNumberOfBytesRead
    );

typedef NTSTATUS(NTAPI* _NtProtectVirtualMemory_Win64)(
    HANDLE  ProcesssHandle, 
    LPVOID  BaseAddress, 
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

typedef NTSTATUS(NTAPI* _NtCreateSection_Win64)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
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

typedef NTSTATUS(NTAPI* _NtQuerySystemInformation_Win64)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* _NtOpenProcess_Win64)(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId
    );

typedef NTSTATUS(NTAPI* _NtTerminateProcess_Win64)(HANDLE hProcess, DWORD ExitCode);

typedef NTSTATUS(NTAPI* _NtDelayExecution_Win64)(BOOL Alertable, PLARGE_INTEGER DelayInterval);

typedef NTSTATUS(NTAPI* _NtSuspendThread_Win64)(HANDLE ThreadHandle, PULONG PreviousSuspendCount);

typedef NTSTATUS(NTAPI* _NtResumeThread_Win64)(HANDLE ThreadHandle, PULONG PreviousSuspendCount);

typedef NTSTATUS(NTAPI* _NtClose_Win64)(HANDLE Handle);



typedef BOOL(WINAPI* CreateProcessW_pWin64)(
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
    );


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

#endif


typedef struct NTSYSCALL_SCNUMBER
{
    DWORD sc_CreateThreadEx;
	DWORD sc_SuspendThread;
	DWORD sc_ResumeThread;
    DWORD sc_AllocMem;
    DWORD sc_VirtualFree;
    DWORD sc_WriteMem;
    DWORD sc_ReadMem;
    DWORD sc_ProtectMem;
    DWORD sc_VirtualQuery;
    DWORD sc_OpenProc;
    DWORD sc_QuerySysInfo;
    DWORD sc_Terminate;
	DWORD sc_CloseHandle;
    //DWORD sc_CreateSec;
    //DWORD sc_mapView;
    //DWORD sc_UnmapView;
}NTSYSCALL_SCNUMBER, * PNTSYSCALL_SCNUMBER;

typedef struct NTSYSAPIADDR
{
    _NtCreateThreadEx_Win64             NtCreateThreadEx;
    _NtSuspendThread_Win64			    NtSuspendThread;
    _NtResumeThread_Win64			    NtResumeThread;
    _NtAllocateVirtualMemory_Win64      NtAllocateVirtualMemory;
    _NtFreeVirtualMemory_Win64          NtFreeVirtualMemory;
    _NtWriteVirtualMemory_Win64         NtWriteVirtualMemory;
    _NtReadVirtualMemory_Win64          NtReadVirtualMemory;
    _NtProtectVirtualMemory_Win64       NtProtectVirtualMemory;
    _NtQueryVirtualMemory_Win64         NtQueryVirtualMemory;
    _NtOpenProcess_Win64                NtOpenProcess;
    _NtTerminateProcess_Win64           NtTerminateProcess;
    _NtQuerySystemInformation_Win64     NtQuerySystemInformation;
	_NtClose_Win64				        NtClose;
    _NtDelayExecution_Win64             NtDelayExecution;
    //_NtCreateSection_Win64              NtCreateSection;
    //_NtMapViewOfSection_Win64           NtMapViewOfSection;
    //_NtUnmapViewOfSection_Win64         NtUnmapViewOfSection;
}NTSYSAPIADDR, *PNTSYSAPIADDR, **PPNTSYSAPIADDR;


DWORD64 Ntdll_ADDR = 0;
DWORD64 Kernel32_ADDR = 0;

void* CreateProcessW_p = 0;


static DWORD64 API = 0;

__declspec(noinline) void decbyte(void* dst, BYTE num)
{
    num--;
    while (num != 0)
    {
        *((DWORD64*)dst + num) = ~(*((DWORD64*)dst + num));
        num--;
    }
    *((DWORD64*)dst + num) = ~(*((DWORD64*)dst + num));
}

//copy from vmp
__declspec(noinline) const wchar_t* FindFileVersion(const BYTE* ptr, size_t data_size) 
{
    const wchar_t* data = reinterpret_cast<const wchar_t*>(ptr);
    data_size /= sizeof(wchar_t);

    for (size_t i = 0; i < data_size; i++) 
    {
        if (data_size >= 13) 
        {
            if (data[i + 0] == L'F' && data[i + 1] == L'i' && data[i + 2] == L'l' && data[i + 3] == L'e' && data[i + 4] == L'V' && data[i + 5] == L'e' && data[i + 6] == L'r' &&
                data[i + 7] == L's' && data[i + 8] == L'i' && data[i + 9] == L'o' && data[i + 10] == L'n' && data[i + 11] == 0 && data[i + 12] == 0)
                return data + i + 13;
        }
        if (data_size >= 15) 
        {
            if (data[i + 0] == L'P' && data[i + 1] == L'r' && data[i + 2] == L'o' && data[i + 3] == L'd' && data[i + 4] == L'u' && data[i + 5] == L'c' && data[i + 6] == L't' &&
                data[i + 7] == L'V' && data[i + 8] == L'e' && data[i + 9] == L'r' && data[i + 10] == L's' && data[i + 11] == L'i' && data[i + 12] == L'o' && data[i + 13] == L'n' && data[i + 14] == 0)
                return data + i + 15;
        }
    }
    return NULL;
}

//ntdll filever
__declspec(noinline) WORD ParseOSBuildBumber()
{
    HMODULE ntdll = 0;
    if (Ntdll_ADDR)
    {
        ntdll = (HMODULE)~Ntdll_ADDR;
	}
	else
    {
        PEB64* peb = reinterpret_cast<PEB64*>(__readgsqword(0x60));
        PMODULE_TABLE_ENTRY list = peb->Ldr->InMemoryOrderModuleList.Flink->Next;//跳过第一个用户程序模块
        ntdll = list->ModBase;
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

__declspec(noinline) int ParseSyscallscNum(void* func, DWORD* scNum)
{
    if (func)
    {
        DWORD instr = 0xB8D18B4C;
        if (*(DWORD*)func == instr)
        {
            *scNum = *(DWORD*)((DWORD64)func + 4);
            return 1;
        }
        if (*(BYTE*)func == 0xE9 || *(WORD*)func == 0x25FF || *(WORD*)func == 0xB848)
        {
			DWORD count = 1;
            DWORD funcVA = 0x10;
            while(count <= 0x20)
            {
                if (*(DWORD*)((DWORD64)func - funcVA) == instr)
                {
                    if (*(DWORD*)((DWORD64)func - funcVA + 8) == 0x82504F6)
                    {
                        *scNum = (*(DWORD*)((DWORD64)func - (funcVA - 4))) + (count / 2);
                    }
                    else
                    {
                        *scNum = (*(DWORD*)((DWORD64)func - (funcVA - 4))) + count;
                    }
                    return 1;
                }
                if (*(DWORD*)((DWORD64)func + funcVA) == instr)
                {
                    if (*(DWORD*)((DWORD64)func + funcVA + 8) == 0x82504F6)
                    {
                        *scNum = (*(DWORD*)((DWORD64)func + (funcVA + 4))) - (count / 2);
                    }
                    else
                    {
                        *scNum = (*(DWORD*)((DWORD64)func + (funcVA + 4))) - count;
                    }
                    return 1;
                }
                funcVA += 0x10;
                count++;
            }
            return -1;
        }
    }
    return 0;
}

__forceinline bool wcstrcmp_pr(const wchar_t* fir, const wchar_t* sec)
{
    int i = 0;
    while ((*(fir + i)) == (*(sec + i)))
    {
        if (*(fir + i) == 0)
            return 1;
        i++;
    }
    return 0;
}

__forceinline int vm_strcmp(const char* str1, const char* str2)
{
    unsigned char c1;
    unsigned char c2;
    size_t pos = 0;
    do {
        c1 = *(str1++);
        c2 = *(str2++);
        if (!c1)
            break;
    } while (c1 == c2);

    if (c1 < c2)
        return -1;
    else if (c1 > c2)
        return 1;
    return 0;
}

__forceinline void InitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString)
{
    if (SourceString)
        DestinationString->MaximumLength = (DestinationString->Length = (USHORT)(wcslen(SourceString) * sizeof(WCHAR))) + sizeof(UNICODE_NULL);
    else
        DestinationString->MaximumLength = DestinationString->Length = 0;

    DestinationString->Buffer = (PWCH)SourceString;
}

__declspec(noinline) void* GetProcAddress_Internal(HMODULE module, const char* proc_name)
{
    // check input
    if (!module || !proc_name)
        return NULL;

    // check module's header
    if (*(WORD*)module != 0x5A4D)
        return NULL;

    // check NT header
    IMAGE_NT_HEADERS* pe_header = reinterpret_cast<IMAGE_NT_HEADERS*>((DWORD64)module + *(DWORD*)((DWORD64)module + 0x3C));
    if (pe_header->Signature != 0x00004550)
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


__declspec(noinline) static DWORD BaseSetLastNTError_inter(DWORD Status)
{
    return RtlSetLastWin32ErrorAndNtStatusFromNtStatus(Status);
}


static void NtSleep(DWORD milliseconds)
{
    if (!API)
    {
        BaseSetLastNTError_inter(EXCEPTION_ACCESS_VIOLATION);
        return Sleep(milliseconds);
    }
    PNTSYSAPIADDR DecAPI = *(PPNTSYSAPIADDR)~API;
    LARGE_INTEGER ms{};
    ms.QuadPart = static_cast<LONGLONG>(-1) * (static_cast<LONGLONG>(milliseconds) * 10000);
    NTSTATUS ret = DecAPI->NtDelayExecution(false, &ms);
    if (ret)
        BaseSetLastNTError_inter(ret);
}


__declspec(noinline) static BOOLEAN WINAPI VirtualProtect_Internal(HANDLE procHandle, LPVOID baseAddr, size_t size, DWORD protect, DWORD* oldp)
{
    if(!API)
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
    PNTSYSAPIADDR DecAPI = *(PPNTSYSAPIADDR)~API;
    NTSTATUS ret = DecAPI->NtProtectVirtualMemory(procHandle, (void**)(&addr), &size, protect, oldp);
    if (ret)
    {
        BaseSetLastNTError_inter(ret);
        return 0;
    }
    return 1;
}


__declspec(noinline) static PVOID WINAPI VirtualAllocEx_Internal(HANDLE procHandle, _In_opt_ PVOID dst_baseaddr, size_t size, DWORD protect)
{
    if (!API)
    {
        BaseSetLastNTError_inter(STATUS_ACCESS_VIOLATION);
        return 0;
    }
    void* baseaddr = dst_baseaddr;
    if(size & 0xFFF)
    {
        size &= 0xFFFFFFFFFFFFF000;
        size += 0x1000;
    }
    PNTSYSAPIADDR DecAPI = *(PPNTSYSAPIADDR)~API;
    NTSTATUS ret = DecAPI->NtAllocateVirtualMemory(procHandle, &baseaddr, 0, &size, MEM_COMMIT | MEM_RESERVE, protect);
    if (ret)
    {
        BaseSetLastNTError_inter(ret);
        return 0;
    }
    return baseaddr;
}


static PVOID WINAPI VirtualAlloc_Internal(_In_opt_ PVOID dst_baseaddr, size_t size, DWORD protect)
{
    return VirtualAllocEx_Internal((HANDLE)-1, dst_baseaddr, size, protect);
}


__declspec(noinline) static BOOLEAN WINAPI VirtualFreeEx_Internal(HANDLE handle, _In_opt_ PVOID baseaddr, size_t size, DWORD Freetype)
{
    if (!API)
    {
        BaseSetLastNTError_inter(STATUS_ACCESS_VIOLATION);
        return 0;
    }
    PNTSYSAPIADDR DecAPI = *(PPNTSYSAPIADDR)~API;
    NTSTATUS ret = DecAPI->NtFreeVirtualMemory(handle, &baseaddr, &size, Freetype);
    if (ret)
    {
        BaseSetLastNTError_inter(ret);
        return 0;
    }
    return 1;
}


static BOOLEAN WINAPI VirtualFree_Internal(_In_opt_ PVOID baseaddr, size_t size, DWORD Freetype)
{
    return VirtualFreeEx_Internal((HANDLE)-1, baseaddr, size, Freetype);
}


__declspec(noinline) static BOOLEAN WINAPI ReadProcessMemoryInternal(HANDLE procHandle, _In_ LPVOID src_baseaddr, _In_opt_ LPVOID dst_buffer, size_t size, size_t* sizeofreadnum)
{
    if(!API)
    {
        BaseSetLastNTError_inter(STATUS_ACCESS_VIOLATION);
        return 0;
    }
    PNTSYSAPIADDR DecAPI = *(PPNTSYSAPIADDR)~API;
    size_t Readsize;
    NTSTATUS ret = DecAPI->NtReadVirtualMemory(procHandle, src_baseaddr, dst_buffer, size, &Readsize);
    if (sizeofreadnum)
        *sizeofreadnum = Readsize;
    if (ret)
    {
        BaseSetLastNTError_inter(ret);
        return 0;
    }
    return 1;
}


__declspec(noinline) static BOOLEAN WINAPI WriteProcessMemoryInternal(HANDLE procHandle, _In_opt_ LPVOID dst_baseaddr, _In_ LPVOID src_buffer, size_t size, size_t* sizeofwritenum)
{
    if (!API)
    {
        BaseSetLastNTError_inter(STATUS_ACCESS_VIOLATION);
        return 0;
    }
    size_t wsize = 0;
    size_t* pwsize = sizeofwritenum;
    if (!sizeofwritenum)
        pwsize = &wsize;

    NTSTATUS ret = 0;
    MEMORY_BASIC_INFORMATION temp = { 0 };
    PNTSYSAPIADDR DecAPI = *(PPNTSYSAPIADDR)~API;
    ret = DecAPI->NtQueryVirtualMemory(procHandle, dst_baseaddr, MemoryBasicInformation, &temp, sizeof(temp), pwsize);
    if (ret)
        goto __failed;
    if (temp.Protect & 0xCC)
    {
        ret = DecAPI->NtWriteVirtualMemory(procHandle, dst_baseaddr, src_buffer, size, pwsize);
        if (ret)
            goto __failed;
        return 1;
    }
    else 
    {
        DWORD oldp = 0;
        size_t alsize = size;
        LPVOID dst_aladdr = dst_baseaddr;
        if (size & 0xFFF)
        {
            alsize = (size & 0xFFFFFFFFFFFFF000) + 0x1000;
            dst_aladdr = (LPVOID)((DWORD64)dst_aladdr & 0xFFFFFFFFFFFFF000);
        }
        ret = DecAPI->NtProtectVirtualMemory(procHandle, &dst_aladdr, &alsize, 0x60000040, &oldp);
        if (!ret)
        {
            ret = DecAPI->NtWriteVirtualMemory(procHandle, dst_baseaddr, src_buffer, size, pwsize);
            DecAPI->NtProtectVirtualMemory(procHandle, &dst_aladdr, &alsize, oldp, &oldp);
            if (ret)
                goto __failed;
            return 1;
        }
    }
__failed:
    BaseSetLastNTError_inter(ret);
    return 0;
}


__declspec(noinline) static LPVOID WINAPI CreateProcInfoSnapshot()
{
    if (!API)
    {
        BaseSetLastNTError_inter(STATUS_ACCESS_VIOLATION);
        return 0;
    }
    LPVOID InfoHeap = 0;
    SIZE_T size = 0x20000;
    PNTSYSAPIADDR DecAPI = *(PPNTSYSAPIADDR)~API;
    while(1)
    {
        NTSTATUS ret = DecAPI->NtAllocateVirtualMemory((HANDLE)-1, &InfoHeap, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (ret)
        {
            BaseSetLastNTError_inter(ret);
            return 0;
        }
        ULONG retsize;
        ret = DecAPI->NtQuerySystemInformation(SystemProcessInformation, ((BYTE*)InfoHeap + 0x1000), static_cast<ULONG>(size - 0x1000), &retsize);
        if (ret == 0xC0000004)
        {
            DecAPI->NtFreeVirtualMemory((HANDLE)-1, &InfoHeap, &size, MEM_RELEASE);
            size = (static_cast<SIZE_T>(retsize & 0xFFFFF000) + 0x2000);
            InfoHeap = 0;
            continue;
        }
        else if (ret)
        {
            BaseSetLastNTError_inter(ret);
            return 0;
        }
        break;
    }
    *(void**)InfoHeap = (BYTE*)InfoHeap + 0x1000;

    return InfoHeap;
}


__declspec(noinline) static DWORD WINAPI GetProcPID(LPCWSTR ProcessName)
{
    if (!ProcessName)
        return 0;
    LPVOID info = CreateProcInfoSnapshot();
    if (!info)
        return 0;

    PSYSTEM_PROCESS_INFORMATION tProc = *(PSYSTEM_PROCESS_INFORMATION*)info;
    HANDLE PID = 0;
    __nop();
    __nop();
    __nop();
    while(1)
    {
        LPCWSTR tProcName = tProc->ImageName.Buffer;
        if (tProcName)
        {
            if (wcstrcmp_pr(tProcName, ProcessName))
            {
                PID = tProc->UniqueProcessId;
                break;
            }
        }
        if (tProc->NextEntryOffset)
        {
            tProc = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)tProc + tProc->NextEntryOffset);
        }
        else break;
    }

    VirtualFree_Internal(info, 0, MEM_RELEASE);
    return (DWORD)PID;
}


__declspec(noinline) static HANDLE WINAPI CreateRemoteThreadEx_Internal(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter)
{
    if (!API)
    {
        BaseSetLastNTError_inter(STATUS_ACCESS_VIOLATION);
        return 0;
    }
    HANDLE retHandle = 0;
    PNTSYSAPIADDR DecAPI = *(PPNTSYSAPIADDR)~API;
    NTSTATUS status = DecAPI->NtCreateThreadEx(&retHandle, GENERIC_ALL, 0, hProcess, lpStartAddress, lpParameter, 0, 0, 0xC000, 0x30000, 0);
    if (status)
    {
        BaseSetLastNTError_inter(status);
        return 0;
    }
    return retHandle;
}


__declspec(noinline) static HANDLE WINAPI OpenProcess_Internal(DWORD dwDesiredAccess, DWORD dwProcessId)
{
    if (!API)
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
    PNTSYSAPIADDR DecAPI = *(PPNTSYSAPIADDR)~API;
    NTSTATUS ret = DecAPI->NtOpenProcess(&opHandle, dwDesiredAccess, &tempOb, &tempID);
    if (ret)
    {
        BaseSetLastNTError_inter(ret);
        return 0;
    }
    return opHandle;
}


__declspec(noinline) static DWORD WINAPI SuspendThread_Internal(HANDLE hThread)
{
	if (!API)
	{
		BaseSetLastNTError_inter(STATUS_ACCESS_VIOLATION);
		return 0;
	}
	PNTSYSAPIADDR DecAPI = *(PPNTSYSAPIADDR)~API;
	DWORD suspendCount = 0;
	NTSTATUS ret = DecAPI->NtSuspendThread(hThread, &suspendCount);
	if (ret)
	{
		BaseSetLastNTError_inter(ret);
		return -1;
	}
	return suspendCount;
}


__declspec(noinline) static DWORD WINAPI ResumeThread_Internal(HANDLE hThread)
{
	if (!API)
	{
		BaseSetLastNTError_inter(STATUS_ACCESS_VIOLATION);
		return 0;
	}
	PNTSYSAPIADDR DecAPI = *(PPNTSYSAPIADDR)~API;
	DWORD suspendCount = 0;
	NTSTATUS ret = DecAPI->NtResumeThread(hThread, &suspendCount);
	if (ret)
	{
		BaseSetLastNTError_inter(ret);
		return -1;
	}
	return suspendCount;
}


__declspec(noinline) static BOOLEAN WINAPI CloseHandle_Internal(HANDLE hObject)
{
	if (!API)
	{
		BaseSetLastNTError_inter(STATUS_ACCESS_VIOLATION);
		return 0;
	}
	PNTSYSAPIADDR DecAPI = *(PPNTSYSAPIADDR)~API;
	NTSTATUS ret = DecAPI->NtClose(hObject);
	if (ret)
	{
		BaseSetLastNTError_inter(ret);
		return 0;
	}
	return 1;
}


__declspec(noinline) static BOOLEAN WINAPI TerminateProcess_Internal(HANDLE hProcess, DWORD Code)
{
    if (!API)
    {
        BaseSetLastNTError_inter(STATUS_ACCESS_VIOLATION);
        return 0;
    }
    PNTSYSAPIADDR DecAPI = *(PPNTSYSAPIADDR)~API;
    NTSTATUS ret = DecAPI->NtTerminateProcess(hProcess, Code);
    if (ret < 0)
    {
        BaseSetLastNTError_inter(ret);
        return 0;
    }
    return 1;
}




static __forceinline void init_syscall_buff(void* buff, void* CallAddr, NTSYSCALL_SCNUMBER* SCnum_struct, PNTSYSAPIADDR Store)
{
	//memset(buff, 0xCC, 0x4000);

    //__nop();
    //random var
    DWORD64 ra = __rdtsc();
    ra ^= (DWORD64)Store;
    DWORD raRAXH = ra >> 32;
    DWORD raRAXL = ra & 0xFFFFFFFF;
    ra ^= raRAXH;
    ra ^= (DWORD64)SCnum_struct;
    WORD ra1 = ra >> 16;
    WORD ra2 = ra & 0xFFFF;
    ra1 ^= ra2;
    ra2 ^= ra1;
    WORD ra3 = (~raRAXL ^ ra) & 0xFFFF;
    WORD ra4 = (~raRAXH ^ ra) & 0xFFFF;

    BYTE* startaddr = (BYTE*)buff + (DWORD)((DWORD)(ra1 & 0xFF) << 4);//private syscall start addr
    BYTE* call = ((startaddr + 0x200) + (DWORD)((DWORD)(ra2 & 0xFF) << 4));//jump to buildfakestack addr
    BYTE* spoofcalladdr = ((call + 0x30) + (DWORD)((DWORD)(ra3 & 0xFF) << 4));//buildfakestack addr
    BYTE* restoreaddr = ((spoofcalladdr + 0x30) + (DWORD)((DWORD)(ra4 & 0xFF) << 4));//restore stack addr

    //jump to buildfakestack part
    *(DWORD64*)call = 0xB94850592414874C;
    *(DWORD64*)(call + 0x8) = ~(DWORD64)CallAddr;
    *(DWORD32*)(call + 0x10) = 0x058D4850;
    *(DWORD32*)(call + 0x14) = (restoreaddr - (call + 0x18));//restoreva
    *(DWORD64*)(call + 0x18) = (0x2404C748 | ((DWORD64)spoofcalladdr << 32));
    *(DWORD64*)(call + 0x20) = (0x42444C7 | ((DWORD64)spoofcalladdr & 0xFFFFFFFF00000000));
    *(call + 0x28) = 0xC3;

    //restore stack part
    *(DWORD64*)(restoreaddr + 0x00) = 0xFFFFFF0024A48D48;
    *(DWORD64*)(restoreaddr + 0x08) = 0x22024A48D48;
    *(DWORD64*)(restoreaddr + 0x10) = 0x8B48944824048748;
    *(DWORD64*)(restoreaddr + 0x18) = 0x834800408B480868;
    *(DWORD32*)(restoreaddr + 0x20) = 0xCCC310C4;

    //buildfakestack part
    *(DWORD64*)(spoofcalladdr + 0x00) = 0x24A48D48C48B4850;
    *(DWORD64*)(spoofcalladdr + 0x08) = 0x242C8748FFFFF980;
    *(DWORD64*)(spoofcalladdr + 0x10) = 0x2404894808EC8348;
    *(DWORD64*)(spoofcalladdr + 0x18) = 0xFFFFFEE024A48D48;
    *(DWORD64*)(spoofcalladdr + 0x20) = 0x8408D48288930FF;
    *(DWORD64*)(spoofcalladdr + 0x28) = 0x2444110F3040100F;
    *(DWORD64*)(spoofcalladdr + 0x30) = 0x44110F4040100F28;
    *(DWORD64*)(spoofcalladdr + 0x38) = 0x110F5040100F3824;
    *(DWORD64*)(spoofcalladdr + 0x40) = 0xF6040100F482444;
    *(DWORD64*)(spoofcalladdr + 0x48) = 0x40874858244411;
    *(DWORD64*)(spoofcalladdr + 0x50) = 0xCCCCE1FFD1F74844;

    //private syscall build
    for(int i = 0; i != 0x10; i++)
    {
        *(DWORD64*)(startaddr + (i * 0x20)) = 0xB948FFFFFFFFB851;
        *(DWORD64*)(startaddr + (i * 0x20) + 0x8) = ~(DWORD64)call;
        *(DWORD64*)(startaddr + (i * 0x20) + 0x10) = 0xCCCCE1FFD1F74844;
        *(DWORD64*)(startaddr + (i * 0x20) + 0x18) = 0xCCCCCCCCCCCCCCCC;
    }

    *(DWORD*)(startaddr + 0x2) = SCnum_struct->sc_CreateThreadEx;
    Store->NtCreateThreadEx = (_NtCreateThreadEx_Win64)startaddr;
    startaddr += 0x20;
    *(DWORD*)(startaddr + 0x2) = SCnum_struct->sc_AllocMem;
    Store->NtAllocateVirtualMemory = (_NtAllocateVirtualMemory_Win64)startaddr;
    startaddr += 0x20;
    *(DWORD*)(startaddr + 0x2) = SCnum_struct->sc_VirtualFree;
    Store->NtFreeVirtualMemory = (_NtFreeVirtualMemory_Win64)startaddr;
    startaddr += 0x20;
    *(DWORD*)(startaddr + 0x2) = SCnum_struct->sc_ProtectMem;
    Store->NtProtectVirtualMemory = (_NtProtectVirtualMemory_Win64)startaddr;
    startaddr += 0x20;
    *(DWORD*)(startaddr + 0x2) = SCnum_struct->sc_WriteMem;
    Store->NtWriteVirtualMemory = (_NtWriteVirtualMemory_Win64)startaddr;
    startaddr += 0x20;
    *(DWORD*)(startaddr + 0x2) = SCnum_struct->sc_ReadMem;
    Store->NtReadVirtualMemory = (_NtReadVirtualMemory_Win64)startaddr;
    startaddr += 0x20;
    *(DWORD*)(startaddr + 0x2) = SCnum_struct->sc_VirtualQuery;
    Store->NtQueryVirtualMemory = (_NtQueryVirtualMemory_Win64)startaddr;
    startaddr += 0x20;
    *(DWORD*)(startaddr + 0x2) = SCnum_struct->sc_OpenProc;
    Store->NtOpenProcess = (_NtOpenProcess_Win64)startaddr;
    startaddr += 0x20;
    *(DWORD*)(startaddr + 0x2) = SCnum_struct->sc_Terminate;
    Store->NtTerminateProcess = (_NtTerminateProcess_Win64)startaddr;
    startaddr += 0x20;
    *(DWORD*)(startaddr + 0x2) = SCnum_struct->sc_QuerySysInfo;
    Store->NtQuerySystemInformation = (_NtQuerySystemInformation_Win64)startaddr;
	startaddr += 0x20;
	*(DWORD*)(startaddr + 0x2) = SCnum_struct->sc_ResumeThread;
	Store->NtResumeThread = (_NtResumeThread_Win64)startaddr;
	startaddr += 0x20;
	*(DWORD*)(startaddr + 0x2) = SCnum_struct->sc_SuspendThread;
	Store->NtSuspendThread = (_NtSuspendThread_Win64)startaddr;
	startaddr += 0x20;
	*(DWORD*)(startaddr + 0x2) = SCnum_struct->sc_CloseHandle;
	Store->NtClose = (_NtClose_Win64)startaddr;
    /*
    startaddr += 0x20;
    *(DWORD*)(startaddr + 0x2) = SCnum_struct->sc_CreateSec;
    Store->NtCreateSection = (_NtCreateSection_Win64)startaddr;
    startaddr += 0x20;
    *(DWORD*)(startaddr + 0x2) = SCnum_struct->sc_mapView;
    Store->NtMapViewOfSection = (_NtMapViewOfSection_Win64)startaddr;
    startaddr += 0x20;
    *(DWORD*)(startaddr + 0x2) = SCnum_struct->sc_UnmapView;
    Store->NtUnmapViewOfSection = (_NtUnmapViewOfSection_Win64)startaddr;
    */
    
}

typedef LPCSTR(CDECL* pwine_get_version)(void);

static NTSTATUS init_NTAPI(DWORD* gspeb, DWORD CMode, DWORD64* PretValue)
{
    PEB64* peb = reinterpret_cast<PEB64*>(__readgsqword(*gspeb));
    //DWORD64 PCRTmain = (DWORD64)(peb->ImageBaseAddress) + (*(DWORD*)((DWORD64)(*(DWORD*)((DWORD64)(peb->ImageBaseAddress) + 0x3C) + (DWORD64)(peb->ImageBaseAddress)) + 0x28));
    PMODULE_TABLE_ENTRY list = peb->Ldr->InMemoryOrderModuleList.Flink->Next;//跳过第一个用户程序模块
    HMODULE ntdll = list->ModBase;
    HMODULE kernel32 = list->Next->ModBase;
    if (!ntdll)
        return STATUS_DLL_NOT_FOUND;
    if (!kernel32)
        return STATUS_DLL_NOT_FOUND;

    Ntdll_ADDR = ~(DWORD64)ntdll;
    Kernel32_ADDR = ~(DWORD64)kernel32;

    NTSYSCALL_SCNUMBER SC_number;
    NTSYSAPIADDR tempstore;
    LPCSTR isWine = (LPCSTR)CMode;

    if(!isWine)
    {
		char str_wine[24];
		*(DWORD64*)(&str_wine) = 0x8B9A98A09A919688;
		*(DWORD64*)(&str_wine[8]) = 0x9190968C8D9A89A0;
		decbyte(str_wine, 2);
        *(DWORD64*)(&str_wine[16]) = 0;
        if (pwine_get_version fptemp = pwine_get_version(GetProcAddress_Internal(ntdll, str_wine)))
        {
            isWine = fptemp();
            isWine = *(LPCSTR*)isWine;
        }
    }

    if(1)
    {
        char str_zct[32];
        *(DWORD64*)(&str_zct) = 0x9A8B9E9A8DBC8BB1;
        *(DWORD64*)(&str_zct[8]) = 0x87BA9B9E9A8D97AB;
        decbyte(str_zct, 2);
        *(DWORD64*)(&str_zct[16]) = 0;
        void* NtCTE = GetProcAddress_Internal(ntdll, str_zct);
        if (!NtCTE)
            return CREATE_THREAD_INITFAILED;

        if(!isWine)
        {
            int i = ParseSyscallscNum(NtCTE, &SC_number.sc_CreateThreadEx);
            if (i != 1)
            {
                return CREATE_THREAD_INITFAILED;
            }
        }
        else
        {
            tempstore.NtCreateThreadEx = (_NtCreateThreadEx_Win64)NtCTE;
        }
    }
    {
        char str_RST[16];
        *(DWORD64*)(&str_RST) = 0x9A928A8C9AAD8BB1;
        *(DWORD64*)(&str_RST[8]) = 0xD3719B9E9A8D97AB;
        decbyte(str_RST, 2);
        str_RST[14] = 0;
        void* NtRST = GetProcAddress_Internal(ntdll, str_RST);
        if (!NtRST)
            return RESUME_INITFAILED;

        if (!isWine)
        {
            int i = ParseSyscallscNum(NtRST, &SC_number.sc_ResumeThread);
            if (i != 1)
            {
                return RESUME_INITFAILED;
            }
        }
        else
        {
            tempstore.NtResumeThread = (_NtResumeThread_Win64)NtRST;
        }
    }
	{
		char str_SPT[16];
		*(DWORD64*)(&str_SPT) = 0x919A8F8C8AAC8BB1;
		*(DWORD64*)(&str_SPT[8]) = 0xC99B9E9A8D97AB9B;
		decbyte(str_SPT, 2);
		str_SPT[15] = 0;
		void* NtST = GetProcAddress_Internal(ntdll, str_SPT);
		if (!NtST)
			return SUSPEND_INITFAILED;
		if (!isWine)
		{
			int i = ParseSyscallscNum(NtST, &SC_number.sc_SuspendThread);
			if (i != 1)
			{
				return SUSPEND_INITFAILED;
			}
		}
		else
		{
			tempstore.NtSuspendThread = (_NtSuspendThread_Win64)NtST;
		}
	}
    {
		char str_close[16];
		*(DWORD64*)(&str_close) = 0x559A8C9093BC8BB1;
		*(DWORD64*)(&str_close[8]) = 0x929AB2939E8A8B8D;
        decbyte(str_close, 2);
		str_close[7] = 0;
		void* NtClose = GetProcAddress_Internal(ntdll, str_close);
		if (!NtClose)
			return CLOSE_HANDLE_INITFAILED;
		if (!isWine)
		{
			int i = ParseSyscallscNum(NtClose, &SC_number.sc_CloseHandle);
			if (i != 1)
			{
				return CLOSE_HANDLE_INITFAILED;
			}
		}
		else
		{
			tempstore.NtClose = (_NtClose_Win64)NtClose;
		}
    }
    {
        char str_alloc[32];
        *(DWORD64*)(&str_alloc) = 0x9E9C909393BE8BB1;
        *(DWORD64*)(&str_alloc[8]) = 0x9E8A8B8D96A99A8B;
        *(DWORD64*)(&str_alloc[16]) = 0x32868D90929AB293;
        decbyte(str_alloc, 3);
		str_alloc[23] = 0;
        void* NtAlloc = GetProcAddress_Internal(ntdll, str_alloc);
        if(!NtAlloc)
            return VIRTUAL_ALLOC_INITFAILED;
        if(!isWine)
        {
            int i = ParseSyscallscNum(NtAlloc, &SC_number.sc_AllocMem);
            if (i != 1)
            {
                return VIRTUAL_ALLOC_INITFAILED;
            }
        }
        else
        {
            tempstore.NtAllocateVirtualMemory = (_NtAllocateVirtualMemory_Win64)NtAlloc;
        }
    }
    {
        char str_free[32];
        *(DWORD64*)(&str_free) = 0x96A99A9A8DB98BB1;
        *(DWORD64*)(&str_free[8]) = 0x929AB2939E8A8B8D;
        *(DWORD64*)(&str_free[16]) = 0x9AB2939EE6868D90;
        decbyte(str_free, 3);
		str_free[19] = 0;
        void* NtFree = GetProcAddress_Internal(ntdll, str_free);
        if (!NtFree)
            return VIRTUAL_FREE_INITFAILED;
        if (!isWine)
        {
            int i = ParseSyscallscNum(NtFree, &SC_number.sc_VirtualFree);
            if (i != 1)
            {
                return VIRTUAL_FREE_INITFAILED;
            }
        }
        else
        {
            tempstore.NtFreeVirtualMemory = (_NtFreeVirtualMemory_Win64)NtFree;
        }
    }
    {
        char str_wrtMem[32];
        *(DWORD64*)(&str_wrtMem) = 0xA99A8B968DA88BB1;
        *(DWORD64*)(&str_wrtMem[8]) = 0x9AB2939E8A8B8D96;
        *(DWORD64*)(&str_wrtMem[16]) = 0x1682329C868D9092;
        decbyte(str_wrtMem, 3);
		*(DWORD*)(&str_wrtMem[20]) = 0;
        void* NtWriteMem = GetProcAddress_Internal(ntdll, str_wrtMem);
        if (!NtWriteMem)
            return WRITE_VIRTUAL_MEM_INITFAILED;

        if (!isWine)
        {
            int i = ParseSyscallscNum(NtWriteMem, &SC_number.sc_WriteMem);
            if (i != 1)
            {
                return WRITE_VIRTUAL_MEM_INITFAILED;
            }
        }
        else
        {
            tempstore.NtWriteVirtualMemory = (_NtWriteVirtualMemory_Win64)NtWriteMem;
        }
    }
    {
        char str_readMem[32];
        *(DWORD64*)(&str_readMem) = 0x96A99B9E9AAD8BB1;
        *(DWORD64*)(&str_readMem[8]) = 0x929AB2939E8A8B8D;
        *(DWORD64*)(&str_readMem[16]) = 0x8AB92293F7868D90;
        decbyte(str_readMem, 3);
        str_readMem[19] = 0;
        void* NtReadMem = GetProcAddress_Internal(ntdll, str_readMem);
        if (!NtReadMem)
            return READ_VIRTUAL_MEM_INITFAILED;

        if (!isWine)
        {
            int i = ParseSyscallscNum(NtReadMem, &SC_number.sc_ReadMem);
            if (i != 1)
            {
                return READ_VIRTUAL_MEM_INITFAILED;
            }
        }
        else
        {
            tempstore.NtReadVirtualMemory = (_NtReadVirtualMemory_Win64)NtReadMem;
        }
    }
    {
        char str_protectMem[32];
        *(DWORD64*)(&str_protectMem) = 0x9C9A8B908DAF8BB1;
        *(DWORD64*)(&str_protectMem[8]) = 0x939E8A8B8D96A98B;
        *(DWORD64*)(&str_protectMem[16]) = 0xAFE9868D90929AB2;
        decbyte(str_protectMem, 3);
		str_protectMem[22] = 0;
        void* NtPVM = GetProcAddress_Internal(ntdll, str_protectMem);
        if (!NtPVM)
            return VIRTUAL_PROTECT_INITFAILED;

        if (!isWine)
        {
            int i = ParseSyscallscNum(NtPVM, &SC_number.sc_ProtectMem);
            if (i != 1)
            {
                return VIRTUAL_PROTECT_INITFAILED;
            }
        }
        else
        {
            tempstore.NtProtectVirtualMemory = (_NtProtectVirtualMemory_Win64)NtPVM;
        }
    }
    {
        char str_QueryMem[32];
        *(DWORD64*)(&str_QueryMem) = 0xA9868D9A8AAE8BB1;
        *(DWORD64*)(&str_QueryMem[8]) = 0x9AB2939E8A8B8D96;
        *(DWORD64*)(&str_QueryMem[16]) = 0x785612AB868D9092;
        decbyte(str_QueryMem, 3);
		str_QueryMem[20] = 0;
        void* NtQVM = GetProcAddress_Internal(ntdll, str_QueryMem);
        if (!NtQVM)
            return VIRTUAL_QUERY_INITFAILED;

        if (!isWine)
        {
            int i = ParseSyscallscNum(NtQVM, &SC_number.sc_VirtualQuery);
            if (i != 1)
            {
                return VIRTUAL_QUERY_INITFAILED;
            }
        }
        else
        {
            tempstore.NtQueryVirtualMemory = (_NtQueryVirtualMemory_Win64)NtQVM;
        }
    }
    {
        char str_openproc[16];
        *(DWORD64*)(&str_openproc) = 0x8DAF919A8FB08BB1;
        *(DWORD64*)(&str_openproc[8]) = 0xA2BF1A8C8C9A9C90;
        decbyte(str_openproc, 2);
		str_openproc[13] = 0;
        void* NtOpenProc = GetProcAddress_Internal(ntdll, str_openproc);
        if (!NtOpenProc)
            return OPEN_PROCESS_INITFAILED;

        if (!isWine)
        {
            int i = ParseSyscallscNum(NtOpenProc, &SC_number.sc_OpenProc);
            if (i != 1)
            {
                return OPEN_PROCESS_INITFAILED;
            }
        }
        else
        {
            tempstore.NtOpenProcess = (_NtOpenProcess_Win64)NtOpenProc;
        }
    }
    {
        char str_QSysInfo[32];
        *(DWORD64*)(&str_QSysInfo) = 0xAC868D9A8AAE8BB1;
        *(DWORD64*)(&str_QSysInfo[8]) = 0x9991B6929A8B8C86;
        *(DWORD64*)(&str_QSysInfo[16]) = 0x9190968B9E928D90;
        decbyte(str_QSysInfo, 3);
        *(DWORD64*)(&str_QSysInfo[24]) = 0;
        void* NtQSysInfo = GetProcAddress_Internal(ntdll, str_QSysInfo);
        if (!NtQSysInfo)
            return QUERY_SYS_INFO_INITFAILED;
        
        if (!isWine)
        {
            int i = ParseSyscallscNum(NtQSysInfo, &SC_number.sc_QuerySysInfo);
            if (i != 1)
            {
                return QUERY_SYS_INFO_INITFAILED;
            }
        }
        else
        {
            tempstore.NtQuerySystemInformation = (_NtQuerySystemInformation_Win64)NtQSysInfo;
        }
    }
    {
        char str_Terminate[32];
        *(DWORD64*)(&str_Terminate) = 0x9196928D9AAB8BB1;
        *(DWORD64*)(&str_Terminate[8]) = 0x9A9C908DAF9A8B9E;
        decbyte(str_Terminate, 3);
        *(DWORD64*)(&str_Terminate[16]) = 0x7373;
        void* NtTerminate = GetProcAddress_Internal(ntdll, str_Terminate);
        if (!NtTerminate)
            return TERMINATE_INITFAILED;

        if (!isWine)
        {
            int i = ParseSyscallscNum(NtTerminate, &SC_number.sc_Terminate);
            if (i != 1)
            {
                return TERMINATE_INITFAILED;
            }
        }
        else
        {
            tempstore.NtTerminateProcess = (_NtTerminateProcess_Win64)NtTerminate;
        }
    }

    /*
    {
        char str_CreateSec[16];
        *(DWORD64*)(&str_CreateSec) = 0x9A8B9E9A8DBC88A5;
        *(DWORD64*)(&str_CreateSec[8]) = 0xFF9190968B9C9AAC;
        decbyte(str_CreateSec, 2);
        void* NtCreateSec = GetProcAddress_Internal(ntdll, str_CreateSec);
        if (!NtCreateSec)
            return CREATE_SECTION_INITFAILED;

        if (!isWine)
        {
            int i = ParseSyscallscNum(NtCreateSec, &SC_number.sc_CreateSec);
            if (i != 1)
            {
                return CREATE_SECTION_INITFAILED;
            }
        }
        else
        {
            tempstore.NtCreateSection = (_NtCreateSection_Win64)NtCreateSec;
        }
    }
    {
        char str_mapview[32];
        *(DWORD64*)(&str_mapview) = 0x9A96A98F9EB28BB1;
        *(DWORD64*)(&str_mapview[8]) = 0x968B9C9AAC99B088;
        *(DWORD32*)(&str_mapview[16]) = 0xCCFF9190;
        decbyte(str_mapview, 3);
        void* Ntmapview = GetProcAddress_Internal(ntdll, str_mapview);
        if (!Ntmapview)
            return MAP_SECTION_INITFAILED;

        if (!isWine)
        {
            int i = ParseSyscallscNum(Ntmapview, &SC_number.sc_mapView);
            if (i != 1)
            {
                return MAP_SECTION_INITFAILED;
            }
        }
        else
        {
            tempstore.NtMapViewOfSection = (_NtMapViewOfSection_Win64)Ntmapview;
        }
    }
    {
        char str_Unmapview[32];
        *(DWORD64*)(&str_Unmapview) = 0xA98F9E9291AA8BB1;
        *(DWORD64*)(&str_Unmapview[8]) = 0x9C9AAC99B0889A96;
        *(DWORD64*)(&str_Unmapview[16]) = 0x539F72FF9190968B;
        decbyte(str_Unmapview, 3);
        void* NtUnmapview = GetProcAddress_Internal(ntdll, str_Unmapview);
        if (!NtUnmapview)
            return UNMAP_SECTION_INITFAILED;

        if (!isWine)
        {
            int i = ParseSyscallscNum(NtUnmapview, &SC_number.sc_UnmapView);
            if (i != 1)
            {
                return UNMAP_SECTION_INITFAILED;
            }
        }
        else
        {
            tempstore.NtUnmapViewOfSection = (_NtUnmapViewOfSection_Win64)NtUnmapview;
        }
    }
    */

    {
        char str_delay[24];
        *(DWORD64*)(&str_delay) = 0xBA869E939ABB8BB1;
        *(DWORD64*)(&str_delay[8]) = 0x9190968B8A9C9A87;
        decbyte(str_delay, 2);
        *(DWORD64*)(&str_delay[16]) = 0;
        BYTE* Ntdelay = (BYTE*)GetProcAddress_Internal(ntdll, str_delay);
        if (!Ntdelay)
            return 0xDEADC0DE;
        
        tempstore.NtDelayExecution = (_NtDelayExecution_Win64)Ntdelay;
    }
 
    if(!isWine)
    {
        BYTE* Ntdelay = (BYTE*)tempstore.NtDelayExecution;
        if (((*(DWORD*)(Ntdelay + 0x12)) & 0xFFFFFF) == 0xC3050F)
        {
            Ntdelay += 0x12;
        }
        else if (((*(DWORD*)(Ntdelay + 0x8)) & 0xFFFFFF) == 0xC3050F)
        {
            Ntdelay += 0x8;
        }
        else
        {
            return 0xDEADC0DE;
        }
        
        SYSCALLSTRUCT initcall;
        initcall.scnumber = SC_number.sc_AllocMem;
        //
        {
            DWORD64 addr;
            while (1)
            {
                DWORD64 randomVA = __rdtsc();
                randomVA &= 0x7FF;
                randomVA <<= 4;
                randomVA += (DWORD64)Ntdelay;
                if (((*(DWORD*)randomVA) & 0xFFFFFF) == 0xC3050F)
                {
                    addr = randomVA;
                    break;
                }
            }
            while (1)
            {
                DWORD64 randomVA = __rdtsc();
                randomVA &= 0x7FF;
                randomVA <<= 4;
                randomVA += (DWORD64)Ntdelay;
                if (((*(DWORD*)randomVA) & 0xFFFFFF) == 0xC3050F)
                {
                    Ntdelay = (BYTE*)randomVA;
                    break;
                }
            }
            initcall.calladdr = ~addr;
        }
        initcall.rcx = -1;
        size_t i = 0x8000;
        DWORD64 addr = 0;
        NTSTATUS ret = ((_NtAllocateVirtualMemory_Win64)&asm_syscall)(&initcall, &addr, 0, &i, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!ret)
        {
            DWORD64 APIstore = addr + 0x1000;
            *(DWORD64*)addr = APIstore;
            DWORD oldp = 0;
            DWORD64 EXaddr = addr + 0x2000;
            i -= 0x2000;
            init_syscall_buff((void*)EXaddr, Ntdelay, &SC_number, &tempstore);
            initcall.scnumber = SC_number.sc_ProtectMem;
            ret = ((_NtProtectVirtualMemory_Win64)&asm_syscall)(&initcall, &EXaddr, &i, PAGE_EXECUTE_READ, &oldp);
            if (ret)
                return ret;
            i = 0x2000;
            memcpy((void*)APIstore, &tempstore, sizeof(NTSYSAPIADDR));
            ret = ((_NtProtectVirtualMemory_Win64)&asm_syscall)(&initcall, &addr, &i, PAGE_READONLY, &oldp);
            if (ret)
                return ret;

            *PretValue = ~addr;
        }
        else
        {
            return ret;
        }
    }
    else
    {
        DWORD64 addr = 0;
        size_t sz = 0x2000;
        NTSTATUS ret = tempstore.NtAllocateVirtualMemory((HANDLE)-1, &addr, 0, &sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (ret)
            return ret;
        *(DWORD64*)addr = (addr + 1000);
        addr += 1000;
        memcpy((void*)addr, &tempstore, sizeof(NTSYSAPIADDR));
        DWORD oldp;
        ret = tempstore.NtProtectVirtualMemory((HANDLE)-1, &addr, &sz, PAGE_READONLY, &oldp);
        if (ret)
            return ret;
        *PretValue = ~addr;
    }
    
    if(1)
    {
        char str_createproc[16];
        *(DWORD64*)(&str_createproc) = 0x8DAF9A8B9E9A8DBC;
        *(DWORD64*)(&str_createproc[8]) = 0x2BFFA88C8C9A9C90;
        decbyte(str_createproc, 2);
        CreateProcessW_p = (CreateProcessW_pWin64)~(DWORD64)GetProcAddress_Internal(kernel32, str_createproc);
    }
    if (!CreateProcessW_p)
    {
        return 0xF2;
    }
    return 0;
}

static NTSTATUS init_API()
{
    if (init_Status)
    {
        DWORD peb = 0x60;
        DWORD err = 0;
        if (init_Status != -1)
            err = 1;
        init_Status = init_NTAPI(&peb, err, &API);
        if (init_Status)
        {
            uint16_t errmsg[32];
            *(DWORD64*)&errmsg[0] = 0x6F007200720045;
            *(DWORD64*)&errmsg[4] = 0x64006F00430072;
            *(DWORD64*)&errmsg[8] = 0x300020003A0065;
            errmsg[12] = 'x';
            {
                int i = 20;
                int bit = 0;
                uint16_t temphex;
                while (i >= 13)
                {
                    temphex = (init_Status >> bit) & 0xF;
                    if (temphex >= 0 && temphex <= 9)
                    {
                        errmsg[i] = temphex + 0x30;
                    }
                    else
                    {
                        errmsg[i] = temphex + 0x37;
                    }
                    i--;
                    bit += 4;
                }
            }
            errmsg[21] = '\n';
            errmsg[22] = 0;
            UNICODE_STRING message_str;
            UNICODE_STRING title_str;
            InitUnicodeString(&message_str, (PWSTR)errmsg);
            InitUnicodeString(&title_str, (PWSTR)L"API Init Failed!");
            ULONG_PTR params[4] = { (ULONG_PTR)&message_str, (ULONG_PTR)&title_str, ((ULONG)ResponseButtonOK | IconError), INFINITE };
            DWORD response;
            NtRaiseHardError(STATUS_SERVICE_NOTIFICATION | HARDERROR_OVERRIDE_ERRORMODE, 4, 3, params, 0, &response);
        }
    }
    return init_Status;
}

#endif