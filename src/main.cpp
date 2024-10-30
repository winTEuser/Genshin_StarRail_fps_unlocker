#define KEY_TOGGLE VK_END
#define KEY_INCREASE VK_UP
#define KEY_INCREASE_SMALL VK_RIGHT
#define KEY_DECREASE VK_DOWN
#define KEY_DECREASE_SMALL VK_LEFT
#define FPS_TARGET 120
#define DEFAULT_DEVICE 2
#define CONFIG_FILENAME L"hoyofps_config.ini"
#define IsKeyPressed(nVirtKey)    ((GetKeyState(nVirtKey) & (1<<(sizeof(SHORT)*8-1))) != 0)

#include <Windows.h>
#include <TlHelp32.h>
#include <stdlib.h>
#include <vector>
#include <string>
#include <thread>
#include <Psapi.h>
#include <iostream>
#include <locale>
#include <codecvt>
#include <iomanip>
#include <locale.h>
#include "inireader.h"

#ifndef _WIN64
#error you must build in Win x64
#endif

using namespace std;

wstring HKSRGamePath{};
wstring GenGamePath{};
wstring GamePath{};
uint32_t FpsValue = FPS_TARGET;
uint32_t Tar_Device = DEFAULT_DEVICE;
uint32_t Target_set_60 = 1000;
uint32_t Target_set_30 = 60;
BYTE isGenshin = 1;
bool Use_mobile_UI = 0;
bool _main_state = 1;
BYTE Process_endstate = 0; 
bool ErrorMsg_EN = 1;
bool isHook = 0;
bool is_old_version = 0;
BYTE isAntimiss = 2;
HWND _console_HWND = 0;
BYTE ConfigPriorityClass = 1;
uint32_t GamePriorityClass = NORMAL_PRIORITY_CLASS;


const BYTE _shellcode_Const[] =
{
    0x00, 0x00, 0x00, 0x00,                         //uint32_t unlocker_pid              _shellcode_[0]
    0x80, 0xBB, 0x20, 0x67,                         //uint32_t timestamp                 _shellcode_[4]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //uint64_t unlocker_FpsValue_addr    _shellcode_[8]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //uint64_t API_OpenProcess           _shellcode_[0x10]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //uint64_t API_ReadProcessmem        _shellcode_[0x16]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //uint64_t API_Sleep                 _shellcode_[0x20]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //uint64_t API_MessageBoxA           _shellcode_[0x28]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //uint64_t API_CloseHandle           _shellcode_[0x30]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //uint64_t Ptr_il2cpp_fps            _shellcode_[0x38]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //uint64_t Ptr_Engine_fps            _shellcode_[0x40]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //FREE
    //int3
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    //int3
    0x48, 0x83, 0xEC, 0x38,                         //sub rsp,0x38                       _shellcode_[0x60] _sync_thread
    0x8B, 0x05, 0x96, 0xFF, 0xFF, 0xFF,             //mov eax,dword[unlocker_pid]
    0x85, 0xC0,                                     //test eax, eax
    0x74, 0x7A,                                     //jz return
    0x41, 0x89, 0xC0,                               //mov r8d, eax
    0x33, 0xD2,                                     //xor edx, edx
    0xB9, 0xFF, 0xFF, 0x1F, 0x00,                   //mov ecx,1FFFFF
    0xFF, 0x15, 0x92, 0xFF, 0xFF, 0xFF,             //call [API_OpenProcess]
    0x85, 0xC0,                                     //test eax, eax
    0x74, 0x66,                                     //jz return
    0x89, 0xC6,                                     //mov esi, eax
    0x44, 0x48, 0x8B, 0x3D, 0x7C, 0xFF, 0xFF, 0xFF, //mov rdi, qword[unlocker_FpsValue_addr]
    0x31, 0xDB,                                     //xor ebx, ebx 
    0x41, 0xBE, 0xF4, 0x01, 0x00, 0x00,             //mov r14d, 0x1F4        (500ms)
    0x44, 0x4C, 0x8D, 0x3D, 0x04, 0x00, 0x00, 0x00, //lea r15, qword:[Read_tar_fps]
    0x0F, 0x1F, 0x40, 0x00,                         //nop


    0x4C, 0x8D, 0x44, 0x24, 0x28,                   //lea r8, qword:[RSP+0x28]        //Read_tar_fps
    0x41, 0xB9, 0x04, 0x00, 0x00, 0x00,             //mov r9d, 0x4  
    0x48, 0x89, 0x5C, 0x24, 0x20,                   //mov qword ptr ss:[rsp+20],rbx
    0x48, 0x89, 0xFA,                               //mov rdx, rdi  
    0x2E, 0x89, 0xF1,                               //mov ecx, esi  
    0xFF, 0x15, 0x5C, 0xFF, 0xFF, 0xFF,             //call [API_ReadProcessmem]
    0x85, 0xC0,                                     //test eax, eax     
    0x75, 0x10,                                     //jnz continue   
    0x49, 0x83, 0xC7, 0x30,                         //add r15, 0x30         //控制循环范围
    0xE8, 0x67, 0x00, 0x00, 0x00,                   //call Show Errormsg and CloseHandle 
    0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00,       //nop
    //continue
    0x8B, 0x4C, 0x24, 0x28,                         //mov ecx, qword:[RSP+0x28]      
    0x48, 0xE8, 0x16, 0x00, 0x00, 0x00,             //call Sync_auto
    0x44, 0x89, 0xF1,                               //mov ecx, r14d
    0x48, 0xFF, 0x15, 0x3C, 0xFF, 0xFF, 0xFF,             //call [API_Sleep]
    0x41, 0xFF, 0xE7,                               //jmp r15
    //int3
    0xCC, 
    //return
    0x48, 0x83, 0xC4, 0x38,                         //add rsp,0x38 
    0xC3,                                           //ret  
    //int3 
    0xCC, 0xCC, 0xCC,
    //int3
    0x44, 0x48, 0x8B, 0x05, 0x40, 0xFF, 0xFF, 0xFF, //mov  rax, qword ptr ds:[il2cpp_fps]
    0x48, 0x85, 0xC0,                               //test rax, rax
    0x74, 0x1B,                                     //jz Write
    //read_game_set                                 
    0x2E, 0x8B, 0x00,                               //mov eax, qword ptr ss:[rax]
    0x83, 0xF8, 0x1E,                               //cmp eax, 0x1E 
    0x74, 0x0D,                                     //je set 60
    0x83, 0xF8, 0x2D,                               //cmp eax, 0x2D
    0x74, 0x0E,                                     //je Sync_unlocker
    0x2E, 0xB9, 0xE8, 0x03, 0x00, 0x00,             //mov ecx, 0x3E8                    
    0xEB, 0x06,                                     //jmp Write
    0x2E, 0xB9, 0x3C, 0x00, 0x00, 0x00,             //mov ecx, 0x3C              
    //Write                                         
    0x44, 0x48, 0x8B, 0x05, 0x20, 0xFF, 0xFF, 0xFF, //mov rax, qword ptr ds:[engine_fps]
    0x89, 0x08,                                     //mov dword ptr ds:[rax], ecx  
    0xC3,                                           //ret 
    //int3
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    //int3
    0x48, 0x83, 0xEC, 0x28,                         //sub rsp, 0x28                        //Show Errormsg and closehandle
    0x31, 0xC9,                                     //xor ecx, ecx 
    0x48, 0x8D, 0x15, 0x23, 0x00, 0x00, 0x00,       //lea rdx, qword:["Sync failed!"]
    0x4C, 0x8D, 0x05, 0x2C, 0x00, 0x00, 0x00,       //lea r8, qword:["Error"]
    0x41, 0xB9, 0x10, 0x00, 0x00, 0x00,             //mov r9d, 0x10 
    0xFF, 0x15, 0xD8, 0xFE, 0xFF, 0xFF,             //call [API_MessageBoxA] 
    0x89, 0xF1,                                     //mov ecx, esi 
    0xFF, 0x15, 0xD8, 0xFE, 0xFF, 0xFF,             //call [API_CloseHandle] 
    0x48, 0x83, 0xC4, 0x28,                         //add rsp, 0x28
    0xC3,                                           //ret 
    //int3
    0xCC, 0xCC, 0xCC, 
    'S','y','n','c',' ','f','a','i','l','e','d','!', 0x00, 0x00, 0x00, 0x00,
    'E','r','r','o','r', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,             //uint32_t Readmem_buffer  
    0x00, 0x00, 0x00, 0x00,             //FREE
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

const BYTE _shellcode_ui_set_Const[] =
{
    0x00, 0x00, 0x00, 0x00,                         //uint32_t target_device    _shellcode_[0]
    0x0A, 0xC7, 0x1C, 0x67,                         //uint32_t timestamp        _shellcode_[4]
    0x00, 0x00, 0x00, 0x00,                         //uint32_t ptrRVA           _shellcode_[0x8]
    0x00, 0x00, 0x00, 0x00,                         //uint32_t free             _shellcode_[0xC]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //uint64_t API_getmodA      _shellcode_[0x10]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //uint64_t free             _shellcode_[0x16]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //uint64_t API_Sleep        _shellcode_[0x20]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //uint64_t free             _shellcode_[0x28]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //uint64_t free             _shellcode_[0x30]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //uint64_t free             _shellcode_[0x38]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //uint64_t FREE             _shellcode_[0x40]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //FREE
    //int3
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    //int3
    0x48, 0x83, 0xEC, 0x38,                              //sub rsp,0x38                       _shellcode_[0x60] _sync_thread
    0x44, 0x48, 0x8D, 0x1D, 0x4C, 0x00, 0x00, 0x00,      //lea rbx, qword[il2cppbase]
    0xBE, 0xF4, 0x01, 0x00, 0x00,                        //mov esi, 0x1F4  (500ms)
    //a
    0x48, 0x89, 0xD9,                                    //mov rcx, rbx
    0xFF, 0x15, 0x96, 0xFF, 0xFF, 0xFF,                  //call [API_getmodA]
    0x48, 0x85, 0xC0,                                    //test rax, rax
    0x75, 0x0B,                                          //jne continue
    0x90, 
    0x89, 0xF1,                                          //mov ecx, esi
    0xFF, 0x15, 0x98, 0xFF, 0xFF, 0xFF,                  //call [API_Sleep]
    0xEB, 0xE7,                                          //jmp a
    //continue
    0x8B, 0x1D, 0x78, 0xFF, 0xFF, 0xFF,                  //mov esi, dword[ptrRVA]
    0x85, 0xDB,                                          //test ebx, ebx 
    0x74, 0x18,                                          //je return
    0x48, 0x8D, 0x3C, 0x18,                              //lea rdi, [rax+rbx]
    0x48, 0x90,                                          //nop
    0x8B, 0x1D, 0x60, 0xFF, 0xFF, 0xFF,                  //mov esi, dword[device]
    //b
    0x89, 0x1F,                                          //mov dword[rdi], ebx
    0x89, 0xF1,                                          //mov ecx, esi
    0xFF, 0x15, 0x76, 0xFF, 0xFF, 0xFF,                  //call [API_Sleep]
    0xEB, 0xF4,                                          //jmp b
    //return                                             
    0x48, 0x83, 0xC4, 0x38,                              //add rsp,0x38 
    0xC3,                                                //ret  
    //int3 
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 
    'g','a','m','e','a','s','s','e','m','b','l','y','.','d','l','l',0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00

};


// 特征搜索
static uintptr_t PatternScan_Region(uintptr_t startAddress, size_t regionSize, const char* signature)
{
    auto pattern_to_byte = [](const char* pattern)
        {
            std::vector<int> bytes;
            const char* start = pattern;
            const char* end = pattern + strlen(pattern);

            for (const char* current = start; current < end; ++current) {
                if (*current == '?') {
                    ++current;
                    if (*current == '?')
                        ++current;
                    bytes.push_back(-1);
                }
                else {
                    bytes.push_back(strtoul(current, const_cast<char**>(&current), 16));
                }
            }
            return bytes;
        };

    std::vector<int> patternBytes = pattern_to_byte(signature);
    auto scanBytes = reinterpret_cast<std::uint8_t*>(startAddress);

    for (size_t i = 0; i < regionSize - patternBytes.size(); ++i)
    {
        bool found = true;
        for (size_t j = 0; j < patternBytes.size(); ++j) {
            if (scanBytes[i + j] != patternBytes[j] && patternBytes[j] != -1) {
                found = false;
                break;
            }
        }
        if (found) {
            return (uintptr_t)&scanBytes[i];
        }
    }
    return 0;
}


static std::wstring GetLastErrorAsString(DWORD code)
{
    LPWSTR buf = nullptr;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&buf, 0, NULL);
    std::wstring ret = buf;
    LocalFree(buf);
    return ret;
}


static std::wstring* NewWideString(size_t Str_size)
{
    std::wstring wtemp = L"";
    std::wstring* wcsptr= (wstring*)malloc(sizeof(wstring));
    if (!wcsptr)
        return 0;
    memcpy(wcsptr, &wtemp, sizeof(wstring));
    *(uintptr_t*)wcsptr = (uintptr_t)malloc(Str_size);
    if (*(uintptr_t*)wcsptr == 0)
        return 0;
    **(wchar_t**)wcsptr = 0;
    return wcsptr;
}


inline static void DeleteWideSting(std::wstring** str)
{
    free(**(wchar_t***)str);
    free(*str);
    *(uintptr_t*)str = 0;
}


inline static void clean_buffer(uint64_t* destptr, size_t size)
{
    size /= 8;
    while (size--)
    {
        *(destptr + size) = 0;
    }
}

//Throw error msgbox
static void Show_Error_Msg(LPCWSTR Prompt_str)
{
    if (ErrorMsg_EN == 0)
        return;
    uint32_t Error_code = GetLastError();
    if (Error_code == ERROR_SUCCESS)
        Error_code = ERROR_INVALID_DATA;
    wstring message{};
    if (Prompt_str)
        message = Prompt_str;
    else
        message = L"Default Error Message";
    message += L"\n" + GetLastErrorAsString(Error_code);
    MessageBoxW(_console_HWND, *(LPCWSTR*)&message, L"An Error has occurred!", 0x10);
    return;
}

// 获取目标进程DLL信息
static bool GetModule(DWORD pid, const wchar_t* ModuleName, PMODULEENTRY32W pEntry)
{
    if (!pEntry)
        return false;

    pEntry->dwSize = sizeof(MODULEENTRY32W);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    bool temp = Module32FirstW(snap, pEntry);
    if (temp)
    {
        do
        {
            if (pEntry->th32ProcessID != pid)
                continue;
            if (wcstrcmp0(pEntry->szModule, ModuleName))
            {
                CloseHandle(snap);
                return 1;
            }

        } while (Module32NextW(snap, pEntry));

    }
    CloseHandle(snap);
    return 0;
}


static bool Get_Section_info(LPVOID PE_buffer, LPCSTR Name_sec, uint32_t* Sec_Vsize, uintptr_t* Sec_Remote_RVA, uintptr_t Remote_BaseAddr)
{
    if ((!PE_buffer) || (!Name_sec) || (!Sec_Vsize) || (!Sec_Remote_RVA))
        return 0;
    uint64_t tar_sec = *(uint64_t*)Name_sec;//max 8 byte
    uintptr_t WinPEfileVA = *(uintptr_t*)(&PE_buffer)+0x3c; //dos_header
    uintptr_t PEfptr = *(uintptr_t*)(&PE_buffer)+*(uint32_t*)WinPEfileVA; //get_winPE_VA
    _IMAGE_NT_HEADERS64* _FilePE_Nt_header = (_IMAGE_NT_HEADERS64*)PEfptr;
    _IMAGE_SECTION_HEADER _sec_temp{};
    if (_FilePE_Nt_header->Signature == 0x00004550)
    {
        DWORD sec_num = _FilePE_Nt_header->FileHeader.NumberOfSections;//获得指定节段参数
        sec_num++;
        DWORD num = sec_num;
        DWORD target_sec_VA_start = 0;
        do
        {
            _sec_temp = *(_IMAGE_SECTION_HEADER*)(PEfptr + 264 + (40 * (static_cast<unsigned long long>(sec_num) - num)));

            if (*(uint64_t*)(_sec_temp.Name) == tar_sec)
            {
                target_sec_VA_start = _sec_temp.VirtualAddress;
                *Sec_Vsize = _sec_temp.Misc.VirtualSize;
                *Sec_Remote_RVA = Remote_BaseAddr + target_sec_VA_start;
                return 1;
            }
            num--;

        } while (num);

        return 0;
    }
    return 0;
}

// 通过进程名搜索进程ID
static DWORD GetPID(const wchar_t* ProcessName)
{
    DWORD pid = 0;
    PROCESSENTRY32 pe32{};
    pe32.dwSize = sizeof(pe32);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    for (Process32FirstW(snap, &pe32); Process32NextW(snap, &pe32);)
    {
        if (wcstrcmp0(pe32.szExeFile, ProcessName))
        {
            pid = pe32.th32ProcessID;
            break;
        }
    }
    CloseHandle(snap);
    return pid;
}


static bool WriteConfig(int fps)
{
    HANDLE hFile = CreateFileW(CONFIG_FILENAME, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_HIDDEN, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        Show_Error_Msg(L"CreateFile failed! (config)");
        return false;
    }
    wstring content;
    content.reserve(0x1000);
    content = L"[Setting]\n";
    content += L"GenshinPath=" + GenGamePath + L"\n";
    content += L"HKSRPath=" + HKSRGamePath + L"\n";
    content += L"IsAntiMisscontact=" + std::to_wstring(isAntimiss) + L"\n";
    content += L"TargetDevice=" + std::to_wstring(Tar_Device) + L"\n";
    content += L"IsHookGameSet=" + std::to_wstring(isHook) + L"\n";
    content += L"GSTarget60=" + std::to_wstring(Target_set_60) + L"\n";
    content += L"GSTarget30=" + std::to_wstring(Target_set_30) + L"\n";
    content += L"EnableErrorMsg=" + std::to_wstring(ErrorMsg_EN) + L"\n";
    content += L"GameProcessPriority=" + std::to_wstring(ConfigPriorityClass) + L"\n";
    content += L"FPS=" + std::to_wstring(fps) + L"\n";

    DWORD written = 0;
    bool re = WriteFile(hFile, content.data(), content.size()*2, &written, nullptr);
    CloseHandle(hFile);
    return re;
}


static bool LoadConfig()
{
    
    INIReader reader(CONFIG_FILENAME);
    if (reader.ParseError() != 0)
    {
        wprintf_s(L" Config Not Found !\n 配置文件未发现\n Don't close unlocker and open the game \n 不要关闭解锁器,并打开游戏\n Wait for game start ......\n 等待游戏启动.....\n");

_no_config:
        DWORD pid = 0;
        while (1)
        {
            if (isGenshin)
            {
                if ((pid = GetPID(L"YuanShen.exe")) || (pid = GetPID(L"GenshinImpact.exe")))
                    break;
            }
            else 
            {
                if (pid = GetPID(L"StarRail.exe"))
                    break;
            }
            Sleep(200);
        }
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE | PROCESS_TERMINATE, FALSE, pid);
        if (!hProcess)
        {
            Show_Error_Msg(L"OpenProcess failed! (Get game path)");
            return 0;
        }

        // 获取进程句柄 - 这权限很低的了 - 不应该获取不了
        // PROCESS_QUERY_LIMITED_INFORMATION - 用于查询进程路经 (K32GetModuleFileNameExA)
        // SYNCHRONIZE - 用于等待进程结束 (WaitForSingleObject)

        DWORD length = 0x1000;
        wchar_t* szPath = (wchar_t*)VirtualAlloc(NULL, length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if(!szPath)
        {
            Show_Error_Msg(L"Alloc Memory failed! (Get game path)");
            return 0;
        }
        QueryFullProcessImageNameW(hProcess, 0, szPath, &length);

        if (isGenshin) 
        {
            GenGamePath = szPath;
        }
        else 
        {
            HKSRGamePath = szPath;
        }
        GamePath = szPath;

        VirtualFree(szPath, 0, MEM_RELEASE);

        DWORD ExitCode = STILL_ACTIVE;
        while (ExitCode == STILL_ACTIVE)
        {
            TerminateProcess(hProcess, 0);
            Sleep(500);
            GetExitCodeProcess(hProcess, &ExitCode);
        }

        // wait for the game to close then continue
        WaitForSingleObject(hProcess, (int) - 1);
        CloseHandle(hProcess);
        system("cls");
        goto __path_ok;
    }

    HKSRGamePath = reader.Get(L"Setting", L"HKSRPath", HKSRGamePath);
    GenGamePath = reader.Get(L"Setting", L"GenshinPath", GenGamePath);
    if (isGenshin)
    {
        GamePath = GenGamePath;
        if (GetFileAttributesW(GamePath.c_str()) == INVALID_FILE_ATTRIBUTES)
        {
            wprintf_s(L" Genshin Path Error!\n Plase open Genshin to set game path.\n 路径错误，请手动打开原神来设置游戏路径 \n");
            goto _no_config;
        }
    }
    else
    {
        GamePath = HKSRGamePath;
        if (GetFileAttributesW(GamePath.c_str()) == INVALID_FILE_ATTRIBUTES)
        {
            wprintf_s(L" HKSR Path Error!\n Plase open StarRail to set game path.\n 路径错误，请手动打开崩铁来设置游戏路径 \n");
            goto _no_config;
        }   
    }

__path_ok:
    isAntimiss = reader.GetInteger(L"Setting", L"IsAntiMisscontact", 2);
    if (isAntimiss == 2)
    {
        int _msgbox_set = MessageBoxW(_console_HWND, L"Is set Anti-miscontact(Console window must be selected to set Fps) ? \n 是否开启防误触(只有选中解锁器窗口才可调节帧率)\n\n", L"Setting", 0x24);
        if (_msgbox_set == 6)
            isAntimiss = 1;
        if (_msgbox_set == 7)
            isAntimiss = 0;
    }
    Target_set_30 = reader.GetInteger(L"Setting", L"GSTarget30", 60);
    Target_set_60 = reader.GetInteger(L"Setting", L"GSTarget60", 1000);
    ErrorMsg_EN = reader.GetBoolean(L"Setting", L"EnableErrorMsg", 1);
    isHook = reader.GetBoolean(L"Setting", L"IsHookGameSet", 0);
    Tar_Device = reader.GetInteger(L"Setting", L"TargetDevice", 2);
    if (Tar_Device > 0x20)
        Tar_Device = 2;
    ConfigPriorityClass = reader.GetInteger(L"Setting", L"GameProcessPriority", 3);
    switch (ConfigPriorityClass)
    {
    case 0 :
        GamePriorityClass = REALTIME_PRIORITY_CLASS;
        break;
    case 1 :
        GamePriorityClass = HIGH_PRIORITY_CLASS;
        break;
    case 2:
        GamePriorityClass = ABOVE_NORMAL_PRIORITY_CLASS;
        break;
    case 3:
        GamePriorityClass = NORMAL_PRIORITY_CLASS; 
        break;
    case 4:
        GamePriorityClass = BELOW_NORMAL_PRIORITY_CLASS;
        break;
    default:
        ConfigPriorityClass = 3;
        GamePriorityClass = NORMAL_PRIORITY_CLASS;
        break;
    }
    FpsValue = reader.GetInteger(L"Setting", L"FPS", FPS_TARGET);
    WriteConfig(FpsValue);
    
    return 1;
}


static bool Init_Game_boot_arg(LPWSTR CommandLinew)
{
    if (!CommandLinew)
    {
        Show_Error_Msg(L"null ptr exception in init commandline");
        return 0;
    }
    *(wchar_t*)CommandLinew = 0;
    int argNum = 0;
    LPWSTR* argvW = CommandLineToArgvW(::GetCommandLineW(), &argNum);
    std::wstring CommandLine{};
    if (argNum >= 2)
    {
        int _game_argc_start = 0;
        std::wstring boot_genshin(L"-Genshin");
        std::wstring boot_starrail(L"-HKSR");
        std::wstring Use_Mobile_UI(L"-EnableMobileUI");

        if (argvW[1] == boot_genshin)
        {
            printf_s("This console control GenshinFPS\n");
            SetConsoleTitleA("GenshinNow");

            if (argNum > 2)
            {
                if (argvW[2] == Use_Mobile_UI)
                {
                    Use_mobile_UI = 1;
                    CommandLine += L" use_mobile_platform -is_cloud 1 -platform_type CLOUD_THIRD_PARTY_MOBILE ";
                    _game_argc_start = 3;
                }
                else { _game_argc_start = 2; }
                for (int i = _game_argc_start; i < argNum; i++)
                {
                    CommandLine += argvW[i] + std::wstring(L" ");
                }
            }

        }
        else if (argvW[1] == boot_starrail)
        {
            isGenshin = 0;
            printf_s("This console control HKStarRailFPS\n");
            SetConsoleTitleA("StarRailNow");
            if (argNum > 2)
            {
                if (argvW[2] == Use_Mobile_UI)
                {
                    Use_mobile_UI = 1;
                    _game_argc_start = 3;
                }
                else { _game_argc_start = 2; }
                for (int i = _game_argc_start; i < argNum; i++)
                {
                    CommandLine += argvW[i] + std::wstring(L" ");
                }
            }
        }
        else
        {
            MessageBoxW(_console_HWND, L"参数错误 \nArguments error ( unlocker.exe -[game] -[game argv] -..... ) \n", L"Tip", 0x10);
            return 0;
        }

    }else
    {
        int gtype = MessageBoxW(_console_HWND, L"Genshin click yes ,StarRail click no ,Cancel to Quit \n启动原神选是，崩铁选否，取消退出 \n", L"GameSelect ", 0x23);
        if (gtype == 2)
        {
            return 0;
        }
        if (gtype == 6)
        {
            printf_s("This console control GenshinFPS\n");
            SetConsoleTitleA("GenshinNow");
        }
        if (gtype == 7)
        {
            isGenshin = 0;
            printf_s("This console control HKStarRailFPS\n");
            SetConsoleTitleA("StarRailNow");
        }
    }
    strncpy0(CommandLinew, CommandLine.c_str(),CommandLine.size()*2);
    return 1;
}

// Hotpatch                         
static DWORD64 inject_patch(LPVOID text_buffer, uint32_t text_size, uintptr_t _text_baseaddr, uintptr_t _ptr_fps, HANDLE Tar_handle)
{
    if ((!text_buffer) || (!text_size) || (!_text_baseaddr) || (!_ptr_fps) || (!Tar_handle))
        return 0;

    DWORD64 Module_TarSec_RVA = (DWORD64)text_buffer;
    DWORD Module_TarSec_Size = text_size;

    DWORD64 address = 0;

    uintptr_t _shellcode_buffer = (uintptr_t)VirtualAlloc(0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (_shellcode_buffer == 0)
    {
        Show_Error_Msg(L"Buffer Alloc Fail! \n");
        return 0;
    }
    memcpy((void*)_shellcode_buffer, &_shellcode_Const, sizeof(_shellcode_Const));
    DWORD64 _Ptr_il2cpp_setting_fps = 0;

    if (!isGenshin)
    {
        while (address = PatternScan_Region(Module_TarSec_RVA, Module_TarSec_Size, "CC 89 0D ?? ?? ?? ?? E9 ?? ?? ?? ?? CC CC CC CC CC"))
        {
            uintptr_t rip = address;
            rip += 3;
            rip += *(int32_t*)(rip)+4;
            if ((rip - (uintptr_t)Module_TarSec_RVA + (uintptr_t)_text_baseaddr) == _ptr_fps)
            {
                DWORD64 Patch0_addr = address + 1;
                DWORD64 Patch0_addr_hook = Patch0_addr - (uintptr_t)Module_TarSec_RVA + (uintptr_t)_text_baseaddr;
                *(uint8_t*)Patch0_addr = 0x8B;      //mov dword ptr ds:[?????????], ecx   -->  mov ecx, dword ptr ds:[?????????]
                if (WriteProcessMemory(Tar_handle, (LPVOID)Patch0_addr_hook, (LPVOID)Patch0_addr, 0x1, 0) == 0)
                {
                    Show_Error_Msg(L"Write Target_Patch Fail! ");
                    return 0;
                }
                goto ___patcher;
            }
            Module_TarSec_Size = address - Module_TarSec_RVA;
            Module_TarSec_RVA = address + 12;
        }
        Show_Error_Msg(L"Get patch pattern Fail! ");
        return 0;
    }
    //genshin_get_gameset
    if (isHook)
    {
        address = PatternScan_Region(Module_TarSec_RVA, Module_TarSec_Size, "48 89 F1 E8 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? 48 8B 0D");
        if (address)
        {
            uintptr_t rip = address;
            rip += 10;
            if ((*(uint32_t*)rip) >> 31)
                rip -= uint32_t(~((*(uint32_t*)rip) + 3));
            else
                rip += uint32_t(*(int32_t*)rip) + 4;

            _Ptr_il2cpp_setting_fps = rip - Module_TarSec_RVA + _text_baseaddr;
        }
        else isHook = 0;
    }

    //shellcode patcher
___patcher:
    uint64_t _Addr_OpenProcess = (uint64_t)(&OpenProcess);
    uint64_t _Addr_ReadProcessmem = (uint64_t)(&ReadProcessMemory);
    uint64_t _Addr_Sleep = (uint64_t)(&Sleep);
    uint64_t _Addr_MessageBoxA = (uint64_t)(&MessageBoxA);
    uint64_t _Addr_CloseHandle = (uint64_t)(&CloseHandle);
    *(uint32_t*)_shellcode_buffer = GetCurrentProcessId();       //unlocker PID
    *(uint64_t*)(_shellcode_buffer + 0x8) = (uint64_t)(&FpsValue); //source ptr
    *(uint64_t*)(_shellcode_buffer + 0x10) = _Addr_OpenProcess;
    *(uint64_t*)(_shellcode_buffer + 0x18) = _Addr_ReadProcessmem;
    *(uint64_t*)(_shellcode_buffer + 0x20) = _Addr_Sleep;
    *(uint64_t*)(_shellcode_buffer + 0x28) = _Addr_MessageBoxA;
    *(uint64_t*)(_shellcode_buffer + 0x30) = _Addr_CloseHandle;
    *(uint64_t*)(_shellcode_buffer + 0x40) = _ptr_fps;
    if (isHook)
    {
        *(uint32_t*)(_shellcode_buffer + 0x10C) = Target_set_60;
        *(uint32_t*)(_shellcode_buffer + 0x114) = Target_set_30;
        *(uint64_t*)(_shellcode_buffer + 0x38) = _Ptr_il2cpp_setting_fps;
    }
    
    LPVOID __Tar_proc_buffer = VirtualAllocEx(Tar_handle, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);
    if (__Tar_proc_buffer)
    {
        if (WriteProcessMemory(Tar_handle, __Tar_proc_buffer, (void*)_shellcode_buffer, sizeof(_shellcode_Const), 0))
        {
            VirtualFree((void*)_shellcode_buffer, 0, MEM_RELEASE);
            
            HANDLE temp = CreateRemoteThread(Tar_handle, 0, 0, (LPTHREAD_START_ROUTINE)((uint64_t)__Tar_proc_buffer + 0x60), 0, 0, 0);
            if (temp)
                CloseHandle(temp);
            else 
            {
                Show_Error_Msg(L"Create InGame SyncThread Fail! ");
                return 0; 
            }
            return ((uint64_t)__Tar_proc_buffer);
        }
        Show_Error_Msg(L"Inject shellcode Fail! ");
        VirtualFree((void*)_shellcode_buffer, 0, MEM_RELEASE);
        return 0;
    }
    else 
    {
        Show_Error_Msg(L"Alloc shellcode space Fail! ");
        return 0;
    }
}

//for StarRail
static bool Hksr_ENmobile(LPCWSTR GPath, HANDLE Gamehandle)
{
    wstring path = GPath;
    path += L"\\GameAssembly.dll";
    uintptr_t il2cpp_base = (uintptr_t)LoadLibraryW(path.c_str());
    if (!il2cpp_base)
    {
        Show_Error_Msg(L"load GameAssembly.dll Failed !\n");
        return 0;
    }
    
    LPVOID GameAssembly_PEbuffer = (void*)il2cpp_base;

    uintptr_t Ua_il2cpp_RVA = 0;
    DWORD32 Ua_il2cpp_Vsize = 0;
    if (Get_Section_info(GameAssembly_PEbuffer, "il2cpp", &Ua_il2cpp_Vsize, &Ua_il2cpp_RVA, (uintptr_t)GameAssembly_PEbuffer))
    {
        if (Ua_il2cpp_RVA && Ua_il2cpp_Vsize)
        {
            //80 B9 ?? ?? ?? ?? 00 74 46 C7 05 ?? ?? ?? ?? 03 00 00 00 48 83 C4 20 5E C3       //HKSR_2.4.0 - 2.5.0
            //      75 05 E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 03 00 00 00 48 83 C4 28 C3          //old-x-x-x--2.6.0
            DWORD Device_type = Tar_Device;
            DWORD64 tar_addr;
            bool is_new_ver = 1;
            DWORD64 address = 0;
            if (address = PatternScan_Region((uintptr_t)Ua_il2cpp_RVA, Ua_il2cpp_Vsize, "75 05 E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 03 00 00 00 48 83 C4 28 C3"))
            {
                tar_addr = address + 9;
                is_new_ver = 0;
            }
            else if (address = PatternScan_Region((uintptr_t)Ua_il2cpp_RVA, Ua_il2cpp_Vsize, "80 B9 ?? ?? ?? ?? 00 74 46 C7 05 ?? ?? ?? ?? 03 00 00 00 48 83 C4 20 5E C3"))
            {
                tar_addr = address + 11;
            }
            else
            {
                Show_Error_Msg(L"UI pattern outdate!");
                FreeLibrary((HMODULE)il2cpp_base);
                return 0;
            }
            int64_t rip = tar_addr;
            rip += *(int32_t*)rip;
            rip += 8;
            {//patcher
                uintptr_t _shellcode_buffer = (uintptr_t)VirtualAlloc(0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (_shellcode_buffer == 0)
                {
                    Show_Error_Msg(L"Buffer Alloc Fail! (UI)\n");
                    return 0;
                }
                memcpy((void*)_shellcode_buffer, &_shellcode_ui_set_Const, sizeof(_shellcode_ui_set_Const));
                uint64_t _Ptr_RVA_setting_ui = rip - il2cpp_base;

                *(uint32_t*)_shellcode_buffer = Device_type;
                *(uint64_t*)(_shellcode_buffer + 0x8) = _Ptr_RVA_setting_ui;
                *(uint64_t*)(_shellcode_buffer + 0x10) = (uint64_t)(&GetModuleHandleA);
                *(uint64_t*)(_shellcode_buffer + 0x20) = (uint64_t)(&Sleep);
                LPVOID __Tar_proc_buffer = VirtualAllocEx(Gamehandle, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);
                if (__Tar_proc_buffer)
                {
                    if (WriteProcessMemory(Gamehandle, __Tar_proc_buffer, (void*)_shellcode_buffer, sizeof(_shellcode_ui_set_Const), 0))
                    {
                        VirtualFree((void*)_shellcode_buffer, 0, MEM_RELEASE);

                        HANDLE temp = CreateRemoteThread(Gamehandle, 0, 0, (LPTHREAD_START_ROUTINE)((uint64_t)__Tar_proc_buffer + 0x60), 0, 0, 0);
                        if (temp)
                        {
                            CloseHandle(temp);
                            VirtualFree((void*)_shellcode_buffer, 0, MEM_RELEASE);
                            FreeLibrary((HMODULE)il2cpp_base);
                            return 1;
                        }
                        else
                        {
                            Show_Error_Msg(L"Create InGame Thread Fail! ");
                            VirtualFree((void*)_shellcode_buffer, 0, MEM_RELEASE);
                        }
                    }
                    else
                    {
                        Show_Error_Msg(L"Inject shellcode Fail! ");
                        VirtualFree((void*)_shellcode_buffer, 0, MEM_RELEASE);
                    }
                }
                else
                {
                    Show_Error_Msg(L"Alloc shellcode space Fail! ");
                }
            }
            FreeLibrary((HMODULE)il2cpp_base);
            return 0;
        }
    }
    Show_Error_Msg(L"get Section info Error !\n");
    FreeLibrary((HMODULE)il2cpp_base);
    return 0;
   
}

//For choose suspend
static DWORD __stdcall Thread_display(LPVOID null)
{
    while (1)
    {
    __fresh_state:
        Sleep(100);
        if (Process_endstate)
            break;
        printf_s("\rFPS: %d - %s    %s", FpsValue, FpsValue < 30 ? "Low power state" : "Normal state   ", "  Press END key stop change  ");
    }
    Process_endstate--;
    return 0;
}

// 禁用控制台滚动 disable console text roll
static void FullScreen() 
{
    HANDLE Hand;
    CONSOLE_SCREEN_BUFFER_INFO Info;
    Hand = GetStdHandle(STD_OUTPUT_HANDLE);
    GetConsoleScreenBufferInfo(Hand, &Info);
    SMALL_RECT rect = Info.srWindow;
    COORD size = { rect.Right + 1 ,rect.Bottom + 1 };	//定义缓冲区大小，保持缓冲区大小和屏幕大小一致即可取消边框 
    SetConsoleScreenBufferSize(Hand, size);
}


int main(/*int argc, char** argvA*/void)
{
    setlocale(LC_CTYPE, "");
    SetConsoleTitleA("HoyoGameFPSunlocker");
    
    _console_HWND = GetConsoleWindow();
    if (_console_HWND == NULL)
    {
        Show_Error_Msg(L"Get Console HWND Failed!");
    }
    FullScreen();

    LPWSTR Command_arg = (LPWSTR)malloc((size_t)0x1000);
    if (!Command_arg)
        return -1;

    if (Init_Game_boot_arg(Command_arg) == 0)
        return 0;

    if (LoadConfig() == 0)
        return 0;

    if (GamePath.length() < 8)
        return -1;

    wstring* ProcessPath = NewWideString(GamePath.size() + 0x10);
    wstring* ProcessDir = NewWideString(GamePath.size() + 0x10);
    wstring* procname = NewWideString(0x40);
    if (!ProcessPath || !ProcessDir || !procname)
    {
        Show_Error_Msg(L"malloc failed!");
        return -1;
    }
    *ProcessPath = GamePath;
    
    wprintf_s(L"FPS unlocker 2.8.1 \nThis program is Free and OpenSource in \n https://github.com/winTEuser/Genshin_StarRail_fps_unlocker \n这个程序开源免费,链接如上\n\nGamePath: %s \n", ProcessPath->c_str());
    if(isGenshin == 0)
    {
        wprintf_s(L"When V-sync is True need open setting then quit to apply change in StarRail. \n当垂直同步开启时解锁帧率需要进设置界面再退出才可应用 \n");
    }

    *ProcessDir = ProcessPath->substr(0, ProcessPath->find_last_of(L"\\"));
    *procname = ProcessPath->substr(ProcessPath->find_last_of(L"\\") + 1);
    if(isGenshin)
    {
        DWORD lSize;
        DWORD64 Size = 0;
        HANDLE file_Handle = CreateFileW(ProcessPath->c_str(), GENERIC_ALL, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if(file_Handle)
        {
            lSize = GetFileSize(file_Handle, (LPDWORD)(&Size));
            Size = (Size << 32) | lSize;
            if (Size < 0x800000)
                is_old_version = 1;
            else is_old_version = 0;
            CloseHandle(file_Handle);
        }
        else 
        {
            Show_Error_Msg(L"OpenFile Fail !");
        }
    }
_wait_process_close:
    DWORD pid = GetPID(procname->c_str());
    if (pid)
    {
        int state = MessageBoxW(NULL, L"Game has being running! \n游戏已在运行！\nYou can click Yes to auto close game or click Cancel to manually close. \n点击确定自动关闭游戏或手动关闭游戏后点取消\n", L"Error", 0x11);
        if (state == 1)
        {
            HANDLE tempHandle = OpenProcess(PROCESS_TERMINATE, false, pid);
            TerminateProcess(tempHandle, 0);
            CloseHandle(tempHandle);
            Sleep(1000);
        }
        goto _wait_process_close;
    }

    STARTUPINFOW* si = (STARTUPINFOW*)malloc(sizeof(STARTUPINFOW));
    PROCESS_INFORMATION* pi = (PROCESS_INFORMATION*)malloc(sizeof(PROCESS_INFORMATION));
    if (!si || !pi)
    {
        Show_Error_Msg(L"malloc failed!");
        return -1;
    }
    clean_buffer((uintptr_t*)si, sizeof(STARTUPINFOW));
    clean_buffer((uintptr_t*)pi, sizeof(PROCESS_INFORMATION));

    if (!CreateProcessW(ProcessPath->c_str(), Command_arg, NULL, NULL, FALSE, NULL, NULL, ProcessDir->c_str(), si, pi))
    {
        Show_Error_Msg(L"CreateProcess Fail!");
        return (int)-1;
    }
    free(Command_arg);
    CloseHandle(pi->hThread);
    printf_s("PID: %d", pi->dwProcessId);

    if ((isGenshin == 0) && Use_mobile_UI)
    {
        Hksr_ENmobile(ProcessDir->c_str(), pi->hProcess);
    }

    //加载和获取模块信息
    LPVOID _mbase_PE_buffer;
    uintptr_t Text_Remote_RVA;
    uintptr_t Unityplayer_baseAddr;
    uint32_t Text_Vsize;
    {
        MODULEENTRY32W* hUnityPlayer = (MODULEENTRY32W*)malloc(sizeof(MODULEENTRY32W));

        if (isGenshin && is_old_version == 0)
        {
            DWORD times = 1000;
            while (times != 0)
            {
                if (GetModule(pi->dwProcessId, procname->c_str(), hUnityPlayer))
                {
                    goto __get_procbase_ok;
                }
                Sleep(50);
                times -= 5;
            }
            Show_Error_Msg(L"Get BaseModule time out!");
            CloseHandle(pi->hProcess);
            return (int)-1;
        }
        {
            DWORD times = 1000;
            while (!GetModule(pi->dwProcessId, L"UnityPlayer.dll", hUnityPlayer))
            {
                Sleep(50);
                times -= 5;
                if (GetModule(pi->dwProcessId, L"unityplayer.dll", hUnityPlayer))
                {
                    goto __get_procbase_ok;
                }
                if (times == 0)
                {
                    Show_Error_Msg(L"Get Unitymodule time out!");
                    CloseHandle(pi->hProcess);
                    return (int)-1;
                }
            }
        }

    __get_procbase_ok:

        _mbase_PE_buffer = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (_mbase_PE_buffer == 0)
        {
            Show_Error_Msg(L"VirtualAlloc Failed! (PE_buffer)");
            CloseHandle(pi->hProcess);
            return (int)-1;
        }
        if (hUnityPlayer->modBaseAddr == 0)
            return (int)-1;
        Unityplayer_baseAddr = (uintptr_t)hUnityPlayer->modBaseAddr;
        free(hUnityPlayer);
        if (ReadProcessMemory(pi->hProcess, (void*)Unityplayer_baseAddr, _mbase_PE_buffer, 0x1000, 0) == 0)
        {
            Show_Error_Msg(L"Readmem Failed! (PE_buffer)");
            VirtualFree(_mbase_PE_buffer, 0, MEM_RELEASE);
            CloseHandle(pi->hProcess);
            return (int)-1;
        }
        if (Get_Section_info(_mbase_PE_buffer, ".text", &Text_Vsize, &Text_Remote_RVA, Unityplayer_baseAddr))
            goto __Get_target_sec;
        Show_Error_Msg(L"Get Target Section Fail! (text)");
        VirtualFree(_mbase_PE_buffer, 0, MEM_RELEASE);
        CloseHandle(pi->hProcess);
        return (int)-1;
    }

__Get_target_sec:
    
    // 在本进程内申请代码段大小的内存 - 用于特征搜索
    LPVOID Copy_Text_VA = VirtualAlloc(0, Text_Vsize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (Copy_Text_VA == NULL)
    {
        Show_Error_Msg(L"VirtualAlloc Failed! (text)");
        CloseHandle(pi->hProcess);
        return (int)-1;
    }
    // 把整个模块读出来
    if (ReadProcessMemory(pi->hProcess, (void*)Text_Remote_RVA, Copy_Text_VA, Text_Vsize, 0) == 0)
    {
        Show_Error_Msg(L"Readmem Fail ! (text)");
        VirtualFree(Copy_Text_VA, 0, MEM_RELEASE);
        CloseHandle(pi->hProcess);
        return (int)-1;
    }

    DeleteWideSting(&ProcessPath);
    DeleteWideSting(&ProcessDir);
    DeleteWideSting(&procname);
   
    //starrail fps 66 0F 6E 05 ?? ?? ?? ?? F2 0F 10 3D ?? ?? ?? ?? 0F 5B C0
    // 
    //7F 0F 8B 05 ?? ?? ?? ?? 66 0F 6E C8 
    // 
    //7F 0E E8 ? ? ? ? 66 0F 6E C8 0F 5B C9
    //
    // 计算相对地址 (FPS)
    //
    //zzz7F 0D 66 0F 6E 0D ?? ?? ?? ?? 0F 5B C9

    uintptr_t pfps = 0;      //normal_fps_ptr
    uintptr_t address = 0;
    if (isGenshin) 
    {
        address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "7F 0E E8 ?? ?? ?? ?? 66 0F 6E C8"); // ver 3.7 - last 
        if (address)
        {
            uintptr_t rip = address;
            rip += 3;
            rip += *(int32_t*)(rip)+6;
            rip += *(int32_t*)(rip)+4;
            pfps = rip - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
            goto __offset_ok;
        }
        address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "7F 0F 8B 05 ?? ?? ?? ?? 66 0F 6E C8"); // ver old
        if (address)
        {
            uintptr_t rip = address;
            rip += 4;
            rip += *(int32_t*)(rip)+4;
            pfps = rip - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
            goto __offset_ok;
        }
        Show_Error_Msg(L"Genshin Pattern Outdated!\nPlase wait new update in github.\n\n");
        CloseHandle(pi->hProcess);
        VirtualFree(Copy_Text_VA, 0, MEM_RELEASE);
        return (int)-1;
    }
    else
    {
        address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "66 0F 6E 05 ?? ?? ?? ?? F2 0F 10 3D ?? ?? ?? ?? 0F 5B C0"); //ver 1.0 - last
        if (address)
        {
            uintptr_t rip = address;
            rip += 4;
            rip += *(int32_t*)(rip)+4;
            pfps = rip - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
            goto __offset_ok;
        }
        Show_Error_Msg(L"StarRail Pattern Outdated!\nPlase wait new update in github.\n\n");
        CloseHandle(pi->hProcess);
        VirtualFree(Copy_Text_VA, 0, MEM_RELEASE);
        return (int)-1;
    }
    //-------------------------------------------------------------------------------------------------------------------------------------------------//
    //7F 0D 66 0F 6E 0D CF A0 69 01 0F 5B C9
__offset_ok:
    
    uintptr_t Patch_ptr = 0;
    
    if (isGenshin && isHook)
    {
        uintptr_t UA_baseAddr = 0;
        if (is_old_version)
        {
            MODULEENTRY32W* hGameil2cpp = (MODULEENTRY32W*)malloc(sizeof(MODULEENTRY32W));
            DWORD times = 1000;
            while (!GetModule(pi->dwProcessId, L"UserAssembly.dll", hGameil2cpp))
            {
                Sleep(50);
                times -= 5;
                if (GetModule(pi->dwProcessId, L"userassembly.dll", hGameil2cpp))
                {
                    UA_baseAddr = (uintptr_t)hGameil2cpp->modBaseAddr;
                    if (!ReadProcessMemory(pi->hProcess, (void*)UA_baseAddr, _mbase_PE_buffer, 0x1000, 0))
                    {
                        Show_Error_Msg(L"Readmem Fail ! (il2cpp_PE)");
                        goto __procfail;
                    }
                }
                if (times == 0)
                {
                    Show_Error_Msg(L"Get il2cpp time out!");
                    goto __procfail;
                }
            }
        }
        if (Get_Section_info(_mbase_PE_buffer, "il2cpp", &Text_Vsize, &Text_Remote_RVA, UA_baseAddr))
            goto __Get_sec_ok;
        Show_Error_Msg(L"Get Section Fail! (il2cpp_GI)");
            
    __procfail:
        isHook = 0;
        goto __Continue;

    __Get_sec_ok:
        VirtualFree(Copy_Text_VA, 0, MEM_RELEASE);
        Copy_Text_VA = VirtualAlloc(0, Text_Vsize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (Copy_Text_VA == NULL)
        {
            Show_Error_Msg(L"VirtualAlloc Failed! (il2cpp_GI)");
            goto __procfail;
        }
        if (!ReadProcessMemory(pi->hProcess, (void*)Text_Remote_RVA, Copy_Text_VA, Text_Vsize, 0))
        {
            Show_Error_Msg(L"Readmem Fail ! (il2cpp_GI)");
            goto __procfail;
        }
    }
    __Continue:
    Patch_ptr = inject_patch(Copy_Text_VA, Text_Vsize, Text_Remote_RVA, pfps, pi->hProcess);//patch inject 
    if (!Patch_ptr)
    {
        Show_Error_Msg(L"Inject Fail !\n");
        return -1;
    }
    
    VirtualFree(_mbase_PE_buffer, 0, MEM_RELEASE);
    VirtualFree(Copy_Text_VA, 0, MEM_RELEASE);
    SetPriorityClass(pi->hProcess, GamePriorityClass);
  
    wprintf_s(L"\n\nDone! \n\nUse Right Ctrl Key with ↑↓←→ key to change fps limted\n使用键盘上的右Ctrl键和方向键调节帧率限制\n\n\n  Rctrl + ↑ : +20\n  Rctrl + ↓ : -20\n  Rctrl + ← : -2 \n  Rctrl + → : +2 \n\n");
    
    // 创建printf线程
    HANDLE temp = CreateThread(0, 0, Thread_display, 0, 0, 0);
    if (temp)
        CloseHandle(temp);
    else
        Show_Error_Msg(L"Create Thread <Thread_display> Error! ");

    DWORD dwExitCode = STILL_ACTIVE;
    uint32_t fps = FpsValue;
    uint32_t cycle_counter = 0;
    while (1)   // handle key input
    {
        Sleep(100);
        cycle_counter++;
        GetExitCodeProcess(pi->hProcess, &dwExitCode);
        if (dwExitCode != STILL_ACTIVE)
        {
            printf_s("\nGame Terminated !\n");
            break;
        }
        if ((FpsValue != fps) && (cycle_counter >= 16))
        {
            WriteConfig(fps);
            FpsValue = fps;
            cycle_counter = 0;
        }
        FpsValue = fps;   //Sync_with_ingame_thread
        if ((GetForegroundWindow() != _console_HWND) && (isAntimiss == 1))
        {
            continue;
        }
        if (GetAsyncKeyState(KEY_DECREASE) & 1 && GetAsyncKeyState(VK_RCONTROL) & 0x8000)
        {
            fps -= 20;
        }
        if (GetAsyncKeyState(KEY_DECREASE_SMALL) & 1 && GetAsyncKeyState(VK_RCONTROL) & 0x8000)
        {
            fps -= 2;
        }
        if (GetAsyncKeyState(KEY_INCREASE) & 1 && GetAsyncKeyState(VK_RCONTROL) & 0x8000)
        {
            fps += 20;
        }
        if (GetAsyncKeyState(KEY_INCREASE_SMALL) & 1 && GetAsyncKeyState(VK_RCONTROL) & 0x8000)
        {
            fps += 2;
        }
        if (fps <= 10)
        {
            fps = 10;
        }
    }
    CloseHandle(pi->hProcess);
    free(pi);
    Process_endstate++;
    while (Process_endstate)
    {
        Sleep(100);
    }
   
    return 1;
}





