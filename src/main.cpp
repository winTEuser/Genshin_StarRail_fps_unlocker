#define KEY_TOGGLE VK_END
#define KEY_INCREASE VK_UP
#define KEY_INCREASE_SMALL VK_RIGHT
#define KEY_DECREASE VK_DOWN
#define KEY_DECREASE_SMALL VK_LEFT
#define FPS_TARGET 120
#define DEFAULT_DEVICE 8 
#define CONFIG_FILENAME (L"hoyofps_config.ini")
#define IsKeyPressed(nVirtKey)    ((GetKeyState(nVirtKey) & (1<<(sizeof(SHORT)*8-1))) != 0)

#include <iostream>
#include <vector>
#include <string>
#include <locale.h>
#include <intrin.h>
#include "NTSYSAPI.h"

#include <Windows.h>
#include <TlHelp32.h>

#include "fastmemcp.h"
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
bool isGenshin = 1;
bool Use_mobile_UI = 0;
bool _main_state = 1;
bool Process_endstate = 0;
bool ErrorMsg_EN = 1;
bool isHook = 0;
bool is_old_version = 0;
bool isAntimiss = 1;
bool AutoExit = 0;
HWND _console_HWND = 0;
BYTE ConfigPriorityClass = 1;
uint32_t GamePriorityClass = NORMAL_PRIORITY_CLASS;


const DECLSPEC_ALIGN(32) BYTE _shellcode_Const[] =
{
    0x00, 0x00, 0x00, 0x00,                              //uint32_t unlocker_pid              _shellcode_[0]
    0xC0, 0x35, 0xDE, 0x67,                              //uint32_t timestamp                 _shellcode_[4]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,      //uint64_t unlocker_FpsValue_addr    _shellcode_[8]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,      //uint64_t Ptr_il2cpp_fps            _shellcode_[0x10]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,      //uint64_t Ptr_Engine_fps            _shellcode_[0x18]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,      //uint64_t hksr_ui_ptr               _shellcode_[0x20]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,      //uint64_t hksr_ui_type              _shellcode_[0x28]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,      //uint64_t Ptr_Function_link         _shellcode_[0x30]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,      //uint64_t NULL                      _shellcode_[0x38]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,      //uint64_t API_OpenProcess           _shellcode_[0x40]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,      //uint64_t API_ReadProcessmem        _shellcode_[0x48]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,      //uint64_t API_Sleep                 _shellcode_[0x50]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,      //uint64_t API_MemProtect            _shellcode_[0x58]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,      //uint64_t API_MessageBoxA           _shellcode_[0x60]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,      //uint64_t API_CloseHandle           _shellcode_[0x68]
    //int3
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    //int3                                               
    0x48, 0x83, 0xEC, 0x38,                              //sub rsp,0x38                       //sync_start
    0x48, 0x8D, 0xAC, 0x24, 0x40, 0x00, 0x00, 0x00,      //lea rbp, [rsp+0x40]
    0x41, 0x89, 0xC8,                                    //mov r8d, ecx
    0x33, 0xD2,                                          //xor edx, edx
    0xB9, 0xFF, 0xFF, 0x1F, 0x00,                        //mov ecx,1FFFFF
    0xFF, 0x15, 0xA4, 0xFF, 0xFF, 0xFF,                  //call [API_OpenProcess]
    0x85, 0xC0,                                          //test eax, eax
    0x74, 0x68,                                          //jz return
    0x2E, 0x41, 0x89, 0xC7,                              //mov r15d, eax
    0x44, 0x48, 0x8B, 0x3D, 0x5C, 0xFF, 0xFF, 0xFF,      //mov rdi, qword[unlocker_FpsValue_addr]
    0x4D, 0x31, 0xF6,                                    //xor r14, r14 
    0xBB, 0xF4, 0x01, 0x00, 0x00,                        //mov ebx, 0x1F4        (500ms)
    0x44, 0x48, 0x8D, 0x35, 0x04, 0x00, 0x00, 0x00,      //lea rsi, qword:[Read_tar_fps]
    0x89, 0x5C, 0x24, 0x28,                              //mov dword:[RSP+0x28], ebx
    //Read_tar_fps                                       
    0x4C, 0x8D, 0x44, 0x24, 0x28,                        //lea r8, qword:[RSP+0x28]        
    0x4C, 0x89, 0x74, 0x24, 0x20,                        //mov qword ptr ss:[rsp+20],r14
    0x41, 0xB9, 0x04, 0x00, 0x00, 0x00,                  //mov r9d, 0x4  
    0x48, 0x89, 0xFA,                                    //mov rdx, rdi  
    0x44, 0x89, 0xF9,                                    //mov ecx, esi  
    0xFF, 0x15, 0x6C, 0xFF, 0xFF, 0xFF,                  //call [API_ReadProcessmem]
    0x85, 0xC0,                                          //test eax, eax     
    0x75, 0x10,                                          //jnz continue   
    //read fail                                          
    0x48, 0x83, 0xC6, 0x30,                              //add r15, 0x30         //控制循环范围
    0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00,                  //nop
    0x48, 0xE8, 0x70, 0x00, 0x00, 0x00,                  //call Show Errormsg and CloseHandle 
    //continue                                           
    0x8B, 0x4C, 0x24, 0x28,                              //mov ecx, qword:[RSP+0x28]      
    0x48, 0xE8, 0x16, 0x00, 0x00, 0x00,                  //call Sync_auto
    0x89, 0xD9,                                          //mov ecx, ebx
    0xFF, 0x15, 0x4E, 0xFF, 0xFF, 0xFF,                  //call [API_Sleep]
    0xFF, 0xE6,                                          //jmp rsi
    //int3                                               
    0xCC, 0xCC, 0xCC, 0xCC,                              
    //return                                             
    0x48, 0x83, 0xC4, 0x38,                              //add rsp,0x38 
    0xC3,                                                //ret  
    //int3                                               
    0xCC, 0xCC, 0xCC,                                    
    //int3                                               
    0x44, 0x48, 0x8B, 0x05, 0xF8, 0xFE, 0xFF, 0xFF,      //mov  rax, qword ptr ds:[il2cpp_fps]
    0x48, 0x85, 0xC0,                                    //test rax, rax
    0x74, 0x1B,                                          //jz Write
    //read_game_set                                      
    0x2E, 0x8B, 0x00,                                    //mov eax, qword ptr ss:[rax]
    0x83, 0xF8, 0x1E,                                    //cmp eax, 0x1E 
    0x74, 0x0D,                                          //je set 60
    0x83, 0xF8, 0x2D,                                    //cmp eax, 0x2D
    0x74, 0x0E,                                          //je Sync_unlocker
    0x2E, 0xB9, 0xE8, 0x03, 0x00, 0x00,                  //mov ecx, 0x3E8                    
    0xEB, 0x06,                                          //jmp Write
    0x2E, 0xB9, 0x3C, 0x00, 0x00, 0x00,                  //mov ecx, 0x3C              
    //Write                                              
    0x44, 0x48, 0x8B, 0x05, 0xD8, 0xFE, 0xFF, 0xFF,      //mov rax, qword ptr ds:[engine_fps]
    0x89, 0x08,                                          //mov dword ptr ds:[rax], ecx  
    0x44, 0x48, 0x8B, 0x05, 0xE6, 0xFE, 0xFF, 0xFF,      //mov rax, qword ptr ds:[Ptr_Function_link]
    0x48, 0x85, 0xC0,                                    //test rax, rax 
    0x75, 0x01,                                          //jnz callproc
    0xC3,                                                //ret
    0xFF, 0xE0,                                          //jmp rax
    //int3                                               
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,      
    //int3                                               
    0x48, 0x83, 0xEC, 0x28,                              //sub rsp, 0x28                        //Show Errormsg and closehandle
    0x44, 0x44, 0x89, 0xF9,                              //mov ecx, r15d
    0xFF, 0x15, 0xFA, 0xFE, 0xFF, 0xFF,                  //call [API_CloseHandle] 
    0x31, 0xC9,                                          //xor ecx, ecx 
    0x48, 0x8D, 0x15, 0x19, 0x00, 0x00, 0x00,            //lea rdx, qword:["Sync failed!"]
    0x4C, 0x8D, 0x05, 0x22, 0x00, 0x00, 0x00,            //lea r8, qword:["Error"]
    0x41, 0xB9, 0x10, 0x00, 0x00, 0x00,                  //mov r9d, 0x10 
    0xFF, 0x15, 0xD6, 0xFE, 0xFF, 0xFF,                  //call [API_MessageBoxA] 
    0x48, 0x83, 0xC4, 0x28,                              //add rsp, 0x28
    0xC3,                                                //ret 
    //int3                                               
    0xCC,                                                
    'S','y','n','c',' ','f','a','i','l','e','d','!', 0x00, 0x00, 0x00, 0x00,
    'E','r','r','o','r', 0x00, 0x00, 0x00,               
    //int3                                               
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,      
    //int3                                               
    0x48, 0x8D, 0xA4, 0x24, 0xF8, 0xF7, 0xFF, 0xFF,      //sub rsp, 0x808                 //code_start
    0x8B, 0x0D, 0x42, 0xFE, 0xFF, 0xFF,                  //mov ecx,dword[unlocker_pid]
    0x85, 0xC9,                                          //test ecx, ecx
    0x74, 0x06,                                          //je ret
    0x48, 0xE8, 0xB8, 0xFE, 0xFF, 0xFF,                  //call sync_start
    0x48, 0x8D, 0xA4, 0x24, 0x08, 0x08, 0x00, 0x00,      //add rsp, 0x808
    0xC3,                                                //ret
    //int3                                               
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,            
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,      
    //int3                                               
	0x4C, 0x48, 0x8B, 0x05, 0x38, 0xFE, 0xFF, 0xFF, 	 //mov r8, qword ptr ds:[hksr_ui_ptr]
	0x8B, 0x0D, 0x3A, 0xFE, 0xFF, 0xFF, 				 //mov ecx, dword ptr ds:[hksr_ui_type]
	0x89, 0x08, 										 //mov dword ptr ds:[rax], ecx
	0xC3, 											     //ret
    //int3
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    //int3
	0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54,                    //push r15,r14,r13,r12                 //hooked_func VA + 0x200
	0x53, 0x55, 0x56, 0x57,                                            //push rbx,rbp,rsi,rdi   
    0x48, 0x83, 0xEC, 0x68,                                            //sub rsp, 0x68
    0x44, 0x48, 0x8B, 0x35, 0x88, 0x01, 0x00, 0x00,                    //mov rsi, [Hooked_funcstruct]
    0x40, 0x48, 0x8B, 0x1D, 0x88, 0x01, 0x00, 0x00,                    //mov rbx, [verfiy_func_ptr]
    0x48, 0x8D, 0xAC, 0x24, 0x28, 0x00, 0x00, 0x00,                    //lea rbp, [rsp + 0x28]
    0x48, 0x89, 0x4D, 0x08,                                            //mov [rbp + 8], rcx
	0x48, 0x89, 0x55, 0x10,							                   //mov [rbp + 0x10], rdx  
	0x4C, 0x89, 0x45, 0x18, 						                   //mov [rbp + 0x18], r8
	0x4C, 0x89, 0x4D, 0x20, 						                   //mov [rbp + 0x20], r9
	0x4C, 0x48, 0x8D, 0x3D, 0xD0, 0x00, 0x00, 0x00,                    //lea rdi, [mem_protect_RXW]
	0x4D, 0x31, 0xE4, 								                   //xor r12, r12
    0x66,0x66,0x66,0x66,0x66,0x0F,0x1F,0x84,0x00,0x00,0x00,0x00,0x00,  //nop
	0x4E, 0x8D, 0x2C, 0x26, 							               //lea r13, [rsi + r12 * 1]
	0x49, 0x8B, 0x4D, 0x00, 							               //mov rcx, [r13 + 0]
	0x49, 0x89, 0xCE, 								                   //mov r14, rcx
	0x48, 0x85, 0xC9, 								                   //test rcx, rcx
	0x74, 0x18, 										               //jz break
	0xFF, 0xD7, 									                   //call rdi
	0x85, 0xC0, 										               //test eax, eax
	0x74, 0x0C, 										               //jz skip
	0xF3, 0x41, 0x0F, 0x6F, 0x45, 0x20, 				               //movdqu xmm0, [r13 + 0x20]
	0xF3, 0x41, 0x0F, 0x7F, 0x46, 0x00, 				               //movdqu [r14], xmm0
	0x49, 0x83, 0xC4, 0x30, 							               //add r12, 0x30
	0xEB, 0xD8, 										               //jmp continue
	0x48, 0x89, 0xD9, 								                   //mov rcx, rbx
	0xE8, 0x90, 0x00, 0x00, 0x00,   			                       //call mem_protect_RXW
	0x48, 0x8B, 0x4D, 0x08, 						                   //mov rcx, [rbp + 8]
	0x48, 0x8B, 0x55, 0x10, 						                   //mov rdx, [rbp + 0x10]
	0x4C, 0x8B, 0x45, 0x18,     		                               //mov r8, [rbp + 0x18]
	0x4C, 0x8B, 0x4D, 0x20,     	                                   //mov r9, [rbp + 0x20]
	0xF3, 0x0F, 0x6F, 0x05, 0x18, 0x01, 0x00, 0x00,	                   //movdqu xmm0, [org_pattern]
	0xF3, 0x0F, 0x7F, 0x03, 							               //movdqu [rbx], xmm0
	0xFF, 0xD3, 										               //call rbx
	0x49, 0x97, 										               //xchg r15, rax
	0xF3, 0x0F, 0x6F, 0x05, 0x18, 0x01, 0x00, 0x00, 				   //movdqu xmm0, [Hooked_pattern]
	0xF3, 0x0F, 0x7F, 0x03, 							               //movdqu [rbx], xmm0
    0x4C, 0x48, 0x8D, 0x3D, 0x8C, 0x00, 0x00, 0x00,                    //lea rdi, [mem_protect_RX]
    0x4D, 0x31, 0xE4, 								                   //xor r12, r12
    0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,		       //nop
    0x4E, 0x8D, 0x2C, 0x26, 							               //lea r13, [rsi + r12 * 1]
    0x49, 0x8B, 0x4D, 0x00, 							               //mov rcx, [r13 + 0]
    0x49, 0x89, 0xCE, 								                   //mov r14, rcx
    0x48, 0x85, 0xC9, 								                   //test rcx, rcx
    0x74, 0x14, 										               //jz break
    0xF3, 0x41, 0x0F, 0x6F, 0x45, 0x10, 				               //movdqu xmm0, [r13 + 0x10]
    0xF3, 0x41, 0x0F, 0x7F, 0x46, 0x00, 				               //movdqu [r14], xmm0
    0xFF, 0xD7, 									                   //call rdi
    0x49, 0x83, 0xC4, 0x30, 							               //add r12, 0x30
    0xEB, 0xDC, 										               //jmp continue
	0x48, 0x89, 0xD9, 								                   //mov rcx, rbx
	0x48, 0xFF, 0xD7,             			                           //call rdi
	0x49, 0x97, 										               //xchg r15, rax
	0x48, 0x83, 0xC4, 0x68, 							               //add rsp, 0x68
	0x5F, 0x5E, 0x5D, 0x5B,                                            //pop rdi, rsi, rbp, rbx,
    0x41, 0x5C, 0x41, 0x5D, 0x41, 0x5E, 0x41, 0x5F,	                   //pop r15,r14,r13,r12
    0xC3,                                                              //ret
	//int3
	0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
	0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 
    //int3
	0x48, 0x83, 0xEC, 0x38,                               //sub rsp, 0x38           //mem_protect_RXW
	0x4C, 0x8D, 0x0C, 0x24,                               //lea r9, [rsp]
	0x41, 0xB8, 0x40, 0x00, 0x00, 0x00, 				  //mov r8d, 0x40
	0xBA, 0x00, 0x20, 0x00, 0x00, 					      //mov edx, 0x2000
	0x48, 0x81, 0xE1, 0x00, 0xF0, 0xFF, 0xFF, 		      //and rcx, 0xFFFFF000
	0x49, 0x83, 0xC1, 0x28, 							  //add r9, 0x28
	0xFF, 0x15, 0x24, 0xFD, 0xFF, 0xFF, 				  //call [API_MemProtect]
	0x48, 0x83, 0xC4, 0x38, 							  //add rsp, 0x38
	0xC3, 											      //ret
	//int3
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 
	//int3
	0x48, 0x83, 0xEC, 0x38, 							  //sub rsp, 0x38           //mem_protect_RX
	0x4C, 0x8D, 0x0C, 0x24, 							  //lea r9, [rsp]
	0x41, 0xB8, 0x20, 0x00, 0x00, 0x00, 				  //mov r8d, 0x20
	0xBA, 0x00, 0x20, 0x00, 0x00, 					      //mov edx, 0x2000
	0x48, 0x81, 0xE1, 0x00, 0xF0, 0xFF, 0xFF, 		      //and rcx, 0xFFFFF000
	0x49, 0x83, 0xC1, 0x28, 							  //add r9, 0x28
	0xFF, 0x15, 0xF4, 0xFC, 0xFF, 0xFF, 				  //call [API_MemProtect]
	0x48, 0x83, 0xC4, 0x38, 							  //add rsp, 0x38
	0xC3, 											      //ret
    //int3
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
};

#define sc_entryVA  (0x1B0)
#define hooked_func_VA (0x200)
#define mem_protect_RXW_VA (0x310)

const DECLSPEC_ALIGN(32) BYTE _GIUIshell_Const[] =
{
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,      //uint64_t MemProtectRXW
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,      //uint64_t MemProtectRX
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	     //uint64_t PHooked_func
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,      //uint64_t Pplat_flag
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
	0x53, 0x55, 0x56, 0x57, 							    //push rbx,rbp,rsi,rdi
	0x48, 0x83, 0xEC, 0x48, 							    //sub rsp, 0x48
	0x48, 0x48, 0x8B, 0x1D, 0xD0, 0xFF, 0xFF, 0xFF,	        //mov rbx, qword ptr ds:[hksr_ui_ptr]
	0x48, 0x8D, 0xAC, 0x24, 0x28, 0x00, 0x00, 0x00,         //lea rbp, [rsp + 0x28]
	0x48, 0x89, 0x4D, 0x08,     			                //mov [rbp + 8], rcx
	0x48, 0x89, 0x55, 0x10,                                 //mov [rbp + 0x10], rdx
	0x4C, 0x89, 0x45, 0x18, 							    //mov [rbp + 0x18], r8
	0x4C, 0x89, 0x4D, 0x20, 							    //mov [rbp + 0x20], r9
	0x48, 0x89, 0xD9, 								        //mov rcx, rbx
	0x44, 0xFF, 0x15, 0x9E, 0xFF, 0xFF, 0xFF, 		        //call [MEM_RXW]
	0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00, 				    //nop
	0xF3, 0x0F, 0x6F, 0x05, 0x50, 0x00, 0x00, 0x00,	        //movdqu xmm0, [Hooked_pattern]
	0xF3, 0x0F, 0x7F, 0x03, 							    //movdqu [rbx], xmm0
	0x48, 0x8B, 0x4D, 0x08,     			                //mov rcx, [rbp + 8]
	0x48, 0x8B, 0x55, 0x10, 							    //mov rdx, [rbp + 0x10]
	0xFF, 0xD3, 									        //call rbx
	0xEB, 0x00,										        //nop
	0x4C, 0x48, 0x8B, 0x3D, 0x90, 0xFF, 0xFF, 0xFF, 	    //mov rdi, qword ptr ds:[platflag]
    0x48, 0x89, 0xF9, 
    0x4C, 0xFF, 0x15, 0x6E, 0xFF, 0xFF, 0xFF, 
    0xC7, 0x07, 0x02, 0x00, 0x00, 0x00, 
    0x48, 0x89, 0xF9, 
    0x4C, 0xFF, 0x15, 0x66, 0xFF, 0xFF, 0xFF, 
    0x48, 0x89, 0xD9, 
    0x4C, 0xFF, 0x15, 0x5C, 0xFF, 0xFF, 0xFF, 
    0x48, 0x83, 0xC4, 0x48,
    0x5F, 0x5E, 0x5D, 0x5B, 
    0xC3, 
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC
};


typedef struct hooked_func_struct
{
	uint64_t func_addr;
	uint64_t Reserved;
    __m128i hookedpart;
	__m128i orgpart;
} hooked_func_struct, *Phooked_func_struct;

// 特征搜索
static uintptr_t PatternScan_Region(uintptr_t startAddress, size_t regionSize, const char* signature)
{
    auto pattern_to_byte = [](const char* pattern)
        {
            std::vector<int> bytes;
            const char* start = pattern;
            const char* end = pattern + strlen(pattern);

            for (const char* current = start; current < end; ++current) 
            {
                if (*current == '?') 
                {
                    ++current;
                    if (*current == '?')
                        ++current;
                    bytes.push_back(-1);
                }
                else 
                {
                    bytes.push_back(strtoul(current, const_cast<char**>(&current), 16));
                }
            }
            return bytes;
        };

    std::vector<int> patternBytes = pattern_to_byte(signature);
    auto scanBytes = reinterpret_cast<std::uint8_t*>(startAddress);

    for (size_t i = 0; i < regionSize - patternBytes.size(); i++)
    {
        bool found = true;
        for (size_t j = 0; j < patternBytes.size(); ++j) 
        {
            if (scanBytes[i + j] != patternBytes[j] && patternBytes[j] != -1) 
            {
                found = false;
                break;
            }
        }
        if (found) 
            return (uintptr_t)&scanBytes[i];
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

//Throw error msgbox
static void Show_Error_Msg(LPCWSTR Prompt_str)
{
    if (ErrorMsg_EN == 0)
        return;
    uint32_t Error_code = GetLastError();
    if (Error_code == ERROR_SUCCESS)
        Error_code = ERROR_INVALID_DATA;
    wstring message{};
    wstring title{};
    if (Prompt_str)
        message = Prompt_str;
    else
        message = L"Default Error Message";
    message += L"\n" + GetLastErrorAsString(Error_code);
    UNICODE_STRING message_str;
    UNICODE_STRING title_str;
    {
        wchar_t cwstr[0x1000];
        PEB64* peb = (PEB64*)__readgsqword(0x60);
        HMODULE self = (HMODULE)peb->ImageBaseAddress;
        GetModuleFileNameW(self, cwstr, 0x800);
        title = cwstr;
        title = title.substr(title.find_last_of(L"\\") + 1);
    }
    InitUnicodeString(&message_str, (PCWSTR)message.c_str());
    InitUnicodeString(&title_str, (PCWSTR)title.c_str());
    ULONG_PTR params[4] = { (ULONG_PTR)&message_str, (ULONG_PTR)&title_str, ((ULONG)ResponseButtonOK | IconError), INFINITE };
    DWORD response;
    NtRaiseHardError(STATUS_SERVICE_NOTIFICATION | HARDERROR_OVERRIDE_ERRORMODE, 4, 3, params, 0, &response);
}

//create pwstr 1 len = 2 byte
static wstring* NewWstring(size_t strlen)
{
    uintptr_t* wcsptr = (uintptr_t*)malloc(sizeof(wstring));
    if (!wcsptr)
    {
        goto __malloc_fail;
    }
    memset(wcsptr, 0, sizeof(wstring));
    if (strlen <= 7)
    {
        *(size_t*)((uintptr_t)wcsptr + 0x10 + sizeof(uintptr_t)) = strlen;
        return (wstring*)wcsptr;
    }
    else
    {
        wchar_t* wcstr = (wchar_t*)malloc(strlen * 2);
        if (!wcstr)
        {
            goto __malloc_fail;
        }
        *(uint64_t*)wcstr = 0;
        *(uintptr_t*)wcsptr = (uintptr_t)wcstr;
        *(size_t*)((uintptr_t)wcsptr + 0x10 + sizeof(uintptr_t)) = strlen;
        return (wstring*)wcsptr;
    }

__malloc_fail:
    Show_Error_Msg(L"malloc failed!");
    ExitProcess(-1);
    return 0;
}

//destroy
static INLINE void DelWstring(wstring** pwstr)
{
    if(*(uintptr_t*)((uintptr_t)*(uintptr_t*)pwstr + 0x10 + sizeof(uintptr_t)) > 7)
        free(**(wchar_t***)pwstr);  
    free(*pwstr);
    *pwstr = 0;
    return;
}


static BYTE* init_shellcode()
{
    BYTE* _shellcode_buffer = (BYTE*)VirtualAlloc_Internal(0, 0x1000, PAGE_READWRITE);
    if (_shellcode_buffer == 0)
    {
        return 0;
    }
    memmove(_shellcode_buffer, _shellcode_Const, sizeof(_shellcode_Const));
    *(uint32_t*)_shellcode_buffer = GetCurrentProcessId();       //unlocker PID
    {
        char str_openproc[16] = { 0 };
        *(DWORD64*)(&str_openproc) = 0x9C908DAF919A8FB0;
        *(DWORD64*)(&str_openproc[8]) = 0x3FCA87DAFF8C8C9A;
        decbyte(str_openproc, 2);
        uint64_t p_openproc = (uint64_t)GetProcAddress_Internal((HMODULE)~Kernel32_ADDR, str_openproc);
        if (!p_openproc)
        {
            Show_Error_Msg(L"Bad Function (Openprocess)");
            VirtualFree_Internal((void*)_shellcode_buffer, 0, MEM_RELEASE);
            return 0;
        }
        *(uint64_t*)(_shellcode_buffer + 0x40) = p_openproc;
    }
    {
        char str_readprocmem[24] = { 0 };
        *(DWORD64*)(&str_readprocmem) = 0x9C908DAF9B9E9AAD;
        *(DWORD64*)(&str_readprocmem[8]) = 0x8D90929AB28C8C9A;
        decbyte(str_readprocmem, 2);
        *(DWORD*)(&str_readprocmem[16]) = 0x79;
        uint64_t p_readmem = (uint64_t)GetProcAddress_Internal((HMODULE)~Kernel32_ADDR, str_readprocmem);
        if (!p_readmem)
        {
            Show_Error_Msg(L"Bad Function (ReadProcMem)");
            VirtualFree_Internal((void*)_shellcode_buffer, 0, MEM_RELEASE);
            return 0;
        }
        *(uint64_t*)(_shellcode_buffer + 0x48) = p_readmem;
    }
    *(uint64_t*)(_shellcode_buffer + 0x50) = (uint64_t)(&Sleep);
    *(uint64_t*)(_shellcode_buffer + 0x60) = (uint64_t)(&MessageBoxA);
    *(uint64_t*)(_shellcode_buffer + 0x68) = (uint64_t)(&CloseHandle);
    return (BYTE*)_shellcode_buffer;
}

//[in],[in],[out],[out],[in]
static bool Get_Section_info(uintptr_t PE_buffer, LPCSTR Name_sec, uint32_t* Sec_Vsize, uintptr_t* Sec_Remote_RVA, uintptr_t Remote_BaseAddr)
{
    if ((!PE_buffer) || (!Name_sec) || (!Sec_Vsize) || (!Sec_Remote_RVA))
        return 0;
    uint64_t tar_sec = *(uint64_t*)Name_sec;//max 8 byte
    int32_t* WinPEfileVA = (int32_t*)((uint64_t)PE_buffer + 0x3C); //dos_header
    uintptr_t PEfptr = (uintptr_t)((uint64_t)PE_buffer + *WinPEfileVA); //get_winPE_VA
    _IMAGE_NT_HEADERS64* _FilePE_Nt_header = (_IMAGE_NT_HEADERS64*)PEfptr;
    if (_FilePE_Nt_header->Signature == 0x00004550)
    {
        DWORD sec_num = _FilePE_Nt_header->FileHeader.NumberOfSections;//获得指定节段参数
        sec_num++;
        DWORD num = sec_num;
        DWORD target_sec_VA_start = 0;
        do
        {
            PIMAGE_SECTION_HEADER _sec_temp = (PIMAGE_SECTION_HEADER)(PEfptr + 264 + (40 * (static_cast<unsigned long long>(sec_num) - num)));

            if (*(uint64_t*)(_sec_temp->Name) == tar_sec)
            {
                target_sec_VA_start = _sec_temp->VirtualAddress;
                *Sec_Vsize = _sec_temp->Misc.VirtualSize;
                *Sec_Remote_RVA = Remote_BaseAddr + target_sec_VA_start;
                return 1;
            }
            num--;

        } while (num);

        return 0;
    }
    return 0;
}

//通过进程名搜索进程ID
static DWORD GetPID(const wchar_t* ProcessName)
{
    return GetProcPID(ProcessName);

    //DWORD pid = 0;
    //PROCESSENTRY32W* pe32 = (PROCESSENTRY32W*)malloc(sizeof(PROCESSENTRY32W));
    //if (!pe32)
    //    return 0;
    //wstring name = ProcessName;
    //towlower0((wchar_t*)name.c_str());
    //pe32->dwSize = sizeof(PROCESSENTRY32W);
    //HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    //for (Process32FirstW(snap, pe32); Process32NextW(snap, pe32);)
    //{
    //    towlower0(pe32->szExeFile);
    //    if (wcstrcmp0(pe32->szExeFile, name.c_str()))
    //    {
    //        pid = pe32->th32ProcessID;
    //        break;
    //    }
    //}
    //CloseHandle(snap);
    //return pid;

}


static bool WriteConfig(int fps)
{
    HANDLE hFile = CreateFileW(CONFIG_FILENAME, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        Show_Error_Msg(L"CreateFile failed! (config)");
        return false;
    }
    wstring content{0};
    LPVOID buffer = VirtualAlloc_Internal(0, 0x10000, PAGE_READWRITE);
    if (!buffer)
        return false;
    *(DWORD64*)&content = ((DWORD64)buffer);
    *(DWORD64*)((DWORD64)&content + 0x18) = 0x8000;
    *(DWORD*)buffer = 0x20FEFF;
    content += L"[Setting]\nGenshinPath=" + GenGamePath + L"\n";
    content += L"HKSRPath=" + HKSRGamePath + L"\n";
    {
        content += L"IsAntiMisscontact=" + std::to_wstring(isAntimiss) + L"\n";
    }
    {
        content += L"TargetDevice=" + std::to_wstring(Tar_Device) + L"\n";
    }
    {
        content += L"IsHookGameSet=" + std::to_wstring(isHook) + L"\n";
    }
    {
        content += L"GSTarget60=" + std::to_wstring(Target_set_60) + L"\n";
    }
    {
        content += L"GSTarget30=" + std::to_wstring(Target_set_30) + L"\n";
    }
    {
        content += L"EnableErrorMsg=" + std::to_wstring(ErrorMsg_EN) + L"\n";
    }
    {
        content += L"AutoExit=" + std::to_wstring(AutoExit) + L"\n";
    }
    {
        content += L"GameProcessPriority=" + std::to_wstring(ConfigPriorityClass) + L"\n";
    }
    {
        content += L"FPS=" + std::to_wstring(fps) + L"\n";
    }

    DWORD written = 0;
    bool re = WriteFile(hFile, buffer, content.size() * 2, &written, nullptr);
    VirtualFree_Internal(buffer, 0, MEM_RELEASE);
    CloseHandle_Internal(hFile);
	memset(&content, 0, sizeof(wstring));
    return re;
}


static bool LoadConfig()
{
    INIReader reader(CONFIG_FILENAME);
    if (reader.ParseError() != 0)
    {
        wprintf_s(L"\n Config Not Found !\n 配置文件未发现\n Don't close unlocker and open the game \n 不要关闭解锁器,并打开游戏\n Wait for game start ......\n 等待游戏启动.....\n");

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
            NtSleep(200);
        }
        HANDLE hProcess = OpenProcess_Internal(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE | PROCESS_TERMINATE, pid);
        if (!hProcess)
        {
            Show_Error_Msg(L"OpenProcess failed! (Get game path)");
            return 0;
        }

        // 获取进程句柄 - 这权限很低的了 - 不应该获取不了
        // PROCESS_QUERY_LIMITED_INFORMATION - 用于查询进程路经 (K32GetModuleFileNameExA)
        // SYNCHRONIZE - 用于等待进程结束 (WaitForSingleObject)

        DWORD length = 0x4000;
        wchar_t* szPath = (wchar_t*)VirtualAlloc_Internal(0, length, PAGE_READWRITE);
        if(!szPath)
        {
            Show_Error_Msg(L"Alloc Memory failed! (Get game path)");
            return 0;
        }
        if (!QueryFullProcessImageNameW(hProcess, 0, szPath, &length))
        {
            Show_Error_Msg(L"Get game path failed!");
            VirtualFree_Internal(szPath, 0, MEM_RELEASE);
            return 0;
        }

        if (isGenshin) 
        {
            GenGamePath = szPath;
        }
        else 
        {
            HKSRGamePath = szPath;
        }
        GamePath = szPath;

        VirtualFree_Internal(szPath, 0, MEM_RELEASE);

        DWORD ExitCode = STILL_ACTIVE;
        while (ExitCode == STILL_ACTIVE)
        {
            // wait for the game to close then continue
            TerminateProcess_Internal(hProcess, 0);
            WaitForSingleObject(hProcess, 2000);
            GetExitCodeProcess(hProcess, &ExitCode);
        }
        CloseHandle_Internal(hProcess);

        //clean screen
        {
            COORD pos = { 0, 8 };
            HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
            SetConsoleCursorPosition(hOut, pos);
        }
        for (int a = 0; a <= 6; a++)
        {
            for (int i = 0; i <= 10; i++)
            {
                printf_s("               ");
            }
            printf_s("\n");
        }
        {
            COORD pos = { 0, 8 };
            HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
            SetConsoleCursorPosition(hOut, pos);
        }
        goto __path_ok;
    }

    HKSRGamePath = reader.Get(L"Setting", L"HKSRPath", HKSRGamePath);
    GenGamePath = reader.Get(L"Setting", L"GenshinPath", GenGamePath);
    if (isGenshin)
    {
        GamePath = GenGamePath;
        if (GetFileAttributesW(GamePath.c_str()) == INVALID_FILE_ATTRIBUTES)
        {
            wprintf_s(L"\n Genshin Path Error!\n Plase open Genshin to set game path.\n 路径错误，请手动打开原神来设置游戏路径 \n");
            goto _no_config;
        }
    }
    else
    {
        GamePath = HKSRGamePath;
        if (GetFileAttributesW(GamePath.c_str()) == INVALID_FILE_ATTRIBUTES)
        {
            wprintf_s(L"\n HKSR Path Error!\n Plase open StarRail to set game path.\n 路径错误，请手动打开崩铁来设置游戏路径 \n");
            goto _no_config;
        }   
    }

__path_ok:
    isAntimiss = reader.GetBoolean(L"Setting", L"IsAntiMisscontact", 1);
    Target_set_30 = reader.GetInteger(L"Setting", L"GSTarget30", 60);
    Target_set_60 = reader.GetInteger(L"Setting", L"GSTarget60", 1000);
    ErrorMsg_EN = reader.GetBoolean(L"Setting", L"EnableErrorMsg", 1);
    AutoExit = reader.GetBoolean(L"Setting", L"AutoExit", 0);
    isHook = reader.GetBoolean(L"Setting", L"IsHookGameSet", 0);
    Tar_Device = reader.GetInteger(L"Setting", L"TargetDevice", DEFAULT_DEVICE);
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


struct Boot_arg
{
    LPWSTR Game_Arg;
    LPWSTR Path_Lib;
};
//[out] CommandLinew
//The first 16 bytes are used by other arg
static bool Init_Game_boot_arg(Boot_arg* arg)
{
    if (!arg)
    {
        return 0;
    }
    int argNum = 0;
    LPWSTR* argvW = CommandLineToArgvW(GetCommandLineW(), &argNum);
    //win32arg maxsize 8191
    std::wstring CommandLine{};
    if (argNum >= 2)
    {
        int _game_argc_start = 2;
        wchar_t boot_genshin[] = L"-genshin";
        wchar_t boot_starrail[] = L"-hksr";
        wchar_t loadLib[] = L"-loadlib";
        wchar_t Use_Mobile_UI[] = L"-enablemobileui";
        wstring* temparg = NewWstring(0x1000);
        *temparg = argvW[1];
        towlower0((wchar_t*)temparg->c_str());
        if (*temparg == boot_genshin)
        {
            SetConsoleTitleA("This console control GenshinFPS");

            if (argNum > 2)
            {
                *temparg = argvW[2];
                towlower0((wchar_t*)temparg->c_str());
                if (*temparg == Use_Mobile_UI)
                {
                    Use_mobile_UI = 1;
                    //CommandLine += L"use_mobile_platform -is_cloud 1 -platform_type CLOUD_THIRD_PARTY_MOBILE ";
                    _game_argc_start = 3;
                }
            }
        }
        else if (*temparg == boot_starrail)
        {
            isGenshin = 0;
            SetConsoleTitleA("This console control HKStarRailFPS");
            if (argNum > 2)
            {
                *temparg = argvW[2];
                towlower0((wchar_t*)temparg->c_str());
                if (*temparg == Use_Mobile_UI)
                {
                    Use_mobile_UI = 1;
                    _game_argc_start = 3;
                }
            }
        }
        else
        {
            Show_Error_Msg(L"参数错误 \nArguments error ( unlocker.exe -[game] -[game argv] ..... ) \n");
            return 0;
        }
        if (argNum > _game_argc_start)
        {
            *temparg = argvW[_game_argc_start];
            towlower0((wchar_t*)temparg->c_str());
            if (*temparg == loadLib)
            {
                _game_argc_start++;
                if (argNum > _game_argc_start)
                {
                    *temparg = argvW[_game_argc_start];
                    LPVOID LibPath = malloc(temparg->size() * 2);
                    strncpy0((wchar_t*)LibPath, temparg->c_str(), temparg->size() * 2);
                    arg->Path_Lib = (LPWSTR)LibPath;
                    _game_argc_start++;
                }
            }
        }
        for (int i = _game_argc_start; i < argNum; i++)
        {
            CommandLine += argvW[i];
            CommandLine += L" ";
        }
        DelWstring(&temparg);
    }
    else
    {
        DWORD gtype = MessageBoxW_Internal(L"Genshin click yes ,StarRail click no ,Cancel to Quit \n启动原神选是，崩铁选否，取消退出 \n", L"GameSelect ", 0x23);
        if (gtype == 3)
        {
            return 0;
        }
        if (gtype == 8)
        {
            SetConsoleTitleA("This console control GenshinFPS");
        }
        if (gtype == 5)
        {
            isGenshin = 0;
            SetConsoleTitleA("This console control HKStarRailFPS");
        }
        //?
    }
    arg->Game_Arg = (LPWSTR)malloc(0x2000);
    if (!arg->Game_Arg)
        return 0;
    *(uint64_t*)arg->Game_Arg = 0;
    strncpy0((wchar_t*)((BYTE*)arg->Game_Arg), CommandLine.c_str(), CommandLine.size() * 2);
    return 1;
}

typedef struct Hook_func_list
{
    uint64_t Pfunc_device_type;//plat_flag
    uint64_t Unhook_func;//hook_bootui
    uint64_t setbug_fix; //func_patch
    uint64_t nop;  
}Hook_func_list, *PHook_func_list;

typedef struct inject_arg
{
    uint64_t Pfps;//GI-fps-set
    uint64_t Bootui;//HKSR ui /GIui type
    uint64_t verfiy;//code verfiy
    PHook_func_list PfuncList;//Phook_funcPtr_list
};

// Hotpatch
static uint64_t inject_patch(HANDLE Tar_handle, uintptr_t _ptr_fps, inject_arg* arg)
{
    if (!_ptr_fps)
        return 0;

    BYTE* _sc_buffer = init_shellcode();
    if (!_sc_buffer)
    {
        Show_Error_Msg(L"initcode failed!");
        return 0;
    }
    //Disable errmsg
    if (AutoExit)
    {
        *(uint16_t*)(_sc_buffer + 0x16E) = 0x1AEB;
    }

    //genshin_get_gameset
    if (isGenshin && isHook)
    {
        *(uint64_t*)(_sc_buffer + 0x10) = arg->Pfps;
    }

    //shellcode patch
    *(uint64_t*)(_sc_buffer + 0x8) = (uint64_t)(&FpsValue); //source ptr
    *(uint64_t*)(_sc_buffer + 0x18) = _ptr_fps;

    LPVOID __Tar_proc_buffer = VirtualAllocEx_Internal(Tar_handle, NULL, 0x1000, PAGE_READWRITE);
    if (!__Tar_proc_buffer)
    {
        Show_Error_Msg(L"AllocEx Fail! ");
        return 0;
    }
    if (arg->Bootui && (!isGenshin))
    {
        *(uint64_t*)(_sc_buffer + 0x20) = arg->Bootui;//HKSR mob
        *(uint32_t*)(_sc_buffer + 0x28) = 2;
        *(uint64_t*)(_sc_buffer + 0x30) = (uint64_t)__Tar_proc_buffer + 0x1E0;
    }
    if (arg->PfuncList)
    {
        PHook_func_list GI_Func = (PHook_func_list)arg->PfuncList;
        if(1)
        {
            //init_memapi
            char str_memprotect[16] = { 0 };
            *(DWORD64*)(&str_memprotect) = 0xAF939E8A8B8D96A9;
            *(DWORD64*)(&str_memprotect[8]) = 0x8EFF8B9C9A8B908D;
            decbyte(str_memprotect, 2);
            uint64_t API_memprotect = (uint64_t)GetProcAddress_Internal((HMODULE)~Kernel32_ADDR, str_memprotect);
            if (!API_memprotect)
            {
                Show_Error_Msg(L"Fail getFunction (memprotect)");
                goto __exit_block;
            }
            *(uint64_t*)(_sc_buffer + 0x58) = API_memprotect;
        }
        if(GI_Func->Pfunc_device_type)
        {
            LPVOID __payload_ui = VirtualAllocEx_Internal(Tar_handle, NULL, 0x1000, PAGE_READWRITE);
            if (!__payload_ui)
            {
                Show_Error_Msg(L"Alloc mem Fail! (GIui) 0");
                goto __exit_block;
            }
            BYTE* ui_payload_temp = (BYTE*)VirtualAlloc_Internal(0, 0x1000, PAGE_READWRITE);
            if (!ui_payload_temp)
            {
                Show_Error_Msg(L"Alloc mem failed! (GIui)");
                goto __exit_block;
            }
            memmove(ui_payload_temp, &_GIUIshell_Const, sizeof(_GIUIshell_Const));
            *(uint64_t*)(ui_payload_temp) = ((uint64_t)__Tar_proc_buffer + mem_protect_RXW_VA);
            *(uint64_t*)(ui_payload_temp + 0x8) = ((uint64_t)__Tar_proc_buffer + mem_protect_RXW_VA + 0x30);
            *(uint64_t*)(ui_payload_temp + 0x10) = GI_Func->Unhook_func;
            *(uint64_t*)(ui_payload_temp + 0x18) = GI_Func->Pfunc_device_type + 1;//plat_flag func_va

            if (!ReadProcessMemoryInternal(Tar_handle, (void*)GI_Func->Unhook_func, ui_payload_temp + sizeof(_GIUIshell_Const), 0x10, 0))
            {
                Show_Error_Msg(L"Failed ReadFunc 0 (GIui)");
                goto __exit_block;
            }
            uint64_t hookpart[2] = { 0x225FF,  ((uint64_t)__payload_ui + 0x30) };
            if (!WriteProcessMemoryInternal(Tar_handle, (void*)GI_Func->Unhook_func, &hookpart, 0x10, 0))
            {
                Show_Error_Msg(L"Failed write payload 0(GIui)");
                goto __exit_block;
            }

            if (!WriteProcessMemoryInternal(Tar_handle, (void*)(GI_Func->Pfunc_device_type + 1), &arg->Bootui, 4, 0))
            {
                Show_Error_Msg(L"Failed write payload 0(GIui)");
                goto __exit_block;
            }
            
            Phooked_func_struct Psettingbug = (Phooked_func_struct)(ui_payload_temp + 0x600);
            Psettingbug->func_addr = GI_Func->setbug_fix;
            //settingbugfix
            if (!ReadProcessMemoryInternal(Tar_handle, (void*)GI_Func->setbug_fix, (void*)&Psettingbug->orgpart, 0x10, 0))
            {
                Show_Error_Msg(L"Failed ReadFunc 1 (GIui)");
                goto __exit_block;
            }
			Psettingbug->hookedpart = Psettingbug->orgpart;
			*(BYTE*)((uint64_t)(&Psettingbug->hookedpart) + 2) = 0xEB;

            //inject to game
            if (!WriteProcessMemoryInternal(Tar_handle, __payload_ui, ui_payload_temp, 0x1000, 0))
            {
                Show_Error_Msg(L"Failed write payload 1(GIui)");
                goto __exit_block;
            }
			VirtualFree_Internal(ui_payload_temp, 0, MEM_RELEASE);
            if (!VirtualProtect_Internal(Tar_handle, __payload_ui, 0x1000, PAGE_EXECUTE_READ, 0))
            {
                Show_Error_Msg(L"Failed change RX (GIui)");
                goto __exit_block;
            }
            *(uint64_t*)(_sc_buffer + sizeof(_shellcode_Const)) = ((uint64_t)__payload_ui + 0x600);//Hookinfo_buffer
        }
        if(arg->verfiy)//hookverfiy
        {
            *(uint64_t*)(_sc_buffer + sizeof(_shellcode_Const) + 8) = arg->verfiy;//func
            if (!ReadProcessMemoryInternal(Tar_handle, (void*)arg->verfiy, (_sc_buffer + sizeof(_shellcode_Const) + 0x10), 0x10, 0))
            {
                Show_Error_Msg(L"Failed ReadFunc (GIui)");
                goto __exit_block;
            }
            uint64_t* hook_pa = (uint64_t*)(_sc_buffer + sizeof(_shellcode_Const) + 0x20);
            *hook_pa = 0x225FF;
            *(hook_pa + 1) = ((uint64_t)__Tar_proc_buffer + hooked_func_VA);
            if (!WriteProcessMemoryInternal(Tar_handle, (void*)arg->verfiy, hook_pa, 0x10, 0))
            {
                Show_Error_Msg(L"Failed hook (GIui)");
                goto __exit_block;
            }
        }
    }
__exit_block:

    if (!WriteProcessMemoryInternal(Tar_handle, __Tar_proc_buffer, (void*)_sc_buffer, 0x1000, 0))
    {
        Show_Error_Msg(L"Write Scode Fail! ");
        return 0;
    }
    VirtualFree_Internal(_sc_buffer, 0, MEM_RELEASE);
    if (VirtualProtect_Internal(Tar_handle, __Tar_proc_buffer, 0x1000, PAGE_EXECUTE_READ, 0))
    {
        HANDLE temp = CreateRemoteThreadEx_Internal(Tar_handle, 0, (LPTHREAD_START_ROUTINE)((uint64_t)__Tar_proc_buffer + sc_entryVA), NULL);
        if (!temp)
        {
            Show_Error_Msg(L"Create SyncThread Fail! ");
            return 0;
        }
        CloseHandle_Internal(temp);
        return ((uint64_t)__Tar_proc_buffer);
    }
	return 0;
}

//when DllPath is null return base img addr
static HMODULE RemoteDll_Inject(HANDLE Tar_handle, LPCWSTR DllPath)
{
    size_t Pathsize = 0x2000;
    size_t strlen = 0;
    if (DllPath)
    {
        while (1)
        {
            if (*(WORD*)(DllPath + strlen))
            {
                strlen++;
            }
            else
            {
                strlen *= 2;
                Pathsize += strlen;
                break;
            }
        }
        //HANDLE file_Handle = CreateFileW(DllPath, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (GetFileAttributesW(DllPath) != INVALID_FILE_ATTRIBUTES)
        {
            //CloseHandle_Internal(file_Handle);
            goto __inject_proc;
        }
        return 0;
    }

__inject_proc:
    LPVOID buffer = VirtualAllocEx_Internal(Tar_handle, NULL, Pathsize, PAGE_READWRITE);
    if (buffer)
    {
        HMODULE result = 0;
        DWORD64 payload[4] = { 0 };
        if (!DllPath)
        {
            payload[0] = 0x5848606A38EC8348;
            payload[1] = 0x10408B48008B4865;
            payload[2] = 0xFE805894844;
            payload[3] = 0xCCCCCCC338C48348;
        }
        else
        {
            payload[0] = 0xB848C03138EC8348;
            payload[1] = (DWORD64)&LoadLibraryW;
            payload[2] = 0xFE605894890D0FF;
            payload[3] = 0xCCC338C483480000;
        }
        if (WriteProcessMemoryInternal(Tar_handle, buffer, &payload, 0x20, 0))
        {
            if (VirtualProtect_Internal(Tar_handle, buffer, 0x1000, PAGE_EXECUTE_READ, 0))
            {
                LPVOID RCX = 0;
                if (DllPath)
                {
                    if (!WriteProcessMemoryInternal(Tar_handle, ((BYTE*)buffer) + 0x1000, (void*)DllPath, strlen, 0))
                    {
                        VirtualFreeEx_Internal(Tar_handle, buffer, 0, MEM_RELEASE);
                        return 0;
                    }
                    RCX = ((BYTE*)buffer) + 0x1000;
                }
                HANDLE hThread = CreateRemoteThreadEx_Internal(Tar_handle, 0, (LPTHREAD_START_ROUTINE)buffer, RCX);
                if (hThread)
                {
                    if (WaitForSingleObject(hThread, 60000))
                    {
                        Show_Error_Msg(L"Dll load Wait Time out!");
                        CloseHandle_Internal(hThread);
                        return 0;
                    }
                    ReadProcessMemoryInternal(Tar_handle, ((BYTE*)buffer) + 0x1000, &result, 0x8, 0);
                    CloseHandle_Internal(hThread);
                }
            }
        }
        VirtualFreeEx_Internal(Tar_handle, buffer, 0, MEM_RELEASE);
        return result;
    }
    return 0;
}

//Get the address of the ptr in the target process
static uint64_t Hksr_ENmobile_get_Ptr(HANDLE Tar_handle, LPCWSTR GPath)
{
    uintptr_t GameAssembly_PEbuffer;
    HMODULE il2cpp_base;
    {
        wstring path = GPath;
        path += L"\\GameAssembly.dll";
        il2cpp_base = RemoteDll_Inject(Tar_handle, path.c_str());
        if (!il2cpp_base)
        {
            Show_Error_Msg(L"load GameAssembly.dll Failed !\n");
            return 0;
        }
        GameAssembly_PEbuffer = (uintptr_t)VirtualAlloc_Internal(0, 0x1000, PAGE_READWRITE);
        if (!GameAssembly_PEbuffer)
            return 0;
        if (!ReadProcessMemoryInternal(Tar_handle, il2cpp_base, (void*)GameAssembly_PEbuffer, 0x1000, 0))
            return 0;
        
        int32_t* WinPEfileVA = (int32_t*)((uint64_t)GameAssembly_PEbuffer + 0x3C); //dos_header
        PIMAGE_NT_HEADERS64 PEfptr = (PIMAGE_NT_HEADERS64)((int64_t)GameAssembly_PEbuffer + *WinPEfileVA); //get_winPE_VA
        uint32_t imgsize = PEfptr->OptionalHeader.SizeOfImage;
        LPVOID IMGbuffer = VirtualAlloc_Internal(0, imgsize, PAGE_READWRITE);
        if (!IMGbuffer)
            return 0;
        if (!ReadProcessMemoryInternal(Tar_handle, il2cpp_base, IMGbuffer, imgsize, 0))
            return 0;

        VirtualFree_Internal((void*)GameAssembly_PEbuffer, 0, MEM_RELEASE);
        GameAssembly_PEbuffer = (uintptr_t)IMGbuffer;
    }
    uintptr_t Ua_il2cpp_RVA = 0;
    DWORD32 Ua_il2cpp_Vsize = 0;
    uint64_t retvar = 0;
    if (!Get_Section_info(GameAssembly_PEbuffer, "il2cpp", &Ua_il2cpp_Vsize, &Ua_il2cpp_RVA, GameAssembly_PEbuffer))
    {
        Show_Error_Msg(L"get Section info Error !\n");
        goto __exit;
    }
    if (Ua_il2cpp_RVA && Ua_il2cpp_Vsize)
    {
        //80 B9 ?? ?? ?? ?? 00 74 46 C7 05 ?? ?? ?? ?? 03 00 00 00 48 83 C4 20 5E C3       
        //      75 05 E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 03 00 00 00 48 83 C4 28 C3          
        DWORD64 tar_addr;
        DWORD64 address;
        if (address = PatternScan_Region((uintptr_t)Ua_il2cpp_RVA, Ua_il2cpp_Vsize, "80 B9 ?? ?? ?? ?? 00 74 ?? C7 05 ?? ?? ?? ?? 03 00 00 00 48 83 C4 20 5E C3"))
        {
            tar_addr = address + 11;
        }
        else if (address = PatternScan_Region((uintptr_t)Ua_il2cpp_RVA, Ua_il2cpp_Vsize, "75 05 E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 03 00 00 00 48 83 C4 28 C3"))
        {
            tar_addr = address + 9;
        }
        else
        {
            Show_Error_Msg(L"UI pattern outdate!");
            goto __exit;
        }
        int64_t rip = tar_addr;
        rip += *(int32_t*)rip;
        rip += 8;
        rip -= GameAssembly_PEbuffer;
        retvar = ((uint64_t)il2cpp_base + rip);
    }
    
__exit:
    VirtualFree_Internal((void*)GameAssembly_PEbuffer, 0, MEM_RELEASE);
    return retvar;

}

//For choose suspend
static DWORD __stdcall Thread_display(LPVOID null)
{
    while (1)
    {
        NtSleep(100);
        if (Process_endstate)
            break;
        printf_s("\rFPS: %d - %s    %s", FpsValue, FpsValue < 30 ? "Low power state" : "Normal state   ", "  Press END key stop change  ");
    }
    Process_endstate = 0;
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
    SetPriorityClass((HANDLE)-1, REALTIME_PRIORITY_CLASS);
    SetThreadPriority((HANDLE)-2, THREAD_PRIORITY_TIME_CRITICAL);
    setlocale(LC_CTYPE, "");
    FullScreen();
    SetConsoleTitleA("HoyoGameFPSunlocker");
    _console_HWND = GetConsoleWindow();
    if (_console_HWND == NULL)
    {
        Show_Error_Msg(L"Get Console HWND Failed!");
    }
    
    wprintf_s(L"FPS unlocker 2.8.8\n\nThis program is OpenSource in this link\n https://github.com/winTEuser/Genshin_StarRail_fps_unlocker \n这个程序开源,链接如上\n\nNTOSver: %u \nNTDLLver: %u\n", *(uint16_t*)((__readgsqword(0x60)) + 0x120), ParseOSBuildBumber());

    if (NTSTATUS r = init_API())
    {
        return r;
    }

    Boot_arg barg{};
    if (Init_Game_boot_arg(&barg) == 0)
        return 0; 

    if (LoadConfig() == 0)
        return 0;

    wstring* ProcessPath = NewWstring(GamePath.size() + 1);
    wstring* ProcessDir = NewWstring(GamePath.size() + 1);
    wstring* procname = NewWstring(32);
    *ProcessPath = GamePath;
    *ProcessDir = ProcessPath->substr(0, ProcessPath->find_last_of(L"\\"));
    *procname = ProcessPath->substr(ProcessPath->find_last_of(L"\\") + 1);

    wprintf_s(L"\nGamePath: %s \n\n", GamePath.c_str());
    if(isGenshin == 0)
    {
        wprintf_s(L"When V-sync is opened, you need open setting then quit to apply change in StarRail.\n当垂直同步开启时解锁帧率需要进设置界面再退出才可应用\n");
    }

    {
    _wait_process_close:
        DWORD pid = GetPID(procname->c_str());
        if (pid)
        {
            int state = MessageBoxW_Internal(L"Game has being running! \n游戏已在运行！\nYou can click Yes to auto close game or click Cancel to manually close. \n点击确定自动关闭游戏或手动关闭游戏后点取消\n", L"Error", 0x11);
            if (state == 6)
            {
                HANDLE tempHandle = OpenProcess_Internal(PROCESS_TERMINATE | SYNCHRONIZE, pid);
                TerminateProcess_Internal(tempHandle, 0);
                WaitForSingleObject(tempHandle, 2000);
                CloseHandle_Internal(tempHandle);
            }
            goto _wait_process_close;
        }
    }

    if (isGenshin)
    {
        DWORD lSize;
        DWORD64 Size = 0;
        HANDLE file_Handle = CreateFileW(ProcessPath->c_str(), GENERIC_ALL, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (file_Handle != INVALID_HANDLE_VALUE)
        {
            lSize = GetFileSize(file_Handle, (LPDWORD)(&Size));
            Size = (Size << 32) | lSize;
            if (Size < 0x800000)
                is_old_version = 1;
            else is_old_version = 0;
            CloseHandle_Internal(file_Handle);
        }
        else
        {
            Show_Error_Msg(L"OpenFile Failed!");
        }
    }
    
    size_t bootsize = sizeof(STARTUPINFOW) + sizeof(PROCESS_INFORMATION) + 0x20;
    LPVOID boot_info = malloc(bootsize);
    STARTUPINFOW* si = (STARTUPINFOW*)((uint8_t*)boot_info + sizeof(PROCESS_INFORMATION) + 0x8);
    PROCESS_INFORMATION* pi = (PROCESS_INFORMATION*)boot_info;
    if (!boot_info)
    {
        Show_Error_Msg(L"Malloc failed!");
        return -1;
    }
    memset(boot_info, 0, bootsize);

    if (!((CreateProcessW_pWin64)~(DWORD64)CreateProcessW_p)(ProcessPath->c_str(), (barg.Game_Arg), NULL, NULL, FALSE, CREATE_SUSPENDED | GamePriorityClass, NULL, ProcessDir->c_str(), si, pi))
    {
        Show_Error_Msg(L"CreateProcess Fail!");
        return 0;
    }
    free(barg.Game_Arg);

    inject_arg injectarg = { 0 };
    Hook_func_list GI_Func = { 0 };
    
    if ((isGenshin == 0) && Use_mobile_UI)
    {
        injectarg.Bootui = Hksr_ENmobile_get_Ptr(pi->hProcess, ProcessDir->c_str());
    }
    //加载和获取模块信息
    LPVOID _mbase_PE_buffer = 0;
    uintptr_t Text_Remote_RVA = 0;
    uintptr_t Unityplayer_baseAddr = 0;
    uint32_t Text_Vsize = 0;
    {
        _mbase_PE_buffer = VirtualAlloc_Internal(0, 0x1000, PAGE_READWRITE);
        if (_mbase_PE_buffer == 0)
        {
            Show_Error_Msg(L"VirtualAlloc Failed! (PE_buffer)");
            TerminateProcess_Internal(pi->hProcess, 0);
            CloseHandle_Internal(pi->hProcess);
            return 0;
        }

        if (isGenshin && is_old_version == 0)
        {
            Unityplayer_baseAddr = (uint64_t)RemoteDll_Inject(pi->hProcess, 0);
        }
        else
        {
            wstring EngPath = *ProcessDir;
            EngPath += L"\\UnityPlayer.dll";
            Unityplayer_baseAddr = (uintptr_t)RemoteDll_Inject(pi->hProcess, EngPath.c_str());
        }

        if (Unityplayer_baseAddr)
        {
            if (ReadProcessMemoryInternal(pi->hProcess, (void*)Unityplayer_baseAddr, _mbase_PE_buffer, 0x1000, 0))
            {
                if (Get_Section_info((uintptr_t)_mbase_PE_buffer, ".text", &Text_Vsize, &Text_Remote_RVA, Unityplayer_baseAddr))
                    goto __Get_target_sec;
            }
        }
        
        Show_Error_Msg(L"Get Target Section Fail! (text)");
        VirtualFree_Internal(_mbase_PE_buffer, 0, MEM_RELEASE);
        TerminateProcess_Internal(pi->hProcess, 0);
        CloseHandle_Internal(pi->hProcess);
        return 0;
    }

__Get_target_sec:
    // 在本进程内申请代码段大小的内存 - 用于特征搜索
    LPVOID Copy_Text_VA = VirtualAlloc_Internal(0, Text_Vsize, PAGE_READWRITE);
    if (Copy_Text_VA == NULL)
    {
        Show_Error_Msg(L"Malloc Failed! (text)");
        TerminateProcess_Internal(pi->hProcess, 0);
        CloseHandle_Internal(pi->hProcess);
        return 0;
    }
    // 把整个模块读出来
    if (ReadProcessMemoryInternal(pi->hProcess, (void*)Text_Remote_RVA, Copy_Text_VA, Text_Vsize, 0) == 0)
    {
        Show_Error_Msg(L"Readmem Fail ! (text)");
        VirtualFree_Internal(Copy_Text_VA, 0, MEM_RELEASE);
        TerminateProcess_Internal(pi->hProcess, 0);
        CloseHandle_Internal(pi->hProcess);
        return 0;
    }
   
    //starrail 
    //66 0F 6E 05 ?? ?? ?? ?? F2 0F 10 3D ?? ?? ?? ?? 0F 5B C0
    // 
    //7F 0F 8B 05 ?? ?? ?? ?? 66 0F 6E C8 
    // 
    //7F 0E E8 ? ? ? ? 66 0F 6E C8 0F 5B C9
    //
    //7E 0C E8 ?? ?? ?? ?? 66 0F 6E C8 0F 5B C9 
    // 8B 0D ?? ?? ?? ?? 66 0F 6E C9 0F 5B C9 
    // 计算相对地址 (FPS)
    
    uintptr_t pfps = 0;
    uintptr_t address = 0;
    if (isGenshin)
    {
        if (Use_mobile_UI)
        {
            //platform_flag_func
            address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "E8 ?? ?? ?? ?? 48 8B 7D 40 89 87 ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C 8B C0");
            if (address)
            {
                int64_t rip = address;
                rip += 1;
                rip += *(int32_t*)(rip)+4 + 1;// +1 jmp va
                rip += *(int32_t*)(rip)+4;
                GI_Func.Pfunc_device_type = rip - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
            }
            else
            {
                Use_mobile_UI = 0;
            }
        }
        address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "8B 0D ?? ?? ?? ?? 66 0F 6E C9 0F 5B C9");//5.5
        if (address)
        {
            int64_t rip = address;
            rip += 2;
            rip += *(int32_t*)(rip)+4;
            pfps = rip - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
            goto __genshin_il;
        }
        address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "7E 0C E8 ?? ?? ?? ?? 66 0F 6E C8 0F 5B C9");//5.4
        if (address)
        {
            int64_t rip = address;
            rip += 3;
            rip += *(int32_t*)(rip) + 6;
            rip += *(int32_t*)(rip) + 4;
            pfps = rip - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
            goto __genshin_il;
        }
        address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "7F 0E E8 ?? ?? ?? ?? 66 0F 6E C8"); // ver 3.7 - 5.3 
        if (address)
        {
            int64_t rip = address;
            rip += 3;
            rip += *(int32_t*)(rip) + 6;
            rip += *(int32_t*)(rip) + 4;
            pfps = rip - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
            goto __genshin_il;
        }
        address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "7F 0F 8B 05 ?? ?? ?? ?? 66 0F 6E C8"); // ver old
        if (address)
        {
            int64_t rip = address;
            rip += 4;
            rip += *(int32_t*)(rip) + 4;
            pfps = rip - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
            goto __genshin_il;
        }
        Show_Error_Msg(L"Genshin Pattern Outdated!\nPlase wait new update in github.\n\n");
        VirtualFree_Internal(Copy_Text_VA, 0, MEM_RELEASE);
        TerminateProcess_Internal(pi->hProcess, 0);
        CloseHandle_Internal(pi->hProcess);
        return 0;
    }
    else
    {//HKSR_pattern
        isHook = 0;
        address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "66 0F 6E 05 ?? ?? ?? ?? F2 0F 10 3D ?? ?? ?? ?? 0F 5B C0"); //ver 1.0 - last
        if (address)
        {
            int64_t rip = address;
            rip += 4;
            rip += *(int32_t*)(rip) + 4;
            pfps = rip - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
            
            if (address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "CC 89 0D ?? ?? ?? ?? E9 ?? ?? ?? ?? CC CC CC CC CC"))
            {
                int64_t rip = address;
                rip += 3;
                rip += *(int32_t*)(rip)+4;
                if ((rip - (uintptr_t)Copy_Text_VA + (uintptr_t)Text_Remote_RVA) == pfps)
                {
                    rip = address + 1;
                    DWORD64 Patch0_addr_hook = rip - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
                    uint8_t patch = 0x8B;      //mov dword ptr ds:[?????????], ecx   -->  mov ecx, dword ptr ds:[?????????]
                    if (WriteProcessMemoryInternal(pi->hProcess, (LPVOID)Patch0_addr_hook, (LPVOID)&patch, 0x1, 0) == 0)
                    {
                        Show_Error_Msg(L"Patch Fail! ");
                    }
                    goto __Continue;
                }
            }
            Show_Error_Msg(L"Get pattern Fail! ");
            goto __Continue;
        }
        Show_Error_Msg(L"StarRail Pattern Outdated!\nPlase wait new update in github.\n\n");
        VirtualFree_Internal(Copy_Text_VA, 0, MEM_RELEASE);
        TerminateProcess_Internal(pi->hProcess, 0);
        CloseHandle_Internal(pi->hProcess);
        return 0;
    }
    //-------------------------------------------------------------------------------------------------------------------------------------------------//

__genshin_il:
    if(Use_mobile_UI || isHook)
    {
        uintptr_t UA_baseAddr = Unityplayer_baseAddr;
        if (is_old_version)
        {
            wstring il2cppPath = *ProcessDir;
            il2cppPath += L"\\YuanShen_Data\\Native\\UserAssembly.dll";
            UA_baseAddr = (uintptr_t)RemoteDll_Inject(pi->hProcess, il2cppPath.c_str());
            if (UA_baseAddr)
            {
                if (!ReadProcessMemoryInternal(pi->hProcess, (void*)UA_baseAddr, _mbase_PE_buffer, 0x1000, 0))
                {
                    goto __procfail;
                }
            }
        }
        if (Get_Section_info((uintptr_t)_mbase_PE_buffer, "il2cpp", &Text_Vsize, &Text_Remote_RVA, UA_baseAddr))
        {
            goto __Get_sec_ok;
        }
        Show_Error_Msg(L"Get Section Fail! (il2cpp_GI)");

    __procfail:
        isHook = 0;
        goto __Continue;

    __Get_sec_ok:
        VirtualFree_Internal(Copy_Text_VA, 0, MEM_RELEASE);
        Copy_Text_VA = VirtualAlloc_Internal(0, Text_Vsize, PAGE_READWRITE);
        if (Copy_Text_VA == NULL)
        {
            Show_Error_Msg(L"Malloc Failed! (il2cpp_GI)");
            goto __procfail;
        }
        if (!ReadProcessMemoryInternal(pi->hProcess, (void*)Text_Remote_RVA, Copy_Text_VA, Text_Vsize, 0))
        {
            Show_Error_Msg(L"Readmem Fail ! (il2cpp_GI)");
            goto __procfail;
        }
        if (isHook)
        {
            address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "48 89 F1 E8 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? 48 8B 0D");
            if (address)
            {
                int64_t rip = address;
                rip += 10;
                rip += *(int32_t*)rip;
                rip += 4;
                injectarg.Pfps = rip - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
            }
        }
        else isHook = 0;

        //verfiyhook
        address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "E8 ?? ?? ?? ?? EB 0D 48 89 F1 BA 02 00 00 00 E8 ?? ?? ?? ?? 48 8B 0D");
        if (address)
        {
            int64_t rip = address;
            rip += 0x1;
            rip += *(int32_t*)(rip)+4;
            injectarg.verfiy = rip - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
        }
        else
        {
            Show_Error_Msg(L"GetFunc Fail ! GIx0");
        }
        if (Use_mobile_UI)
        {
            //setting bug
            address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "E8 ?? ?? ?? ?? 83 F8 02 75 0B 48 89 F1 48 89 FA E8");
            if (address)
            {
                int64_t rip = address;
                rip += 0x6;
                GI_Func.setbug_fix = rip - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
            }
            else
            {
                Use_mobile_UI = 0;
            }
            //Unhook_hook
            address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "48 89 F1 E8 ?? ?? ?? ?? 48 89 D9 E8 ?? ?? ?? ?? 80 3D ?? ?? ?? ?? 00 0F 85 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 80 B9 ?? ?? ?? ?? 00");
            if (address)
            {
                int64_t rip = address;
                rip += 0xC;
                rip += *(int32_t*)(rip)+4;
                GI_Func.Unhook_func = rip - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
            }
            else
            {
                Use_mobile_UI = 0;
            }
            if (Use_mobile_UI)
            {
                injectarg.Bootui = Tar_Device;
                injectarg.PfuncList = &GI_Func;
            }
            else 
            {
                GI_Func.Pfunc_device_type = 0;
            }
        }

    }

__Continue:
    uintptr_t Patch_buffer = inject_patch(pi->hProcess, pfps, &injectarg);
    if (!Patch_buffer)
    {
        Show_Error_Msg(L"Inject Fail !\n");
        TerminateProcess_Internal(pi->hProcess, 0);
        CloseHandle_Internal(pi->hProcess);
        return 0;
    }

    if (barg.Path_Lib)
    {
        wprintf_s(L"You may be banned for using this feature. Make sure you had checked the source and credibility of the plugin.\n\n");
        HMODULE mod = RemoteDll_Inject(pi->hProcess, barg.Path_Lib);
        if (!mod)
        {
            Show_Error_Msg(L"Dll Inject Fail !\n");
        }
        free(barg.Path_Lib);
    }
    
    DelWstring(&ProcessPath);
    DelWstring(&ProcessDir);
    DelWstring(&procname);

    VirtualFree_Internal(_mbase_PE_buffer, 0, MEM_RELEASE);
    VirtualFree_Internal(Copy_Text_VA, 0, MEM_RELEASE);
    
	SetThreadAffinityMask(pi->hThread, 0x1);
	SetThreadPriority(pi->hThread, THREAD_PRIORITY_HIGHEST);
    ResumeThread_Internal(pi->hThread);
    CloseHandle_Internal(pi->hThread);
    
    SetPriorityClass((HANDLE) -1, NORMAL_PRIORITY_CLASS);

    if(!AutoExit)
    {
        wprintf_s(L"PID: %d\n \nDone! \n \nUse ↑ ↓ ← → key to change fps limted\n使用键盘上的方向键调节帧率限制\n\n\n  UpKey : +20\n  DownKey : -20\n  LeftKey : -2\n  RightKey : +2\n\n", pi->dwProcessId);

        // 创建printf线程
        HANDLE hdisplay = CreateRemoteThreadEx_Internal((HANDLE)-1, 0, Thread_display, 0);
        if (!hdisplay)
            Show_Error_Msg(L"Create Thread <Thread_display> Error! ");

        DWORD dwExitCode = STILL_ACTIVE;
        uint32_t fps = FpsValue;
        uint32_t cycle_counter = 0;
        while (1)   // handle key input
        {
            NtSleep(50);
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
            if (GetAsyncKeyState(KEY_DECREASE) & 1)
            {
                fps -= 20;
            }
            if (GetAsyncKeyState(KEY_DECREASE_SMALL) & 1)
            {
                fps -= 2;
            }
            if (GetAsyncKeyState(KEY_INCREASE) & 1)
            {
                fps += 20;
            }
            if (GetAsyncKeyState(KEY_INCREASE_SMALL) & 1)
            {
                fps += 2;
            }
            if (fps <= 10)
            {
                fps = 10;
            }
        }
        Process_endstate = 1;
        WaitForSingleObject(hdisplay, INFINITE);
        CloseHandle_Internal(hdisplay);
    }
    else
    {
        NtSleep(1000);
    }
    CloseHandle_Internal(pi->hProcess);
    free(boot_info);
    
    
    return 1;
}





