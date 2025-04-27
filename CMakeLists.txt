cmake_minimum_required(VERSION 3.15)
project(FPSUnlocker LANGUAGES C CXX ASM_MASM) 

aux_source_directory(./src DIR_SRCS)
set(ASMFILE ./src/syscall.asm)
add_executable(FPSUnlocker ${ASMFILE} ${DIR_SRCS})

set_property(TARGET FPSUnlocker PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")

set_target_properties(FPSUnlocker PROPERTIES
    LINK_FLAGS "/FUNCTIONPADMIN /MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\" /SUBSYSTEM:CONSOLE"
    WIN32_EXECUTABLE TRUE
)


