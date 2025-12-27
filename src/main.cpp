#define KEY_TOGGLE VK_END
#define KEY_INCREASE VK_UP
#define KEY_INCREASE_SMALL VK_RIGHT
#define KEY_DECREASE VK_DOWN
#define KEY_DECREASE_SMALL VK_LEFT
#define FPS_TARGET 120
#define DEFAULT_DEVICE 8 
#define CONFIG_FILENAME (L"hoyofps_config.ini")
#define IsKeyPressed(nVirtKey)    ((GetKeyState(nVirtKey) & (1<<(sizeof(SHORT)*8-1))) != 0)

#ifndef _WIN64
#error you must build in Win x64
#endif


#include <iostream>
#include <vector>
#include <string>

#include <Windows.h>
#include <TlHelp32.h>

#include "NTSYSAPI.h"
#include "inireader.h"
#include "shellcode_header.h"


using namespace std;


wstring HKSRGamePath{};
wstring GenGamePath{};
wstring GamePath{};
uint32_t FpsValue = FPS_TARGET;
uint32_t Tar_Device = DEFAULT_DEVICE;
uint32_t Target_set_60 = 1000;
uint32_t Target_set_30 = 60;
uint32_t PowerSave_target = 10;
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


typedef struct hooked_func_struct
{
	uint64_t func_addr;
	uint64_t Reserved;
    __m128i hookedpart;
	__m128i orgpart;
} hooked_func_struct, *Phooked_func_struct;


const DECLSPEC_ALIGN(32) int8_t g_HexLookup[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0-15
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 16-31
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 32-47
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1, // 48-63 ('0'-'9')
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 64-79 ('A'-'F')
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 80-95
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 96-111 ('a'-'f')
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1  // 112-127
};

#define SSE2_Support 0b0001
#define AVX2_Support 0b0010
#define AVX512_Support 0b0100

static uint8_t InitCPUFeatures()
{
    uint8_t result = 0;

    int cpuInfo[4];
    __cpuid(cpuInfo, 1);

    // 检测SSE2
    if (cpuInfo[3] & (1 << 26))
        result |= SSE2_Support;

    // 检测AVX2
    const int hasOSXSAVE = (cpuInfo[2] & (1 << 27)) != 0;
    const int hasAVX = (cpuInfo[2] & (1 << 28)) != 0;

    if (hasOSXSAVE && hasAVX)
    {
        const unsigned long long xcrFeatureMask = _xgetbv(_XCR_XFEATURE_ENABLED_MASK);
        if ((xcrFeatureMask & 6) == 6)
        {
            __cpuidex(cpuInfo, 7, 0);
            if (cpuInfo[1] & (1 << 5))
                result |= AVX2_Support;

            // 检测AVX512
            const int avx512f = (cpuInfo[1] & (1 << 16)) != 0;  // AVX512F
            const int avx512bw = (cpuInfo[1] & (1 << 30)) != 0; // AVX512BW
            const int avx512vl = (cpuInfo[1] & (1 << 31)) != 0; // AVX512VL

            // 需要AVX512F、AVX512BW和AVX512VL支持字节操作
            if (avx512f && avx512bw && avx512vl)
                result |= AVX512_Support;
        }
    }
    return result;
}

static uint8_t g_cpuFeatures = InitCPUFeatures();

typedef struct {
    uintptr_t* buffer;     // 存储匹配地址缓冲区
    size_t maxCount;       // 缓冲区最大容量(数量)
    size_t count;          // 实际找到的匹配数量
} PatternScanInfo;


__declspec(noinline) static uintptr_t PatternScanRegionEx(uintptr_t startAddress, size_t regionSize, const char* signature, PatternScanInfo* results)
{
    if (!signature || !startAddress || !regionSize || !results || !results->buffer || !results->maxCount)
        return 0;

    const size_t kStackThreshold = 512;
    const size_t kSimdWidth = sizeof(__m256i);

    struct PatternData {
        uint8_t* bytes = nullptr;
        uint32_t* masks = nullptr;
        bool* patternWildcard = nullptr;
        size_t length = 0;
        size_t blockCount = 0;
        bool stackAllocated = false;
    } pattern;

    size_t patternLen = 0;
    const char* p = signature;

    while (*p)
    {
        if (*p == ' ') { p++; continue; }
        if (*p == '?') {
            patternLen++;
            p++;
            if (*p == '?') p++;
        }
        else {
            patternLen++;
            p += 2;
        }
    }

    if (patternLen == 0) return 0;
    pattern.length = patternLen;

    // 计算需要的块数
    pattern.blockCount = (patternLen + kSimdWidth - 1) / kSimdWidth;

    const size_t totalSize = pattern.blockCount * kSimdWidth;
    const size_t maskCount = pattern.blockCount;

    if (totalSize <= kStackThreshold)
    {
        // 栈上分配
        static constexpr size_t kMaxStackSize = kStackThreshold;
        uint8_t stackBytes[kMaxStackSize];
        uint32_t stackMasks[kMaxStackSize / kSimdWidth];
        bool stackPatternWildcard[kMaxStackSize];

        pattern.bytes = stackBytes;
        pattern.masks = stackMasks;
        pattern.patternWildcard = stackPatternWildcard;
        pattern.stackAllocated = true;
    }
    else
    {
        // 堆上分配
        pattern.bytes = (uint8_t*)malloc(totalSize);
        pattern.masks = (uint32_t*)malloc(maskCount * sizeof(uint32_t));
        pattern.patternWildcard = (bool*)malloc(patternLen * sizeof(bool));
        if (!pattern.bytes || !pattern.masks || !pattern.patternWildcard)
        {
            if (pattern.bytes) free(pattern.bytes);
            if (pattern.masks) free(pattern.masks);
            if (pattern.patternWildcard) free(pattern.patternWildcard);
            return 0;
        }
        pattern.stackAllocated = false;
    }

    memset(pattern.bytes, 0, totalSize);
    memset(pattern.masks, 0, maskCount * sizeof(uint32_t));
    memset(pattern.patternWildcard, 0, patternLen * sizeof(bool));

    p = signature;
    size_t index = 0;

    while (*p && index < patternLen)
    {
        while (*p == ' ') p++;
        if (!*p) break;

        if (*p == '?')
        {
            // 通配符
            p++;
            if (*p == '?') p++;
            pattern.patternWildcard[index] = true;
        }
        else
        {
            // 有效字节
            uint8_t char1 = g_HexLookup[(uint8_t)*p++];
            while (*p == ' ') p++; if (!*p) break;
            uint8_t char2 = g_HexLookup[(uint8_t)*p++];

            if (char1 > 0x0F || char2 > 0x0F)
            {
                if (!pattern.stackAllocated)
                {
                    free(pattern.bytes);
                    free(pattern.masks);
                    free(pattern.patternWildcard);
                }
                return 0;
            }

            uint8_t byteValue = (char1 << 4) | char2;
            size_t blockIdx = index / kSimdWidth;
            size_t bitPos = index % kSimdWidth;

            pattern.bytes[blockIdx * kSimdWidth + bitPos] = byteValue;
            pattern.masks[blockIdx] |= (1 << bitPos);
        }
        index++;
    }

    if (index != patternLen)
    {
        if (!pattern.stackAllocated)
        {
            free(pattern.bytes);
            free(pattern.masks);
            free(pattern.patternWildcard);
        }
        return 0;
    }

    uint8_t* scanBytes = (uint8_t*)startAddress;
    size_t scanEnd = regionSize - (patternLen + sizeof(__m512i));
    size_t scannedBytes = 0;
    uintptr_t* resultBuffer = results->buffer;
    const size_t maxCount = results->maxCount - 1;
    size_t foundCount = 0;

    // 找到第一个非通配符字节用于快速跳过
    int firstNonWildcardByte = -1;
    size_t firstNonWildcardIdx = 0;

    for (; firstNonWildcardIdx < patternLen; firstNonWildcardIdx++)
    {
        size_t blockIdx = firstNonWildcardIdx / kSimdWidth;
        size_t bitPos = firstNonWildcardIdx % kSimdWidth;

        if (pattern.masks[blockIdx] & (1 << bitPos))
        {
            firstNonWildcardByte = pattern.bytes[blockIdx * kSimdWidth + bitPos];
            break;
        }
    }

    // 全是通配符
    if (firstNonWildcardByte == -1)
    {
        if (!pattern.stackAllocated)
        {
            free(pattern.bytes);
            free(pattern.masks);
            free(pattern.patternWildcard);
        }
        return startAddress;
    }

    _mm_prefetch((const char*)(scanBytes), _MM_HINT_T0);
    if (g_cpuFeatures & AVX512_Support)
    {
        constexpr size_t avx512Width = sizeof(__m512i);
        __m512i firstByteVec = _mm512_set1_epi8((char)firstNonWildcardByte);
        scanEnd -= (avx512Width * 4);

        while (scannedBytes <= scanEnd)
        {
            __m512i dataBlocks[4];
            __mmask64 cmpMasks[4];

            for (int i = 0; i < 4; i++)
            {
                dataBlocks[i] = _mm512_loadu_si512((const __m512i*)(scanBytes + scannedBytes + avx512Width * i));
                cmpMasks[i] = _mm512_cmpeq_epi8_mask(dataBlocks[i], firstByteVec);
            }

            uint64_t combinedMasks[4] = {
                (uint64_t)cmpMasks[0],
                (uint64_t)cmpMasks[1],
                (uint64_t)cmpMasks[2],
                (uint64_t)cmpMasks[3]
            };

            for (int vectorIdx = 0; vectorIdx < 4; vectorIdx++)
            {
                uint64_t mask = combinedMasks[vectorIdx];
                while (mask != 0)
                {
                    DWORD bit;
                    _BitScanForward64(&bit, mask);
                    mask &= mask - 1;

                    size_t pos = scannedBytes + vectorIdx * avx512Width + bit;

                    if (!pattern.patternWildcard[patternLen - 1])
                    {
                        if (scanBytes[pos + patternLen - 1] != pattern.bytes[patternLen - 1])
                        {
                            continue;
                        }
                    }

                    __nop();
                    bool matched = true;
                    for (size_t blockIdx = 0; blockIdx < pattern.blockCount; blockIdx++)
                    {
                        size_t byteOffset = blockIdx * kSimdWidth;
                        if (pos + byteOffset + kSimdWidth > regionSize)
                        {
                            matched = false;
                            break;
                        }

                        __m256i dataChunk = _mm256_loadu_si256((const __m256i*)(scanBytes + pos + byteOffset));
                        __m256i patternChunk = _mm256_loadu_si256((const __m256i*)(pattern.bytes + byteOffset));
                        __m256i cmp = _mm256_cmpeq_epi8(dataChunk, patternChunk);
                        int maskResult = _mm256_movemask_epi8(cmp);

                        if ((maskResult & pattern.masks[blockIdx]) != pattern.masks[blockIdx])
                        {
                            matched = false;
                            break;
                        }
                    }

                    if (matched)
                    {
                        resultBuffer[foundCount++] = (uintptr_t)(scanBytes + pos);
                        if (foundCount >= maxCount)
                        {
                            goto _m512_cleanup;
                        }
                    }
                }
            }
            scannedBytes += avx512Width * 4;
        }
    _m512_cleanup:
        _mm256_zeroupper();
    }
    else if (g_cpuFeatures & AVX2_Support)
    {
        constexpr size_t avx2Width = sizeof(__m256i);
        constexpr uint8_t avx2BlocksPerScan = 4;
        __m256i firstByteVec = _mm256_set1_epi8((char)firstNonWildcardByte);
        scanEnd -= (avx2Width * avx2BlocksPerScan);

        while (scannedBytes <= scanEnd)
        {
            __m256i dataBlocks[avx2BlocksPerScan];
            uint64_t combinedMasks[avx2BlocksPerScan / 2];

            for (int i = 0; i < avx2BlocksPerScan; i++)
            {
                dataBlocks[i] = _mm256_loadu_si256((const __m256i*)(scanBytes + scannedBytes + avx2Width * i));
            }

            combinedMasks[0] = (uint64_t)_mm256_movemask_epi8(_mm256_cmpeq_epi8(dataBlocks[0], firstByteVec)) |
                ((uint64_t)_mm256_movemask_epi8(_mm256_cmpeq_epi8(dataBlocks[1], firstByteVec)) << 32);

            combinedMasks[1] = (uint64_t)_mm256_movemask_epi8(_mm256_cmpeq_epi8(dataBlocks[2], firstByteVec)) |
                ((uint64_t)_mm256_movemask_epi8(_mm256_cmpeq_epi8(dataBlocks[3], firstByteVec)) << 32);

            __nop();
            for (int maskIdx = 0; maskIdx < (avx2BlocksPerScan / 2); maskIdx++)
            {
                uint64_t mask = combinedMasks[maskIdx];
                while (mask != 0)
                {
                    DWORD bit;
                    _BitScanForward64(&bit, mask);
                    mask &= mask - 1;

                    size_t pos = scannedBytes + (maskIdx * (avx2Width * 2)) + bit;

                    if (!pattern.patternWildcard[patternLen - 1])
                    {
                        if (scanBytes[pos + patternLen - 1] != pattern.bytes[patternLen - 1])
                        {
                            continue;
                        }
                    }
                    bool matched = true;
                    for (size_t blockIdx = 0; blockIdx < pattern.blockCount; blockIdx++)
                    {
                        size_t byteOffset = blockIdx * avx2Width;
                        if (pos + byteOffset + avx2Width > regionSize)
                        {
                            matched = false;
                            break;
                        }

                        __m256i dataChunk = _mm256_loadu_si256((const __m256i*)(scanBytes + pos + byteOffset));
                        __m256i patternChunk = _mm256_loadu_si256((const __m256i*)(pattern.bytes + byteOffset));
                        __m256i cmp = _mm256_cmpeq_epi8(dataChunk, patternChunk);
                        int maskResult = _mm256_movemask_epi8(cmp);

                        if ((maskResult & pattern.masks[blockIdx]) != pattern.masks[blockIdx])
                        {
                            matched = false;
                            break;
                        }
                    }

                    if (matched)
                    {
                        resultBuffer[foundCount++] = (uintptr_t)(scanBytes + pos);
                        if (foundCount >= maxCount)
                        {
                            goto _m256_cleanup;
                        }
                    }
                }
            }

            scannedBytes += (avx2Width * avx2BlocksPerScan);
        }

    _m256_cleanup:
        _mm256_zeroupper();
    }
    else
    {
        __m128i firstByteVec = _mm_set1_epi8((char)firstNonWildcardByte);
        scanEnd -= (kSimdWidth * 2);
        __nop();
        __nop();
        __nop();
        for (; scannedBytes <= scanEnd; scannedBytes += (kSimdWidth * 2))
        {
            __m128i dataBlock0 = _mm_loadu_si128((const __m128i*)(scanBytes + scannedBytes));
            __m128i dataBlock1 = _mm_loadu_si128((const __m128i*)(scanBytes + scannedBytes + 16));
            __m128i dataBlock2 = _mm_loadu_si128((const __m128i*)(scanBytes + scannedBytes + 32));
            __m128i dataBlock3 = _mm_loadu_si128((const __m128i*)(scanBytes + scannedBytes + 48));
            __m128i cmp0 = _mm_cmpeq_epi8(dataBlock0, firstByteVec);
            __m128i cmp1 = _mm_cmpeq_epi8(dataBlock1, firstByteVec);
            __m128i cmp2 = _mm_cmpeq_epi8(dataBlock2, firstByteVec);
            __m128i cmp3 = _mm_cmpeq_epi8(dataBlock3, firstByteVec);

            uint64_t mask = (uint64_t)(_mm_movemask_epi8(cmp0) | (_mm_movemask_epi8(cmp1) << 16) | (((uint64_t)_mm_movemask_epi8(cmp2)) << 32) | (((uint64_t)_mm_movemask_epi8(cmp3)) << 48));

            while (mask != 0)
            {
                DWORD bit;
                _BitScanForward64(&bit, mask);
                mask &= mask - 1;

                size_t pos = scannedBytes + bit;

                if (!pattern.patternWildcard[patternLen - 1])
                {
                    if (scanBytes[pos + patternLen - 1] != pattern.bytes[patternLen - 1])
                    {
                        continue;
                    }
                }

                bool matched = true;
                for (size_t blockIdx = 0; blockIdx < pattern.blockCount; blockIdx++)
                {
                    size_t byteOffset = blockIdx * kSimdWidth;
                    if (pos + byteOffset + kSimdWidth > regionSize)
                    {
                        matched = false;
                        break;
                    }

                    __m128i dataChunk0 = _mm_loadu_si128((const __m128i*)(scanBytes + pos + byteOffset));
                    __m128i dataChunk1 = _mm_loadu_si128((const __m128i*)(scanBytes + pos + byteOffset + 16));
                    __m128i patternChunk0 = _mm_loadu_si128((const __m128i*)(pattern.bytes + byteOffset));
                    __m128i patternChunk1 = _mm_loadu_si128((const __m128i*)(pattern.bytes + byteOffset + 16));
                    __m128i cmp0 = _mm_cmpeq_epi8(dataChunk0, patternChunk0);
                    __m128i cmp1 = _mm_cmpeq_epi8(dataChunk1, patternChunk1);
                    int maskResult = _mm_movemask_epi8(cmp0) | (_mm_movemask_epi8(cmp1) << 16);

                    if ((maskResult & pattern.masks[blockIdx]) != pattern.masks[blockIdx])
                    {
                        matched = false;
                        break;
                    }
                }

                if (matched)
                {
                    resultBuffer[foundCount++] = (uintptr_t)(scanBytes + pos);
                    if (foundCount > maxCount)
                    {
                        goto cleanup;
                    }
                }
            }
        }
    }

    if ((patternLen < (regionSize - scannedBytes)) && (foundCount < maxCount))
    {
        scanBytes += scannedBytes;
        regionSize -= scannedBytes;
        for (size_t i = 0; i < regionSize - patternLen; ++i)
        {
            bool matched = true;

            for (size_t j = 0; j < patternLen; ++j)
            {
                size_t blockIdx = j / kSimdWidth;
                size_t bitPos = j % kSimdWidth;

                if ((pattern.masks[blockIdx] & (1 << bitPos)) && scanBytes[i + j] != pattern.bytes[blockIdx * kSimdWidth + bitPos])
                {
                    matched = false;
                    break;
                }
            }

            if (matched)
            {
                resultBuffer[foundCount++] = (uintptr_t)(scanBytes + i);
                if (foundCount >= maxCount)
                {
                    break;
                }
            }
        }
    }

cleanup:
    if (!pattern.stackAllocated)
    {
        free(pattern.bytes);
        free(pattern.masks);
        free(pattern.patternWildcard);
    }

    results->count = foundCount;
    return foundCount > 0 ? resultBuffer[0] : 0;
}


static uintptr_t PatternScan_Region(uintptr_t startAddress, size_t regionSize, const char* signature)
{
    uintptr_t results_buffer[1] = { 0 };
    PatternScanInfo results = { results_buffer, 1, 0 };
    return PatternScanRegionEx(startAddress, regionSize, signature, &results);
}


static std::wstring GetLastErrorAsString(DWORD code)
{
    LPWSTR buf = nullptr;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&buf, 0, NULL);
    std::wstring ret = buf;
    LocalFree(buf);
    return ret;
}


static wstring To_Hexwstring_64bit(uint64_t value)
{
    uint16_t* hstr = (uint16_t*)malloc(0x30);
	if (!hstr)
	{
		ExitProcess(-1);
	}
	for (int i = 15; i >= 0; --i)
	{
        uint16_t byte = value & 0xF;
        if (byte >= 0 && byte <= 9)
        {
            hstr[i] = byte + 0x30;
        }
        else
        {
            hstr[i] = byte + 0x37;
        }
		value >>= 4;
	}
    hstr[16] = 0;
    wstring hexstr = (LPWSTR)hstr;
	free(hstr);
	return hexstr;
}

static wstring To_Hexwstring_32bit(uint32_t value)
{
    uint16_t* hstr = (uint16_t*)malloc(0x20);
    if (!hstr)
    {
		ExitProcess(-1);
    }
    for (int i = 7; i >= 0; --i)
    {
        uint16_t byte = value & 0xF;
        if (byte >= 0 && byte <= 9)
        {
            hstr[i] = byte + 0x30;
        }
        else
        {
            hstr[i] = byte + 0x37;
        }
        value >>= 4;
    }
    hstr[8] = 0; // Ensure null-termination
    wstring hexstr = (LPWSTR)hstr;
    free(hstr);
	return hexstr;
}

//Throw error msgbox
static void Show_Error_Msg(LPCWSTR Prompt_str)
{
    if (ErrorMsg_EN == 0)
        return;
    uint32_t Error_code = *(uint32_t*)((BYTE*)(__readgsqword(0x30)) + 0x68);
    uint32_t LastStatus = *(uint32_t*)((BYTE*)(__readgsqword(0x30)) + 0x1250);
    wstring message{};
    wstring title{};
    {
        if (Prompt_str)
            message = Prompt_str;
        else
            message = L"Default Error Message";
        message += L"\n" + GetLastErrorAsString(Error_code);
        message += L"\nErrorCode: 0x" + To_Hexwstring_32bit(Error_code);
        message += L"\nLastStatus: 0x" + To_Hexwstring_32bit(LastStatus);
    }
    UNICODE_STRING message_str;
    UNICODE_STRING title_str;
    {
        wchar_t* cwstr = (wchar_t*)malloc(0x2000);
		if (!cwstr)
		{
			ExitProcess(-1);
		}
        PEB64* peb = (PEB64*)__readgsqword(0x60);
        HMODULE self = (HMODULE)peb->ImageBaseAddress;
        GetModuleFileNameW(self, cwstr, 0x1000);
        title = cwstr;
        title = title.substr(title.find_last_of(L"\\") + 1);
		free(cwstr); // Free the allocated memory
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
static FORCEINLINE void DelWstring(wstring** pwstr)
{
    if(*(uintptr_t*)((uintptr_t)*(uintptr_t*)pwstr + 0x10 + sizeof(uintptr_t)) > 7)
        free(**(wchar_t***)pwstr);  
    free(*pwstr);
    *pwstr = 0;
    return;
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
    {
        content += L"[Setting]\nGenshinPath=" + GenGamePath + L"\n";
    }
    {
        content += L"HKSRPath=" + HKSRGamePath + L"\n";
    }
    {
        content += L"IsAntiMisscontact=" + std::to_wstring(isAntimiss) + L"\n";
    }
    {
        content += L"IsHookGameSet=" + std::to_wstring(isHook) + L"\n";
    }
    {
        content += L"GenShinTarget60=" + std::to_wstring(Target_set_60) + L"\n";
    }
    {
        content += L"GenShinTarget30=" + std::to_wstring(Target_set_30) + L"\n";
    }
    {
        content += L"PowerSaveTarget=" + std::to_wstring(PowerSave_target) + L"\n";
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
    bool re = WriteFile(hFile, buffer, content.size() * 2, &written, 0);
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
        wprintf_s(L"\n Config Not Found !\n 配置文件未发现\n try read reg info\n 尝试读取启动器注册表配置...\n ......");

    _no_config:
        DWORD length = 0x10000;
        wchar_t* szPath = (wchar_t*)VirtualAlloc_Internal(0, length, PAGE_READWRITE);
        if (!szPath)
        {
            Show_Error_Msg(L"Alloc Memory failed! (Get game path)");
            return 0;
        }
        //尝试从注册表获取游戏路径
        DWORD ver_region = 0;
        HKEY htempKey = 0;
        //Software\\Cognosphere\HYP\\1_0\\hk4e_global
        //Software\\Cognosphere\HYP\\1_0\\hkrpg_global
        //Software\\miHoYo\HYP\1_2\\hk4e_cn
        //Software\\miHoYo\HYP\1_2\\hkrpg_cn
		const wchar_t* CNserver = L"Software\\miHoYo\\HYP\\1_2";
		const wchar_t* Globalserver = L"Software\\Cognosphere\\HYP\\1_0";
        if (!RegOpenKeyW(HKEY_CURRENT_USER, CNserver, &htempKey))
        {
            ver_region |= 0x1;
			RegCloseKey(htempKey);
        }
        if (!RegOpenKeyW(HKEY_CURRENT_USER, Globalserver, &htempKey))
        {
            ver_region |= 0x2;
            RegCloseKey(htempKey);
        }
        if(ver_region)
        {
            HKEY hExtKey = 0;
			DWORD ret = 0;
            _ver_result:
            switch (ver_region)
            {
			    case 0x1: //cn
                {
                    {
                        wstring hk4eKey = CNserver;
                        hk4eKey += L"\\hk4e_cn";
                        ret = RegOpenKeyW(HKEY_CURRENT_USER, hk4eKey.c_str(), &hExtKey);
                        if (ret != ERROR_SUCCESS)
                        {
                            goto _reg_getpath_fail;
                        }
                    }
                    ret = RegGetValueW(hExtKey, NULL, L"GameInstallPath", RRF_RT_REG_SZ, NULL, szPath, &length);
                    RegCloseKey(hExtKey);
                    if (ret != ERROR_SUCCESS)
                    {
                        goto _reg_getpath_fail;
                    }
                    else
                    {
                        wchar_t* pstrend = szPath;
                        while (*pstrend != 0) pstrend++;
                        pstrend[0] = L'\\';
                        pstrend[1] = L'Y';
                        pstrend[2] = L'u';
                        pstrend[3] = L'a';
                        pstrend[4] = L'n';
                        pstrend[5] = L'S';
                        pstrend[6] = L'h';
                        pstrend[7] = L'e';
                        pstrend[8] = L'n';
                        pstrend[9] = L'.';
                        pstrend[10] = L'e';
                        pstrend[11] = L'x';
                        pstrend[12] = L'e';
                        pstrend[13] = 0;
                        if (GetFileAttributesW(szPath) != INVALID_FILE_ATTRIBUTES)
                        {
                            GenGamePath = szPath;
                        }
                    }
					{
						wstring hkrpgKey = CNserver;
						hkrpgKey += L"\\hkrpg_cn";
						ret = RegOpenKeyW(HKEY_CURRENT_USER, hkrpgKey.c_str(), &hExtKey);
						if (ret != ERROR_SUCCESS)
						{
							goto _reg_getpath_fail;
						}
					}
                    ret = RegGetValueW(hExtKey, NULL, L"GameInstallPath", RRF_RT_REG_SZ, NULL, szPath, &length);
					RegCloseKey(hExtKey);
                    if (ret != ERROR_SUCCESS)
                    {
                        goto _reg_getpath_fail;
                    }
                    else
                    {
                        wchar_t* pstrend = szPath;
                        while (*pstrend != 0) pstrend++;
                        pstrend[0] = L'\\';
                        pstrend[1] = L'S';
                        pstrend[2] = L't';
                        pstrend[3] = L'a';
                        pstrend[4] = L'r';
                        pstrend[5] = L'R';
                        pstrend[6] = L'a';
                        pstrend[7] = L'i';
                        pstrend[8] = L'l';
                        pstrend[9] = L'.';
                        pstrend[10] = L'e';
                        pstrend[11] = L'x';
                        pstrend[12] = L'e';
                        pstrend[13] = 0;
                        if (GetFileAttributesW(szPath) != INVALID_FILE_ATTRIBUTES)
						{
							HKSRGamePath = szPath;
						}
                    }
					break;
                }
			    case 0x2: //global
                {
                    {
                        wstring hk4eKey = Globalserver;
                        hk4eKey += L"\\hk4e_global";
                        ret = RegOpenKeyW(HKEY_CURRENT_USER, hk4eKey.c_str(), &hExtKey);
                        if (ret != ERROR_SUCCESS)
                        {
                            goto _reg_getpath_fail;
                        }
                    }
					ret = RegGetValueW(hExtKey, NULL, L"\\hk4e_global\\GameInstallPath", RRF_RT_REG_SZ, NULL, szPath, &length);
					RegCloseKey(hExtKey);
					if (ret != ERROR_SUCCESS)
					{
						goto _reg_getpath_fail;
					}
                    else
                    {
                        wchar_t* pstrend = szPath;
                        while (*pstrend != 0) pstrend++;
						pstrend[0] = L'\\';
                        pstrend[1] = L'G';
                        pstrend[2] = L'e';
                        pstrend[3] = L'n';
                        pstrend[4] = L's';
                        pstrend[5] = L'h';
                        pstrend[6] = L'i';
                        pstrend[7] = L'n';
                        pstrend[8] = L'I';
                        pstrend[9] = L'm';
                        pstrend[10] = L'p';
                        pstrend[11] = L'a';
                        pstrend[12] = L'c';
                        pstrend[13] = L't';
                        pstrend[14] = L'.';
                        pstrend[15] = L'e';
                        pstrend[16] = L'x';
                        pstrend[17] = L'e';
                        pstrend[18] = 0;
                        if (GetFileAttributesW(szPath) != INVALID_FILE_ATTRIBUTES)
						{
							GenGamePath = szPath;
						}
                    }
                    {
                        wstring hkrpgKey = Globalserver;
                        hkrpgKey += L"\\hkrpg_global";
                        ret = RegOpenKeyW(HKEY_CURRENT_USER, hkrpgKey.c_str(), &hExtKey);
                        if (ret != ERROR_SUCCESS)
                        {
                            goto _reg_getpath_fail;
                        }
                    }
                    ret = RegGetValueW(hExtKey, NULL, L"GameInstallPath", RRF_RT_REG_SZ, NULL, szPath, &length);
                    RegCloseKey(hExtKey);
                    if (ret != ERROR_SUCCESS)
                    {
                        goto _reg_getpath_fail;
                    }
                    else
                    {
                        wchar_t* pstrend = szPath;
                        while (*pstrend != 0) pstrend++;
                        pstrend[0] = L'\\';
                        pstrend[1] = L'S';
                        pstrend[2] = L't';
                        pstrend[3] = L'a';
                        pstrend[4] = L'r';
                        pstrend[5] = L'R';
                        pstrend[6] = L'a';
                        pstrend[7] = L'i';
                        pstrend[8] = L'l';
                        pstrend[9] = L'.';
                        pstrend[10] = L'e';
                        pstrend[11] = L'x';
                        pstrend[12] = L'e';
                        pstrend[13] = 0;
                        if (GetFileAttributesW(szPath) != INVALID_FILE_ATTRIBUTES)
                        {
                            HKSRGamePath = szPath;
                        }
                    }
                    break;
                }
                case 0x3:
                {
					ret = MessageBoxW_Internal(L"Both CN and Global version registry keys found! Please select the version you want to launch. \
                        \n注册表内有两个版本的启动器，请选择游戏服务器版本\nClick Yes to CN Ver, No to Global Ver\n点“是”使用国服，点“否“使用国际服", L"Version Selection", MB_ICONQUESTION | MB_YESNO);
                    if (ret == 8)
                    {
						ver_region = 0x1; //CN
						goto _ver_result;
					}
					ver_region = 0x2; //Global
					goto _ver_result;
                }
                default:
                    goto _reg_getpath_fail;
            }
            if (isGenshin)
            {
                GamePath = GenGamePath;
            }
            else
            {
                GamePath = HKSRGamePath;
            }
			goto _getpath_done;
        }

		//没有成功获取到,开始进程搜索//不区分版本
    _reg_getpath_fail:
		wprintf_s(L"\n Search Game Path failed! Don't close this window and Try manually boot game \n 获取启动器注册表配置失败，请手动启动游戏获取路径\n");
        if(1)
        {
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

            if (!QueryFullProcessImageNameW(hProcess, 0, szPath, &length))
            {
                Show_Error_Msg(L"Get game path failed!");
                VirtualFree_Internal(szPath, 0, MEM_RELEASE);
                return 0;
            }
            DWORD ExitCode = STILL_ACTIVE;
            while (ExitCode == STILL_ACTIVE)
            {
                // wait for the game to close then continue
                TerminateProcess_Internal(hProcess, 0);
                WaitForSingleObject(hProcess, 2000);
                GetExitCodeProcess(hProcess, &ExitCode);
            }
            CloseHandle_Internal(hProcess);
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

    _getpath_done:
        
        VirtualFree_Internal(szPath, 0, MEM_RELEASE);


        //clean screen
        {
            COORD pos = { 0, 8 };
            HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
            SetConsoleCursorPosition(hOut, pos);
        }
        for (int a = 0; a <= 6; a++)
        {
            for (int i = 0; i <= 16; i++)
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
    isAntimiss = reader.GetBoolean(L"Setting", L"IsAntiMisscontact", isAntimiss);
    Target_set_30 = reader.GetInteger(L"Setting", L"GenShinTarget30", Target_set_30);
    Target_set_60 = reader.GetInteger(L"Setting", L"GenShinTarget60", Target_set_60);
	PowerSave_target = reader.GetInteger(L"Setting", L"PowerSaveTarget", PowerSave_target);
    ErrorMsg_EN = reader.GetBoolean(L"Setting", L"EnableErrorMsg", ErrorMsg_EN);
    AutoExit = reader.GetBoolean(L"Setting", L"AutoExit", AutoExit);
    isHook = reader.GetBoolean(L"Setting", L"IsHookGameSet", isHook);
    ConfigPriorityClass = reader.GetInteger(L"Setting", L"GameProcessPriority", ConfigPriorityClass);
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
    int32_t FpsValue_t = reader.GetInteger(L"Setting", L"FPS", FPS_TARGET);
    if (FpsValue_t > 1000) FpsValue_t = 1000;
    FpsValue = FpsValue_t;
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
                    LPVOID LibPath = malloc((temparg->size() * 2) + 0x10);
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
    uint64_t UI_unhook_time;
    uint64_t Func_gui_set;
    uint64_t Func_input_set;
    uint64_t Grph_class;
    uint32_t Grph_UIcl_VA;
	uint32_t Grph_inputcl_VA;
}Hook_func_list, *PHook_func_list;

typedef struct inject_arg
{
    uint64_t Pfps;//GI-fps-set
    uint64_t Bootui;//HKSR ui /GIui type
    uint64_t verfiy;//code verfiy
    uint64_t P_UnityWndclass;
    uint64_t payloadoep;
    PHook_func_list PfuncList;//Phook_funcPtr_list
}inject_arg, *Pinject_arg;

//Code inject
static uint64_t inject_patch(HANDLE Tar_handle, uintptr_t Tar_ModBase, uintptr_t _ptr_fps, inject_arg* arg)
{
    if (!_ptr_fps)
        return 0;

    BYTE* _sc_buffer = (BYTE*)VirtualAlloc_Internal(0, 0x4000, PAGE_READWRITE);
    if (!_sc_buffer)
    {
        Show_Error_Msg(L"initcode failed!");
        return 0;
    }
    memmove(_sc_buffer, _shellcode_Const, sizeof(_shellcode_Const));

    //shellcode patch
    *(uint32_t*)_sc_buffer = *(uint32_t*)((BYTE*)(__readgsqword(0x30)) + 0x40);     //unlocker PID
    *(uint64_t*)(_sc_buffer + 0x08) = (uint64_t)(&FpsValue);                        //unlocker ptr
    *(uint64_t*)(_sc_buffer + 0x80) = (uint64_t)(&MessageBoxA);
    *(uint64_t*)(_sc_buffer + 0x88) = (uint64_t)(&CloseHandle);
    *(uint64_t*)(_sc_buffer + 0x90) = (uint64_t)(&GetForegroundWindow);
    //onlyGI
    *(uint32_t*)(_sc_buffer + 0x150) = Target_set_60;
    *(uint32_t*)(_sc_buffer + 0x158) = Target_set_30;

    //Disable errmsg
    if (AutoExit)
    {
        *(uint16_t*)(_sc_buffer + 0x18A) = 0x3AEB;
    }

    //genshin_get_gamefpsset
    if (arg->Pfps)
    {
        *(uint64_t*)(_sc_buffer + 0x10) = arg->Pfps;
    }

    if (!isGenshin)
    {
        *(uint64_t*)(_sc_buffer + 0x18) = _ptr_fps;
    }

    LPVOID Remote_payload_buffer = VirtualAllocEx_Internal(Tar_handle, NULL, 0x4000, PAGE_READWRITE);
    if (!Remote_payload_buffer)
    {
        Show_Error_Msg(L"AllocEx Fail! ");
        return 0;
    }

    uint64_t hook_info_ptr = ((uint64_t)_sc_buffer + 0x2000);
    PHook_func_list GI_Func = (PHook_func_list)arg->PfuncList;
    if (arg->P_UnityWndclass)
    {
        *(uint64_t*)(_sc_buffer + 0x30) = (uint64_t)Remote_payload_buffer + PowerSaveSet_FuncVA;
        *(uint64_t*)(_sc_buffer + PowerSaveSet_FuncVA + 0x10) = arg->P_UnityWndclass;
        *(uint32_t*)(_sc_buffer + PowerSaveSet_FuncVA + 0x1C) = PowerSave_target;//power_save_targetfps
    }
    else
    {
        *(uint64_t*)(_sc_buffer + PowerSaveSet_FuncVA) = 0xCCC3C889;
    }
    if ((!isGenshin) && arg->Bootui)
    {
        *(uint64_t*)(_sc_buffer + 0x20) = arg->Bootui;//HKSR mobile uisetptr
        *(uint32_t*)(_sc_buffer + 0x28) = 2;
        *(uint64_t*)(_sc_buffer + 0x30) = (uint64_t)Remote_payload_buffer + HKSR_UISet_FuncVA;
    }
    if (isGenshin && GI_Func)
    {
        //hookverfiy
        if (arg->verfiy)
        {
            *(uint64_t*)(_sc_buffer + 0x20) = ((uint64_t)Remote_payload_buffer + 0x2000);//Hookinfo_buffer
            *(uint64_t*)(_sc_buffer + 0x28) = arg->verfiy;//func
            if (!ReadProcessMemoryInternal(Tar_handle, (void*)arg->verfiy, (_sc_buffer + 0x60), 0x10, 0))
            {
                Show_Error_Msg(L"Failed ReadFunc 0xFF (GIverf)");
                goto __exit_block;
            }
            uint64_t* hook_pa = (uint64_t*)(_sc_buffer + 0x70);
            *hook_pa = 0x225FF;
            *(hook_pa + 1) = ((uint64_t)Remote_payload_buffer + GI_hooked_Vfunc_VA);
            if (!WriteProcessMemoryInternal(Tar_handle, (void*)arg->verfiy, hook_pa, 0x10, 0))
            {
                Show_Error_Msg(L"Failed hook (GIverf)");
                goto __exit_block;
            }
        }
        if (1)//basefps
        {
            uint64_t Private_buffer = 0;
            for (uint64_t buffer = 0x10000; !Private_buffer && buffer < 0x7FFF8000; buffer += 0x1000)
            {
                Private_buffer = (uint64_t)VirtualAllocEx_Internal(Tar_handle, (void*)(Tar_ModBase - buffer), 0x1000, PAGE_READWRITE);
            }
            if (!Private_buffer)
            {
                Show_Error_Msg(L"AllocEx Fail! (Base_fps)");
                return 0;
            }
            *(uint64_t*)(_sc_buffer + 0x18) = Private_buffer;
            uint64_t alienaddr = _ptr_fps & 0xFFFFFFFFFFFFFFF8;
            Phooked_func_struct Pfps_patch = (Phooked_func_struct)hook_info_ptr;
            Pfps_patch->func_addr = alienaddr;
            if (!ReadProcessMemoryInternal(Tar_handle, (void*)alienaddr, (void*)&Pfps_patch->orgpart, 0x10, 0))
            {
                Show_Error_Msg(L"Failed Readfpspart (Base_fps)");
                return 0;
            }
            Pfps_patch->hookedpart = Pfps_patch->orgpart;
            uint8_t mask = _ptr_fps & 0x7;
            int32_t immva = (int64_t)((Private_buffer - _ptr_fps) - 4);
            *(int32_t*)(((uint64_t)(&Pfps_patch->hookedpart)) + mask) = immva;
            hook_info_ptr = (uint64_t)hook_info_ptr + sizeof(hooked_func_struct);
        }

        if (GI_Func->UI_unhook_time)
        {
            *(uint64_t*)(_sc_buffer + 0x40) = GI_Func->UI_unhook_time;
            *(uint64_t*)(_sc_buffer + 0x48) = (uint64_t)Remote_payload_buffer + 0x3000;
			memcpy(_sc_buffer + 0x3000, &GI_Func->Func_gui_set, sizeof(Hook_func_list) - sizeof(uint64_t));
            if (ReadProcessMemoryInternal(Tar_handle, (void*)GI_Func->UI_unhook_time, (_sc_buffer + 0x50), 0x10, 0))
            {
                uint64_t hookpart[2] = { 0x225FF,  ((uint64_t)Remote_payload_buffer + GI_UnHooked_UI_fVA) };
                if (!WriteProcessMemoryInternal(Tar_handle, (void*)GI_Func->UI_unhook_time, &hookpart, 0x10, 0))
                    Show_Error_Msg(L"Failed write payload 0(GIui)");
            }
            else Show_Error_Msg(L"Failed ReadFunc 0 (GIui)");
        }
    }
__exit_block:

    if (!WriteProcessMemoryInternal(Tar_handle, Remote_payload_buffer, (void*)_sc_buffer, 0x4000, 0))
    {
        Show_Error_Msg(L"Write Scode Fail! ");
        return 0;
    }
    VirtualFree_Internal(_sc_buffer, 0, MEM_RELEASE);
    if (VirtualProtectEx_Internal(Tar_handle, Remote_payload_buffer, 0x4000, PAGE_EXECUTE_READWRITE, 0))
    {
        HANDLE hThread = 0;
        if (arg->payloadoep)
        {
            hThread = CreateRemoteThreadEx_Internal(Tar_handle, 0, (LPTHREAD_START_ROUTINE)arg->payloadoep, (LPVOID)((uint64_t)Remote_payload_buffer + shellcode_entryVA));
        }
        else
        {
            hThread = CreateRemoteThreadEx_Internal(Tar_handle, 0, (LPTHREAD_START_ROUTINE)((uint64_t)Remote_payload_buffer + shellcode_entryVA), NULL);
        }
        if (!hThread)
        {
            Show_Error_Msg(L"Create SyncThread Fail! ");
            return 0;
        }
        WaitForSingleObject(hThread, 1000);
        if (1)
        {
            int32_t ecode = GetExitCodeThread_Internal(hThread);
            if (ecode < 0)
            {
                BaseSetLastNTError_inter(ecode);
                Show_Error_Msg(L"GameSyncThread may Crashed!");
                CloseHandle_Internal(hThread);
                ExitProcess(0);
            }
        }
        CloseHandle_Internal(hThread);
        return ((uint64_t)Remote_payload_buffer);
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
        if (GetFileAttributesW(DllPath) != INVALID_FILE_ATTRIBUTES)
        {
            goto __inject_proc;
        }
		Show_Error_Msg(L"DllPath Not Found!");
        return 0;
    }
    else
    {
        PPEB64 peb_base = GetProcessPEB(Tar_handle);
        HMODULE result = 0;
        if (!ReadProcessMemoryInternal(Tar_handle, ((PBYTE)peb_base + 0x10), &result, 0x8, 0))
            return 0;
        return result;
    }

__inject_proc:
    LPVOID buffer = VirtualAllocEx_Internal(Tar_handle, NULL, Pathsize, PAGE_READWRITE);
    if (buffer)
    {
        HMODULE result = 0;
        DWORD64 payload[4] = { 0 };
        if (1)
        {
            payload[0] = 0xB848C03138EC8348;
            payload[1] = (DWORD64)&LoadLibraryW;
            payload[2] = 0xFE605894890D0FF;
            payload[3] = 0xCCC338C483480000;
        }
        if (WriteProcessMemoryInternal(Tar_handle, buffer, &payload, 0x20, 0))
        {
            if (VirtualProtectEx_Internal(Tar_handle, buffer, 0x1000, PAGE_EXECUTE_READ, 0))
            {
                LPVOID RCX = 0;
                if (1)
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
                    }
                    else
                    {
                        ReadProcessMemoryInternal(Tar_handle, ((PBYTE)buffer + 0x1000), &result, 0x8, 0);
                    }
                    CloseHandle_Internal(hThread);
                }
            }
        }
        VirtualFreeEx_Internal(Tar_handle, buffer, 0, MEM_RELEASE);
        return result;
    }
    return 0;
}


static HMODULE RemoteDll_Inject_mem(HANDLE Tar_handle, LPCWSTR DllPath)
{
    LPVOID buffer = 0;
    SIZE_T file_size = 0;
    if (DllPath)
    {
        HANDLE file_Handle = CreateFileW(DllPath, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (file_Handle != INVALID_HANDLE_VALUE)
        {
            GetFileSizeEx(file_Handle, (PLARGE_INTEGER)&file_size);
            buffer = VirtualAlloc_Internal(NULL, file_size, PAGE_READWRITE);
            if (!buffer)
            {
                Show_Error_Msg(L"VirtualAlloc Failed! (loadlib mem)");
                CloseHandle_Internal(file_Handle);
                return 0;
            }
            if (ReadFile(file_Handle, buffer, file_size, NULL, NULL))
            {
                if (*(WORD*)buffer == 0x5A4D)
                {
                    CloseHandle_Internal(file_Handle);
                    goto __inject_proc;
                }
                else
                {
                    Show_Error_Msg(L"Bad PE file (loadlib mem)");
                }
            }
            else
            {
                Show_Error_Msg(L"ReadFile Failed! (loadlib mem)");
            }
            CloseHandle_Internal(file_Handle);
            VirtualFree_Internal(buffer, 0, MEM_RELEASE);
            return 0;
        }
        Show_Error_Msg(L"Open LibFile Failed!");
    }
    return 0;

__inject_proc:
    HMODULE result = 0;
    LPVOID buffer_load = VirtualAllocEx_Internal(Tar_handle, NULL, 0x2000, PAGE_READWRITE);
    LPVOID shell_mem_load = VirtualAllocEx_Internal(Tar_handle, NULL, sizeof(_PE_MEM_LOADER), PAGE_READWRITE);
    LPVOID file_buffer = VirtualAllocEx_Internal(Tar_handle, NULL, file_size, PAGE_READWRITE);
    if (buffer_load && shell_mem_load && file_buffer)
    {
        DWORD64 payload[5] = { 0 };
        payload[0] = 0x15FFC03128EC8348;
        payload[1] = 0x0589484800000014;
        payload[2] = 0x8348C03300000FEC;
        payload[3] = 0xCCCCCCCCCCC328C4;
        payload[4] = (DWORD64)shell_mem_load;
        if (WriteProcessMemoryInternal(Tar_handle, buffer_load, &payload, 0x30, 0) &&
            WriteProcessMemoryInternal(Tar_handle, shell_mem_load, (LPVOID)&_PE_MEM_LOADER, sizeof(_PE_MEM_LOADER), 0) &&
            WriteProcessMemoryInternal(Tar_handle, file_buffer, buffer, file_size, 0))
        {
            VirtualFree_Internal(buffer, 0, MEM_RELEASE);
            if (VirtualProtectEx_Internal(Tar_handle, buffer_load, 0x1000, PAGE_EXECUTE_READ, 0) &&
                VirtualProtectEx_Internal(Tar_handle, shell_mem_load, sizeof(_PE_MEM_LOADER), PAGE_EXECUTE_READWRITE, 0) &&
                VirtualProtectEx_Internal(Tar_handle, file_buffer, file_size, PAGE_READONLY, 0))
            {
                HANDLE hThread = CreateRemoteThreadEx_Internal(Tar_handle, 0, (LPTHREAD_START_ROUTINE)buffer_load, file_buffer);
                if (hThread)
                {
                    if (WaitForSingleObject(hThread, 60000))
                    {
                        Show_Error_Msg(L"Lib load Wait Time out!");
                        CloseHandle_Internal(hThread);
                        goto __failure_safe_exit;
                    }
                    else
                    {
                        int32_t ecode = GetExitCodeThread_Internal(hThread);
                        if (ecode < 0)
                        {
                            BaseSetLastNTError_inter(ecode);
                            Show_Error_Msg(L"Lib load has an error occurred! Game has crashed");
                            CloseHandle_Internal(hThread);
                            ExitProcess(0);
                        }
                        else
                        {
                            ReadProcessMemoryInternal(Tar_handle, ((BYTE*)buffer_load) + 0x1000, &result, 0x8, 0);
                        }
                    }
                    CloseHandle_Internal(hThread);
                }
                else
                {
                    Show_Error_Msg(L"CreateThread Failed! (loadlib mem)");
                }
            }
            else
            {
                Show_Error_Msg(L"VirtualProtectEx Failed! (loadlib mem)");
            }
        }
        else
        {
            Show_Error_Msg(L"WriteProcessMemory Failed! (loadlib mem)");
        }
    }
    else
    {
        Show_Error_Msg(L"VirtualAllocEx Failed! (loadlib mem)");
    }
    VirtualFreeEx_Internal(Tar_handle, buffer_load, 0, MEM_RELEASE);
    VirtualFreeEx_Internal(Tar_handle, file_buffer, 0, MEM_RELEASE);
    VirtualFreeEx_Internal(Tar_handle, shell_mem_load, 0, MEM_RELEASE);
__failure_safe_exit:
    VirtualFree_Internal(buffer, 0, MEM_RELEASE);
    return result;
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
        if (address = PatternScan_Region((uintptr_t)Ua_il2cpp_RVA, Ua_il2cpp_Vsize, "80 B9 ?? ?? ?? ?? 00 0F 84 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 03 00 00 00 48 83 C4 20 5E C3"))
        {
            tar_addr = address + 15;
        }
        else if (address = PatternScan_Region((uintptr_t)Ua_il2cpp_RVA, Ua_il2cpp_Vsize, "80 B9 ?? ?? ?? ?? 00 74 ?? C7 05 ?? ?? ?? ?? 03 00 00 00 48 83 C4 20 5E C3"))
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
    
    wprintf_s(L"FPS unlocker 2.9.2\n\nThis program is OpenSource in this link\n https://github.com/winTEuser/Genshin_StarRail_fps_unlocker \n这个程序开源,链接如上\n\nNTKver: %u\nNTDLLver: %u\n", (uint32_t)*(uint16_t*)(0x7FFE0260), ParseOSBuildBumber());

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
        HANDLE file_Handle = CreateFileW(ProcessPath->c_str(), GENERIC_ALL, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (file_Handle != INVALID_HANDLE_VALUE)
        {
            DWORD64 Size = 0;
            GetFileSizeEx(file_Handle, (PLARGE_INTEGER)(&Size));
            if (Size < 0x800000) is_old_version = 1;
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
    LPVOID _imgbase_PE_buffer = 0;
    uintptr_t Text_Remote_RVA = 0;
    uintptr_t Unityplayer_baseAddr = 0;
    uint32_t Text_Vsize = 0;
    
    _imgbase_PE_buffer = VirtualAlloc_Internal(0, 0x1000, PAGE_READWRITE);
    if (_imgbase_PE_buffer == 0)
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
        if (ReadProcessMemoryInternal(pi->hProcess, (void*)Unityplayer_baseAddr, _imgbase_PE_buffer, 0x1000, 0))
        {
            if (Get_Section_info((uintptr_t)_imgbase_PE_buffer, ".text", &Text_Vsize, &Text_Remote_RVA, Unityplayer_baseAddr))
                goto __Get_target_sec;
        }
    }
    
    Show_Error_Msg(L"Get Target Section Fail! (text)");
    VirtualFree_Internal(_imgbase_PE_buffer, 0, MEM_RELEASE);
    TerminateProcess_Internal(pi->hProcess, 0);
    CloseHandle_Internal(pi->hProcess);
    return 0;
    

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
	// Read .text section to localmemory
    if (ReadProcessMemoryInternal(pi->hProcess, (void*)Text_Remote_RVA, Copy_Text_VA, Text_Vsize, 0) == 0)
    {
        Show_Error_Msg(L"Readmem Fail ! (text)");
        VirtualFree_Internal(Copy_Text_VA, 0, MEM_RELEASE);
        TerminateProcess_Internal(pi->hProcess, 0);
        CloseHandle_Internal(pi->hProcess);
        return 0;
    }

    uintptr_t pfps = 0;
    uintptr_t address = 0;
    if (isGenshin)
    {
		address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "0F 10 05 ?? ?? ?? ?? 0F 11 41 ?? 0F 10 05 ?? ?? ?? ?? 0F 11 41 ?? 0F 10 05 ?? ?? ?? ?? 0F 11 41 ?? 0F 10 05 ?? ?? ?? ?? 0F 11 01");
        if (address)
        {
            int64_t rip = address;
            rip += 0x24;
            rip += *(int32_t*)(rip)+4;
            rip = rip - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
			uint8_t* strbuffer = (uint8_t*)malloc(0x50);
            if (strbuffer)
            {
                if (ReadProcessMemoryInternal(pi->hProcess, (void*)rip, strbuffer, 0x50, 0))
                {
					printf_s("Genshin ver sign: %s\n", strbuffer);
                }
                free(strbuffer);
			}
        }
        else
        {
            wprintf_s(L"Unknown game ver\n");
		}
    }
    //Get UnityWndclass addr
    if (1)
    {
        address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "C7 44 24 28 00 00 00 80 C7 44 24 20 00 00 00 80 FF 15 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 48 85 C0");
        if (address)
        {
            int64_t rip = address;
            rip += 0x19;
            rip += *(int32_t*)(rip)+4;
            injectarg.P_UnityWndclass = rip - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
        }
        else
        {
            wprintf_s(L"HWND Partten outdate...");
        }
    }
    if (1)
    {
        address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "48 83 EC 28 FF D1 31 C0 48 83 C4 28 C3");
        if (address)
        {
            injectarg.payloadoep = address - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
        }
        else
        {
            uintptr_t* buffer = (uintptr_t*)VirtualAlloc_Internal(0, 0x20000, PAGE_READWRITE);
            if (buffer)
            {
                PatternScanInfo info;
                info.buffer = buffer;
                info.maxCount = (0x20000 / sizeof(uintptr_t));
                address = PatternScanRegionEx((uintptr_t)Copy_Text_VA, Text_Vsize, "FF E1", &info);
                if (address)
                {
                    DWORD64 randnum;
					_rdrand64_step(&randnum);
                    address = buffer[((randnum ^ (DWORD64)address) % (info.count + 1))];
                    injectarg.payloadoep = address - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
                }
				VirtualFree_Internal(buffer, 0, MEM_RELEASE);
            }
        }
    }
    //get fps ptr
    if (isGenshin)
    {
        //66 0F 6E 0D ?? ?? ?? ?? 0F 57 C0 0F 5B C9
        address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "66 0F 6E 0D ?? ?? ?? ?? 0F 57 C0 0F 5B C9");//5.5
        if (address)
        {
            int64_t rip = address;
            rip += 4;
            //rip += *(int32_t*)(rip)+4;
            pfps = rip - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
            goto __genshin_il;
        }
        address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "7E 0C E8 ?? ?? ?? ?? 66 0F 6E C8 0F 5B C9");//5.4
        if (address)
        {
            int64_t rip = address;
            rip += 3;
            rip += *(int32_t*)(rip) + 6;
            //rip += *(int32_t*)(rip) + 4;
            pfps = rip - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
            goto __genshin_il;
        }
        address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "7F 0E E8 ?? ?? ?? ?? 66 0F 6E C8"); // ver 3.7 - 5.3 
        if (address)
        {
            int64_t rip = address;
            rip += 3;
            rip += *(int32_t*)(rip) + 6;
            //rip += *(int32_t*)(rip) + 4;
            pfps = rip - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
            goto __genshin_il;
        }
        address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "7F 0F 8B 05 ?? ?? ?? ?? 66 0F 6E C8"); // ver old
        if (address)
        {
            int64_t rip = address;
            rip += 4;
            //rip += *(int32_t*)(rip) + 4;
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
    if(1)
    {
        uintptr_t UA_baseAddr = Unityplayer_baseAddr;
        if (is_old_version)
        {
            wstring il2cppPath = *ProcessDir;
            il2cppPath += L"\\YuanShen_Data\\Native\\UserAssembly.dll";
            UA_baseAddr = (uintptr_t)RemoteDll_Inject(pi->hProcess, il2cppPath.c_str());
            if (UA_baseAddr)
            {
                if (!ReadProcessMemoryInternal(pi->hProcess, (void*)UA_baseAddr, _imgbase_PE_buffer, 0x1000, 0))
                {
                    goto __procfail;
                }
            }
        }
        if (Get_Section_info((uintptr_t)_imgbase_PE_buffer, "il2cpp", &Text_Vsize, &Text_Remote_RVA, UA_baseAddr))
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
        address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "E8 ?? ?? ?? ?? EB 0D 48 89 F1 BA 02 00 00 00 E8 ?? ?? ?? ?? 48 89 F1 31 D2");
        if (address)
        {
            int64_t rip = address;
            rip += 0x1;
            rip += *(int32_t*)(rip)+4;
            injectarg.verfiy = rip - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
        }
        else if (address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "E8 ?? ?? ?? ?? EB 0D 48 89 F1 BA 02 00 00 00 E8 ?? ?? ?? ?? 48 8B 0D"))
        {
            int64_t rip = address;
            rip += 0x1;
            rip += *(int32_t*)(rip)+4;
            injectarg.verfiy = rip - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
        }
        else
        {
            Show_Error_Msg(L"GetFunc Fail ! GIxv");
            TerminateProcess_Internal(pi->hProcess, 0);
            CloseHandle_Internal(pi->hProcess);
            return 0;
        }
        if (Use_mobile_UI)
        {
            address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "48 8B 05 ?? ?? ?? ?? 48 8B 88 ?? ?? ?? ?? 48 85 C9 0F ?? ?? ?? ?? ?? BA 02 00 00 00 E8 ?? ?? ?? ?? 48 89 F9 BA 03 00 00 00 E8");
            if (address)
            {
                int64_t rip = address;
                rip += 0x3;
                rip += *(int32_t*)(rip)+4;
                GI_Func.Grph_class = rip - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
				rip = address + 0xA;
				GI_Func.Grph_UIcl_VA = *(int32_t*)(rip);
                rip = address + 0x1D;
				rip += *(int32_t*)(rip)+4;
                GI_Func.Func_gui_set = rip - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
				rip = address + 0x2A;
				rip += *(int32_t*)(rip)+4;
                GI_Func.Func_input_set = rip - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
            }
            else
            {
                Use_mobile_UI = 0;
            }
            address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "48 8B 05 ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 48 8B B8 ?? ?? ?? ?? 48 85 FF 0F 84 ?? ?? ?? ?? 83 BF ?? ?? ?? ?? 03");
            if (address)
            {
                int64_t rip = address;
                rip += 0x10;
                GI_Func.Grph_inputcl_VA = *(int32_t*)(rip);
            }
            else
            {
                Use_mobile_UI = 0;
			}

            //Unhook_hook
            //old 48 89 F1 E8 ?? ?? ?? ?? 48 89 D9 E8 ?? ?? ?? ?? 80 3D ?? ?? ?? ?? 00 0F 85 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 80 B9 ?? ?? ?? ?? 00
            address = PatternScan_Region((uintptr_t)Copy_Text_VA, Text_Vsize, "E8 ?? ?? ?? ?? 48 89 D9 E8 ?? ?? ?? ?? 80 3D ?? ?? ?? ?? 00 0F 85 ?? ?? ?? ?? 48 8B 0D");
            if (address)
            {
                int64_t rip = address;
                rip += 0x9;
                rip += *(int32_t*)(rip)+4;
                GI_Func.UI_unhook_time = rip - (uintptr_t)Copy_Text_VA + Text_Remote_RVA;
            }
            else
            {
                Use_mobile_UI = 0;
            }
        }
		injectarg.PfuncList = &GI_Func;
    }

__Continue:
    wprintf_s(L"Inject...\n");
    uintptr_t Patch_buffer = inject_patch(pi->hProcess, Unityplayer_baseAddr, pfps, &injectarg);
    if (!Patch_buffer)
    {
        Show_Error_Msg(L"Inject Fail !!\n");
        TerminateProcess_Internal(pi->hProcess, 0);
        CloseHandle_Internal(pi->hProcess);
        return 0;
    }

    if (barg.Path_Lib)
    {
        HMODULE mod = 0;
        DWORD dret = MessageBoxW_Internal(L"You may be banned for using this feature. Make sure you had checked the source and credibility of the plugin.\n\nClick Ok use mem load, Cancel to normal load", L"Load Info", 0x01);
        if (dret == 6)
        {
            mod = RemoteDll_Inject_mem(pi->hProcess, barg.Path_Lib);
        }
        else
        {
            mod = RemoteDll_Inject(pi->hProcess, barg.Path_Lib);
        }
        wstring str_addr = To_Hexwstring_64bit((uint64_t)mod);
        wprintf_s(L"Plugin BaseAddr : 0x%s", str_addr.c_str());
        free(barg.Path_Lib);
    }
    
    DelWstring(&ProcessPath);
    DelWstring(&ProcessDir);
    DelWstring(&procname);

    VirtualFree_Internal(_imgbase_PE_buffer, 0, MEM_RELEASE);
    VirtualFree_Internal(Copy_Text_VA, 0, MEM_RELEASE);
    
	//SetThreadAffinityMask(pi->hThread, 0xF);
	SetThreadPriority(pi->hThread, THREAD_PRIORITY_TIME_CRITICAL);
    ResumeThread_Internal(pi->hThread);
    CloseHandle_Internal(pi->hThread);
    
    SetPriorityClass((HANDLE) -1, NORMAL_PRIORITY_CLASS);

    wprintf_s(L"PID: %d\n \nDone! \n \n", pi->dwProcessId);

    if(!AutoExit)
    {
        wprintf_s(L"Use ↑ ↓ ← → key to change fps limted\n使用键盘上的方向键调节帧率限制\n\n\n  UpKey : +20\n  DownKey : -20\n  LeftKey : -2\n  RightKey : +2\n\n");

        // 创建printf线程
        HANDLE hdisplay = CreateRemoteThreadEx_Internal((HANDLE)-1, 0, Thread_display, 0);
        if (!hdisplay)
            Show_Error_Msg(L"Create Thread <Thread_display> Error! ");

        uint32_t fps = FpsValue;
        uint32_t cycle_counter = 0;
        while (1)   // handle key input
        {
            NtSleep(50);
            cycle_counter++;
            if (GetExitCodeProcess_Internal(pi->hProcess) != STILL_ACTIVE)
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
            if (fps > 1000)
            {
                fps = 1000;
            }
        }
        Process_endstate = 1;
        WaitForSingleObject(hdisplay, INFINITE);
        CloseHandle_Internal(hdisplay);
    }
    else
    {
        wprintf_s(L"Exit......");
        NtSleep(2000);
    }
    CloseHandle_Internal(pi->hProcess);
    free(boot_info);
    
    
    return 1;
}





