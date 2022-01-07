#ifndef _WINDOWS

#include <stdint.h>
#include <stdlib.h>

#define CALLBACK
#define WINAPI

typedef uint32_t DWORD, *PDWORD;
typedef int16_t SHORT, *PSHORT;
typedef uint16_t USHORT, *PUSHORT;

typedef char CHAR;
typedef uint8_t BYTE;
typedef uint8_t *PBYTE;
typedef int16_t SHORT;
typedef uint16_t USHORT, WORD;
typedef int32_t BOOL;
typedef int32_t INT, INT32;
typedef uint32_t UINT, UINT32;
typedef int64_t INT64, LONG64;
typedef uint64_t UINT64;
typedef long long LONGLONG;
typedef void VOID, *HMODULE, *PVOID, *LPVOID;
#define TRUE ((BOOL)1)
#define FALSE ((BOOL)0)
typedef long LONG;
typedef unsigned long ULONG, *PULONG;
typedef uintptr_t ULONG_PTR;
typedef intptr_t LONG_PTR;
typedef size_t SIZE_T;

typedef char *LPSTR;
typedef const char *LPCSTR;
typedef const void *LPCVOID;
typedef void *HANDLE;

#define ERROR_INVALID_DATA 0x10001
#define ERROR_INVALID_OPERATION 0x10002
#define ERROR_NOT_ENOUGH_MEMORY 0x10003
#define ERROR_INVALID_PARAMETER 0x10004
#define ERROR_INVALID_HANDLE 0x10005
#define ERROR_INVALID_BLOCK 0x10006
#define ERROR_DYNAMIC_CODE_BLOCKED 0x10007
#define ERROR_NOT_SAME_THREAD 0x10020

#define ERROR_MACH_FAIL_BASE 0x20100
#define ERROR_ERRNO_FAIL_BASE 0x20200
#define NO_ERROR 0

extern "C" {
extern void SetLastError(int err);
extern int GetLastError();
}

static int GetCurrentThreadId() {
    return 0;
}

static HANDLE GetCurrentThread() {
    return (HANDLE)-2;
}

static HANDLE GetCurrentProcess() {
    return (HANDLE)-1;
}

#else

#include <windows.h>

#endif // _WINDOWS


#ifdef DETOURS_INTERNAL
extern "C" {
static unsigned long DetourGetModuleSize(void *) {
    return 0x1337;
}
}
#ifndef _WINDOWS

#include <stdio.h>
#include <stddef.h>
#include <memory.h>

#include <unistd.h>
#include <errno.h>

#ifdef _LINUX
#include <fcntl.h>
#include <sys/mman.h>
#endif

#ifdef _DARWIN
#include <unistd.h>
#include <mach/mach.h> 
#include <mach/vm_region.h>
#include <mach/vm_map.h>
#endif

#define C_ASSERT(e) typedef char __C_ASSERT__[(e)?1:-1]
#define ARRAYSIZE(A) (sizeof(A)/sizeof(A[0]))

#define UNALIGNED

#define UNREFERENCED_PARAMETER(P) (P)

static inline
LONG InterlockedCompareExchange(LONG *ptr, LONG nval, LONG oval)
{
    return __sync_val_compare_and_swap (ptr, nval, oval);
}

static inline ULONG PtrToUlong(PVOID ptr) {
    return (ULONG)(ptr);
}

static void CopyMemory(
        PVOID  Destination,
  const VOID   *Source,
        SIZE_T Length
) {
    memcpy(Destination, Source, Length);
}

#define PAGE_READ 1
#define PAGE_WRITE 2 
#define PAGE_EXECUTE 4
#define PAGE_READONLY (PAGE_READ)
#define PAGE_READWRITE (PAGE_READ | PAGE_WRITE)
#define PAGE_EXECUTE_READ (PAGE_READ | PAGE_EXECUTE)
#define PAGE_EXECUTE_READWRITE (PAGE_READ | PAGE_WRITE | PAGE_EXECUTE)

#define MEM_COMMIT 0x00001000
#define MEM_FREE   0x00010000
#define MEM_RESERVE 0x00002000

#define MEM_RELEASE 0

typedef struct _MEMORY_BASIC_INFORMATION {
  PVOID  BaseAddress;
  PVOID  AllocationBase;
  DWORD  AllocationProtect;
  WORD   PartitionId;
  SIZE_T RegionSize;
  DWORD  State;
  DWORD  Protect;
  DWORD  Type;
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;

static SIZE_T VirtualQuery(
  LPCVOID                   lpAddress,
  PMEMORY_BASIC_INFORMATION lpBuffer,
  SIZE_T                    dwLength
) {
    if (!lpBuffer) return 0;
#if defined(_LINUX)
    int a = 0;
    unsigned int prot = 0;
    int f = open("/proc/self/maps", O_RDONLY);
    char b[1024] = { 0 };
    int b_pos = 0;
    unsigned long last_addr0 = 0, last_addr1 = 0;
    while ((read(f, &a, 1)) >= 0) {
        b[b_pos++] = a;
        if (b_pos >= sizeof(b) || a == '\n') {
            char*end0 = NULL;
            unsigned long addr0 = strtoul(b, &end0, 16);
            char*end1 = NULL;
            unsigned long addr1 = strtoul(end0+1, &end1, 16);
            if ((void*)addr0 <= lpAddress && lpAddress < (void*)addr1) {
                lpBuffer->BaseAddress = (PVOID)addr0;
                lpBuffer->AllocationBase = (PVOID)addr0;
                lpBuffer->RegionSize = addr1 - addr0;
                prot |= (end1+1)[0] == 'r' ? PAGE_READ : 0;
                prot |= (end1+1)[1] == 'w' ? PAGE_WRITE : 0;
                prot |= (end1+1)[2] == 'x' ? PAGE_EXECUTE : 0;
                prot |= (end1+1)[3] == 'p' ? 0
                     : (end1+1)[3] == 's' ? 0 : 0;
                lpBuffer->AllocationProtect = prot;
                lpBuffer->PartitionId = 0;
                lpBuffer->State = MEM_COMMIT;
                break;
            } else if (lpAddress < (void*)addr0) {
                lpBuffer->BaseAddress = (PVOID)last_addr1;
                lpBuffer->AllocationBase = (PVOID)addr0;
                lpBuffer->RegionSize = addr0 - last_addr1;
                lpBuffer->AllocationProtect = 0;
                lpBuffer->PartitionId = 0;
                lpBuffer->State = MEM_FREE;
                break;
            }
            memset(b, 0, sizeof(b));
            b_pos = 0;
            last_addr0 = addr0;
            last_addr1 = addr1;
        }
    }
    
    close(f);
    return sizeof(MEMORY_BASIC_INFORMATION);
#elif defined(_DARWIN)
    kern_return_t kr = KERN_SUCCESS;
    mach_port_t object_name;
    mach_vm_size_t size_info;
    mach_vm_address_t address_info = address;
    mach_msg_type_number_t info_cnt = sizeof (vm_region_basic_info_data_64_t);
    vm_region_basic_info_data_64_t info;
    kr = mach_vm_region(mach_task_self(), &address_info, &size_info, VM_REGION_BASIC_INFO_64, (vm_region_info_t)info, &info_cnt, &object_name);
    if (kr) {
        SetLastError(kr + ERROR_TFP_FAIL_BASE);
    }
    lpAddress->BaseAddress = (PVOID)address_info;
    lpAddress->AllocationBase = (PVOID)address_info;
    lpAddress->RegionSize = size_info;
    prot |= info.protection & VM_PROT_READ ? PAGE_READ : 0;
    prot |= info.protection & VM_PROT_WRITE ? PAGE_WRITE : 0;
    prot |= info.protection & VM_PROT_EXECUTE ? PAGE_EXECUTE : 0;
    lpAddress->AllocationProtect = prot;
    lpAddress->PartitionId = 0;
    lpAddress->State = MEM_COMMIT;
    return sizeof(MEMORY_BASIC_INFORMATION);
#endif
    return 0;
}

static BOOL VirtualProtect(PVOID addr, SIZE_T dwSize, DWORD flNewProtect, DWORD *flOld) {
    int newR = flNewProtect & PAGE_READ;
    int newW = flNewProtect & PAGE_WRITE;
    int newX = flNewProtect & PAGE_EXECUTE;
#if defined(_LINUX) || defined(_DARWIN)
    LONG aligned_addr = (LONG)addr & ~(getpagesize() - 1);
    SIZE_T aligned_size = (LONG)addr - aligned_addr + dwSize;
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((void *)aligned_addr, &mbi, sizeof(mbi))) {
        return FALSE;
    }
    int oldProt = mbi.AllocationProtect;
    int newProt = 0;
    newProt |= newR ? PROT_READ : 0;
    newProt |= newW ? PROT_WRITE : 0;
    newProt |= newX ? PROT_EXEC : 0;
    int ret = mprotect((void *)aligned_addr, aligned_size, newProt);
    if (ret == -1){
        SetLastError(ERROR_ERRNO_FAIL_BASE + errno);
        return FALSE;
    }
    *flOld = oldProt;
    return TRUE;
#else
#error Unknown OS (Please define _LINUX or _DARWIN)
#endif
    return FALSE;
}

static LPVOID VirtualAlloc(
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
) {
    int newR = flProtect & PAGE_READ;
    int newW = flProtect & PAGE_WRITE;
    int newX = flProtect & PAGE_EXECUTE;
    int newProt = 0;
    newProt |= newR ? PROT_READ : 0;
    newProt |= newW ? PROT_WRITE : 0;
    newProt |= newX ? PROT_EXEC : 0;

    LPVOID retAddr = mmap(lpAddress, dwSize, newProt, MAP_SHARED | MAP_ANONYMOUS, 0, 0);
    if (!retAddr) {
        SetLastError(ERROR_ERRNO_FAIL_BASE + errno);
        return NULL;
    }
    return retAddr;
}

static BOOL FlushInstructionCache(
  HANDLE  hProcess,
  LPCVOID lpBaseAddress,
  SIZE_T  dwSize
) {
    return TRUE;
}

static BOOL VirtualFree(
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  dwFreeType
) {
    if(munmap(lpAddress, dwSize)) {
        SetLastError(ERROR_ERRNO_FAIL_BASE + errno);
        return FALSE;
    };
    return TRUE;
}

static DWORD ResumeThread(
  HANDLE hThread
) {
    return 1;
}

static DWORD SuspendThread(
  HANDLE hThread
) {
    return 0;
}

#define ZeroMemory(a,s) memset((a), 0, (s))
#define __debugbreak() (void)0
#define DebugBreak() (void)0

#endif // _WINDOWS

#endif // DETOURS_INTERNAL