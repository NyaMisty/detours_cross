#include <stdlib.h>
#include <memory.h>
#define DETOURS_INTERNAL
#include "detours.h"

#define min(a,b) ((a) < (b) ? (a) : (b))

#if defined(_DARWIN)
#include <sys/mman.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <unistd.h>

BOOL _CodePatchPage(void *address, void *buffer, uint32_t buffer_size) {
  kern_return_t kr;

  ULONG_PTR page_size = getpagesize();
  ULONG_PTR aligned_addr = (ULONG_PTR)address & ~(page_size - 1);
  ULONG_PTR offset = (ULONG_PTR)address - aligned_addr;

  mach_port_t self_port = mach_task_self();
  // try modify with substrated (steal from frida-gum)
  ULONG_PTR remap_dummy_page =
      (ULONG_PTR)mmap(0, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 255 << 24, 0);
  if ((void *)remap_dummy_page == MAP_FAILED)
    return FALSE;

  // copy original page
  memcpy((void *)remap_dummy_page, (void *)aligned_addr, page_size);

  // patch buffer
  memcpy((void *)(remap_dummy_page + offset), buffer, buffer_size);

  // change permission
  if (-1 == mprotect((void *)remap_dummy_page, page_size, PROT_READ | PROT_WRITE)) {
      SetLastError(ERROR_ERRNO_FAIL_BASE + errno);
      return FALSE;
  }

  BOOL ret = FALSE;
#if 0 && defined(CODE_PATCH_WITH_SUBSTRATED) && defined(TARGET_ARCH_ARM64)
  ret = code_remap_with_substrated((uint8_t *)remap_dummy_page, (uint32_t)page_size, (ULONG_PTR)aligned_addr);
  if (0 && !ret)
    DLOG(0, "substrated failed, use vm_remap");
#endif
  if (!ret) {
    if (-1 == mprotect((void *)remap_dummy_page, page_size, PROT_READ | PROT_EXEC)){
        SetLastError(ERROR_ERRNO_FAIL_BASE + errno);
        return FALSE;
    }
    mach_vm_address_t remap_dest_page = (mach_vm_address_t)aligned_addr;
    vm_prot_t curr_protection, max_protection;
    kr = mach_vm_remap(self_port, (mach_vm_address_t *)&remap_dest_page, page_size, 0,
                       VM_FLAGS_OVERWRITE | VM_FLAGS_FIXED, self_port, (mach_vm_address_t)remap_dummy_page, TRUE,
                       &curr_protection, &max_protection, VM_INHERIT_COPY);
    if (kr != KERN_SUCCESS) {
      SetLastError(ERROR_MACH_FAIL_BASE + kr);
      return FALSE;
    }
  }

  // unmap the origin page
  int err = munmap((void *)remap_dummy_page, (mach_vm_address_t)page_size);
  if (err == -1) {
    SetLastError(ERROR_ERRNO_FAIL_BASE + errno);
    return FALSE;
  }

  ULONG_PTR clear_start = (ULONG_PTR)aligned_addr + offset;
  DETOUR_ASSERT(clear_start == (ULONG_PTR)address);
  return TRUE;
}

#elif defined(_LINUX)

BOOL _CodePatchPage(void *target, void *buffer, size_t count) {
    DWORD flOld = 0;
    if (!VirtualProtect(target, count, PAGE_READWRITE_EXECUTE, &flOld)) {
        return FALSE;
    }
    memcpy(target, buffer, count);
    if (!VirtualProtect(target, count, flOld, &flOld)) {
        return FALSE;
    }
    return TRUE;
}

#elif defined(_WINDOWS)

BOOL _CodePatchPage(void *target, void *buffer, size_t count) {
    DWORD flOld = 0;
    if (!VirtualProtect(target, count, PAGE_READWRITE_EXECUTE, &flOld)) {
        return FALSE;
    }
    memcpy(target, buffer, count);  
    if (!VirtualProtect(target, count, flOld, &flOld)) {
        return FALSE;
    }
    return TRUE;
}

#endif

#include <vector>

extern "C" {

BOOL CodePatch(void *address, void *buffer, size_t buffer_size) {
    std::vector<char> _buffer;
    if (!buffer) {
        _buffer.resize(buffer_size);
        buffer = _buffer.data();
        memcpy(buffer, address, buffer_size);
    }
    char * start_addr = (char *)address;
    char * startPage = (char *)((uintptr_t)(start_addr + getpagesize()) & ~(getpagesize() - 1));
    BOOL ret = TRUE;
    if (!(ret = _CodePatchPage(start_addr, buffer, min(startPage - start_addr, buffer_size)))) {
        return ret;
    }
    uint32_t bufloc = min(startPage - start_addr, buffer_size);
    while (bufloc < buffer_size) {
        uint32_t nextbufloc = min(bufloc + 0x1000, buffer_size);
        if (!(ret = _CodePatchPage(start_addr + bufloc, (char *)buffer + bufloc, nextbufloc - bufloc))) {
            return ret;
        }
        bufloc = nextbufloc;
    }
    return ret;
}

}