#include <stdint.h>
typedef uintptr_t ULONG_PTR_;
typedef unsigned char *PBYTE_;
struct DetourMemoryOpWrapper {
    DetourMemoryOpWrapper *pNext;
    DetourMemoryOpWrapper *pPrev;
    void *pbCode;
    char rbCode[0x100];
};

static DetourMemoryOpWrapper *s_detoursMemoryOp = NULL;

inline static void push_op(DetourMemoryOpWrapper *o) {
    o->pPrev = s_detoursMemoryOp;
    if (s_detoursMemoryOp) {
        s_detoursMemoryOp->pNext = o;
    }
    o->pNext = NULL;
    s_detoursMemoryOp = o;
}

// do 's|detour_gen_(.*?)\((.*?)\);|detour_gen_$1_($2);|' on detours.cpp
template<typename T1, typename T2>
PBYTE_ detour_gen_jmp_indirect_(T1 pbCode, T2 value) {
    char pbCodeBuf[0x100] = { 0 };
    memcpy(pbCodeBuf, pbCode, sizeof(pbCodeBuf));
    ULONG_PTR_ newvalue = NULL;
    if (value != NULL) {
        newvalue = (ULONG_PTR_)value - (ULONG_PTR_)pbCode + (ULONG_PTR_)pbCodeBuf;
    }
    PBYTE_ ret = detour_gen_jmp_indirect((T1)pbCodeBuf, (T2)newvalue);
    
    DetourMemoryOpWrapper *o = new DetourMemoryOpWrapper;
    o->pbCode = pbCode;
    memcpy(o->rbCode, pbCodeBuf, sizeof(o->rbCode));
    push_op(o);

    ret = (PBYTE_)((ULONG_PTR_)ret - (ULONG_PTR_)pbCodeBuf + (ULONG_PTR_)pbCode);
    return ret;
}

template<typename T1, typename T2>
PBYTE_ detour_gen_jmp_immediate_(T1 pbCode, T2 value) {
    char pbCodeBuf[0x100] = { 0 };
    memcpy(pbCodeBuf, pbCode, sizeof(pbCodeBuf));
    ULONG_PTR_ newvalue = NULL;
    if (value != NULL) {
        newvalue = (ULONG_PTR_)value - (ULONG_PTR_)pbCode + (ULONG_PTR_)pbCodeBuf;
    }
    PBYTE_ ret = detour_gen_jmp_immediate((T1)pbCodeBuf, (T2)(ULONG_PTR_)newvalue);
    
    DetourMemoryOpWrapper *o = new DetourMemoryOpWrapper;
    o->pbCode = pbCode;
    memcpy(o->rbCode, pbCodeBuf, sizeof(o->rbCode));
    push_op(o);

    ret = (PBYTE_)((ULONG_PTR_)ret - (ULONG_PTR_)pbCodeBuf + (ULONG_PTR_)pbCode);
    return ret;
}

template<typename T1, typename T2, typename T3>
PBYTE_ detour_gen_jmp_immediate_(T1 pbCode, T2 ppPool, T3 pbJmpVal) {
    if (ppPool) {
        return detour_gen_jmp_immediate(pbCode, ppPool, pbJmpVal);
    }

    char pbCodeBuf[0x100] = { 0 };
    memcpy(pbCodeBuf, pbCode, sizeof(pbCodeBuf));
    ULONG_PTR_ newvalue = NULL;
    if (value != NULL) {
        newvalue = (ULONG_PTR_)pbJmpVal - (ULONG_PTR_)pbCode + (ULONG_PTR_)pbCodeBuf;
    }
    PBYTE_ ret = detour_gen_jmp_immediate((T1)pbCodeBuf, NULL, (T3)newvalue);
    
    DetourMemoryOpWrapper *o = new DetourMemoryOpWrapper;
    o->pbCode = pbCode;
    memcpy(o->rbCode, pbCodeBuf, sizeof(o->rbCode));
    push_op(o);

    ret = (PBYTE_)((ULONG_PTR_)ret - (ULONG_PTR_)pbCodeBuf + (ULONG_PTR_)pbCode);
    return ret;
}

template<typename T1, typename T2>
PBYTE_ detour_gen_brk_(T1 pbCode, T2 value) {
    char pbCodeBuf[0x100] = { 0 };
    memcpy(pbCodeBuf, pbCode, sizeof(pbCodeBuf));
    ULONG_PTR_ newvalue = NULL;
    if (value != NULL) {
        newvalue = (ULONG_PTR_)value - (ULONG_PTR_)pbCode + (ULONG_PTR_)pbCodeBuf;
    }
    PBYTE_ ret = detour_gen_brk((T1)pbCodeBuf, (T2)newvalue);
    
    DetourMemoryOpWrapper *o = new DetourMemoryOpWrapper;
    o->pbCode = pbCode;
    memcpy(o->rbCode, pbCodeBuf, sizeof(o->rbCode));
    push_op(o);
    ret = (PBYTE_)((ULONG_PTR_)ret - (ULONG_PTR_)pbCodeBuf + (ULONG_PTR_)pbCode);
    return ret;
}


#define DetourTransactionCommit _DetourTransactionCommit
#include "detours.cpp"
#undef DetourTransactionCommit

#include <vector>

#if defined(_DARWIN) || defined(_LINUX)
static BOOL CodePatch(void *target, void *buffer, size_t count) {
    DWORD flOld = 0;
    if (!VirtualProtect(target, count, PAGE_READWRITE, &flOld)) {
        return FALSE;
    }
    memcpy(target, buffer, count);
    if (!VirtualProtect(target, count, flOld, &flOld)) {
        return FALSE;
    }
    return TRUE;
}
#elif defined(_WINDOWS)
static BOOL CodePatch(void *target, void *buffer, size_t count) {
    DWORD flOld = 0;
    if (!VirtualProtect(target, count, PAGE_READWRITE, &flOld)) {
        return FALSE;
    }
    memcpy(target, buffer, count);
    if (!VirtualProtect(target, count, flOld, &flOld)) {
        return FALSE;
    }
    return TRUE;
}
#endif


extern "C" {

// struct DetourOperationWrapper {
//     DetourOperationWrapper *pNext;
//     PBYTE oldPbTarget;
//     PBYTE newPbTarget;
//     DWORD cbTarget;
//     DWORD flOld;
// };
LONG WINAPI DetourTransactionCommit() {
//     DetourOperationWrapper *ori_s_pPendingOperations = NULL;
//     LONG ret = 0;
//     for (DetourOperation *o = s_pPendingOperations; o != NULL;) {
//         DetourOperationWrapper *o_ = new DetourOperationWrapper;
//         o_->oldPbTarget = o->pbTarget;
//         o_->cbTarget = o->pTrampoline->pbRemain - o->pbTarget;
//         o_->newPbTarget = new BYTE[o_->cbTarget + 0x100];
//         memcpy(o_->newPbTarget, o_->oldPbTarget, o_->cbTarget);
//         o_->flOld = o->dwPerm;
//         if (!VirtualProtect(o_->oldPbTarget, o_->cbTarget, PAGE_READWRITE, &o_->flOld)) {
//             // wait for ret
//             ret = GetLastError();
//             delete o_;
//             break;
//         }
        
//         o_->pNext = ori_s_pPendingOperations;
//         ori_s_pPendingOperations = o_;
//         DETOUR_TRACE(("Before transaction commit: %p (%x)\n", o_->oldPbTarget, o_->cbTarget));
//         // o->pbTarget = o_->newPbTarget;
//         // o->pTrampoline->pbRemain = o_->newPbTarget + o_->cbTarget;
//         // o->pTrampoline->rbCodeIn
//         o = o->pNext;
//     }
//     if (!ret) {
//         ret = _DetourTransactionCommit();
//         DETOUR_TRACE(("Transaction Result: %d\n", ret));
//     } else {
//         DETOUR_TRACE(("Error During VirtualProtect prepare: %d\n", ret));
//     }
    
//     for (DetourOperationWrapper *o_ = ori_s_pPendingOperations; o_ != NULL;) {
//         //if (!!memcmp(o_->oldPbTarget, o_->newPbTarget, o_->cbTarget)) {
//         //    DETOUR_TRACE(("Applying After transaction commit: %p (%x) <- %p\n", o_->oldPbTarget, o_->cbTarget, o_->newPbTarget));
//         //    CodePatch(o_->oldPbTarget, o_->newPbTarget, o_->cbTarget);
//         //}
//         DWORD flOld = 0;
//         if (!VirtualProtect(o_->oldPbTarget, o_->cbTarget, o_->flOld, &flOld)) {
//             // wait for ret
//             ret = GetLastError();
//             DETOUR_TRACE(("Failed to restore page permission for %p: error %d\n", o_->oldPbTarget, ret));
//         }

//         delete[] o_->newPbTarget;
//         DetourOperationWrapper *n_ = o_->pNext;
//         delete o_;
//         o_ = n_;
//     }
//     return ret;
    LONG ret = _DetourTransactionCommit();
    DetourMemoryOpWrapper *begin = NULL;
    for (DetourMemoryOpWrapper *o = s_detoursMemoryOp; o != NULL; ) {
        begin = o;
        o = o->pPrev;
    }
    for (DetourMemoryOpWrapper *o = begin; o != NULL; ) {
        DETOUR_TRACE(("Applying Code Changes: %p\n", o->pbCode));
        if (!CodePatch(o->pbCode, o->rbCode, sizeof(o->rbCode)))
            ret = GetLastError();
        DetourMemoryOpWrapper *n = o->pNext;
        delete o;
        o = n;
    }
    return ret;
}



}
