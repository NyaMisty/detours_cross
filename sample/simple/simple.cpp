//////////////////////////////////////////////////////////////////////////////
//
//  Detours Test Program (simple.cpp of simple.dll)
//
//  Microsoft Research Detours Package
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//
//  This DLL will detour the Windows SleepEx API so that TimedSleep function
//  gets called instead.  TimedSleepEx records the before and after times, and
//  calls the real SleepEx API through the TrueSleepEx function pointer.
//
#include <stdio.h>
#include "detours.h"
#include <string.h>
#include <stdlib.h>


static int user_input = 0;

int to_be_hook(int arg)
{
    printf("simple: to_be_hook got arg: %d.\n", arg);
    return arg;
}

static int (*ori_to_be_hook)(int) = to_be_hook;

int hooker(int arg)
{
    int newarg = arg * arg;
    printf("detours_simple: hook_to_be_hook got arg: %d, changed to %d.\n", arg, newarg);
    return ori_to_be_hook(newarg);
}


int main(int argc, char ** argv)
{
    printf("detours_simple: Starting.\n");
    fflush(stdout);
    printf("DetourTransactionBegin\n");fflush(stdout);
    DetourTransactionBegin();
    printf("UpdateThread\n");fflush(stdout);
    DetourUpdateThread(GetCurrentThread());
    printf("Attach\n");fflush(stdout);
    DetourAttach(&(PVOID&)ori_to_be_hook, (void *)hooker);
    printf("Commit\n");fflush(stdout);
    int error = DetourTransactionCommit();

    if (error == NO_ERROR) {
        printf("detours_simple: Detoured SleepEx().\n");
    }
    else {
        printf("detours_simple: Error detouring SleepEx(): %ld\n", error);
    }
    if (argc == 2) {
        to_be_hook(strlen(argv[1]));
    }
    else {
        printf("simple: Starting.\n");

        to_be_hook(100);

        printf("simple: Done.\n");
    }
    return 0;
}
//
///////////////////////////////////////////////////////////////// End of File.
