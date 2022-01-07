# detours-cross

Cross Platform Support based on Detours

## Usage

1. Compile with CMake (currently no cross-compile support)
2. Include `detours.h` located in include/ folder
3. Link the libdetours.lib generated

## How does it work

Detours has a brilliant disassembly engine, so it can reliably handle various corner case of x86 & ARM stuffs.

I made a windows shim header for detours, in particular wrappers for VirtualAlloc, VirtualProtect, VirtualFree and VirtualQuery.
With these wrappers and some minor modification, Detours's main functionality would work on most platforms, and we can still easily port patches from upstream Detours.