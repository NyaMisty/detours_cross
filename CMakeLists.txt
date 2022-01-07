cmake_minimum_required(VERSION 3.10)

project(detours_cross)

add_library(detour_asm_engine STATIC 
            src/disolarm.cpp 
            src/disolarm64.cpp 
            src/disolia64.cpp
            src/disolx86.cpp
            src/disolx64.cpp
            src/helper.cpp
)

add_library(detour STATIC 
            src/detours.cpp
            src/disasm.cpp
            src/helper.cpp
)


if (CMAKE_SYSTEM_NAME STREQUAL "Windows" OR CMAKE_SYSTEM_NAME STREQUAL "MSYS")
    message("Building for Windows")
    add_compile_definitions(_WINDOWS)
    add_compile_definitions(_WIN32)
elseif (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    message("Building for Darwin")
    add_compile_definitions(_DARWIN)
elseif (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message("Building for Linux")
    add_compile_definitions(_LINUX)
endif()


if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64)")
    message("Building for ARM64")
    add_compile_definitions(_ARM64_)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^arm")
    message("Building for ARM")
    add_compile_definitions(_ARM_)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "(x86_64)|(AMD64|amd64)")
    message("Building for AMD64")
    add_compile_definitions(_AMD64_)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "(^i.86$)")
    message("Building for X86")
    add_compile_definitions(_X86_)
endif()


add_executable(sample_simple sample/simple/simple.cpp)
include_directories(sample_simple src/)
target_link_libraries(sample_simple PRIVATE detour)