cmake_minimum_required(VERSION 3.20)

project(
    blackbird
    VERSION 0.1.0
    DESCRIPTION "XDP multicast forwarding utilities"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(BLACKBIRD_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)
option(BLACKBIRD_ENABLE_LTO "Enable link-time optimization in release builds" ON)
option(BLACKBIRD_ENABLE_NATIVE_ARCH "Enable -march=native for release builds" ON)
option(BLACKBIRD_ENABLE_SPDLOG "Enable spdlog (allocating logging path)" OFF)
option(BLACKBIRD_BUILD_SOCKET_RECEIVER "Build optional non-XDP socket receiver fallback" OFF)
option(BLACKBIRD_BUILD_XDP_BENCHMARKS "Build XDP microbenchmarks" ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(CompilerWarnings)
include(CompilerOptimizations)
include(CPM)

add_library(blackbird_project_warnings INTERFACE)
blackbird_set_project_warnings(
    blackbird_project_warnings
    ${BLACKBIRD_WARNINGS_AS_ERRORS}
)

add_library(blackbird_project_options INTERFACE)
blackbird_set_project_optimizations(
    blackbird_project_options
    ${BLACKBIRD_ENABLE_NATIVE_ARCH}
)

if(BLACKBIRD_ENABLE_LTO)
    include(CheckIPOSupported)
    check_ipo_supported(RESULT blackbird_lto_supported OUTPUT blackbird_lto_error)
    if(blackbird_lto_supported)
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO ON)
    else()
        message(WARNING "LTO requested but not supported: ${blackbird_lto_error}")
    endif()
endif()

if(BLACKBIRD_ENABLE_SPDLOG)
    CPMAddPackage(
        NAME spdlog
        GITHUB_REPOSITORY gabime/spdlog
        VERSION 1.14.1
        OPTIONS
            "SPDLOG_BUILD_EXAMPLE OFF"
            "SPDLOG_BUILD_TESTS OFF"
            "SPDLOG_BUILD_BENCH OFF"
            "SPDLOG_INSTALL OFF"
    )
endif()

if(BLACKBIRD_BUILD_XDP_BENCHMARKS)
    CPMAddPackage(
        NAME benchmark
        GITHUB_REPOSITORY google/benchmark
        VERSION 1.9.1
        OPTIONS
            "BENCHMARK_ENABLE_TESTING OFF"
            "BENCHMARK_ENABLE_INSTALL OFF"
            "BENCHMARK_ENABLE_GTEST_TESTS OFF"
    )
endif()

add_subdirectory(common)
add_subdirectory(xdp)
add_subdirectory(tc)

if(BLACKBIRD_BUILD_SOCKET_RECEIVER)
    add_subdirectory(client)
endif()
