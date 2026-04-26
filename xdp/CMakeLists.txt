add_executable(blackbird_xdp_ctl src/main.cpp)
target_include_directories(blackbird_xdp_ctl PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(
    blackbird_xdp_ctl
    PRIVATE
        blackbird_common
        blackbird_project_options
        blackbird_project_warnings
)

find_program(
    BLACKBIRD_CLANG_EXECUTABLE
    NAMES
        clang
        clang-19
        clang-18
        clang-17
        clang-16
)
if(BLACKBIRD_CLANG_EXECUTABLE)
    set(BLACKBIRD_XDP_BPF_OBJ ${CMAKE_CURRENT_BINARY_DIR}/blackbird_xdp_kern.o)
    add_custom_command(
        OUTPUT ${BLACKBIRD_XDP_BPF_OBJ}
        COMMAND
            ${BLACKBIRD_CLANG_EXECUTABLE}
            -O2
            -g
            -target bpf
            -D__TARGET_ARCH_x86
            -Wall
            -Werror
            -I${CMAKE_CURRENT_SOURCE_DIR}/include
            -c ${CMAKE_CURRENT_SOURCE_DIR}/src/blackbird_xdp_kern.c
            -o ${BLACKBIRD_XDP_BPF_OBJ}
        DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/src/blackbird_xdp_kern.c
            ${CMAKE_CURRENT_SOURCE_DIR}/include/blackbird/xdp/forward_config.h
        VERBATIM
    )
    add_custom_target(blackbird_xdp_bpf DEPENDS ${BLACKBIRD_XDP_BPF_OBJ})
    add_dependencies(blackbird_xdp_ctl blackbird_xdp_bpf)
    target_compile_definitions(
        blackbird_xdp_ctl
        PRIVATE BLACKBIRD_DEFAULT_XDP_OBJ_PATH="${BLACKBIRD_XDP_BPF_OBJ}"
    )
else()
    message(
        WARNING
            "clang not found: blackbird_xdp_bpf target is disabled. Install clang to build XDP object file."
    )
endif()

if(BLACKBIRD_BUILD_XDP_BENCHMARKS AND TARGET benchmark::benchmark)
    add_subdirectory(bench)
endif()
