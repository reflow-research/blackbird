add_executable(blackbird_tc_ctl src/main.cpp)
target_include_directories(
    blackbird_tc_ctl
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/xdp/include
)
target_link_libraries(
    blackbird_tc_ctl
    PRIVATE
        blackbird_common
        blackbird_project_options
        blackbird_project_warnings
)

find_program(
    BLACKBIRD_TC_CLANG_EXECUTABLE
    NAMES
        clang
        clang-19
        clang-18
        clang-17
        clang-16
)
if(BLACKBIRD_TC_CLANG_EXECUTABLE)
    set(BLACKBIRD_TC_BPF_OBJ ${CMAKE_CURRENT_BINARY_DIR}/blackbird_tc_kern.o)
    add_custom_command(
        OUTPUT ${BLACKBIRD_TC_BPF_OBJ}
        COMMAND
            ${BLACKBIRD_TC_CLANG_EXECUTABLE}
            -O2
            -g
            -target bpf
            -D__TARGET_ARCH_x86
            -Wall
            -Werror
            -I${CMAKE_SOURCE_DIR}/xdp/include
            -c ${CMAKE_CURRENT_SOURCE_DIR}/src/blackbird_tc_kern.c
            -o ${BLACKBIRD_TC_BPF_OBJ}
        DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/src/blackbird_tc_kern.c
            ${CMAKE_SOURCE_DIR}/xdp/include/blackbird/xdp/forward_config.h
        VERBATIM
    )
    add_custom_target(blackbird_tc_bpf DEPENDS ${BLACKBIRD_TC_BPF_OBJ})
    add_dependencies(blackbird_tc_ctl blackbird_tc_bpf)
    target_compile_definitions(
        blackbird_tc_ctl
        PRIVATE BLACKBIRD_DEFAULT_TC_OBJ_PATH="${BLACKBIRD_TC_BPF_OBJ}"
    )
else()
    message(
        WARNING
            "clang not found: blackbird_tc_bpf target is disabled. Install clang to build TC object file."
    )
endif()

target_compile_features(blackbird_tc_ctl PRIVATE cxx_std_23)
