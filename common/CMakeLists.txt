add_library(blackbird_common STATIC
    src/log.cpp
    src/perf.cpp
)

target_include_directories(blackbird_common
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(blackbird_common
    PUBLIC
        blackbird_project_warnings
        blackbird_project_options
)

if(BLACKBIRD_ENABLE_SPDLOG)
    target_link_libraries(blackbird_common PUBLIC spdlog::spdlog)
    target_compile_definitions(blackbird_common PUBLIC BLACKBIRD_ENABLE_SPDLOG=1)
endif()

target_compile_features(blackbird_common PUBLIC cxx_std_23)
