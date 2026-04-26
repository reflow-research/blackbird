add_library(blackbird_client_lib STATIC
    src/receiver.cpp
)

target_include_directories(blackbird_client_lib
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(blackbird_client_lib
    PUBLIC
        blackbird_common
)

target_compile_features(blackbird_client_lib PUBLIC cxx_std_23)

add_executable(blackbird_client
    src/main.cpp
)

target_link_libraries(blackbird_client
    PRIVATE
        blackbird_client_lib
)

target_compile_features(blackbird_client PRIVATE cxx_std_23)
