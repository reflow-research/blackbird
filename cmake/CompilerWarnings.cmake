function(blackbird_set_project_warnings target warnings_as_errors)
    if(MSVC)
        target_compile_options(
            ${target}
            INTERFACE
                /W4
                /permissive-
        )
        if(warnings_as_errors)
            target_compile_options(${target} INTERFACE /WX)
        endif()
    else()
        target_compile_options(
            ${target}
            INTERFACE
                -Wall
                -Wextra
                -Wpedantic
                -Wconversion
                -Wsign-conversion
        )
        if(warnings_as_errors)
            target_compile_options(${target} INTERFACE -Werror)
        endif()
    endif()
endfunction()

