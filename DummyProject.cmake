# Functions for managin projects without translation units,
# only with additional files that should be visible in IDE

function(add_dummy_project name)
    add_library(${name} INTERFACE)
    set_source_files_properties(CMakeLists.txt PROPERTIES HEADER_FILE_ONLY TRUE)
    set_target_properties(${name} PROPERTIES LINKER_LANGUAGE C)
endfunction()

function(dummy_project_add_filter project name files)
    foreach(FILE IN LISTS files)
        set_source_files_properties(${files} PROPERTIES HEADER_FILE_ONLY TRUE)
    endforeach()
    message(${CMAKE_CURRENT_SOURCE_DIR})
    target_sources(${project} PRIVATE ${files})
    source_group(${name} FILES ${files})
endfunction()
