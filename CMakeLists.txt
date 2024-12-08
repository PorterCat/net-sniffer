cmake_minimum_required(VERSION 3.15)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

project(CppProjectTemplate)


add_executable(${PROJECT_NAME}
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp)
    
target_link_libraries(${PROJECT_NAME} PRIVATE )

set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT ${PROJECT_NAME})
#set_target_properties(StbImage PROPERTIES FOLDER ThirdParty)

include(DummyProject.cmake)
set(RESOURCES ./conanfile.txt ./src/.clang-format ./.gitignore)
add_dummy_project(Environment)
dummy_project_add_filter(Environment "Resources" "${RESOURCES}")
file(GLOB BUILD_SCRIPTS ./scripts/*)
dummy_project_add_filter(Environment "BuildScripts" "${BUILD_SCRIPTS}")
